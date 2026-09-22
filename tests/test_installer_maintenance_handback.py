"""The transfer hostPath goes back to the operator before its Pod disappears.

Measured on a proof deployment: maintenance containers run as root, so every
byte they wrote under `storage.transfer_path/<operation>` was root-owned and
the teardown needed sudo for four per-operation directories, one of them 8.9 G.
No cluster, no kubeconfig: the fake kubectl records the exact argv it was given.
"""
import json
import os

from tests.test_installer import _site, runtime  # noqa: F401

OWNER = f"{os.getuid()}:{os.getgid()}"
POD = "gsj-backup-maintenance"


def _cluster(state, phase="Running", present=True):
    value = json.loads(state.read_text())
    value["resources"] = {}
    if present:
        value["resources"]["Pod/" + POD] = {
            "kind": "Pod", "metadata": {"name": POD, "uid": "pod-uid",
                                        "labels": {"gsj.io/operation": POD}},
            "status": {"phase": phase}}
    value["calls"] = []
    state.write_text(json.dumps(value))


def _site_transfer(work, path):
    site = _site()
    site["storage"]["transfer_path"] = path
    (work / "site.json").write_text(json.dumps(site))


def _backup_complete(work):
    (work / "operation.json").write_text(json.dumps({"operation": "a" * 24, "status": "applying"}))
    (work / "archive.enc").write_bytes(b"synthetic encrypted archive")
    return f'''quiescence_snapshot() {{ printf '%s' "$TEST_WORK/snapshot.json"; }}
validate_backup_closure() {{ :; }}
offbox_backup() {{ :; }}
backup_complete "$TEST_WORK/archive.enc" {POD}
'''


def _chowns(state):
    return [c for c in json.loads(state.read_text())["calls"] if c[:1] == ["exec"] and "chown" in c]


def test_transfer_hostpath_is_handed_back_before_the_pod_that_wrote_it_is_deleted(runtime):
    run, state, work = runtime
    _site_transfer(work, "/data/gsj-install/transfer")
    _cluster(state)
    result = run(_backup_complete(work))
    assert result.returncode == 0, result.stderr
    calls = json.loads(state.read_text())["calls"]
    chown = next(i for i, c in enumerate(calls) if c[:1] == ["exec"] and "chown" in c)
    delete = next(i for i, c in enumerate(calls) if c[:2] == ["delete", "pod"])
    assert calls[chown] == ["exec", POD, "--", "chown", "-R", OWNER, "/transfer"]
    assert chown < delete
    assert json.loads((work / "operation.json").read_text())["status"] == "backup-verified"


def test_an_emptydir_transfer_owns_nothing_outside_the_pod_and_is_never_chowned(runtime):
    run, state, work = runtime
    _site_transfer(work, "")
    _cluster(state)
    result = run(_backup_complete(work))
    assert result.returncode == 0, result.stderr
    assert _chowns(state) == []
    assert any(c[:2] == ["delete", "pod"] for c in json.loads(state.read_text())["calls"])


def test_a_stopped_or_absent_maintenance_pod_is_skipped_without_failing(runtime):
    run, state, work = runtime
    _site_transfer(work, "/data/gsj-install/transfer")
    for phase, present in (("Succeeded", True), ("Failed", True), ("Running", False)):
        _cluster(state, phase=phase, present=present)
        result = run(f"transfer_handback {POD}\n")
        assert result.returncode == 0, result.stderr
        assert _chowns(state) == []


def test_only_the_transfer_mount_is_touched_and_a_refused_handback_never_fails_the_operation(runtime):
    run, state, work = runtime
    _site_transfer(work, "/data/gsj-install/transfer")
    _cluster(state)
    result = run(f'''k() {{ if [[ $1 == exec ]]; then return 13; fi; command kubectl "$@"; }}
transfer_handback {POD}
''')
    assert result.returncode == 0, result.stderr
    assert "will need root" in result.stderr
    assert "/volumes" not in result.stderr


def test_a_stopped_operation_hands_the_directory_back_on_the_failure_path(runtime):
    """The pod outlives the failure for `resume`; its transfer bytes must still
    stop being root-owned, so the exit path hands them back as well."""
    run, state, work = runtime
    _site_transfer(work, "/data/gsj-install/transfer")
    _cluster(state)
    result = run(f'''stop_owned_process_group() {{ :; }}
install_exit_traps
TRANSFER_HANDBACK_POD={POD}
false
''')
    assert result.returncode == 1
    assert _chowns(state) == [["exec", POD, "--", "chown", "-R", OWNER, "/transfer"]]
    assert not any(c[:2] == ["delete", "pod"] for c in json.loads(state.read_text())["calls"])
