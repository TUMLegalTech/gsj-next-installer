"""The transfer hostPath goes back to the operator before its Pod disappears.

Measured on a proof deployment: maintenance containers run as root, so every
byte they wrote under `storage.transfer_path/<operation>` was root-owned and
the teardown needed sudo for four per-operation directories, one of them 8.9 G.
No cluster, no kubeconfig: the fake kubectl records the exact argv it was given.
"""
import hashlib
import json
import os

import pytest

from tests.test_installer import INSTALLER, _site, runtime  # noqa: F401
from tests.test_installer_restore import _binding_fixture

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


# --- the plaintext a maintenance Pod stages -----------------------------------
# Measured on a proof deployment: every backup left two plaintext copies of all
# three volumes under the node's transfer directory (snapshot.tar.gz and
# roundtrip.tar.gz, 13 G per operation), never pruned, and a restore left its
# decrypted archive. The encrypted archive on the operator's host is the
# recovery point; once it is verified those copies are only exposure.

PLAINTEXT = ["/transfer/snapshot.tar.gz", "/transfer/roundtrip.tar.gz"]


def _removals(calls):
    return [i for i, c in enumerate(calls) if c[:1] == ["exec"] and "rm" in c]


def test_a_completed_backup_removes_both_plaintext_copies_before_the_handback_and_the_pod_deletion(runtime):
    run, state, work = runtime
    _site_transfer(work, "/data/gsj-install/transfer")
    _cluster(state)
    result = run(_backup_complete(work))
    assert result.returncode == 0, result.stderr
    calls = json.loads(state.read_text())["calls"]
    removal = _removals(calls)
    assert [calls[i] for i in removal] == [["exec", POD, "--", "rm", "-f", *PLAINTEXT]]
    chown = next(i for i, c in enumerate(calls) if c[:1] == ["exec"] and "chown" in c)
    delete = next(i for i, c in enumerate(calls) if c[:2] == ["delete", "pod"])
    assert removal[0] < chown < delete


def test_a_removal_that_fails_is_logged_with_the_directory_and_never_fails_the_backup(runtime):
    run, state, work = runtime
    _site_transfer(work, "/data/gsj-install/transfer")
    _cluster(state)
    body = _backup_complete(work).replace("backup_complete ", '''OPERATION=aaaaaaaaaaaaaaaaaaaaaaaa
k() { if [[ $1 == exec && $4 == rm ]]; then echo "error: ZZ-KUBECTL-WORDS" >&2; return 13; fi; command kubectl "$@"; }
backup_complete ''', 1)
    result = run(body)
    assert result.returncode == 0, result.stderr
    assert "/data/gsj-install/transfer/" + "a" * 24 + " on node synthetic-node" in result.stderr
    assert "by hand" in result.stderr
    assert "ZZ-KUBECTL-WORDS" not in result.stderr, "kubectl's words are kept, never printed"
    assert "ZZ-KUBECTL-WORDS" in (work / "transfer-remove.err").read_text()
    assert (work / "transfer-remove.err").stat().st_mode & 0o077 == 0
    assert json.loads((work / "operation.json").read_text())["status"] == "backup-verified"


def test_a_failed_operation_s_exit_path_never_removes_what_a_repair_reads(runtime):
    """backup-repair and restore-repair read a stopped Pod's /transfer; the
    exit path hands the directory back and removes nothing."""
    run, state, work = runtime
    _site_transfer(work, "/data/gsj-install/transfer")
    _cluster(state)
    body = _backup_complete(work).replace("offbox_backup() { :; }", "offbox_backup() { fail 'synthetic off-box refusal'; }")
    result = run(f'''stop_owned_process_group() {{ :; }}
install_exit_traps
TRANSFER_HANDBACK_POD={POD}
{body}''')
    assert result.returncode == 1
    calls = json.loads(state.read_text())["calls"]
    assert _chowns(state), "the exit path still hands the directory back"
    assert _removals(calls) == []


def test_the_roundtrip_copy_is_written_private_like_the_metadata():
    source = (INSTALLER / "runtime.sh").read_text()
    assert "k exec -i \"$pod\" -- sh -c 'umask 077; cat > /transfer/roundtrip.tar.gz'" in source
    assert "sh -c 'cat > /transfer/roundtrip.tar.gz'" not in source


def _finished_restore(runtime, transfer):
    run, state, work, saved, operation, pod, prefix = _binding_fixture(runtime)
    _site_transfer(work, transfer)
    settings = {"namespace_uid": "target-namespace-uid", "release_identity": "synthetic-release",
                "archive_sha256": "b" * 64, "encrypted_archive_sha256": "c" * 64}
    payload = json.dumps(settings).encode()
    (saved / "files-settings.json").write_bytes(payload)
    (saved / "archive-proof.json").write_text(json.dumps({"manifest_sha256": "d" * 64, "entries": 9}))
    (saved / "files-result.json").write_text(json.dumps({
        "format": "gsj.restore-files-result/1", "status": "complete", "restored": True, "operation": operation,
        **settings, "settings_file_sha256": hashlib.sha256(payload).hexdigest(), "manifest_sha256": "d" * 64, "entries": 9}))
    (saved / "Pod" / pod).mkdir(parents=True)
    (saved / "Pod" / pod / "receipt.json").write_text(json.dumps({"uid": "restore-pod-uid"}))
    restoration = json.loads((work / "restoration.json").read_text())
    restoration["archive_sha256"] = "c" * 64
    (work / "restoration.json").write_text(json.dumps(restoration))
    data = json.loads(state.read_text())
    data["resources"]["Pod/" + pod] = {"kind": "Pod", "metadata": {"name": pod, "uid": "restore-pod-uid"},
                                       "spec": {"volumes": []}, "status": {"phase": "Running"}}
    data["calls"] = []
    state.write_text(json.dumps(data))
    return run, state, work, pod, prefix


def test_a_finished_restore_removes_its_decrypted_archive_before_the_handback(runtime):
    run, state, work, pod, prefix = _finished_restore(runtime, "/data/gsj-install/transfer")
    result = run(prefix + "restore_finish_pod")
    assert result.returncode == 0, result.stderr
    calls = json.loads(state.read_text())["calls"]
    removal = _removals(calls)
    assert [calls[i] for i in removal] == [["exec", pod, "--", "rm", "-f", "/transfer/snapshot-" + "c" * 64 + ".tar.gz"]]
    chown = next(i for i, c in enumerate(calls) if c[:1] == ["exec"] and "chown" in c)
    delete = next(i for i, c in enumerate(calls) if c[:2] == ["delete", "--raw"])
    assert removal[0] < chown < delete


def test_a_restore_archive_that_cannot_be_removed_is_logged_and_the_restore_completes(runtime):
    run, state, work, pod, prefix = _finished_restore(runtime, "/data/gsj-install/transfer")
    result = run(prefix + '''k() { if [[ $1 == exec && $4 == rm ]]; then return 13; fi; command kubectl "$@"; }
restore_finish_pod''')
    assert result.returncode == 0, result.stderr
    assert "/data/gsj-install/transfer/" + "a" * 24 + " on node synthetic-node" in result.stderr and "by hand" in result.stderr
    assert "Pod/" + pod not in json.loads(state.read_text())["resources"]


# --- the transfer directory is private before anything is written ----------------

def _maintenance_values(work):
    (work / "values.pending.json").write_text(json.dumps({
        "image": {"pullSecrets": []}, "storage": {key: {"existingClaim": ""} for key in ("data", "forgejo", "chroma")}}))
    (work / "sleep.json").write_text('["sleep","86400"]')


@pytest.mark.parametrize("transfer", ["/data/gsj-install/transfer", ""])
def test_a_maintenance_pod_makes_its_transfer_directory_private_once_it_is_ready(runtime, transfer):
    """A hostPath the kubelet creates (DirectoryOrCreate) is root's, mode 0755:
    readable by every account on the node. An emptyDir lives inside the Pod's
    own kubelet directory and needs nothing."""
    run, state, work = runtime
    _site_transfer(work, transfer)
    _cluster(state, present=False)
    _maintenance_values(work)
    result = run(f'OPERATION={"a" * 24}\nmaintenance_pod {POD} registry.invalid/web@sha256:{"e" * 64} "$TEST_WORK/sleep.json"\n')
    assert result.returncode == 0, result.stderr
    calls = json.loads(state.read_text())["calls"]
    private = [i for i, c in enumerate(calls) if c[:1] == ["exec"] and "chmod" in c]
    if not transfer:
        assert private == []
        return
    ready = next(i for i, c in enumerate(calls) if c[:2] == ["wait", "--for=condition=Ready"])
    assert [calls[i] for i in private] == [["exec", POD, "--", "chmod", "700", "/transfer"]]
    assert ready < private[0] == len(calls) - 1


def test_a_restore_pod_makes_its_transfer_directory_private_once_it_is_ready(runtime):
    run, state, work = runtime
    _site_transfer(work, "/data/gsj-install/transfer")
    _cluster(state, present=False)
    _maintenance_values(work)
    result = run(f'''OPERATION={"a" * 24}
restore_resource() {{ :; }}
restore_no_writers() {{ exit 7; }}
restore_files synthetic-restore synthetic-release registry.invalid/web@sha256:{"e" * 64}
''')
    assert result.returncode == 7, result.stderr
    calls = json.loads(state.read_text())["calls"]
    ready = next(i for i, c in enumerate(calls) if c[:2] == ["wait", "--for=condition=Ready"])
    assert calls[ready + 1:] == [["exec", "synthetic-restore", "--", "chmod", "700", "/transfer"]]


def test_a_directory_that_cannot_be_made_private_is_logged_not_refused(runtime):
    run, state, work = runtime
    _site_transfer(work, "/data/gsj-install/transfer")
    _cluster(state, present=False)
    _maintenance_values(work)
    result = run(f'''OPERATION={"a" * 24}
k() {{ if [[ $1 == exec && $4 == chmod ]]; then echo "error: ZZ-KUBECTL-WORDS" >&2; return 13; fi; command kubectl "$@"; }}
maintenance_pod {POD} registry.invalid/web@sha256:{"e" * 64} "$TEST_WORK/sleep.json"
''')
    assert result.returncode == 0, result.stderr
    assert "/data/gsj-install/transfer/" + "a" * 24 + " on node synthetic-node" in result.stderr
    assert "ZZ-KUBECTL-WORDS" not in result.stderr
    assert "ZZ-KUBECTL-WORDS" in (work / "transfer-private.err").read_text()
