"""The storage check's one refusal that used to say nothing about its cause.

Measured on a reference k3s cluster: a hand-made kubernetes.io/no-provisioner
class with storage.data.existing_claim left empty. The check's temporary 1Gi
claim bound one of the operator's own PersistentVolumes, marked it Delete,
deleted the claim -- and with nothing able to delete it the volume went Failed,
while the install ended with four words and a closing line that named `resume`,
which refuses the very edit that fixes it.

A refusal up front would be wrong: with a static-volume deleter the same site
is legitimate. And the StorageClass cannot tell the two stories apart -- that
deleter uses the same provisioner string. The volume's own PHASE can.
"""
import json
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(shutil.which("jq") is None, reason="jq unavailable")


def _run(tmp_path, *, claim="", deleted=False, pv_phase="Failed", pod_phase="Succeeded", logs=True, status="owned"):
    # logs: True = a verdict is printed; "empty" = kubectl logs succeeds with nothing; False = kubectl logs fails
    source = (ROOT / "ops/installer/runtime.sh").read_text().split("# ENTRY POINT", 1)[0]
    source = source.replace("@CLIENT_TABLE@", "gsj_client_info() { return 1; }")
    (tmp_path / "functions.sh").write_text(source)
    work = tmp_path / "work"; state = tmp_path / "state"; work.mkdir(); state.mkdir()
    site = {"storage": {"class": "static-local", "node": "worker-1", "minimum_free_bytes": 1,
                        "data": {"existing_claim": claim}}}
    (work / "site.json").write_text(json.dumps(site))
    (work / "values.pending.json").write_text(json.dumps({"image": {"pullSecrets": []}}))
    (state / "operation.json").write_text(json.dumps({"operation": "a" * 24, "kind": "install", "status": status}))
    # a record of ANOTHER class, left by an earlier run in this state directory: it must play no part
    (state / "storage-class.json").write_text(json.dumps({"metadata": {"name": "some-other-class"},
                                                           "provisioner": "kubernetes.io/no-provisioner"}))
    script = f'''source {shlex.quote(str(tmp_path / "functions.sh"))}
GSJ_WORK={shlex.quote(str(work))}; STATE_DIR={shlex.quote(str(state))}; SITE="$GSJ_WORK/site.json"; CONFIG=/operator/site.json
NAMESPACE=legal; RELEASE=gsj; OPERATION=aaaaaaaaaaaaaaaaaaaaaaaa
assert_owner() {{ :; }}; payload_image() {{ echo registry.invalid/web@sha256:0; }}
fail() {{ printf 'GSJ: %s\\n' "$*" >&2; printf 'HINT: %s\\n' "${{RECOVERY_HINT:-resume --operation $OPERATION}}" >&2; exit 1; }}
k() {{
  printf '%s\\n' "$*" >> "$STATE_DIR/calls"
  case "$1 $2" in
    "create -f") cat >/dev/null;;
    "get pod") printf {pod_phase};;
    "logs "*) {"printf '{\"status\":\"passed\"}'" if logs is True else ("printf ''" if logs == "empty" else "return 7")};;
    "get pvc") case "$*" in *metadata.uid*) printf uid-1;; *) printf pv-operator-7;; esac;;
    "get pv") case "$*" in *jsonpath*) printf {pv_phase};; *) printf '{{"spec":{{"claimRef":{{"uid":"uid-1","namespace":"legal"}}}}}}';; esac;;
    "wait --for=delete") {"return 0" if deleted else "return 1"};;
    *) :;;
  esac
}}
storage_probe
'''
    result = subprocess.run(["bash", "-c", script], text=True, capture_output=True, timeout=60)
    return result, (state / "calls").read_text().splitlines()


def test_a_volume_nothing_can_delete_is_named_with_a_way_out_that_works(tmp_path):
    result, calls = _run(tmp_path)
    assert result.returncode == 1
    message, hint = [l for l in result.stderr.splitlines() if l.startswith(("GSJ:", "HINT:"))]
    assert message.startswith("GSJ: temporary storage backend cleanup incomplete: PersistentVolume pv-operator-7 ")
    assert "it is now Failed" in message and "StorageClass static-local" in message
    assert "storage.data.existing_claim" in message and "deleted and created again" in message
    # the closing line must not send the operator to `resume`, which refuses an edited site
    assert hint.startswith("HINT: abandon --operation aaaaaaaaaaaaaaaaaaaaaaaa --reason ")
    assert "180 s" in hint and "install again" in hint and "resume" not in hint
    # what the message describes is what happened: the volume WAS marked Delete
    assert any(c.startswith("patch pv pv-operator-7 ") and "Delete" in c for c in calls)


@pytest.mark.parametrize("phase", ["Released", "Bound", ""])
def test_a_volume_something_is_still_removing_is_not_the_operators_to_touch(tmp_path, phase):
    """A dynamic provisioner that is slow, or a static-volume deleter at work: the
    first version of this message told them to delete the volume (audit, high)."""
    result, calls = _run(tmp_path, pv_phase=phase)
    assert result.returncode == 1
    message, hint = [l for l in result.stderr.splitlines() if l.startswith(("GSJ:", "HINT:"))]
    assert f"(phase {phase or 'unknown'})" in message and "Do not delete the volume by hand" in message
    assert "existing_claim" not in message and "created again" not in message
    assert hint == "HINT: resume --operation aaaaaaaaaaaaaaaaaaaaaaaa"


def test_a_stale_class_record_in_the_state_directory_plays_no_part(tmp_path):
    """The second version read $STATE_DIR/storage-class.json, which is written for
    one profile only and never removed (audit, high). The fixture always plants a
    no-provisioner record for another class; the verdict follows the volume."""
    result, _ = _run(tmp_path, pv_phase="Released")
    assert "Do not delete the volume by hand" in result.stderr


@pytest.mark.parametrize("logs, expected", [(True, "what it printed is in "), (False, "what it printed could not be read"), ("empty", "it printed nothing")])
def test_the_cleanup_refusal_does_not_hide_a_check_that_failed(tmp_path, logs, expected):
    result, _ = _run(tmp_path, pod_phase="Failed", logs=logs)
    assert result.returncode == 1
    assert "The storage check itself did not pass either" in result.stderr and expected in result.stderr


def test_a_check_that_passed_is_not_reported_as_failed(tmp_path):
    result, _ = _run(tmp_path)
    assert "did not pass either" not in result.stderr


def test_a_deleter_lets_the_same_site_pass(tmp_path):
    """The reason this is a message and not a refusal up front."""
    result, calls = _run(tmp_path, deleted=True)
    assert result.returncode == 0, result.stderr
    assert "Storage passed" in result.stderr


def test_a_named_claim_makes_no_temporary_claim_and_touches_no_volume(tmp_path):
    result, calls = _run(tmp_path, claim="gsj-data")
    assert result.returncode == 0, result.stderr
    assert not any(c.startswith(("patch pv", "delete pvc", "wait --for=delete")) for c in calls)
    assert sum(c.startswith("create -f") for c in calls) == 1      # the check's Pod only, no claim


# ---- the check's Pod never ran: an image pull, a scheduling refusal, or a wait that ran out ----
#
# Measured: with no registry.base the pull probe does not run, so a pull Secret
# that is wrong, a token that has expired or a node that cannot reach the
# registry is first met HERE, by the storage check's own Pod -- which then never
# leaves Pending, and the refusal read `storage WAL/locking/fsync/free-space
# qualification failed`: an image-pull failure reported as a storage failure.
# The operator would go and look at the disk. The storage backend was never
# tested; the message must say what the Pod reported instead.

def _run_never_ran(tmp_path, *, status_json, deleted=True, poll_phase="Pending", json_read_fails=False, pull_secret=None, status="owned"):
    source = (ROOT / "ops/installer/runtime.sh").read_text().split("# ENTRY POINT", 1)[0]
    source = source.replace("@CLIENT_TABLE@", "gsj_client_info() { return 1; }")
    (tmp_path / "functions.sh").write_text(source)
    work = tmp_path / "work"; state = tmp_path / "state"; work.mkdir(); state.mkdir()
    site = {"storage": {"class": "local-path", "node": "worker-1", "minimum_free_bytes": 1,
                        "data": {"existing_claim": ""}}}
    if pull_secret:
        site["registry"] = {"pull_secret": pull_secret}
    (state / "operation.json").write_text(json.dumps({"operation": "a" * 24, "kind": "install", "status": status}))
    (work / "site.json").write_text(json.dumps(site))
    (work / "values.pending.json").write_text(json.dumps({"image": {"pullSecrets": [pull_secret] if pull_secret else []}}))
    (state / "pod-status.json").write_text(json.dumps(status_json))
    script = f'''source {shlex.quote(str(tmp_path / "functions.sh"))}
GSJ_WORK={shlex.quote(str(work))}; STATE_DIR={shlex.quote(str(state))}; SITE="$GSJ_WORK/site.json"; CONFIG=/operator/site.json
NAMESPACE=legal; RELEASE=gsj; OPERATION=aaaaaaaaaaaaaaaaaaaaaaaa
assert_owner() {{ :; }}; payload_image() {{ echo ghcr.example/team/web@sha256:0; }}
sleep() {{ SECONDS=$((SECONDS + 150)); }}
fail() {{ printf 'GSJ: %s\\n' "$*" >&2; printf 'HINT: %s\\n' "${{RECOVERY_HINT:-resume --operation $OPERATION}}" >&2; exit 1; }}
k() {{
  printf '%s\\n' "$*" >> "$STATE_DIR/calls"
  case "$1 $2" in
    "create -f") cat >/dev/null;;
    "get pod") case "$*" in *jsonpath*) printf {poll_phase};; *json*) {"return 3" if json_read_fails else 'cat "$STATE_DIR/pod-status.json"'};; esac;;
    "logs "*) return 7;;
    "get pvc") case "$*" in *metadata.uid*) printf uid-1;; *) printf {"pv-operator-7" if not deleted else "''"};; esac;;
    "get pv") case "$*" in *jsonpath*) printf Released;; *) printf '{{"spec":{{"claimRef":{{"uid":"uid-1","namespace":"legal"}}}}}}';; esac;;
    "wait --for=delete") {"return 0" if deleted else "return 1"};;
    *) :;;
  esac
}}
storage_probe
'''
    result = subprocess.run(["bash", "-c", script], text=True, capture_output=True, timeout=60)
    return result, (state / "calls").read_text().splitlines()


PULL_FAILED = {"status": {"phase": "Pending", "conditions": [{"type": "PodScheduled", "status": "True"}],
               "containerStatuses": [{"name": "storage-check", "image": "ghcr.example/team/web@sha256:0",
                                      "state": {"waiting": {"reason": "ImagePullBackOff",
                                                            "message": "Back-off pulling image \"ghcr.example/team/web@sha256:0\""}}}]}}
UNSCHEDULABLE = {"status": {"phase": "Pending",
                 "conditions": [{"type": "PodScheduled", "status": "False", "reason": "Unschedulable",
                                 "message": "0/3 nodes are available: 3 node(s) didn't match Pod's node affinity/selector."}]}}
STILL_STARTING = {"status": {"phase": "Pending", "conditions": [{"type": "PodScheduled", "status": "True"}],
                  "containerStatuses": [{"name": "storage-check", "image": "ghcr.example/team/web@sha256:0",
                                         "state": {"waiting": {"reason": "ContainerCreating"}}}]}}
STILL_RUNNING = {"status": {"phase": "Running", "conditions": [{"type": "PodScheduled", "status": "True"}],
                 "containerStatuses": [{"name": "storage-check", "image": "ghcr.example/team/web@sha256:0",
                                        "state": {"running": {"startedAt": "2026-01-01T00:00:00Z"}}}]}}


def test_an_image_the_node_cannot_pull_is_not_reported_as_a_storage_failure(tmp_path):
    result, _ = _run_never_ran(tmp_path, status_json=PULL_FAILED)
    assert result.returncode == 1
    message = [l for l in result.stderr.splitlines() if l.startswith("GSJ:")][0]
    assert "storage WAL/locking/fsync/free-space qualification failed" not in message
    assert "could not pull" in message and "ImagePullBackOff" in message and "registry.pull_secret" in message
    assert "was not tested" in message
    hint = [l for l in result.stderr.splitlines() if l.startswith("HINT:")][0]
    assert hint.startswith("HINT: resume --operation aaaaaaaaaaaaaaaaaaaaaaaa"), "repair never runs the storage check; resume does"
    # the site names no pull Secret, so the hint must not name one ("the pull Secret null")
    assert "null" not in hint and "deleted first" not in hint
    assert "repair --operation" not in hint, "repair applies a changed site without ever running this check"
    assert "abandon" in hint and "install again" in hint, "a changed site value cannot be resumed: a new operation from the corrected file"


def test_the_pull_hint_names_the_sites_pull_secret_when_there_is_one(tmp_path):
    result, _ = _run_never_ran(tmp_path, status_json=PULL_FAILED, pull_secret="gsj-pull")
    hint = [l for l in result.stderr.splitlines() if l.startswith("HINT:")][0]
    assert "the pull Secret gsj-pull in namespace legal" in hint and "deleted first" in hint


def test_a_failed_pod_snapshot_keeps_the_phase_the_poll_saw(tmp_path):
    """A later audit found: when the final `-o json` read failed, the empty snapshot
    overwrote the polled phase and a check last seen Running was reported as
    "never ran (unknown)" -- the misattribution the Running branch removes."""
    result, _ = _run_never_ran(tmp_path, status_json=STILL_RUNNING, poll_phase="Running", json_read_fails=True)
    assert result.returncode == 1
    message = [l for l in result.stderr.splitlines() if l.startswith("GSJ:")][0]
    assert "still running" in message and "unknown" not in message and "never ran" not in message
    # the status file is empty on this path: the message says the status could not be read, never names the file
    assert "could not be read" in message and "storage-check-pod.json" not in message


def test_the_hints_after_a_backup_never_say_install_again_or_a_repeated_check(tmp_path):
    """Over an installed source the operation has passed its backup (status
    backup-verified): the deployment is quiesced, so abandon refuses, and resume
    continues from backup-verified WITHOUT this storage check (that phase's
    pipeline skips it); a changed storage block is refused by compatibility.
    The first-install hints (abandon, install again, "runs again on resume")
    would send that operator into two refusals and a false expectation. The
    discriminator is the operation's recorded status, which every caller
    writes before this check runs -- not a file some resume paths never read."""
    result, _ = _run_never_ran(tmp_path, status_json=PULL_FAILED, status="backup-verified")
    message = [l for l in result.stderr.splitlines() if l.startswith("GSJ:")][0]
    hint = [l for l in result.stderr.splitlines() if l.startswith("HINT:")][0]
    assert hint.startswith("HINT: resume --operation") and "install again" not in hint and "abandon" not in hint
    assert "repair --operation" in hint, "after the backup a changed registry value goes through repair"
    assert "not repeated" in hint and "runs again on resume" not in message and "does not repeat this check" in message
    assert "qualified at its install" not in message and "qualified at its install" not in hint
    (tmp_path / "s").mkdir()
    result, _ = _run_never_ran(tmp_path / "s", status_json=UNSCHEDULABLE, status="backup-verified")
    hint = [l for l in result.stderr.splitlines() if l.startswith("HINT:")][0]
    assert hint.startswith("HINT: resume --operation") and "install again" not in hint and "abandon" not in hint
    assert "refused" in hint and "storage" in hint


def test_a_first_install_is_told_the_check_runs_again_on_resume(tmp_path):
    result, _ = _run_never_ran(tmp_path, status_json=PULL_FAILED, status="owned")
    message = [l for l in result.stderr.splitlines() if l.startswith("GSJ:")][0]
    assert "runs again on resume" in message


def test_a_pod_the_scheduler_refused_is_not_reported_as_a_storage_failure(tmp_path):
    result, _ = _run_never_ran(tmp_path, status_json=UNSCHEDULABLE)
    assert result.returncode == 1
    message = [l for l in result.stderr.splitlines() if l.startswith("GSJ:")][0]
    assert "storage WAL/locking/fsync/free-space qualification failed" not in message
    assert "Unschedulable" in message and "storage.node" in message and "was not tested" in message
    hint = [l for l in result.stderr.splitlines() if l.startswith("HINT:")][0]
    assert hint.startswith("HINT: resume --operation aaaaaaaaaaaaaaaaaaaaaaaa")
    assert "abandon --operation" in hint and "storage.node" in hint         # a changed node needs a new operation
    assert "upgrade and repair refuse" not in hint, "a later audit: repair does not refuse a changed storage block on a first install"


def test_a_check_that_never_finished_names_the_wait_not_the_disk(tmp_path):
    result, _ = _run_never_ran(tmp_path, status_json=STILL_STARTING)
    assert result.returncode == 1
    message = [l for l in result.stderr.splitlines() if l.startswith("GSJ:")][0]
    assert "storage WAL/locking/fsync/free-space qualification failed" not in message
    assert "did not finish" in message and "300 s" in message and "was not tested" in message


def test_a_check_whose_pod_succeeded_passed_even_when_its_log_could_not_be_read(tmp_path):
    """Measured: the Pod ran to an end (Succeeded:
    the check's own asserts all held, its exit was 0) but `kubectl logs` failed
    (pods/log is not in the preflight's permission list). The run first ended
    with the storage verdict, then with "tested but not judged" -- but the
    phase IS the verdict; only the measurements are missing."""
    result, _ = _run(tmp_path, pod_phase="Succeeded", logs=False, deleted=True)
    assert result.returncode == 0, result.stderr
    assert "storage WAL/locking/fsync/free-space qualification failed" not in result.stderr
    assert "Storage passed" in result.stderr and "measurements could not be read" in result.stderr and "pods/log" in result.stderr
    assert "not judged" not in result.stderr and "nothing about the disk" not in result.stderr
    # and when the cleanup refusal comes first, its note says the same, never "did not pass"
    (tmp_path / "second").mkdir()
    result, _ = _run(tmp_path / "second", pod_phase="Succeeded", logs=False)
    assert result.returncode == 1 and "cleanup incomplete" in result.stderr
    assert "did not pass" not in result.stderr and "not judged" not in result.stderr
    assert "passed (its Pod ended Succeeded)" in result.stderr and "measurements could not be read" in result.stderr


def test_a_check_still_running_at_the_wait_is_named_for_that_not_for_the_pull(tmp_path):
    """A later audit found: a Pod in phase Running when the 300 s ran out was
    blamed on the image pull or the claim binding, which had both finished."""
    result, _ = _run_never_ran(tmp_path, status_json=STILL_RUNNING, poll_phase="Running")
    assert result.returncode == 1
    message = [l for l in result.stderr.splitlines() if l.startswith("GSJ:")][0]
    assert "storage WAL/locking/fsync/free-space qualification failed" not in message
    assert "still running" in message and "300 s" in message and "was not tested" in message
    assert "pulling the image" not in message and "binding" not in message
    hint = [l for l in result.stderr.splitlines() if l.startswith("HINT:")][0]
    assert "quiet" not in hint and "resume --operation" in hint, "nothing measured the disk's load"


def test_a_pod_that_never_ran_leaves_a_cleanup_note_that_never_says_did_not_pass(tmp_path):
    """A later audit found: when the cleanup refusal comes first, its note said "the
    storage check itself did not pass either" for a Pod that never ran."""
    result, _ = _run_never_ran(tmp_path, status_json=PULL_FAILED, deleted=False)
    assert result.returncode == 1
    message = [l for l in result.stderr.splitlines() if l.startswith("GSJ:")][0]
    assert "cleanup incomplete" in message                                     # the cleanup refusal came first
    assert "did not pass" not in message
    assert "never ran" in message and "ImagePullBackOff" in message and "not tested" in message


def test_after_the_backup_every_storage_hint_says_resume_does_not_repeat_the_check(tmp_path):
    """The recorded status decides every hint of this check, not two of them:
    a check still running, a check that failed, and the cleanup refusal all
    used to name resume as if it would run the check again, or abandon,
    which refuses after the backup."""
    result, _ = _run_never_ran(tmp_path, status_json=STILL_RUNNING, poll_phase="Running", status="backup-verified")
    hint = [l for l in result.stderr.splitlines() if l.startswith("HINT:")][0]
    assert "without repeating this check" in hint and "abandon" not in hint and "stays stuck" not in hint
    assert hint.startswith("HINT: resume --operation aaaaaaaaaaaaaaaaaaaaaaaa ("), "cleanup_exit prints `Use <hint>.`: the hint must read as a command"
    # the failed verdict: a first install is told resume repeats the check; after the backup it is not
    (tmp_path / "f").mkdir()
    result, _ = _run(tmp_path / "f", pod_phase="Failed", deleted=True, status="owned")
    assert result.returncode == 1 and "qualification failed" in result.stderr
    hint = [l for l in result.stderr.splitlines() if l.startswith("HINT:")][0]
    assert "resume --operation" in hint and "repeats this check" in hint
    (tmp_path / "g").mkdir()
    result, _ = _run(tmp_path / "g", pod_phase="Failed", deleted=True, status="backup-verified")
    hint = [l for l in result.stderr.splitlines() if l.startswith("HINT:")][0]
    assert "without repeating this check" in hint and "repeats this check" not in hint
    # the cleanup refusal after the backup: no "name a claim of your own" (a changed storage block is refused), no abandon
    (tmp_path / "h").mkdir()
    result, _ = _run(tmp_path / "h", status="backup-verified")
    message = [l for l in result.stderr.splitlines() if l.startswith("GSJ:")][0]
    hint = [l for l in result.stderr.splitlines() if l.startswith("HINT:")][0]
    assert "cleanup incomplete" in message and "Name a claim of your own" not in message and "refused for an installed release" in message
    assert "abandon" not in hint and hint.startswith("HINT: resume --operation")
