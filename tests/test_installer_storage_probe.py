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


def _run(tmp_path, *, claim="", deleted=False, pv_phase="Failed", pod_phase="Succeeded", logs=True):
    source = (ROOT / "ops/installer/runtime.sh").read_text().split("# ENTRY POINT", 1)[0]
    source = source.replace("@CLIENT_TABLE@", "gsj_client_info() { return 1; }")
    (tmp_path / "functions.sh").write_text(source)
    work = tmp_path / "work"; state = tmp_path / "state"; work.mkdir(); state.mkdir()
    site = {"storage": {"class": "static-local", "node": "worker-1", "minimum_free_bytes": 1,
                        "data": {"existing_claim": claim}}}
    (work / "site.json").write_text(json.dumps(site))
    (work / "values.pending.json").write_text(json.dumps({"image": {"pullSecrets": []}}))
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
    "logs "*) {"printf '{\"status\":\"passed\"}'" if logs else "return 7"};;
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


@pytest.mark.parametrize("logs, expected", [(True, "what it printed is in "), (False, "printed nothing that could be read")])
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
