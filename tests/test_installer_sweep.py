"""test_installer_sweep — the `sweep` verb.

A killed or refused run leaves a canonical record every later operation refuses
("another active operation or later phase owns canonical state"), plus the
installer's own Jobs, record ConfigMaps, token Secrets and a transfer directory
— and `abandon` cannot reach it, because abandon releases a LIVE operation's
Lease and refuses without one. `sweep` clears exactly that residue, per target,
evidence first, and never a live operation or a live deployment.
"""
import json
import os
import re
import time
from pathlib import Path

import pytest

from tests.test_installer import INSTALLER, runtime, _foreign_release  # noqa: F401  (fixture)

OP = "d" * 24


def _obj(kind, name, labels=None, extra=None):
    value = {"apiVersion": "batch/v1" if kind == "Job" else "v1", "kind": kind,
             "metadata": {"name": name, "uid": f"uid-{kind.lower()}-{name}", "labels": labels or {}}}
    if extra:
        value.update(extra)
    return value


def _dead_target(state, work, tmp_path, *, lease=None, status="initializing", tls_profile="existing", extra_resources=()):
    """The residue a dead run leaves: its canonical record, an intent, the
    provisioning Job, the record ConfigMaps, a verification plan, the token
    Secrets, plus what must NEVER go — a claim, a supplied Secret, a foreign
    directory under the transfer path."""
    transfer = tmp_path / "transfer"; transfer.mkdir()
    (transfer / OP).mkdir(); (transfer / OP / "snapshot.tar.gz").write_bytes(b"x")
    (transfer / "zzz-not-ours").mkdir()
    site = json.loads((work / "site.json").read_text())
    site["storage"]["transfer_path"] = str(transfer)
    site["tls"].update(profile=tls_profile, secret="synthetic-release-tls")
    (work / "site.json").write_text(json.dumps(site))
    (work / "operation.json").write_text(json.dumps({"operation": OP, "kind": "install", "status": status, "target": "synthetic-release"}))
    (work / "operation-intents" / OP).mkdir(parents=True)
    (work / "lease-lost").write_text("")
    resources = {
        "Job/synthetic-release-provision": _obj("Job", "synthetic-release-provision", {"app.kubernetes.io/instance": "synthetic-release"}),
        "ConfigMap/synthetic-release-installed": _obj("ConfigMap", "synthetic-release-installed", {"gsj.io/owner": "synthetic-release"}),
        # written by the provisioning Job inside the cluster, carrying NO installer label (measured: the one object the first sweep left behind)
        "ConfigMap/synthetic-release-provisioned": _obj("ConfigMap", "synthetic-release-provisioned"),
        "ConfigMap/synthetic-release-verify-1234abcd-a1": _obj("ConfigMap", "synthetic-release-verify-1234abcd-a1", {"gsj.io/owner": "synthetic-release"}),
        "Secret/synthetic-release-admin-token": _obj("Secret", "synthetic-release-admin-token"),
        "Secret/synthetic-release-agent-token": _obj("Secret", "synthetic-release-agent-token"),
        "Secret/synthetic-release-tls": _obj("Secret", "synthetic-release-tls", extra={"type": "kubernetes.io/tls"}),
        "Secret/operator-supplied-registry": _obj("Secret", "operator-supplied-registry"),
        "PersistentVolumeClaim/synthetic-release-data": _obj("PersistentVolumeClaim", "synthetic-release-data", {"app.kubernetes.io/instance": "synthetic-release"}),
    }
    for item in extra_resources:
        resources[item["kind"] + "/" + item["metadata"]["name"]] = item
    state.write_text(json.dumps({"lease": lease, "calls": [], "resources": resources}))
    return transfer


def _lease(holder, renewed_seconds_ago):
    renew = time.strftime("%Y-%m-%dT%H:%M:%S.000000Z", time.gmtime(time.time() - renewed_seconds_ago))
    return {"apiVersion": "coordination.k8s.io/v1", "kind": "Lease",
            "metadata": {"name": "synthetic-release-operation", "resourceVersion": "7", "uid": "lease-uid"},
            "spec": {"holderIdentity": holder, "renewTime": renew}}


def _sweep(run, reason="synthetic: the run was killed and its namespace removed"):
    return run(f'ABANDON_REASON={json.dumps(reason)}\nsweep_target\n')


def _records(work):
    return sorted(work.glob("swept-*.json"))


def test_sweep_refuses_a_live_operation_and_touches_nothing(runtime, tmp_path):
    run, state, work = runtime
    _dead_target(state, work, tmp_path, lease=_lease(OP, 5))
    before = json.loads(state.read_text())["resources"]
    result = _sweep(run)
    assert result.returncode != 0
    # The misattribution pass, audit round 1: the retained Lease of a DEAD run also reads "live" for 180 s; the
    # refusal states the age it measured and the wait, never "stop that tools process"
    assert "is still live" in result.stderr and "was renewed" in result.stderr and "run the same command again" in result.stderr
    assert "sweep never takes a live operation" in result.stderr and "stop that tools process" not in result.stderr
    assert json.loads(state.read_text())["resources"] == before
    assert not _records(work)
    assert json.loads((work / "operation.json").read_text())["status"] == "initializing"


def test_sweep_refuses_a_stale_held_lease_and_names_abandon(runtime, tmp_path):
    run, state, work = runtime
    _dead_target(state, work, tmp_path, lease=_lease(OP, 3600))
    result = _sweep(run)
    assert result.returncode != 0
    assert f"abandon --operation {OP}" in result.stderr
    assert not _records(work)


@pytest.mark.parametrize("what", ["helm-history", "controller"])
def test_sweep_never_removes_a_deployment(runtime, tmp_path, what):
    run, state, work = runtime
    extra = [_foreign_release()] if what == "helm-history" else [
        {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "synthetic-release-web", "uid": "dep",
                                                                     "labels": {"app.kubernetes.io/instance": "synthetic-release"}}}]
    _dead_target(state, work, tmp_path, extra_resources=extra)
    result = _sweep(run)
    assert result.returncode != 0
    assert ("uninstall it" if what == "helm-history" else "controller(s)") in result.stderr
    assert "Job/synthetic-release-provision" in json.loads(state.read_text())["resources"]
    assert not _records(work)


def test_sweep_requires_a_printable_reason(runtime, tmp_path):
    run, state, work = runtime
    _dead_target(state, work, tmp_path)
    assert "requires --reason" in _sweep(run, "").stderr
    assert "one line" in run("ABANDON_REASON=$'two\\nlines'\nsweep_target\n").stderr
    assert not _records(work)


def test_sweep_clears_the_dead_residue_evidence_first_and_keeps_the_claims(runtime, tmp_path):
    run, state, work = runtime
    transfer = _dead_target(state, work, tmp_path)
    result = _sweep(run)
    assert result.returncode == 0, result.stderr
    records = _records(work)
    assert len(records) == 1 and records[0].name.endswith(f"-{OP}.json")
    evidence = json.loads(records[0].read_text())
    assert evidence["format"] == "gsj.target-swept/1"
    assert evidence["reason"].startswith("synthetic:") and "@" in evidence["swept_by"]
    assert evidence["canonical"] == {"operation": OP, "status": "initializing", "disposition": "retained, marked swept"}
    deleted = {(o["kind"], o["name"]): o["uid"] for o in evidence["deleted"]["objects"]}
    assert deleted == {("Job", "synthetic-release-provision"): "uid-job-synthetic-release-provision",
                       ("ConfigMap", "synthetic-release-installed"): "uid-configmap-synthetic-release-installed",
                       ("ConfigMap", "synthetic-release-provisioned"): "uid-configmap-synthetic-release-provisioned",
                       ("ConfigMap", "synthetic-release-verify-1234abcd-a1"): "uid-configmap-synthetic-release-verify-1234abcd-a1",
                       ("Secret", "synthetic-release-admin-token"): "uid-secret-synthetic-release-admin-token",
                       ("Secret", "synthetic-release-agent-token"): "uid-secret-synthetic-release-agent-token"}
    assert evidence["deleted"]["transfer_directories"] == [str(transfer / OP)]
    assert evidence["kept"]["persistent_volume_claims"] == "untouched"
    assert "NOT revoked" in evidence["kept"]["forgejo_tokens"]
    left = json.loads(state.read_text())["resources"]
    assert set(left) == {"Secret/synthetic-release-tls", "Secret/operator-supplied-registry", "PersistentVolumeClaim/synthetic-release-data"}
    assert not (transfer / OP).exists() and (transfer / "zzz-not-ours").is_dir()
    assert not (work / "lease-lost").exists()
    canonical = json.loads((work / "operation.json").read_text())
    assert canonical["status"] == "swept" and canonical["swept"]["record"] == str(records[0]) and canonical["operation"] == OP
    assert "Swept synthetic-release" in result.stderr and "claims untouched" in result.stderr
    # the record was written BEFORE any deletion: it lists what the cluster held
    assert records[0].stat().st_mode & 0o077 == 0


def test_sweep_deletes_the_tls_secret_only_when_the_installer_made_it(runtime, tmp_path):
    run, state, work = runtime
    _dead_target(state, work, tmp_path, tls_profile="managed-local-ca")
    result = _sweep(run)
    assert result.returncode == 0, result.stderr
    assert "Secret/synthetic-release-tls" not in json.loads(state.read_text())["resources"]
    assert "Secret/operator-supplied-registry" in json.loads(state.read_text())["resources"]


def test_sweep_with_nothing_stranded_is_a_noop(runtime, tmp_path):
    run, state, work = runtime
    _dead_target(state, work, tmp_path, status="complete")
    value = json.loads(state.read_text()); value["resources"] = {"PersistentVolumeClaim/synthetic-release-data": value["resources"]["PersistentVolumeClaim/synthetic-release-data"]}
    state.write_text(json.dumps(value))
    site = json.loads((work / "site.json").read_text()); site["storage"]["transfer_path"] = ""; (work / "site.json").write_text(json.dumps(site))
    result = _sweep(run)
    assert result.returncode == 0, result.stderr
    assert "Nothing to sweep" in result.stderr and not _records(work)
    assert json.loads((work / "operation.json").read_text())["status"] == "complete"


def test_the_canonical_guard_admits_a_swept_record():
    """The acquire path admits complete / backup-complete / abandoned / swept and
    refuses everything else — pinned on the runtime's own jq expression."""
    text = (INSTALLER / "runtime.sh").read_text()
    guard = re.search(r"\(\.status\|IN\(([^)]*)\)\)", text).group(1)
    admitted = set(re.findall(r'"([a-z-]+)"', guard))
    assert admitted == {"complete", "backup-complete", "abandoned", "swept"}
    assert "sweep_target; return" in text and "gsj-install.sh sweep" in text


def test_sweep_of_a_target_whose_intents_left_no_transfer_directory_still_runs(runtime, tmp_path):
    """Found by running it on a reference k3s cluster: the real orphan (its
    transfer directories already removed by hand, its record without a live
    operation) made the verb exit 1 with no message — a false `[[ ]] &&` at the
    end of a command substitution under errexit/pipefail. The verb must run to
    its verdict on that shape."""
    run, state, work = runtime
    transfer = _dead_target(state, work, tmp_path, status="abandoned")
    import shutil; shutil.rmtree(transfer / OP)                       # nothing of ours left under the path
    (work / "operation-intents" / ("e" * 24)).mkdir()                 # a second intent, also without a directory
    result = _sweep(run)
    assert result.returncode == 0, result.stderr
    assert "Swept synthetic-release" in result.stderr
    evidence = json.loads(_records(work)[0].read_text())
    assert evidence["deleted"]["transfer_directories"] == []
    assert (transfer / "zzz-not-ours").is_dir()


def test_sweep_of_a_target_without_a_canonical_record_clears_the_cluster_residue(runtime, tmp_path):
    run, state, work = runtime
    _dead_target(state, work, tmp_path)
    (work / "operation.json").unlink()
    result = _sweep(run)
    assert result.returncode == 0, result.stderr
    records = _records(work)
    assert len(records) == 1 and records[0].name.endswith("-none.json")
    assert json.loads(records[0].read_text())["canonical"] == {"operation": None, "status": None, "disposition": "retained, marked swept"}
    assert "Job/synthetic-release-provision" not in json.loads(state.read_text())["resources"]
    assert not (work / "operation.json").exists()


def test_a_namespace_that_could_not_be_read_is_not_taken_for_absent(runtime, tmp_path):
    """The misattribution pass: `if k get namespace …` treated an
    expired kubeconfig, an RBAC denial or an API outage as "the namespace is
    gone", skipped the Lease, release and controller checks, deleted the
    transfer directories and reported a clean target."""
    run, state, work = runtime
    transfer = _dead_target(state, work, tmp_path)
    value = json.loads(state.read_text()); value["namespace_read_fails"] = True; state.write_text(json.dumps(value))
    result = _sweep(run)
    assert result.returncode == 1
    assert "could not be read" in result.stderr and "nothing was swept" in result.stderr
    assert not _records(work), "no swept record for a target that could not be read"
    assert (transfer / OP / "snapshot.tar.gz").exists(), "the transfer directory is untouched"
