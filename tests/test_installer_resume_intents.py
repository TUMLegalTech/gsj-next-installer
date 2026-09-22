"""The named resume entry point recovers Lease-first acquisition interruptions."""
import json

import pytest

from tests.test_installer import _foreign_release, _lease, _site, runtime
from tests.test_installer_operation_intents import interrupted


@pytest.mark.parametrize("conflict", [False, True])
def test_resume_promotes_only_after_winning_cas_then_continues_same_install(runtime, conflict):
    invoke, state, work, _, operation, _ = interrupted(runtime)
    cluster = json.loads(state.read_text())
    cluster["lease"]["spec"]["renewTime"] = "2000-01-01T00:00:00.000000Z"
    cluster["conflict_replace"] = conflict
    state.write_text(json.dumps(cluster))
    result = invoke('''RESUME_ID="$ID"; COMMAND=resume
compatibility() { : > "$GSJ_WORK/installed.json"; }
secret_inputs() { printf 'credentials\n' >> "$GSJ_WORK/actions"; }
managed_dependencies() { printf 'dependencies\n' >> "$GSJ_WORK/actions"; }
storage_probe() { printf 'storage\n' >> "$GSJ_WORK/actions"; }
helm_apply() { printf 'helm\n' >> "$GSJ_WORK/actions"; }
wait_application() { printf 'ready\n' >> "$GSJ_WORK/actions"; }
record_ready() { printf 'record-ready\n' >> "$GSJ_WORK/actions"; }
verify_application() { printf 'verify\n' >> "$GSJ_WORK/actions"; }
record_installed() { printf 'record-complete\n' >> "$GSJ_WORK/actions"; }
resume_operation
''', ID=operation)
    if conflict:
        assert result.returncode != 0
        assert not (work / "operation.json").exists()
        assert not (work / "actions").exists()
    else:
        assert result.returncode == 0, result.stderr
        assert json.loads((work / "operation.json").read_text())["operation"] == operation
        assert (work / "actions").read_text().splitlines() == [
            "credentials", "dependencies", "storage", "helm", "ready", "record-ready", "verify", "record-complete"]
    assert json.loads(state.read_text())["lease"]["spec"]["holderIdentity"] == operation


def test_resume_refuses_a_foreign_release_for_an_owned_install(runtime):
    """A foreign release is refused on the resume path too. An install interrupted
    between its Lease and its Helm apply is continued by `resume`, and the
    install refusal itself sends the operator there ("Use resume --operation
    ..."). Its owned phase has not applied yet, so a Helm release of the
    target name is foreign here too — a pre-fix installer that stopped inside
    that window against a pilot-shaped namespace leaves exactly this state.
    The resumed install is refused with the same named reason, before any
    credential, dependency, storage or Helm step."""
    invoke, state, work, _, operation, _ = interrupted(runtime)
    cluster = json.loads(state.read_text())
    cluster["lease"]["spec"]["renewTime"] = "2000-01-01T00:00:00.000000Z"
    cluster["resources"] = {"Secret/sh.helm.release.v1.synthetic-release.v1": _foreign_release()}
    state.write_text(json.dumps(cluster))
    result = invoke('''RESUME_ID="$ID"; COMMAND=resume
h() { printf %s '[{"revision":2,"status":"deployed","chart":"gsj-0.9.1-beta.23","app_version":"0.9.1-beta.23"}]'; }
compatibility() { printf 'compatibility\n' >> "$GSJ_WORK/actions"; }
secret_inputs() { printf 'credentials\n' >> "$GSJ_WORK/actions"; }
managed_dependencies() { printf 'dependencies\n' >> "$GSJ_WORK/actions"; }
storage_probe() { printf 'storage\n' >> "$GSJ_WORK/actions"; }
helm_apply() { printf 'helm\n' >> "$GSJ_WORK/actions"; }
wait_application() { printf 'ready\n' >> "$GSJ_WORK/actions"; }
resume_operation
''', ID=operation)
    assert result.returncode != 0
    assert "no installer record" in result.stderr and "revision 2" in result.stderr, result.stderr
    assert not (work / "actions").exists(), "the refusal must precede every step of the owned phase"


def _route_resume(runtime, phase, change, renewal=":"):
    """Resume a saved operation after the operator moved its verification route
    from host.docker.internal:18446 to node-control-plane:30443 (plus `change`)."""
    run, state, work = runtime
    operation = "c" * 24
    lease = _lease(operation)
    lease["spec"]["renewTime"] = "2000-01-01T00:00:00.000000Z"
    state.write_text(json.dumps({"lease": lease, "calls": []}))
    (work / "operation.json").write_text(json.dumps({"operation": operation, "target": "synthetic-release",
                                                      "kind": "install", "status": phase}))
    retained = _site()
    retained["verification"].update(connect_host="host.docker.internal", connect_port=18446)
    if change.get("managed_ca"):  # an operation saved before the installer derived its CA paths
        retained["tls"].update(profile="managed-local-ca", ca_file="")
        (work / "tls").mkdir()
        (work / "tls/ca.crt").write_text("synthetic CA")
    selected = json.loads(json.dumps(retained))
    selected["verification"].update(connect_host="node-control-plane", connect_port=30443)
    if change.get("managed_ca"):
        selected["tls"]["ca_file"] = selected["verification"]["ca_file"] = str(work / "tls/ca.crt")
    if "public_url" in change: selected["public_url"] = change["public_url"]
    if "ca_file" in change: selected["verification"]["ca_file"] = change["ca_file"]
    if "profile" in change: selected["tls"]["profile"] = change["profile"]
    if "upload_mb" in change: selected["limits"]["upload_mb"] = change["upload_mb"]
    (work / "retained-input.json").write_text(json.dumps(retained))
    (work / "selected-input.json").write_text(json.dumps(selected))
    (work / "operation-intents" / operation).mkdir(parents=True)
    if change.get("continued"):  # a startup Helm continuation's intent binds the saved site
        (work / f"startup-helm-{operation}").mkdir()
        (work / f"startup-helm-{operation}" / "intent.json").write_text("{}")
    # Both site files go through jq, as load_site and stage_operation_config write them.
    result = run(f'''jq . "$TEST_WORK/retained-input.json" > "$STATE_DIR/site.pending.json"
jq . "$TEST_WORK/selected-input.json" > "$SITE"
cp "$STATE_DIR/site.pending.json" "$TEST_WORK/site.before.json"
cp "$STATE_DIR/site.pending.json" "$TEST_WORK/operation-intents/{operation}/site.json"
RESUME_ID={operation}; COMMAND=resume
start_renewal() {{ {renewal}; }}
record_action() {{ printf '%s\\n' "$1" >> "$GSJ_WORK/actions"; }}
compatibility() {{ record_action compatibility; }}; secret_inputs() {{ record_action credentials; }}
managed_dependencies() {{ record_action dependencies; }}; storage_probe() {{ record_action storage; }}
helm_apply() {{ record_action helm; }}; helm_application_validate() {{ record_action validate; }}
wait_application() {{ record_action ready; }}; record_ready() {{ record_action record-ready; }}
verify_application() {{ record_action verify; }}; record_installed() {{ record_action record-complete; }}
resume_operation
''')
    return result, work, operation


@pytest.mark.parametrize("phase,change,admitted", [
    ("verifying", {}, True),
    ("verifying", {"managed_ca": True}, True),
    ("owned", {}, False),
    ("applying", {}, False),
    ("initializing", {}, False),
    ("backup-verified", {}, False),
    ("verifying", {"public_url": "https://other.example"}, False),
    ("verifying", {"ca_file": "/operator/ca.crt"}, False),
    ("verifying", {"profile": "files"}, False),
    ("verifying", {"upload_mb": 128}, False),
])
def test_resume_admits_only_a_verifying_route_correction(runtime, phase, change, admitted):
    result, work, operation = _route_resume(runtime, phase, change)
    before = (work / "site.before.json").read_bytes()
    assert (work / "operation-intents" / operation / "site.json").read_bytes() == before
    if not admitted:
        assert result.returncode != 0
        assert "resume configuration changed" in result.stderr
        assert (work / "site.pending.json").read_bytes() == before
        assert not (work / "actions").exists()
        return
    assert result.returncode == 0, result.stderr
    assert ("Verification route corrected for resume: host.docker.internal:18446 -> node-control-plane:30443"
            in result.stderr)
    pending, prior = json.loads((work / "site.pending.json").read_text()), json.loads(before)
    assert pending["verification"] == {**prior["verification"], "connect_host": "node-control-plane", "connect_port": 30443}
    pending["verification"] = prior["verification"]
    assert pending == prior  # nothing but the two route fields moved
    if not change:
        assert (work / "site.pending.json").read_bytes() == (work / "site.json").read_bytes()
    assert (work / "actions").read_text().splitlines() == ["ready", "record-ready", "verify", "record-complete"]


def test_a_continued_operation_keeps_its_saved_route_on_resume(runtime):
    result, work, _ = _route_resume(runtime, "verifying", {"continued": True})
    assert result.returncode != 0
    assert "a continued operation keeps its exact saved configuration, including its verification route" in result.stderr
    assert (work / "site.pending.json").read_bytes() == (work / "site.before.json").read_bytes()
    assert not (work / "actions").exists()


def test_route_correction_rechecks_ownership_before_its_write(runtime):
    other = "f" * 24
    lost = f'''jq '.lease.spec.holderIdentity="{other}"' "$TEST_KUBECTL_STATE" > "$TEST_WORK/lease.json" && mv "$TEST_WORK/lease.json" "$TEST_KUBECTL_STATE"'''
    result, work, _ = _route_resume(runtime, "verifying", {}, renewal=lost)
    assert result.returncode != 0
    assert "operation ownership changed" in result.stderr
    assert (work / "site.pending.json").read_bytes() == (work / "site.before.json").read_bytes()
    assert not (work / "actions").exists()
