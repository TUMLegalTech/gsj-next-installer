"""Actual repair/resume Bash with synthetic Lease, storage and backup bytes."""
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
from datetime import datetime, timezone

import pytest

from tests.test_installer import _site, _release
from tests.test_installer_backup_retry import maintenance, _cluster

OPERATION = "a" * 24
OLD_TIME = "2020-01-01T00:00:00.000000Z"
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def repair_shell(maintenance, tmp_path):
    m = maintenance
    site = _site()
    site["target"].update(namespace="legal", release="gsj")
    site["storage"]["class"] = "synthetic"
    site["backup"]["offbox_url"] = ""
    (m["work"] / "site.json").write_text(json.dumps(site))
    (m["state"] / "site.pending.json").write_text(json.dumps(site))
    (m["state"] / "input-site.json").write_text(json.dumps(site))
    (m["state"] / "values.pending.json").write_bytes((m["work"] / "values.pending.json").read_bytes())
    installed_path = m["work"] / "installed.json"
    installed = json.loads(installed_path.read_text())
    installed["site"] = site
    installed_path.write_text(json.dumps(installed))
    operation = {"operation": OPERATION, "target": "source-release", "kind": "backup", "status": "owned"}
    (m["state"] / "operation.json").write_text(json.dumps(operation))
    lease = {"apiVersion": "coordination.k8s.io/v1", "kind": "Lease",
             "metadata": {"name": "gsj-operation", "resourceVersion": "1"},
             "spec": {"holderIdentity": OPERATION, "leaseDurationSeconds": 180, "renewTime": OLD_TIME}}
    _cluster(m, lambda state: state.update(lease=lease, ready_on_scale=True))
    fake = tmp_path / "repair-k.py"
    original = (tmp_path / "k.py").read_text()
    prefix = '''if a[:2]==['get','lease']: result=s['lease']
elif a[:1]==['replace']:
 obj=json.load(sys.stdin)
 if s.get('conflict_replace') or obj['metadata']['resourceVersion']!=s['lease']['metadata']['resourceVersion']:
  p.write_text(json.dumps(s)); raise SystemExit(31)
 obj['metadata']['resourceVersion']=str(int(obj['metadata']['resourceVersion'])+1); s['lease']=obj
elif a[:1]==['wait']: pass
elif a[:2]==['get','namespace']'''
    fake.write_text(original.replace("if a[:2]==['get','namespace']", prefix))
    payload = tmp_path / "payload"
    payload.mkdir()
    (payload / "compile.jq").write_bytes((ROOT / "ops/installer/compile.jq").read_bytes())
    (payload / "defaults.json").write_bytes((ROOT / "ops/installer/defaults.json").read_bytes())
    release = _release()
    release.update(identity="target-release", supported_sources=["source-release"])
    (payload / "release.json").write_text(json.dumps(release))
    env = {**m["env"], "OPERATION": OPERATION, "SITE": str(m["work"] / "site.json"),
           "GSJ_PAYLOAD": str(payload), "SITE_DIR": str(m["work"])}

    def run(body, *, release="source-release"):
        script = f'''source {shlex.quote(str(tmp_path / 'functions.sh'))}
RESUME_ID={OPERATION}; GENERATION=1; RELEASE_ID={shlex.quote(release)}; CONFIG="$STATE_DIR/input-site.json"; RENEWER=''; LEASE_ACQUIRED=false
k() {{ {shlex.quote(sys.executable)} {shlex.quote(str(fake))} "$@"; }}
start_renewal() {{ :; }}
read_installed() {{ :; }}
capacity_qualify() {{ :; }}
capacity_scan_pod() {{ :; }}
backup_credential_fingerprint() {{ printf '%064d\\n' 0; }}
maintenance_pod() {{ :; }}
offbox_backup() {{ :; }}
backup_resources() {{ for f in cluster-private.json volumes-private.json site_inputs.json; do printf '{{}}' > "$GSJ_WORK/$f"; done; }}
secret_inputs() {{ printf 'secrets\\n' >> "$STATE_DIR/actions"; }}
managed_dependencies() {{ printf 'dependencies\\n' >> "$STATE_DIR/actions"; }}
helm_apply() {{ printf 'helm\\n' >> "$STATE_DIR/actions"; }}
wait_application() {{ printf 'ready\\n' >> "$STATE_DIR/actions"; }}
record_ready() {{ printf 'record-ready\\n' >> "$STATE_DIR/actions"; }}
verify_application() {{ printf 'verify\\n' >> "$STATE_DIR/actions"; }}
record_installed() {{ printf 'record-installed\\n' >> "$STATE_DIR/actions"; }}
{body}
'''
        return subprocess.run(["bash", "-c", script], env=env, text=True, capture_output=True, timeout=30)

    result = run("quiesce")
    assert result.returncode == 0, result.stderr
    partial = m["backups"] / (OPERATION + ".tar.gz.enc.partial")
    partial.write_bytes(b"original encrypted partial must survive wrapper retries")
    _cluster(m, lambda state: state.update(calls=[]))
    return {**m, "run_shell": run, "partial": partial, "installed": installed_path,
            "site": m["work"] / "site.json", "snapshot": m["state"] / f"quiescence-{OPERATION}.json"}


def _operation(m, **changes):
    path = m["state"] / "operation.json"
    value = json.loads(path.read_text())
    value.update(changes)
    path.write_text(json.dumps(value))
    return value


def _link(m):
    return {"installer": "target-release", "prior_target": "source-release", "source": "source-release",
            "site_sha256": hashlib.sha256(m["site"].read_bytes()).hexdigest(), "prior_status": "verifying"}


def _replacement_source(m):
    # Construct a consistent original verification-pending source fixture;
    # this is fixture setup, not a runtime rewrite of captured evidence.
    value = json.loads(m["installed"].read_text())
    value["status"] = "verification-pending"
    m["installed"].write_text(json.dumps(value))
    snapshot = json.loads(m["snapshot"].read_text())
    snapshot["installed"] = value
    m["snapshot"].write_text(json.dumps(snapshot))
    closure_path = Path(str(m["snapshot"]) + ".closure.json")
    closure = json.loads(closure_path.read_text())
    closure["snapshot_sha256"] = hashlib.sha256(m["snapshot"].read_bytes()).hexdigest()
    closure_path.write_text(json.dumps(closure))


def test_backup_repair_retains_exact_expired_owner_and_kind_until_resume(repair_shell):
    m = repair_shell
    original = m["partial"].read_bytes()
    result = m["run_shell"]("backup_repair_operation")
    assert result.returncode == 0, result.stderr
    state = json.loads(m["cluster"].read_text())
    assert state["lease"]["spec"]["holderIdentity"] == OPERATION
    assert state["lease"]["spec"]["renewTime"] == OLD_TIME
    operation = json.loads((m["state"] / "operation.json").read_text())
    assert (operation["kind"], operation["target"], operation["status"], operation["backup_generation"]) == ("backup", "source-release", "backup-verified", 1)
    assert m["partial"].read_bytes() == original
    assert not (m["state"] / "actions").exists()
    assert "resume --operation" in result.stderr


def test_repeat_selected_completed_generation_never_overwrites_or_releases_owner(repair_shell):
    m = repair_shell
    assert m["run_shell"]("backup_repair_operation").returncode == 0
    artifacts = {p.name: p.read_bytes() for p in m["backups"].iterdir()}
    before = json.loads(m["cluster"].read_text())["lease"]
    again = m["run_shell"]("backup_repair_operation")
    assert again.returncode != 0  # Already verified: the next verb is resume.
    assert {p.name: p.read_bytes() for p in m["backups"].iterdir()} == artifacts
    assert json.loads(m["cluster"].read_text())["lease"] == before


@pytest.mark.parametrize("failure", ["holder", "fresh", "site", "phase", "target", "source", "cas", "kind"])
def test_backup_repair_rejects_changed_authority_or_source_and_preserves_artifacts(repair_shell, failure):
    m = repair_shell
    if failure == "holder": _cluster(m, lambda s: s["lease"]["spec"].update(holderIdentity="foreign"))
    elif failure == "fresh": _cluster(m, lambda s: s["lease"]["spec"].update(renewTime=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000000Z")))
    elif failure == "site": m["site"].write_bytes(m["site"].read_bytes() + b"\n")
    elif failure == "phase": _operation(m, status="applying")
    elif failure == "target": _operation(m, target="unrelated-target")
    elif failure == "source":
        value = json.loads(m["installed"].read_text()); value["manifest"]["identity"] = "different-source"; m["installed"].write_text(json.dumps(value))
    elif failure == "cas": _cluster(m, lambda s: s.update(conflict_replace=True))
    else: _operation(m, kind="restore")
    before = {p.name: p.read_bytes() for p in m["backups"].iterdir()}
    result = m["run_shell"]("backup_repair_operation")
    assert result.returncode != 0
    assert {p.name: p.read_bytes() for p in m["backups"].iterdir()} == before
    assert not any(a[0] == "scale" for a in json.loads(m["cluster"].read_text())["calls"])
    assert not (m["state"] / "actions").exists()


def test_failed_new_archive_keeps_owner_new_partial_and_old_recovery_point(repair_shell):
    m = repair_shell
    result = m["run_shell"]('''backup() { archive=$(backup_archive); printf 'new interrupted bytes' > "$archive.partial"; return 82; }
backup_repair_operation
''')
    assert result.returncode == 82
    state = json.loads(m["cluster"].read_text())
    assert state["lease"]["spec"]["holderIdentity"] == OPERATION
    assert state["lease"]["spec"]["renewTime"] != OLD_TIME
    assert m["partial"].read_bytes() == b"original encrypted partial must survive wrapper retries"
    assert (m["backups"] / f"{OPERATION}.g1.tar.gz.enc.partial").read_bytes() == b"new interrupted bytes"
    assert not (m["state"] / "actions").exists()


def test_replacement_backup_recovery_keeps_old_target_and_new_installer_link(repair_shell):
    m = repair_shell
    _replacement_source(m)
    link = _link(m)
    _operation(m, kind="install", status="repair-backing-up", repair_backup=link)
    result = m["run_shell"]("backup_repair_operation", release="target-release")
    assert result.returncode == 0, result.stderr
    operation = json.loads((m["state"] / "operation.json").read_text())
    assert operation["target"] == "source-release" and operation["kind"] == "install"
    assert operation["repair_backup"] == link
    assert "repair --operation" in result.stderr
    assert json.loads(m["cluster"].read_text())["lease"]["spec"]["renewTime"] == OLD_TIME


@pytest.mark.parametrize("field", ["source", "prior_target", "installer", "site_sha256"])
def test_changed_replacement_linkage_refuses_before_generation_mutation(repair_shell, field):
    m = repair_shell
    _replacement_source(m)
    link = _link(m)
    link[field] = "changed"
    _operation(m, kind="install", status="repair-backing-up", repair_backup=link)
    before = {p.name: p.read_bytes() for p in m["backups"].iterdir()}
    result = m["run_shell"]("backup_repair_operation", release="target-release")
    assert result.returncode != 0
    assert {p.name: p.read_bytes() for p in m["backups"].iterdir()} == before
    assert "backup_generation" not in json.loads((m["state"] / "operation.json").read_text())


def test_matching_old_target_cannot_bypass_recorded_new_installer_repair_context(repair_shell):
    m = repair_shell
    _replacement_source(m)
    _operation(m, kind="install", status="repair-backing-up", repair_backup=_link(m))
    before = json.loads(m["cluster"].read_text())["lease"]
    result = m["run_shell"]("backup_repair_operation", release="source-release")
    assert result.returncode != 0
    assert json.loads(m["cluster"].read_text())["lease"] == before
    assert "backup_generation" not in json.loads((m["state"] / "operation.json").read_text())


def test_repair_captures_source_target_link_before_a_failed_backup(repair_shell):
    m = repair_shell
    _replacement_source(m)
    _operation(m, kind="install", status="verifying")
    result = m["run_shell"]("backup() { return 83; }; repair_operation", release="target-release")
    assert result.returncode == 83, result.stderr
    operation = json.loads((m["state"] / "operation.json").read_text())
    assert operation["status"] == "repair-backing-up"
    assert operation["target"] == "source-release"
    assert operation["repair_backup"] == _link(m)
    assert not (m["state"] / "actions").exists()


@pytest.mark.parametrize("phase", ["backup-verified", "backup-restarting"])
def test_named_backup_resume_uses_selected_generation_and_original_replica_snapshot(repair_shell, phase):
    m = repair_shell
    assert m["run_shell"]("backup_repair_operation").returncode == 0
    _operation(m, status=phase)
    before = {p.name: p.read_bytes() for p in m["backups"].iterdir()}
    result = m["run_shell"]("resume_operation")
    assert result.returncode == 0, result.stderr
    assert {p.name: p.read_bytes() for p in m["backups"].iterdir()} == before
    assert all(d["spec"]["replicas"] == 1 for d in json.loads(m["cluster"].read_text())["controllers"]["items"])
    assert json.loads((m["state"] / "operation.json").read_text())["status"] == "backup-complete"
    assert not (m["state"] / "actions").exists()


def test_deployment_resume_after_verified_backup_prepares_dependencies_before_helm(repair_shell):
    m = repair_shell
    _operation(m, kind="upgrade", status="backup-verified")
    result = m["run_shell"]("resume_operation")
    assert result.returncode == 0, result.stderr
    assert (m["state"] / "actions").read_text().splitlines() == ["secrets", "dependencies", "helm", "ready", "record-ready", "verify", "record-installed"]


def test_same_selected_failed_generation_refuses_and_next_generation_keeps_both_partials(repair_shell):
    m = repair_shell
    first = m["run_shell"]('backup() { archive=$(backup_archive); printf next-partial > "$archive.partial"; return 82; }; backup_repair_operation')
    assert first.returncode == 82
    _cluster(m, lambda s: s["lease"]["spec"].update(renewTime=OLD_TIME))
    before = {p.name: p.read_bytes() for p in m["backups"].iterdir()}
    same = m["run_shell"]("backup_repair_operation")
    assert same.returncode != 0
    assert {p.name: p.read_bytes() for p in m["backups"].iterdir()} == before
    _cluster(m, lambda s: s["lease"]["spec"].update(renewTime=OLD_TIME))
    second = m["run_shell"]("GENERATION=2; backup_repair_operation")
    assert second.returncode == 0, second.stderr
    assert all((m["backups"] / name).read_bytes() == data for name, data in before.items())
    assert json.loads((m["state"] / "operation.json").read_text())["backup_generation"] == 2


def test_verified_repair_link_is_retired_before_target_promotion_and_not_reused_as_current_context(repair_shell):
    m = repair_shell
    _replacement_source(m)
    _operation(m, kind="install", status="repair-backing-up", repair_backup=_link(m))
    prepared = m["run_shell"]("backup_repair_operation", release="target-release")
    assert prepared.returncode == 0, prepared.stderr
    original_artifacts = {p.name: p.read_bytes() for p in m["backups"].iterdir()}
    result = m["run_shell"]('''helm_apply() { jq '.status="applying"' "$STATE_DIR/operation.json" | atomic "$STATE_DIR/operation.json"; return 84; }
repair_operation
''', release="target-release")
    assert result.returncode == 84, result.stderr
    operation = json.loads((m["state"] / "operation.json").read_text())
    assert operation["target"] == "target-release" and "repair_backup" not in operation
    assert len(operation["repair_backup_history"]) == 1
    history = operation["repair_backup_history"][0]
    assert "source" not in history
    assert history["observed_source"] == history["archive_source"] == "source-release"
    assert history["prior_target"] == "source-release"
    assert history["installer"] == "target-release" and history["archive"].endswith(f"{OPERATION}.g1.tar.gz.enc")
    assert all((m["backups"] / name).read_bytes() == data for name, data in original_artifacts.items())
    _cluster(m, lambda s: s["lease"]["spec"].update(renewTime=OLD_TIME))
    # No Helm mutation happened in this fixture: prove a fresh context can be
    # opened without mistaking old linkage for current source/configuration.
    again = m["run_shell"]("backup() { return 85; }; repair_operation", release="target-release")
    assert again.returncode == 85, again.stderr
    current = json.loads((m["state"] / "operation.json").read_text())
    assert current["repair_backup"]["prior_target"] == "target-release"
    assert current["repair_backup"]["source"] == "source-release"
    assert current["repair_backup"]["site_sha256"] == hashlib.sha256(m["site"].read_bytes()).hexdigest()
    assert current["repair_backup_history"] == operation["repair_backup_history"]


def _before_backup(m):
    """A capacity precheck failure has not started quiescence or an archive."""
    m['snapshot'].unlink()
    Path(str(m['snapshot']) + '.closure.json').unlink()
    m['partial'].unlink()
    def ready(state):
        for controller in state['controllers']['items']:
            controller['spec']['replicas'] = 1
            controller['status'] = {'observedGeneration': controller['metadata']['generation'],
                                    'readyReplicas': 1, 'availableReplicas': 1}
    _cluster(m, ready)
    link = _link(m)
    link['installer'] = 'failed-repair-program'
    _operation(m, kind='install', status='repair-backing-up', repair_backup=link)
    payload = m['work'].parent / 'payload' / 'release.json'
    release = json.loads(payload.read_text())
    release['supported_sources'].append('failed-repair-program')
    payload.write_text(json.dumps(release))
    return link, payload


def test_corrected_repair_program_preserves_failed_prebackup_intent(repair_shell):
    m = repair_shell
    previous, _ = _before_backup(m)
    # The separate source-selection suite exercises real workload projection.
    # Here prove its mandatory ordering before the repair context is changed.
    audit = 'read_backup_source() { printf "source-audit\\n" >> "$STATE_DIR/source-audit"; }; '
    result = m['run_shell'](audit + 'prepare_repair_backup source-release', release='target-release')
    assert result.returncode == 0, result.stderr
    path = m['state'] / 'operation.json'
    operation = json.loads(path.read_text())
    assert operation['target'] == 'source-release'
    assert operation['repair_backup'] == {**previous, 'installer': 'target-release'}
    assert operation['repair_backup_history'] == [{**previous, 'status': 'superseded-before-backup',
                                                 'replacement_installer': 'target-release'}]
    before = path.read_bytes()
    again = m['run_shell']('prepare_repair_backup source-release', release='target-release')
    assert again.returncode == 0, again.stderr
    assert path.read_bytes() == before
    assert (m['state'] / 'source-audit').read_text() == 'source-audit\n'
    calls = json.loads(m['cluster'].read_text())['calls']
    assert not any(call[0] in ('create', 'scale', 'delete', 'exec') for call in calls)


@pytest.mark.parametrize('fault', ['undeclared', 'source', 'site', 'prior-target', 'phase',
                                   'snapshot', 'archive', 'symlink', 'round', 'generation',
                                   'stopped', 'unready', 'maintenance', 'source-audit', 'source-record'])
def test_corrected_repair_program_refuses_changed_or_started_backup(repair_shell, fault):
    m = repair_shell
    _, payload = _before_backup(m)
    path = m['state'] / 'operation.json'
    operation = json.loads(path.read_text())
    prefix = 'read_backup_source() { :; }; '
    if fault == 'undeclared':
        release = json.loads(payload.read_text()); release['supported_sources'].remove('failed-repair-program')
        payload.write_text(json.dumps(release))
    elif fault in ('source', 'site', 'prior-target'):
        key = {'source': 'source', 'site': 'site_sha256', 'prior-target': 'prior_target'}[fault]
        operation['repair_backup'][key] = 'different'
    elif fault == 'phase': operation['status'] = 'backing-up'
    elif fault == 'snapshot': m['snapshot'].write_text('{}')
    elif fault == 'archive': m['partial'].write_bytes(b'preserve partial')
    elif fault == 'symlink': m['snapshot'].symlink_to(m['state'] / 'absent')
    elif fault in ('round', 'generation'): operation['backup_' + fault] = 1
    elif fault in ('stopped', 'unready'):
        def drift(state):
            controller = state['controllers']['items'][0]
            if fault == 'stopped': controller['spec']['replicas'] = 0
            else: controller['status']['readyReplicas'] = 0
        _cluster(m, drift)
    elif fault == 'source-audit': prefix = 'read_backup_source() { return 92; }; '
    elif fault == 'source-record': prefix = 'read_backup_source() { jq \' .namespace_uid="recreated" \' "$GSJ_WORK/installed.json" | atomic "$GSJ_WORK/installed.json"; }; '
    else: prefix = "k() { printf '{}\\n'; }; "
    path.write_text(json.dumps(operation))
    before = path.read_bytes()
    result = m['run_shell'](prefix + 'prepare_repair_backup source-release', release='target-release')
    assert result.returncode != 0
    assert path.read_bytes() == before
    assert not any(call[0] in ('create', 'scale', 'delete', 'exec')
                   for call in json.loads(m['cluster'].read_text())['calls'])
    if fault == 'archive': assert m['partial'].read_bytes() == b'preserve partial'
    if fault == 'symlink': assert m['snapshot'].is_symlink()
