"""Capacity qualification on temporary filesystems and fake Kubernetes objects."""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import sqlite3
import subprocess
import sys

import pytest

from gsj_deploy import backup
from tests.test_installer_backup_retry import maintenance

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("installer_capacity", ROOT / "ops/installer/capacity.py")
capacity = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capacity)


@pytest.fixture
def source_volumes(tmp_path):
    result = {}
    for role, database in capacity.ROLES.items():
        root = tmp_path / "volumes" / role
        path = root / database
        path.parent.mkdir(parents=True)
        with sqlite3.connect(path) as db:
            db.execute("CREATE TABLE fixture (id INTEGER)")
            db.execute("INSERT INTO fixture VALUES (7)")
        result[role] = str(root)
    return result


def fs(identity="a", available=100 * 1024 ** 3, inodes=100000):
    return {"filesystem_id": identity, "available_bytes": available,
            "available_inodes": inodes, "block_bytes": 4096}


def test_bound_covers_actual_archive_sparse_hardlinked_and_pax_names(source_volumes, tmp_path):
    root = Path(source_volumes["gsj"])
    path = root / ("privat-" + "ü" * 100)
    path.write_bytes(os.urandom(1024 * 1024))
    os.link(path, root / "hardlink")
    with (root / "sparse").open("wb") as out:
        out.seek(8 * 1024 * 1024)
        out.write(b"synthetic")
    report = capacity.qualify(source_volumes, tmp_path, {"backup": fs("b"), "work": fs("c")}, 0)
    record = next(v for v in report["volumes"] if v["role"] == "gsj")
    assert record["logical_bytes"] > 10 * 1024 * 1024
    assert record["logical_bytes"] == sum(p.stat().st_size for p in root.rglob("*") if p.is_file())
    archive = tmp_path / "snapshot.tar.gz"
    backup.create(archive, source_volumes, {"quiesced": True, "generation": "synthetic:1", "release_identity": "synthetic"})
    assert archive.stat().st_size < report["archive_upper_bound_bytes"]
    assert "privat" not in json.dumps(report)


def test_shared_filesystem_requirements_add_but_free_bytes_do_not(source_volumes, tmp_path, monkeypatch):
    monkeypatch.setattr(capacity, "filesystem", lambda path: fs())
    report = capacity.qualify(source_volumes, tmp_path, {"backup": fs(), "work": fs()}, 20 * 1024 ** 3)
    assert len(report["filesystems"]) == 1
    group = report["filesystems"][0]
    assert group["available_bytes"] == 100 * 1024 ** 3
    assert group["required_bytes"] == (20 * 1024 ** 3 + 3 * report["archive_budget_bytes"]
                                       + 2 * capacity.RESOURCE_RESERVE + capacity.METADATA_RESERVE)
    assert set(group["roles"]) == {"gsj", "forgejo", "chroma", "transfer", "host_backup", "host_work"}


@pytest.mark.parametrize("failure", ["backup", "work", "transfer", "gsj", "inodes"])
def test_any_actual_filesystem_shortage_refuses(source_volumes, tmp_path, monkeypatch, failure):
    def measured(path):
        role = next((r for r, p in source_volumes.items() if Path(p) == Path(path)), "transfer")
        return fs({"gsj": "a", "forgejo": "b", "chroma": "c", "transfer": "d"}[role],
                  available=0 if role == failure else 100 * 1024 ** 3,
                  inodes=0 if failure == "inodes" else 100000)
    monkeypatch.setattr(capacity, "filesystem", measured)
    hosts = {"backup": fs("e", available=0 if failure == "backup" else 100 * 1024 ** 3),
             "work": fs("f", available=0 if failure == "work" else 100 * 1024 ** 3)}
    report = capacity.qualify(source_volumes, tmp_path, hosts, 1024 ** 3)
    assert report["status"] == "insufficient"


def test_verified_reuse_does_not_demand_new_archive_space(source_volumes, tmp_path, monkeypatch):
    monkeypatch.setattr(capacity, "filesystem", lambda path: fs(available=8 * 1024 ** 2))
    hosts = {"backup": fs("b", available=1), "work": fs("c", available=1)}
    assert capacity.qualify(source_volumes, tmp_path, hosts, 1024, "reuse")["status"] == "passed"
    assert capacity.qualify(source_volumes, tmp_path, hosts, 1024, "create")["status"] == "insufficient"


def test_unknown_layout_returns_coarse_failure_without_private_path(source_volumes, tmp_path):
    secret_name = "private-customer-file-never-log"
    os.mkfifo(Path(source_volumes["gsj"]) / secret_name)
    result = subprocess.run([sys.executable, str(ROOT / "ops/installer/capacity.py"),
                             "--volumes", json.dumps(source_volumes), "--transfer", str(tmp_path),
                             "--hosts", json.dumps({"backup": fs(), "work": fs()}), "--minimum", "0"],
                            text=True, capture_output=True)
    assert result.returncode == 2
    assert json.loads(result.stdout)["status"] == "unknown"
    assert secret_name not in result.stdout + result.stderr


@pytest.fixture
def cluster_capacity(maintenance, source_volumes, tmp_path):
    m = maintenance
    installed_path = m["work"] / "installed.json"
    installed = json.loads(installed_path.read_text())
    installed["site"]["storage"] = {"node": "node-original", "minimum_free_bytes": 1024,
                                   **{r: {"existing_claim": ""} for r in ("data", "forgejo", "chroma")}}
    installed_path.write_text(json.dumps(installed))
    values_path = m["work"] / "values.pending.json"
    values = json.loads(values_path.read_text())
    values["image"] = {"pullSecrets": []}
    values_path.write_text(json.dumps(values))
    cluster = json.loads(m["cluster"].read_text())
    cluster.update(volumes=source_volumes, transfer=str(tmp_path / "transfer"), pods={})
    Path(cluster["transfer"]).mkdir()
    for controller in cluster["controllers"]["items"]:
        name = controller["metadata"]["name"]
        pod = controller["spec"]["template"]["spec"]
        pod["nodeSelector"] = {"kubernetes.io/hostname": "node-original"}
        role = "data" if name == "gsj-web" else name.removeprefix("gsj-")
        pod["volumes"] = [{"name": role, "persistentVolumeClaim": {"claimName": "gsj-" + role}}]
        for container in pod["containers"]:
            mounts = {"gsj-web": [("/data/db", "db")],
                      "agent-runner": [("/data/runner-workspace", "runner-workspace"), ("/runner-home", "runner-home")],
                      "gsj-mcp": [("/data/cases", "cases")], "forgejo": [("/data", "")], "chroma": [("/data", "")]}
            container["volumeMounts"] = [{"name": role, "mountPath": path, **({"subPath": sub} if sub else {})}
                                         for path, sub in mounts[container["name"]]]
    m["cluster"].write_text(json.dumps(cluster))
    payload = tmp_path / "payload" / "helpers"
    payload.mkdir(parents=True)
    (payload / "capacity.py").write_bytes((ROOT / "ops/installer/capacity.py").read_bytes())
    fake = tmp_path / "capacity-k.py"
    fake.write_text('''import json, os, pathlib, subprocess, sys
p=pathlib.Path(os.environ['TEST_CLUSTER']); s=json.loads(p.read_text()); a=sys.argv[1:]; s['calls'].append(a)
result=None
if a[:2]==['get','namespace']: result={'metadata':{'uid':s['namespace_uid']}}
elif a[:2]==['get','configmap']: result=s['restored_configmap']
elif a[:2]==['get','node']: result=s['node']
elif a[:2]==['get','deployments,statefulsets,daemonsets,replicasets,jobs,cronjobs']: result=s['controllers']
elif a[:2]==['get','pods']: result={'items':list(s['pods'].values())}
elif a[:2]==['get','deploy']: result=s['controllers']
elif a[:2]==['get','pvc']:
 v=next(v for v in s['storage'] if v['name']==a[2]); result={'metadata':{'name':v['name'],'uid':v['uid']},'spec':{'volumeName':v['volume'],'storageClassName':v['storageClass']},'status':{'phase':s.get('pvc_phase','Bound')}}
elif a[:2]==['get','pv']:
 v=next(v for v in s['storage'] if v['volume']==a[2]); result={'metadata':{'name':v['volume'],'uid':s.get('pv_uid',v['volume']+'-uid')},'spec':{'claimRef':{'namespace':'legal','name':v['name'],'uid':s.get('binding_uid',v['uid'])}},'status':{'phase':'Bound'}}
elif a[:2]==['get','pod']: result=s['pods'].get(a[2])
elif a[:1]==['create']:
 obj=json.loads(pathlib.Path(a[a.index('-f')+1]).read_text()); obj['metadata']['uid']='reader-uid'
 if obj['spec'].get('imagePullSecrets')==[]: obj['spec'].pop('imagePullSecrets')
 mutation=s.get('capacity_admission_mutation')
 if mutation=='pull': obj['spec']['imagePullSecrets']=[{'name':'foreign-registry'}]
 elif mutation=='mounts': obj['spec']['containers'][0].pop('volumeMounts')
 elif mutation=='read-only': obj['spec']['volumes'][0]['persistentVolumeClaim']['readOnly']=False
 elif mutation=='containers': obj['spec']['containers'].append({'name':'foreign','image':'registry.invalid/foreign'})
 s['pods'][obj['metadata']['name']]=obj
elif a[:1]==['wait']: pass
elif a[:1]==['exec']:
 script=sys.stdin.read(); args=a[a.index('--')+3:]; args[args.index('--volumes')+1]=json.dumps(s['volumes']); args[args.index('--transfer')+1]=s['transfer']
 run=subprocess.run([sys.executable,'-',*args],input=script,text=True,capture_output=True)
 if s.get('change_pv_during_scan'): s['pv_uid']='replaced-during-scan'
 if s.get('change_controller_during_scan'): s['controllers']['items'][0]['metadata']['uid']='replaced-during-scan'
 p.write_text(json.dumps(s)); sys.stdout.write(run.stdout); sys.stderr.write(run.stderr); raise SystemExit(run.returncode)
elif a[:2]==['delete','--raw']:
 name=a[2].rsplit('/',1)[1]; options=json.loads(pathlib.Path(a[a.index('-f')+1]).read_text()); assert options['preconditions']['uid']==s['pods'][name]['metadata']['uid']; del s['pods'][name]
else: raise SystemExit('unexpected synthetic call '+repr(a))
p.write_text(json.dumps(s))
if result is not None: print(json.dumps(result))
''')
    env = {**m["env"], "GSJ_PAYLOAD": str(payload.parent)}

    def run(body="capacity_qualify create"):
        script = f'''source {shlex.quote(str(tmp_path / 'functions.sh'))}
assert_owner() {{ :; }}
k() {{ {shlex.quote(sys.executable)} {shlex.quote(str(fake))} "$@"; }}
stat() {{ printf 'ffff 1000000000 4096 10000000\\n'; }}
{body}
'''
        return subprocess.run(["bash", "-c", script], env=env, text=True, capture_output=True)
    return {**m, "run_capacity": run}


def test_capacity_uses_installed_claims_read_only_and_deletes_exact_reader(cluster_capacity):
    m = cluster_capacity
    result = m["run_capacity"]()
    assert result.returncode == 0, result.stderr
    state = json.loads(m["cluster"].read_text())
    assert state["pods"] == {}
    assert not any(a[0] == "scale" for a in state["calls"])
    requested = json.loads((m["work"] / "capacity-pod.json").read_text())
    assert requested["spec"]["automountServiceAccountToken"] is False
    claims = [v["persistentVolumeClaim"] for v in requested["spec"]["volumes"] if "persistentVolumeClaim" in v]
    assert {v["claimName"] for v in claims} == {"gsj-data", "gsj-forgejo", "gsj-chroma"}
    assert all(v["readOnly"] is True for v in claims)
    assert all(v["readOnly"] for v in requested["spec"]["containers"][0]["volumeMounts"] if v["name"] != "transfer")
    report = json.loads((m["state"] / "capacity-operation123-before.json").read_text())
    assert report["status"] == "passed" and report["measurement"] == "live-estimate"


@pytest.mark.parametrize("mutation", ["pull", "mounts", "read-only", "containers"])
def test_capacity_default_normalization_does_not_accept_changed_reader(cluster_capacity, mutation):
    m = cluster_capacity
    state = json.loads(m["cluster"].read_text())
    state["capacity_admission_mutation"] = mutation
    m["cluster"].write_text(json.dumps(state))
    result = m["run_capacity"]()
    assert result.returncode != 0
    assert "mutated by admission" in result.stderr
    after = json.loads(m["cluster"].read_text())
    assert not any(call[0] in ("exec", "delete", "scale") for call in after["calls"])
    assert after["pods"]


@pytest.mark.parametrize("change", ["pvc_phase", "binding_uid", "node", "mount", "missing_claim", "namespace"])
def test_storage_identity_or_mount_gap_refuses_before_reader_creation(cluster_capacity, change):
    m = cluster_capacity
    state = json.loads(m["cluster"].read_text())
    if change in ("pvc_phase", "binding_uid"): state[change] = "wrong"
    elif change == "node": state["controllers"]["items"][0]["spec"]["template"]["spec"]["nodeSelector"] = {"kubernetes.io/hostname": "replacement"}
    elif change == "mount": state["controllers"]["items"][0]["spec"]["template"]["spec"]["containers"][0]["volumeMounts"][0]["subPath"] = "other-db"
    elif change == "missing_claim": state["storage"][0]["uid"] = "replacement"
    else: state["namespace_uid"] = "replacement"
    m["cluster"].write_text(json.dumps(state))
    result = m["run_capacity"]()
    assert result.returncode != 0
    assert not any(a[0] in ("create", "scale", "delete") for a in json.loads(m["cluster"].read_text())["calls"])


def test_binding_replaced_during_scan_cannot_pass(cluster_capacity):
    m = cluster_capacity
    state = json.loads(m["cluster"].read_text())
    state["change_pv_during_scan"] = True
    m["cluster"].write_text(json.dumps(state))
    result = m["run_capacity"]()
    assert result.returncode != 0
    assert "binding changed" in result.stderr
    assert not any(a[0] == "scale" for a in json.loads(m["cluster"].read_text())["calls"])
    assert not (m["state"] / "capacity-operation123-before.json").exists()


def test_controller_replaced_during_scan_cannot_publish_pass(cluster_capacity):
    m = cluster_capacity
    state = json.loads(m["cluster"].read_text())
    state["change_controller_during_scan"] = True
    m["cluster"].write_text(json.dumps(state))
    result = m["run_capacity"]()
    assert result.returncode != 0
    assert "controller identity" in result.stderr
    assert not (m["state"] / "capacity-operation123-before.json").exists()


def test_existing_claim_names_are_taken_from_recorded_source(cluster_capacity):
    m = cluster_capacity
    installed_path = m["work"] / "installed.json"
    installed = json.loads(installed_path.read_text())
    state = json.loads(m["cluster"].read_text())
    for role in ("data", "forgejo", "chroma"):
        previous, actual = "gsj-" + role, "retained-" + role
        installed["site"]["storage"][role]["existing_claim"] = actual
        for collection in (installed["storage"], state["storage"]):
            next(s for s in collection if s["name"] == previous)["name"] = actual
        for deployment in state["controllers"]["items"]:
            for volume in deployment["spec"]["template"]["spec"]["volumes"]:
                if volume["persistentVolumeClaim"]["claimName"] == previous:
                    volume["persistentVolumeClaim"]["claimName"] = actual
    installed_path.write_text(json.dumps(installed))
    m["cluster"].write_text(json.dumps(state))
    result = m["run_capacity"]()
    assert result.returncode == 0, result.stderr
    pod = json.loads((m["work"] / "capacity-pod.json").read_text())
    assert {v["persistentVolumeClaim"]["claimName"] for v in pod["spec"]["volumes"] if "persistentVolumeClaim" in v} == {"retained-data", "retained-forgejo", "retained-chroma"}


def test_foreign_capacity_pod_cannot_be_reused_or_deleted(cluster_capacity):
    m = cluster_capacity
    state = json.loads(m["cluster"].read_text())
    foreign = {"metadata": {"name": "gsj-capacity-operatio", "uid": "foreign", "labels": {}}, "spec": {}}
    state["pods"][foreign["metadata"]["name"]] = foreign
    m["cluster"].write_text(json.dumps(state))
    result = m["run_capacity"]()
    assert result.returncode != 0
    after = json.loads(m["cluster"].read_text())
    assert after["pods"][foreign["metadata"]["name"]] == foreign
    assert not any(a[0] in ("create", "exec", "delete", "scale") for a in after["calls"])


@pytest.mark.parametrize("mutation", [None, "claim", "subpath", "transfer", "extra_container"])
def test_quiesced_scan_checks_actual_maintenance_mounts(cluster_capacity, mutation):
    m = cluster_capacity
    initial = m["run_capacity"]()
    assert initial.returncode == 0, initial.stderr
    state = json.loads(m["cluster"].read_text())
    name = "gsj-backup-operatio"
    reader = json.loads((m["work"] / "capacity-pod.json").read_text())
    reader["metadata"] = {"name": name, "uid": "maintenance-uid", "labels": {"gsj.io/operation": name}}
    reader["spec"]["containers"][0]["name"] = "maintenance"
    for mount in reader["spec"]["containers"][0]["volumeMounts"]:
        mount.pop("readOnly", None)
    for volume in reader["spec"]["volumes"]:
        if "persistentVolumeClaim" in volume:
            volume["persistentVolumeClaim"].pop("readOnly", None)
    if mutation == "claim": reader["spec"]["volumes"][0]["persistentVolumeClaim"]["claimName"] = "foreign-claim"
    elif mutation == "subpath": reader["spec"]["containers"][0]["volumeMounts"][0]["subPath"] = "wrong-root"
    elif mutation == "transfer": reader["spec"]["volumes"][-1]["emptyDir"] = {"medium": "Memory"}
    elif mutation == "extra_container": reader["spec"]["containers"].append({"name": "unowned", "image": "foreign"})
    state["pods"][name] = reader
    state["calls"] = []
    m["cluster"].write_text(json.dumps(state))
    result = m["run_capacity"](f'capacity_scan_pod {name} create quiesced')
    if mutation is None:
        assert result.returncode == 0, result.stderr
        report = json.loads((m["state"] / "capacity-operation123-quiesced.json").read_text())
        assert report["measurement"] == "quiesced" and report["storage_identity_verified"] is True
    else:
        assert result.returncode != 0
        assert not any(a[0] == "exec" for a in json.loads(m["cluster"].read_text())["calls"])


def test_backup_capacity_failure_precedes_quiescence(maintenance):
    m = maintenance
    result = m["run"]('capacity_qualify() { return 71; }; backup')
    assert result.returncode == 71
    assert not any(a[0] == "scale" for a in json.loads(m["cluster"].read_text())["calls"])
    assert not list(m["backups"].iterdir())


def test_actual_maintenance_capacity_rechecked_before_archive(maintenance):
    m = maintenance
    result = m["run"]('maintenance_pod() { :; }; capacity_scan_pod() { return 72; }; backup')
    assert result.returncode != 0
    assert "quiesced source" in result.stderr
    calls = json.loads(m["cluster"].read_text())["calls"]
    assert any(a[0] == "scale" for a in calls)
    assert not any(a[0] == "exec" for a in calls)
    assert not list(m["backups"].iterdir())


@pytest.fixture
def restored_capacity(cluster_capacity):
    """A different real target identity with restored SQLite roots and no app controllers."""
    m = cluster_capacity
    historical = json.loads((m["work"] / "installed.json").read_text())
    historical["format"] = "gsj.installed/1"
    (m["work"] / "installed.json").write_text(json.dumps(historical))
    original_bytes = (m["work"] / "installed.json").read_bytes()
    state = json.loads(m["cluster"].read_text())
    state["namespace_uid"] = "namespace-restored"
    state["controllers"] = {"items": []}
    state["node"] = {"metadata": {"name": "node-restored", "uid": "node-restored-uid",
                                  "labels": {"kubernetes.io/hostname": "node-restored"}},
                     "status": {"conditions": [{"type": "Ready", "status": "True"}]}}
    for row in state["storage"]:
        row["uid"] += "-restored"
        row["volume"] += "-restored"
    site = json.loads(json.dumps(historical["site"]))
    site["storage"]["node"] = "node-restored"
    Path(m["env"]["SITE"]).write_text(json.dumps(site))
    payload = Path(m["env"]["GSJ_PAYLOAD"]) if "GSJ_PAYLOAD" in m["env"] else m["work"].parent / "payload"
    (payload / "release.json").write_text(json.dumps(historical["manifest"]))
    saved = m["state"] / "restore-operation123"
    saved.mkdir()

    def write(path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value))
        return hashlib.sha256(path.read_bytes()).hexdigest()

    bindings = {}
    for row in state["storage"]:
        role = row["name"].removeprefix("gsj-")
        if role == "data": role = "gsj"
        bindings[role] = {"name": row["name"], "uid": row["uid"], "pv_name": row["volume"],
                          "pv_uid": row["volume"] + "-uid", "root": "/volumes/" + role}
        write(saved / "PersistentVolumeClaim" / row["name"] / "receipt.json", {"uid": row["uid"]})
    write(saved / "bindings.json", bindings)
    write(m["state"] / "operation.json", {"operation": "operation123", "target": "source-release",
                                             "kind": "restore", "status": "restore-files-verified"})
    write(m["state"] / "restoration.json", {"format": "gsj.restore/1", "operation": "operation123",
        "release_identity": "source-release", "status": "files-restored", "source_namespace_uid": "namespace-original",
        "target_namespace_uid": "namespace-restored", "archive_sha256": "b" * 64,
        "references": {"PersistentVolumeClaim": [v["name"] for v in state["storage"]]}})
    settings = {"format": "gsj.restore-files/1", "operation": "operation123", "volumes": bindings,
                "namespace_uid": "namespace-restored", "release_identity": "source-release",
                "archive_sha256": "a" * 64, "encrypted_archive_sha256": "b" * 64}
    settings_sha = write(saved / "files-settings.json", settings)
    write(saved / "archive-proof.json", {"archive_sha256": "a" * 64, "manifest_sha256": "c" * 64, "entries": 3})
    write(saved / "files-result.json", {"status": "complete", "restored": True,
        **settings, "format": "gsj.restore-files-result/1", "operation": "operation123", "settings_file_sha256": settings_sha,
        "manifest_sha256": "c" * 64, "entries": 3})
    cm = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "gsj-installed", "namespace": "legal",
        "labels": {"gsj.io/restore-operation": "operation123"}, "annotations": {"gsj.io/restore-archive-sha256": "b" * 64}},
        "data": {"installed.json": original_bytes.decode()}}
    cfg = saved / "ConfigMap/gsj-installed"
    intent_sha = write(cfg / "intent.json", cm)
    write(cfg / "attempt.json", {"attempted": True, "intent_sha256": intent_sha})
    write(cfg / "receipt.json", {"uid": "restored-configmap-uid", "intent_sha256": intent_sha})
    cm["metadata"]["uid"] = "restored-configmap-uid"
    state["restored_configmap"] = cm
    m["cluster"].write_text(json.dumps(state))
    return {**m, "saved": saved, "historical": original_bytes,
            "invoke_restored": lambda: m["run_capacity"]("RELEASE_ID=source-release; restore_capacity_qualify")}


def test_restored_capacity_uses_new_bound_roots_preserves_historical_source(restored_capacity):
    m = restored_capacity
    result = m["invoke_restored"]()
    assert result.returncode == 0, result.stderr
    assert (m["work"] / "installed.json").read_bytes() == m["historical"]
    context = json.loads((m["saved"] / "capacity-context.json").read_text())
    assert context["format"] == "gsj.restore-capacity-context/1" and "status" not in context
    assert context["namespace_uid"] == "namespace-restored"
    assert context["restoration"]["source_namespace_uid"] == "namespace-original"
    assert context["site"]["storage"]["node"] == "node-restored"
    report = json.loads((m["state"] / "capacity-operation123-before.json").read_text())
    assert report["status"] == "passed" and report["purpose"] == "restored-files-before-startup"
    assert report["namespace_uid"] == "namespace-restored"
    state = json.loads(m["cluster"].read_text())
    assert state["pods"] == {} and state["controllers"] == {"items": []}
    assert not any(c[0] in ("scale", "apply", "replace") for c in state["calls"])


@pytest.mark.parametrize("fault", ["namespace", "node", "historical-payload", "configmap-uid", "receipt", "files-proof", "claim", "writer"])
def test_restored_capacity_refuses_unproven_target_before_reader(restored_capacity, fault):
    m = restored_capacity
    state = json.loads(m["cluster"].read_text())
    if fault == "namespace": state["namespace_uid"] = "foreign"
    elif fault == "node": state["node"]["metadata"]["labels"]["kubernetes.io/hostname"] = "foreign"
    elif fault == "historical-payload": state["restored_configmap"]["data"]["installed.json"] = "{}"
    elif fault == "configmap-uid": state["restored_configmap"]["metadata"]["uid"] = "foreign"
    elif fault == "receipt": (m["saved"] / "ConfigMap/gsj-installed/receipt.json").unlink()
    elif fault == "files-proof":
        path = m["saved"] / "files-result.json"; value = json.loads(path.read_text()); value["entries"] += 1; path.write_text(json.dumps(value))
    elif fault == "claim": state["storage"][0]["uid"] = "foreign"
    else: state["controllers"]["items"] = [{"metadata": {"labels": {"app.kubernetes.io/instance": "gsj"}}, "spec": {}}]
    m["cluster"].write_text(json.dumps(state))
    result = m["invoke_restored"]()
    assert result.returncode != 0
    assert (m["work"] / "installed.json").read_bytes() == m["historical"]
    assert not any(c[0] in ("create", "exec", "delete", "scale") for c in json.loads(m["cluster"].read_text())["calls"])


def test_restored_capacity_detects_pv_replacement_during_actual_scan(restored_capacity):
    m = restored_capacity
    state = json.loads(m["cluster"].read_text()); state["change_pv_during_scan"] = True; m["cluster"].write_text(json.dumps(state))
    result = m["invoke_restored"]()
    assert result.returncode != 0
    assert "bindings changed" in result.stderr
    assert not (m["state"] / "capacity-operation123-before.json").exists()


def test_restored_insufficient_actual_space_cannot_publish_success(restored_capacity):
    m = restored_capacity
    site = Path(m["env"]["SITE"]); value = json.loads(site.read_text()); value["storage"]["minimum_free_bytes"] = 10 ** 25; site.write_text(json.dumps(value))
    result = m["invoke_restored"]()
    assert result.returncode != 0
    report = json.loads((m["state"] / "capacity-operation123-before.json").read_text())
    assert report["status"] == "insufficient" and report["purpose"] == "restored-files-before-startup"


def test_helm_restored_file_phase_dispatches_target_capacity_only(restored_capacity):
    m = restored_capacity
    result = m["run_capacity"]('''
RELEASE_ID=source-release
restore_capacity_qualify() { printf restored > "$GSJ_WORK/dispatch"; }
read_installed() { echo 'unexpected historical capacity path' >&2; exit 78; }
stage_operation_config() { exit 79; }
helm_apply
''')
    assert result.returncode == 79, result.stderr
    assert (m["work"] / "dispatch").read_text() == "restored"
    assert (m["work"] / "installed.json").read_bytes() == m["historical"]


@pytest.mark.parametrize("field", ["namespace_uid", "encrypted_archive_sha256", "volumes"])
def test_restored_capacity_rejects_internally_consistent_foreign_file_proof(restored_capacity, field):
    m = restored_capacity
    settings = m["saved"] / "files-settings.json"
    result = m["saved"] / "files-result.json"
    value = json.loads(settings.read_text()); value[field] = {} if field == "volumes" else "foreign"
    settings.write_text(json.dumps(value))
    proof = json.loads(result.read_text()); proof[field] = value[field]
    proof["settings_file_sha256"] = hashlib.sha256(settings.read_bytes()).hexdigest()
    result.write_text(json.dumps(proof))
    out = m["invoke_restored"]()
    assert out.returncode != 0
    assert "not bound to this target" in out.stderr
    assert not any(c[0] == "create" for c in json.loads(m["cluster"].read_text())["calls"])


def _restored_record(m, kind, installed_bytes):
    """Write one restored ConfigMap's create intent, attempt and UID receipt."""
    name = "gsj-" + kind
    cm = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name, "namespace": "legal",
          "labels": {"gsj.io/restore-operation": "operation123"}, "annotations": {"gsj.io/restore-archive-sha256": "b" * 64}},
          "data": {"installed.json": installed_bytes.decode()}}
    evidence = m["saved"] / "ConfigMap" / name
    evidence.mkdir(parents=True, exist_ok=True)
    (evidence / "intent.json").write_text(json.dumps(cm))
    intent_sha = hashlib.sha256((evidence / "intent.json").read_bytes()).hexdigest()
    (evidence / "attempt.json").write_text(json.dumps({"attempted": True, "intent_sha256": intent_sha}))
    (evidence / "receipt.json").write_text(json.dumps({"uid": "restored-" + kind + "-uid", "intent_sha256": intent_sha}))
    cm["metadata"]["uid"] = "restored-" + kind + "-uid"
    return cm


@pytest.mark.parametrize("installed", ["absent", "older-release"])
def test_restored_capacity_uses_the_ready_state_of_a_verification_pending_source(restored_capacity, installed):
    m = restored_capacity
    pending = json.loads(m["historical"]); pending["status"] = "verification-pending"
    pending_bytes = json.dumps(pending).encode()
    ready = _restored_record(m, "ready-state", pending_bytes)
    if installed == "absent":
        shutil.rmtree(m["saved"] / "ConfigMap" / "gsj-installed")
    else:
        older = json.loads(m["historical"]); older["manifest"]["identity"] = "older-release"
        _restored_record(m, "installed", json.dumps(older).encode())
    state = json.loads(m["cluster"].read_text()); state["restored_configmap"] = ready; m["cluster"].write_text(json.dumps(state))
    result = m["invoke_restored"]()
    assert result.returncode == 0, result.stderr
    context = json.loads((m["saved"] / "capacity-context.json").read_text())
    assert context["restoration"]["historical_installed_sha256"] == hashlib.sha256(pending_bytes + b"\n").hexdigest()
    calls = json.loads(m["cluster"].read_text())["calls"]
    assert ["get", "configmap", "gsj-ready-state", "-o", "json"] in calls
    assert not any(c[:3] == ["get", "configmap", "gsj-installed"] for c in calls)
    assert (m["work"] / "installed.json").read_bytes() == m["historical"]


def test_restored_capacity_refuses_when_no_restored_record_is_the_archived_source(restored_capacity):
    m = restored_capacity
    older = json.loads(m["historical"]); older["manifest"]["identity"] = "older-release"
    record = _restored_record(m, "installed", json.dumps(older).encode())
    state = json.loads(m["cluster"].read_text()); state["restored_configmap"] = record; m["cluster"].write_text(json.dumps(state))
    result = m["invoke_restored"]()
    assert result.returncode != 0
    assert "differs from the restore proof" in result.stderr
    assert not any(c[0] in ("create", "exec", "delete", "scale") for c in json.loads(m["cluster"].read_text())["calls"])
