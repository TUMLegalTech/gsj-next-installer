"""Retry an operation against synthetic Kubernetes identities; never use a cluster."""
from __future__ import annotations

import base64
import hashlib
import io
import json
import os
from pathlib import Path
import shlex
import subprocess
import tarfile

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def maintenance(tmp_path):
    source = (ROOT / "ops/installer/runtime.sh").read_text().split("# ENTRY POINT", 1)[0]
    source = source.replace("@CLIENT_TABLE@", "gsj_client_info() { return 1; }")
    functions = tmp_path / "functions.sh"
    functions.write_text(source)
    work, state, backups = (tmp_path / name for name in ("work", "state", "backups"))
    for path in (work, state, backups):
        path.mkdir()
    site = {"target": {"namespace": "legal", "release": "gsj"},
            "backup": {"offbox_url": "https://backup.invalid/source"}}
    (state / "site.pending.json").write_text(json.dumps(site))
    (state / "operation.json").write_text('{"id":"operation123","status":"applying"}')
    (work / "values.pending.json").write_text(json.dumps({
        "storage": {name: {"existingClaim": ""} for name in ("data", "forgejo", "chroma")}}))
    images = {name: {"repository": "registry.invalid/" + name, "digest": "sha256:" + "a" * 64}
              for name in ("web", "runner", "mcp", "forgejo", "chroma", "decisionsData")}
    controllers = {"items": []}
    for role, containers in (("web", [("gsj-web", "web"), ("agent-runner", "runner"), ("gsj-mcp", "mcp")]),
                             ("forgejo", [("forgejo", "forgejo")]), ("chroma", [("chroma", "chroma")])):
        pod = {"containers": [{"name": name, "image": images[key]["repository"] + "@" + images[key]["digest"]}
                              for name, key in containers]}
        if role == "web":
            pod["initContainers"] = [{"name": "wait-deps", "env": [
                {"name": "GSJ_DEPLOYMENT_GENERATION", "value": "source-release:7"}]}]
        controllers["items"].append({"metadata": {"name": "gsj-" + role, "uid": role + "-uid", "generation": 1},
                                     "spec": {"replicas": 1, "template": {"spec": pod}}})
    storage = [{"name": "gsj-" + role, "uid": role + "-pvc", "volume": role + "-pv",
                "storageClass": "synthetic", "requested": "20Gi", "capacity": "20Gi"}
               for role in ("chroma", "data", "forgejo")]
    installed = {"status": "complete", "namespace_uid": "namespace-original", "site": site,
                 "manifest": {"identity": "source-release", "images": images}, "storage": storage}
    (work / "installed.json").write_text(json.dumps(installed))
    cluster = tmp_path / "cluster.json"
    cluster.write_text(json.dumps({"namespace_uid": "namespace-original", "controllers": controllers,
                                   "storage": storage, "calls": []}))
    fake = tmp_path / "k.py"
    fake.write_text('''import json, os, pathlib, sys
p=pathlib.Path(os.environ['TEST_CLUSTER']); s=json.loads(p.read_text()); a=sys.argv[1:]
s['calls'].append(a); result=None
if a[:2]==['get','namespace']: result={'metadata':{'uid':s['namespace_uid']}}
elif a[:2]==['get','deploy']: result=s['controllers']
elif a[:2]==['get','deployment']:
 obj=next(v for v in s['controllers']['items'] if v['metadata']['name']==a[2])
 if '-o' in a and a[a.index('-o')+1]=="jsonpath={.metadata.uid}": print(obj['metadata']['uid'])
 else: result=obj
elif a[:2] in (['get','pods'],['get','jobs']):
 if a[1]=='pods' and s.get('fail_pod_read'): p.write_text(json.dumps(s)); raise SystemExit(29)
 items=s.get('writer_pods' if a[1]=='pods' else 'writer_jobs',[])
 # A release label selector cannot see foreign Pods; an unselected listing can.
 if a[1]=='pods' and '-l' not in a: items=items+s.get('foreign_pods',[])
 result={'items':items}
elif a[:2]==['get','pvc']:
 v=next(v for v in s['storage'] if v['name']==a[2])
 result={'metadata':{'name':v['name'],'uid':v['uid']},'spec':{'volumeName':v['volume'],'storageClassName':v['storageClass'],'resources':{'requests':{'storage':v['requested']}}},'status':{'phase':'Bound','capacity':{'storage':v['capacity']}}}
elif a[:2]==['get','pv']:
 v=next(v for v in s['storage'] if v['volume']==a[2])
 result={'metadata':{'name':v['volume'],'uid':v.get('pv_uid',v['volume']+'-uid')},'spec':{'claimRef':{'namespace':'legal','name':v['name'],'uid':v['uid']}},'status':{'phase':'Bound'}}
elif a[:1]==['scale']:
 replicas=int(next(v for v in a if v.startswith('--replicas=')).split('=',1)[1])
 for obj in s['controllers']['items']:
  if a[1]=='deployment' or a[1]=='deployment/'+obj['metadata']['name']:
   if obj['spec']['replicas']!=replicas: obj['metadata']['generation']+=1
   obj['spec']['replicas']=replicas
   if s.get('ready_on_scale'): obj['status']={'observedGeneration':obj['metadata']['generation'],'availableReplicas':replicas}
elif a[:2]==['get','pod']: result=None
elif a[:1]==['exec']:
 if '-i' in a: sys.stdin.buffer.read()
 if a[-2:]==['cat','/transfer/snapshot.tar.gz']: sys.stdout.buffer.write(b'synthetic verified PVC archive')
else: raise SystemExit('unexpected synthetic kubectl call: '+repr(a))
p.write_text(json.dumps(s))
if result is not None: print(json.dumps(result))
''')
    password = tmp_path / "recovery-key"
    password.write_text("synthetic-recovery-passphrase\n")
    password.chmod(0o600)
    env = dict(os.environ, COPYFILE_DISABLE="1", GSJ_WORK=str(work), STATE_DIR=str(state), BACKUP_DIR=str(backups),
               SITE=str(state / "site.pending.json"), BACKUP_PASSWORD=str(password),
               OPERATION="operation123", NAMESPACE="legal", RELEASE="gsj", TEST_CLUSTER=str(cluster))

    def run(body):
        script = f'''source {shlex.quote(str(functions))}
assert_owner() {{ :; }}
k() {{ python3 {shlex.quote(str(fake))} "$@"; }}
offbox_backup() {{ printf 'offbox\\n' >> "$GSJ_WORK/side-effects"; }}
maintenance_pod() {{ printf 'maintenance\\n' >> "$GSJ_WORK/side-effects"; exit 79; }}
capacity_qualify() {{ :; }}
capacity_scan_pod() {{ :; }}
backup_credential_fingerprint() {{ printf '%064d\\n' 0; }}
{body}
'''
        return subprocess.run(["bash", "-c", script], env=env, text=True, capture_output=True)

    return {"run": run, "work": work, "state": state, "backups": backups,
            "cluster": cluster, "password": password, "env": env}


def _cluster(m, change):
    value = json.loads(m["cluster"].read_text())
    change(value)
    m["cluster"].write_text(json.dumps(value))


def _snapshot(m):
    return m["state"] / "quiescence-operation123.json"


def _archive(m):
    return m["backups"] / "operation123.tar.gz.enc"


def _verified(m):
    result = m["run"]("quiesce")
    assert result.returncode == 0, result.stderr
    archive = _archive(m)
    archive.write_bytes(b"synthetic original encrypted volume bytes")
    Path(str(archive) + ".resources.enc").write_bytes(b"synthetic original encrypted resource bytes")
    challenge = b"synthetic independent recovery challenge"
    encrypted = subprocess.run(["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-iter", "600000",
                                "-salt", "-pass", "file:" + str(m["password"])],
                               input=challenge, capture_output=True, check=True).stdout
    source = json.loads(_snapshot(m).read_text())["installed"]
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    receipt = {"format": "gsj.backup/1", "verified": True, "operation": "operation123",
               "archive": str(archive), "sha256": digest(archive),
               "resources_sha256": digest(Path(str(archive) + ".resources.enc")),
               "quiescence_sha256": digest(_snapshot(m)), "closure_sha256": digest(Path(str(_snapshot(m)) + ".closure.json")), "release_identity": "source-release",
               "namespace_uid": source["namespace_uid"], "storage": source["storage"],
               "key_check": base64.b64encode(encrypted).decode(),
               "key_check_sha256": hashlib.sha256(challenge).hexdigest()}
    Path(str(archive) + ".json").write_text(json.dumps(receipt))
    Path(str(archive) + ".offbox.json").write_text(json.dumps({
        "format": "gsj.offbox-backup/1", "readback_verified": True,
        "destination": "https://backup.invalid/source", "archive": archive.name}))
    return archive


def test_quiescence_preserves_first_replica_snapshot_on_retry(maintenance):
    m = maintenance
    assert m["run"]("quiesce").returncode == 0
    original = _snapshot(m).read_bytes()
    assert all(c["spec"]["replicas"] == 0 for c in json.loads(m["cluster"].read_text())["controllers"]["items"])
    result = m["run"]("quiesce")
    assert result.returncode == 0, result.stderr
    assert _snapshot(m).read_bytes() == original
    assert all(c["spec"]["replicas"] == 1 for c in json.loads((m["work"] / "controllers.json").read_text())["items"])


@pytest.mark.parametrize("mutation", ["namespace", "storage", "uid", "image", "generation"])
def test_initial_source_mismatch_never_scales_or_captures(maintenance, mutation):
    m = maintenance
    def change(s):
        if mutation == "namespace": s["namespace_uid"] = "replacement"
        if mutation == "storage": s["storage"][0]["uid"] = "replacement"
        if mutation == "uid": s["controllers"]["items"][0]["metadata"]["uid"] = ""
        if mutation == "image": s["controllers"]["items"][0]["spec"]["template"]["spec"]["containers"][0]["image"] = "partial-target"
        if mutation == "generation": s["controllers"]["items"][0]["spec"]["template"]["spec"]["initContainers"][0]["env"][0]["value"] = "target-release:8"
    _cluster(m, change)
    result = m["run"]("quiesce")
    assert result.returncode != 0
    assert not _snapshot(m).exists()
    assert not any(a[0] == "scale" for a in json.loads(m["cluster"].read_text())["calls"])


@pytest.mark.parametrize("suffix", ["", ".partial", ".resources.enc", ".resources.enc.partial", ".sha256"])
def test_incomplete_backup_refuses_before_cluster_mutation(maintenance, suffix):
    m = maintenance
    path = Path(str(_archive(m)) + suffix)
    path.write_bytes(b"the only remaining original source")
    result = m["run"]("backup")
    assert result.returncode != 0
    assert "incomplete backup artifacts" in result.stderr
    assert path.read_bytes() == b"the only remaining original source"
    assert json.loads(m["cluster"].read_text())["calls"] == []


@pytest.mark.parametrize("mutation", ["metadata", "image", "generation"])
def test_verified_retry_refuses_historical_backup_as_fresh_source_before_scale(maintenance, mutation):
    m = maintenance
    archive = _verified(m)
    before = {p.name: p.read_bytes() for p in m["backups"].iterdir()}
    original = _snapshot(m).read_bytes()
    def change(s):
        s["calls"] = []
        for controller in s["controllers"]["items"]:
            controller["spec"]["replicas"] = 1
        if mutation == "image":
            s["controllers"]["items"][0]["spec"]["template"]["spec"]["containers"][0]["image"] = "partial-target"
        if mutation == "generation":
            s["controllers"]["items"][0]["spec"]["template"]["spec"]["initContainers"][0]["env"][0]["value"] = "source-release:8"
    _cluster(m, change)
    if mutation == "metadata":
        installed = json.loads((m["work"] / "installed.json").read_text())
        installed["manifest"]["identity"] = "partially-written-target-metadata"
        (m["work"] / "installed.json").write_text(json.dumps(installed))
    result = m["run"]("backup")
    assert result.returncode != 0
    assert any(message in result.stderr for message in ("differs from its stopped-writer snapshot", "unchanged stopped writers", "historical, not a fresh recovery point"))
    assert {p.name: p.read_bytes() for p in m["backups"].iterdir()} == before
    assert _snapshot(m).read_bytes() == original
    assert not (m["work"] / "side-effects").exists()
    assert not any(a[0] == "scale" for a in json.loads(m["cluster"].read_text())["calls"])
    assert all(c["spec"]["replicas"] == 1 for c in json.loads(m["cluster"].read_text())["controllers"]["items"])
    assert "backup" not in json.loads((m["state"] / "operation.json").read_text())


def test_verified_retry_rejects_restarted_writers_without_replacing_source_snapshot(maintenance):
    m = maintenance
    archive = _verified(m)
    before = {p.name: p.read_bytes() for p in m["backups"].iterdir()}
    original = _snapshot(m).read_bytes()
    _cluster(m, lambda s: [c["spec"].update(replicas=2) for c in s["controllers"]["items"]])
    result = m["run"]("backup")
    assert result.returncode != 0
    assert {p.name: p.read_bytes() for p in m["backups"].iterdir()} == before
    assert _snapshot(m).read_bytes() == original
    assert all(c["spec"]["replicas"] == 1 for c in json.loads((m["work"] / "controllers.json").read_text())["items"])
    assert "backup" not in json.loads((m["state"] / "operation.json").read_text())


@pytest.mark.parametrize("mutation", ["archive", "resources", "snapshot", "key", "uid", "namespace", "storage"])
def test_verified_retry_rejects_changed_evidence_before_scale(maintenance, mutation):
    m = maintenance
    archive = _verified(m)
    _cluster(m, lambda s: s.update(calls=[]))
    if mutation == "archive": archive.write_bytes(b"changed")
    elif mutation == "resources": Path(str(archive) + ".resources.enc").write_bytes(b"changed")
    elif mutation == "snapshot": _snapshot(m).write_text(_snapshot(m).read_text() + "\n")
    elif mutation == "key": m["password"].write_text("different-protected-recovery-key\n")
    elif mutation == "uid": _cluster(m, lambda s: s["controllers"]["items"][0]["metadata"].update(uid="recreated-controller"))
    elif mutation == "namespace": _cluster(m, lambda s: s.update(namespace_uid="recreated-namespace"))
    elif mutation == "storage": _cluster(m, lambda s: s["storage"][0].update(uid="recreated-pvc"))
    result = m["run"]("backup")
    assert result.returncode != 0
    assert not any(a[0] == "scale" for a in json.loads(m["cluster"].read_text())["calls"])
    assert not (m["work"] / "side-effects").exists()


def test_captured_source_cannot_be_newly_archived_after_template_change(maintenance):
    m = maintenance
    assert m["run"]("quiesce").returncode == 0
    _cluster(m, lambda s: s["controllers"]["items"][0]["spec"]["template"]["spec"]["containers"][0].update(image="partial-target"))
    result = m["run"]("backup")
    assert result.returncode != 0
    assert "unchanged stopped writers" in result.stderr
    assert not _archive(m).exists()
    assert not (m["work"] / "side-effects").exists()


def test_immutable_publication_cannot_replace_original_entry(maintenance):
    m = maintenance
    target = m["state"] / "immutable"
    target.write_bytes(b"original")
    result = m["run"]('printf changed | immutable_file "$STATE_DIR/immutable"')
    assert result.returncode != 0
    assert target.read_bytes() == b"original"


def test_pod_listing_failure_cannot_claim_writers_stopped(maintenance):
    m = maintenance
    _cluster(m, lambda s: s.update(fail_pod_read=True))
    result = m["run"]("backup")
    assert result.returncode == 29, result.stderr
    assert "writers have stopped" not in result.stderr
    assert not _archive(m).exists()
    assert not (m["work"] / "side-effects").exists()


def test_new_backup_encrypts_original_snapshot_and_then_reuses_it(maintenance):
    m = maintenance
    # The archive helper has separate real SQLite/tar tests. Here the fake
    # maintenance process supplies bytes after its create/verify calls while
    # this test exercises actual Bash publication, tar, encryption and receipt.
    result = m["run"]('''
maintenance_pod() { :; }
backup_resources() {
 for file in cluster-private.json volumes-private.json site_inputs.json; do
   printf '{}' > "$GSJ_WORK/$file"
 done
}
backup
''')
    assert result.returncode == 0, result.stderr
    archive = _archive(m)
    receipt = json.loads(Path(str(archive) + ".json").read_text())
    assert receipt["verified"] is True
    assert receipt["release_identity"] == "source-release"
    def decrypt(path):
        return subprocess.run(["openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", "600000",
                               "-pass", "file:" + str(m["password"]), "-in", str(path)],
                              capture_output=True, check=True).stdout
    assert decrypt(archive) == b"synthetic verified PVC archive"
    with tarfile.open(fileobj=io.BytesIO(decrypt(Path(str(archive) + ".resources.enc")))) as tar:
        assert sorted(tar.getnames()) == ["cluster-private.json", "controllers.json", "installed.json",
                                           "site.pending.json", "site_inputs.json", "volumes-private.json"]
        controllers = json.load(tar.extractfile("controllers.json"))
        assert all(c["spec"]["replicas"] == 1 for c in controllers["items"])
    before = {p.name: p.read_bytes() for p in m["backups"].iterdir()}
    result = m["run"]("backup")
    assert result.returncode == 0, result.stderr
    assert {p.name: p.read_bytes() for p in m["backups"].iterdir()} == before


def test_captured_but_unarchived_source_can_continue_after_scale_zero(maintenance):
    m = maintenance
    assert m["run"]("quiesce").returncode == 0
    result = m["run"]("backup")
    # Our maintenance fake intentionally stops at archive creation: reaching
    # it proves the pre-archive retry admitted exactly the unchanged source.
    assert result.returncode == 79, result.stderr
    assert (m["work"] / "side-effects").read_text() == "maintenance\n"


def _claim_pod(name, claim, phase, labels=None):
    return {"metadata": {"name": name, "labels": labels or {}}, "status": {"phase": phase},
            "spec": {"volumes": [{"name": "mounted", "persistentVolumeClaim": {"claimName": claim}}]}}


@pytest.mark.parametrize("pod,refused", [
    (_claim_pod("debug-shell", "gsj-data", "Running"), True),
    (_claim_pod("foreign-job", "gsj-forgejo", "Pending"), True),
    (_claim_pod("gsj-backup-operatio", "gsj-chroma", "Running"), True),
    (_claim_pod("finished-job", "gsj-chroma", "Succeeded"), False),
    (_claim_pod("gsj-backup-operatio", "gsj-data", "Running", {"gsj.io/operation": "gsj-backup-operatio"}), False),
    (_claim_pod("unrelated", "someone-else", "Running"), False),
])
def test_quiescence_refuses_any_unowned_pod_mounting_the_source_claims(maintenance, pod, refused):
    m = maintenance
    _cluster(m, lambda s: s.update(foreign_pods=[pod]))
    result = m["run"]("quiesce")
    if refused:
        assert result.returncode != 0
        assert "another Pod mounts the backup source storage" in result.stderr
        assert not Path(str(_snapshot(m)) + ".closure.json").exists()
    else:
        assert result.returncode == 0, result.stderr
        assert Path(str(_snapshot(m)) + ".closure.json").exists()
