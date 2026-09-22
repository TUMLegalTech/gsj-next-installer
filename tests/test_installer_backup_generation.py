"""Named archive generations retain every earlier recovery artifact."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import shlex
import subprocess
import sys
import tarfile
import time

import pytest

from tests.test_installer_backup_retry import maintenance, _cluster, _snapshot, _archive

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("backup_recovery", ROOT / "ops/installer/backup-recovery.py")
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)


def prepare(m):
    state = m["state"] / "operation.json"
    value = json.loads(state.read_text())
    value["kind"] = "backup"
    state.write_text(json.dumps(value))
    result = m["run"]("quiesce")
    assert result.returncode == 0, result.stderr
    Path(str(_archive(m)) + ".partial").write_bytes(b"preserve original interrupted ciphertext")
    _cluster(m, lambda s: s.update(calls=[]))


def test_new_generation_keeps_original_bytes_and_uses_separate_archive_and_pod(maintenance):
    m = maintenance
    prepare(m)
    original = Path(str(_archive(m)) + ".partial")
    source = original.read_bytes()
    result = m["run"]("prepare_backup_generation 1; backup_archive; printf '\\n'; backup_pod_name")
    assert result.returncode == 0, result.stderr
    assert "operation123.g1.tar.gz.enc" in result.stdout
    assert result.stdout.endswith("gsj-backup-operatio-g1")
    assert original.read_bytes() == source
    intent = json.loads((m["state"] / "backup-generation-operation123-1.json").read_text())
    assert intent["prior_artifacts"] == [{"suffix": ".partial", "sha256": hashlib.sha256(source).hexdigest(), "bytes": len(source)}]
    assert intent["quiescence_sha256"] == hashlib.sha256(_snapshot(m).read_bytes()).hexdigest()
    assert json.loads((m["state"] / "operation.json").read_text())["backup_generation"] == 1


def test_repeated_preparation_after_pointer_loss_reuses_exact_intent(maintenance):
    m = maintenance
    prepare(m)
    assert m["run"]("prepare_backup_generation 1").returncode == 0
    intent = m["state"] / "backup-generation-operation123-1.json"
    original = intent.read_bytes()
    state = m["state"] / "operation.json"
    current = json.loads(state.read_text())
    current.pop("backup_generation")
    state.write_text(json.dumps(current))
    result = m["run"]("prepare_backup_generation 1")
    assert result.returncode == 0, result.stderr
    assert intent.read_bytes() == original
    assert json.loads(state.read_text())["backup_generation"] == 1


def test_another_interruption_requires_next_explicit_generation(maintenance):
    m = maintenance
    prepare(m)
    assert m["run"]("prepare_backup_generation 1").returncode == 0
    partial = m["backups"] / "operation123.g1.tar.gz.enc.partial"
    partial.write_bytes(b"preserve second interrupted stream too")
    result = m["run"]("backup")
    assert result.returncode != 0 and "incomplete backup artifacts" in result.stderr
    before = {p.name: p.read_bytes() for p in m["backups"].iterdir()}
    result = m["run"]("prepare_backup_generation 2")
    assert result.returncode == 0, result.stderr
    assert {p.name: p.read_bytes() for p in m["backups"].iterdir()} == before
    assert json.loads((m["state"] / "backup-generation-operation123-2.json").read_text())["previous_archive"].endswith("operation123.g1.tar.gz.enc")


@pytest.mark.parametrize("failure", ["credentials", "historical", "controller", "metadata", "receipt", "collision", "restore_kind", "skipped_generation"])
def test_new_generation_refuses_unsafe_source_without_archive_mutation(maintenance, failure):
    m = maintenance
    prepare(m)
    command = "prepare_backup_generation 1"
    if failure == "credentials": command = "backup_credential_fingerprint() { printf '%064d\\n' 1; }; " + command
    elif failure == "historical":
        value = json.loads(_snapshot(m).read_text()); value.pop("credential_fingerprint"); _snapshot(m).write_text(json.dumps(value))
    elif failure == "controller": _cluster(m, lambda s: s["controllers"]["items"][0]["spec"]["template"]["spec"]["containers"][0].update(image="partly-migrated-target"))
    elif failure == "metadata":
        path = m["work"] / "installed.json"; value = json.loads(path.read_text()); value["manifest"]["identity"] = "target"; path.write_text(json.dumps(value))
    elif failure == "receipt": Path(str(_archive(m)) + ".json").write_text('{"verified":true}')
    elif failure == "collision": (m["backups"] / "operation123.g1.tar.gz.enc").write_bytes(b"foreign recovery bytes")
    elif failure == "restore_kind":
        path = m["state"] / "operation.json"; value = json.loads(path.read_text()); value["kind"] = "restore"; path.write_text(json.dumps(value))
    else: command = "prepare_backup_generation 2"
    before = {p.name: p.read_bytes() for p in m["backups"].iterdir()}
    result = m["run"](command)
    assert result.returncode != 0
    assert {p.name: p.read_bytes() for p in m["backups"].iterdir()} == before
    assert not any(a[0] == "scale" for a in json.loads(m["cluster"].read_text())["calls"])
    assert "backup_generation" not in json.loads((m["state"] / "operation.json").read_text())


def test_credential_fingerprint_is_stable_and_changes_without_outputting_values(maintenance):
    m = maintenance
    # Exercise the real fingerprint implementation after overriding only its
    # read-only Kubernetes/resource collector with a synthetic bundle.
    source = (ROOT / "ops/installer/runtime.sh").read_text()
    function = source.split("backup_credential_fingerprint() {", 1)[1].split("\n}\n", 1)[0]
    body = 'backup_credential_fingerprint() {' + function + '\n}\n'
    body += '''backup_resources() { printf '%s' '{"items":[{"kind":"Secret","metadata":{"name":"owned"},"type":"Opaque","data":{"key":"synthetic-private-value"}}]}' > "$GSJ_WORK/cluster-private.json"; }
backup_credential_fingerprint
backup_credential_fingerprint
'''
    result = m["run"](body)
    assert result.returncode == 0, result.stderr
    a, b = result.stdout.splitlines()
    assert a == b and len(a) == 64
    assert "synthetic-private-value" not in result.stdout + result.stderr
    changed = m["run"](body.replace("synthetic-private-value", "different-private-value"))
    assert changed.returncode == 0 and changed.stdout != result.stdout


def test_recovery_archive_roundtrip_preserves_every_partial_file_and_detects_change(tmp_path):
    root = tmp_path / "transfer"
    root.mkdir()
    (root / ".gsj-backup-partial").write_bytes(os.urandom(1024 * 1024))
    (root / "metadata.json").write_text('{"synthetic":true}')
    (root / "snapshot.tar.gz").write_bytes(b"incomplete archive bytes")
    stream = io.BytesIO()
    expected = recovery.summary(recovery.inventory(root))
    recovery.archive(root, stream)
    assert len(stream.getvalue()) <= expected["archive_upper_bound_bytes"]
    assert recovery.verify(root, io.BytesIO(stream.getvalue())) == expected
    (root / ".gsj-backup-partial").write_bytes(b"changed after preservation")
    with pytest.raises(ValueError): recovery.verify(root, io.BytesIO(stream.getvalue()))


def test_recovery_rejects_escape_types_and_cannot_run_freeze_on_the_tools_host(tmp_path):
    root = tmp_path / "transfer"; root.mkdir()
    (root / "unsafe").symlink_to("/etc/passwd")
    with pytest.raises(ValueError): recovery.inventory(root)
    # A test never invokes freeze against the host /proc. This CLI call takes
    # a nonexistent root and the process-identity guard rejects this host.
    # Invoke an isolated fake /proc view through a patched loader instead.
    original = recovery.Path
    class FakePath:
        def __init__(self, path): self.path = path
        def read_bytes(self): return b"not-a-maintenance-pod\0"
    try:
        recovery.Path = FakePath
        with pytest.raises(ValueError, match="dedicated"): recovery.maintenance_processes()
    finally:
        recovery.Path = original


def test_stop_processes_actually_stops_only_the_owned_child(tmp_path):
    # Use a single explicitly spawned child, never enumerate host processes.
    path = tmp_path / "heartbeat"
    child = subprocess.Popen([sys.executable, "-c", "import pathlib,sys,time; p=pathlib.Path(sys.argv[1]);\nwhile True: p.write_text(str(time.time_ns())); time.sleep(.02)", str(path)])
    try:
        deadline = time.monotonic() + 5
        while not path.exists() and time.monotonic() < deadline: time.sleep(.01)
        assert path.exists()
        stopped = False
        def inspect(pid):
            nonlocal stopped
            assert pid == child.pid
            if not stopped:
                got, status = os.waitpid(pid, os.WUNTRACED | os.WNOHANG)
                stopped = got == pid and os.WIFSTOPPED(status)
            return {"pid": pid, "start": "owned-child", "state": "T" if stopped else "S"}
        recovery.stop_processes([{"pid": child.pid, "start": "owned-child"}], inspect=inspect)
        before = path.read_bytes(); time.sleep(.1)
        assert path.read_bytes() == before
        os.kill(child.pid, signal.SIGCONT)
        deadline = time.monotonic() + 2
        while path.read_bytes() == before and time.monotonic() < deadline: time.sleep(.01)
        assert path.read_bytes() != before
    finally:
        child.kill(); child.wait(timeout=5)


@pytest.fixture
def abandoned_pod(maintenance, tmp_path):
    m = maintenance
    installed_path = m["work"] / "installed.json"
    installed = json.loads(installed_path.read_text())
    installed["site"]["storage"] = {"node": "source-node"}
    installed_path.write_text(json.dumps(installed))
    prepare(m)
    bindings = [{"role": role, "claim": "gsj-" + role} for role in ("data", "forgejo", "chroma")]
    (m["work"] / "capacity-before-bindings.json").write_text(json.dumps(bindings))
    name = "gsj-backup-operatio"
    image = installed["manifest"]["images"]["web"]
    mounts, volumes = [], []
    for binding in bindings:
        role = "gsj" if binding["role"] == "data" else binding["role"]
        mounts.append({"name": role, "mountPath": "/volumes/" + role})
        volumes.append({"name": role, "persistentVolumeClaim": {"claimName": binding["claim"]}})
    mounts.append({"name": "transfer", "mountPath": "/transfer"})
    volumes.append({"name": "transfer", "emptyDir": {}})
    pod = {"metadata": {"name": name, "uid": "old-maintenance-uid", "labels": {"gsj.io/operation": name}},
           "spec": {"automountServiceAccountToken": False, "nodeSelector": {"kubernetes.io/hostname": "source-node"},
                    "containers": [{"name": "maintenance", "image": image["repository"] + "@" + image["digest"],
                                    "command": ["sleep", "86400"], "volumeMounts": mounts}], "volumes": volumes}}
    transfer = tmp_path / "transfer"
    transfer.mkdir()
    (transfer / ".gsj-backup-incomplete").write_bytes(os.urandom(8192))
    (transfer / "metadata.json").write_text('{"synthetic":true}')
    _cluster(m, lambda state: state.update(pods={name: pod}, transfer=str(transfer)))
    payload = tmp_path / "payload" / "helpers"
    payload.mkdir(parents=True)
    (payload / "backup-recovery.py").write_bytes((ROOT / "ops/installer/backup-recovery.py").read_bytes())
    fake = tmp_path / "preservation-k.py"
    original = (tmp_path / "k.py").read_text()
    special = '''if a[:2]==['get','pod']: result=s.get('pods',{}).get(a[2])
elif a[:2]==['delete','--raw']:
 name=a[2].rsplit('/',1)[1]; options=json.loads(pathlib.Path(a[a.index('-f')+1]).read_text())
 assert options['preconditions']['uid']==s['pods'][name]['metadata']['uid']
 assert s.get('stopped') is True
 assert any(json.loads(f.read_text()).get('verified') is True for f in pathlib.Path(os.environ['BACKUP_DIR']).glob('*.previous-pod.enc.json'))
 if s.get('fail_delete'): p.write_text(json.dumps(s)); raise SystemExit(78)
 del s['pods'][name]
elif a[:1]==['exec']:
 import importlib.util
 module=pathlib.Path(os.environ['GSJ_PAYLOAD'])/'helpers'/'backup-recovery.py'
 spec=importlib.util.spec_from_file_location('fixture_recovery',module); recovery=importlib.util.module_from_spec(spec); spec.loader.exec_module(recovery)
 data=sys.stdin.buffer.read() if '-i' in a else b''
 if '-c' in a:
  assert data==module.read_bytes(); s['helper_staged']=True
 else:
  action=a[-1]; assert s['helper_staged']
  if action=='freeze':
   if s.get('fail_freeze'): p.write_text(json.dumps(s)); raise SystemExit(77)
   s['stopped']=True; result={'format':'gsj.exec-freeze/1','frozen':True}
  else:
   assert s.get('stopped') is True
   if action=='inspect': result=recovery.summary(recovery.inventory(s['transfer']))
   elif action=='archive':
    if s.get('fail_archive'): sys.stdout.buffer.write(b'incomplete encrypted attempt input'); p.write_text(json.dumps(s)); raise SystemExit(73)
    recovery.archive(s['transfer'],sys.stdout.buffer)
   elif action=='verify':
    import io
    if s.get('fail_verify'): p.write_text(json.dumps(s)); raise SystemExit(74)
    result=recovery.verify(s['transfer'],io.BytesIO(data))
   else: raise SystemExit('unexpected recovery action')
elif a[:1]==['wait']: pass
elif a[:2]==['get','namespace']'''
    fake.write_text(original.replace("if a[:2]==['get','namespace']", special).replace("print(json.dumps(result))", "print(json.dumps(result,sort_keys=True))"))
    env = {**m["env"], "GSJ_PAYLOAD": str(payload.parent)}

    def run(body="prepare_backup_generation 1"):
        script = f'''source {shlex.quote(str(tmp_path / 'functions.sh'))}
assert_owner() {{ :; }}
k() {{ {shlex.quote(sys.executable)} {shlex.quote(str(fake))} "$@"; }}
backup_credential_fingerprint() {{ printf '%064d\\n' 0; }}
capacity_qualify() {{ :; }}
capacity_host_filesystems() {{ printf '%s' '{{"backup":{{"available_bytes":1099511627776}}}}' > "$GSJ_WORK/capacity-host.json"; }}
{body}
'''
        return subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True)
    return {**m, "run_preservation": run, "transfer": transfer, "pod_name": name}


def test_generation_encrypts_verifies_then_uid_deletes_abandoned_writer_pod(abandoned_pod):
    m = abandoned_pod
    result = m["run_preservation"]()
    assert result.returncode == 0, result.stderr
    state = json.loads(m["cluster"].read_text())
    assert state["pods"] == {} and state["stopped"] is True
    artifact = m["backups"] / "operation123.g1.tar.gz.enc.previous-pod.enc"
    receipt = json.loads(Path(str(artifact) + ".json").read_text())
    assert receipt["verified"] is True
    assert receipt["archive_sha256"] == hashlib.sha256(artifact.read_bytes()).hexdigest()
    decrypted = subprocess.run(["openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", "600000",
                                "-pass", "file:" + str(m["password"]), "-in", str(artifact)], capture_output=True, check=True).stdout
    assert recovery.verify(m["transfer"], io.BytesIO(decrypted)) == receipt["transfer"]
    assert json.loads((m["state"] / "operation.json").read_text())["backup_generation"] == 1


@pytest.mark.parametrize("failure", ["fail_freeze", "fail_archive", "fail_verify"])
def test_failed_preservation_never_deletes_pod_or_admits_new_generation(abandoned_pod, failure):
    m = abandoned_pod
    _cluster(m, lambda state: state.update({failure: True}))
    result = m["run_preservation"]()
    assert result.returncode != 0
    state = json.loads(m["cluster"].read_text())
    assert m["pod_name"] in state["pods"]
    assert not any(a[:2] == ["delete", "--raw"] for a in state["calls"])
    assert "backup_generation" not in json.loads((m["state"] / "operation.json").read_text())


def test_interrupted_preservation_keeps_partial_ciphertext_and_named_retry_converges(abandoned_pod):
    m = abandoned_pod
    _cluster(m, lambda state: state.update(fail_archive=True))
    first = m["run_preservation"]()
    assert first.returncode != 0
    partials = list(m["backups"].glob("*.previous-pod.enc.partial.*"))
    assert len(partials) == 1
    prior = partials[0].read_bytes()
    _cluster(m, lambda state: state.update(fail_archive=False))
    second = m["run_preservation"]()
    assert second.returncode == 0, second.stderr
    assert partials[0].read_bytes() == prior
    assert json.loads(m["cluster"].read_text())["pods"] == {}


def test_preservation_receipt_does_not_allow_wrong_recovery_key_before_delete(abandoned_pod):
    m = abandoned_pod
    _cluster(m, lambda state: state.update(fail_delete=True))
    assert m["run_preservation"]().returncode != 0
    assert (m["backups"] / "operation123.g1.tar.gz.enc.previous-pod.enc.json").is_file()
    m["password"].write_text("a different protected recovery key\n")
    _cluster(m, lambda state: state.update(fail_delete=False, calls=[]))
    result = m["run_preservation"]()
    assert result.returncode != 0
    assert not any(a[:2] == ["delete", "--raw"] for a in json.loads(m["cluster"].read_text())["calls"])
