"""Immutable fresh source rounds and continuously stopped writer evidence."""
from copy import deepcopy
import json
from pathlib import Path
import subprocess

import pytest

from tests.test_installer_backup_retry import maintenance, _cluster, _verified, _archive, _snapshot


@pytest.fixture
def rounds(maintenance, tmp_path):
    m = maintenance
    source = json.loads((m["work"] / "installed.json").read_text())
    source["format"] = "gsj.installed/1"
    source["manifest"]["corpus"] = {"manifest_sha256": "b" * 64}
    source["site"]["corpus"] = {"repair_generation": 0}
    source["site"]["storage"] = {"node": "source-node", **{r: {"existing_claim": ""} for r in ("data", "forgejo", "chroma")}}
    (m["work"] / "installed.json").write_text(json.dumps(source))
    (m["state"] / "operation.json").write_text(json.dumps({"operation": "operation123", "kind": "upgrade", "target": "target-release", "status": "owned"}))
    state = json.loads(m["cluster"].read_text())
    for controller in state["controllers"]["items"]:
        pod = controller["spec"]["template"]["spec"]
        role = "data" if controller["metadata"]["name"] == "gsj-web" else controller["metadata"]["name"].removeprefix("gsj-")
        pod["nodeSelector"] = {"kubernetes.io/hostname": "source-node"}
        pod["volumes"] = [{"name": role, "persistentVolumeClaim": {"claimName": "gsj-" + role}}]
        for container in pod["containers"]:
            paths = {"gsj-web": [("/data/db", "db")], "agent-runner": [("/data/runner-workspace", "runner-workspace"), ("/runner-home", "runner-home")],
                     "gsj-mcp": [("/data/cases", "cases")], "forgejo": [("/data", "")], "chroma": [("/data", "")]}
            container["volumeMounts"] = [{"name": role, "mountPath": path, **({"subPath": sub} if sub else {})} for path, sub in paths[container["name"]]]
        if role == "data":
            images = source["manifest"]["images"]
            image = lambda key: images[key]["repository"] + "@" + images[key]["digest"]
            pod["initContainers"][0]["image"] = image("web")
            pod["initContainers"] += [{"name": "corpus-copy", "image": image("decisionsData"), "args": ["--destination", "/source", "--manifest-sha256", "b" * 64]},
                                      {"name": "corpus-initialize", "image": image("web"), "command": ["python", "-m", "gsj_deploy.initialize", "--settings", "/scripts/initializer.json"]}]
            pod["volumes"].append({"name": "scripts", "configMap": {"name": "gsj-scripts"}})
    state["source_cms"] = {"gsj-installed": _record(source), "gsj-scripts": {"data": {"initializer.json": json.dumps({"manifest_sha256": "b" * 64, "repair_generation": 0, "model_path": "/app/models/snowflake-arctic-embed-m-v2.0"})}}}
    m["cluster"].write_text(json.dumps(state))
    fake = tmp_path / "k.py"
    fake.write_text(fake.read_text().replace("if a[:2]==['get','namespace']", "if a[:2]==['get','configmap']: result=s['source_cms'].get(a[2])\nelif a[:2]==['get','namespace']").replace("b'synthetic verified PVC archive'", "s.get('archive_bytes','synthetic verified PVC archive').encode()"))
    return m


def _record(source):
    return {"metadata": {"labels": {"gsj.io/owner": "gsj"}}, "data": {"installed.json": json.dumps(source)}}


def _advance(m, *, identity="target-release", repair=1):
    def change(state):
        source = json.loads(state["source_cms"]["gsj-installed"]["data"]["installed.json"])
        source["status"] = "verification-pending"
        source["manifest"]["identity"] = identity
        source["site"]["corpus"]["repair_generation"] = repair
        state["source_cms"]["gsj-ready-state"] = _record(source)
        init = json.loads(state["source_cms"]["gsj-scripts"]["data"]["initializer.json"])
        init["repair_generation"] = repair
        state["source_cms"]["gsj-scripts"]["data"]["initializer.json"] = json.dumps(init)
        for controller in state["controllers"]["items"]:
            controller["metadata"]["generation"] += 1
            controller["spec"]["replicas"] = 1
            if controller["metadata"]["name"] == "gsj-web":
                controller["spec"]["template"]["spec"]["initContainers"][0]["env"][0]["value"] = identity + ":8"
    _cluster(m, change)


def _create_body():
    return '''maintenance_pod() { :; }
backup_resources() { for f in cluster-private.json volumes-private.json site_inputs.json; do printf '{}' > "$GSJ_WORK/$f"; done; }
backup
'''


def test_current_source_selects_actual_ready_target_over_old_complete_record(rounds):
    m = rounds
    _advance(m)
    result = m["run"]("read_backup_source current")
    assert result.returncode == 0, result.stderr
    source = json.loads((m["work"] / "installed.json").read_text())
    assert source["status"] == "verification-pending" and source["manifest"]["identity"] == "target-release"
    assert not any(a[0] != "get" for a in json.loads(m["cluster"].read_text())["calls"])


def test_matching_complete_record_preferred_only_when_source_payload_agrees(rounds):
    m = rounds
    source = json.loads((m["work"] / "installed.json").read_text())
    pending = {**source, "status": "verification-pending"}
    _cluster(m, lambda s: s["source_cms"].update({"gsj-ready-state": _record(pending)}))
    result = m["run"]("read_backup_source current")
    assert result.returncode == 0, result.stderr
    assert json.loads((m["work"] / "installed.json").read_text())["status"] == "complete"
    pending = deepcopy(pending)
    pending["site"]["public_url"] = "https://another.invalid"
    _cluster(m, lambda s: s["source_cms"].update({"gsj-ready-state": _record(pending)}))
    result = m["run"]("read_backup_source current")
    assert result.returncode != 0 and "ambiguous" in result.stderr


@pytest.mark.parametrize("fault", ["image", "corpus_image", "initializer_generation", "manifest", "model_path", "unowned", "namespace", "pv", "unrecorded_target"])
def test_current_source_rejects_mismatched_runtime_or_record_without_mutation(rounds, fault):
    m = rounds
    def change(s):
        pod = s["controllers"]["items"][0]["spec"]["template"]["spec"]
        if fault == "image": pod["containers"][0]["image"] = "unrecorded"
        elif fault == "corpus_image": pod["initContainers"][1]["image"] = "unrecorded"
        elif fault in {"initializer_generation", "manifest", "model_path"}:
            init = json.loads(s["source_cms"]["gsj-scripts"]["data"]["initializer.json"])
            init[{"initializer_generation": "repair_generation", "manifest": "manifest_sha256", "model_path": "model_path"}[fault]] = "changed"
            s["source_cms"]["gsj-scripts"]["data"]["initializer.json"] = json.dumps(init)
        elif fault == "unowned": s["source_cms"]["gsj-installed"]["metadata"]["labels"]["gsj.io/owner"] = "foreign"
        elif fault == "namespace": s["namespace_uid"] = "replacement"
        elif fault == "pv": s["storage"][0]["uid"] = "rebound"
        else: pod["initContainers"][0]["env"][0]["value"] = "unrecorded-target:8"
    _cluster(m, change)
    result = m["run"]("read_backup_source current")
    assert result.returncode != 0
    assert not any(a[0] != "get" for a in json.loads(m["cluster"].read_text())["calls"])


def test_fresh_round_preserves_old_archive_and_captures_new_source_before_stopping(rounds):
    m = rounds
    _verified(m)
    old = {p.name: p.read_bytes() for p in m["backups"].iterdir()}
    original_snapshot = _snapshot(m).read_bytes()
    _advance(m)
    result = m["run"]("prepare_backup_round 1; backup_archive; printf '\\n'; backup_pod_name")
    assert result.returncode == 0, result.stderr
    assert result.stdout.endswith("gsj-backup-operatio-r1")
    assert "operation123.r1.tar.gz.enc" in result.stdout
    assert {p.name: p.read_bytes() for p in m["backups"].iterdir()} == old
    assert _snapshot(m).read_bytes() == original_snapshot
    snapshot = json.loads((m["state"] / "quiescence-operation123.r1.json").read_text())
    assert snapshot["installed"]["manifest"]["identity"] == "target-release"
    assert all(c["spec"]["replicas"] == 1 for c in snapshot["controllers"]["items"])
    assert all(c["spec"]["replicas"] == 1 for c in json.loads(m["cluster"].read_text())["controllers"]["items"])
    result = m["run"](_create_body())
    assert result.returncode == 0, result.stderr
    receipt = json.loads((m["backups"] / "operation123.r1.tar.gz.enc.json").read_text())
    assert receipt["release_identity"] == "target-release" and receipt["round"] == 1
    assert all((m["backups"] / name).read_bytes() == data for name, data in old.items())


def test_selected_round_retry_and_lost_pointer_keep_original_intent_and_replicas(rounds):
    m = rounds
    _verified(m)
    _advance(m)
    assert m["run"]("prepare_backup_round 1").returncode == 0
    intent = m["state"] / "backup-round-operation123-1.json"
    before = intent.read_bytes()
    result = m["run"]("prepare_backup_round 1")
    assert result.returncode == 0, result.stderr
    state = json.loads((m["state"] / "operation.json").read_text())
    state.pop("backup_round"); state.pop("backup_generation")
    (m["state"] / "operation.json").write_text(json.dumps(state))
    result = m["run"]("prepare_backup_round 1")
    assert result.returncode == 0, result.stderr
    assert intent.read_bytes() == before
    assert m["run"]("quiesce; prepare_backup_round 1").returncode == 0
    assert intent.read_bytes() == before


def test_same_release_new_round_archives_later_bytes_and_can_take_another_round(rounds):
    m = rounds
    _verified(m)
    old = {p.name: p.read_bytes() for p in m["backups"].iterdir()}
    def writers(s):
        for controller in s["controllers"]["items"]:
            controller["metadata"]["generation"] += 1
            controller["spec"]["replicas"] = 1
        s["archive_bytes"] = "later synthetic case and history bytes"
    _cluster(m, writers)
    result = m["run"]("prepare_backup_round 1; " + _create_body())
    assert result.returncode == 0, result.stderr
    archive = m["backups"] / "operation123.r1.tar.gz.enc"
    decrypted = subprocess.run(["openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", "600000", "-pass", "file:" + str(m["password"]), "-in", str(archive)], capture_output=True, check=True).stdout
    assert decrypted == b"later synthetic case and history bytes"
    assert all((m["backups"] / name).read_bytes() == data for name, data in old.items())
    all_before = {p.name: p.read_bytes() for p in m["backups"].iterdir()}
    _cluster(m, writers)
    result = m["run"]("prepare_backup_round 2")
    assert result.returncode == 0, result.stderr
    assert {p.name: p.read_bytes() for p in m["backups"].iterdir()} == all_before
    intent = json.loads((m["state"] / "backup-round-operation123-2.json").read_text())
    assert intent["previous_archive"] == str(archive)


@pytest.mark.parametrize("fault", ["skip", "partial", "key", "archive", "site", "source", "collision", "kind"])
def test_fresh_round_refuses_without_replacing_or_stopping_anything(rounds, fault):
    m = rounds
    archive = _verified(m)
    _advance(m)
    command = "prepare_backup_round 1"
    if fault == "skip": command = "prepare_backup_round 2"
    elif fault == "partial": Path(str(archive) + ".json").unlink()
    elif fault == "key": m["password"].write_text("wrong recovery key")
    elif fault == "archive": archive.write_bytes(b"damaged original")
    elif fault in {"site", "source"}:
        assert m["run"](command).returncode == 0
        if fault == "site": (m["state"] / "site.pending.json").write_text('{"changed":true}')
        else: _advance(m, identity="different-target", repair=2)
    elif fault == "collision": (m["backups"] / "operation123.r1.tar.gz.enc.partial").write_bytes(b"unowned")
    else:
        path = m["state"] / "operation.json"; op = json.loads(path.read_text()); op["kind"] = "restore"; path.write_text(json.dumps(op))
    _cluster(m, lambda s: s.update(calls=[]))
    before = {p.name: p.read_bytes() for p in m["backups"].iterdir()}
    result = m["run"](command)
    assert result.returncode != 0
    assert {p.name: p.read_bytes() for p in m["backups"].iterdir()} == before
    assert not any(a[0] == "scale" for a in json.loads(m["cluster"].read_text())["calls"])


def test_incomplete_generation_is_scoped_to_its_new_round(rounds):
    m = rounds
    _verified(m); _advance(m)
    assert m["run"]("prepare_backup_round 1; quiesce").returncode == 0
    partial = m["backups"] / "operation123.r1.tar.gz.enc.partial"
    partial.write_bytes(b"newer interrupted source archive")
    result = m["run"]("prepare_backup_generation 1; backup_archive; printf '\\n'; backup_pod_name")
    assert result.returncode == 0, result.stderr
    assert "operation123.r1.g1.tar.gz.enc" in result.stdout and result.stdout.endswith("gsj-backup-operatio-r1-g1")
    assert partial.read_bytes() == b"newer interrupted source archive"
    assert (m["state"] / "backup-generation-operation123.r1-1.json").is_file()


@pytest.mark.parametrize("fault", ["up_down", "pv", "credentials", "writer_pod", "active_job", "pending_job", "finished_new_job", "missing_closure"])
def test_reuse_requires_continuous_stopped_writers_storage_and_credentials(rounds, fault):
    m = rounds
    _verified(m)
    command = "backup"
    if fault == "up_down": _cluster(m, lambda s: [c["metadata"].update(generation=c["metadata"]["generation"] + 2) for c in s["controllers"]["items"]])
    elif fault == "pv": _cluster(m, lambda s: s["storage"][0].update(pv_uid="replacement-pv"))
    elif fault == "credentials": command = "backup_credential_fingerprint() { printf '%064d\\n' 1; }; backup"
    elif fault == "writer_pod": _cluster(m, lambda s: s.update(writer_pods=[{"status": {"phase": "Running"}}]))
    elif fault == "active_job": _cluster(m, lambda s: s.update(writer_jobs=[{"status": {"active": 1}}]))
    elif fault == "pending_job": _cluster(m, lambda s: s.update(writer_jobs=[{"status": {}}]))
    elif fault == "finished_new_job": _cluster(m, lambda s: s.update(writer_jobs=[{"metadata": {"name": "new-job", "uid": "new-job-uid"}, "status": {"conditions": [{"type": "Complete", "status": "True"}]}}]))
    else:
        Path(str(_snapshot(m)) + ".closure.json").unlink()
        receipt = Path(str(_archive(m)) + ".json"); value = json.loads(receipt.read_text()); value.pop("closure_sha256"); receipt.write_text(json.dumps(value))
    before = {p.name: p.read_bytes() for p in m["backups"].iterdir()}
    _cluster(m, lambda s: s.update(calls=[]))
    result = m["run"](command)
    assert result.returncode != 0
    assert {p.name: p.read_bytes() for p in m["backups"].iterdir()} == before
    assert not any(a[0] == "scale" for a in json.loads(m["cluster"].read_text())["calls"])


def test_lost_closure_publication_continues_only_the_single_scale_to_zero(rounds):
    m = rounds
    result = m["run"]("backup_closure_state() { return 89; }; quiesce")
    assert result.returncode == 89
    assert not Path(str(_snapshot(m)) + ".closure.json").exists()
    assert m["run"]("quiesce").returncode == 0
    closure = Path(str(_snapshot(m)) + ".closure.json")
    original = closure.read_bytes()
    result = m["run"]("quiesce")
    assert result.returncode == 0 and closure.read_bytes() == original
    closure.unlink()
    _cluster(m, lambda s: [c["metadata"].update(generation=c["metadata"]["generation"] + 2) for c in s["controllers"]["items"]])
    result = m["run"]("quiesce")
    assert result.returncode != 0 and not closure.exists()


def test_tampered_round_snapshot_and_closure_cannot_certify_an_old_archive(rounds):
    m = rounds
    _verified(m)
    assert m["run"]("prepare_backup_round 1; " + _create_body()).returncode == 0
    snapshot = m["state"] / "quiescence-operation123.r1.json"
    original = snapshot.read_bytes()
    value = json.loads(original); value["controllers"]["items"][0]["spec"]["replicas"] = 7
    snapshot.write_text(json.dumps(value))
    assert m["run"]("backup_archive").returncode != 0
    snapshot.write_bytes(original)
    closure = Path(str(snapshot) + ".closure.json")
    value = json.loads(closure.read_text()); value["controllers"][0]["generation"] += 2
    closure.write_text(json.dumps(value))
    result = m["run"]("backup")
    assert result.returncode != 0 and "closure differs" in result.stderr


def test_restarted_writer_during_archive_cannot_publish_verified_receipt(rounds):
    m = rounds
    body = _create_body().replace("backup\n", '''eval "$(declare -f capacity_scan_pod | sed '1s/capacity_scan_pod/original_scan/')"
capacity_scan_pod() { k scale deployment --replicas=1 >/dev/null; }
backup
''')
    result = m["run"](body)
    assert result.returncode != 0
    assert not Path(str(_archive(m)) + ".json").exists()


def test_long_release_and_round_generation_have_bounded_distinct_pod_names(rounds):
    m = rounds
    path = m["state"] / "operation.json"
    state = json.loads(path.read_text()); state.update(backup_round=999999, backup_generation=999999)
    path.write_text(json.dumps(state))
    first = m["run"]("RELEASE=" + "a" * 48 + "; backup_pod_name")
    second = m["run"]("RELEASE=" + "a" * 47 + "b; backup_pod_name")
    assert first.returncode == second.returncode == 0
    assert first.stdout != second.stdout
    assert len(first.stdout) <= 63 and len(second.stdout) <= 63
    assert "-r999999-g999999-" in first.stdout
