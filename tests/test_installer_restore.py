"""Named restore control recovery; synthetic Kubernetes, real encrypted inputs.

These tests exercise the shipped Bash ownership/phase protocol. Actual archive
extraction and killed file writers are tested separately by restore-files.
"""
import json
import hashlib

import pytest

from tests.test_installer import _restore_fixture, runtime


@pytest.mark.parametrize('fault', ['empty-omitted', 'nonempty-omitted', 'changed-list'])
def test_restore_pod_normalizes_only_omitted_empty_pull_credentials(runtime, fault):
    run, state, work = runtime
    operation = 'a' * 24
    pulls = [] if fault == 'empty-omitted' else [{'name': 'synthetic-registry'}]
    desired = {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': 'synthetic-restore'},
               'spec': {'imagePullSecrets': pulls, 'containers': [{'name': 'maintenance', 'image': 'registry.invalid/synthetic'}]}}
    source = work / 'desired.json'; source.write_text(json.dumps(desired))
    (work / 'restoration.json').write_text(json.dumps({'archive_sha256': 'b' * 64}))
    cluster = {'lease': {'spec': {'holderIdentity': operation}}, 'calls': [], 'resources': {}}
    state.write_text(json.dumps(cluster))
    body = 'OPERATION="$ID"; restore_resource "$SOURCE"'
    first = run(body, ID=operation, SOURCE=str(source))
    assert first.returncode == 0, first.stderr
    saved = work / f'restore-{operation}/Pod/synthetic-restore'
    intent = (saved / 'intent.json').read_bytes()
    (saved / 'receipt.json').unlink()
    cluster = json.loads(state.read_text()); cluster['calls'] = []
    actual = cluster['resources']['Pod/synthetic-restore']
    if fault == 'changed-list': actual['spec']['imagePullSecrets'] = [{'name': 'foreign-registry'}]
    else: actual['spec'].pop('imagePullSecrets')
    state.write_text(json.dumps(cluster))
    result = run(body, ID=operation, SOURCE=str(source))
    assert (result.returncode == 0) == (fault == 'empty-omitted'), result.stderr
    after = json.loads(state.read_text())
    assert after['resources'] == cluster['resources']
    assert (saved / 'intent.json').read_bytes() == intent
    assert not any(c[0] in ('create', 'replace', 'delete', 'apply') for c in after['calls'])
    assert (saved / 'receipt.json').exists() == (fault == 'empty-omitted')


def _expire(state):
    data = json.loads(state.read_text())
    operation = data["lease"]["spec"]["holderIdentity"]
    data["lease"]["spec"]["renewTime"] = "2000-01-01T00:00:00.000000Z"
    state.write_text(json.dumps(data))
    return operation


def test_named_restore_reconciles_partial_creates_without_replacing_credentials(runtime, tmp_path):
    invoke, _ = _restore_fixture(runtime, tmp_path)
    _, state, work = runtime
    data = json.loads(state.read_text())
    data["fail_create"] = "ConfigMap/synthetic-release-trust"
    state.write_text(json.dumps(data))
    failed = invoke()
    assert failed.returncode != 0
    before = json.loads(state.read_text())["resources"]
    assert before and all(v["metadata"]["uid"] for v in before.values())
    operation = _expire(state)
    data = json.loads(state.read_text())
    del data["fail_create"]
    state.write_text(json.dumps(data))
    # Model a response accepted by Kubernetes before the tools process saved
    # the UID receipt. The durable create intent and attempted flag survive.
    receipt = work / f"restore-{operation}/Secret/synthetic-release-admin-token/receipt.json"
    receipt.unlink()
    result = invoke("restore-repair", operation)
    assert result.returncode == 0, result.stderr
    after = json.loads(state.read_text())
    assert all(after["resources"][key] == value for key, value in before.items())
    assert not any(call[0] in ("delete", "apply") for call in after["calls"])
    assert json.loads((work / "restoration.json").read_text())["status"] == "complete"


def test_lost_create_response_is_reconciled_by_actual_identity(runtime, tmp_path):
    invoke, _ = _restore_fixture(runtime, tmp_path)
    _, state, work = runtime
    data = json.loads(state.read_text())
    data["fail_after_create"] = "Secret/synthetic-release-operator"
    state.write_text(json.dumps(data))
    result = invoke()
    assert result.returncode == 0, result.stderr
    checkpoint = json.loads((work / "restoration.json").read_text())
    receipt = work / f"restore-{checkpoint['operation']}/Secret/synthetic-release-operator/receipt.json"
    assert json.loads(receipt.read_text())["uid"] == "created-synthetic-release-operator"


def test_restore_recovers_lease_before_any_canonical_checkpoint(runtime, tmp_path):
    invoke, _ = _restore_fixture(runtime, tmp_path)
    _, state, work = runtime
    result = invoke(before_restore="recover_operation_intent() { exit 79; }")
    assert result.returncode == 79, result.stderr
    assert not (work / "restoration.json").exists()
    assert not (work / "operation.json").exists()
    operation = _expire(state)
    intent = work / f"operation-intents/{operation}/intent.json"
    original = intent.read_bytes()
    recovered = invoke("restore-repair", operation)
    assert recovered.returncode == 0, recovered.stderr
    assert intent.read_bytes() == original
    assert json.loads((work / "operation.json").read_text())["operation"] == operation
    assert json.loads((work / "restoration.json").read_text())["status"] == "complete"


@pytest.mark.parametrize("damage", ["resource-uid", "resource-data", "namespace", "operation", "live-lease", "archive"])
def test_named_restore_refuses_changed_identity_or_bytes(runtime, tmp_path, damage):
    invoke, _ = _restore_fixture(runtime, tmp_path)
    _, state, work = runtime
    data = json.loads(state.read_text())
    data["fail_restore"] = True
    state.write_text(json.dumps(data))
    assert invoke().returncode != 0
    operation = _expire(state)
    data = json.loads(state.read_text())
    del data["fail_restore"]
    item = data["resources"]["Secret/synthetic-release-operator"]
    if damage == "resource-uid": item["metadata"]["uid"] = "replacement-uid"
    elif damage == "resource-data": item["data"]["unexpected"] = "c3ludGhldGlj"
    elif damage == "namespace": data["namespace_uid"] = "replacement-namespace"
    elif damage == "operation": operation = "f" * 24
    elif damage == "live-lease": data["lease"]["spec"]["renewTime"] = "2099-01-01T00:00:00.000000Z"
    elif damage == "archive":
        metadata = tmp_path / "snapshot.tar.gz.enc.json"
        metadata.write_text(metadata.read_text() + "\n")
    data["calls"] = []
    state.write_text(json.dumps(data))
    result = invoke("restore-repair", operation)
    assert result.returncode != 0
    after = json.loads(state.read_text())
    assert after["resources"] == data["resources"]
    assert not any(call[0] in ("create", "delete", "apply", "exec") for call in after["calls"])


@pytest.mark.parametrize("kind", ["Deployment", "Pod"])
def test_restore_refuses_foreign_writer_even_without_application_labels(runtime, tmp_path, kind):
    invoke, _ = _restore_fixture(runtime, tmp_path)
    _, state, _ = runtime
    data = json.loads(state.read_text())
    spec = {"volumes": [{"name": "foreign", "persistentVolumeClaim": {"claimName": "synthetic-release-data"}}]}
    data["resources"][kind + "/foreign-writer"] = {
        "kind": kind, "metadata": {"name": "foreign-writer", "uid": "unrelated-uid"},
        "spec": spec if kind == "Pod" else {"template": {"spec": spec}},
    }
    state.write_text(json.dumps(data))
    result = invoke()
    assert result.returncode != 0, result.stderr
    after = json.loads(state.read_text())
    assert after["resources"] == data["resources"]
    assert not any(call[0] == "exec" for call in after["calls"])


def test_restore_repair_interface_is_exposed_without_bootstrap(runtime):
    run, _, _ = runtime
    result = run("main help")
    assert result.returncode == 0
    assert "restore-repair --operation ID" in result.stdout
    assert "backup-repair --operation ID --generation N" in result.stdout


@pytest.mark.parametrize("window", ["resource-intent", "files-proof"])
def test_restore_phase_updates_reconcile_interruption_between_files(runtime, tmp_path, window):
    invoke, _ = _restore_fixture(runtime, tmp_path)
    _, state, work = runtime
    data = json.loads(state.read_text())
    if window == "resource-intent": data["fail_create"] = "Secret/synthetic-release-admin-token"
    else: data["fail_restore"] = True
    state.write_text(json.dumps(data))
    assert invoke().returncode != 0
    operation = _expire(state)
    data = json.loads(state.read_text())
    data.pop("fail_create", None); data.pop("fail_restore", None)
    data["calls"] = []
    state.write_text(json.dumps(data))
    if window == "resource-intent":
        path = work / "operation.json"
        doc = json.loads(path.read_text()); doc["status"] = "owned"
    else:
        # The fixture treats filesystem proof as a separately tested boundary.
        # This models proof/restore checkpoint published before operation phase.
        path = work / "restoration.json"
        doc = json.loads(path.read_text()); doc["status"] = "files-restored"
    path.write_text(json.dumps(doc))
    result = invoke("restore-repair", operation)
    assert result.returncode == 0, result.stderr
    assert json.loads((work / "restoration.json").read_text())["status"] == "complete"
    if window == "files-proof":
        calls = json.loads(state.read_text())["calls"]
        assert any("restore-finish" in call for call in calls)
        assert not any(call[0] == "create" or (call[0] == "exec" and "restore" in call) for call in calls)


def _binding_fixture(runtime):
    run, state, work = runtime
    operation = "a" * 24
    pod = "synthetic-restore"
    saved = work / f"restore-{operation}"
    resources = {}
    claims = []
    (work / "values.pending.json").write_text(json.dumps({"storage": {key: {"existingClaim": ""} for key in ("data", "forgejo", "chroma")}}))
    for key in ("data", "forgejo", "chroma"):
        name = "synthetic-release-" + key
        uid, volume = "claim-" + key, "pv-" + key
        claims.append(name)
        directory = saved / "PersistentVolumeClaim" / name
        directory.mkdir(parents=True)
        (directory / "receipt.json").write_text(json.dumps({"uid": uid}))
        resources["PersistentVolumeClaim/" + name] = {"kind": "PersistentVolumeClaim", "metadata": {"name": name, "uid": uid}, "spec": {"volumeName": volume}, "status": {"phase": "Bound"}}
        resources["PersistentVolume/" + volume] = {"kind": "PersistentVolume", "metadata": {"name": volume, "uid": "backend-" + key}, "spec": {"claimRef": {"uid": uid, "name": name, "namespace": "synthetic-namespace"}}}
    (work / "restoration.json").write_text(json.dumps({"operation": operation, "pod": pod, "target_namespace_uid": "target-namespace-uid", "references": {"PersistentVolumeClaim": claims}}))
    (work / "operation.json").write_text(json.dumps({"operation": operation, "kind": "restore", "target": "synthetic-release", "status": "restore-files-verified"}))
    data = json.loads(state.read_text())
    data["resources"] = resources
    state.write_text(json.dumps(data))
    prefix = f'OPERATION={operation}\nassert_owner() {{ :; }}\n'
    return run, state, work, saved, operation, pod, prefix


@pytest.mark.parametrize("damage", ["pvc-uid", "pv-uid", "pv-owner", "namespace", "unbound"])
def test_restore_binding_replay_refuses_storage_replacement(runtime, damage):
    run, state, _, saved, _, _, prefix = _binding_fixture(runtime)
    first = run(prefix + "restore_bindings")
    assert first.returncode == 0, first.stderr
    proof = (saved / "bindings.json").read_bytes()
    data = json.loads(state.read_text())
    claim = data["resources"]["PersistentVolumeClaim/synthetic-release-data"]
    volume = data["resources"]["PersistentVolume/pv-data"]
    if damage == "pvc-uid": claim["metadata"]["uid"] = "replacement"
    elif damage == "pv-uid": volume["metadata"]["uid"] = "replacement"
    elif damage == "pv-owner": volume["spec"]["claimRef"]["uid"] = "foreign"
    elif damage == "namespace": volume["spec"]["claimRef"]["namespace"] = "another-namespace"
    elif damage == "unbound": claim["status"]["phase"] = "Pending"
    state.write_text(json.dumps(data))
    result = run(prefix + "restore_bindings")
    assert result.returncode != 0
    assert (saved / "bindings.json").read_bytes() == proof


@pytest.mark.parametrize("damage", [None, "pod-uid", "namespace-uid", "result-hash"])
def test_restore_pod_cleanup_uses_exact_uid_and_saved_file_proof(runtime, damage):
    run, state, work, saved, operation, pod, prefix = _binding_fixture(runtime)
    settings = {"namespace_uid": "target-namespace-uid", "release_identity": "synthetic-release", "archive_sha256": "b" * 64, "encrypted_archive_sha256": "c" * 64}
    payload = json.dumps(settings).encode()
    (saved / "files-settings.json").write_bytes(payload)
    (saved / "archive-proof.json").write_text(json.dumps({"manifest_sha256": "d" * 64, "entries": 9}))
    result = {"format": "gsj.restore-files-result/1", "status": "complete", "restored": True, "operation": operation, **settings, "settings_file_sha256": hashlib.sha256(payload).hexdigest(), "manifest_sha256": "d" * 64, "entries": 9}
    if damage == "result-hash": result["archive_sha256"] = "e" * 64
    (saved / "files-result.json").write_text(json.dumps(result))
    directory = saved / "Pod" / pod
    directory.mkdir(parents=True)
    (directory / "receipt.json").write_text(json.dumps({"uid": "restore-pod-uid"}))
    data = json.loads(state.read_text())
    data["resources"]["Pod/" + pod] = {"kind": "Pod", "metadata": {"name": pod, "uid": "replacement" if damage == "pod-uid" else "restore-pod-uid"}, "spec": {"volumes": []}}
    if damage == "namespace-uid": data["namespace_uid"] = "replacement"
    state.write_text(json.dumps(data))
    completed = run(prefix + "restore_finish_pod")
    after = json.loads(state.read_text())
    if damage:
        assert completed.returncode != 0
        assert after["resources"] == data["resources"]
    else:
        assert completed.returncode == 0, completed.stderr
        assert "Pod/" + pod not in after["resources"]
        # Lost delete response: the same completion proof admits absence,
        # without recreating the Pod or revisiting restored data.
        again = run(prefix + "restore_finish_pod")
        assert again.returncode == 0, again.stderr


def _quantity_pod():
    return {'apiVersion':'v1','kind':'Pod','metadata':{'name':'owned-proof','labels':{'gsj.io/startup-source':'a'*24}},'spec':{'automountServiceAccountToken':False,'containers':[{'name':'proof','image':'signed@sha256:'+'b'*64,'resources':{'requests':{'cpu':'100m','memory':'512Mi'},'limits':{'cpu':'1000m','memory':'1024Mi'}},'volumeMounts':[{'name':'data','mountPath':'/volumes/gsj','readOnly':True}]}],'volumes':[{'name':'data','persistentVolumeClaim':{'claimName':'exact-data','readOnly':True}}]}}


def _compare_quantities(runtime,expected,actual):
    run,state,work=runtime
    wanted=work/'quantity-expected.json';live=work/'quantity-actual.json'
    wanted.write_text(json.dumps(expected));live.write_text(json.dumps(actual));before=wanted.read_bytes(),live.read_bytes()
    result=run('owned_resource_matches "$ACTUAL" "$EXPECTED"',ACTUAL=str(live),EXPECTED=str(wanted))
    assert before==(wanted.read_bytes(),live.read_bytes())
    return result


@pytest.mark.parametrize('part,resource,expected,actual',[
    ('limits','cpu','1000m','1'),('requests','cpu','2000m','2'),
    ('limits','memory','1024Mi','1Gi'),('requests','memory','1048576Ki','1Gi'),
    ('limits','memory','1073741824','1Gi'),('limits','memory','1024Gi','1Ti'),
])
def test_owned_pod_compares_equivalent_positive_resource_quantities(runtime,part,resource,expected,actual):
    from copy import deepcopy
    want=_quantity_pod();want['spec']['containers'][0]['resources'][part][resource]=expected
    live=deepcopy(want);live['metadata']['uid']='original-owned-uid';live['spec']['containers'][0]['resources'][part][resource]=actual
    result=_compare_quantities(runtime,want,live);assert result.returncode==0,result.stderr


def test_owned_pod_quantity_normalization_also_preserves_init_container_shape(runtime):
    from copy import deepcopy
    want=_quantity_pod();want['spec']['initContainers']=[{'name':'readonly-preflight','image':'signed-preflight','resources':{'limits':{'cpu':'1000m','memory':'1024Mi'}}}]
    live=deepcopy(want);live['spec']['initContainers'][0]['resources']['limits']={'cpu':'1','memory':'1Gi'}
    result=_compare_quantities(runtime,want,live);assert result.returncode==0,result.stderr
    live['spec']['initContainers'].append(deepcopy(live['spec']['initContainers'][0]))
    assert _compare_quantities(runtime,want,live).returncode!=0


@pytest.mark.parametrize('damage',['cpu','memory','missing_limits','missing_cpu','missing_request','extra_container','mount','missing_label','changed_label'])
def test_resource_quantity_normalization_does_not_weaken_other_ownership(runtime,damage):
    from copy import deepcopy
    want=_quantity_pod();live=deepcopy(want);container=live['spec']['containers'][0]
    container['resources']['limits'].update(cpu='1',memory='1Gi')
    if damage=='cpu':container['resources']['limits']['cpu']='2'
    elif damage=='memory':container['resources']['limits']['memory']='2Gi'
    elif damage=='missing_limits':container['resources'].pop('limits')
    elif damage=='missing_cpu':container['resources']['limits'].pop('cpu')
    elif damage=='missing_request':container['resources']['requests'].pop('memory')
    elif damage=='extra_container':live['spec']['containers'].append(deepcopy(container))
    elif damage=='mount':container['volumeMounts'][0]['readOnly']=False
    elif damage=='missing_label':live['metadata'].pop('labels')
    else:live['metadata']['labels']['gsj.io/startup-source']='foreign'
    assert _compare_quantities(runtime,want,live).returncode!=0


@pytest.mark.parametrize('resource,value',[
    ('cpu','0'),('cpu','-1'),('cpu','NaN'),('cpu','Infinity'),('cpu','1e3'),('cpu','0.5'),('cpu',1),('cpu',None),
    ('cpu','9007199254740993m'),('cpu','9007199254741'),
    ('memory','0Mi'),('memory','-1Gi'),('memory','1G'),('memory','1.5Gi'),('memory','9007199254740993'),('memory','8192Ti'),
])
def test_owned_pod_refuses_unsupported_or_inexact_quantities_even_when_identical(runtime,resource,value):
    from copy import deepcopy
    want=_quantity_pod();want['spec']['containers'][0]['resources']['limits'][resource]=value
    assert _compare_quantities(runtime,want,deepcopy(want)).returncode!=0
