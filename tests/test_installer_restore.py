"""Named restore control recovery; synthetic Kubernetes, real encrypted inputs.

These tests exercise the shipped Bash ownership/phase protocol. Actual archive
extraction and killed file writers are tested separately by restore-files.
"""
import ast
import json
import hashlib
import os

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


# --- the transfer directory has room for the decrypted archive before the stream ----

GIB = 1024 ** 3


def _staging(runtime, tmp_path, transfer, free, size=1000, total=GIB, shared=False, floor=None):
    """restore_files up to its stream: the Pod is Ready, the writers and the
    bindings are proven, and the fake exec answers the measurement -- free
    bytes, the filesystem's size, and whether /transfer shares its filesystem
    with an application volume. The default filesystem is small enough that
    its 15 % never decides the margin."""
    run, state, work = runtime
    site = json.loads((work / "site.json").read_text())
    site["storage"]["transfer_path"] = transfer
    if floor is not None:
        site["storage"]["minimum_free_bytes"] = floor
    (work / "site.json").write_text(json.dumps(site))
    (work / "values.pending.json").write_text(json.dumps({
        "image": {"pullSecrets": []}, "storage": {key: {"existingClaim": ""} for key in ("data", "forgejo", "chroma")}}))
    (work / "restoration.json").write_text(json.dumps({"archive_sha256": "c" * 64}))
    archive = tmp_path / "archive.enc"
    archive.write_bytes(b"")
    os.truncate(archive, size)      # sparse: its length is all the check reads
    cluster = json.loads(state.read_text())
    answer = f"{free} {total} {int(shared)}\n" if free != "" else ""
    cluster.update(resources={}, calls=[], exec_rules=[{"match": "statvfs", "stdout": answer}])
    state.write_text(json.dumps(cluster))
    result = run(f'''OPERATION={"a" * 24}; ARCHIVE="$TEST_ARCHIVE"; BACKUP_PASSWORD="$TEST_ARCHIVE"
trap 'echo "HINT=${{RECOVERY_HINT:-}}" >&2' EXIT
restore_resource() {{ :; }}; restore_no_writers() {{ :; }}; restore_bindings() {{ :; }}; assert_owner() {{ :; }}
restore_files synthetic-restore synthetic-release registry.invalid/web@sha256:{"e" * 64}
''', TEST_ARCHIVE=str(archive))
    return result, json.loads(state.read_text())["calls"]


def _streamed(calls):
    return [c for c in calls if c[:2] == ["exec", "-i"]]


@pytest.mark.parametrize("transfer, where", [
    ("/data/gsj-install/transfer", "/data/gsj-install/transfer/" + "a" * 24 + " on node synthetic-node"),
    ("", "emptyDir on node synthetic-node's own filesystem"),
])
def test_a_transfer_directory_without_room_for_the_archive_is_refused_before_the_stream(runtime, tmp_path, transfer, where):
    """restore_files streamed the decrypted archive into /transfer without
    asking whether it fits; a full node disk would end the stream partway,
    after all the time the transfer took."""
    result, calls = _staging(runtime, tmp_path, transfer, free=268435456)
    assert result.returncode != 0
    assert _streamed(calls) == [], "refused before a byte was streamed"
    refusal = next(line for line in result.stderr.splitlines() if line.startswith("GSJ: "))
    assert refusal.startswith("GSJ: restore staging space is insufficient"), refusal
    assert where in refusal
    # the encrypted archive is 1000 bytes; the margin is the larger of 256 MiB and a tenth of it
    assert "268435456 bytes free" in refusal and str(1000 + 268435456) in refusal
    assert "nothing was streamed" in refusal
    assert any(c[:1] == ["exec"] and "statvfs" in " ".join(c) for c in calls), "measured inside the Pod"
    hint = result.stderr.rsplit("HINT=", 1)[1]
    assert hint.startswith("restore-repair --operation " + "a" * 24), hint


def test_a_tenth_of_a_large_archive_is_the_margin(runtime, tmp_path):
    size = 3 * 1024 ** 3                                  # a tenth of it is more than 256 MiB
    result, calls = _staging(runtime, tmp_path, "/data/gsj-install/transfer", free=size + 268435456, size=size)
    assert result.returncode != 0
    assert _streamed(calls) == []
    refusal = next(line for line in result.stderr.splitlines() if line.startswith("GSJ: "))
    assert str(size + size // 10) in refusal, refusal


def test_a_transfer_directory_with_room_is_streamed_into(runtime, tmp_path):
    result, calls = _staging(runtime, tmp_path, "/data/gsj-install/transfer", free=1000 + 268435456)
    assert "restore staging space" not in result.stderr
    assert len(_streamed(calls)) == 1, "the measurement admitted the stream"


def test_an_unmeasured_transfer_directory_is_refused_before_the_stream(runtime, tmp_path):
    result, calls = _staging(runtime, tmp_path, "/data/gsj-install/transfer", free="")
    assert result.returncode != 0
    assert _streamed(calls) == []
    refusal = next(line for line in result.stderr.splitlines() if line.startswith("GSJ: "))
    assert refusal.startswith("GSJ: restore staging space is unmeasured"), refusal
    assert "nothing was streamed" in refusal

def _refusal(result):
    return next(line for line in result.stderr.splitlines() if line.startswith("GSJ: "))


def test_fifteen_percent_of_the_filesystem_stays_free_after_the_stream(runtime, tmp_path):
    """An emptyDir lives on the node's root filesystem, where the kubelet
    evicts Pods by default below 10 % free (nodefs.available) and, where the
    images share that filesystem as on a single-disk node, below 15 %
    (imagefs.available): an archive that fit with 256 MiB to spare could push
    the node under that line and get the restore Pod evicted after the whole
    transfer. A tenth kept free was still under the image line. What stays
    free after the stream is at least 15 % of the filesystem."""
    transfer, total, size = "", 100 * GIB, 1000
    margin = total * 15 // 100
    result, calls = _staging(runtime, tmp_path, transfer, free=size + margin - 1, total=total, size=size)
    assert result.returncode != 0
    assert _streamed(calls) == [], "refused before a byte was streamed"
    refusal = _refusal(result)
    assert refusal.startswith("GSJ: restore staging space is insufficient"), refusal
    assert f"a margin of {margin}" in refusal and str(size + margin) in refusal, refusal
    assert f"15 % of the filesystem's {total} bytes" in refusal, refusal
    assert "eviction thresholds" in refusal and "imagefs.available" in refusal, refusal
    result, calls = _staging(runtime, tmp_path, transfer, free=size + margin, total=total, size=size)
    assert "restore staging space" not in result.stderr
    assert len(_streamed(calls)) == 1


HOST_PATH = "/data/gsj-install/transfer"


def test_a_transfer_hostpath_is_not_held_to_a_share_of_its_filesystem(runtime, tmp_path):
    """The kubelet's eviction thresholds watch the node's root filesystem,
    where an emptyDir lives. storage.transfer_path is a directory the operator
    chose, a dedicated data disk among others: a share of that disk kept free
    refused restores that fit. There the least margin and a tenth of the
    archive hold, and nothing about the filesystem's size."""
    total, size = 2000 * GIB, 1000
    result, calls = _staging(runtime, tmp_path, HOST_PATH, free=size + 268435456, total=total, size=size)
    assert "restore staging space" not in result.stderr, _refusal(result)
    assert len(_streamed(calls)) == 1, "the least margin admitted the stream"
    result, calls = _staging(runtime, tmp_path, HOST_PATH, free=size + 268435456 - 1, total=total, size=size)
    assert result.returncode != 0 and _streamed(calls) == []
    refusal = _refusal(result)
    assert "a margin of 268435456: 256 MiB, the least margin" in refusal, refusal
    assert "of the filesystem's" not in refusal and "eviction" not in refusal, refusal


@pytest.mark.parametrize("size, total, shared, floor, named", [
    (1000, 100 * GIB, False, None, "256 MiB, the least margin"),
    (3 * GIB, 100 * GIB, False, None, "a tenth of the archive"),
    (1000, 100 * GIB, True, 20 * GIB, "storage.minimum_free_bytes"),
    (30 * GIB, 100 * GIB, True, GIB, "a tenth of the archive"),       # a floor below the archive's tenth does not decide
], ids=["least", "archive", "site-floor", "floor-below-the-archive"])
def test_a_transfer_hostpath_refusal_names_only_the_floor_that_applied(runtime, tmp_path, size, total, shared, floor, named):
    """On a hostPath the floors are the least margin, a tenth of the archive and,
    on the application volumes' filesystem, storage.minimum_free_bytes: the
    refusal names the one that decided and never the filesystem's share."""
    result, calls = _staging(runtime, tmp_path, HOST_PATH, free=1000, total=total, size=size, shared=shared, floor=floor)
    assert result.returncode != 0 and _streamed(calls) == []
    refusal = _refusal(result)
    assert named in refusal, refusal
    for other in {"256 MiB, the least margin", "a tenth of the archive", "15 % of the filesystem's", "storage.minimum_free_bytes"} - {named}:
        assert other not in refusal, (other, refusal)
    margin = {"256 MiB, the least margin": 268435456, "a tenth of the archive": size // 10, "storage.minimum_free_bytes": floor}[named]
    assert f"needs {size + margin} (" in refusal, refusal


def test_a_transfer_directory_on_the_volumes_filesystem_leaves_the_sites_free_space_floor(runtime, tmp_path):
    """/transfer on the filesystem the restored volumes live on: the stream
    spends the room the application needs there, which the backup's capacity
    check keeps at storage.minimum_free_bytes. The same floor holds here."""
    total, size, floor = 100 * GIB, 1000, 20 * GIB
    result, calls = _staging(runtime, tmp_path, "", free=size + 15 * GIB, total=total, size=size, shared=True, floor=floor)
    assert result.returncode != 0
    assert _streamed(calls) == []
    refusal = _refusal(result)
    assert f"a margin of {floor}" in refusal and str(size + floor) in refusal, refusal
    assert "storage.minimum_free_bytes" in refusal, refusal
    # the same room on a filesystem of its own is enough: the floor is the volumes'
    result, calls = _staging(runtime, tmp_path, "", free=size + 15 * GIB, total=total, size=size, shared=False, floor=floor)
    assert "restore staging space" not in result.stderr and len(_streamed(calls)) == 1
    result, calls = _staging(runtime, tmp_path, "", free=size + floor, total=total, size=size, shared=True, floor=floor)
    assert "restore staging space" not in result.stderr and len(_streamed(calls)) == 1


@pytest.mark.parametrize("size, total, shared, floor, named", [
    (1000, GIB, False, None, "256 MiB, the least margin"),
    (3 * GIB, GIB, False, None, "a tenth of the archive"),
    (1000, 100 * GIB, False, None, "15 % of the filesystem's"),
    (1000, 100 * GIB, True, 20 * GIB, "storage.minimum_free_bytes"),
    (1000, 100 * GIB, True, 12 * GIB, "15 % of the filesystem's"),    # a floor below the 15 % does not decide
], ids=["least", "archive", "filesystem", "site-floor", "floor-below-the-share"])
def test_the_refusal_names_the_floor_that_decided_the_margin(runtime, tmp_path, size, total, shared, floor, named):
    result, calls = _staging(runtime, tmp_path, "", free=1000, total=total, size=size, shared=shared, floor=floor)
    assert result.returncode != 0 and _streamed(calls) == []
    refusal = _refusal(result)
    assert named in refusal, refusal
    for other in {"256 MiB, the least margin", "a tenth of the archive", "15 % of the filesystem's", "storage.minimum_free_bytes"} - {named}:
        assert other not in refusal, (other, refusal)


def test_the_measurement_reads_the_filesystem_size_and_the_volumes_filesystem_ids(runtime, tmp_path):
    """The filesystem measured is the one /transfer is on: the free bytes, the
    size and the filesystem id the three volumes' ids are compared with all
    come from one os.statvfs("/transfer"). The words alone were held before:
    a program that measured "/" instead, or compared the volumes' ids with
    another filesystem's, printed three numbers and passed."""
    result, calls = _staging(runtime, tmp_path, "", free=GIB, total=2 * GIB)
    call = next(c for c in calls if c[:1] == ["exec"] and "statvfs" in " ".join(c))
    command = " ".join(call)
    assert "f_blocks" in command and "f_fsid" in command, command
    for mount in ("/volumes/gsj", "/volumes/forgejo", "/volumes/chroma"):
        assert mount in command, command
    program = ast.parse(call[call.index("-c") + 1])

    def statvfs_of(node):
        return (isinstance(node, ast.Call) and ast.unparse(node.func) == "os.statvfs"
                and len(node.args) == 1 and not node.keywords and node.args[0])
    measured = [node.targets[0].id for node in ast.walk(program)
                if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                and isinstance(statvfs_of(node.value), ast.Constant) and statvfs_of(node.value).value == "/transfer"]
    assert len(measured) == 1, ast.unparse(program)
    t = measured[0]
    printed = [node for node in ast.walk(program) if isinstance(node, ast.Call) and ast.unparse(node.func) == "print"]
    assert len(printed) == 1 and len(printed[0].args) == 3, ast.unparse(program)
    free, total, shared = (ast.unparse(arg) for arg in printed[0].args)
    assert free == f"{t}.f_bavail * {t}.f_frsize" and total == f"{t}.f_blocks * {t}.f_frsize", (free, total)
    # the one comparison: a volume's filesystem id with the id of that same measurement
    compared = [node for node in ast.walk(printed[0].args[2]) if isinstance(node, ast.Compare)]
    assert len(compared) == 1 and [type(op) for op in compared[0].ops] == [ast.Eq], shared
    left, right = compared[0].left, compared[0].comparators[0]
    volume = right if ast.unparse(left) == f"{t}.f_fsid" else left
    assert f"{t}.f_fsid" in (ast.unparse(left), ast.unparse(right)), shared
    assert isinstance(volume, ast.Attribute) and volume.attr == "f_fsid", shared
    assert isinstance(statvfs_of(volume.value), ast.Name), shared
    loop = next(node for node in ast.walk(printed[0].args[2]) if isinstance(node, ast.comprehension))
    assert ast.unparse(loop.target) == statvfs_of(volume.value).id, shared
    assert ast.literal_eval(loop.iter) == ("/volumes/gsj", "/volumes/forgejo", "/volumes/chroma"), shared



PRIOR = "b" * 24


def _prior_restore(work, checkpoint, canonical):
    """The site directory of a deployment an earlier restore made: its
    checkpoint, and the canonical record as abandon, sweep or a later
    operation left it (None: no canonical record at all)."""
    (work / "restoration.json").write_text(json.dumps({
        "format": "gsj.restore/1", "archive": "/earlier/snapshot.tar.gz.enc", "archive_sha256": "e" * 64,
        "operation": PRIOR, "release_identity": "synthetic-release", "target_namespace_uid": "replaced-namespace-uid",
        "status": checkpoint}))
    if canonical is None:
        return
    operation, status = canonical
    (work / "operation.json").write_text(json.dumps({"operation": operation, "kind": "restore",
                                                     "target": "synthetic-release", "status": status}))
    if status == "abandoned":
        (work / f"abandoned-{operation}.json").write_text(json.dumps({"format": "gsj.operation-abandoned/1", "operation": operation}))
    if status == "swept":
        (work / f"swept-20260101T000000Z-{operation}.json").write_text(json.dumps({"format": "gsj.target-swept/1"}))


@pytest.mark.parametrize("canonical", [(PRIOR, "complete"), (PRIOR, "abandoned"), (PRIOR, "swept"), ("c" * 24, "backup-complete")])
def test_a_fresh_restore_retires_the_completed_checkpoint_of_an_ended_restore(runtime, tmp_path, canonical):
    # One cluster: the namespace was deleted and is restored again from the
    # same site directory, where the restore that made the deployment left its
    # completed checkpoint. Retired beside that operation's evidence, it no
    # longer refuses the fresh restore, which records its own.
    invoke, _ = _restore_fixture(runtime, tmp_path)
    _, state, work = runtime
    _prior_restore(work, "complete", canonical)
    original = (work / "restoration.json").read_bytes()
    result = invoke()
    assert result.returncode == 0, result.stderr
    retired = work / f"restore-{PRIOR}" / "retired-restoration.json"
    assert retired.read_bytes() == original
    assert f"Retired the completed restore checkpoint of ended operation {PRIOR}" in result.stderr
    current = json.loads((work / "restoration.json").read_text())
    assert current["operation"] not in (PRIOR, "c" * 24) and current["status"] == "complete"
    assert json.loads((work / "operation.json").read_text())["operation"] == current["operation"]


@pytest.mark.parametrize("checkpoint,canonical", [
    ("files-restored", (PRIOR, "verifying")),   # an unfinished restore whose operation has not ended
    ("restoring-files", None),
    ("complete", (PRIOR, "verifying")),         # its operation has not ended
    ("complete", None),                         # nothing proves it ended
])
def test_any_other_restore_checkpoint_still_refuses_a_fresh_restore(runtime, tmp_path, checkpoint, canonical):
    invoke, _ = _restore_fixture(runtime, tmp_path)
    _, state, work = runtime
    _prior_restore(work, checkpoint, canonical)
    original = (work / "restoration.json").read_bytes()
    result = invoke()
    assert result.returncode != 0
    assert "restore checkpoint already exists; use restore-repair --operation ID" in result.stderr, result.stderr
    assert (work / "restoration.json").read_bytes() == original
    assert not (work / f"restore-{PRIOR}").exists()
    assert not any(call[0] in ("create", "replace", "apply", "delete", "scale", "exec", "patch", "label")
                   for call in json.loads(state.read_text())["calls"])


@pytest.mark.parametrize("checkpoint,ended", [("files-restored", "abandoned"), ("restoring-files", "swept")])
def test_the_unfinished_checkpoint_of_an_ended_restore_names_a_fresh_restore_from_a_new_site_directory(runtime, tmp_path, checkpoint, ended):
    """The unfinished checkpoint of a restore the operator has since abandoned
    or swept still refuses a fresh restore from its site directory -- it is
    that operation's own evidence -- but the refusal named restore-repair and
    resume, and both refuse an ended operation. It names the route that is
    left: this site directory kept as it is, and a restore from a new one.
    abandon refuses an ended operation too, so that route starts at the
    uninstall."""
    invoke, _ = _restore_fixture(runtime, tmp_path)
    _, state, work = runtime
    _prior_restore(work, checkpoint, (PRIOR, ended))
    original = (work / "restoration.json").read_bytes()
    result = invoke()
    assert result.returncode != 0
    route = ("into an empty namespace synthetic-namespace from a new site directory: on another cluster, or on this one "
             "once the deployment is removed (helm -n synthetic-namespace uninstall synthetic-release, sweep, "
             "then delete namespace synthetic-namespace)")
    refusal = next(line for line in result.stderr.splitlines() if line.startswith("GSJ: "))
    assert "abandon --operation" not in refusal, refusal
    assert refusal == (f"GSJ: restore checkpoint already exists for operation {PRIOR}, which was {ended} before its restore "
                       f"completed, so restore-repair and resume refuse it; keep this site directory as it is, and restore {route}"), refusal
    assert "use restore-repair" not in result.stderr
    assert (work / "restoration.json").read_bytes() == original
    assert not (work / f"restore-{PRIOR}").exists()
    assert not any(call[0] in ("create", "replace", "apply", "delete", "scale", "exec", "patch", "label")
                   for call in json.loads(state.read_text())["calls"])


def test_the_fresh_restore_refusal_names_both_routes_for_one_cluster(runtime):
    # Most sites have one cluster: the empty namespace is on another cluster,
    # or this one recreated once the deployment is removed; a new site
    # directory either way, keeping the retained operation's as it is.
    run, _, work = runtime
    operation = "a" * 24
    result = run(f'''OPERATION={operation}; LEASE_ACQUIRED=true; GSJ_WORK="$TEST_WORK/throwaway"; mkdir -p "$GSJ_WORK"
install_exit_traps
restore_fresh_fail 'the restored evidence changed'
''')
    assert result.returncode != 0
    route = ("into an empty namespace synthetic-namespace from a new site directory: on another cluster, or on this one "
             f"once the deployment is removed (abandon --operation {operation}, helm -n synthetic-namespace uninstall synthetic-release, sweep, "
             "then delete namespace synthetic-namespace)")
    fresh = "its verified archive with the exact source installer"
    assert (f"GSJ: the restored evidence changed; keep operation {operation} retained with this site directory as it is, "
            f"and restore {fresh} {route}\n") in result.stderr, result.stderr
    assert (f"Use restore of {fresh} {route}; keep operation {operation} retained with this site directory as it is."
            ) in result.stderr, result.stderr
    assert "Kubernetes context" not in result.stderr
    assert "managed add-ons" not in result.stderr, "this site selects none"


@pytest.mark.parametrize("key, profile", [("ingress", "managed-traefik"), ("tls", "managed-acme"), ("storage", "managed-local-path")])
def test_the_one_cluster_route_removes_the_managed_add_ons_a_recreated_namespace_would_refuse(runtime, key, profile):
    """Each managed add-on's owner record hashes the namespace's uid: once the
    namespace is deleted and made again, the restore's add-on step refuses
    the add-ons the old identity owns. The route named only the application's
    release, and spelled its uninstall without the namespace it lives in. The
    steps run in the guide's order: abandon, the uninstall, sweep, the
    namespace, and last the add-ons with their CRDs."""
    run, _, work = runtime
    site = json.loads((work / "site.json").read_text())
    site[key]["profile"] = profile
    (work / "site.json").write_text(json.dumps(site))
    operation = "a" * 24
    result = run(f'''OPERATION={operation}; LEASE_ACQUIRED=true; GSJ_WORK="$TEST_WORK/throwaway"; mkdir -p "$GSJ_WORK"
install_exit_traps
restore_fresh_fail 'the restored evidence changed'
''')
    assert result.returncode != 0
    route = (f"(abandon --operation {operation}, helm -n synthetic-namespace uninstall synthetic-release, sweep, "
             "delete namespace synthetic-namespace, then remove its managed add-ons and their CRDs (see the guide))")
    refusal = next(line for line in result.stderr.splitlines() if line.startswith("GSJ: "))
    assert route in refusal, refusal
    assert route in result.stderr.rsplit("Use restore of", 1)[1], "the closing line names the same route"
