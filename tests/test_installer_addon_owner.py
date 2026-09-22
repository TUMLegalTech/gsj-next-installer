"""Pinned chart rendering with fake Kubernetes; no infrastructure mutations."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
ADDONS = ROOT / "ops/.build/installer-addons"


def test_generated_managed_traefik_values_render_with_exact_pinned_schema(tmp_path):
    import hashlib
    import yaml

    chart = ADDONS / "traefik-41.5.0.tgz"
    if not chart.exists():
        pytest.skip("pinned addon archive absent; release regression preparation supplies it")
    expected = "30f8db73182019b2764179d7fc0a7efc9505670204f847ffc3a779bacaae3a1a"
    assert hashlib.sha256(chart.read_bytes()).hexdigest() == expected
    source = (ROOT / "ops/installer/runtime.sh").read_text().split("# ENTRY POINT", 1)[0]
    functions = tmp_path / "functions.sh"
    functions.write_text(source.replace("@CLIENT_TABLE@", "gsj_client_info() { return 1; }"))
    payload = tmp_path / "payload"; payload.mkdir()
    shutil.copyfile(chart, payload / chart.name)
    image = "docker.io/traefik@sha256:f86a2cab1b5c649070c49f883c743dd32d8485a56e3368c5f93b9e91f1e91259"
    (payload / "release.json").write_text(json.dumps({"addons": {"traefik": {"path": chart.name, "sha256": expected, "images": {"traefik": image}}}}))
    site = tmp_path / "site.json"
    site.write_text(json.dumps({"storage": {"profile": "reuse"}, "ingress": {"profile": "managed-traefik", "namespace": "managed-ingress", "class": "managed-traefik", "service_type": "NodePort", "http_node_port": 30080, "https_node_port": 30443}}))
    env = {**os.environ, "GSJ_WORK": str(tmp_path), "GSJ_PAYLOAD": str(payload), "SITE": str(site), "COMMAND": "install", "KUBECONFIG": "/nonexistent/addon-test-kubeconfig"}
    script = f'''source {shlex.quote(str(functions))}
assert_owner() {{ :; }}
managed_helm_addon() {{ command helm template "$3" "$4" --namespace "$2" --include-crds --values "$5" > "$GSJ_WORK/rendered.yaml"; exit $?; }}
managed_dependencies
'''
    result = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    generated = json.loads((tmp_path / "traefik-values.json").read_text())
    assert generated["log"] == {"level": "INFO"} and "logs" not in generated
    objects = [obj for obj in yaml.safe_load_all((tmp_path / "rendered.yaml").read_text()) if obj]
    pod = next(obj for obj in objects if obj["kind"] == "Deployment")["spec"]["template"]["spec"]
    assert pod["containers"][0]["image"] == image
    assert "--log.level=INFO" in pod["containers"][0]["args"]
    for entrypoint in ("web", "websecure"):
        assert f"--entryPoints.{entrypoint}.transport.respondingTimeouts.readTimeout=3600s" in pod["containers"][0]["args"]
        assert f"--entryPoints.{entrypoint}.transport.respondingTimeouts.writeTimeout=0s" in pod["containers"][0]["args"]
    service = next(obj for obj in objects if obj["kind"] == "Service")
    assert service["spec"]["type"] == "NodePort"
    assert {p["nodePort"] for p in service["spec"]["ports"]} == {30080, 30443}
    generated["logs"] = {"general": {"level": "INFO"}}
    invalid = tmp_path / "invalid.json"; invalid.write_text(json.dumps(generated))
    rejected = subprocess.run(["helm", "template", "managed-traefik", str(chart), "--values", str(invalid)], env=env, capture_output=True, text=True)
    assert rejected.returncode != 0 and "'logs' not allowed" in rejected.stderr


@pytest.fixture
def addon_runtime(tmp_path):
    source = (ROOT / "ops/installer/runtime.sh").read_text().split("# ENTRY POINT", 1)[0]
    source = source.replace("@CLIENT_TABLE@", "gsj_client_info() { return 1; }")
    functions = tmp_path / "functions.sh"
    functions.write_text(source)
    work, payload, state_dir = tmp_path / "work", tmp_path / "payload", tmp_path / "state"
    work.mkdir(); payload.mkdir(); state_dir.mkdir()
    site = tmp_path / "site.json"
    site.write_text(json.dumps({"operator":{"secret":"operator"},"tls":{"profile":"existing","secret":"application-tls"},
                               "registry":{"pull_secret":""},"llm":{"credential":{"file":"","secret":""}},
                               "ocr":{"credential":{"file":"","secret":""}},"trust":{"proxy_file":""}}))
    manifest = {"addons": {name: {"path": "addons/" + name, "sha256": "a" * 64,
                                  "images": {"controller": "registry.invalid/controller@sha256:" + "b" * 64}}
                           for name in ("traefik", "certManager")}}
    (payload / "release.json").write_text(json.dumps(manifest))
    # Use a small chart fixture so ownership tests also run in clean checkouts
    # without engineering addon downloads. Separate tests render pinned charts.
    chart = tmp_path / "chart"
    (chart / "templates").mkdir(parents=True)
    (chart / "crds").mkdir()
    (chart / "Chart.yaml").write_text("apiVersion: v2\nname: synthetic-addon\nversion: 1.0.0\n")
    (chart / "crds/objects.yaml").write_text('''apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: synthetic.gsj.invalid
spec:
  group: gsj.invalid
  names: {kind: Synthetic, plural: synthetic}
  scope: Namespaced
  versions: [{name: v1, served: true, storage: true, schema: {openAPIV3Schema: {type: object}}}]
''')
    (chart / "templates/resources.yaml").write_text('''{{- $labels := .Values.commonLabels | default .Values.global.commonLabels }}
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Release.Name }}
  namespace: {{ .Release.Namespace }}
  labels: {{ $labels | toJson }}
spec:
  replicas: 1
  template:
    spec:
      containers: [{name: controller, image: "registry.invalid/controller@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]
---
apiVersion: networking.k8s.io/v1
kind: IngressClass
metadata:
  name: {{ .Release.Name }}
  labels: {{ $labels | toJson }}
spec: {controller: gsj.invalid/synthetic}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ .Release.Name }}-leader
  namespace: kube-system
  labels: {{ $labels | toJson }}
rules: []
{{- if .Values.startupapicheck }}
{{- $root := . }}
{{- range $kind := list "ServiceAccount" "Role" "RoleBinding" "Job" }}
---
apiVersion: {{ if eq $kind "Job" }}batch/v1{{ else if eq $kind "ServiceAccount" }}v1{{ else }}rbac.authorization.k8s.io/v1{{ end }}
kind: {{ $kind }}
metadata:
  name: {{ $root.Release.Name }}-hook-{{ $kind | lower }}
  namespace: {{ $root.Release.Namespace }}
  labels: {{ $labels | toJson }}
  annotations: {{ $root.Values.startupapicheck.jobAnnotations | toJson }}
{{- if eq $kind "Job" }}
spec:
  template:
    spec:
      restartPolicy: Never
      containers: [{name: check, image: registry.invalid/check}]
{{- end }}
{{- end }}
{{- end }}
''')
    (chart / "values.yaml").write_text("global: {commonLabels: {}}\ncommonLabels: {}\n")
    # Helper integrity is checked upstream by addon_path. This unit passes
    # the exact packaged fixture bytes, like production's immutable tgz.
    subprocess.run(["helm", "package", str(chart), "--destination", str(tmp_path)], check=True, capture_output=True)
    archive = tmp_path / "synthetic-addon-1.0.0.tgz"
    values = tmp_path / "values.json"
    values.write_text('{"service":{"type":"NodePort"},"crds":{"enabled":true}}')
    cluster = tmp_path / "cluster.json"
    cluster.write_text(json.dumps({"objects": {"Namespace//legal": {
        "apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "legal", "uid": "site-uid"}}}, "calls": []}))
    fake = tmp_path / "fake.py"
    fake.write_text('''import base64, gzip, json, os, pathlib, subprocess, sys, time
import yaml
p=pathlib.Path(os.environ['TEST_CLUSTER']); s=json.loads(p.read_text()); args=sys.argv[1:]; ns='default'
mode='kubectl'
if args and args[0]=='--helm': mode='helm'; args=args[1:]
a=[]; i=0
while i<len(args):
 if args[i] in ('--context','--kube-context','--namespace','-n'):
  if args[i] in ('--namespace','-n'): ns=args[i+1]
  i+=2
 else: a.append(args[i]); i+=1
s['calls'].append([mode,ns]+a)
cluster_kinds={'Namespace','IngressClass','StorageClass','CustomResourceDefinition','ClusterRole','ClusterRoleBinding','MutatingWebhookConfiguration','ValidatingWebhookConfiguration'}
aliases={'configmap':'ConfigMap','configmaps':'ConfigMap','secret':'Secret','secrets':'Secret','namespace':'Namespace'}
def key(o):
 return o['kind']+'/'+('' if o['kind'] in cluster_kinds else o['metadata'].get('namespace',ns))+'/'+o['metadata']['name']
def save(): p.write_text(json.dumps(s))
if mode=='helm':
 if a[0] not in ('install','upgrade','rollback'): raise SystemExit('unexpected helm mutation')
 release=a[1]
 if a[0]=='rollback':
  if s.get('lose_owner_during_rollback'):
   s['owner_lost']=True; save(); time.sleep(5)
  histories=[o for o in s['objects'].values() if o['kind']=='Secret' and o['metadata'].get('labels',{}).get('name')==release]
  previous=next(o for o in histories if o['metadata']['labels']['version']==a[2])
  owner=previous['metadata']['labels']['gsj.io/addon-owner']
  version=max(int(o['metadata']['labels']['version']) for o in histories)+1
  stored=json.loads(gzip.decompress(base64.b64decode(base64.b64decode(previous['data']['release']))))
 else:
  owner=a[a.index('--labels')+1].split('=',1)[1]; version=1
  command=[os.environ['REAL_HELM'],'install',release,a[2],'--namespace',ns,'--values',a[a.index('--values')+1],'--skip-crds','--dry-run=client','--output','json']
  result=subprocess.run(command,capture_output=True,check=True,env=dict(os.environ,KUBECONFIG='/dev/null',HELM_DRIVER='secret'))
  stored=json.loads(result.stdout)
 if s.get('race_helm'):
  foreign={'kind':'Secret','metadata':{'name':'foreign-release','namespace':ns,'labels':{'owner':'helm','name':release}},'data':{'release':'foreign-bytes'}}
  s['objects'][key(foreign)]=foreign
 if a[0]=='install' and any(o['kind']=='Secret' and o['metadata'].get('namespace')==ns and o['metadata'].get('labels',{}).get('name')==release for o in s['objects'].values()): save(); raise SystemExit(74)
 if s.get('stop_before_helm'): save(); raise SystemExit(73)
 for obj in json.loads((pathlib.Path(os.environ['GSJ_WORK'])/'addon-render.json').read_text())['items']:
  if obj['kind']=='CustomResourceDefinition': continue
  obj['metadata'].setdefault('annotations',{}).update({'meta.helm.sh/release-name':release,'meta.helm.sh/release-namespace':ns})
  obj['metadata']['uid']=s['objects'].get(key(obj),{}).get('metadata',{}).get('uid','uid-'+obj['metadata']['name'])
  s['objects'][key(obj)]=obj
 stored['version']=version; stored['info']['status']='deployed'
 for hook in stored.get('hooks',[]): hook['last_run']={'phase':'Succeeded'}
 encoded=base64.b64encode(base64.b64encode(gzip.compress(json.dumps(stored).encode()))).decode()
 obj={'kind':'Secret','type':'helm.sh/release.v1','metadata':{'name':'sh.helm.release.v1.'+release+'.v'+str(version),'namespace':ns,'uid':'helm-uid-'+str(version),'resourceVersion':'1','labels':{'owner':'helm','name':release,'version':str(version),'status':'deployed','gsj.io/addon-owner':owner}},'data':{'release':encoded}}
 s['objects'][key(obj)]=obj
 if a[0]=='rollback':
  if s.get('mutate_credential'): s['objects']['Secret/addon-ns/webhook-key']['data']['tls.key']='changed'
  if s.get('mutate_crd'): s['objects']['CustomResourceDefinition//synthetic.gsj.invalid']['metadata']['uid']='replacement-crd'
  if s.get('drop_history'): del s['objects'][key(previous)]
  if s.get('failed_hooks'):
   for hook in stored.get('hooks',[]): hook['last_run']={'phase':'Failed'}
   obj['data']['release']=base64.b64encode(base64.b64encode(gzip.compress(json.dumps(stored).encode()))).decode()
  if s.get('mutate_repaired_config'):
   stored['config']['unexpected']='wrong deployed values'
   obj['data']['release']=base64.b64encode(base64.b64encode(gzip.compress(json.dumps(stored).encode()))).decode()
elif a[:1]==['create'] and '--dry-run=client' in a:
 docs=[d for d in yaml.safe_load_all(pathlib.Path(a[a.index('-f')+1]).read_text()) if d]
 if s.get('kubectl_json_stream'):
  for doc in docs: print(json.dumps(doc))
 else: print(json.dumps({'items':docs}))
elif a[:1]==['get']:
 kinds=[aliases.get(k,k) for k in a[1].split(',')]
 if len(a)>2 and not a[2].startswith('-'):
  obj={'kind':kinds[0],'metadata':{'name':a[2]}}
  found=s['objects'].get(key(obj))
  if found: print(json.dumps(found))
  elif '--ignore-not-found' not in a: save(); raise SystemExit(1)
 else:
  labels=dict(v.split('=',1) for v in a[a.index('-l')+1].split(',')) if '-l' in a else {}
  print(json.dumps({'items':[o for o in s['objects'].values() if o['kind'] in kinds and o['metadata'].get('namespace',ns)==ns and all(o['metadata'].get('labels',{}).get(k)==v for k,v in labels.items())]}))
elif a[:1]==['create']:
 obj=json.loads(pathlib.Path(a[a.index('-f')+1]).read_text())
 if key(obj) in s['objects']: save(); raise SystemExit(1)
 obj['metadata']['uid']='uid-'+obj['metadata']['name']
 s['objects'][key(obj)]=obj
elif a[:1] in (['wait'],['rollout']): pass
else: raise SystemExit('unexpected kubectl '+repr(a))
save()
''')
    env = dict(os.environ, GSJ_WORK=str(work), GSJ_PAYLOAD=str(payload), CONTEXT="synthetic",
               NAMESPACE="legal", RELEASE="gsj", TEST_CLUSTER=str(cluster), STATE_DIR=str(state_dir),
               OPERATION="operation123", SITE=str(site), REAL_HELM=shutil.which("helm"))
    def run(addon="traefik", suffix="", revision=""):
        script = f'''source {shlex.quote(str(functions))}
kubectl() {{ {shlex.quote(str(ROOT / '.venv/bin/python'))} {shlex.quote(str(fake))} "$@"; }}
helm() {{ if [[ $1 == template || " $* " == *" --dry-run=client "* ]]; then {shlex.quote(shutil.which('helm'))} "$@"; else {shlex.quote(str(ROOT / '.venv/bin/python'))} {shlex.quote(str(fake))} --helm "$@"; fi; }}
assert_owner() {{ if jq -e '.owner_lost // false' "$TEST_CLUSTER" >/dev/null; then return 1; fi; }}
managed_helm_addon {shlex.quote(addon)} addon-ns dedicated {shlex.quote(str(archive))} {shlex.quote(str(values))} {shlex.quote(revision)}
{suffix}
'''
        return subprocess.run(["bash", "-c", script], env=env, text=True, capture_output=True)
    def run_storage(payload_file):
        script = f'''source {shlex.quote(str(functions))}
kubectl() {{ {shlex.quote(str(ROOT / '.venv/bin/python'))} {shlex.quote(str(fake))} "$@"; }}
managed_storage {shlex.quote(str(payload_file))}
'''
        return subprocess.run(["bash", "-c", script], env=env, text=True, capture_output=True)
    return {"run": run, "run_storage": run_storage, "site": site, "cluster": cluster, "values": values,
            "work": work, "manifest": payload / "release.json", "state": state_dir}


def _change(m, callback):
    s = json.loads(m["cluster"].read_text()); callback(s); m["cluster"].write_text(json.dumps(s))


def _writes(m):
    return [c for c in json.loads(m["cluster"].read_text())["calls"] if c[0] == "helm" or
            (c[2] == "create" and "--dry-run=client" not in c)]


@pytest.mark.parametrize("addon", ["traefik", "certManager"])
def test_actual_kubectl_object_stream_is_one_complete_immutable_inventory(addon_runtime, addon):
    m = addon_runtime
    _change(m, lambda s: s.update(kubectl_json_stream=True))
    result = m["run"](addon)
    assert result.returncode == 0, result.stderr
    rendered = json.loads((m["work"] / "addon-render.json").read_text())["items"]
    objects = json.loads(m["cluster"].read_text())["objects"]
    profile = json.loads(objects["ConfigMap/addon-ns/gsj-addon-owner"]["data"]["identity.json"])
    actual = {(r["kind"], r["name"], r["namespace"]) for r in profile["resources"]}
    expected = {(r["kind"], r["metadata"]["name"], r["metadata"].get("namespace", "")) for r in rendered}
    assert actual == expected
    assert len(actual) >= 4
    assert {"CustomResourceDefinition", "Deployment", "IngressClass", "Role"} <= {r[0] for r in actual}
    if addon == "certManager":
        assert {"ServiceAccount", "RoleBinding", "Job"} <= {r[0] for r in actual}


@pytest.mark.parametrize("stream", [False, True])
def test_managed_storage_accepts_list_and_actual_object_stream_without_losing_objects(addon_runtime, stream):
    m = addon_runtime
    _change(m, lambda s: s.update(kubectl_json_stream=stream))
    site = json.loads(m["site"].read_text())
    site["storage"] = {"class": "synthetic-local", "node": "synthetic-node", "backend_path": "/synthetic/storage"}
    m["site"].write_text(json.dumps(site))
    manifest = json.loads(m["manifest"].read_text())
    manifest["addons"]["localPath"] = {"sha256": "f" * 64}
    m["manifest"].write_text(json.dumps(manifest))
    docs = [
        {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "gsj-storage"}},
        {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "local-path-config", "namespace": "gsj-storage"},
         "data": {"config.json": "{}"}},
        {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "local-path-provisioner", "namespace": "gsj-storage"},
         "spec": {"replicas": 1}},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole", "metadata": {"name": "synthetic-local-role"}, "rules": []},
    ]
    payload = m["work"] / "storage.yaml"
    payload.write_text("\n---\n".join(json.dumps(doc) for doc in docs))
    result = m["run_storage"](payload)
    assert result.returncode == 0, result.stderr
    rendered = json.loads((m["work"] / "storage-payload.json").read_text())["items"]
    assert len(rendered) == len(docs)
    assert {(r["kind"], r["metadata"]["name"]) for r in rendered} == {(r["kind"], r["metadata"]["name"]) for r in docs}
    objects = json.loads(m["cluster"].read_text())["objects"]
    config = objects["ConfigMap/gsj-storage/local-path-config"]
    assert json.loads(config["data"]["config.json"]) == {"nodePathMap": [{"node": "synthetic-node", "paths": ["/synthetic/storage"]}]}
    assert objects["StorageClass//synthetic-local"]["reclaimPolicy"] == "Retain"
    assert objects["ConfigMap/gsj-storage/gsj-local-path-owner"]["immutable"] is True


@pytest.mark.parametrize("kind,namespace,name", [
    ("Deployment", "addon-ns", "dedicated"), ("IngressClass", "", "dedicated"),
    ("CustomResourceDefinition", "", "synthetic.gsj.invalid"),
    ("Role", "kube-system", "dedicated-leader"),
    ("Namespace", "", "addon-ns"),
    ("Secret", "addon-ns", "sh.helm.release.v1.dedicated.v1"),
])
def test_foreign_named_resource_refused_before_any_write(addon_runtime, kind, namespace, name):
    m = addon_runtime
    obj = {"kind": kind, "metadata": {"name": name, "namespace": namespace}}
    if kind == "Secret": obj["metadata"]["labels"] = {"owner": "helm", "name": "dedicated"}
    _change(m, lambda s: s["objects"].update({kind + "/" + namespace + "/" + name: obj}))
    result = m["run"]()
    assert result.returncode != 0
    assert _writes(m) == []


@pytest.mark.parametrize("addon", ["traefik", "certManager"])
def test_owned_identical_retry_converges_without_replacing_owner(addon_runtime, addon):
    m = addon_runtime
    first = m["run"](addon)
    assert first.returncode == 0, first.stderr
    assert [c for c in _writes(m) if c[0] == "helm"][0][2] == "install"
    objects = json.loads(m["cluster"].read_text())["objects"]
    record = objects["ConfigMap/addon-ns/gsj-addon-owner"]
    assert record["immutable"] is True
    profile = json.loads(record["data"]["identity.json"])
    assert profile["owner"]["namespace_uid"] == "site-uid"
    assert profile["owner"]["release"] == "gsj"
    assert any(r["namespace"] == "kube-system" for r in profile["resources"])
    _change(m, lambda s: s.update(calls=[]))
    second = m["run"](addon)
    assert second.returncode == 0, second.stderr
    assert json.loads(m["cluster"].read_text())["objects"]["ConfigMap/addon-ns/gsj-addon-owner"] == record
    assert all(c[0] == "helm" for c in _writes(m))
    assert _writes(m)[0][2] == "upgrade"
    if addon == "certManager":
        values = json.loads((m["work"] / "addon-values.json").read_text())
        check = values["startupapicheck"]
        for annotations in (check["jobAnnotations"], check["rbac"]["annotations"], check["serviceAccount"]["annotations"]):
            assert annotations == {"meta.helm.sh/release-name": "dedicated", "meta.helm.sh/release-namespace": "addon-ns",
                                   "helm.sh/hook": "post-install,post-upgrade,post-rollback"}


@pytest.mark.parametrize("mutation", ["site", "values", "images", "resource", "history", "pending", "crd_spec", "admission"])
def test_owned_profile_or_identity_drift_refused_before_write(addon_runtime, mutation):
    m = addon_runtime
    result = m["run"]()
    assert result.returncode == 0, result.stderr
    if mutation == "site": _change(m, lambda s: s["objects"]["Namespace//legal"]["metadata"].update(uid="replacement-site"))
    elif mutation == "values": m["values"].write_text('{"service":{"type":"LoadBalancer"}}')
    elif mutation == "images":
        release = json.loads(m["manifest"].read_text()); release["addons"]["traefik"]["images"]["controller"] = "changed"
        m["manifest"].write_text(json.dumps(release))
    elif mutation == "resource": _change(m, lambda s: s["objects"]["Deployment/addon-ns/dedicated"]["metadata"]["labels"].clear())
    elif mutation == "history": _change(m, lambda s: s["objects"]["Secret/addon-ns/sh.helm.release.v1.dedicated.v1"]["metadata"]["labels"].pop("gsj.io/addon-owner"))
    elif mutation == "pending": _change(m, lambda s: s["objects"]["Secret/addon-ns/sh.helm.release.v1.dedicated.v1"]["metadata"]["labels"].update(status="pending-install"))
    elif mutation == "crd_spec": _change(m, lambda s: s["objects"]["CustomResourceDefinition//synthetic.gsj.invalid"]["spec"].update(group="different.invalid"))
    elif mutation == "admission": _change(m, lambda s: s["objects"]["Namespace//addon-ns"]["metadata"]["labels"].update({"pod-security.kubernetes.io/enforce": "restricted"}))
    _change(m, lambda s: s.update(calls=[]))
    result = m["run"]()
    assert result.returncode != 0
    assert _writes(m) == []


def test_partial_owned_crd_install_can_retry_without_adoption(addon_runtime):
    m = addon_runtime
    _change(m, lambda s: s.update(stop_before_helm=True))
    result = m["run"]()
    assert result.returncode == 73, result.stderr
    _change(m, lambda s: s.update(stop_before_helm=False, calls=[]))
    result = m["run"]()
    assert result.returncode == 0, result.stderr
    assert all(c[0] == "helm" for c in _writes(m))


def test_release_collision_after_preflight_uses_create_only_helm(addon_runtime):
    m = addon_runtime
    _change(m, lambda s: s.update(race_helm=True))
    result = m["run"]()
    assert result.returncode == 74, result.stderr
    s = json.loads(m["cluster"].read_text())
    assert s["objects"]["Secret/addon-ns/foreign-release"]["data"] == {"release": "foreign-bytes"}
    assert all(c[2] == "install" for c in s["calls"] if c[0] == "helm")


def _pending(m, addon="traefik", mutate=None):
    import base64
    import gzip
    result = m["run"](addon)
    assert result.returncode == 0, result.stderr
    def change(s):
        history = s["objects"]["Secret/addon-ns/sh.helm.release.v1.dedicated.v1"]
        history["metadata"]["labels"]["status"] = "pending-install"
        release = json.loads(gzip.decompress(base64.b64decode(base64.b64decode(history["data"]["release"]))))
        release["info"]["status"] = "pending-install"
        if mutate: mutate(release)
        history["data"]["release"] = base64.b64encode(base64.b64encode(gzip.compress(json.dumps(release).encode()))).decode()
        s["objects"]["Secret/addon-ns/webhook-key"] = {"kind":"Secret","type":"Opaque","metadata":{"name":"webhook-key","namespace":"addon-ns","uid":"webhook-secret-uid"},"data":{"tls.key":"synthetic-private-bytes"}}
        s["objects"]["Secret/legal/application-tls"] = {"kind":"Secret","type":"kubernetes.io/tls","metadata":{"name":"application-tls","namespace":"legal","uid":"app-secret-uid"},"data":{"tls.key":"synthetic-app-key"}}
        s["calls"] = []
    _change(m, change)


@pytest.mark.parametrize("addon", ["traefik", "certManager"])
def test_named_pending_first_revision_repair_preserves_credentials_and_history(addon_runtime, addon):
    m = addon_runtime
    _pending(m, addon)
    before = json.loads(m["cluster"].read_text())["objects"]
    result = m["run"](addon, revision="1")
    assert result.returncode == 0, result.stderr
    after = json.loads(m["cluster"].read_text())["objects"]
    for name in ("Secret/addon-ns/webhook-key", "Secret/legal/application-tls",
                 "CustomResourceDefinition//synthetic.gsj.invalid"):
        assert after[name] == before[name]
    assert after["Secret/addon-ns/sh.helm.release.v1.dedicated.v1"]["metadata"]["uid"] == before["Secret/addon-ns/sh.helm.release.v1.dedicated.v1"]["metadata"]["uid"]
    assert after["Secret/addon-ns/sh.helm.release.v1.dedicated.v2"]["metadata"]["labels"]["status"] == "deployed"
    receipt = json.loads((m["state"] / ("addon-repair-" + addon + ".json")).read_text())
    assert receipt["selected_revision"] == 1 and receipt["deployed_revision"] == 2
    assert receipt["credentials_preserved"] is True
    assert "synthetic-private-bytes" not in result.stdout + result.stderr
    writes = _writes(m)
    assert len(writes) == 1 and writes[0][2:5] == ["rollback", "dedicated", "1"]
    assert "--history-max=0" in writes[0]
    assert not any(flag in writes[0] for flag in ("--force-replace", "--force-conflicts", "--cleanup-on-fail"))


@pytest.mark.parametrize("field", ["chart", "config", "manifest", "hooks"])
def test_pending_repair_rejects_stored_release_content_drift(addon_runtime, field):
    m = addon_runtime
    def mutate(r):
        if field == "chart": r["chart"]["metadata"]["description"] = "changed signed source"
        elif field == "config": r["config"]["service"]["type"] = "LoadBalancer"
        elif field == "manifest": r["manifest"] += "\n# foreign additional manifest\n"
        else: r["hooks"] = [{"name":"foreign","manifest":"foreign"}]
    _pending(m, mutate=mutate)
    result = m["run"](revision="1")
    assert result.returncode != 0
    assert _writes(m) == []


@pytest.mark.parametrize("effect", ["mutate_credential", "mutate_crd", "drop_history", "failed_hooks", "mutate_repaired_config"])
def test_repair_cannot_certify_changed_credentials_crds_history_or_failed_hooks(addon_runtime, effect):
    m = addon_runtime
    addon = "certManager" if effect == "failed_hooks" else "traefik"
    _pending(m, addon)
    _change(m, lambda s: s.update({effect: True}))
    result = m["run"](addon, revision="1")
    assert result.returncode != 0
    assert not (m["state"] / ("addon-repair-" + addon + ".json")).exists()


def test_repair_stops_helm_when_operation_ownership_is_lost(addon_runtime):
    m = addon_runtime
    _pending(m)
    _change(m, lambda s: s.update(lose_owner_during_rollback=True))
    result = m["run"](revision="1")
    assert result.returncode != 0
    assert "lost operation ownership" in result.stderr
    assert not (m["state"] / "addon-repair-traefik.json").exists()


@pytest.mark.parametrize("addon,filename,label_path", [
    ("traefik", "traefik-41.5.0.tgz", "commonLabels"),
    ("certManager", "cert-manager-v1.21.2.tgz", "global.commonLabels"),
])
def test_pinned_chart_labels_and_explicit_namespaces(addon, filename, label_path, tmp_path, addon_runtime):
    import yaml
    chart = ADDONS / filename
    if not chart.exists(): pytest.skip("engineering addon download is not present")
    command = ["helm", "template", "dedicated", str(chart), "--namespace", "addon-ns",
               "--include-crds", "--set", label_path + r".gsj\.io/addon-owner=synthetic"]
    if addon == "certManager":
        fixture = addon_runtime
        result = fixture["run"](addon)
        assert result.returncode == 0, result.stderr
        configured = json.loads((fixture["work"] / "addon-values.json").read_text())
        hook_values = tmp_path / "hook-values.json"
        hook_values.write_text(json.dumps({"startupapicheck": configured["startupapicheck"]}))
        command += ["--set", "crds.enabled=true", "--values", str(hook_values)]
    result = subprocess.run(command, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    objects = [d for d in yaml.safe_load_all(result.stdout) if d]
    cluster = {"ClusterRole", "ClusterRoleBinding", "CustomResourceDefinition", "IngressClass",
               "MutatingWebhookConfiguration", "ValidatingWebhookConfiguration"}
    assert objects
    assert all(d["metadata"].get("namespace") for d in objects if d["kind"] not in cluster)
    assert all(d["metadata"].get("labels", {}).get("gsj.io/addon-owner") == "synthetic"
               for d in objects if d["kind"] != "CustomResourceDefinition")
    if addon == "certManager":
        hooks = [d for d in objects if d["metadata"].get("annotations", {}).get("helm.sh/hook")]
        assert {d["kind"] for d in hooks} == {"Job", "Role", "RoleBinding", "ServiceAccount"}
        for hook in hooks:
            annotations = hook["metadata"]["annotations"]
            assert annotations["meta.helm.sh/release-name"] == "dedicated"
            assert annotations["meta.helm.sh/release-namespace"] == "addon-ns"
            assert annotations["helm.sh/hook"] == "post-install,post-upgrade,post-rollback"


@pytest.mark.parametrize("record", ["none", "legacy", "current"])
def test_managed_traefik_entrypoints_allow_long_uploads_and_unbounded_streams(tmp_path, record):
    # legacy: Traefik installed by an earlier release recorded no entrypoint
    # transport; its immutable owner profile is kept, never silently migrated.
    import hashlib

    source = (ROOT / "ops/installer/runtime.sh").read_text().split("# ENTRY POINT", 1)[0]
    functions = tmp_path / "functions.sh"
    functions.write_text(source.replace("@CLIENT_TABLE@", "gsj_client_info() { return 1; }"))
    payload = tmp_path / "payload"; payload.mkdir()
    chart = payload / "traefik.tgz"; chart.write_bytes(b"synthetic chart bytes")
    image = "docker.io/traefik@sha256:" + "f" * 64
    (payload / "release.json").write_text(json.dumps({"addons": {"traefik": {
        "path": chart.name, "sha256": hashlib.sha256(chart.read_bytes()).hexdigest(), "images": {"traefik": image}}}}))
    site = tmp_path / "site.json"
    site.write_text(json.dumps({"storage": {"profile": "reuse"}, "ingress": {"profile": "managed-traefik", "namespace": "managed-ingress", "class": "managed-traefik", "service_type": "NodePort", "http_node_port": 30080, "https_node_port": 30443}}))
    env = {**os.environ, "GSJ_WORK": str(tmp_path), "GSJ_PAYLOAD": str(payload), "SITE": str(site), "COMMAND": "install",
           "CONTEXT": "synthetic-context"}
    legacy = record == "legacy"
    transport = {"respondingTimeouts": {"readTimeout": "3600s", "writeTimeout": "0s"}}
    if record != "none":
        ports = {"web": {"nodePort": 30080}, "websecure": {"nodePort": 30443}}
        if record == "current":
            for port in ports.values():
                port["transport"] = transport
        (tmp_path / "owner.json").write_text(json.dumps({"data": {"identity.json": json.dumps({"values": {"ports": ports}})}}))
    script = f'''source {shlex.quote(str(functions))}
assert_owner() {{ :; }}
kubectl() {{ if [[ " $* " == *" get configmap gsj-addon-owner "* && -f $GSJ_WORK/owner.json ]]; then cat "$GSJ_WORK/owner.json"; fi; }}
managed_helm_addon() {{ cp "$5" "$GSJ_WORK/used-values.json"; }}
managed_dependencies
'''
    result = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    values = json.loads((tmp_path / "used-values.json").read_text())
    for entrypoint, port in (("web", 30080), ("websecure", 30443)):
        expected = {"nodePort": port} if legacy else {"nodePort": port, "transport": transport}
        assert values["ports"][entrypoint] == expected
    assert ("explicit addon migration" in result.stderr) is legacy
