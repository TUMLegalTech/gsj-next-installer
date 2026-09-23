"""Exercise the shipped Bash functions/JQ contracts with synthetic tools.

No kubeconfig, cluster, registry, endpoint or credential file is used. The
entry point is excluded so sourcing never bootstraps/downloads anything.
"""
import hashlib
import base64
import io
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import tarfile

import pytest


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "ops/installer"
pytestmark = pytest.mark.skipif(shutil.which("jq") is None, reason="jq unavailable")


def _site():
    site = json.loads((INSTALLER / "defaults.json").read_text())
    site["target"]["context"] = "synthetic-context"
    site["public_url"] = "https://legal.example"
    site["operator"]["password_file"] = "operator-password"
    site["llm"].update(base_url="https://llm.example/v1", model="synthetic-model")
    site["ocr"]["url"] = "https://ocr.example/v1/chat/completions"
    site["storage"].update({"class": "local-path", "node": "synthetic-node"})
    site["backup"].update(directory="backups", passphrase_file="backup-passphrase")
    return site


def _validate(site):
    return subprocess.run(["jq", "--slurpfile", "schema", str(INSTALLER / "site.schema.json"),
                           "-f", str(INSTALLER / "validate.jq")], input=json.dumps(site),
                          capture_output=True, text=True)


def _release():
    return {"identity": "synthetic-release", "version": "v1.2.3", "core": {"tag": "v4.9.2-deployment"},
            "images": {name: {"repository": "registry.invalid/" + name,
                               "digest": "sha256:" + "a" * 64}
                       for name in ("web", "runner", "mcp", "forgejo", "chroma", "decisionsData")},
            "corpus": {"manifest_sha256": "b" * 64}}


def test_valid_configuration_compiles_to_runtime_fields(tmp_path):
    site = _site()
    site["llm"].update(context_window=32768, output_tokens=2048)
    site["limits"].update(upload_mb=128, worktree_cache_mb=8192)
    assert _validate(site).returncode == 0
    path = tmp_path / "release.json"
    path.write_text(json.dumps(_release()))
    result = subprocess.run(["jq", "--slurpfile", "release", str(path),
                             "-f", str(INSTALLER / "compile.jq")],
                            input=json.dumps(site), capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    compiled = json.loads(result.stdout)
    assert compiled["corpus"]["enabled"] is True
    assert compiled["corpus"]["manifestSha256"] == "b" * 64
    assert compiled["web"] == {"publicUrl": "https://legal.example", "uploadMaxMB": 128,
                               "worktreeBudgetMB": 8192}
    assert compiled["llm"]["model"] == "openai@https://llm.example/v1#synthetic-model"
    assert compiled["llm"]["contextWindow"] == 32768
    assert compiled["llm"]["outputTokens"] == 2048
    assert compiled["operator"]["password"] == ""


def test_schema_defaults_match_the_distributed_configuration_authority():
    schema = json.loads((INSTALLER / "site.schema.json").read_text())
    defaults = json.loads((INSTALLER / "defaults.json").read_text())

    def visit(node, value):
        if isinstance(value, dict):
            for key, item in value.items(): visit(node["properties"][key], item)
        else: assert node["default"] == value
    visit(schema, defaults)


@pytest.mark.parametrize("role", ["web", "mcp", "runner", "forgejo", "chroma", "initializer"])
def test_optional_cpu_limits_reach_every_runtime_container(tmp_path, role):
    site = _site()
    site["resources"][role]["limits"]["cpu"] = "3"
    assert _validate(site).returncode == 0
    path = tmp_path / "release.json"; path.write_text(json.dumps(_release()))
    compiled = subprocess.run(["jq", "--slurpfile", "release", str(path), "-f", str(INSTALLER / "compile.jq")],
                              input=json.dumps(site), text=True, capture_output=True, check=True)
    values = json.loads(compiled.stdout)
    target = values["corpus"]["resources"] if role == "initializer" else values["resources"][role]
    assert target["limits"]["cpu"] == "3"


@pytest.mark.parametrize("mode,resource,value", [
    ("requests", "cpu", "1Gi"), ("limits", "cpu", "2Mi"),
    ("requests", "memory", "20m"), ("limits", "memory", "20m"),
    ("limits", "cpu", "100m"), ("limits", "memory", "1Gi"),
])
def test_resource_units_and_request_limit_relationship_are_checked(mode, resource, value):
    site = _site(); site["resources"]["web"][mode][resource] = value
    assert _validate(site).returncode != 0


@pytest.mark.parametrize("path,value", [
    (["unknown"], "must-not-echo-this-value"),
    (["public_url"], "http://legal.example"),
    (["public_url"], "https://user:secret@legal.example"),
    (["public_url"], "https://legal.example:99999"),
    (["public_url"], "https://legal.example:0"),
    (["llm", "base_url"], "https://user:secret@llm.example/v1"),
    (["ocr", "url"], "https://user:secret@ocr.example/v1/chat/completions"),
    (["target", "context"], "bad\ncontext"),
    (["target", "context"], "bad\n"),
    (["target", "context"], "bad\t"),
    (["target", "context"], "bad\x00"),
    (["operator", "login"], "gsj-admin"),
    (["operator", "login"], "system"),
    (["llm", "flags"], ["unsupported"]),
    # jq's $ also matches before a final newline; runtime validators refuse
    # queries, fragments, whitespace and userinfo in every endpoint URL.
    (["public_url"], "https://legal.example\n"),
    (["llm", "base_url"], "https://llm.example/v1?tenant=a"),
    (["llm", "base_url"], "https://llm.example/v1#models"),
    (["llm", "base_url"], "https://llm example/v1"),
    (["llm", "base_url"], "https://llm.example/v1\n"),
    (["llm", "model"], "synthetic-model\n"),
    (["llm", "allowed_origins"], ["https://llm.example\n"]),
    (["ocr", "url"], "https://ocr.example/v1/chat/completions?x=1"),
    (["ocr", "url"], "https://ocr.example/v1/chat/completions#x"),
    (["ocr", "url"], "https://ocr.example/v1/chat completions"),
    (["ocr", "url"], "https://ocr.example/v1/chat/completions\n"),
    (["limits", "turn_seconds"], 59),
])
def test_invalid_configuration_fails_without_echoing_values(path, value):
    site = _site()
    assert _validate(site).returncode == 0, "the baseline must be valid before testing one invalid field"
    parent = site
    for key in path[:-1]:
        parent = parent[key]
    parent[path[-1]] = value
    result = _validate(site)
    assert result.returncode != 0, f"invalid {'.'.join(path)} accepted"
    if isinstance(value, str):
        assert value not in result.stderr


@pytest.fixture
def runtime(tmp_path):
    return _runtime(tmp_path)


def _runtime(tmp_path):
    source = (INSTALLER / "runtime.sh").read_text()
    assert "# ENTRY POINT" in source, "fixture must never source the live entry point"
    source = source.split("# ENTRY POINT", 1)[0]
    source = source.replace("@CLIENT_TABLE@", "gsj_client_info() { return 1; }")
    functions = tmp_path / "functions.sh"
    functions.write_text(source)
    bindir = tmp_path / "bin"
    bindir.mkdir()
    state = tmp_path / "kubectl.json"
    state.write_text(json.dumps({"lease": None, "calls": []}))
    fake = bindir / "kubectl"
    fake.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys, time
p = pathlib.Path(os.environ["TEST_KUBECTL_STATE"])
s = json.loads(p.read_text())
a = sys.argv[1:]
while a and a[0] in ("--context", "--namespace", "-n"): a = a[2:]
s["calls"].append(a)
code = 0
if a[:2] == ["config", "get-contexts"]: print(a[2])
elif a[:2] == ["get", "namespace"]:
    print(json.dumps({"metadata":{"uid":s.get("namespace_uid","target-namespace-uid")}}) if "json" in a else "synthetic namespace")
elif a[:2] == ["get", "ns"]: print("target-namespace-uid")
elif a[:2] == ["get", "lease"]:
    if s["lease"] is not None: print(json.dumps(s["lease"]))
elif a[:2] == ["get", "pods"]:
    print(json.dumps({"items":[v for v in s.get("resources",{}).values() if v["kind"]=="Pod"]}))
elif a[:1] == ["get"]:
    # a state without "resources" is an empty cluster: a named get finds
    # nothing, a selector get lists nothing (the install refusal reads the
    # Helm history of every acquire)
    resources = s.get("resources", {})
    aliases = {"secrets":"Secret", "secret":"Secret", "configmaps":"ConfigMap", "cm":"ConfigMap",
               "pvc":"PersistentVolumeClaim", "pv":"PersistentVolume", "pod":"Pod", "services":"Service",
               "ingresses":"Ingress", "serviceaccounts":"ServiceAccount", "roles":"Role",
               "rolebindings":"RoleBinding", "deployments":"Deployment", "networkpolicies":"NetworkPolicy",
               "deploy":"Deployment", "replicasets":"ReplicaSet", "statefulsets":"StatefulSet",
               "daemonsets":"DaemonSet", "jobs":"Job", "job":"Job", "cronjobs":"CronJob"}
    kinds = [aliases.get(v,v) for v in a[1].split(",")]
    if len(a)>2 and not a[2].startswith("-"):
        obj = resources.get(kinds[0]+"/"+a[2])
        if s.get("fail_get") == kinds[0]+"/"+a[2]: code = 23
        elif obj is None: code = 0 if "--ignore-not-found" in a else 1
        else: print(json.dumps(obj))
    else:
        selector = dict(v.split("=",1) for v in a[a.index("-l")+1].split(",")) if "-l" in a else {}
        objects = [v for v in resources.values() if v["kind"] in kinds and
                   all(v["metadata"].get("labels",{}).get(k)==value for k,value in selector.items())]
        print(json.dumps({"items":objects}))
elif a[:1] in (["create"], ["replace"]):
    source = a[a.index("-f")+1]
    obj = json.load(sys.stdin) if source=="-" else json.loads(pathlib.Path(source).read_text())
    if obj.get("kind") != "Lease" and "resources" in s and s.get("race_resource"):
        item = s.pop("race_resource")
        s["resources"][item["kind"]+"/"+item["metadata"]["name"]] = item
    if obj.get("kind") == "List" and "resources" in s:
        for item in obj["items"]:
            key = item["kind"]+"/"+item["metadata"]["name"]
            if key in s["resources"]: code = 1; break
            s["resources"][key] = item
    elif obj.get("kind") != "Lease":
        if "resources" not in s: code = 19
        else:
            key = obj["kind"]+"/"+obj["metadata"]["name"]
            if s.get("fail_create") == key: code = 31
            elif key in s["resources"]: code = 1
            else:
                obj["metadata"]["uid"]="created-"+obj["metadata"]["name"]
                s["resources"][key]=obj
                if s.get("fail_after_create") == key: code=42
    elif a[0] == "create":
        if s["lease"] is not None or s.get("conflict_create"): code = 1
        else:
            obj["metadata"]["resourceVersion"] = "1"; s["lease"] = obj
    elif s["lease"] is None: code = 1
    elif s.get("conflict_replace") or obj["metadata"].get("resourceVersion") != s["lease"]["metadata"]["resourceVersion"]: code = 1
    else:
        obj["metadata"]["resourceVersion"] = str(int(obj["metadata"]["resourceVersion"])+1); s["lease"] = obj
elif a[:1] == ["exec"]:
    if "-i" in a: sys.stdin.buffer.read()
    if s.get("fail_restore") and "restore" in a: code = 42
    # Fault hooks: scripted exec outcomes, first match on the joined argv wins.
    # A rule is {match, code, stdout, delay} - delay models a CNI that DROPs
    # (the request hangs until the client's own timeout) versus one that
    # REJECTs (it fails at once). Both are a blocked path.
    for rule in s.get("exec_rules", []):
        if rule["match"] in " ".join(a):
            if rule.get("delay"): time.sleep(rule["delay"])
            if rule.get("stdout"): sys.stdout.write(rule["stdout"])
            code = rule.get("code", 0)
            break
elif a[:1] == ["delete"]:
    if a[1:2] == ["lease"] and "--raw" not in a:
        s["lease"] = None
    elif "--raw" in a and "resources" in s:
        uri=a[a.index("--raw")+1].split("/"); name=uri[-1]
        key={"pods":"Pod","jobs":"Job","configmaps":"ConfigMap","secrets":"Secret","leases":"Lease"}.get(uri[-2],uri[-2])+"/"+name
        request=json.loads(pathlib.Path(a[a.index("-f")+1]).read_text())
        if key not in s["resources"]: code=1
        elif request["preconditions"]["uid"] != s["resources"][key]["metadata"]["uid"]: code=9
        else: del s["resources"][key]
elif a[:1] == ["wait"]: pass
else: code = 17
p.write_text(json.dumps(s))
sys.exit(code)
''')
    fake.chmod(0o755)
    curl = bindir / "curl"
    curl.write_text('''#!/usr/bin/env python3
import json, os, pathlib, shutil, sys
a = sys.argv[1:]
if os.environ.get("TEST_ARTIFACT_MAP"):
    lookup = json.loads(pathlib.Path(os.environ["TEST_ARTIFACT_MAP"]).read_text())
    url = next(v for v in a if v.startswith("https://"))
    source = lookup[url.rsplit("/", 1)[-1]]
else: source = os.environ["TEST_ARTIFACT"]
shutil.copyfile(source, a[a.index("-o")+1])
''')
    curl.chmod(0o755)
    work = tmp_path / "work"
    work.mkdir()
    (work / "site.json").write_text(json.dumps(_site()))
    (work / "values.pending.json").write_text("{}")
    env = {**os.environ, "PATH": str(bindir) + os.pathsep + os.environ["PATH"],
           "TEST_KUBECTL_STATE": str(state), "TEST_FUNCTIONS": str(functions),
           "TEST_WORK": str(work)}

    def run(body, **extra):
        prefix = '''source "$TEST_FUNCTIONS"
CONTEXT=synthetic-context; NAMESPACE=synthetic-namespace; RELEASE=synthetic-release
STATE_DIR="$TEST_WORK"; GSJ_WORK="$TEST_WORK"; SITE_DIR="$TEST_WORK"; SITE="$TEST_WORK/site.json"; RELEASE_ID=synthetic-release; RENEWER=''; COMMAND=install
start_renewal() { :; }
'''
        return subprocess.run(["bash", "-c", prefix + body], env={**env, **extra},
                              text=True, capture_output=True, timeout=30)

    return run, state, work


def test_load_site_merges_defaults_and_keeps_context_out_of_state_path(runtime, tmp_path):
    run, _, _ = runtime
    payload = tmp_path / "load-payload"
    payload.mkdir()
    for name in ("defaults.json", "site.schema.json", "validate.jq", "compile.jq"):
        shutil.copyfile(INSTALLER / name, payload / name)
    (payload / "release.json").write_text(json.dumps(_release()))
    site = _site()
    site["target"]["context"] = "../synthetic-context"
    del site["limits"]  # Exercise the shipped merge with a partial site document.
    config = tmp_path / "site.json"
    config.write_text(json.dumps(site))
    for name in ("operator-password", "backup-passphrase"):
        path = tmp_path / name
        path.write_text("synthetic-private-value")
        path.chmod(0o600)
    result = run('GSJ_PAYLOAD="$TEST_PAYLOAD"\nCONFIG="$TEST_CONFIG"\nCONTEXT_ARG=""\nload_site\n',
                 TEST_PAYLOAD=str(payload), TEST_CONFIG=str(config))
    assert result.returncode == 0, result.stderr
    state = tmp_path / ".gsj" / hashlib.sha256(b"../synthetic-context").hexdigest() / "gsj" / "gsj"
    compiled = json.loads((runtime[2] / "values.pending.json").read_text())
    assert not (state / "values.pending.json").exists(), "unowned input parsing must not overwrite an active operation"
    assert compiled["web"]["uploadMaxMB"] == 64
    assert compiled["web"]["worktreeBudgetMB"] == 2048
    assert state.stat().st_mode & 0o077 == 0
    assert "synthetic-private-value" not in result.stdout + result.stderr


def _foreign_release(revision=1, status="deployed", storage="secret"):
    """A Helm history record for the target release that THIS installer never
    wrote — the shape measured by installing the product's own chart directly,
    the way an existing pilot deployment was installed — in Helm's Secret
    storage (the default driver) or its ConfigMap storage
    (HELM_DRIVER=configmap; no `type`, the same labels)."""
    kind = "Secret" if storage == "secret" else "ConfigMap"
    return {"apiVersion": "v1", "kind": kind, **({"type": "helm.sh/release.v1"} if kind == "Secret" else {}),
            "metadata": {"name": f"sh.helm.release.v1.synthetic-release.v{revision}",
                         "labels": {"owner": "helm", "name": "synthetic-release",
                                    "version": str(revision), "status": status}}}


@pytest.mark.parametrize("storage", ["secret", "configmap"])
def test_install_refuses_a_helm_release_without_an_installer_record(runtime, tmp_path, storage):
    """A namespace already holding a Helm release of the target name that this
    installer did not create — Helm history present, no installer record, no
    operation Lease — is REFUSED before any Lease or application write. Taking
    it over would rename every resource (fullnameOverride) and let Helm drop
    the old PVCs with their data. The refusal names what was found, whichever
    storage driver the ambient HELM_DRIVER — inherited by the very apply the
    gate guards — keeps the history in. An installer-born site (its Lease
    present) keeps the existing operation path; a fresh namespace proceeds."""
    run, state, work = runtime
    payload = tmp_path / "payload"                  # acquire's operation intent copies release.json
    payload.mkdir()
    (payload / "release.json").write_text(json.dumps(_release()))
    history = (f'GSJ_PAYLOAD="{payload}"\n'
               'h() { printf %s \'[{"revision":1,"status":"deployed","chart":"gsj-0.9.1-beta.23","app_version":"0.9.1-beta.23"}]\'; }\n')
    s = json.loads(state.read_text())
    record = _foreign_release(storage=storage)
    s["resources"] = {record["kind"] + "/sh.helm.release.v1.synthetic-release.v1": record}
    state.write_text(json.dumps(s))
    result = run(history + "read_installed\nacquire\n")
    assert result.returncode != 0, result.stderr
    assert "no installer record" in result.stderr, result.stderr
    for named in ("synthetic-release", "synthetic-namespace", "gsj-0.9.1-beta.23", "deployed"):
        assert named in result.stderr, (named, result.stderr)
    after = json.loads(state.read_text())
    assert after["lease"] is None and not any(c[:1] == ["create"] for c in after["calls"]), \
        "the refusal must precede the Lease and every write"
    # an installer-born site: its (released) operation Lease marks it ours, so
    # the gate is skipped and acquire proceeds to its operation intent (the
    # fixture models no prior operation records, so later phases stop there)
    s["lease"] = _lease("")
    state.write_text(json.dumps(s))
    result = run(history + "read_installed\nacquire\n")
    assert "no installer record" not in result.stderr and "Prepared operation" in result.stderr, result.stderr
    # a fresh namespace: no Helm history at all -> the gate is skipped too
    # (acquire's completion in this stripped fixture is the other tests' job)
    s["lease"] = None
    s["resources"] = {}
    state.write_text(json.dumps(s))
    result = run(history + 'STATE_DIR="$TEST_WORK/fresh"; mkdir -p "$STATE_DIR"\nread_installed\nacquire\n')
    assert "no installer record" not in result.stderr and "Prepared operation" in result.stderr, result.stderr


def _lease(holder=""):
    return {"apiVersion": "coordination.k8s.io/v1", "kind": "Lease",
            "metadata": {"name": "synthetic-release-operation", "resourceVersion": "1"},
            "spec": {"holderIdentity": holder}}


@pytest.mark.parametrize("existing", [False, True])
def test_operation_acquire_creates_or_cas_replaces_empty_lease(runtime, existing):
    run, state, work = runtime
    payload = work / 'payload'; payload.mkdir()
    (payload / 'release.json').write_text(json.dumps(_release()))
    if existing:
        state.write_text(json.dumps({"lease": _lease(), "calls": []}))
    result = run('GSJ_PAYLOAD="$TEST_PAYLOAD"; acquire\n', TEST_PAYLOAD=str(payload))
    assert result.returncode == 0, result.stderr
    actual = json.loads(state.read_text())
    operation = json.loads((work / "operation.json").read_text())
    assert actual["lease"]["spec"]["holderIdentity"] == operation["operation"]
    writes = [a[0] for a in actual["calls"] if a[0] in ("create", "replace")]
    assert writes == ["replace" if existing else "create"]


def test_existing_holder_and_cas_conflict_never_claim_ownership(runtime):
    run, state, work = runtime
    payload = work / 'payload'; payload.mkdir()
    (payload / 'release.json').write_text(json.dumps(_release()))
    state.write_text(json.dumps({"lease": _lease("someone-else"), "calls": []}))
    result = run('GSJ_PAYLOAD="$TEST_PAYLOAD"; acquire\n', TEST_PAYLOAD=str(payload))
    assert result.returncode != 0
    assert json.loads(state.read_text())["lease"]["spec"]["holderIdentity"] == "someone-else"
    assert not (work / "operation.json").exists()
    state.write_text(json.dumps({"lease": _lease(), "calls": [], "conflict_replace": True}))
    result = run('GSJ_PAYLOAD="$TEST_PAYLOAD"; acquire\n', TEST_PAYLOAD=str(payload))
    assert result.returncode != 0
    assert json.loads(state.read_text())["lease"]["spec"]["holderIdentity"] == ""
    assert not (work / "operation.json").exists()


@pytest.mark.parametrize("holder", ["our-operation", "someone-else"])
def test_release_only_clears_the_owned_lease(runtime, holder):
    run, state, _ = runtime
    state.write_text(json.dumps({"lease": _lease(holder), "calls": []}))
    result = run("OPERATION=our-operation\nrelease_operation\n")
    assert result.returncode == 0, result.stderr
    actual = json.loads(state.read_text())
    assert actual["lease"]["spec"]["holderIdentity"] == ("" if holder == "our-operation" else holder)
    assert sum(a[0] == "replace" for a in actual["calls"]) == (1 if holder == "our-operation" else 0)


def test_wizard_sets_literal_values_without_shell_expansion(runtime, tmp_path):
    run, _, _ = runtime
    wizard = tmp_path / "wizard.json"
    wizard.write_text(json.dumps(_site()))
    value = 'literal $v and "quotes"'
    result = run('WIZARD="$TEST_WIZARD"\nset_site .target.context "$TEST_VALUE"\n',
                 TEST_WIZARD=str(wizard), TEST_VALUE=value)
    assert result.returncode == 0, result.stderr
    assert json.loads(wizard.read_text())["target"]["context"] == value


def _backup_fixture(state, work):
    source = _site()
    source["operator"]["secret"] = "source-operator"
    source["registry"]["pull_secret"] = "source-registry"
    source["llm"]["credential"]["secret"] = "source-llm"
    source["ocr"]["credential"]["file"] = "source-ocr-private-file"
    source["tls"]["secret"] = "source-tls"
    source["trust"].update(ca_file="source-ca-file", proxy_file="source-proxy-file")
    identities = [{"name": "existing-"+role, "uid": "uid-"+role, "volume": "pv-"+role}
                  for role in ("forgejo", "gsj", "chroma")]
    (work / "installed.json").write_text(json.dumps({"site": source, "storage": identities}))
    # The target may change references. Backup must preserve source credentials.
    target = _site()
    target["tls"]["secret"] = "target-tls"
    (work / "site.pending.json").write_text(json.dumps(target))
    for name in ("operator-password", "source-ocr-private-file", "source-ca-file", "source-proxy-file"):
        path = work / name
        path.write_text("synthetic-input")
        path.chmod(0o600)
    resources = {}

    def add(kind, name, labels=None, **extra):
        obj = {"apiVersion": "v1", "kind": kind, "metadata": {"name": name, "labels": labels or {}}, **extra}
        resources[kind+"/"+name] = obj
        return obj

    for name in ("synthetic-release-admin-token", "synthetic-release-agent-token",
                 "synthetic-release-webhook", "source-operator", "source-registry", "source-llm",
                 "synthetic-release-ocr-key", "source-tls", "synthetic-release-proxy"):
        add("Secret", name, data={"synthetic": "c3ludGhldGlj"})
    add("ConfigMap", "synthetic-release-provisioned")
    add("ConfigMap", "synthetic-release-trust")
    add("ConfigMap", "release-scripts", {"app.kubernetes.io/instance": "synthetic-release"})
    add("Deployment", "release-web", {"app.kubernetes.io/instance": "synthetic-release"})
    add("ConfigMap", "release-installed", {"gsj.io/owner": "synthetic-release"})
    add("Secret", "sh.helm.release.v1.synthetic-release.v1", {"owner": "helm", "name": "synthetic-release"})
    # Name collisions across resource kinds must not widen the Secret selection.
    for name in ("release-scripts", "existing-gsj", "target-tls", "unrelated"):
        add("Secret", name)
    add("Secret", "sh.helm.release.v1.someone-else.v1", {"owner": "helm", "name": "someone-else"})
    add("Deployment", "someone-else", {"app.kubernetes.io/instance": "someone-else"})
    add("PersistentVolume", "unrelated-pv", spec={"claimRef": {"namespace": "someone-else", "uid": "other"}})
    for identity in identities:
        claim = add("PersistentVolumeClaim", identity["name"], spec={"volumeName": identity["volume"]})
        claim["metadata"]["uid"] = identity["uid"]
        add("PersistentVolume", identity["volume"],
            spec={"claimRef": {"namespace": "synthetic-namespace", "uid": identity["uid"]}})
    state.write_text(json.dumps({"lease": None, "calls": [], "resources": resources}))
    return resources


def test_backup_captures_typed_source_references_and_exact_existing_storage(runtime):
    run, state, work = runtime
    _backup_fixture(state, work)
    result = run('SITE="$TEST_WORK/site.pending.json"\nbackup_resources\n')
    assert result.returncode == 0, result.stderr
    cluster = json.loads((work / "cluster-private.json").read_text())
    keys = {item["kind"]+"/"+item["metadata"]["name"] for item in cluster["items"]}
    assert keys == {
        "Secret/"+name for name in ("synthetic-release-admin-token", "synthetic-release-agent-token",
          "synthetic-release-webhook", "source-operator", "source-registry", "source-llm",
          "synthetic-release-ocr-key", "source-tls", "synthetic-release-proxy",
          "sh.helm.release.v1.synthetic-release.v1")
    } | {"ConfigMap/"+name for name in ("synthetic-release-provisioned", "synthetic-release-trust",
                                        "release-scripts", "release-installed")} | {
        "Deployment/release-web", "PersistentVolumeClaim/existing-forgejo",
        "PersistentVolumeClaim/existing-gsj", "PersistentVolumeClaim/existing-chroma"}
    volumes = json.loads((work / "volumes-private.json").read_text())
    assert {v["metadata"]["name"] for v in volumes["items"]} == {"pv-forgejo", "pv-gsj", "pv-chroma"}
    calls = json.loads(state.read_text())["calls"]
    assert [a for a in calls if a[:2] == ["get", "secrets"]] == [
        ["get", "secrets", "-l", "owner=helm,name=synthetic-release", "-o", "json"]]
    assert all(a[2].startswith("pv-") for a in calls if a[:2] == ["get", "pv"])
    assert "c3ludGhldGlj" not in result.stdout + result.stderr
    inputs = json.loads((work / "site_inputs.json").read_text())
    assert inputs["format"] == "gsj.site-inputs/1"
    assert {v["name"] for v in inputs["entries"]} == {
        "operator.password_file", "ocr.credential.file", "trust.ca_file", "trust.proxy_file"}
    assert all(base64.b64decode(v["data"]) == b"synthetic-input" and v["mode"] == 0o600 for v in inputs["entries"])


def test_backup_captures_only_explicit_managed_ca_ownership_files(runtime):
    run, state, work = runtime
    _backup_fixture(state, work)
    installed = json.loads((work / "installed.json").read_text())
    installed["site"]["tls"]["profile"] = "managed-local-ca"
    (work / "installed.json").write_text(json.dumps(installed))
    tls = work / "tls"
    tls.mkdir()
    for name in ("ca.key", "ca.crt", "unrelated-private-file"):
        path = tls / name
        path.write_bytes(b"synthetic-"+name.encode())
        path.chmod(0o600)
    result = run("backup_resources\n")
    assert result.returncode == 0, result.stderr
    entries = json.loads((work / "site_inputs.json").read_text())["entries"]
    assert {v["name"] for v in entries if v["name"].startswith("managed_tls.")} == {"managed_tls.ca.key", "managed_tls.ca.crt"}
    assert all(b"unrelated" not in base64.b64decode(v["data"]) for v in entries)


@pytest.mark.parametrize("damage", ["claim-uid", "claim-volume", "pv-namespace", "pv-uid", "missing-secret"])
def test_backup_refuses_changed_bindings_or_missing_required_credentials(runtime, damage):
    run, state, work = runtime
    resources = _backup_fixture(state, work)
    if damage == "claim-uid":
        resources["PersistentVolumeClaim/existing-gsj"]["metadata"]["uid"] = "replaced"
    elif damage == "claim-volume":
        resources["PersistentVolumeClaim/existing-gsj"]["spec"]["volumeName"] = "rebound"
    elif damage.startswith("pv-"):
        resources["PersistentVolume/pv-gsj"]["spec"]["claimRef"][damage[3:]] = "rebound"
    else:
        del resources["Secret/synthetic-release-admin-token"]
    state.write_text(json.dumps({"lease": None, "calls": [], "resources": resources}))
    result = run("backup_resources\n")
    assert result.returncode != 0
    assert not (work / "cluster-private.json").exists()
    assert not (work / "volumes-private.json").exists()


def _restore_fixture(runtime, tmp_path, damage=None, fallback=False, password_newline=False, transport_files=False, transform=None):
    run, state, work = runtime
    payload = tmp_path / "restore-payload"
    payload.mkdir()
    for name in ("defaults.json", "site.schema.json", "validate.jq", "compile.jq"):
        shutil.copyfile(INSTALLER / name, payload / name)
    release = _release()
    release["core"]["commit"] = "c" * 40
    release["model"] = {"identity": "synthetic-embedding", "dimension": 8}
    (payload / "release.json").write_text(json.dumps(release))
    site = _site()
    site["target"].update(namespace="synthetic-namespace", release="synthetic-release")
    site["operator"]["secret"] = "synthetic-release-operator"
    site["llm"]["credential"]["file"] = "llm-key"
    site["ocr"]["credential"]["file"] = "ocr-key"
    site["registry"].update(pull_secret="synthetic-release-registry", config_file="registry-json")
    site["tls"].update(profile="managed-local-ca", secret="synthetic-release-tls",
                        certificate_file="tls-crt", private_key_file="tls-key", ca_file="ca-crt")
    site["trust"].update(ca_file="trust-crt", proxy_file="proxy-json")
    site["verification"]["ca_file"] = "verify-crt"
    inputs = {
        "operator.password_file": b"synthetic-password-without-newline",
        "llm.credential.file": b"synthetic-llm-key", "ocr.credential.file": b"synthetic-ocr-key",
        "registry.config_file": b'{"auths":{"registry.invalid":{"auth":"c3ludGhldGlj"}}}',
        "tls.certificate_file": b"synthetic-tls-certificate\n", "tls.private_key_file": b"synthetic-tls-key\n",
        "tls.ca_file": b"synthetic-ca-certificate\n", "verification.ca_file": b"synthetic-ca-certificate\n",
        "trust.ca_file": b"synthetic-ca-bundle\n",
        "trust.proxy_file": b'{"HTTP_PROXY":"","HTTPS_PROXY":"","NO_PROXY":"localhost"}',
        "managed_tls.ca.key": b"synthetic-ca-private-key\n", "managed_tls.ca.crt": b"synthetic-ca-certificate\n",
    }
    if transport_files:
        site["delivery"].update(ca_file="delivery-crt", auth_header_file="delivery-header")
        site["backup"].update(ca_file="backup-crt", auth_header_file="backup-header",
                              offbox_url="https://backup.example/synthetic")
        inputs.update({"delivery.ca_file": b"synthetic-delivery-ca\n",
                       "delivery.auth_header_file": b"Authorization: Bearer synthetic-delivery\n",
                       "backup.ca_file": b"synthetic-backup-ca\n",
                       "backup.auth_header_file": b"Authorization: Bearer synthetic-backup\n"})
    if password_newline:
        inputs["operator.password_file"] += b"\n"
    def secret(name, data, **extra):
        return {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": name},
                "data": {key: base64.b64encode(value).decode() for key, value in data.items()}, **extra}
    items = [secret("synthetic-release-"+role, {"token" if role != "webhook" else "secret": b"synthetic"})
             for role in ("admin-token", "agent-token", "webhook")]
    for suffix, field, key in (("operator", "operator.password_file", "password"),
                               ("llm-key", "llm.credential.file", "key"),
                               ("ocr-key", "ocr.credential.file", "key"),
                               ("registry", "registry.config_file", ".dockerconfigjson")):
        value = inputs[field].rstrip(b"\n") if key == "password" else inputs[field]
        items.append(secret("synthetic-release-"+suffix, {key: value}))
    items.append(secret("synthetic-release-tls", {"tls.crt": inputs["tls.certificate_file"],
                 "tls.key": inputs["tls.private_key_file"]}, type="kubernetes.io/tls"))
    proxy = json.loads(inputs["trust.proxy_file"])
    proxy["NO_PROXY"] = ",".join(sorted({"localhost", ".localhost", "127.0.0.1", ".svc", ".cluster.local",
                                        "synthetic-release-forgejo", "synthetic-release-chroma"}))
    items.append(secret("synthetic-release-proxy", {k: v.encode() for k, v in proxy.items()}))
    items += [{"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "synthetic-release-provisioned"},
               "data": {"generation": "source:1"}},
              {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "synthetic-release-trust"},
               "data": {"bundle.pem": inputs["trust.ca_file"].decode()}}]
    identities, pvs = [], []
    for role in ("data", "forgejo", "chroma"):
        identity = {"name": "synthetic-release-"+role, "uid": "source-uid-"+role, "volume": "source-pv-"+role}
        identities.append(identity)
        items.append({"apiVersion": "v1", "kind": "PersistentVolumeClaim",
                      "metadata": {"name": identity["name"], "uid": identity["uid"]},
                      "spec": {"volumeName": identity["volume"], "storageClassName": "source-class"}})
        pvs.append({"apiVersion": "v1", "kind": "PersistentVolume", "metadata": {"name": identity["volume"]},
                    "spec": {"claimRef": {"uid": identity["uid"], "namespace": "synthetic-namespace"}}})
    installed = {"format": "gsj.installed/1", "manifest": json.loads(json.dumps(release)), "site": site,
                 "storage": identities, "namespace_uid": "source-namespace-uid"}
    target = json.loads(json.dumps(site))
    target["target"]["context"] = "relocated-context"
    target["storage"].update(node="target-node", **{"class": "target-class"})
    if damage == "model": installed["manifest"]["model"]["identity"] = "wrong-model"
    if damage == "core": installed["manifest"]["core"]["commit"] = "d" * 40
    if damage == "schema": installed["site"]["schema_version"] = "gsj.site/999"
    if damage == "target-ref": target["tls"]["secret"] = "different-secret"
    if damage == "target-tls-owner": target["tls"]["profile"] = "existing"
    if damage == "target-claim": target["storage"]["data"]["existing_claim"] = "different-claim"
    if damage == "foreign-secret": items.append(secret("someone-else", {"private": b"synthetic"}))
    if damage == "missing-secret": items = [v for v in items if v["metadata"]["name"] != "synthetic-release-agent-token"]
    if damage == "duplicate": items.append(items[-1])
    entries = [{"name": name, "data": base64.b64encode(value).decode(), "mode": 0o600}
               for name, value in inputs.items() if not fallback or name.startswith("managed_tls.")]
    if damage == "input-key": entries[0]["data"] = base64.b64encode(b"different password").decode()
    if damage == "input-name": entries[0]["name"] = "unapproved.file"
    if damage == "input-duplicate": entries.append(entries[0])
    if damage == "input-mode": entries[0]["mode"] = 0o644
    documents = {"installed.json": installed, "site.pending.json": site, "controllers.json": {"items": []},
                 "cluster-private.json": {"kind": "List", "items": items},
                 "volumes-private.json": {"kind": "List", "items": pvs},
                 "site_inputs.json": {"format": "gsj.site-inputs/1", "entries": entries}}
    if transform is not None:
        transform(documents, target, work)
    packed = tmp_path / "resources.tar.gz"
    with tarfile.open(packed, "w:gz", format=tarfile.USTAR_FORMAT) as archive:
        for name, obj in documents.items():
            entry = tarfile.TarInfo(name)
            data = json.dumps(obj).encode()
            entry.size, entry.mode = len(data), 0o600
            if name == "installed.json" and damage in ("symlink", "hardlink", "device", "directory"):
                entry.type = {"symlink": tarfile.SYMTYPE, "hardlink": tarfile.LNKTYPE,
                              "device": tarfile.CHRTYPE, "directory": tarfile.DIRTYPE}[damage]
                entry.linkname = "../../outside-victim"
                entry.size = 0
            archive.addfile(entry, io.BytesIO(data) if entry.isfile() else None)
    password = tmp_path / "backup-password"
    password.write_bytes(b"synthetic-backup-passphrase")
    password.chmod(0o600)
    archive_path = tmp_path / "snapshot.tar.gz.enc"
    plaintext = tmp_path / "synthetic-volumes"
    plaintext.write_bytes(b"synthetic volume bytes; physical archive verification is separately tested")
    for src, dst in ((plaintext, archive_path), (packed, Path(str(archive_path)+".resources.enc"))):
        subprocess.run(["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-iter", "600000", "-salt",
                        "-pass", "file:"+str(password), "-in", str(src), "-out", str(dst)],
                       check=True, capture_output=True)
    Path(str(archive_path)+".json").write_text(json.dumps({"format": "gsj.backup/1", "verified": True,
        "release_identity": release["identity"], "sha256": hashlib.sha256(archive_path.read_bytes()).hexdigest(),
        "resources_sha256": hashlib.sha256(Path(str(archive_path)+".resources.enc").read_bytes()).hexdigest()}))
    (work / "target-site.json").write_text(json.dumps(target))
    result = subprocess.run(["jq", "--slurpfile", "release", str(payload / "release.json"), "-f", str(INSTALLER / "compile.jq")],
                            input=json.dumps(target), text=True, capture_output=True, check=True)
    (work / "values.pending.json").write_text(result.stdout)
    state.write_text(json.dumps({"lease": None, "calls": [], "resources": {}}))
    body = '''COMMAND="${TEST_COMMAND:-restore}"; RESUME_ID="${TEST_RESUME:-}"
SITE="$TEST_WORK/target-site.json"; GSJ_PAYLOAD="$TEST_PAYLOAD"
ARCHIVE="$TEST_ARCHIVE"; BACKUP_PASSWORD="$TEST_BACKUP_PASSWORD"; OP_PASSWORD="$TEST_WORK/operator-password"
managed_dependencies() { :; }
# This fixture tests Kubernetes/credential reconciliation. File extraction and
# its killed-process replay are exercised with real archives in their own tests.
restore_files() {
 k exec synthetic-restore -- restore
 jq '.status="files-restored"' "$STATE_DIR/restoration.json" | atomic "$STATE_DIR/restoration.json"
 jq '.status="restore-files-verified"' "$STATE_DIR/operation.json" | atomic "$STATE_DIR/operation.json"
}
restore_finish_pod() { k exec synthetic-restore -- restore-finish; }
secret_inputs() { secret_file "$(j .operator.secret)" password "$OP_PASSWORD"; }
helm_apply() { :; }; wait_application() { :; }; record_ready() { :; }; verify_application() { :; }; record_installed() { :; }
restore_archive
'''
    def invoke(command="restore", operation="", before_restore=""):
        script = body.replace("\nrestore_archive\n", "\n" + before_restore + "\nrestore_archive\n")
        return run(script, TEST_PAYLOAD=str(payload), TEST_ARCHIVE=str(archive_path), TEST_BACKUP_PASSWORD=str(password),
                   TEST_COMMAND=command, TEST_RESUME=operation)
    return invoke, inputs


@pytest.mark.parametrize("fallback,password_newline", [(False, False), (True, False), (False, True)])
def test_restore_empty_target_preserves_credentials_and_ca_files_exactly(runtime, tmp_path, fallback, password_newline):
    invoke, inputs = _restore_fixture(runtime, tmp_path, fallback=fallback, password_newline=password_newline)
    _, state, work = runtime
    result = invoke()
    assert result.returncode == 0, result.stderr
    assert (work / "operator-password").read_bytes() == inputs["operator.password_file"]
    assert (work / "llm-key").read_bytes() == inputs["llm.credential.file"]
    assert (work / "ocr-key").read_bytes() == inputs["ocr.credential.file"]
    assert (work / "registry-json").read_bytes() == inputs["registry.config_file"]
    assert (work / "tls-key").read_bytes() == inputs["tls.private_key_file"]
    assert (work / "tls" / "ca.key").read_bytes() == inputs["managed_tls.ca.key"]
    assert (work / "tls" / "ca.crt").read_bytes() == inputs["managed_tls.ca.crt"]
    assert (work / "trust-crt").read_bytes() == inputs["trust.ca_file"]
    proxy = json.loads((work / "proxy-json").read_bytes())
    assert proxy["HTTP_PROXY"] == proxy["HTTPS_PROXY"] == ""
    assert "localhost" in proxy["NO_PROXY"].split(",")
    assert (work / "operator-password").stat().st_mode & 0o777 == 0o600
    assert json.loads((work / "restoration.json").read_text())["status"] == "complete"
    actual = json.loads(state.read_text())
    claims = [v for v in actual["resources"].values() if v["kind"] == "PersistentVolumeClaim"]
    assert len(claims) == 3
    assert all(v["spec"]["storageClassName"] == "target-class" and "volumeName" not in v["spec"] for v in claims)
    assert "synthetic-password" not in result.stdout + result.stderr


@pytest.mark.parametrize("damage", ["symlink", "hardlink", "device", "directory", "model", "core", "schema",
                                    "target-ref", "target-claim", "target-tls-owner", "foreign-secret", "missing-secret", "duplicate",
                                    "input-key", "input-name", "input-duplicate", "input-mode"])
def test_restore_rejects_unsafe_metadata_before_any_cluster_mutation(runtime, tmp_path, damage):
    invoke, _ = _restore_fixture(runtime, tmp_path, damage=damage)
    _, state, work = runtime
    victim = tmp_path / "outside-victim"
    victim.write_bytes(b"existing unrelated bytes")
    result = invoke()
    assert result.returncode != 0
    assert victim.read_bytes() == b"existing unrelated bytes"
    assert not (work / "restoration.json").exists()
    assert not any(a[0] in ("create", "replace", "apply", "delete", "exec") for a in json.loads(state.read_text())["calls"])


@pytest.mark.parametrize("collision", ["PersistentVolumeClaim/synthetic-release-data", "Secret/synthetic-release-operator", "input-file", "api-error"])
def test_restore_never_overwrites_existing_resources_or_files(runtime, tmp_path, collision):
    invoke, _ = _restore_fixture(runtime, tmp_path)
    _, state, work = runtime
    current = json.loads(state.read_text())
    if "/" in collision:
        kind, name = collision.split("/", 1)
        current["resources"][collision] = {"kind": kind, "metadata": {"name": name}, "data": {"preserve": "synthetic"}}
    elif collision == "input-file":
        (work / "operator-password").write_bytes(b"preserve existing password")
    else:
        current["fail_get"] = "Secret/synthetic-release-operator"
    state.write_text(json.dumps(current))
    result = invoke()
    assert result.returncode != 0
    actual = json.loads(state.read_text())
    assert actual["resources"] == current["resources"]
    assert not any(a[0] in ("create", "replace", "apply", "delete", "exec") for a in actual["calls"])
    if collision == "input-file":
        assert (work / "operator-password").read_bytes() == b"preserve existing password"


def test_interrupted_restore_retains_phase_and_refuses_automatic_replay(runtime, tmp_path):
    invoke, _ = _restore_fixture(runtime, tmp_path)
    _, state, work = runtime
    current = json.loads(state.read_text())
    current["fail_restore"] = True
    state.write_text(json.dumps(current))
    result = invoke()
    assert result.returncode != 0
    assert json.loads((work / "restoration.json").read_text())["status"] == "restoring-files"
    assert json.loads((work / "operation.json").read_text())["status"] == "restoring-files"
    after_failure = json.loads(state.read_text())
    assert after_failure["lease"]["spec"]["holderIdentity"]
    retry = invoke()
    assert retry.returncode != 0 and "checkpoint" in retry.stderr
    assert json.loads(state.read_text()) == after_failure


def test_restore_create_collision_keeps_winners_bytes_and_records_partial_phase(runtime, tmp_path):
    invoke, _ = _restore_fixture(runtime, tmp_path)
    _, state, work = runtime
    current = json.loads(state.read_text())
    winner = {"kind": "Secret", "metadata": {"name": "synthetic-release-operator"},
              "data": {"password": base64.b64encode(b"another owners password").decode()}}
    current["race_resource"] = winner
    state.write_text(json.dumps(current))
    result = invoke()
    assert result.returncode != 0
    actual = json.loads(state.read_text())
    assert actual["resources"]["Secret/synthetic-release-operator"] == winner
    assert not any(a[0] == "exec" for a in actual["calls"])
    assert json.loads((work / "restoration.json").read_text())["status"] == "creating-resources"
    retry = invoke()
    assert retry.returncode != 0 and "checkpoint" in retry.stderr
    assert json.loads(state.read_text()) == actual


@pytest.mark.parametrize("matching", [False, True])
def test_download_hash_is_verified_before_any_installer_execution(runtime, tmp_path, matching):
    run, _, _ = runtime
    artifact = tmp_path / "artifact.sh"
    artifact.write_text('#!/bin/sh\nprintf verified > "$TEST_EXECUTED"\n')
    marker, output = tmp_path / "executed", tmp_path / "verified.sh"
    expected = hashlib.sha256(artifact.read_bytes()).hexdigest() if matching else "0" * 64
    result = run('fetch https://releases.example/installer "$TEST_OUTPUT" "$TEST_SHA"\nbash "$TEST_OUTPUT"\n',
                 TEST_ARTIFACT=str(artifact), TEST_EXECUTED=str(marker), TEST_OUTPUT=str(output), TEST_SHA=expected)
    assert (result.returncode == 0) is matching
    assert marker.exists() is matching
    assert output.exists() is matching


@pytest.mark.parametrize("damage", [None, "signature", "hash", "length", "version", "trust"])
@pytest.mark.parametrize("command", ["upgrade", "repair"])
def test_upgrade_requires_signature_target_identity_and_bytes_before_execution(runtime, tmp_path, damage, command):
    run, _, work = runtime
    payload = tmp_path / "payload"
    trust = payload / "trust"
    trust.mkdir(parents=True)
    private, public = tmp_path / "synthetic-private.pem", trust / "release.pem"
    subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
                    "-out", str(private)], check=True, capture_output=True)
    subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)],
                   check=True, capture_output=True)
    (payload / "release.json").write_text(json.dumps({"release_base_url": "https://releases.example"}))
    installer = tmp_path / "target-installer.sh"
    installer.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$TEST_EXECUTED"\n')
    descriptor = tmp_path / "installer-descriptor.json"
    data = {"schema": "gsj.installer-descriptor/1", "signature": "RSA-SHA256", "version": "v1.2.3",
            "trustKeySha256": hashlib.sha256(public.read_bytes()).hexdigest(),
            "installer": {"name": "gsj-install.sh", "sha256": hashlib.sha256(installer.read_bytes()).hexdigest(),
                          "bytes": installer.stat().st_size}}
    if damage == "hash":
        data["installer"]["sha256"] = "0" * 64
    if damage == "length":
        data["installer"]["bytes"] += 1
    if damage == "version":
        data["version"] = "v9.9.9"
    if damage == "trust":
        data["trustKeySha256"] = "0" * 64
    descriptor.write_text(json.dumps(data))
    signature = tmp_path / "installer-descriptor.sig"
    subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(private), "-out", str(signature),
                    str(descriptor)], check=True, capture_output=True)
    if damage == "signature":
        signature.write_bytes(b"invalid signature")
    mapping = tmp_path / "artifacts.json"
    mapping.write_text(json.dumps({"installer-descriptor.json": str(descriptor),
                                   "installer-descriptor.sig": str(signature), "gsj-install.sh": str(installer)}))
    marker = tmp_path / "executed"
    result = run('GSJ_PAYLOAD="$TEST_PAYLOAD"\nCONFIG=synthetic-site.json\nCOMMAND="$TEST_COMMAND"\nRESUME_ID=synthetic-operation\nINTERACTIVE=false\nacquire_target v1.2.3\n',
                 TEST_ARTIFACT_MAP=str(mapping), TEST_PAYLOAD=str(payload), TEST_EXECUTED=str(marker), TEST_COMMAND=command)
    assert (result.returncode == 0) is (damage is None), result.stderr
    assert marker.exists() is (damage is None)
    if damage is None:
        expected = [command, "--config", "synthetic-site.json", "--expected-version", "v1.2.3"]
        if command == "repair":
            expected += ["--operation", "synthetic-operation"]
        assert marker.read_text().splitlines() == expected + ["--non-interactive"]
    elif damage in ("signature", "version"):
        assert not (work / "target-v1.2.3.sh").exists(), "untrusted descriptor triggered installer download"


def test_backup_preserves_explicit_delivery_and_backup_transport_files_but_not_recovery_key(runtime):
    run, state, work = runtime
    _backup_fixture(state, work)
    installed = json.loads((work / "installed.json").read_text())
    expected = {}
    for section in ("delivery", "backup"):
        for field in ("ca_file", "auth_header_file"):
            name = section + "." + field
            path = work / name
            path.write_bytes(("synthetic-" + name + "\n").encode())
            path.chmod(0o600)
            installed["site"][section][field] = str(path)
            expected[name] = path.read_bytes()
    recovery = work / "recovery-key"
    recovery.write_bytes(b"synthetic-decryption-secret")
    recovery.chmod(0o600)
    installed["site"]["backup"]["passphrase_file"] = str(recovery)
    (work / "installed.json").write_text(json.dumps(installed))
    result = run("backup_resources\n")
    assert result.returncode == 0, result.stderr
    entries = json.loads((work / "site_inputs.json").read_text())["entries"]
    actual = {entry["name"]: base64.b64decode(entry["data"]) for entry in entries}
    assert all(actual[name] == value for name, value in expected.items())
    assert "backup.passphrase_file" not in actual
    assert b"synthetic-decryption-secret" not in actual.values()


def test_restore_recovers_explicit_delivery_and_backup_transport_files(runtime, tmp_path):
    invoke, inputs = _restore_fixture(runtime, tmp_path, transport_files=True)
    _, _, work = runtime
    result = invoke()
    assert result.returncode == 0, result.stderr
    for field, name in (("delivery.ca_file", "delivery-crt"),
                        ("delivery.auth_header_file", "delivery-header"),
                        ("backup.ca_file", "backup-crt"),
                        ("backup.auth_header_file", "backup-header")):
        assert (work / name).read_bytes() == inputs[field]
        assert (work / name).stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("credential", ["missing", "archived", "new"])
def test_restore_changed_backup_destination_requires_distinct_explicit_auth(runtime, tmp_path, credential):
    invoke, inputs = _restore_fixture(runtime, tmp_path, transport_files=True)
    _, state, work = runtime
    target = json.loads((work / "target-site.json").read_text())
    target["backup"]["offbox_url"] = "https://different-backup.example/synthetic"
    (work / "target-site.json").write_text(json.dumps(target))
    auth = work / "backup-header"
    if credential != "missing":
        auth.write_bytes(inputs["backup.auth_header_file"] if credential == "archived"
                         else b"Authorization: Bearer synthetic-new-destination\n")
        auth.chmod(0o600)
    result = invoke()
    assert (result.returncode == 0) is (credential == "new"), result.stderr
    if credential == "new":
        assert auth.read_bytes() == b"Authorization: Bearer synthetic-new-destination\n"
        assert json.loads((work / "restoration.json").read_text())["status"] == "complete"
    else:
        assert "backup destination changed" in result.stderr
        assert not (work / "restoration.json").exists()
        assert not any(call[0] in ("create", "replace", "apply", "delete", "exec")
                       for call in json.loads(state.read_text())["calls"])
    assert "Bearer synthetic" not in result.stdout + result.stderr


# The terminal codes no restart can clear: wait_application stops on them and
# acquire admits the operation that repairs them.
TERMINAL_CODES = ["terminal-budget-exhausted", "deadline-exceeded", "checkpoint-identity-mismatch",
                  "source-verification-failed", "corpus-update-required", "model-change-blocked",
                  "manifest-mismatch", "core-mismatch", "invalid-settings"]


def _init_status(state, message=None):
    status = {"name": "corpus-initialize", "state": state}
    if message is not None:
        status["lastState"] = {"terminated": {"exitCode": 1, "message": message}}
    return status


@pytest.mark.parametrize("status,refused", [
    (_init_status({"running": {}}), True),
    (_init_status({"waiting": {"reason": "CrashLoopBackOff"}}, "gsj-corpus:chroma-unavailable"), True),
    (_init_status({"waiting": {"reason": "CrashLoopBackOff"}}, ""), True),
    (_init_status({"terminated": {"exitCode": 0}}), False),
    # Never ran (first image pull back-off): it cannot write yet.
    (_init_status({"waiting": {"reason": "ImagePullBackOff"}}), False),
] + [(_init_status({"waiting": {"reason": "CrashLoopBackOff"}}, "gsj-corpus:" + code), False) for code in TERMINAL_CODES])
def test_acquire_refuses_a_running_or_backing_off_initializer(runtime, status, refused):
    run, kube, work = runtime
    payload = work / "payload"; payload.mkdir()
    (payload / "release.json").write_text(json.dumps(_release()))
    pod = {"kind": "Pod", "metadata": {"name": "synthetic-web", "labels": {"app.kubernetes.io/instance": "synthetic-release"}},
           "status": {"initContainerStatuses": [status]}}
    kube.write_text(json.dumps({"lease": None, "calls": [], "resources": {"Pod/synthetic-web": pod}}))
    result = run('GSJ_PAYLOAD="$TEST_PAYLOAD"; acquire\n', TEST_PAYLOAD=str(payload))
    lease = json.loads(kube.read_text())["lease"]
    if refused:
        assert result.returncode != 0 and "still running or restarting" in result.stderr
        assert lease is None and not (work / "operation.json").exists()
    else:
        assert result.returncode == 0, result.stderr
        assert lease["spec"]["holderIdentity"]


_WAIT_BODY = '''OPERATION=aaaaaaaaaaaaaaaaaaaaaaaa; CONFIG=/secure/site.json
assert_owner() { :; }; helm_application_validate() { :; }; sleep() { :; }
k() {
 case "$1 $2" in
  "get deploy")
   if [[ -f $TEST_WORK/ready ]]; then printf '%s' '{"metadata":{"generation":1},"status":{"observedGeneration":1,"updatedReplicas":1,"availableReplicas":1,"readyReplicas":1}}'
   else touch "$TEST_WORK/ready"; printf '%s' '{"metadata":{"generation":1},"status":{}}'; fi;;
  "get pods") cat "$TEST_WORK/pods.json";;
  *) :;;
 esac
}
wait_application
'''


def _initializer_pods(name, state, last=None, deleting=False):
    status = {"name": name, "state": state}
    if last is not None:
        status["lastState"] = {"terminated": {"exitCode": 1, "message": last}}
    metadata = {"name": "synthetic-web"}
    if deleting:
        metadata["deletionTimestamp"] = "2026-09-14T00:00:00Z"
    return {"items": [{"metadata": metadata, "status": {"phase": "Pending", "initContainerStatuses": [status]}}]}


BACKING_OFF = {"waiting": {"reason": "CrashLoopBackOff"}}


@pytest.mark.parametrize("pods,message", [
    (_initializer_pods("corpus-initialize", BACKING_OFF, "gsj-corpus:terminal-budget-exhausted\n"),
     "run: gsj-install.sh repair --operation aaaaaaaaaaaaaaaaaaaaaaaa --config /secure/site.json --non-interactive"),
    (_initializer_pods("corpus-initialize", {"terminated": {"exitCode": 1, "message": "gsj-corpus:deadline-exceeded"}}),
     "stopped terminally (deadline-exceeded)"),
    (_initializer_pods("corpus-copy", BACKING_OFF, "gsj-copy:source-verification-failed"),
     "corpus image payload failed its signed verification"),
    (_initializer_pods("corpus-initialize", BACKING_OFF, "gsj-corpus:source-verification-failed"),
     "stopped terminally (source-verification-failed)"),
    (_initializer_pods("corpus-initialize", BACKING_OFF, "gsj-corpus:checkpoint-identity-mismatch"),
     "stopped terminally (checkpoint-identity-mismatch)"),
    (_initializer_pods("corpus-initialize", BACKING_OFF, "gsj-corpus:corpus-update-required"), "corpus.allow_update=true"),
    (_initializer_pods("corpus-initialize", BACKING_OFF, "gsj-corpus:model-change-blocked"), "different embedding model"),
    (_initializer_pods("corpus-initialize", BACKING_OFF, "gsj-corpus:manifest-mismatch"), "signed manifest or core"),
    (_initializer_pods("corpus-copy", BACKING_OFF, "gsj-copy:core-mismatch"), "signed manifest or core"),
    (_initializer_pods("corpus-initialize", BACKING_OFF, "gsj-corpus:invalid-settings"), "signed manifest or core"),
    # A declared vector sidecar that never arrived is terminal and names its own
    # action: refused by name, never silently replaced by embedding, and not
    # "retried until its deadline".
    (_initializer_pods("corpus-initialize", BACKING_OFF, "gsj-corpus:released-vectors-missing"),
     "declares released vectors but none were staged"),
])
def test_wait_fails_fast_with_the_named_recovery_for_terminal_initializer_codes(runtime, pods, message):
    run, _, work = runtime
    (work / "pods.json").write_text(json.dumps(pods))
    result = run(_WAIT_BODY)
    assert result.returncode != 0
    assert message in result.stderr
    assert not (work / "ready").exists() or "deadline exceeded" not in result.stderr


@pytest.mark.parametrize("pods", [
    _initializer_pods("corpus-initialize", BACKING_OFF, "gsj-corpus:chroma-unavailable"),
    _initializer_pods("corpus-initialize", BACKING_OFF, "gsj-corpus:internal-error"),
    _initializer_pods("corpus-initialize", BACKING_OFF, "gsj-corpus:writer-busy"),
    _initializer_pods("corpus-initialize", {"running": {}}, "gsj-corpus:terminal-budget-exhausted"),
    _initializer_pods("corpus-initialize", {"terminated": {"exitCode": 0}}, "gsj-corpus:deadline-exceeded"),
    _initializer_pods("corpus-initialize", BACKING_OFF, "gsj-corpus:deadline-exceeded", deleting=True),
    _initializer_pods("corpus-initialize", BACKING_OFF, "gsj-corpus:../../etc Deadline"),
    _initializer_pods("wait-deps", BACKING_OFF, "gsj-corpus:deadline-exceeded"),
    {"items": []},
])
def test_wait_keeps_waiting_through_transient_or_foreign_initializer_state(runtime, pods):
    run, _, work = runtime
    (work / "pods.json").write_text(json.dumps(pods))
    result = run(_WAIT_BODY)
    assert result.returncode == 0, result.stderr
    assert (work / "ready").exists()


def test_terminal_initializer_names_repair_instead_of_resume_on_exit(runtime):
    run, _, _ = runtime
    result = run('''GSJ_WORK="$TEST_WORK/throwaway"; mkdir -p "$GSJ_WORK"
OPERATION=aaaaaaaaaaaaaaaaaaaaaaaa; CONFIG=/secure/site.json; LEASE_ACQUIRED=true
install_exit_traps
initializer_stop deadline-exceeded
''')
    assert result.returncode != 0
    assert "Use repair --operation aaaaaaaaaaaaaaaaaaaaaaaa --config /secure/site.json --non-interactive." in result.stderr
    assert "Use resume" not in result.stderr


@pytest.mark.parametrize("code", TERMINAL_CODES + ["chroma-unavailable", "writer-busy", "internal-error"])
def test_initializer_stop_is_terminal_exactly_for_the_codes_acquire_admits(runtime, code):
    run, _, _ = runtime
    result = run(f'OPERATION=aaaaaaaaaaaaaaaaaaaaaaaa; CONFIG=/secure/site.json\ninitializer_stop {code}\n')
    assert (result.returncode != 0) is (code in TERMINAL_CODES), result.stderr


@pytest.mark.parametrize("change,with_ca,accepted", [
    ({}, True, True),
    ({"tls": "CA", "verification": "CA"}, True, True),
    ({"tls": "CA", "verification": "CA"}, False, False),
    ({"tls": "CA"}, True, False),
    ({"tls": "/elsewhere/ca.crt", "verification": "/elsewhere/ca.crt"}, True, False),
    ({"tls": "CA", "verification": "CA", "public_url": "https://other.example"}, True, False),
    ({"tls": "CA", "verification": "CA", "retained_ca": "/operator/ca.crt"}, True, False),
    ({"tls": "CA", "verification": "CA", "profile": "files"}, True, False),
    ({"tls": "CA", "verification": "CA"}, "symlink", False),
])
def test_retained_site_admits_only_this_operations_derived_local_ca_paths(runtime, change, with_ca, accepted):
    # Operations started by a build older than the one that first filled the two
    # generated managed-local-ca trust paths into the saved site kept their site
    # without them; resume and restore must still continue those operations, and
    # must refuse every other difference.
    run, _, work = runtime
    ca = str(work / "state/tls/ca.crt")
    retained = {"public_url": "https://gsj.example", "tls": {"profile": "managed-local-ca", "ca_file": ""},
                "verification": {"ca_file": ""}}
    if "retained_ca" in change:
        retained["tls"]["ca_file"] = retained["verification"]["ca_file"] = change["retained_ca"]
    if "profile" in change:
        retained["tls"]["profile"] = change["profile"]
    selected = json.loads(json.dumps(retained))
    for key in ("tls", "verification"):
        if key in change:
            selected[key]["ca_file"] = ca if change[key] == "CA" else change[key]
    if "public_url" in change:
        selected["public_url"] = change["public_url"]
    (work / "retained.json").write_text(json.dumps(retained))
    (work / "selected.json").write_text(json.dumps(selected))
    setup = {True: 'printf ca > "$STATE_DIR/tls/ca.crt"', False: ':',
             'symlink': 'printf ca > "$STATE_DIR/tls/real.crt"; ln -s real.crt "$STATE_DIR/tls/ca.crt"'}[with_ca]
    result = run(f'''STATE_DIR="$TEST_WORK/state"; mkdir -p "$STATE_DIR/tls"
{setup}
retained_site_matches "$TEST_WORK/selected.json" "$TEST_WORK/retained.json"
''')
    assert (result.returncode == 0) is accepted, result.stderr


def test_verification_creates_its_run_directory_before_writing_trust(runtime):
    # The settings file stays off the data volume, so nothing else creates
    # /data/verification/RUN before the CA certificate is written into it.
    import sys
    run, _, work = runtime
    (work / "ca.pem").write_text("synthetic CA")
    result = run('''settings="$TEST_WORK/host/settings.json"; mkdir -p "${settings%/*}"; printf '{}' > "$settings"
OP_PASSWORD="$TEST_WORK/pw"; printf secret > "$OP_PASSWORD"; pod=synthetic
remote="$TEST_WORK/data/verification/abc"; staged="$TEST_WORK/tmp/gsj-verification/abc/settings.json"
j() { if [[ $1 == .verification.ca_file ]]; then printf '%s' "$TEST_WORK/ca.pem"; fi; }
resolve_file() { printf '%s' "$1"; }
python() { "$TEST_PYTHON" "$@"; }
k() { while [[ $1 != -- ]]; do shift; done; shift; "$@"; }
verification_stage_settings
''', TEST_PYTHON=sys.executable)
    assert result.returncode == 0, result.stderr
    assert (work / "data/verification/abc/ca.crt").read_text() == "synthetic CA"


def test_a_verification_route_host_requires_its_port():
    # connection_route refuses port 0 only inside the Pod, after the Lease;
    # load_site refuses the same combination before any cluster action.
    site = _site()
    site["verification"].update(connect_host="synthetic-control-plane", connect_port=0)
    refused = _validate(site)
    assert refused.returncode != 0
    assert "verification: connect_port required with connect_host" in refused.stderr
    assert "synthetic-control-plane" not in refused.stderr
    site["verification"]["connect_port"] = 30443
    assert _validate(site).returncode == 0


def _route_probe():
    body = (INSTALLER / "runtime.sh").read_text().split("verification_route_preflight() {", 1)[1]
    return body.split("python -c '", 1)[1].split("' \"$staged\"", 1)[0]


def _probe_env(**proxy):
    """This process's environment without its proxy settings, plus `proxy`."""
    return {**{k: v for k, v in os.environ.items() if not k.lower().endswith("_proxy")}, **proxy}


def test_inline_route_probe_dials_the_route_and_verifies_the_canonical_host(tmp_path):
    # The Pod-side preflight, run with this Python against local listeners:
    # TCP goes to connect_host:connect_port, SNI and hostname stay public_url's.
    import socket, ssl, sys, threading
    def openssl(*args):
        subprocess.run(["openssl", *map(str, args)], check=True, capture_output=True)
    def authority(name):
        key, cert = tmp_path / f"{name}.key", tmp_path / f"{name}.crt"
        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", f"/CN={name}",
                "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                "-keyout", key, "-out", cert)
        return key, cert
    ca_key, ca_cert = authority("synthetic-ca")
    _, other_cert = authority("other-ca")
    leaf_key, leaf_csr, leaf = tmp_path / "leaf.key", tmp_path / "leaf.csr", tmp_path / "leaf.crt"
    openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=legal.example",
            "-keyout", leaf_key, "-out", leaf_csr)
    extensions = tmp_path / "leaf.ext"
    extensions.write_text("subjectAltName=DNS:legal.example\nbasicConstraints=critical,CA:FALSE\n"
                          "keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n"
                          "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n")
    openssl("x509", "-req", "-in", leaf_csr, "-CA", ca_cert, "-CAkey", ca_key, "-CAcreateserial", "-days", "1",
            "-sha256", "-extfile", extensions, "-out", leaf)
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(leaf, leaf_key)
    listener = socket.create_server(("127.0.0.1", 0))
    def serve():
        while True:
            try: connection, _ = listener.accept()
            except OSError: return
            try: server.wrap_socket(connection, server_side=True).close()
            except OSError: connection.close()
    threading.Thread(target=serve, daemon=True).start()
    closed = socket.create_server(("127.0.0.1", 0)); unused = closed.getsockname()[1]; closed.close()
    def probe(port, ca):
        settings = tmp_path / "settings.json"
        settings.write_text(json.dumps({"web_url": "https://legal.example:8443", "connect_host": "127.0.0.1",
                                        "connect_port": port, "ca_file": str(ca)}))
        # No proxy carries the origin, and none of this host's settings leak in.
        return subprocess.run([sys.executable, "-c", _route_probe(), str(settings)], env=_probe_env(NO_PROXY="*"),
                              capture_output=True, text=True, timeout=60)
    try:
        assert probe(unused, ca_cert).returncode == 73
        assert probe(listener.getsockname()[1], other_cert).returncode == 74
        accepted = probe(listener.getsockname()[1], ca_cert)
        assert accepted.returncode == 0, accepted.stderr
    finally:
        listener.close()


@pytest.mark.parametrize("proxy,code", [
    ({"HTTPS_PROXY": "http://127.0.0.1:9"}, 0),
    ({"https_proxy": "http://127.0.0.1:9", "no_proxy": "cluster.local,.example"}, 73),
    ({"HTTPS_PROXY": "http://127.0.0.1:9", "NO_PROXY": "legal.example"}, 73),
    ({"HTTP_PROXY": "http://127.0.0.1:9"}, 73),
])
def test_inline_route_probe_leaves_a_proxied_origin_to_the_proxy(tmp_path, proxy, code):
    # trust.proxy_file gives gsj-web HTTPS_PROXY/NO_PROXY. When the proxy
    # carries public_url, the verifier's httpx goes through it and the route
    # fields are inert: the closed route below is not dialled. When NO_PROXY
    # exempts the host, or the proxy is for another scheme, it is dialled.
    import socket, sys
    closed = socket.create_server(("127.0.0.1", 0)); unused = closed.getsockname()[1]; closed.close()
    settings = tmp_path / "settings.json"
    settings.write_text(json.dumps({"web_url": "https://legal.example:8443", "connect_host": "127.0.0.1",
                                    "connect_port": unused, "ca_file": ""}))
    result = subprocess.run([sys.executable, "-c", _route_probe(), str(settings)], env=_probe_env(**proxy),
                            capture_output=True, text=True, timeout=60)
    assert result.returncode == code, result.stderr


STRICT_CA = ("basicConstraints=critical,CA:TRUE", "keyUsage=critical,keyCertSign,cRLSign")  # managed_dependencies


def _local_ca(directory, ca_extensions=STRICT_CA, leaf_extensions=""):
    """A CA and a server certificate for legal.example, issued as managed_dependencies issues them."""
    directory.mkdir(parents=True, exist_ok=True)
    def openssl(*args):
        subprocess.run(["openssl", *args], check=True, capture_output=True, cwd=directory)
    openssl("req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes", "-days", "1", "-subj", "/CN=GSJ sandbox local CA",
            *[value for extension in ca_extensions for value in ("-addext", extension)], "-keyout", "ca.key", "-out", "ca.crt")
    openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=legal.example", "-keyout", "tls.key", "-out", "tls.csr")
    (directory / "extensions").write_text("subjectAltName=DNS:legal.example\nextendedKeyUsage=serverAuth\n"
                                          "keyUsage=critical,digitalSignature,keyEncipherment\n"
                                          "basicConstraints=critical,CA:FALSE\n" + leaf_extensions)
    openssl("x509", "-req", "-in", "tls.csr", "-CA", "ca.crt", "-CAkey", "ca.key", "-CAcreateserial", "-days", "1",
            "-sha256", "-extfile", "extensions", "-out", "tls.crt")
    (directory / "ca.key").chmod(0o600)


def _handshakes(directory):
    """A loopback listener that completes TLS handshakes with directory's server certificate."""
    import socket, ssl, threading
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(directory / "tls.crt", directory / "tls.key")
    listener = socket.create_server(("127.0.0.1", 0))
    def serve():
        while True:
            try: connection, _ = listener.accept()
            except OSError: return
            try: server.wrap_socket(connection, server_side=True).close()
            except OSError: connection.close()
    threading.Thread(target=serve, daemon=True).start()
    return listener


def _pod_preflight_env(work, port, anchor):
    """Staged settings for the route through the listener, and an environment without proxies."""
    import sys
    (work / "staged.json").write_text(json.dumps({"web_url": "https://legal.example", "connect_host": "127.0.0.1",
                                                 "connect_port": port, "ca_file": str(anchor),
                                                 "operator_password": "SYNTHETIC_PASSWORD_DO_NOT_ECHO"}))
    return {**{name: "" for name in os.environ if name.lower().endswith("_proxy")},
            "NO_PROXY": "*", "no_proxy": "*", "TEST_PYTHON": sys.executable}


# verification_route_preflight with its Pod command run here, under this Python;
# every other kubectl call goes to the fixture's fake (a jsonpath read, as jq).
POD_PREFLIGHT = '''GSJ_WORK="$TEST_WORK/throwaway"; mkdir -p "$GSJ_WORK"
OPERATION=aaaaaaaaaaaaaaaaaaaaaaaa; pod=synthetic; settings="$TEST_WORK/staged.json"; staged=$settings
python() { "$TEST_PYTHON" -B "$@"; }
k() {
 if [[ $1 == exec ]]; then while [[ $1 != -- ]]; do shift; done; shift; "$@"
 elif [[ ${5:-} == jsonpath=* ]]; then kubectl "$1" "$2" "$3" -o json | jq -r .metadata.resourceVersion
 else kubectl "$@"; fi
}
'''


def _strict_python():
    import ssl
    if not ssl.create_default_context().verify_flags & ssl.VERIFY_X509_STRICT:
        pytest.skip("this interpreter is not X.509-strict like the verifier image's Python 3.13")


@pytest.mark.parametrize("case,reason,named", [
    ("ca-without-key-usage", "CA cert does not include key usage extension", True),
    ("ca-basic-constraints-not-critical", "Basic Constraints of CA cert not marked critical", True),
    ("leaf-without-authority-key-id", "Missing Authority Key Identifier", False),
    ("wrong-trust-anchor", "unable to get local issuer certificate", False),
    ("files-profile", "CA cert does not include key usage extension", False),
    ("ca-produced-by-tls-repair", "CA cert does not include key usage extension", False),
])
def test_pod_preflight_names_tls_repair_only_for_a_ca_defect_it_repairs(runtime, case, reason, named):
    # Real certificates through the real probe and classification: tls-repair
    # reissues only the managed CA's signing extensions, once per CA.
    _strict_python()
    run, _, work = runtime
    ca = {"ca-without-key-usage": STRICT_CA[:1], "files-profile": STRICT_CA[:1], "ca-produced-by-tls-repair": STRICT_CA[:1],
          "ca-basic-constraints-not-critical": ("basicConstraints=CA:TRUE", STRICT_CA[1])}.get(case, STRICT_CA)
    _local_ca(work / "tls", ca, "authorityKeyIdentifier=none\nsubjectKeyIdentifier=none\n" if case.startswith("leaf") else "")
    anchor = work / "tls/ca.crt"
    if case == "wrong-trust-anchor":
        _local_ca(work / "other"); anchor = work / "other/ca.crt"
    if case == "ca-produced-by-tls-repair":
        (work / "tls-repair.json").write_text(json.dumps({"after_ca_sha256": hashlib.sha256(anchor.read_bytes()).hexdigest()}))
    site = _site(); site["tls"]["profile"] = "files" if case == "files-profile" else "managed-local-ca"
    (work / "site.json").write_text(json.dumps(site))
    listener = _handshakes(work / "tls"); port = listener.getsockname()[1]
    try:
        result = run(POD_PREFLIGHT + "LEASE_ACQUIRED=true; install_exit_traps\nverification_route_preflight\n",
                     **_pod_preflight_env(work, port, anchor))
    finally:
        listener.close()
    output = result.stdout + result.stderr
    assert result.returncode != 0 and "SYNTHETIC_PASSWORD_DO_NOT_ECHO" not in output
    assert f"reached https://legal.example through verification route 127.0.0.1:{port}" in result.stderr, result.stderr
    assert f"({reason}; origin-tls-failed)" in result.stderr, result.stderr
    operation = "a" * 24
    if named:
        assert (f"Use tls-repair --operation {operation}, then resume --operation {operation}; each needs the operation "
                "Lease unrenewed for 180 seconds, so wait 3 minutes before each.") in result.stderr
    else:
        assert "tls-repair" not in output
        assert (f"Use resume --operation {operation} once the certificate served for https://legal.example passes "
                "strict verification from the Pod.") in result.stderr


def test_tls_repair_output_passes_the_pod_preflight_and_names_the_second_lease_wait(runtime):
    # The live incident end to end: the Pod refuses the legacy managed CA before
    # any verifier exists; tls-repair reissues it under the same key, keeps the
    # served certificate and names the Lease wait before resume; the same
    # strict check then passes.
    _strict_python()
    run, state, work = runtime
    _local_ca(work / "tls", STRICT_CA[:1])
    leaf = (work / "tls/tls.crt").read_bytes()
    site = _site(); site["tls"]["profile"] = "managed-local-ca"
    (work / "site.json").write_text(json.dumps(site))
    operation = "a" * 24
    cluster = json.loads(state.read_text())
    cluster["lease"] = {"kind": "Lease", "metadata": {"name": "synthetic-release-operation", "resourceVersion": "1"},
                        "spec": {"holderIdentity": operation, "renewTime": "2020-01-01T00:00:00.000000Z"}}
    cluster["resources"] = {"Secret/gsj-tls": {"kind": "Secret", "metadata": {"name": "gsj-tls", "resourceVersion": "7"},
                                               "data": {"tls.crt": base64.b64encode(leaf).decode()}}}
    state.write_text(json.dumps(cluster))
    listener = _handshakes(work / "tls"); port = listener.getsockname()[1]
    env = _pod_preflight_env(work, port, work / "tls/ca.crt")
    try:
        refused = run(POD_PREFLIGHT + "LEASE_ACQUIRED=true; install_exit_traps\nverification_route_preflight\n", **env)
        repaired = run(POD_PREFLIGHT + f"RESUME_ID={operation}; tls_repair\nOPERATION={operation}; verification_route_preflight\n"
                       "log 'Pod preflight passed'\n", **env)
    finally:
        listener.close()
    assert refused.returncode != 0 and f"Use tls-repair --operation {operation}, then resume" in refused.stderr, refused.stderr
    assert repaired.returncode == 0, repaired.stderr
    assert (f"Wait until the operation Lease has been unrenewed for 180 seconds, then run resume --operation {operation} "
            "with the installer that owns the operation") in repaired.stderr
    assert repaired.stderr.rstrip().endswith("Pod preflight passed")
    receipt = json.loads((work / "tls-repair.json").read_text())
    assert receipt["after_ca_sha256"] == hashlib.sha256((work / "tls/ca.crt").read_bytes()).hexdigest()
    assert (work / "tls/tls.crt").read_bytes() == leaf
    for result in (refused, repaired):
        assert "SYNTHETIC_PASSWORD_DO_NOT_ECHO" not in result.stdout + result.stderr


def test_a_damaged_corpus_image_payload_is_not_sent_to_repair(runtime):
    # The copier quarantines and recopies a damaged derived shard itself, so
    # gsj-copy:source-verification-failed means the image payload is bad.
    run, _, work = runtime
    (work / "pods.json").write_text(json.dumps(
        _initializer_pods("corpus-copy", BACKING_OFF, "gsj-copy:source-verification-failed")))
    result = run(_WAIT_BODY)
    assert result.returncode != 0
    assert "corpus image payload failed its signed verification" in result.stderr
    assert "run: gsj-install.sh repair" not in result.stderr
    derived = run('OPERATION=aaaaaaaaaaaaaaaaaaaaaaaa; CONFIG=/secure/site.json\n'
                  'initializer_stop corpus:source-verification-failed\n')
    assert derived.returncode != 0
    assert "stopped terminally (source-verification-failed)" in derived.stderr
    trapped = run('''GSJ_WORK="$TEST_WORK/throwaway"; mkdir -p "$GSJ_WORK"
OPERATION=aaaaaaaaaaaaaaaaaaaaaaaa; CONFIG=/secure/site.json; LEASE_ACQUIRED=true
install_exit_traps
initializer_stop copy:source-verification-failed
''')
    assert trapped.returncode != 0
    assert "--to VERSION with a verified signed release" in trapped.stderr


def test_turn_timeout_schema_floor_is_the_agent_runner_floor():
    import sys
    schema = json.loads((INSTALLER / "site.schema.json").read_text())
    floor = schema["properties"]["limits"]["properties"]["turn_seconds"]["minimum"]
    assert floor == 60
    site = _site()
    for value, accepted in ((floor - 1, False), (floor, True)):
        site["limits"]["turn_seconds"] = value
        assert (_validate(site).returncode == 0) is accepted
        pytest.importorskip("agent_runner")  # the product package, installed at web-pin.json's commit
        runner = subprocess.run([sys.executable, "-c", "from agent_runner.service import Settings; Settings()"],
                                cwd=ROOT, capture_output=True, text=True,
                                env={"PATH": os.environ["PATH"], "GSJ_AGENT_TOKEN": "synthetic",
                                     "GSJ_AGENT_TURN_TIMEOUT": str(value)})
        assert (runner.returncode == 0) is accepted, runner.stderr


@pytest.mark.parametrize("path,value", [
    (["llm", "base_url"], "https://llm.example/v1?tenant=a"),
    (["llm", "base_url"], "https://llm.example/v1#models"),
    (["llm", "base_url"], "https://llm example/v1"),
    (["ocr", "url"], "https://ocr.example/v1/chat/completions?x=1"),
    (["ocr", "url"], "https://ocr.example/v1/chat/completions#x"),
    (["ocr", "url"], "https://user:secret@ocr.example/v1/chat/completions"),
    (["ocr", "url"], "https://ocr.example/v1/chat completions"),
])
def test_schema_url_patterns_refuse_what_the_runtime_validator_refuses(path, value):
    http_url = pytest.importorskip("gsj_web.config").http_url  # the product package, at the pin
    with pytest.raises(ValueError):
        http_url(value, "probe")
    site = _site()
    site[path[0]][path[1]] = value
    assert _validate(site).returncode != 0


_PREFLIGHT_BODY = '''GSJ_PAYLOAD="$TEST_WORK/payload"; COMMAND="${TEST_COMMAND:-install}"
k() {
 case "$1" in
  cluster-info) return 0;;
  auth) printf 'yes\\n';;
  get)
   case "$2" in
    nodes) printf '%s' '{"items":[{"metadata":{"name":"synthetic-node"},"status":{"nodeInfo":{"architecture":"amd64"}}}]}';;
    storageclass) printf '%s' '{"provisioner":"rancher.io/local-path"}';;
    ingressclass) printf '{}';;
    secret) printf '%s\\n' "$3" >> "$TEST_WORK/secret-reads"; [[ -f $TEST_WORK/pull-secret.json ]] && cat "$TEST_WORK/pull-secret.json";;
   esac;;
 esac
}
preflight
'''


@pytest.mark.parametrize("secret,config_file,command,accepted", [
    (None, "", "install", False),
    ({"type": "Opaque", "data": {"key": "c3ludGhldGlj"}}, "", "install", False),
    ({"type": "kubernetes.io/dockerconfigjson", "data": {}}, "", "install", False),
    ({"type": "kubernetes.io/dockerconfigjson", "data": {".dockerconfigjson": "e30="}}, "", "install", True),
    (None, "registry.json", "install", True),
    (None, "", "restore", True),
])
def test_referenced_pull_secret_is_checked_read_only_before_mutation(runtime, secret, config_file, command, accepted):
    run, _, work = runtime
    payload = work / "payload"; payload.mkdir()
    release = _release(); release["platforms"] = ["linux/amd64"]
    (payload / "release.json").write_text(json.dumps(release))
    site = _site(); site["registry"].update(pull_secret="registry-auth", config_file=config_file)
    (work / "site.json").write_text(json.dumps(site))
    if secret is not None:
        (work / "pull-secret.json").write_text(json.dumps(secret))
    result = run(_PREFLIGHT_BODY, TEST_COMMAND=command)
    assert (result.returncode == 0) is accepted, result.stderr
    if not accepted:
        assert "registry.pull_secret must name an existing image pull Secret" in result.stderr
    assert "c3ludGhldGlj" not in result.stdout + result.stderr
    reads = (work / "secret-reads").read_text().split() if (work / "secret-reads").exists() else []
    assert reads == ([] if config_file or command == "restore" else ["registry-auth"])


def test_trust_bundle_uses_the_system_probe_and_never_the_download_override(runtime, tmp_path):
    run, _, work = runtime
    system = next((Path(p) for p in ("/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt",
                                     "/etc/ssl/cert.pem") if Path(p).is_file()), None)
    if system is None:
        pytest.skip("no system CA bundle on this host")
    ca = tmp_path / "site-ca.crt"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=synthetic site CA",
                    "-keyout", str(tmp_path / "site-ca.key"), "-out", str(ca)], check=True, capture_output=True)
    override = tmp_path / "download-ca.pem"
    override.write_text("SYNTHETIC-DELIVERY-ONLY-CA\n")
    site = _site(); site["trust"]["ca_file"] = str(ca)
    (work / "site.json").write_text(json.dumps(site))
    result = run('''assert_owner() { :; }; secret_file() { :; }; OP_PASSWORD=unused
k() { if [[ $1 == apply ]]; then cat > /dev/null; fi; }
secret_inputs
''', CURL_CA_BUNDLE=str(override))
    assert result.returncode == 0, result.stderr
    assert (work / "ca-bundle.pem").read_bytes() == system.read_bytes() + ca.read_bytes()


def test_managed_local_ca_path_is_saved_before_the_operation_so_resume_matches(runtime, tmp_path):
    run, kube, work = runtime
    payload = tmp_path / "ca-payload"; payload.mkdir()
    for name in ("defaults.json", "site.schema.json", "validate.jq", "compile.jq"):
        shutil.copyfile(INSTALLER / name, payload / name)
    (payload / "release.json").write_text(json.dumps(_release()))
    site = _site(); site["tls"]["profile"] = "managed-local-ca"
    config = tmp_path / "site.json"
    config.write_text(json.dumps(site))
    for name in ("operator-password", "backup-passphrase"):
        (tmp_path / name).write_text("synthetic-private-value"); (tmp_path / name).chmod(0o600)
    kube.write_text(json.dumps({"lease": None, "calls": [], "resources": {
        "Secret/gsj-tls": {"kind": "Secret", "metadata": {"name": "gsj-tls"}}}}))
    load = 'GSJ_PAYLOAD="$TEST_PAYLOAD"\nCONFIG="$TEST_CONFIG"\nCONTEXT_ARG=""\nload_site\n'
    env = {"TEST_PAYLOAD": str(payload), "TEST_CONFIG": str(config)}
    # Acquire stages the loaded site for the operation and its named resume.
    first = run(load + 'cp "$SITE" "$TEST_WORK/staged-site.json"\n', **env)
    assert first.returncode == 0, first.stderr
    ca = tmp_path / ".gsj" / hashlib.sha256(b"synthetic-context").hexdigest() / "gsj" / "gsj" / "tls" / "ca.crt"
    saved = json.loads(config.read_text())
    assert saved["tls"]["ca_file"] == saved["verification"]["ca_file"] == str(ca)
    staged = (work / "staged-site.json").read_bytes()
    assert json.loads(staged)["tls"]["ca_file"] == str(ca)
    inode = config.stat().st_ino
    # The CA step no longer rewrites the operator's site mid-operation.
    second = run(load + '''assert_owner() { :; }
mkdir -p "$STATE_DIR/tls"; printf synthetic > "$STATE_DIR/tls/ca.crt"
cp "$CONFIG" "$TEST_WORK/config-before"
managed_dependencies
cmp "$SITE" "$TEST_WORK/staged-site.json" && cmp "$CONFIG" "$TEST_WORK/config-before"
''', **env)
    assert second.returncode == 0, second.stderr
    # An interrupted operation's resume loads byte-identical configuration.
    third = run(load + 'cmp "$SITE" "$TEST_WORK/staged-site.json"\n', **env)
    assert third.returncode == 0, third.stderr
    assert config.stat().st_ino == inode


def test_operation_retained_before_the_site_derivation_shim_keeps_the_operators_site_untouched(runtime, tmp_path):
    # An operation saved by a build older than the one that first filled the
    # generated managed-local-ca paths into the saved site retains its site
    # without the derived CA paths; its own installer resumes byte-exactly, so a
    # newer installer must derive the paths in memory and never rewrite the
    # operator's file.
    run, _, work = runtime
    payload = tmp_path / "ca-payload"; payload.mkdir()
    for name in ("defaults.json", "site.schema.json", "validate.jq", "compile.jq"):
        shutil.copyfile(INSTALLER / name, payload / name)
    (payload / "release.json").write_text(json.dumps(_release()))
    site = _site(); site["tls"]["profile"] = "managed-local-ca"
    config = tmp_path / "site.json"; config.write_text(json.dumps(site))
    for name in ("operator-password", "backup-passphrase"):
        (tmp_path / name).write_text("synthetic-private-value"); (tmp_path / name).chmod(0o600)
    state = tmp_path / ".gsj" / hashlib.sha256(b"synthetic-context").hexdigest() / "gsj" / "gsj"
    state.mkdir(parents=True); (state / "site.pending.json").write_text(json.dumps(site))
    before = config.read_bytes()
    result = run('GSJ_PAYLOAD="$TEST_PAYLOAD"\nCONFIG="$TEST_CONFIG"\nCONTEXT_ARG=""\nload_site\n'
                 'jq -r .tls.ca_file,.verification.ca_file "$SITE" > "$TEST_WORK/derived"\n',
                 TEST_PAYLOAD=str(payload), TEST_CONFIG=str(config))
    assert result.returncode == 0, result.stderr
    assert config.read_bytes() == before
    assert (work / "derived").read_text().split() == [str(state / "tls" / "ca.crt")] * 2


def test_managed_local_ca_path_is_never_written_through_a_symlinked_site(runtime, tmp_path):
    run, _, _ = runtime
    payload = tmp_path / "ca-payload"; payload.mkdir()
    for name in ("defaults.json", "site.schema.json", "validate.jq", "compile.jq"):
        shutil.copyfile(INSTALLER / name, payload / name)
    (payload / "release.json").write_text(json.dumps(_release()))
    site = _site(); site["tls"]["profile"] = "managed-local-ca"
    target = tmp_path / "real-site.json"; target.write_text(json.dumps(site))
    config = tmp_path / "site.json"; config.symlink_to(target)
    before = target.read_bytes()
    result = run('GSJ_PAYLOAD="$TEST_PAYLOAD"\nCONFIG="$TEST_CONFIG"\nCONTEXT_ARG=""\nload_site\n',
                 TEST_PAYLOAD=str(payload), TEST_CONFIG=str(config))
    assert result.returncode != 0 and "must be a regular file" in result.stderr
    assert config.is_symlink() and target.read_bytes() == before


def test_initialization_deadline_default_covers_the_measured_full_import(tmp_path):
    defaults = json.loads((INSTALLER / "defaults.json").read_text())
    assert defaults["deadlines"]["initialization_seconds"] == 86400
    path = tmp_path / "release.json"; path.write_text(json.dumps(_release()))
    compiled = json.loads(subprocess.run(["jq", "--slurpfile", "release", str(path), "-f", str(INSTALLER / "compile.jq")],
                                         input=json.dumps(_site()), text=True, capture_output=True, check=True).stdout)
    assert compiled["corpus"]["deadlineSeconds"] == 86400
    assert compiled["startup"]["progressDeadlineSeconds"] > 86400 + defaults["deadlines"]["dependencies_seconds"]


def test_success_summary_reports_identity_status_and_redacted_settings(runtime):
    run, _, work = runtime
    payload = work / "payload"; payload.mkdir()
    release = _release()
    release.update(core={"tag": "v4.9.2-deployment", "commit": "c" * 40},
                   model={"model": "Snowflake/snowflake-arctic-embed-m-v2.0", "revision": "d" * 40, "manifest_sha256": "e" * 64,
                          "dimensions": 768, "distance": "cosine", "encoding": "synthetic-encoding-v1"})
    release["corpus"].update(fingerprint="f" * 64, rows=33979, chunks=1141170)
    (payload / "release.json").write_text(json.dumps(release))
    (payload / "chart.tgz").write_bytes(b"synthetic chart")
    site = _site()
    site["operator"]["password_file"] = "/secure/operator-password"
    site["llm"]["credential"]["file"] = "/secure/llm-key"
    site["backup"]["passphrase_file"] = "/secure/backup-passphrase"
    (work / "site.json").write_text(json.dumps(site))
    (work / "verification.json").write_text(json.dumps({"status": "passed", "checks": [
        {"name": "mcp-tools-corpus-schema", "status": "passed"}, {"name": "operator-login", "status": "passed"}]}))
    (work / "public-check.json").write_text(json.dumps({"name": "public-https", "status": "passed"}))
    (work / "network-check.json").write_text(json.dumps({"name": "networkpolicy-deny-allow", "status": "passed"}))
    result = run('GSJ_PAYLOAD="$TEST_WORK/payload"; OPERATION=aaaaaaaaaaaaaaaaaaaaaaaa; VERSION=v1.2.3\ninstallation_summary\n')
    assert result.returncode == 0, result.stderr
    summary = json.loads((work / "summary.json").read_text())
    assert json.loads(result.stdout) == summary
    assert summary["public_url"] == "https://legal.example" and summary["operator_login"] == "operator"
    assert summary["release"] == {"identity": "synthetic-release", "version": "v1.2.3"}
    assert summary["fingerprints"]["chart_sha256"] == hashlib.sha256(b"synthetic chart").hexdigest()
    assert summary["fingerprints"]["core"]["commit"] == "c" * 40
    assert summary["fingerprints"]["model"]["revision"] == "d" * 40
    assert summary["fingerprints"]["corpus"] == "f" * 64
    assert summary["corpus"] == {"rows": 33979, "vectors": 1141170, "status": "verified"}
    assert summary["verification"] == {"status": "passed", "coverage": "full", "checks_passed": 2, "checks_skipped": 0, "checks": 2,
                                       "skipped": [], "endpoints": {}, "public_https": "passed", "networkpolicy": "passed"}
    assert summary["settings"]["operator"]["password_file"] == "(protected file)"
    assert summary["settings"]["llm"]["credential"] == {"file": "(protected file)", "secret": ""}
    assert summary["settings"]["llm"]["base_url"] == "https://llm.example/v1"
    assert "/secure/" not in result.stdout + result.stderr
    assert summary["installed_record"] == str(work / "installed.json")
    assert summary["verification_report"] == str(work / "verification.json")
    assert "Summary: " + str(work / "summary.json") in result.stderr


@pytest.mark.parametrize("url,refused", [
    ("http://proxy.example:3128", False), ("http://[::1]:3128", False), ("", False),
    ("proxy.example:3128", False),
    ("http://user:pass@proxy.example:3128", True), ("https://user@proxy.example", True),
    ("user:pass@proxy.example:3128", True), ("http://user:pa/ss@proxy.example:3128", True),
    ("http://proxy.example:3128/path@x", True)])
def test_proxy_file_refuses_credentials_in_proxy_urls(runtime, tmp_path, url, refused):
    """Proxy credentials are scrubbed from the agent runner's environment. This
    is the site-input half: the runner strips a proxy URL's user:password@ from
    pi's env, so an authenticating proxy could never serve the model endpoint —
    refuse it where the operator can read the reason, not as a 407 in every
    turn. ANY `@` is refused: the scheme-less `user:pass@host:port` curl and
    urllib honour has no `://` for a scheme-anchored test to find, and a proxy
    URL has no legitimate `@` elsewhere."""
    run, _, _ = runtime
    proxy = tmp_path / "proxy.json"
    proxy.write_text(json.dumps({"HTTP_PROXY": url, "HTTPS_PROXY": url, "NO_PROXY": "localhost"}))
    result = run(f'proxy_file_check "{proxy}"\n')
    if refused:
        assert result.returncode != 0 and "must not carry credentials" in result.stderr, result.stderr
    else:
        assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("credentialed", [True, False])
def test_secret_inputs_refuses_a_credentialed_proxy_file_before_any_secret(runtime, tmp_path, credentialed):
    """The same rule, the WIRING (found by auditing it): the check above is
    reachable from the real secret_inputs — a site whose trust.proxy_file
    carries user:password@ (here the scheme-less shape a scheme-anchored test
    admits) is refused with the named reason before the proxy Secret is
    compared or created. The credential-free control takes the same path to
    its Secret, so the refusal is the check's, not a stub's."""
    run, _, work = runtime
    proxy = tmp_path / "proxy.json"
    url = "user:s3cret@proxy.example:3128" if credentialed else "http://proxy.example:3128"
    proxy.write_text(json.dumps({"HTTP_PROXY": url, "HTTPS_PROXY": url, "NO_PROXY": "localhost"}))
    proxy.chmod(0o600)
    site = _site(); site["trust"]["proxy_file"] = str(proxy)
    (work / "site.json").write_text(json.dumps(site))
    result = run('''assert_owner() { :; }; secret_file() { :; }; OP_PASSWORD=unused
k() { if [[ $1 == create ]]; then cat >> "$TEST_WORK/k-created"; fi; }
secret_inputs
''')
    if credentialed:
        assert result.returncode != 0
        assert "proxy_file URLs must not carry credentials" in result.stderr, result.stderr
        assert "s3cret" not in result.stdout + result.stderr
        assert not (work / "proxy.json").exists() and not (work / "k-created").exists()
    else:
        assert result.returncode == 0, result.stderr
        created = json.loads((work / "k-created").read_text())
        assert created["metadata"]["name"] == "synthetic-release-proxy" and created["stringData"]["HTTP_PROXY"] == url
        assert "localhost" in created["stringData"]["NO_PROXY"].split(",")


# network_verify had no test at all: one suite stubs it to a no-op, another
# writes a fake passed record. It proved the deny by requiring the blocked
# request to take >= 4 seconds, i.e. to HANG - which only a DROP based CNI
# does. On a reference k3s cluster, enforcement goes through kube-router, which
# REJECTs, so a correctly enforced policy failed the check in 0 ms and took the
# whole install down at `verifying`. What the check must assert is REACHABILITY.
def _network_cluster(state, *, deny_code, deny_delay=0.0):
    """A cluster where Forgejo may reach the door and must not reach Chroma."""
    def pod(name, component):
        return {"kind": "Pod", "metadata": {"name": name, "labels": {
            "app.kubernetes.io/instance": "synthetic-release",
            "app.kubernetes.io/component": component}},
            "status": {"phase": "Running"}}
    s = json.loads(state.read_text())
    s["resources"] = {"Pod/forgejo-0": pod("forgejo-0", "forgejo"),
                      "Pod/gsj-0": pod("gsj-0", "gsj")}
    # Keyed on the distinctive flag, not the address: the denied wget and the
    # PERMITTED control both target the same heartbeat path.
    s["exec_rules"] = [
        {"match": "8780/readyz", "code": 0, "stdout": json.dumps({"status": "ok"})},
        {"match": "-O /dev/null", "code": deny_code, "delay": deny_delay},
    ]
    state.write_text(json.dumps(s))


def test_networkpolicy_deny_passes_when_the_cni_rejects_immediately(runtime):
    """The kube-router case: the policy IS enforced, and the block is
    instantaneous."""
    run, state, work = runtime
    _network_cluster(state, deny_code=1, deny_delay=0.0)
    result = run("network_verify\n")
    assert result.returncode == 0, result.stderr
    record = json.loads((work / "network-check.json").read_text())
    assert record["name"] == "networkpolicy-deny-allow" and record["status"] == "passed"


def test_networkpolicy_deny_passes_when_the_cni_drops_and_the_request_hangs(runtime):
    """The Calico/kindnet case must keep passing: a hang is also a block."""
    run, state, work = runtime
    _network_cluster(state, deny_code=1, deny_delay=4.5)
    result = run("network_verify\n")
    assert result.returncode == 0, result.stderr
    assert json.loads((work / "network-check.json").read_text())["status"] == "passed"


def test_networkpolicy_check_is_red_when_the_denied_path_is_reachable(runtime):
    """The regression guard: an absent or ineffective policy must still fail."""
    run, state, work = runtime
    _network_cluster(state, deny_code=0, deny_delay=0.0)
    result = run("network_verify\n")
    assert result.returncode != 0
    assert "not enforced" in result.stderr, result.stderr
    assert not (work / "network-check.json").exists()


def test_every_pipeline_that_applies_stages_the_declared_sidecar_before_it_waits():
    """With the vector sidecar DECLARED, an initializer that finds none refuses
    by name instead of embedding — so every pipeline that can (re)start it must
    stage before it waits, not only `install`. Pinned on the runtime text: a
    resume, repair, restore re-apply or credential/TLS repair that applied Helm
    without staging would strand a declared site in a refusal no verb re-stages
    out of. Staging is a no-op for an undeclared site."""
    text = (INSTALLER / "runtime.sh").read_text()
    pipelines = [line for line in text.splitlines()
                 if re.search(r"\bhelm_apply;", line) and "wait_application" in line and not line.lstrip().startswith("#")]
    assert len(pipelines) >= 8, pipelines
    for line in pipelines:
        assert re.search(r"helm_apply; stage_vectors; wait_application", line), line
    assert re.search(r"^\s*initializing\)\s*stage_vectors; wait_application;;", text, re.M)
    assert re.search(r"helm_application_validate; stage_vectors; wait_application;;", text)
    # and the refusal code reaches the operator by name in every list that reads it
    assert text.count("released-vectors-missing") >= 3


# ---- an install without a model endpoint (the degraded install) ----

def _compile(site, tmp_path):
    path = tmp_path / "release.json"; path.write_text(json.dumps(_release()))
    result = subprocess.run(["jq", "--slurpfile", "release", str(path), "-f", str(INSTALLER / "compile.jq")],
                            input=json.dumps(site), capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_an_empty_llm_and_an_empty_ocr_validate_and_compile_to_a_declared_absence(tmp_path):
    """The operator may leave both endpoints out: the site validates, the
    chart gets an EMPTY model ref declared absent (`llm.absent`), and an
    empty `ocr.url` passes through. What the product cannot do until they are
    set is the guide's business; the installer completes the install."""
    site = _site()
    site["llm"].update(base_url="", model="")
    site["ocr"]["url"] = ""
    checked = _validate(site)
    assert checked.returncode == 0, checked.stderr
    compiled = _compile(json.loads(checked.stdout), tmp_path)
    assert compiled["llm"]["model"] == "" and compiled["llm"]["absent"] is True
    assert compiled["ocr"]["url"] == "" and compiled["ocr"]["model"] == "glm-ocr"
    # a configured LLM is what it was, and is not declared absent
    compiled = _compile(json.loads(_validate(_site()).stdout), tmp_path)
    assert compiled["llm"]["model"] == "openai@https://llm.example/v1#synthetic-model" and "absent" not in compiled["llm"]   # the key exists only to declare an absence


@pytest.mark.parametrize("change,message", [
    (lambda s: s["llm"].update(base_url=""), "llm: base_url and model are set together"),
    (lambda s: s["llm"].update(model=""), "llm: base_url and model are set together"),
    (lambda s: (s["llm"].update(base_url="", model=""), s["llm"]["credential"].update(file="credentials/llm-key")), "llm: a credential or allowed origins without base_url"),
    (lambda s: (s["llm"].update(base_url="", model=""), s["llm"].update(allowed_origins=["https://llm.example"])), "llm: a credential or allowed origins without base_url"),
    (lambda s: (s["ocr"].update(url=""), s["ocr"]["credential"].update(file="credentials/ocr-key")), "ocr: a credential without url"),
    (lambda s: s["ocr"].update(url="https://ocr.example"), "ocr.url: invalid format"),          # a bare host is still not a route
    (lambda s: s["llm"].update(base_url="ftp://llm.example/v1"), "llm.base_url: invalid format"),
])
def test_half_an_endpoint_or_a_credential_without_an_address_is_refused(change, message):
    site = _site()
    change(site)
    checked = _validate(site)
    assert checked.returncode != 0 and message in checked.stderr, checked.stderr


# ---- the endpoint preflight: advisory, from this host, in the first minute ----

FAKE_ENDPOINT_CURL = '''#!/usr/bin/env python3
"""A curl that answers the endpoint preflight per URL and records every argv."""
import json, os, pathlib, sys
a = sys.argv[1:]
log = pathlib.Path(os.environ["TEST_CURL_LOG"]); log.write_text(log.read_text() + json.dumps(a) + "\\n" if log.exists() else json.dumps(a) + "\\n")
url = next(v for v in a if v.startswith("http"))
out = a[a.index("-o") + 1]
answers = json.loads(os.environ["TEST_CURL_ANSWERS"])
answer = answers[url]
if isinstance(answer, int):            # a curl exit code: nothing answered
    sys.exit(answer)
code, body = answer
pathlib.Path(out).write_text(body)
sys.stdout.write(str(code))
'''


def _preflight(runtime, site, answers):
    run, _, work = runtime
    (work / "site.json").write_text(json.dumps(site))
    bindir = work.parent / "bin"
    (bindir / "curl").write_text(FAKE_ENDPOINT_CURL); (bindir / "curl").chmod(0o755)
    log = work / "curl-log"
    result = run("endpoint_preflight\n", TEST_CURL_LOG=str(log), TEST_CURL_ANSWERS=json.dumps(answers))
    calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
    record = json.loads((work / "endpoint-preflight.json").read_text())
    return result, calls, record


def test_endpoint_preflight_reports_absent_endpoints_without_a_request_and_never_refuses(runtime):
    site = _site(); site["llm"].update(base_url="", model=""); site["ocr"]["url"] = ""
    result, calls, record = _preflight(runtime, site, {})
    assert result.returncode == 0 and calls == []
    assert record == {"format": "gsj.endpoint-preflight/1", "probed_from": record["probed_from"], "llm": "absent", "ocr": "absent"}
    assert "LLM endpoint: none in the site file" in result.stderr and "skips agent-turn-note-history and generated-document" in result.stderr
    assert "OCR endpoint: none in the site file" in result.stderr and "skips scanned-ingest-search" in result.stderr
    assert "the agent cannot answer until an endpoint is set" in result.stderr and "scanned pages are not read" in result.stderr


@pytest.mark.parametrize("llm_answer,llm_state,ocr_answer,ocr_state", [
    ([200, json.dumps({"data": [{"id": "synthetic-model"}]})], "working",
     [200, json.dumps({"choices": [{"message": {"content": "AKTE  58203"}}]})], "working"),
    (7, "unreachable", 7, "unreachable"),
    ([401, "{}"], "refused (HTTP 401)", [400, json.dumps({"error": "not a multimodal model"})], "refused (HTTP 400)"),
    ([200, json.dumps({"data": [{"id": "another-model"}]})], "answers, but does not list llm.model",
     [200, json.dumps({"choices": [{"message": {"content": "An essay about text recognition."}}]})], "not vision-capable (answered, but did not read the image)"),
    ([200, json.dumps({"data": [{"id": "synthetic-model"}]})], "working", 28, "no answer within 90 s"),
    ([200, json.dumps({"data": [{"id": "synthetic-model"}]})], "working", [200, json.dumps({"detail": "sign in"})], "answers, but not as a chat-completions route"),
])
def test_endpoint_preflight_probes_a_configured_endpoint_as_the_application_would_and_records_the_verdict(runtime, tmp_path, llm_answer, llm_state, ocr_answer, ocr_state):
    site = _site()
    key = tmp_path / "llm-key"; key.write_text("SYNTHETIC-LLM-KEY-NEVER-ON-A-COMMAND-LINE\n"); key.chmod(0o600)
    site["llm"]["credential"]["file"] = str(key)
    result, calls, record = _preflight(runtime, site, {"https://llm.example/v1/models": llm_answer,
                                                         "https://ocr.example/v1/chat/completions": ocr_answer})
    assert result.returncode == 0, result.stderr                                        # advisory: never a refusal
    assert record["llm"] == llm_state and record["ocr"] == ocr_state
    llm_call, ocr_call = calls
    assert "https://llm.example/v1/models" in llm_call and "--max-time" in llm_call
    header = llm_call[llm_call.index("--header") + 1]
    assert header.startswith("@") and "SYNTHETIC-LLM-KEY" not in json.dumps(calls)     # the key rides in a file, never in argv
    assert "--header" not in ocr_call                                                   # the OCR endpoint has no credential here
    request = json.loads(Path(ocr_call[ocr_call.index("-d") + 1][1:]).read_text())
    assert request["model"] == "glm-ocr" and request["max_tokens"] == 2048
    assert request["messages"][0]["content"][0]["type"] == "image_url" and request["messages"][0]["content"][1] == {"type": "text", "text": "Text Recognition:"}
    assert not (tmp_path / "work/endpoint-llm.header").exists()                          # the header file is removed
    if llm_state == "working": assert "answers from this host and lists synthetic-model" in result.stderr
    else: assert "skips agent-turn-note-history and generated-document" in result.stderr
    if ocr_state == "working": assert "read the test image from this host" in result.stderr
    elif ocr_state.startswith("not vision"): assert "would store whatever this endpoint answers as the text of a scanned page" in result.stderr
    else: assert "skips scanned-ingest-search" in result.stderr


def test_a_partial_verification_is_named_in_the_summary_and_on_screen(runtime):
    run, _, work = runtime
    payload = work / "payload"; payload.mkdir()
    release = _release()
    release.update(core={"tag": "v4.9.2-deployment", "commit": "c" * 40}, model={"model": "m", "revision": "d" * 40, "manifest_sha256": "e" * 64, "dimensions": 768, "distance": "cosine", "encoding": "x"})
    release["corpus"].update(fingerprint="f" * 64, rows=33979, chunks=1141170)
    (payload / "release.json").write_text(json.dumps(release)); (payload / "chart.tgz").write_bytes(b"synthetic chart")
    (work / "verification.json").write_text(json.dumps({"status": "passed", "coverage": "partial", "endpoints": {"llm": "unreachable", "ocr": "absent"}, "checks": [
        {"name": "operator-login", "status": "passed"}, {"name": "scanned-ingest-search", "status": "skipped", "reason": "ocr-absent"},
        {"name": "mcp-tools-corpus-schema", "status": "passed"}, {"name": "agent-turn-note-history", "status": "skipped", "reason": "llm-unreachable"},
        {"name": "generated-document", "status": "skipped", "reason": "llm-unreachable"}]}))
    (work / "public-check.json").write_text(json.dumps({"name": "public-https", "status": "passed"}))
    (work / "network-check.json").write_text(json.dumps({"name": "networkpolicy-deny-allow", "status": "passed"}))
    result = run('GSJ_PAYLOAD="$TEST_WORK/payload"; OPERATION=aaaaaaaaaaaaaaaaaaaaaaaa; VERSION=v1.2.3\ninstallation_summary\n')
    assert result.returncode == 0, result.stderr
    summary = json.loads((work / "summary.json").read_text())
    assert summary["status"] == "complete"                                               # the INSTALL is complete; the verification is what is partial
    assert summary["verification"] == {"status": "passed", "coverage": "partial", "checks_passed": 2, "checks_skipped": 3, "checks": 5,
                                       "skipped": [{"name": "scanned-ingest-search", "reason": "ocr-absent"},
                                                   {"name": "agent-turn-note-history", "reason": "llm-unreachable"},
                                                   {"name": "generated-document", "reason": "llm-unreachable"}],
                                       "endpoints": {"llm": "unreachable", "ocr": "absent"}, "public_https": "passed", "networkpolicy": "passed"}
    closing = [line for line in result.stderr.splitlines() if "verification PARTIAL" in line]
    assert len(closing) == 1 and "Complete GSJ installation verified" not in result.stderr
    assert "2 of 5 application checks ran and passed; 3 skipped: scanned-ingest-search (ocr-absent), agent-turn-note-history (llm-unreachable), generated-document (llm-unreachable)" in closing[0]
    # per reason: the LLM is configured and did not answer; the OCR endpoint is absent
    assert "Until the LLM endpoint at llm.base_url answers from inside the cluster, the agent cannot answer: it is configured, but it did not answer the acceptance probe" in closing[0]
    assert "Until an OCR endpoint is set, scanned pages are not read: set ocr.url and ocr.model in the site file. Then run install again with the site file" in closing[0]
    assert closing[0].endswith("Summary: " + str(work / "summary.json"))
    # only the OCR endpoint missing: the advice names that endpoint alone
    (work / "verification.json").write_text(json.dumps({"status": "passed", "endpoints": {"llm": "working", "ocr": "refused"}, "ocr_http_status": 400, "checks": [
        {"name": "operator-login", "status": "passed"}, {"name": "scanned-ingest-search", "status": "skipped", "reason": "ocr-refused"}, {"name": "agent-turn-note-history", "status": "passed"}]}))
    result = run('GSJ_PAYLOAD="$TEST_WORK/payload"; OPERATION=aaaaaaaaaaaaaaaaaaaaaaaa; VERSION=v1.2.3\ninstallation_summary\n')
    closing = [line for line in result.stderr.splitlines() if "verification PARTIAL" in line]
    assert len(closing) == 1 and "2 of 3 application checks ran and passed; 1 skipped: scanned-ingest-search (ocr-refused)" in closing[0]
    assert "Until the OCR endpoint at ocr.url accepts the recognition request, scanned pages are not read: it answered HTTP 400 to the acceptance probe, so check ocr.model and its credential. Then run install again" in closing[0]
    assert "Einstellungen" not in closing[0] and "agent cannot answer" not in closing[0]
    # a full verification (an older verifier's report carries no coverage field at all) keeps the closing line it had
    (work / "verification.json").write_text(json.dumps({"status": "passed", "checks": [{"name": "operator-login", "status": "passed"}]}))
    result = run('GSJ_PAYLOAD="$TEST_WORK/payload"; OPERATION=aaaaaaaaaaaaaaaaaaaaaaaa; VERSION=v1.2.3\ninstallation_summary\n')
    summary = json.loads((work / "summary.json").read_text())
    assert summary["verification"]["coverage"] == "full" and summary["verification"]["skipped"] == [] and summary["verification"]["endpoints"] == {}
    assert "Complete GSJ installation verified: v1.2.3 at https://legal.example" in result.stderr and "PARTIAL" not in result.stderr


def _partial_summary_run(runtime, endpoints, checks, extra=None):
    run, _, work = runtime
    payload = work / "payload"; payload.mkdir(exist_ok=True)
    release = _release()
    release.update(core={"tag": "v4.9.2-deployment", "commit": "c" * 40}, model={"model": "m", "revision": "d" * 40, "manifest_sha256": "e" * 64, "dimensions": 768, "distance": "cosine", "encoding": "x"})
    release["corpus"].update(fingerprint="f" * 64, rows=33979, chunks=1141170)
    (payload / "release.json").write_text(json.dumps(release)); (payload / "chart.tgz").write_bytes(b"synthetic chart")
    report = {"status": "passed", "coverage": "partial", "endpoints": endpoints, "checks": checks}
    report.update(extra or {})
    (work / "verification.json").write_text(json.dumps(report))
    (work / "public-check.json").write_text(json.dumps({"name": "public-https", "status": "passed"}))
    (work / "network-check.json").write_text(json.dumps({"name": "networkpolicy-deny-allow", "status": "passed"}))
    result = run('GSJ_PAYLOAD="$TEST_WORK/payload"; OPERATION=aaaaaaaaaaaaaaaaaaaaaaaa; VERSION=v1.2.3\ninstallation_summary\n')
    assert result.returncode == 0, result.stderr
    closing = [line for line in result.stderr.splitlines() if "verification PARTIAL" in line]
    assert len(closing) == 1
    return closing[0], json.loads((work / "summary.json").read_text())


def test_the_partial_closing_line_states_what_the_probe_established_per_reason(runtime):
    """The misattribution pass (instance 4 carried further): the
    closing line used to end every partial verification with `Until … is set …
    Set llm.base_url … ocr.url …` — advice to SET an endpoint that IS set and
    merely did not answer, refused the request, or could not read an image.
    The operator would edit a site value that was right. Each reason word the
    probe recorded has its own established fact; the line says that one."""
    # an LLM that is set but did not answer, and an OCR endpoint that answered without reading the page
    line, summary = _partial_summary_run(runtime, {"llm": "unreachable", "ocr": "not-vision-capable"}, [
        {"name": "operator-login", "status": "passed"},
        {"name": "scanned-ingest-search", "status": "skipped", "reason": "ocr-not-vision-capable"},
        {"name": "agent-turn-note-history", "status": "skipped", "reason": "llm-unreachable"},
        {"name": "generated-document", "status": "skipped", "reason": "llm-unreachable"}])
    assert "did not answer the acceptance probe" in line and "reachable from the Pods" in line
    assert "did not read the test page" in line and "vision-capable" in line
    assert "Until the endpoints are set" not in line and "Set ocr.url" not in line and "Einstellungen" not in line
    # an OCR endpoint that refused the request: the status it answered, never "set it"
    line, summary = _partial_summary_run(runtime, {"llm": "working", "ocr": "refused"}, [
        {"name": "operator-login", "status": "passed"},
        {"name": "scanned-ingest-search", "status": "skipped", "reason": "ocr-refused"},
        {"name": "agent-turn-note-history", "status": "passed"}], extra={"ocr_http_status": 400})
    assert "answered HTTP 400" in line and "ocr.model" in line and "credential" in line
    assert "is set" not in line and "agent cannot answer" not in line
    assert summary["verification"]["ocr_http_status"] == 400
    # both absent: setting them IS the established fact
    line, summary = _partial_summary_run(runtime, {"llm": "absent", "ocr": "absent"}, [
        {"name": "operator-login", "status": "passed"},
        {"name": "scanned-ingest-search", "status": "skipped", "reason": "ocr-absent"},
        {"name": "agent-turn-note-history", "status": "skipped", "reason": "llm-absent"},
        {"name": "generated-document", "status": "skipped", "reason": "llm-absent"}])
    assert "Until an LLM endpoint is set" in line and "Einstellungen" in line and "llm.base_url and llm.model" in line
    assert "Until an OCR endpoint is set" in line and "ocr.url and ocr.model" in line
    assert "ocr_http_status" not in summary["verification"]


def test_a_refused_site_value_is_a_named_refusal_that_states_the_expected_format(runtime, tmp_path):
    """The misattribution pass: a site value the schema refuses surfaced as jq's own error
    line (`jq: error (at <stdin>:170): site.operator.login: invalid format`) --
    not a `GSJ:` refusal, and without the format that was expected, so the
    operator learned only that a value was wrong, not how. Measured on the
    published release with an operator login carrying an underscore."""
    run, _, _ = runtime
    payload = tmp_path / "load-payload"
    payload.mkdir()
    for name in ("defaults.json", "site.schema.json", "validate.jq", "compile.jq"):
        shutil.copyfile(INSTALLER / name, payload / name)
    (payload / "release.json").write_text(json.dumps(_release()))
    site = _site()
    site["operator"]["login"] = "gsj_admin"
    config = tmp_path / "site.json"
    config.write_text(json.dumps(site))
    for name in ("operator-password", "backup-passphrase"):
        path = tmp_path / name
        path.write_text("secret")
        path.chmod(0o600)
    result = run(f'GSJ_PAYLOAD="{payload}"; CONFIG="{config}"; CONTEXT_ARG=""; load_site\n')
    assert result.returncode == 1
    lines = [l for l in result.stderr.splitlines() if l.startswith("GSJ:")]
    assert len(lines) == 1, result.stderr
    assert "site.operator.login: invalid format" in lines[0]
    assert "expected" in lines[0] and "letters, digits and dashes" in lines[0]
    assert "jq: error" not in result.stderr
