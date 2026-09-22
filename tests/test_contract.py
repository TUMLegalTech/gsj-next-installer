"""test_contract — the installer ↔ chart contract, pinned against the PINNED
product chart (web-pin.json), never a working tree.

`ops/installer/CONTRACT.md` states the contract in words; this module holds
it: every example site validates, compiles and renders with the pinned chart;
every leaf `compile.jq` emits is a value the chart declares; the objects the
runtime addresses by name are rendered under those names; the init containers
run in the documented order with the termination-message policy the runtime
reads; the initializer receives exactly its settings keys; the verifier's
checks, failure codes and exit codes are what the runtime and the operator
guide expect; and the deadline, controller and released-vectors mappings hold.

Skip-guarded on the pinned Git objects (a public runner has no product) and
on helm and jq, like the product's own chart tests.
"""
import ast
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

import pytest
import yaml

from tests import pinned_web
from tests.pinned_web import needs_web
from tests.test_installer import INSTALLER, ROOT, _release, _site

pytestmark = [needs_web,
              pytest.mark.skipif(shutil.which("helm") is None, reason="helm not installed"),
              pytest.mark.skipif(shutil.which("jq") is None, reason="jq not installed")]

EXAMPLES = sorted((INSTALLER / "examples").glob("*.site.json"))
CORPUS = ["--set", "corpus.enabled=true", "--set", "corpus.manifestSha256=" + "a" * 64,
          "--set", "image.corpus.repository=registry.invalid/decisions-data",
          "--set", "image.corpus.digest=sha256:" + "b" * 64]


def merged(example):
    """defaults.json deep-merged with a partial site, exactly as the runtime does (`jq -s '.[0] * .[1]'`)."""
    out = subprocess.run(["jq", "-s", ".[0] * .[1]", str(INSTALLER / "defaults.json"), str(example)],
                         capture_output=True, text=True, check=True)
    return json.loads(out.stdout)


def validated(site):
    out = subprocess.run(["jq", "--slurpfile", "schema", str(INSTALLER / "site.schema.json"),
                          "-f", str(INSTALLER / "validate.jq")], input=json.dumps(site),
                         capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


def compiled(tmp_path, site, *extra):
    release = tmp_path / "release.json"
    release.write_text(json.dumps(_release()))
    out = subprocess.run(["jq", "--slurpfile", "release", str(release), *extra, "-f", str(INSTALLER / "compile.jq")],
                         input=json.dumps(site), capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


def rendered(tmp_path, values=None, *args, release="gsj"):
    """`helm template` of the PINNED chart; returns the non-empty documents."""
    command = ["helm", "template", release, str(pinned_web.chart())]
    if values is not None:
        path = tmp_path / "values.json"
        path.write_text(json.dumps(values))
        command += ["--values", str(path)]
    else:  # the installer always sets fullnameOverride to the release name (§3 of the contract)
        command += ["--set", "fullnameOverride=" + release, "--set", "operator.password=x",
                    "--set", "llm.model=openai@http://llm.test:8000/v1#test-model"]
    out = subprocess.run(command + list(args), capture_output=True, text=True,
                         env=dict(os.environ, KUBECONFIG=os.devnull))
    assert out.returncode == 0, out.stderr
    return [d for d in yaml.safe_load_all(out.stdout) if d]


def leaves(node, prefix=""):
    if isinstance(node, dict) and node:
        for key, value in node.items():
            yield from leaves(value, f"{prefix}{key}.")
    else:
        yield prefix[:-1]


def containers(doc):
    spec = doc["spec"]["template"]["spec"]
    return (spec.get("initContainers") or []) + (spec.get("containers") or [])


def web_deployment(docs, release="gsj"):
    return next(d for d in docs if d["kind"] == "Deployment" and d["metadata"]["name"] == release + "-web")


# ---- every example site: validate, compile, render ---------------------------

@pytest.mark.parametrize("example", EXAMPLES, ids=[p.name for p in EXAMPLES])
def test_every_example_site_validates_compiles_and_renders_with_the_pinned_chart(tmp_path, example):
    site = validated(merged(example))
    values = compiled(tmp_path, site)
    release = site["target"]["release"]
    docs = rendered(tmp_path, values, release=release)
    kinds = {(d["kind"], d["metadata"]["name"]) for d in docs}
    for kind, name in (("Deployment", f"{release}-web"), ("Deployment", f"{release}-forgejo"), ("Deployment", f"{release}-chroma"),
                       ("Service", f"{release}-web"), ("Service", f"{release}-forgejo"), ("Service", f"{release}-chroma"),
                       ("Job", f"{release}-provision"), ("ConfigMap", f"{release}-scripts"), ("Ingress", f"{release}-web")):
        assert (kind, name) in kinds, f"{example.name}: the chart did not render {kind} {name}"
    web = web_deployment(docs, release)
    assert [c["name"] for c in web["spec"]["template"]["spec"]["initContainers"]] == ["wait-deps", "corpus-copy", "corpus-initialize"]
    assert [c["name"] for c in web["spec"]["template"]["spec"]["containers"]] == ["gsj-web", "gsj-mcp", "agent-runner"]
    # the installer's own Secrets and ConfigMaps are never rendered by the chart
    names = {d["metadata"]["name"] for d in docs}
    for reserved in ("operation", "ready-state", "installed", "trust", "proxy", "llm-key", "ocr-key"):
        assert f"{release}-{reserved}" not in names, f"the chart rendered the installer-owned {release}-{reserved}"
    assert site["operator"]["secret"] not in names, "the chart rendered the operator Secret the installer creates"
    # the existing claims an operator brings replace the chart's own
    claims = {d["metadata"]["name"] for d in docs if d["kind"] == "PersistentVolumeClaim"}
    for volume in ("data", "forgejo", "chroma"):
        own = site["storage"][volume]["existing_claim"]
        assert (f"{release}-{volume}" in claims) == (own == ""), (example.name, volume)
    # registry.base relocates the repository and keeps the digest
    if site["registry"].get("base"):
        for role in ("web", "runner", "mcp", "forgejo", "chroma", "corpus"):
            assert values["image"][role]["repository"].startswith(site["registry"]["base"] + "/")
            assert values["image"][role]["digest"] == "sha256:" + "a" * 64


@pytest.mark.parametrize("example", EXAMPLES, ids=[p.name for p in EXAMPLES])
def test_every_compiled_leaf_is_a_value_the_pinned_chart_declares(tmp_path, example):
    """The inverse of the chart's `test_every_value_has_a_consumer`: the
    installer emits no key the chart does not declare, so a renamed value
    fails here before it silently changes nothing on a cluster."""
    declared = set(leaves(yaml.safe_load(pinned_web.show("chart/values.yaml"))))
    values = compiled(tmp_path, validated(merged(example)))
    emitted = set(leaves(values))
    # maps the chart hands on whole (`toYaml .Values.resources.web`, the
    # placement selector) or declares empty: compare at the map
    maps = {"placement.nodeSelector", "ingress.annotations", "trust", "corpus.resources",
            "resources.web", "resources.mcp", "resources.runner", "resources.forgejo", "resources.chroma"}
    unknown = sorted(leaf for leaf in emitted
                     if leaf not in declared and not any(leaf.startswith(m + ".") or leaf == m for m in maps))
    assert unknown == [], f"compile.jq emits values the pinned chart does not declare: {unknown}"


def test_the_synthetic_site_compiles_to_the_documented_keys(tmp_path):
    values = compiled(tmp_path, _site())
    assert set(values) == {"fullnameOverride", "deployment", "image", "corpus", "startup", "web", "ingress", "networkPolicy",
                           "operator", "agent", "llm", "ocr", "selfhostedKey", "placement", "storage", "resources", "trust", "retention"}
    assert set(values["image"]) == {"gsjNextTag", "web", "runner", "mcp", "forgejo", "chroma", "corpus", "pullSecrets"}
    assert set(values["corpus"]) == {"enabled", "manifestSha256", "deadlineSeconds", "attempts", "repairGeneration",
                                     "allowUpdate", "releasedVectors", "resources"}
    assert values["corpus"]["enabled"] is True and values["retention"]["keepClaims"] is True
    assert values["operator"] == {"login": "operator", "existingSecret": "gsj-operator", "password": "", "autogenPassword": False}
    assert values["startup"] == {"dependencyDeadlineSeconds": _site()["deadlines"]["dependencies_seconds"],
                                 "progressDeadlineSeconds": _site()["deadlines"]["dependencies_seconds"] + _site()["deadlines"]["initialization_seconds"] + 1800,
                                 "modelFailureThreshold": 180}


# ---- the objects and init containers the runtime addresses -------------------

def test_the_pinned_chart_renders_every_object_the_runtime_addresses(tmp_path):
    docs = rendered(tmp_path, None, *CORPUS)
    names = {(d["kind"], d["metadata"]["name"]) for d in docs}
    expected = {("Deployment", "gsj-web"), ("Deployment", "gsj-forgejo"), ("Deployment", "gsj-chroma"),
                ("Service", "gsj-web"), ("Service", "gsj-forgejo"), ("Service", "gsj-chroma"),
                ("Job", "gsj-provision"), ("ConfigMap", "gsj-scripts"),
                ("Secret", "gsj-operator"),
                ("PersistentVolumeClaim", "gsj-data"), ("PersistentVolumeClaim", "gsj-forgejo"), ("PersistentVolumeClaim", "gsj-chroma"),
                ("ServiceAccount", "gsj-provisioner"), ("ServiceAccount", "gsj-pod"),
                ("Role", "gsj-provisioner"), ("Role", "gsj-marker-reader"),
                ("RoleBinding", "gsj-provisioner"), ("RoleBinding", "gsj-marker-reader"),
                ("NetworkPolicy", "gsj-default-deny-ingress"), ("NetworkPolicy", "gsj-gsj-web-ingress"),
                ("NetworkPolicy", "gsj-forgejo-ingress"), ("NetworkPolicy", "gsj-forgejo-egress"), ("NetworkPolicy", "gsj-chroma-ingress"),
                ("Ingress", "gsj-web")}
    missing = expected - names
    assert not missing, f"the pinned chart no longer renders {sorted(missing)}"
    job = next(d for d in docs if d["kind"] == "Job")
    assert set(job["metadata"]["annotations"]["helm.sh/hook"].split(",")) >= {"post-install", "post-upgrade", "post-rollback"}
    assert job["metadata"]["annotations"]["helm.sh/hook-delete-policy"] == "before-hook-creation"
    assert [c["name"] for c in containers(job)] == ["plan", "forge-bootstrap", "provision"]
    web = web_deployment(docs)
    assert web["spec"]["template"]["spec"]["enableServiceLinks"] is False
    ports = {d["metadata"]["name"]: d["spec"]["ports"][0]["port"] for d in docs if d["kind"] == "Service"}
    assert ports == {"gsj-web": 8780, "gsj-forgejo": 3000, "gsj-chroma": 8000}


def test_the_init_containers_run_the_documented_programs_with_the_termination_policy_the_runtime_reads(tmp_path):
    web = web_deployment(rendered(tmp_path, None, *CORPUS))
    inits = {c["name"]: c for c in web["spec"]["template"]["spec"]["initContainers"]}
    assert list(inits) == ["wait-deps", "corpus-copy", "corpus-initialize"]
    assert inits["corpus-copy"]["command"] == ["python", "-m", "gsj_deploy.corpus", "copy"]
    assert inits["corpus-copy"]["args"] == ["--destination", "/source", "--manifest-sha256", "a" * 64]
    assert inits["corpus-copy"]["image"] == "registry.invalid/decisions-data@sha256:" + "b" * 64
    assert inits["corpus-initialize"]["command"] == ["python", "-m", "gsj_deploy.initialize", "--settings", "/scripts/initializer.json"]
    for name in ("corpus-copy", "corpus-initialize"):
        c = inits[name]
        assert c.get("terminationMessagePath", "/dev/termination-log") == "/dev/termination-log", name
        assert c.get("terminationMessagePolicy", "File") == "File", name
    # the runtime recognises the initializer by exactly this image and command
    runtime = (INSTALLER / "runtime.sh").read_text()
    assert '.name=="corpus-initialize" and .image==$images.web and .command==["python","-m","gsj_deploy.initialize","--settings","/scripts/initializer.json"]' in runtime
    without = web_deployment(rendered(tmp_path))
    assert [c["name"] for c in without["spec"]["template"]["spec"]["initContainers"]] == ["wait-deps", "migrate"]


def test_the_initializer_receives_exactly_its_settings_keys(tmp_path):
    docs = rendered(tmp_path, None, *CORPUS, "--set", "corpus.releasedVectors=true")
    scripts = next(d for d in docs if d["kind"] == "ConfigMap" and d["metadata"]["name"] == "gsj-scripts")
    settings = json.loads(scripts["data"]["initializer.json"])
    source = pinned_web.show("gsj_deploy/initialize.py").decode()
    literal = re.search(r"required = (\{[^}]+\})", source)
    assert literal, "the pinned initializer no longer declares its required settings as a set literal"
    required = ast.literal_eval(literal.group(1))
    assert set(settings) == required == {"db", "source", "state", "chroma_url", "model_path", "manifest_sha256",
                                         "deadline_seconds", "attempts", "repair_generation", "allow_update", "released_vectors"}
    assert settings["released_vectors"] is True and settings["chroma_url"] == "http://gsj-chroma:8000"
    assert set(scripts["data"]) == {"initializer.json", "wait-deps.py", "provision.py", "forge-bootstrap.sh"}


# ---- the verifier: checks, codes, exits ---------------------------------------

def _assigned_set(source, name):
    tree = ast.parse(source)
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            value = node.value
            if isinstance(value, ast.Call):          # frozenset({...})
                value = value.args[0]
            return set(ast.literal_eval(value))
    raise AssertionError(f"{name} not found")


def test_the_verifier_contract_is_what_the_runtime_and_the_guide_expect():
    source = pinned_web.show("gsj_deploy/verify.py").decode()
    checks = _assigned_set(source, "REQUIRED_CHECKS")
    codes = _assigned_set(source, "FAILURE_CODES")
    assert checks == {"operator-login", "temporary-users", "digital-ingest-search", "scanned-ingest-search", "authorization",
                      "notes-library", "mcp-tools-corpus-schema", "agent-turn-note-history", "logout", "live-sse-signed-webhook",
                      "lawyer-origin-and-hook", "generated-document", "bot-contract-hook", "upload-limit-and-pdf-delivery",
                      "pipeline-index-freshness"}
    assert len(codes) == 29
    guide = (INSTALLER / "OPERATOR.md").read_text()
    assert [c for c in sorted(codes) if f"`{c}`" not in guide] == [], "a failure code the guide's codes table does not list"
    assert [c for c in sorted(checks) if c not in guide] == [], "a required check the guide does not name"
    exits = re.search(r'raise SystemExit\((\{[^}]+\})\.get\(report\["status"\], 1\)\)', source)
    assert exits, "the verifier's exit map moved"
    assert ast.literal_eval(exits.group(1)) == {"passed": 0, "checks-passed-cleanup-pending": 75, "cleanup-pending": 75,
                                                "bot-check-pending": 76, "cleaned-reverify-required": 77, "bot-check-failed": 79}
    assert "raise SystemExit(78)" in source
    runtime = (INSTALLER / "runtime.sh").read_text()
    for code in (75, 76, 77, 78, 79):
        assert re.search(rf"rc (?:==|!=) {code}\b", runtime), f"the runtime never reads verifier exit {code}"


# ---- the mappings the chart and the installer agree on (moved from the product's chart tests) ----

def test_progress_deadline_outlasts_the_dependency_wait_and_the_import(tmp_path):
    """The first rollout holds the dependency wait AND the corpus import. The
    chart's defaults ARE the installer's mapping of the same site deadlines
    (compile.jq: dependency + initialization + 1800 s for pulls and startup
    probes), the import budget is 24 h, and the render refuses a progress
    window that does not exceed the two deadlines together."""
    values = yaml.safe_load(pinned_web.show("chart/values.yaml"))
    startup, corpus = values["startup"], values["corpus"]
    assert corpus["deadlineSeconds"] == 86400
    site = _site()
    site["deadlines"].update(dependencies_seconds=startup["dependencyDeadlineSeconds"],
                             initialization_seconds=corpus["deadlineSeconds"])
    values_out = compiled(tmp_path, site)
    assert values_out["corpus"]["deadlineSeconds"] == corpus["deadlineSeconds"]
    assert values_out["startup"]["progressDeadlineSeconds"] == startup["progressDeadlineSeconds"]
    floor = startup["dependencyDeadlineSeconds"] + corpus["deadlineSeconds"]
    for threshold in (startup["modelFailureThreshold"], values_out["startup"]["modelFailureThreshold"]):
        assert startup["progressDeadlineSeconds"] > floor + threshold * 5
    assert web_deployment(rendered(tmp_path, None, *CORPUS))["spec"]["progressDeadlineSeconds"] == startup["progressDeadlineSeconds"]
    out = subprocess.run(["helm", "template", "gsj", str(pinned_web.chart()), "--set", "fullnameOverride=gsj",
                          "--set", "operator.password=x", "--set", "llm.model=openai@http://llm.test:8000/v1#test-model",
                          *CORPUS, "--set", f"startup.progressDeadlineSeconds={floor}"],
                         capture_output=True, text=True)
    assert out.returncode != 0, "a progress window equal to the two deadlines must not render"
    assert "startup.progressDeadlineSeconds must exceed" in out.stderr, out.stderr


def test_compiled_values_name_the_controller_and_carry_no_inert_key(tmp_path):
    """compile.jq names the controller — its managed Traefik by profile, a
    reused class by the spec.controller the installer passes, else
    ingress-nginx as before — and emits neither nginx annotations (the chart
    derives them) nor the removed remint knob. Each result renders."""
    def site(profile):
        s = _site()
        s["ingress"]["profile"] = profile
        return s
    cases = [(site("managed-traefik"), (), "traefik.io/ingress-controller"),
             (site("reuse"), ("--arg", "ingress_controller", "traefik.io/ingress-controller"), "traefik.io/ingress-controller"),
             (site("reuse"), ("--arg", "ingress_controller", "k8s.io/ingress-nginx"), "k8s.io/ingress-nginx"),
             (site("reuse"), (), "k8s.io/ingress-nginx")]
    for s, extra, controller in cases:
        values = compiled(tmp_path, s, *extra)
        assert values["ingress"]["controller"] == controller
        assert "annotations" not in values["ingress"]
        assert "provisioning" not in values
        path = tmp_path / "values.json"
        path.write_text(json.dumps(values))
        out = subprocess.run(["helm", "template", "gsj", str(pinned_web.chart()), "--values", str(path),
                              "--show-only", "templates/ingress.yaml"], capture_output=True, text=True)
        assert out.returncode == 0, out.stderr
        annotations = next(yaml.safe_load_all(out.stdout))["metadata"].get("annotations") or {}
        assert bool(annotations) == (controller == "k8s.io/ingress-nginx"), controller


def test_the_site_declares_released_vectors_to_the_initializer(tmp_path):
    """compile.jq turns a configured corpus.vectors_url OR vectors_path into
    corpus.releasedVectors=true — the declaration the initializer waits on
    instead of inferring the sidecar's arrival from blocks that may land
    after its first look — and the chart writes it into the initializer's
    settings."""
    site = _site()
    site["corpus"].update(vectors_url="", vectors_path="", vectors_sha256="")
    assert compiled(tmp_path, site)["corpus"]["releasedVectors"] is False
    site["corpus"].update(vectors_url="https://127.0.0.1:8443/vectors.json", vectors_sha256="a" * 64)
    assert compiled(tmp_path, site)["corpus"]["releasedVectors"] is True
    site["corpus"].update(vectors_url="", vectors_path="/srv/gsj-vectors/vectors.json")
    assert compiled(tmp_path, site)["corpus"]["releasedVectors"] is True
    for flag in ("true", "false"):
        docs = rendered(tmp_path, None, *CORPUS, "--set", f"corpus.releasedVectors={flag}")
        scripts = next(d for d in docs if d["kind"] == "ConfigMap" and d["metadata"]["name"] == "gsj-scripts")
        assert json.loads(scripts["data"]["initializer.json"])["released_vectors"] is (flag == "true")


def test_the_contract_document_names_this_module_and_the_pin_test():
    text = (INSTALLER / "CONTRACT.md").read_text()
    assert "tests/test_contract.py" in text and "tests/test_web_pin.py" in text
    assert "chart/INSTALLER-CONTRACT.md" in text and "ops/installer/CONTRACT.md" in text
