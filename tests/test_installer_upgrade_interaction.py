"""Interactive upgrade delegates site prompts to the explicitly selected release."""
import json

import pytest

from tests.test_installer import runtime, _release


@pytest.mark.parametrize("selected", ["1.2.3", "1.2.4"])
def test_only_the_selected_release_runs_site_wizard(runtime, selected):
    run, _, work = runtime
    payload = work / "payload"
    payload.mkdir()
    (payload / "release.json").write_text(json.dumps({"version": "1.2.3"}))
    result = run('''GSJ_PAYLOAD="$TEST_WORK/payload"; CONFIG="$SITE"
COMMAND=upgrade; TO=''; INTERACTIVE=true; NON_INTERACTIVE=false
ask() { printf '%s' "$SELECTED"; }
wizard() { printf 'site-wizard\n' >> "$TEST_WORK/wizard-called"; }
configure_interaction
printf '%s\n' "$TO" > "$TEST_WORK/selected"
''', SELECTED=selected)
    assert result.returncode == 0, result.stderr
    assert (work / "selected").read_text().strip() == selected
    assert not (work / "wizard-called").exists()


def test_verified_target_runs_wizard_without_prompting_or_reacquiring(runtime):
    run, _, work = runtime
    result = run('''COMMAND=upgrade; TO=''; EXPECTED_VERSION=1.2.3
INTERACTIVE=true; NON_INTERACTIVE=false
ask() { exit 90; }
wizard() { printf 'target-wizard\n' > "$TEST_WORK/wizard-called"; }
configure_interaction
''')
    assert result.returncode == 0, result.stderr
    assert (work / "wizard-called").read_text().strip() == "target-wizard"


@pytest.mark.parametrize("command", ["upgrade", "repair"])
@pytest.mark.parametrize("selected", ["1.2.3", "1.2.4"])
def test_main_always_acquires_explicit_version_before_cluster_mutation(runtime, command, selected):
    run, _, work = runtime
    helpers = work / "payload/helpers"
    helpers.mkdir(parents=True)
    for name in ("verification-cleanup.sh", "startup-recovery.sh"):
        (helpers / name).write_text("")
    result = run('''GSJ_PAYLOAD="$TEST_WORK/payload"; VERSION=1.2.3
bootstrap() { :; }
install_exit_traps() { :; }
load_site() { :; }
inspect_cluster() { printf '{}\n'; }
preflight() { touch "$TEST_WORK/unexpected-preflight"; exit 91; }
acquire_target() { printf '%s\n' "$1" > "$TEST_WORK/acquired"; }
main "$TEST_COMMAND" --to "$SELECTED" --config "$SITE" --non-interactive
''', TEST_COMMAND=command, SELECTED=selected)
    assert result.returncode == 0, result.stderr
    assert (work / "acquired").read_text().strip() == selected
    assert not (work / "unexpected-preflight").exists()


def test_target_version_mismatch_refuses_before_wizard_or_site_access(runtime):
    run, _, work = runtime
    payload = work / "payload"
    (payload / "helpers").mkdir(parents=True)
    (payload / "release.json").write_text('{"version":"1.2.3"}')
    for name in ("verification-cleanup.sh", "startup-recovery.sh"):
        (payload / "helpers" / name).write_text("")
    result = run('''GSJ_PAYLOAD="$TEST_WORK/payload"
bootstrap() { :; }
install_exit_traps() { :; }
configure_interaction() { touch "$TEST_WORK/unexpected-wizard"; }
load_site() { touch "$TEST_WORK/unexpected-site"; }
main upgrade --expected-version 1.2.4 --interactive --config "$SITE"
''')
    assert result.returncode != 0
    assert "different release version" in result.stderr
    assert not (work / "unexpected-wizard").exists()
    assert not (work / "unexpected-site").exists()


def test_target_acquisition_requires_existing_site_before_wizard(runtime):
    run, _, work = runtime
    payload = work / "payload"
    payload.mkdir()
    (payload / "release.json").write_text('{"version":"1.2.3"}')
    result = run('''GSJ_PAYLOAD="$TEST_WORK/payload"; CONFIG="$TEST_WORK/missing-site.json"
COMMAND=upgrade; TO=1.2.4; INTERACTIVE=true; NON_INTERACTIVE=false
wizard() { touch "$TEST_WORK/unexpected-wizard"; }
configure_interaction
''')
    assert result.returncode != 0
    assert not (work / "unexpected-wizard").exists()


@pytest.mark.parametrize("arguments,admitted", [("", False), ("--expected-version 1.2.3", True), ("--to 1.2.3", True)])
def test_noninteractive_upgrade_requires_an_explicit_target(runtime, arguments, admitted):
    run, _, work = runtime
    result = run(f'''bootstrap() {{ touch "$TEST_WORK/bootstrapped"; exit 92; }}
main upgrade {arguments} --config "$SITE" --non-interactive
''')
    if admitted:
        assert result.returncode == 92, result.stderr
    else:
        assert result.returncode != 0
        assert "requires --to VERSION" in result.stderr
    assert (work / "bootstrapped").exists() is admitted


def _compatibility(runtime, fault=None):
    """Run the real compatibility gate against a synthetic completed source."""
    run, kube, work = runtime
    payload = work / "payload"
    payload.mkdir(exist_ok=True)
    release = _release()
    release.update(model={"model": "synthetic-embedding", "dimensions": 8}, supported_sources=[])
    release["corpus"]["fingerprint"] = "b" * 64
    storage = [{"name": "synthetic-release-" + role, "uid": "uid-" + role, "volume": "pv-" + role,
                "storageClass": "local-path", "requested": "20Gi", "capacity": "20Gi"}
               for role in ("chroma", "data", "forgejo")]
    resources = {"PersistentVolumeClaim/" + s["name"]: {
        "kind": "PersistentVolumeClaim", "metadata": {"name": s["name"], "uid": s["uid"]},
        "spec": {"volumeName": s["volume"], "storageClassName": s["storageClass"],
                 "resources": {"requests": {"storage": s["requested"]}}},
        "status": {"capacity": {"storage": s["capacity"]}}} for s in storage}
    cluster = {"lease": None, "calls": [], "resources": resources}
    site = json.loads((work / "site.json").read_text())
    installed = {"format": "gsj.installed/1", "status": "complete", "manifest": json.loads(json.dumps(release)),
                 "site": json.loads(json.dumps(site)), "storage": storage, "namespace_uid": "target-namespace-uid"}
    if fault == "target":
        installed["site"]["operator"]["login"] = "previous-operator"
    elif fault == "model":
        installed["manifest"]["model"]["model"] = "previous-embedding"
    elif fault == "undeclared":
        installed["manifest"]["identity"] = "older-release"
    elif fault == "migration":
        installed["manifest"]["identity"] = "older-release"
        release["supported_sources"] = ["older-release"]
        installed["site"]["schema_version"] = "gsj.site/0"
    elif fault == "storage":
        resources["PersistentVolumeClaim/synthetic-release-data"]["metadata"]["uid"] = "replaced"
    elif fault == "namespace":
        cluster["namespace_uid"] = "recreated-namespace"
    elif fault in ("corpus", "corpus-allowed"):
        installed["manifest"]["corpus"]["fingerprint"] = "c" * 64
        if fault == "corpus-allowed":
            site["corpus"]["allow_update"] = True
            (work / "site.json").write_text(json.dumps(site))
    (payload / "release.json").write_text(json.dumps(release))
    (work / "values.pending.json").write_text(json.dumps(
        {"storage": {role: {"existingClaim": ""} for role in ("data", "forgejo", "chroma")}}))
    (work / "installed.json").write_text(json.dumps(installed))
    kube.write_text(json.dumps(cluster))
    return run('GSJ_PAYLOAD="$TEST_WORK/payload"\ncompatibility selected\n')


@pytest.mark.parametrize("fault", [None, "corpus-allowed"])
def test_compatible_source_passes_the_real_upgrade_gate(runtime, fault):
    result = _compatibility(runtime, fault)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("fault,message", [
    ("target", "upgrade cannot change target, operator or storage identity"),
    ("model", "model change blocked"),
    ("undeclared", "does not declare this source-to-target transition"),
    ("migration", "explicit target migration"),
    ("storage", "persistent storage identity changed"),
    ("namespace", "namespace was recreated"),
    ("corpus", "corpus change requires explicit corpus.allow_update=true"),
])
def test_upgrade_compatibility_refuses_each_unsupported_transition(runtime, fault, message):
    _, kube, _ = runtime
    result = _compatibility(runtime, fault)
    assert result.returncode != 0
    assert message in result.stderr
    assert not any(call[0] in ("create", "replace", "apply", "delete", "scale", "exec")
                   for call in json.loads(kube.read_text())["calls"])
