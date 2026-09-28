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


@pytest.mark.parametrize("command", ["upgrade", "repair"])
@pytest.mark.parametrize("flags,handed", [
    ("", None),
    ("--fetch-tools=kubectl", "--fetch-tools=kubectl"),
    ("--fetch-tools=helm,jq", "--fetch-tools=jq,helm"),
    ("--fetch-tools", "--fetch-tools"),
    ("--fetch-tools=helm --fetch-tools", "--fetch-tools"),
])
def test_the_verified_child_fetches_the_clients_this_run_fetched(runtime, command, flags, handed):
    """Every --to hands off to the target's own installer before preflight, so
    the child alone runs the checks a fetched client answers to -- for an
    upgrade child, among them the refusal of a fetched kubectl more than one
    minor from the server; a repair child makes no such check, and takes the
    set so that it runs on the clients this run fetched, as fetched. The
    child's argv carried no --fetch-tools: its fetched set was empty while the
    parent's fetched kubectl sat first on the PATH it inherited, and an
    upgrade child only warned about that skew. The child now receives the set
    this run fetched (the archives are cached by checksum, so nothing
    downloads twice, and it verifies them itself); all three stay the bare
    flag, the one form a target that predates the per-client form parses.
    Nothing fetched, no flag."""
    run, _, work = runtime
    payload = work / "payload"
    (payload / "helpers").mkdir(parents=True)
    (payload / "release.json").write_text(json.dumps({"version": "1.2.3", "release_base_url": "https://releases.example"}))
    for name in ("verification-cleanup.sh", "startup-recovery.sh"):
        (payload / "helpers" / name).write_text("")
    operation = "--operation synthetic-operation" if command == "repair" else ""
    result = run(f'''GSJ_PAYLOAD="$TEST_WORK/payload"
bootstrap() {{ :; }}
install_exit_traps() {{ :; }}
load_site() {{ :; }}
inspect_cluster() {{ printf '{{}}\\n'; }}
preflight() {{ touch "$TEST_WORK/unexpected-preflight"; exit 91; }}
download_curl() {{ [[ ${{*: -1}} != *.json.partial ]] || jq -n '{{version:"1.2.4",installer:{{name:"gsj-install.sh",sha256:"synthetic"}}}}' > "${{*: -1}}"; : >> "${{*: -1}}"; }}
openssl() {{ :; }}; fetch() {{ :; }}; verify_target() {{ :; }}
bash() {{ shift; printf '%s\\n' "$@" > "$TEST_WORK/child-argv"; }}
main {command} --to 1.2.4 {operation} --config "$SITE" --non-interactive {flags}
''')
    assert result.returncode == 0, result.stderr
    assert not (work / "unexpected-preflight").exists()
    argv = (work / "child-argv").read_text().splitlines()
    expected = [command, "--config", str(work / "site.json"), "--expected-version", "1.2.4"]
    if command == "repair":
        expected += ["--operation", "synthetic-operation"]
    expected += ["--non-interactive"] + ([handed] if handed else [])
    assert argv == expected, argv


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


def _compatibility(runtime, fault=None, edit=None, prefix=""):
    """Run the real compatibility gate against a synthetic completed source.
    `edit` changes the current site after the installed record was taken from
    it; `prefix` runs before the gate (an owned Lease, for instance)."""
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
    if edit:
        edit(site)
        (work / "site.json").write_text(json.dumps(site))
    (payload / "release.json").write_text(json.dumps(release))
    (work / "values.pending.json").write_text(json.dumps(
        {"storage": {role: {"existingClaim": ""} for role in ("data", "forgejo", "chroma")}}))
    (work / "installed.json").write_text(json.dumps(installed))
    kube.write_text(json.dumps(cluster))
    return run(prefix + 'GSJ_PAYLOAD="$TEST_WORK/payload"\ncompatibility selected\n')


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


# ---- the staging directory and the free-space floor are not storage identity ----

WRITES = ("create", "replace", "apply", "delete", "scale", "exec", "patch", "label")
UNFROZEN = [(("transfer_path",), "/srv/gsj/transfer"), (("minimum_free_bytes",), 5 * 2 ** 30)]
FROZEN = [(("profile",), "managed-local-path"), (("class",), "another-class"), (("node",), "another-node"),
          (("backend_path",), "/srv/another-backend"),
          (("data", "size"), "40Gi"), (("forgejo", "size"), "20Gi"), (("chroma", "size"), "40Gi"),
          (("data", "existing_claim"), "claim-of-my-own"), (("forgejo", "existing_claim"), "claim-of-my-own"),
          (("chroma", "existing_claim"), "claim-of-my-own")]


def _storage(path, value):
    def edit(site):
        node = site["storage"]
        for key in path[:-1]:
            node = node[key]
        node[path[-1]] = value
    return edit


def _frozen_with_unfrozen(path, value):
    """One frozen storage key changed, and both unfrozen ones with it: leaving
    those two out of the comparison must not hide any other difference."""
    def edit(site):
        _storage(path, value)(site)
        for unfrozen, changed in UNFROZEN:
            _storage(unfrozen, changed)(site)
    return edit


def _ids(cases):
    return [".".join(path) for path, _ in cases]


def _no_writes(kube):
    return not any(call[:1] and call[0] in WRITES for call in json.loads(kube.read_text())["calls"])


@pytest.mark.parametrize("path,value", UNFROZEN, ids=_ids(UNFROZEN))
def test_upgrade_admits_a_changed_transfer_path_or_free_space_floor(runtime, path, value):
    """A release installed with an empty storage.transfer_path, on a node whose
    root filesystem cannot hold the archive twice, could neither be backed up
    nor upgraded, and the path could not be corrected in place: the gate
    compared the whole storage block. Where a maintenance Pod stages and how
    much free space it demands say nothing about which volumes hold the data,
    and both are read from the current site, so a change to either passes."""
    result = _compatibility(runtime, edit=_storage(path, value))
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("path,value", FROZEN, ids=_ids(FROZEN))
def test_upgrade_still_refuses_every_other_storage_change(runtime, path, value):
    _, kube, _ = runtime
    result = _compatibility(runtime, edit=_frozen_with_unfrozen(path, value))
    assert result.returncode != 0
    assert "upgrade cannot change target, operator or storage identity" in result.stderr
    assert _no_writes(kube)


def _backup_compare(runtime, edit):
    """backup_operation as far as its settings comparison: the installed record
    is served by the fake ConfigMap, and acquire, the first step after the
    comparison, ends the run with 93."""
    run, kube, work = runtime
    site = json.loads((work / "site.json").read_text())
    installed = {"format": "gsj.installed/1", "status": "complete", "manifest": {"identity": "synthetic-release"},
                 "site": json.loads(json.dumps(site)), "storage": [], "namespace_uid": "target-namespace-uid"}
    edit(site)
    (work / "site.json").write_text(json.dumps(site))
    record = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "synthetic-release-installed"},
              "data": {"installed.json": json.dumps(installed)}}
    # the fake keys a named get by the kind as spelled: read_installed asks for "configmap"
    kube.write_text(json.dumps({"lease": None, "calls": [],
                                "resources": {"configmap/synthetic-release-installed": record}}))
    return run('acquire() { touch "$TEST_WORK/acquired"; exit 93; }\nbackup_operation\n')


@pytest.mark.parametrize("path,value", UNFROZEN, ids=_ids(UNFROZEN))
def test_backup_admits_a_changed_transfer_path_or_free_space_floor(runtime, path, value):
    """The same two keys no longer count as application settings for a backup:
    correcting the staging directory is what makes the backup possible."""
    _, _, work = runtime
    result = _backup_compare(runtime, _storage(path, value))
    assert result.returncode == 93, result.stderr
    assert (work / "acquired").exists()


@pytest.mark.parametrize("path,value", FROZEN, ids=_ids(FROZEN))
def test_backup_still_refuses_every_other_storage_change(runtime, path, value):
    _, kube, work = runtime
    result = _backup_compare(runtime, _frozen_with_unfrozen(path, value))
    assert result.returncode != 0
    assert "backup cannot change application settings" in result.stderr
    assert not (work / "acquired").exists()
    assert _no_writes(kube)


def test_capacity_measurement_applies_the_current_sites_free_space_floor(runtime):
    """The floor the capacity scan enforces is the one the site names now, so a
    lowered or raised storage.minimum_free_bytes governs the very backup that
    follows the edit, not only the one after an operation has recorded it."""
    run, _, work = runtime
    site = json.loads((work / "site.json").read_text())
    installed = {"site": json.loads(json.dumps(site))}
    site["storage"]["minimum_free_bytes"] = 5 * 2 ** 30
    (work / "site.json").write_text(json.dumps(site))
    (work / "installed.json").write_text(json.dumps(installed))
    helpers = work / "payload" / "helpers"
    helpers.mkdir(parents=True)
    (helpers / "capacity.py").write_text("")
    result = run('''GSJ_PAYLOAD="$TEST_WORK/payload"
capacity_host_filesystems() { printf '{}\\n' > "$GSJ_WORK/capacity-host.json"; }
assert_owner() { :; }
k() { printf '%s\\n' "$@" > "$TEST_WORK/scan-argv"; printf '{"format":"gsj.capacity/1","status":"passed"}\\n'; }
capacity_scan_pod reader create before
''')
    assert result.returncode == 0, result.stderr
    argv = (work / "scan-argv").read_text().splitlines()
    assert argv[argv.index("--minimum") + 1] == str(5 * 2 ** 30)


# ---- corpus.allow_update is consent for one corpus change -----------------------

OPERATION = "a" * 24
OWNED = f'LEASE_ACQUIRED=true; OPERATION={OPERATION}\nassert_owner() {{ :; }}\n'


def _allow_update(site):
    site["corpus"]["allow_update"] = True


@pytest.mark.parametrize("fault,owned,marked", [
    ("corpus", True, True),     # the gate again under the operation's Lease
    ("corpus", False, False),   # the read-only preview before the Lease
    (None, True, False),        # the same corpus: a stale true admits nothing
])
def test_an_admitted_corpus_change_is_recorded_on_the_owned_operation(runtime, fault, owned, marked):
    """The gate that admits a corpus change is the one place that knows the
    installed corpus; under the Lease it records the admitted change on the
    operation, which survives a resume, for record_installed to complete. It
    changes no site file itself."""
    _, _, work = runtime
    before = {"operation": OPERATION, "target": "synthetic-release", "kind": "upgrade", "status": "owned"}
    (work / "operation.json").write_text(json.dumps(before))
    result = _compatibility(runtime, fault, edit=_allow_update, prefix=OWNED if owned else "")
    assert result.returncode == 0, result.stderr
    after = json.loads((work / "operation.json").read_text())
    assert after == ({**before, "corpus_update_from": "c" * 64} if marked else before)
    assert json.loads((work / "site.json").read_text())["corpus"]["allow_update"] is True


def test_upgrade_records_the_corpus_change_in_its_second_gate_not_the_preview(runtime):
    """main runs the gate twice: a read-only preview, then again once the Lease
    is held. Only the second writes, and it writes to the new operation's
    record, never to the completed operation the preview still sees."""
    _, _, work = runtime
    previous = {"operation": "b" * 24, "target": "synthetic-release", "kind": "upgrade", "status": "complete"}
    (work / "operation.json").write_text(json.dumps(previous))
    helpers = work / "payload" / "helpers"
    helpers.mkdir(parents=True)
    for name in ("verification-cleanup.sh", "startup-recovery.sh"):
        (helpers / name).write_text("")
    stubs = f'''GSJ_PAYLOAD="$TEST_WORK/payload"
bootstrap() {{ :; }}; install_exit_traps() {{ :; }}; load_site() {{ :; }}; helm_verb_preflight() {{ :; }}
inspect_cluster() {{ printf '{{}}\\n'; }}; preflight() {{ :; }}; endpoint_preflight() {{ :; }}; read_installed() {{ :; }}
assert_owner() {{ :; }}
acquire() {{ cp "$STATE_DIR/operation.json" "$TEST_WORK/seen-by-preview.json"; OPERATION={OPERATION}; LEASE_ACQUIRED=true
  printf '{{"operation":"%s","target":"synthetic-release","kind":"upgrade","status":"owned"}}' "$OPERATION" > "$STATE_DIR/operation.json"; }}
relocated_images_probe() {{ exit 94; }}
main upgrade --expected-version v1.2.3 --config "$SITE" --non-interactive
'''
    result = _compatibility(runtime, "corpus-allowed", prefix=stubs)
    assert result.returncode == 94, result.stderr
    assert json.loads((work / "seen-by-preview.json").read_text()) == previous
    assert json.loads((work / "operation.json").read_text()) == {
        "operation": OPERATION, "target": "synthetic-release", "kind": "upgrade", "status": "owned",
        "corpus_update_from": "c" * 64}


BROKEN = b'{"schema_version": "gsj.site/1",\n "corpus": {"vectors_url": "", "allow_update": true,}\n'


def _record_installed(runtime, operation, link=False, stop=None, broken=None, prefix=""):
    """record_installed with the fake: the installed ConfigMap is rendered by a
    stand-in for `create --dry-run` and captured at apply. stop: the write the
    run is killed before -- "file" (the operator's site file) or "saved" (the
    operation's saved site). broken: the one of those two an edit left
    unreadable while the operation ran (BROKEN, a syntax error)."""
    run, _, work = runtime
    state = work / "state"
    state.mkdir()
    payload = work / "payload"
    payload.mkdir()
    release = _release()
    release["corpus"]["fingerprint"] = "b" * 64
    (payload / "release.json").write_text(json.dumps(release))
    site = json.loads((work / "site.json").read_text())
    site["corpus"]["allow_update"] = True
    for path in (work / "site.json", state / "site.pending.json"):
        path.write_text(json.dumps(site))
    # the operator's own file stays narrow: only the one value changes
    own = {"schema_version": "gsj.site/1", "target": {"context": "synthetic-context"},
           "corpus": {"vectors_url": "", "allow_update": True}}
    operator = work / "operator"
    operator.mkdir()
    config = operator / "site.json"
    if link:
        (operator / "kept-elsewhere.json").write_text(json.dumps(own))
        config.symlink_to(operator / "kept-elsewhere.json")
    else:
        config.write_text(json.dumps(own))
    for name in ("verification.json", "public-check.json", "network-check.json"):
        (state / name).write_text("{}")
    if broken:
        {"file": config, "saved": state / "site.pending.json"}[broken].write_bytes(BROKEN)
    (state / "operation.json").write_text(json.dumps(
        {"operation": OPERATION, "target": "synthetic-release", "kind": "upgrade", "status": "verifying", **operation}))
    stopper = ""
    if stop:
        target = {"file": '"$CONFIG"', "saved": '"$STATE_DIR/site.pending.json"'}[stop]
        stopper = ('eval "$(declare -f atomic | sed 1s/^atomic/real_atomic/)"\n'
                   f'atomic() {{ [[ $1 != {target} ]] || exit 137; real_atomic "$@"; }}\n')
    result = run(f'''STATE_DIR="$TEST_WORK/state"; GSJ_PAYLOAD="$TEST_WORK/payload"; CONFIG="$TEST_CONFIG"; OPERATION={OPERATION}
assert_owner() {{ :; }}
storage_identity() {{ printf '[]\\n'; }}
installation_summary() {{ :; }}
{prefix}{stopper}k() {{ case "$1" in
  create) jq -n --arg name "$3" --rawfile record "${{4#--from-file=installed.json=}}" '{{apiVersion:"v1",kind:"ConfigMap",metadata:{{name:$name}},data:{{"installed.json":$record}}}}';;
  apply) cat > "$TEST_WORK/applied.json";;
  *) kubectl --context "$CONTEXT" --namespace "$NAMESPACE" "$@";;
esac; }}
record_installed
''', TEST_CONFIG=str(config))
    return result, _places(runtime, config), own, config


def _places(runtime, config):
    """corpus.allow_update in each place; a file that does not read as JSON
    shows as its bytes."""
    _, _, work = runtime
    state = work / "state"

    def flag(path):
        try:
            return json.loads(path.read_text())["corpus"]["allow_update"]
        except ValueError:
            return path.read_bytes()
    applied = json.loads(json.loads((work / "applied.json").read_text())["data"]["installed.json"])
    return {"site file": flag(config),
            "merged site": flag(work / "site.json"),
            "saved operation site": flag(state / "site.pending.json"),
            "installed record": applied["site"]["corpus"]["allow_update"],
            "installed record kept here": json.loads((state / "installed.json").read_text())["site"]["corpus"]["allow_update"]}


def test_a_completed_corpus_change_sets_allow_update_back_to_false_everywhere(runtime):
    """A site that set corpus.allow_update=true to admit one corpus change kept
    it true, so the next release's corpus was adopted without being asked for.
    Once the operation that made the change is recorded complete, the consent
    is spent: the operator's file, the merged site, the operation's saved site
    and the installed record all say false again, and one line says why."""
    result, places, own, config = _record_installed(runtime, {"corpus_update_from": "c" * 64})
    assert result.returncode == 0, result.stderr
    assert places == dict.fromkeys(places, False), places
    assert json.loads(config.read_text()) == {**own, "corpus": {**own["corpus"], "allow_update": False}}
    assert "corpus.allow_update" in result.stderr and "set back to false" in result.stderr
    _, _, work = runtime
    recorded = json.loads((work / "state" / "operation.json").read_text())
    assert recorded["status"] == "complete" and "corpus_update_reset" not in recorded, recorded


@pytest.mark.parametrize("operation", [
    {},                                                    # no corpus change in this operation
    {"corpus_update_from": "b" * 64},                      # recorded, yet the corpus is this release's
    {"kind": "restore", "corpus_update_from": "c" * 64},   # a restore never spends the consent
], ids=["no-change", "same-corpus", "restore"])
def test_allow_update_is_left_alone_unless_a_corpus_change_completed(runtime, operation):
    result, places, _, _ = _record_installed(runtime, operation)
    assert result.returncode == 0, result.stderr
    assert places == dict.fromkeys(places, True), places
    assert "corpus.allow_update" not in result.stderr


def test_a_linked_site_file_keeps_allow_update_and_is_named(runtime):
    """A site file that is a symbolic link is never rewritten through the link.
    Changing the records alone would leave the file saying true and every later
    backup refused as a settings change, so nothing is changed and the closing
    log names the file for the operator to correct."""
    result, places, _, config = _record_installed(runtime, {"corpus_update_from": "c" * 64}, link=True)
    assert result.returncode == 0, result.stderr
    assert places == dict.fromkeys(places, True), places
    assert config.is_symlink()
    assert "is a symbolic link or no longer a regular file" in result.stderr and str(config) in result.stderr


@pytest.mark.parametrize("broken, place, name", [
    ("file", "site file", None),
    ("saved", "saved operation site", "state/site.pending.json"),
])
def test_a_site_file_broken_during_the_operation_keeps_its_bytes_and_the_marker(runtime, broken, place, name):
    """The operator edited the site file into a syntax error during a day-long
    upgrade. jq could not read it, and atomic published jq's empty output over
    it: the whole site file was gone and the run stopped. jq now writes into
    the work directory and only a complete result is published, so the file
    keeps its bytes, corpus.allow_update is still true in it, the log names it,
    the operation carries its reset marker still, and it completes. The saved
    site of the operation is written the same way."""
    _, _, work = runtime
    result, places, own, config = _record_installed(runtime, {"corpus_update_from": "c" * 64}, broken=broken)
    assert result.returncode == 0, result.stderr
    named = str(work / name) if name else str(config)
    assert places[place] == BROKEN, places
    assert places["installed record"] is False and places["merged site"] is False
    if broken == "saved":
        assert places["site file"] is False     # the file first: it was readable
    else:
        assert places["saved operation site"] is True
    assert f"corpus.allow_update is still true in {named}" in result.stderr, result.stderr
    assert "set back to false" not in result.stderr
    recorded = json.loads((work / "state" / "operation.json").read_text())
    assert recorded["status"] == "complete" and recorded.get("corpus_update_reset") == "pending", recorded
    assert not list((work / "state").glob("*.pending.[0-9]*")) and not list(config.parent.glob("*.pending.[0-9]*"))


def test_the_merged_site_is_published_only_from_a_complete_rewrite(runtime):
    """The merged site went through the same pipe: had jq failed on it, atomic
    would have published an empty file there too. A failure now publishes
    nothing and stops before the operation is complete, with no marker, for
    its resume to record again."""
    _, _, work = runtime
    failing = 'jq() { if [[ $* == *allow_update=false* && ${@: -1} == "$SITE" ]]; then return 5; fi; command jq "$@"; }\n'
    with pytest.raises(FileNotFoundError):            # nothing was applied
        _record_installed(runtime, {"corpus_update_from": "c" * 64}, prefix=failing)
    assert (work / "site.json").read_bytes() != b"", "an empty merged site was published"
    assert json.loads((work / "site.json").read_text())["corpus"]["allow_update"] is True
    recorded = json.loads((work / "state" / "operation.json").read_text())
    assert recorded["status"] == "verifying" and "corpus_update_reset" not in recorded, recorded


def _resume(runtime, config):
    """A named resume of the operation the stop left: its Lease unrenewed for
    180 s, and the merged site load_site builds from the operator's file as
    that file now reads."""
    run, state, work = runtime
    cluster = json.loads(state.read_text())
    cluster["lease"] = {"apiVersion": "coordination.k8s.io/v1", "kind": "Lease",
                        "metadata": {"name": "synthetic-release-operation", "resourceVersion": "7"},
                        "spec": {"holderIdentity": OPERATION, "renewTime": "2000-01-01T00:00:00.000000Z"}}
    state.write_text(json.dumps(cluster))
    site = json.loads((work / "site.json").read_text())
    site["corpus"]["allow_update"] = json.loads(config.read_text())["corpus"]["allow_update"]
    (work / "site.json").write_text(json.dumps(site))
    return run(f'''STATE_DIR="$TEST_WORK/state"; GSJ_PAYLOAD="$TEST_WORK/payload"; CONFIG="$TEST_CONFIG"; RESUME_ID={OPERATION}; COMMAND=resume
assert_owner() {{ :; }}
resume_operation
''', TEST_CONFIG=str(config))


@pytest.mark.parametrize("stop, file_after_stop", [("file", True), ("saved", False)])
def test_a_stop_between_the_completed_record_and_the_site_rewrites_is_finished_by_resume(runtime, stop, file_after_stop):
    """record_installed marks the operation complete and only then rewrites
    the operator's file and the operation's saved site, in two steps. A stop
    before the first left both true beside a false installed record -- the
    resume said 'already complete' and every later backup was refused as a
    settings change; a stop between them left the file false and the saved
    site true, and the resume refused 'configuration changed'. The operation
    now carries a marker, written before it is complete, that admits exactly
    that difference, and the resume finishes both rewrites."""
    _, _, work = runtime
    result, places, own, config = _record_installed(runtime, {"corpus_update_from": "c" * 64}, stop=stop)
    assert result.returncode == 137, result.stderr
    stopped = json.loads((work / "state" / "operation.json").read_text())
    assert stopped["status"] == "complete" and stopped.get("corpus_update_reset") == "pending", stopped
    assert places["installed record"] is False and places["saved operation site"] is True
    assert places["site file"] is file_after_stop
    resumed = _resume(runtime, config)
    assert resumed.returncode == 0, resumed.stderr
    assert "configuration changed" not in resumed.stderr
    after = _places(runtime, config)
    del after["merged site"]           # rebuilt from the file by every run
    assert after == dict.fromkeys(after, False), after
    assert json.loads(config.read_text()) == {**own, "corpus": {**own["corpus"], "allow_update": False}}
    finished = json.loads((work / "state" / "operation.json").read_text())
    assert finished["status"] == "complete" and "corpus_update_reset" not in finished, finished
    assert "set back to false" in resumed.stderr


def test_the_marker_admits_a_difference_in_allow_update_alone(runtime):
    """retained_site_matches admits the one value record_installed changes, and
    only while the operation carries its marker; anything else still refuses."""
    run, _, work = runtime
    saved = json.loads((work / "site.json").read_text())
    (work / "saved.json").write_text(json.dumps(saved))
    only = {**saved, "corpus": {**saved["corpus"], "allow_update": not saved["corpus"]["allow_update"]}}
    (work / "only.json").write_text(json.dumps(only))
    (work / "more.json").write_text(json.dumps({**only, "public_url": "https://other.example"}))
    body = 'for f in only more; do if retained_site_matches "$TEST_WORK/$f.json" "$TEST_WORK/saved.json"; then echo "$f=admitted"; else echo "$f=refused"; fi; done'
    (work / "operation.json").write_text(json.dumps({"operation": OPERATION, "status": "complete", "corpus_update_reset": "pending"}))
    assert run(body).stdout.split() == ["only=admitted", "more=refused"]
    (work / "operation.json").write_text(json.dumps({"operation": OPERATION, "status": "complete"}))
    assert run(body).stdout.split() == ["only=refused", "more=refused"]


@pytest.mark.parametrize("status, admitted", [("verifying", False), ("complete", True)])
def test_the_marker_admits_the_difference_only_once_the_operation_is_complete(runtime, status, admitted):
    """record_installed writes the marker before it marks the operation
    complete, and rewrites the operator's file and the saved site only after:
    in between, both still say what the operation was compiled from, so a
    difference there is the operator's own edit. The marker admitted it for an
    operation still verifying -- resume, backup-repair and restore-repair took
    a changed corpus.allow_update for this operation's own reset."""
    run, _, work = runtime
    saved = json.loads((work / "site.json").read_text())
    (work / "saved.json").write_text(json.dumps(saved))
    (work / "only.json").write_text(json.dumps(
        {**saved, "corpus": {**saved["corpus"], "allow_update": not saved["corpus"]["allow_update"]}}))
    (work / "operation.json").write_text(json.dumps({"operation": OPERATION, "status": status, "corpus_update_reset": "pending"}))
    result = run('if retained_site_matches "$TEST_WORK/only.json" "$TEST_WORK/saved.json"; then echo admitted; else echo refused; fi')
    assert result.stdout.split() == ["admitted" if admitted else "refused"], result.stderr
