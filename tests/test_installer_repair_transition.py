"""Interrupt the shipped repair publication between its durable writes."""
import json
import subprocess
from pathlib import Path

import pytest

from tests.test_installer_backup_repair import (
    OLD_TIME, _operation, _replacement_source, repair_shell,
)
from tests.test_installer_backup_retry import _cluster, maintenance

ROOT = Path(__file__).resolve().parents[1]

# Only repair may open one new bounded account-cleanup round, so the signal is
# exported by repair_operation and by nothing else.
SIGNAL = 'verify_application() { printf \'%s\\n\' "${GSJ_CLEANUP_NEW_ROUND:-unset}" >> "$STATE_DIR/new-round"; }\n'


def _prepare(m):
    _replacement_source(m)
    _operation(m, kind="install", status="verifying")
    result = m["run_shell"]('prepare_repair_transition source-release', release="target-release")
    assert result.returncode == 0, result.stderr
    record = json.loads((m["state"] / "operation.json").read_text())
    intent = m["state"] / record["repair_transition"]["file"]
    assert record["status"] == "repair-prepared"
    assert record["target"] == "source-release"
    assert json.loads(m["site"].read_text())["corpus"]["repair_generation"] == 0
    return intent, intent.read_bytes()


@pytest.mark.parametrize("destination", [
    "$SITE", "$CONFIG", "$STATE_DIR/site.pending.json",
    "$GSJ_WORK/values.pending.json", "$STATE_DIR/values.pending.json",
    "$STATE_DIR/operation.json",
])
@pytest.mark.parametrize("when", ["before", "after"])
@pytest.mark.parametrize("shape", ["complete", "minimal", "managed-local-ca-minimal"])
def test_resume_finishes_each_publication_window_without_incrementing_twice(repair_shell, destination, when, shape):
    m = repair_shell
    config = m["state"] / "input-site.json"
    written = json.loads(config.read_text()); ca = None
    if shape == "minimal":
        written = _minimal(written); config.write_text(json.dumps(written, indent=2))
    elif shape == "managed-local-ca-minimal":
        config, written, ca = _managed_local_ca(m, config_has_paths=False)
    intent, original = _prepare(m)
    fault = f'''
eval "$(declare -f atomic | sed '1s/atomic/real_atomic/')"
atomic() {{
  if [[ $1 == "{destination}" && {when} == before ]]; then cat >/dev/null; exit 86; fi
  real_atomic "$1"
  if [[ $1 == "{destination}" && {when} == after ]]; then exit 86; fi
}}
finish_repair_transition
'''
    failed = m["run_shell"](fault, release="target-release")
    assert failed.returncode == 86, failed.stderr
    assert not (m["state"] / "actions").exists()
    _cluster(m, lambda s: s["lease"]["spec"].update(renewTime=OLD_TIME))
    resumed = m["run_shell"]("resume_operation", release="target-release")
    assert resumed.returncode == 0, resumed.stderr
    record = json.loads((m["state"] / "operation.json").read_text())
    assert record["target"] == "target-release"
    assert "repair_transition" not in record
    assert len(record["repair_transition_history"]) == 1
    assert intent.read_bytes() == original
    expected = json.loads(original)["site_after"]
    for path in (m["site"], m["state"] / "site.pending.json"):
        assert json.loads(path.read_text()) == expected
    # the operator's own file: what they wrote, plus the one value repair changed
    assert json.loads(config.read_text()) == _deep(written, {"corpus": {"repair_generation": 1}})
    assert _loaded(config, ca) == (m["state"] / "site.pending.json").read_bytes()
    assert expected["corpus"]["repair_generation"] == 1
    assert (m["state"] / "actions").read_text().splitlines() == [
        "secrets", "dependencies", "helm", "ready", "record-ready", "verify", "record-installed",
    ]


def _minimal(site):
    """A hand-written site: only what differs from the shipped defaults (step 7
    leaves every defaulted block out). It merges back to exactly `site`."""
    defaults = json.loads((ROOT / "ops/installer/defaults.json").read_text())

    def strip(value, default):
        if isinstance(value, dict) and isinstance(default, dict):
            return {k: strip(v, default.get(k)) for k, v in value.items() if k not in default or v != default[k]}
        return value
    return strip(site, defaults)


def _deep(base, extra):
    out = dict(base)
    for key, value in extra.items():
        out[key] = _deep(out[key], value) if isinstance(value, dict) and isinstance(out.get(key), dict) else value
    return out


def _loaded(config, ca=None):
    """The bytes load_site builds from a saved site file once the state directory
    holds an operation: defaults merged under it, validated, and -- under
    tls.profile=managed-local-ca -- the two trust paths derived into the result
    (pass `ca`). resume and the named repairs `cmp` exactly this against the site
    the operation retained."""
    installer = ROOT / "ops/installer"
    merged = subprocess.run(["jq", "-s", ".[0] * .[1]", str(installer / "defaults.json"), str(config)],
                            capture_output=True, check=True).stdout
    site = subprocess.run(["jq", "--slurpfile", "schema", str(installer / "site.schema.json"), "-f",
                           str(installer / "validate.jq")], input=merged, capture_output=True, check=True).stdout
    if ca is None:
        return site
    return subprocess.run(["jq", "--arg", "ca", ca, 'if .tls.profile=="managed-local-ca" then .tls.ca_file=$ca | .verification.ca_file=$ca else . end'],
                          input=site, capture_output=True, check=True).stdout


def test_repair_leaves_a_minimal_site_file_minimal(repair_shell):
    """Repair used to write the complete merged site into the operator's own
    file, pinning every default of that release into a file left minimal on
    purpose. It now writes only the one value it changes."""
    m = repair_shell
    config = m["state"] / "input-site.json"
    written = _minimal(json.loads(m["site"].read_text()))
    assert "resources" not in written and "corpus" not in written and "deadlines" not in written
    config.write_text(json.dumps(written, indent=2))
    intent, original = _prepare(m)
    _cluster(m, lambda s: s["lease"]["spec"].update(renewTime=OLD_TIME))
    resumed = m["run_shell"]("resume_operation", release="target-release")
    assert resumed.returncode == 0, resumed.stderr
    after = json.loads(config.read_text())
    assert after == {**written, "corpus": {"repair_generation": 1}}
    assert list(after)[:len(written)] == list(written)      # their keys, in their order
    assert "complete configuration" not in resumed.stderr
    assert oct(config.stat().st_mode & 0o777) == "0o600"
    # The continuation contract, byte for byte: what load_site rebuilds from the
    # narrow file IS the site the operation retained.
    assert _loaded(config) == (m["state"] / "site.pending.json").read_bytes()
    assert json.loads(_loaded(config)) == json.loads(original)["site_after"]


def test_repair_keeps_the_operators_own_corpus_keys_and_raises_their_generation(repair_shell):
    m = repair_shell
    config = m["state"] / "input-site.json"
    site = json.loads(m["site"].read_text())
    site["corpus"].update(repair_generation=4, allow_update=True)
    for path in (m["site"], m["state"] / "site.pending.json"):
        path.write_text(json.dumps(site))
    installed = json.loads(m["installed"].read_text()); installed["site"] = site
    m["installed"].write_text(json.dumps(installed))
    written = _minimal(site)
    assert written["corpus"] == {"repair_generation": 4, "allow_update": True}
    config.write_text(json.dumps(written))
    _replacement_source(m)
    _operation(m, kind="install", status="verifying")
    assert m["run_shell"]('prepare_repair_transition source-release', release="target-release").returncode == 0
    _cluster(m, lambda s: s["lease"]["spec"].update(renewTime=OLD_TIME))
    resumed = m["run_shell"]("resume_operation", release="target-release")
    assert resumed.returncode == 0, resumed.stderr
    assert json.loads(config.read_text()) == _deep(written, {"corpus": {"repair_generation": 5}})
    assert _loaded(config) == (m["state"] / "site.pending.json").read_bytes()


def test_repair_writes_the_complete_site_when_the_narrow_file_cannot_reproduce_it(repair_shell):
    """The narrow write is admitted on proof only. Two keys the defaults do not
    carry keep the ORDER of the file they came from, so a saved file that lists
    them the other way round is equal as JSON -- every guard passes -- yet
    rebuilds to different bytes than the operation recorded. cmp would refuse
    that at the next resume; the publication writes the complete site instead."""
    m = repair_shell
    config = m["state"] / "input-site.json"
    site = json.loads(m["site"].read_text())
    site["x_first"] = 1; site["x_second"] = 2
    for path in (m["site"], m["state"] / "site.pending.json"):
        path.write_text(json.dumps(site))
    installed = json.loads(m["installed"].read_text()); installed["site"] = site
    m["installed"].write_text(json.dumps(installed))
    written = _minimal(site)
    swapped = {k: v for k, v in written.items() if not k.startswith("x_")}
    swapped["x_second"] = 2; swapped["x_first"] = 1
    config.write_text(json.dumps(swapped))
    _replacement_source(m)
    _operation(m, kind="install", status="verifying")
    assert m["run_shell"]('prepare_repair_transition source-release', release="target-release").returncode == 0
    record = json.loads((m["state"] / "operation.json").read_text())
    expected = json.loads((m["state"] / record["repair_transition"]["file"]).read_text())["site_after"]
    _cluster(m, lambda s: s["lease"]["spec"].update(renewTime=OLD_TIME))
    resumed = m["run_shell"]("resume_operation", release="target-release")
    assert resumed.returncode == 0, resumed.stderr
    assert "writing the complete configuration" in resumed.stderr
    assert config.read_bytes() == (m["state"] / "site.pending.json").read_bytes()
    assert json.loads(config.read_text()) == expected and list(json.loads(config.read_text()))[-2:] == ["x_first", "x_second"]


def _managed_local_ca(m, *, config_has_paths):
    """A managed-local-ca site the way load_site leaves it once the state
    directory already holds an operation: $SITE and the retained site carry the
    two derived trust paths, and a saved file that lacks them was left alone."""
    ca = str(m["state"] / "tls/ca.crt")
    site = json.loads(m["site"].read_text())
    site["tls"].update(profile="managed-local-ca", ca_file=ca)
    site["verification"]["ca_file"] = ca
    for path in (m["site"], m["state"] / "site.pending.json"):
        path.write_text(json.dumps(site))
    installed = json.loads(m["installed"].read_text()); installed["site"] = site
    m["installed"].write_text(json.dumps(installed))
    written = _minimal(site)
    if not config_has_paths:
        del written["tls"]["ca_file"]; del written["verification"]
    config = m["state"] / "input-site.json"
    config.write_text(json.dumps(written, indent=2))
    return config, written, ca


def test_repair_accepts_a_saved_file_that_never_received_the_derived_trust_paths(repair_shell):
    """Measured on a real repair: a second site file in the same state directory
    -- or one regenerated from a template -- never gets the two managed-local-ca
    paths load_site derives. The publication compared the RAW merge of that file
    and refused the UNEDITED file, after the backup, with every controller at
    zero: 'saved configuration changed during repair publication'. load_site's
    derivation is not an operator's edit."""
    m = repair_shell
    config, written, ca = _managed_local_ca(m, config_has_paths=False)
    assert "ca_file" not in written["tls"] and "verification" not in written
    intent, original = _prepare(m)
    assert json.loads(original)["site_before"]["tls"]["ca_file"] == ca
    _cluster(m, lambda s: s["lease"]["spec"].update(renewTime=OLD_TIME))
    resumed = m["run_shell"]("resume_operation", release="target-release")
    assert resumed.returncode == 0, resumed.stderr
    # ...and the file stays the operator's: one value added, the paths still not written into it
    assert json.loads(config.read_text()) == _deep(written, {"corpus": {"repair_generation": 1}})
    assert "complete configuration" not in resumed.stderr
    for path in (m["site"], m["state"] / "site.pending.json"):
        assert json.loads(path.read_text()) == json.loads(original)["site_after"]
    # the continuation contract: what load_site rebuilds from that file IS the retained site, byte for byte
    assert _loaded(config, ca) == (m["state"] / "site.pending.json").read_bytes()
    assert _loaded(config) != (m["state"] / "site.pending.json").read_bytes()      # ...and only with the derivation


def test_repair_treats_the_two_trust_paths_as_load_site_does(repair_shell):
    """Under managed-local-ca load_site overrides whatever the file says at the two
    keys -- a recovery site copied from another host carries the SOURCE's path
    there. The publication compares what load_site builds, so such a file is
    accepted, exactly as load_site accepted it at the start of the same run."""
    m = repair_shell
    config, written, ca = _managed_local_ca(m, config_has_paths=False)
    written["tls"]["ca_file"] = "/home/someone-else/.gsj/tls/ca.crt"
    config.write_text(json.dumps(written))
    intent, original = _prepare(m)
    _cluster(m, lambda s: s["lease"]["spec"].update(renewTime=OLD_TIME))
    resumed = m["run_shell"]("resume_operation", release="target-release")
    assert resumed.returncode == 0, resumed.stderr
    assert _loaded(config, ca) == (m["state"] / "site.pending.json").read_bytes()


@pytest.mark.parametrize("edit", [{"limits": {"upload_mb": 128}}, {"verification": {"connect_host": "192.0.2.7", "connect_port": 8443}},
                                  {"tls": {"secret": "another-tls"}}, {"tls": {"profile": "existing"}}])
def test_repair_still_refuses_a_real_edit_on_a_managed_local_ca_site(repair_shell, edit):
    """The derivation admits exactly the two trust paths and nothing else --
    not their neighbours in the same two blocks, and not the profile itself."""
    m = repair_shell
    config, written, ca = _managed_local_ca(m, config_has_paths=False)
    _prepare(m)
    edited = _deep(written, edit)
    config.write_text(json.dumps(edited))
    before = config.read_bytes()
    _cluster(m, lambda s: s["lease"]["spec"].update(renewTime=OLD_TIME))
    failed = m["run_shell"]("resume_operation", release="target-release")
    assert failed.returncode != 0
    assert "saved configuration changed during repair publication" in failed.stderr
    assert config.read_bytes() == before
    assert json.loads((m["state"] / "operation.json").read_text())["status"] == "repair-prepared"


def test_repair_is_unchanged_for_a_managed_local_ca_file_that_has_the_paths(repair_shell):
    m = repair_shell
    config, written, ca = _managed_local_ca(m, config_has_paths=True)
    intent, original = _prepare(m)
    _cluster(m, lambda s: s["lease"]["spec"].update(renewTime=OLD_TIME))
    resumed = m["run_shell"]("resume_operation", release="target-release")
    assert resumed.returncode == 0, resumed.stderr
    assert json.loads(config.read_text()) == _deep(written, {"corpus": {"repair_generation": 1}})
    assert _loaded(config) == (m["state"] / "site.pending.json").read_bytes()
    assert _loaded(config, ca) == _loaded(config)             # the derivation is the identity on such a file


@pytest.mark.parametrize("damage", ["site", "config", "pending-site", "pending-values", "intent", "namespace", "release"])
def test_repair_publication_refuses_new_edits_or_changed_identity(repair_shell, damage):
    m = repair_shell
    intent, original = _prepare(m)
    if damage == "intent": intent.write_bytes(original + b"\n")
    elif damage == "namespace": _cluster(m, lambda s: s.update(namespace_uid="replacement"))
    elif damage == "release":
        path = m["work"].parent / "payload/release.json"
        value = json.loads(path.read_text()); value["identity"] = "another-release"
        path.write_text(json.dumps(value))
    else:
        path = {"site": m["site"], "config": m["state"] / "input-site.json",
                "pending-site": m["state"] / "site.pending.json", "pending-values": m["state"] / "values.pending.json"}[damage]
        value = json.loads(path.read_text()); value["unexpected"] = True
        path.write_text(json.dumps(value))
    before = {p: p.read_bytes() for p in (m["site"], m["state"] / "input-site.json",
                                         m["state"] / "site.pending.json", m["state"] / "values.pending.json")}
    failed = m["run_shell"]("resume_operation", release="target-release")
    assert failed.returncode != 0
    assert all(path.read_bytes() == content for path, content in before.items())
    assert not (m["state"] / "actions").exists()
    assert json.loads((m["state"] / "operation.json").read_text())["status"] == "repair-prepared"


def test_resume_never_signals_that_a_new_cleanup_round_is_permitted(repair_shell):
    m = repair_shell
    _operation(m, kind="upgrade", status="backup-verified")
    result = m["run_shell"](SIGNAL + "resume_operation")
    assert result.returncode == 0, result.stderr
    assert (m["state"] / "new-round").read_text().split() == ["unset"]


def test_repair_signals_that_one_new_cleanup_round_is_permitted(repair_shell):
    m = repair_shell
    _prepare(m)
    _cluster(m, lambda s: s["lease"]["spec"].update(renewTime=OLD_TIME))
    result = m["run_shell"](SIGNAL + "resume_operation", release="target-release")
    assert result.returncode == 0, result.stderr
    assert (m["state"] / "new-round").read_text().split() == ["1"]
