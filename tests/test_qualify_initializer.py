"""The initializer qualification (review B1): the pure parts of ci/qualify-initializer.py,
and that the release's documents and the runtime registry name it."""
import importlib.util
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "ops" / "installer"
SCRIPT = INSTALLER / "ci" / "qualify-initializer.py"


@pytest.fixture(scope="module")
def module():
    spec = importlib.util.spec_from_file_location("qualify_initializer", SCRIPT)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def _passed(module):
    observed = {name: dict(expected) for name, expected in module.EXPECTED.items()}
    pair = ("43785dcca030cc96fcaa8ebc66f2e4f586cd122e82117cd3bc77b0901397b507",
            "2ee3f420432386ef549d98802182f0e681a86af7b37dcd1d242b9b70e1ae097b")
    return {"schema": module.SCHEMA, "cases": module.judge(observed),
            "pair": {"initialize_sha256": pair[0], "corpus_sha256": pair[1], "registered": True}}


def test_the_judgement_lives_on_the_host_and_every_expected_value_is_load_bearing(module):
    """The driver measures; judge() decides against EXPECTED. Every expected
    value, when the observation disagrees, fails its case by name -- the
    pass criteria cannot be deleted or inverted without this test noticing."""
    observed = {name: dict(expected) for name, expected in module.EXPECTED.items()}
    assert {name: case["status"] for name, case in module.judge(observed).items()} == {name: "passed" for name in module.EXPECTED}
    for name, expected in module.EXPECTED.items():
        for key, value in expected.items():
            broken = {n: dict(e) for n, e in module.EXPECTED.items()}
            broken[name][key] = (not value) if isinstance(value, bool) else (str(value) + "x" if isinstance(value, str) else value + 1)
            cases = module.judge(broken)
            assert cases[name]["status"] == "failed" and cases[name]["disagreements"] == [key], (name, key)
    # the pinned initializer's shape (two attempts, the budget word; a missing
    # block spent both and the restart stayed terminal) fails core, block and
    # restage by name
    old = {n: dict(e) for n, e in module.EXPECTED.items()}
    for name in ("core", "block"):
        old[name].update(first_reason="terminal-budget-exhausted", first_shard_attempts=2, checkpoint_terminal=None,
                         checkpoint_last_error="terminal-budget-exhausted", restart_reason="terminal-budget-exhausted",
                         restart_shard_attempts=2)
    old["restage"].update(missing_reason="terminal-budget-exhausted", missing_shard_attempts=2, damaged_reason="terminal-budget-exhausted",
                          damaged_verdicts_lifted=0, damaged_shard_attempts=2, restaged_exit=1, restaged_verdicts_lifted=0,
                          restaged_complete=False, restaged_vector_source=None, restaged_rows_match=False, restaged_vectors_match=False,
                          restaged_shard_complete=False, restaged_shard_imported=False, restaged_chroma_count_matches=False)
    old["restage-valid"].update(exit=1, complete=False, rows_match=False, vectors_match=False, restart_exit=1, restart_complete=False)
    assert {n: c["status"] for n, c in module.judge(old).items()} == {"import": "passed", "readback": "passed", "core": "failed", "block": "failed", "restage": "failed", "restage-valid": "failed"}
    # the last pass's initializer (9c8426, withdrawn): terminal at once and
    # terminal on every restart, the restaged block never judged -- fails
    # restage by name and nothing else
    reviewed = {n: dict(e) for n, e in module.EXPECTED.items()}
    reviewed["restage"].update(damaged_verdicts_lifted=0, restaged_exit=1, restaged_verdicts_lifted=0, restaged_complete=False,
                               restaged_vector_source=None, restaged_rows_match=False, restaged_vectors_match=False,
                               restaged_shard_complete=False, restaged_shard_imported=False, restaged_chroma_count_matches=False)
    reviewed["restage-valid"].update(exit=1, complete=False, rows_match=False, vectors_match=False, restart_exit=1, restart_complete=False)
    assert {n: c["status"] for n, c in module.judge(reviewed).items()} == {"import": "passed", "readback": "passed", "core": "passed", "block": "passed", "restage": "failed", "restage-valid": "failed"}
    # the withdrawn 7b32ab04 (never deployed): every case but restage-valid --
    # a valid sidecar restaged after the manifest was loaded was judged
    # against the old entries, terminal, bound to the new bytes, and the
    # restart repeated it -- fails restage-valid by name and nothing else
    withdrawn = {n: dict(e) for n, e in module.EXPECTED.items()}
    withdrawn["restage-valid"].update(exit=1, complete=False, rows_match=False, vectors_match=False, restart_exit=1, restart_complete=False)
    assert {n: c["status"] for n, c in module.judge(withdrawn).items()} == {"import": "passed", "readback": "passed", "core": "passed", "block": "passed", "restage": "passed", "restage-valid": "failed"}
    assert module.judge({})["import"]["status"] == "failed"


def test_restage_valid_proves_its_own_precondition_or_is_not_exercised(module):
    """The restage-valid case exists only while the initializer is stopped BEFORE
    it judged any shard (A loaded, nothing imported): a stop that lands after the
    import completed judges nothing and must not count as a pass. The driver
    reports what the initializer's own checkpoint said at the stop; the judge
    holds the case to it and names a stop that came too late "not exercised"."""
    assert module.EXPECTED["restage-valid"]["stopped_before_import"] is True
    late = {name: dict(expected) for name, expected in module.EXPECTED.items()}
    late["restage-valid"]["stopped_before_import"] = False
    late["restage-valid"]["not_exercised"] = "the initializer had completed the import when it was stopped"
    cases = module.judge(late)
    assert cases["restage-valid"]["status"] == "not exercised"
    assert "stopped_before_import" in cases["restage-valid"]["disagreements"]
    assert {n: c["status"] for n, c in cases.items() if n != "restage-valid"} == {n: "passed" for n in module.EXPECTED if n != "restage-valid"}
    report = {"schema": module.SCHEMA, "cases": cases,
              "pair": {"registered": True, "initialize_sha256": "a" * 64, "corpus_sha256": "b" * 64}}
    assert module.verdict(report) == "failed"
    # a stop that came in time, reported so, is judged as before
    good = {name: dict(expected) for name, expected in module.EXPECTED.items()}
    assert module.judge(good)["restage-valid"]["status"] == "passed"
    # the driver reads the precondition off the checkpoint the initializer wrote,
    # at the stop, never off the events the driver had read so far
    for step in ("checkpoint_at_stop", "stopped_before_import", "not_exercised", "shards_judged_at_stop"):
        assert step in module.DRIVER, step


def test_the_verdict_needs_every_case_and_a_registered_measured_pair(module):
    assert module.verdict(_passed(module)) == "passed"
    for name in module.EXPECTED:
        report = _passed(module); report["cases"][name] = {"status": "failed"}
        assert module.verdict(report) == "failed", name
        report = _passed(module); del report["cases"][name]
        assert module.verdict(report) == "failed", name
    report = _passed(module); report["pair"]["registered"] = False
    assert module.verdict(report) == "failed"
    report = _passed(module); del report["pair"]["initialize_sha256"]
    assert module.verdict(report) == "failed"
    report = _passed(module); report["schema"] = "gsj.something-else/1"
    assert module.verdict(report) == "failed"
    assert module.verdict({}) == "failed" and module.verdict(None) == "failed"
    # the registry the verdict consults is the installer's own
    pairs = module.registered_pairs()
    assert ("43785dcca030cc96fcaa8ebc66f2e4f586cd122e82117cd3bc77b0901397b507",
            "2ee3f420432386ef549d98802182f0e681a86af7b37dcd1d242b9b70e1ae097b") in pairs


def test_the_images_are_read_off_the_release_manifest_by_repository_and_digest(module):
    release = {"images": {"web": {"repository": "registry.invalid/web", "digest": "sha256:" + "a" * 64},
                          "chroma": {"repository": "registry.invalid/chroma", "digest": "sha256:" + "b" * 64}}}
    assert module.image_references(release) == {"web": "registry.invalid/web@sha256:" + "a" * 64,
                                                "chroma": "registry.invalid/chroma@sha256:" + "b" * 64}
    for broken in ({"images": {"web": {"repository": "x", "digest": "sha256:" + "a" * 64}}},
                   {"images": {"web": {"repository": "x", "digest": "latest"}, "chroma": {"repository": "y", "digest": "sha256:" + "b" * 64}}},
                   {}):
        with pytest.raises(SystemExit):
            module.image_references(broken)


def test_the_driver_is_valid_python_and_runs_the_six_cases_through_the_real_entrypoint(module):
    """The driver runs inside the released web image: it must parse, and it must
    run the initializer as the kubelet does -- `python -m gsj_deploy.initialize
    --settings` -- once per case and once more for each restart (the restage
    case restarts twice: the block restaged damaged, then intact; the
    restage-valid case stops the first run with SIGSTOP right after
    `corpus-vector-source`, stages sidecar B with the release's own staging
    helper (its source from the environment), continues it, and restarts)."""
    compile(module.DRIVER, "driver", "exec")
    assert '"-m", "gsj_deploy.initialize", "--settings"' in module.DRIVER
    assert module.CASES == ("import", "core", "block", "restage", "restage-valid") and set(module.EXPECTED) == {*module.CASES, "readback"}
    for step in ("signal.SIGSTOP", "signal.SIGCONT", 'os.environ["GSJ_STAGE_HELPER"]', "mtime=1700000000", "restage-valid-staged"):
        assert step in module.DRIVER, step
    assert module.STAGE_HELPER.is_file() and module.STAGE_HELPER.name == "stage-vectors.py"
    for name in module.CASES:
        assert f'hosts["{name}"]' in module.DRIVER, name
    assert "restart" in module.DRIVER and "corpus-vector-source" in module.DRIVER
    for step in ('"missing"', '"damaged"', '"restaged"', "block4.unlink()", "intact[:-7]", "corpus-verdict-lifted"):
        assert step in module.DRIVER, step
    # the driver measures the pair inside the image and judges nothing
    assert "inspect.getfile(init)" in module.DRIVER and "inspect.getfile(corpus)" in module.DRIVER
    assert "disagreements" not in module.DRIVER and "EXPECTED" not in module.DRIVER


def test_the_release_steps_and_the_runtime_registry_name_this_qualification():
    readme = (INSTALLER / "README.md").read_text()
    assert "ci/qualify-initializer.py" in readme
    step = readme.split("**Initializer qualification**", 1)[1].split("\n6. ", 1)[0]
    for phrase in ("before any deployment that runs\n   this initializer is upgraded", "before the installer is published",
                   "core-mismatch", "source-verification-failed", "restaged", "valid sidecar", "QUALIFIED_SOURCE_RUNTIMES", "ci/qualify.py gate"):
        assert phrase in step, phrase
    assert "5. **Initializer qualification**" in readme and "6. **Staging**" in readme      # before anything leaves the machine
    registry = (INSTALLER / "startup-runtime-preflight.py").read_text()
    assert "ci/qualify-initializer.py" in registry
    # the pair the registration comment backs is the LAST registered pair, and
    # the three withdrawn initializers (the message-pass one, 9c8426 and
    # 7b32ab04, none ever deployed) are not registered
    pairs = re.findall(r"\('([0-9a-f]{64})',\s*'([0-9a-f]{64})'\)", registry)
    assert pairs[-1] == ("43785dcca030cc96fcaa8ebc66f2e4f586cd122e82117cd3bc77b0901397b507",
                         "2ee3f420432386ef549d98802182f0e681a86af7b37dcd1d242b9b70e1ae097b")
    assert not any(p[0].startswith(("4de81568", "9c8426db", "7b32ab04")) for p in pairs)
    # the gate reads the report
    assert "check_initializer_qualification" in (INSTALLER / "ci" / "qualify.py").read_text()
