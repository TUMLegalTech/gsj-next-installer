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
    pair = ("7b32ab049fda8a37b8d49a1bd6ebc332f8f98152db59d4ca35df149d0053ede1",
            "c51fb2d3d12862edef0055fd1ecba8e6ab7083d06fcb9dca35bf00fd892a30c8")
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
    assert {n: c["status"] for n, c in module.judge(old).items()} == {"import": "passed", "readback": "passed", "core": "failed", "block": "failed", "restage": "failed"}
    # the last pass's initializer (9c8426, withdrawn): terminal at once and
    # terminal on every restart, the restaged block never judged -- fails
    # restage by name and nothing else
    reviewed = {n: dict(e) for n, e in module.EXPECTED.items()}
    reviewed["restage"].update(damaged_verdicts_lifted=0, restaged_exit=1, restaged_verdicts_lifted=0, restaged_complete=False,
                               restaged_vector_source=None, restaged_rows_match=False, restaged_vectors_match=False,
                               restaged_shard_complete=False, restaged_shard_imported=False, restaged_chroma_count_matches=False)
    assert {n: c["status"] for n, c in module.judge(reviewed).items()} == {"import": "passed", "readback": "passed", "core": "passed", "block": "passed", "restage": "failed"}
    assert module.judge({})["import"]["status"] == "failed"


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
    assert ("7b32ab049fda8a37b8d49a1bd6ebc332f8f98152db59d4ca35df149d0053ede1",
            "c51fb2d3d12862edef0055fd1ecba8e6ab7083d06fcb9dca35bf00fd892a30c8") in pairs


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


def test_the_driver_is_valid_python_and_runs_the_five_cases_through_the_real_entrypoint(module):
    """The driver runs inside the released web image: it must parse, and it must
    run the initializer as the kubelet does -- `python -m gsj_deploy.initialize
    --settings` -- once per case and once more for each restart (the restage
    case restarts twice: the block restaged damaged, then intact)."""
    compile(module.DRIVER, "driver", "exec")
    assert '"-m", "gsj_deploy.initialize", "--settings"' in module.DRIVER
    assert module.CASES == ("import", "core", "block", "restage") and set(module.EXPECTED) == {*module.CASES, "readback"}
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
                   "core-mismatch", "source-verification-failed", "restaged", "QUALIFIED_SOURCE_RUNTIMES", "ci/qualify.py gate"):
        assert phrase in step, phrase
    assert "5. **Initializer qualification**" in readme and "6. **Staging**" in readme      # before anything leaves the machine
    registry = (INSTALLER / "startup-runtime-preflight.py").read_text()
    assert "ci/qualify-initializer.py" in registry
    # the pair the registration comment backs is the LAST registered pair, and
    # the two withdrawn initializers (the message-pass one and the last pass's
    # 9c8426, neither ever deployed) are not registered
    pairs = re.findall(r"\('([0-9a-f]{64})',\s*'([0-9a-f]{64})'\)", registry)
    assert pairs[-1] == ("7b32ab049fda8a37b8d49a1bd6ebc332f8f98152db59d4ca35df149d0053ede1",
                         "c51fb2d3d12862edef0055fd1ecba8e6ab7083d06fcb9dca35bf00fd892a30c8")
    assert not any(p[0].startswith(("4de81568", "9c8426db")) for p in pairs)
    # the gate reads the report
    assert "check_initializer_qualification" in (INSTALLER / "ci" / "qualify.py").read_text()
