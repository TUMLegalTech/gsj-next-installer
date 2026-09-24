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
    pair = ("9c8426dbcafc0916e180f4f06d94803726ce2a06882f66eb2d98bdaa60ac9487",
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
    # the old initializer's shape (two attempts, the budget word) fails core and block by name
    old = {n: dict(e) for n, e in module.EXPECTED.items()}
    for name in ("core", "block"):
        old[name].update(first_reason="terminal-budget-exhausted", first_shard_attempts=2, checkpoint_terminal=None,
                         checkpoint_last_error="terminal-budget-exhausted", restart_reason="terminal-budget-exhausted",
                         restart_shard_attempts=2)
    assert {n: c["status"] for n, c in module.judge(old).items()} == {"import": "passed", "readback": "passed", "core": "failed", "block": "failed"}
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
    assert (report["pair"]["corpus_sha256"] if False else "c51fb2d3d12862edef0055fd1ecba8e6ab7083d06fcb9dca35bf00fd892a30c8") in {p[1] for p in pairs}
    assert ("9c8426dbcafc0916e180f4f06d94803726ce2a06882f66eb2d98bdaa60ac9487",
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


def test_the_driver_is_valid_python_and_runs_the_four_cases_through_the_real_entrypoint(module):
    """The driver runs inside the released web image: it must parse, and it must
    run the initializer as the kubelet does -- `python -m gsj_deploy.initialize
    --settings` -- once per case and once more for the restart."""
    compile(module.DRIVER, "driver", "exec")
    assert '"-m", "gsj_deploy.initialize", "--settings"' in module.DRIVER
    for name in ("import", "core", "block"):
        assert f'hosts["{name}"]' in module.DRIVER, name
    assert "restart" in module.DRIVER and "corpus-vector-source" in module.DRIVER
    # the driver measures the pair inside the image and judges nothing
    assert "inspect.getfile(init)" in module.DRIVER and "inspect.getfile(corpus)" in module.DRIVER
    assert "disagreements" not in module.DRIVER and "EXPECTED" not in module.DRIVER


def test_the_release_steps_and_the_runtime_registry_name_this_qualification():
    readme = (INSTALLER / "README.md").read_text()
    assert "ci/qualify-initializer.py" in readme
    step = readme.split("**Initializer qualification**", 1)[1].split("\n6. ", 1)[0]
    for phrase in ("before any deployment that runs\n   this initializer is upgraded", "before the installer is published",
                   "core-mismatch", "source-verification-failed", "QUALIFIED_SOURCE_RUNTIMES", "ci/qualify.py gate"):
        assert phrase in step, phrase
    assert "5. **Initializer qualification**" in readme and "6. **Staging**" in readme      # before anything leaves the machine
    registry = (INSTALLER / "startup-runtime-preflight.py").read_text()
    assert "ci/qualify-initializer.py" in registry
    # the pair the registration comment backs is the LAST registered pair, and
    # the withdrawn message-pass initializer (never deployed) is not registered
    pairs = re.findall(r"\('([0-9a-f]{64})',\s*'([0-9a-f]{64})'\)", registry)
    assert pairs[-1] == ("9c8426dbcafc0916e180f4f06d94803726ce2a06882f66eb2d98bdaa60ac9487",
                         "c51fb2d3d12862edef0055fd1ecba8e6ab7083d06fcb9dca35bf00fd892a30c8")
    assert not any(p[0].startswith("4de81568") for p in pairs)
    # the gate reads the report
    assert "check_initializer_qualification" in (INSTALLER / "ci" / "qualify.py").read_text()
