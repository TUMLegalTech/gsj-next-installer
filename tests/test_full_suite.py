"""ci/full-suite.py -- the release's first step: the full run with nothing
skipped and nothing excluded, decided mechanically."""
import importlib.util
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "ops/installer/ci/full-suite.py"
_spec = importlib.util.spec_from_file_location("gsj_full_suite", SCRIPT)
full_suite = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(full_suite)


def _results(**counts):
    results = full_suite.Results()
    results.per_file = counts.pop("per_file", {})
    for name, value in counts.items():
        setattr(results, name, value)
    return results


def test_a_complete_run_is_the_full_run():
    results = _results(collected=3, passed=3, per_file={"test_a.py": 2, "test_b.py": 1})
    assert full_suite.verdict(results, ["test_a.py", "test_b.py"], 0) == []


@pytest.mark.parametrize("fault,expected", [
    ({"skipped": 1}, "skipped: 1"),
    ({"xfailed": 1}, "xfailed: 1"),
    ({"xpassed": 1}, "xpassed: 1"),
    ({"deselected": 2}, "deselected: 2"),
    ({"errors": 1}, "errors: 1"),
    ({"failed": 1}, "failed: 1"),
    ({"per_file": {"test_a.py": 3}}, "test_b.py contributed no test"),
    ({"passed": 2}, "passed 2 of 3 collected"),
    ({"collected": 0, "passed": 0, "per_file": {}}, "nothing was collected"),
])
def test_anything_short_of_every_test_passing_is_not_the_full_run(fault, expected):
    """A skip, an expected failure, a deselection, a collection error, a
    failure, a file that contributed nothing, or a count that does not add up:
    each is a named reason, and a run with a reason fails."""
    counts = {"collected": 3, "passed": 3, "per_file": {"test_a.py": 2, "test_b.py": 1}}
    counts.update(fault)
    reasons = full_suite.verdict(_results(**counts), ["test_a.py", "test_b.py"], 0)
    assert any(expected in reason for reason in reasons), reasons


def test_a_nonzero_pytest_exit_is_a_reason_of_its_own():
    results = _results(collected=1, passed=1, per_file={"test_a.py": 1})
    assert full_suite.verdict(results, ["test_a.py"], 2) == ["pytest exited 2"]


def test_the_suite_list_is_every_test_file_in_the_tree_including_this_one():
    files = full_suite.suites()
    assert files == sorted(p.name for p in (ROOT / "tests").glob("test_*.py"))
    assert "test_full_suite.py" in files


def test_check_only_names_what_is_missing_or_confirms_every_prerequisite():
    """In the maintainer's environment every prerequisite is present and the
    check says so; anywhere else it names each absent one and exits 2 without
    running a test. Both outcomes are asserted against what THIS environment
    has, so the test holds wherever it runs."""
    result = subprocess.run([sys.executable, "-B", str(SCRIPT), "--check-only"], capture_output=True, text=True)
    missing = full_suite.missing_prerequisites()
    if missing:
        assert result.returncode == 2, result.stderr
        assert "the full run cannot start" in result.stderr
        for line in missing:
            assert line in result.stderr
    else:
        assert result.returncode == 0, result.stderr
        assert "every prerequisite of the full run is present" in result.stdout


def test_an_explicitly_named_file_is_collected_despite_collect_ignore(tmp_path):
    """The script names every test file to pytest explicitly because
    conftest's `collect_ignore` applies only while pytest recurses into a
    directory: a file named on the command line is collected, and an ignored
    file that cannot be imported (the shape of this repository's ignores: the
    modules that import the absent product) is then a collection ERROR, never
    a silent omission. Pinned here against the installed pytest, since the
    script's whole claim rests on it."""
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "conftest.py").write_text('collect_ignore = ["test_ignored.py", "test_broken.py"]\n')
    (tests / "test_kept.py").write_text("def test_kept():\n    pass\n")
    (tests / "test_ignored.py").write_text("def test_ignored():\n    pass\n")
    (tests / "test_broken.py").write_text("import a_package_that_is_absent\n")
    pytest_cmd = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"]
    by_directory = subprocess.run([*pytest_cmd, "tests"], cwd=tmp_path, capture_output=True, text=True)
    by_name = subprocess.run([*pytest_cmd, "tests/test_kept.py", "tests/test_ignored.py"], cwd=tmp_path, capture_output=True, text=True)
    by_broken = subprocess.run([*pytest_cmd, "tests/test_broken.py"], cwd=tmp_path, capture_output=True, text=True)
    assert "1 passed" in by_directory.stdout, by_directory.stdout      # the directory walk honours both ignores
    assert "2 passed" in by_name.stdout, by_name.stdout                # the explicit names do not
    assert by_broken.returncode != 0 and "test_broken.py" in by_broken.stdout and "error" in by_broken.stdout.lower(), by_broken.stdout


def _fake_helm(tmp_path, version):
    """A `helm` on PATH that reports the given version and nothing else."""
    bindir = tmp_path / "bin"; bindir.mkdir(exist_ok=True)
    fake = bindir / "helm"
    fake.write_text("#!/bin/sh\n[ \"$1\" = version ] && { echo " + version + "; exit 0; }\nexit 1\n")
    fake.chmod(0o755)
    return bindir


def test_the_gate_refuses_any_helm_but_the_engineered_client(tmp_path, monkeypatch):
    """Review finding B3: the gate checked only that `helm` was on
    PATH -- it accepted Helm 3.22 and a fake client reporting v0.0.1, and
    under Helm 3 two modules gave 27 failures (Helm 3 attempts cluster
    discovery for the offline render Helm 4.2.2 performs without a cluster).
    The gate now refuses, before collection, any client other than the one
    it is engineered for -- the catalog's (ops/installer/clients.json) --
    naming both versions."""
    engineered = full_suite.engineered_helm_version()
    assert engineered == "v4.2.2"
    for found in ("v0.0.1+gdeadbee", "v3.22.0+g144ca65", "v3.13.3+gc8b9489", "v4.2.1+g0000000",
                  # review finding: a pre-release of the engineered version is not it --
                  # the parser once read v4.2.2-rc.1+g1234567 as v4.2.2
                  "v4.2.2-rc.1+g1234567", "v4.2.2-rc.1", "v4.2.2.1+gabcdef0"):
        monkeypatch.setenv("PATH", str(_fake_helm(tmp_path, found)) + ":/usr/bin:/bin")
        lines = [line for line in full_suite.missing_prerequisites() if "helm" in line]
        assert lines, found
        assert found.split("+")[0] in lines[0] and engineered in lines[0], lines[0]
        assert "clients.json" in lines[0]
    # the exact release, with or without Helm's build metadata, is the engineered client
    for found in ("v4.2.2+gb05881c", "v4.2.2"):
        monkeypatch.setenv("PATH", str(_fake_helm(tmp_path, found)) + ":/usr/bin:/bin")
        assert full_suite.helm_version_found() == "v4.2.2", found
    # the engineered client itself: no helm line
    monkeypatch.setenv("PATH", str(_fake_helm(tmp_path, "v4.2.2+gb05881c")) + ":/usr/bin:/bin")
    assert not [line for line in full_suite.missing_prerequisites() if "helm" in line]
    # no helm at all: still named, with the engineered version
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    lines = [line for line in full_suite.missing_prerequisites() if "helm" in line]
    assert lines and engineered in lines[0]


def test_the_gate_names_every_failure_in_its_short_summary():
    """The gate ran pytest with `-rs`, so its log named the skips
    and not the failures -- one red of a 1,819-test run was counted and never
    named. `-ra` prints every failure, error, skip and xfail by id."""
    source = (ROOT / "ops/installer/ci/full-suite.py").read_text()
    call = source[source.index("pytest.main(["):source.index("], plugins=[results])")]
    assert '"-ra"' in call and '"-rs"' not in call, call
