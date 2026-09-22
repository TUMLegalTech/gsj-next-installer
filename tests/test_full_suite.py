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
