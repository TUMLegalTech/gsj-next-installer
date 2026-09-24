#!/usr/bin/env python3
"""The full run: every test in this repository, nothing skipped, nothing excluded.

The public CI (.github/workflows/tests.yml) cannot run the whole suite. The
product is private, so the modules that import it are ignored there
(tests/conftest.py) and the tests that read the pinned Git objects, the product
package or the staged add-on archives skip -- and those include security checks
(archive corruption after verification, foreign ownership, damaged or wrongly
bound sources, image and namespace drift, credential-URL agreement, the pin's
digests and the contract). Releases are hand-run, so the full run is the
release's first step, and this script makes it mechanical:

  - it refuses to START when a prerequisite it knows is missing: the four
    packages (gsj_deploy, gsj_web, agent_runner, gsj), a chromadb-client still
    installed, a Git directory carrying the pinned product commit, bash, jq
    and openssl on PATH, THE ENGINEERED HELM -- the catalog's exact version
    (ops/installer/clients.json), since two modules render releases offline,
    which Helm 3 cannot do, and a gate that can pass on the wrong client is
    not a gate -- the two staged add-on archives, an interpreter that is not
    X.509-strict, a missing system CA bundle -- the verdict, not this list, is
    the authority: a skip the list did not foresee still fails the run;
  - it names every tests/test_*.py file to pytest explicitly, so a module the
    conftest would ignore is a collection error, never a silent omission;
  - it FAILS on any skip, xfail, xpass, deselection, collection error, failure,
    or test file that contributed no test;
  - it writes a report (gsj.full-suite/1) naming the installer commit, the
    product pin, the counts and every file's item count.

Engineering tool only; the generated installer never needs it.
"""
import argparse
import importlib.metadata
import importlib.util
import json
from pathlib import Path
import platform
import re
import shutil
import ssl
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
_spec = importlib.util.spec_from_file_location("gsj_installer_webpin", ROOT / "ops/installer/webpin.py")
webpin = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(webpin)
ADDONS = ROOT / "ops/.build/installer-addons"
ADDON_FILES = ("traefik-41.5.0.tgz", "cert-manager-v1.21.2.tgz")     # the two the add-on tests read
PRODUCT_PACKAGES = ("gsj_deploy", "gsj_web", "agent_runner", "gsj")
TOOLS = ("bash", "jq", "openssl")
CLIENTS = ROOT / "ops/installer/clients.json"


def engineered_helm_version():
    """The Helm this suite is engineered for: the catalog's, read off its
    download name (ops/installer/clients.json is the one place the pin lives)."""
    catalog = json.loads(CLIENTS.read_text())
    url = next(iter(catalog["helm"].values()))["url"]
    return re.search(r"helm-(v\d+\.\d+\.\d+)-", url).group(1)


def helm_version_found():
    """The Helm on PATH, as `helm version --short` reports it (vX.Y.Z), or
    None when there is none or it reports no version."""
    if shutil.which("helm") is None:
        return None
    try:
        out = subprocess.run(["helm", "version", "--short"], capture_output=True, text=True, timeout=20).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    match = re.match(r"v?(\d+\.\d+\.\d+)", out.strip())
    return "v" + match.group(1) if match else None
CA_BUNDLES = ("/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/cert.pem")


def missing_prerequisites():
    """The prerequisites this check knows -- each one a skip or a setup error
    the suite has produced -- so the run is refused before it starts rather
    than found short at its end. The verdict stays the authority: a skip this
    list did not foresee still fails the run."""
    missing = []
    for name in PRODUCT_PACKAGES:
        if importlib.util.find_spec(name) is None:
            missing.append(f"the package `{name}` is not importable (README: install requirements-local.txt into .venv)")
    try:
        importlib.metadata.distribution("chromadb-client")
        missing.append("chromadb-client is installed; it shadows the embedded chromadb the Chroma fixtures open "
                       "(README: uninstall it, then reinstall chromadb==1.5.9)")
    except importlib.metadata.PackageNotFoundError:
        pass
    if not webpin.available():
        missing.append("no Git directory here carries the pinned gsj-next-web commit (README: the ../gsj-next-web sibling, "
                       "ops/.build/gsj-next-web.git, or GSJ_NEXT_WEB_GIT_DIR)")
    for tool in TOOLS:
        if shutil.which(tool) is None:
            missing.append(f"`{tool}` is not on PATH")
    # review finding B3: the gate admitted any helm -- Helm 3.22, a fake reporting
    # v0.0.1 -- and under Helm 3 two modules failed on the offline render
    # only Helm 4 performs. The client is the catalog's exact version, named
    # beside what was found.
    engineered, found = engineered_helm_version(), helm_version_found()
    if found != engineered:
        missing.append(f"`helm` on PATH is {found or 'absent, or reports no version'}, not the engineered client {engineered} this suite runs "
                       f"under (ops/installer/clients.json; the add-on and application modules render releases offline, which only Helm 4 does): "
                       f"put {engineered} first on PATH, e.g. python3 -B ops/installer/ci/release.py clients --output DIR")
    for name in ADDON_FILES:
        if not (ADDONS / name).is_file():
            missing.append(f"the add-on archive {ADDONS.relative_to(ROOT) / name} is not staged "
                           "(README: mkdir -p ops/.build && rm -rf ops/.build/installer-addons, then python3 -B ops/installer/prepare-addons.py --output ops/.build/installer-addons)")
    if not ssl.create_default_context().verify_flags & ssl.VERIFY_X509_STRICT:
        missing.append("this interpreter is not X.509-strict by default (Python 3.13 or newer is); two tests skip on it")
    if not any(Path(p).is_file() for p in CA_BUNDLES):
        missing.append("no system CA bundle at any of " + ", ".join(CA_BUNDLES) + "; one test skips without it")
    return missing


def suites():
    return sorted(p.name for p in (ROOT / "tests").glob("test_*.py"))


class Results:
    """Every outcome pytest reports, counted; collection-level skips and errors included."""

    def __init__(self):
        self.collected = self.passed = self.failed = self.skipped = self.xfailed = self.xpassed = self.deselected = self.errors = 0
        self.per_file = {}

    def pytest_collection_finish(self, session):
        self.collected = len(session.items)
        for item in session.items:
            name = Path(str(item.fspath)).name
            self.per_file[name] = self.per_file.get(name, 0) + 1

    def pytest_deselected(self, items):
        self.deselected += len(items)

    def pytest_collectreport(self, report):
        if report.skipped:
            self.skipped += 1
        elif report.failed:
            self.errors += 1

    def pytest_runtest_logreport(self, report):
        if hasattr(report, "wasxfail"):
            if report.skipped:
                self.xfailed += 1
            elif report.passed and report.when == "call":
                self.xpassed += 1
        elif report.skipped:
            self.skipped += 1
        elif report.failed:
            self.failed += 1
        elif report.when == "call" and report.passed:
            self.passed += 1


def verdict(results, files, rc):
    """The reasons a run is not the full run; empty means it is."""
    reasons = []
    if rc != 0:
        reasons.append(f"pytest exited {rc}")
    for name in files:
        if results.per_file.get(name, 0) == 0:
            reasons.append(f"{name} contributed no test (ignored, empty or failed to collect)")
    for label in ("skipped", "xfailed", "xpassed", "deselected", "errors", "failed"):
        if getattr(results, label):
            reasons.append(f"{label}: {getattr(results, label)}")
    if results.collected == 0:
        reasons.append("nothing was collected")
    elif results.passed != results.collected:
        reasons.append(f"passed {results.passed} of {results.collected} collected")
    return reasons


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--report", type=Path, help="write the gsj.full-suite/1 report here (create-only)")
    parser.add_argument("--check-only", action="store_true", help="only check the prerequisites; run nothing")
    args = parser.parse_args()
    missing = missing_prerequisites()
    if missing:
        print("the full run cannot start; it would skip or exclude tests:", file=sys.stderr)
        for line in missing:
            print("  - " + line, file=sys.stderr)
        return 2
    if args.check_only:
        print("every prerequisite of the full run is present")
        return 0
    if args.report and args.report.exists():
        parser.error(f"{args.report} exists; the report is create-only")
    import pytest
    results = Results()
    files = suites()
    rc = pytest.main(["-q", "-rs", "-p", "no:cacheprovider", *("tests/" + name for name in files)], plugins=[results])
    reasons = verdict(results, files, rc)
    pin = webpin.load()
    report = {"schema": "gsj.full-suite/1", "status": "passed" if not reasons else "failed", "reasons": reasons,
              "installer_commit": subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip(),
              "installer_dirty": bool(subprocess.check_output(["git", "-C", str(ROOT), "status", "--porcelain", "--untracked-files=all"], text=True).strip()),
              "product_commit": pin["commit"], "product_release": pin["release"], "core_tag": pin["core"]["tag"],
              "platform": platform.platform(), "python": platform.python_version(), "pytest": pytest.__version__,
              "helm": helm_version_found(),
              "collected": results.collected, "passed": results.passed, "failed": results.failed, "skipped": results.skipped,
              "xfailed": results.xfailed, "xpassed": results.xpassed, "deselected": results.deselected, "errors": results.errors,
              "files": {name: results.per_file.get(name, 0) for name in files}}
    if args.report:
        with args.report.open("x") as output:
            json.dump(report, output, sort_keys=True, indent=2)
            output.write("\n")
    print(json.dumps({k: report[k] for k in ("status", "collected", "passed", "skipped", "errors", "reasons")}, sort_keys=True))
    return 0 if not reasons else 1


if __name__ == "__main__":
    sys.exit(main())
