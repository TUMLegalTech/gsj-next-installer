#!/usr/bin/env python3
"""Isolated engineering release regressions; never an operator dependency."""
import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import subprocess

from release import clients, download, webpin

ROOT = Path(__file__).resolve().parents[3]
ADDONS = {
    "traefik-41.5.0.tgz": {
        "url": "https://traefik.github.io/charts/traefik/traefik-41.5.0.tgz",
        "sha256": "30f8db73182019b2764179d7fc0a7efc9505670204f847ffc3a779bacaae3a1a"},
    "cert-manager-v1.21.2.tgz": {
        "url": "https://charts.jetstack.io/charts/cert-manager-v1.21.2.tgz",
        "sha256": "73a56e1728edd6c99f1f31082618c3259d279a76b7ebd3d4bdc5475c2442d34a"},
}
# Enumerate the whole tests/ tree, never a hand-kept list. The list
# named 48 files while 76 existed - it omitted the restore-program suite and
# every door/runner suite (admin, authz, agent_runner, case_delete, events,
# hardening, identity...), so an "isolated regression" silently skipped them.
# Enumerating the directory cannot drift, and a suite removed with its subject
# disappears from the run without an edit here.
def suites():
    return sorted(p.name for p in (ROOT / "tests").glob("test_*.py"))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prepare(directory):
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"}:
        raise ValueError("public release regression preparation requires native Linux amd64")
    clients(directory, ("helm", "jq"))
    target = ROOT / "ops/.build/installer-addons"
    target.mkdir(parents=True, exist_ok=True)
    for name, item in ADDONS.items():
        path = target / name
        if path.exists():
            if digest(path) != item["sha256"]:
                raise ValueError("staged regression addon checksum differs")
        else:
            download(item, path, allow_public_redirects=True)


def run(report):
    # The hand-run harness enters a fresh network namespace with loopback only
    # before calling this.
    # Synthetic TLS/proxy tests may bind localhost; external access is absent.
    interfaces = sorted(line.split(":", 1)[0].strip()
                        for line in Path("/proc/net/dev").read_text().splitlines() if ":" in line)
    if platform.system() != "Linux" or interfaces != ["lo"]:
        raise ValueError("release regressions require an isolated loopback-only network namespace")
    os.chdir(ROOT)
    os.environ.update(HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1",
                      HF_HUB_DISABLE_TELEMETRY="1", ANONYMIZED_TELEMETRY="False",
                      PYTHONDONTWRITEBYTECODE="1", KUBECONFIG="/nonexistent/gsj-regression-kubeconfig",
                      DOCKER_HOST="unix:///nonexistent/gsj-regression-docker.sock")
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        os.environ.pop(name, None)
    os.environ["NO_PROXY"] = os.environ["no_proxy"] = "localhost,127.0.0.1,::1"
    import pytest

    class Results:
        passed = failed = skipped = collected = 0

        def pytest_collection_finish(self, session):
            self.collected = len(session.items)

        def pytest_collectreport(self, report):
            if report.skipped:
                self.skipped += 1
            elif report.failed:
                self.failed += 1

        def pytest_runtest_logreport(self, report):
            if report.skipped:
                self.skipped += 1
            elif report.failed:
                self.failed += 1
            elif report.when == "call" and report.passed:
                self.passed += 1

    results = Results()
    tests = ["tests/" + name for name in suites()]
    rc = pytest.main(["-q", "-p", "no:cacheprovider", *tests], plugins=[results])
    passed = rc == 0 and results.collected > 0 and results.passed == results.collected and not results.skipped
    # The product and its library are installed at their pins; the regression
    # binds the installer commit, the product commit and the library commit.
    pin = webpin.load()
    product = json.loads(importlib.metadata.distribution("gsj-web").read_text("direct_url.json"))["vcs_info"]
    core = json.loads(importlib.metadata.distribution("gsj").read_text("direct_url.json"))["vcs_info"]
    if product.get("commit_id") != pin["commit"]:
        raise ValueError("the installed product distribution is not at web-pin.json's commit")
    source = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    files = [ROOT / "ops/installer/runtime.sh", ROOT / "web-pin.json", Path(__file__),
             Path(__file__).with_name("regression-requirements.txt")]
    files += sorted(p for p in (ROOT / "ops/installer").iterdir() if p.is_file())
    files += [ROOT / test.split("::")[0] for test in tests]
    value = {"schema": "gsj.isolated-regression/1", "status": "passed" if passed else "failed",
             "installer_commit": source, "product_commit": pin["commit"],
             "product": product, "core": core, "web_pin": {"chart": pin["chart"], "gsj_deploy": pin["gsj_deploy"]},
             "network_interfaces": interfaces,
             "external_network_disabled": True, "tests": tests, "collected": results.collected,
             "passed": results.passed, "failed": results.failed, "skipped": results.skipped,
             "source_files": {str(path.relative_to(ROOT)): digest(path) for path in files if path.is_file()}}
    with report.open("x") as output:
        json.dump(value, output, sort_keys=True, indent=2)
        output.write("\n")
    if not passed:
        raise SystemExit(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "run"))
    parser.add_argument("--tools", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    if args.command == "prepare":
        if not args.tools:
            parser.error("prepare requires --tools")
        prepare(args.tools)
    else:
        if not args.report:
            parser.error("run requires --report")
        run(args.report)


if __name__ == "__main__":
    main()
