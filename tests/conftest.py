"""Collection policy: the installer's tests run everywhere; the ones that need
the pinned product (its installed package, or its Git objects) are skipped
where it is absent, never failed at import.

The generated installer needs no Python. The tests do: the product package
`gsj-web` (gsj_deploy, gsj_web, agent_runner) and its library `gsj`, both at
the pins in requirements-local.txt, plus a Git directory carrying the pinned
product commit for the chart. A public CI runner has neither (the product is
private), so those modules are ignored there and the README says which.
"""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Modules whose IMPORT needs the product package (gsj_deploy / gsj / httpx
# helpers that import it). Everything else imports only the standard library,
# pytest, PyYAML (in the regression requirements) and the installer's own files.
NEEDS_PRODUCT_PACKAGE = [
    "test_installer_capacity.py",          # from gsj_deploy import backup
    "test_installer_restore_files.py",     # from gsj_deploy import backup
    "test_installer_startup_runtime.py",   # from gsj_deploy import corpus
    "test_installer_startup_source.py",    # from gsj import ports, store; gsj_deploy
    "test_release_fixture.py",             # loads ci/fixture.py: gsj_deploy.verify
]

collect_ignore = []
if importlib.util.find_spec("gsj_deploy") is None:
    collect_ignore += NEEDS_PRODUCT_PACKAGE


# The runtime resolves every host a site names (its LLM, OCR, allowed origins
# and proxies) with `getent ahosts` on the machine it runs on, so every test
# that compiles a site would otherwise ask the real resolver about
# llm.example and its kin. This session-wide fixture puts a synthetic
# resolver first on PATH, like the synthetic cluster the fake kubectl is: an
# IP literal answers with itself, any other name with one address derived
# from its spelling (203.0.113.0/24, the documentation range), and nothing
# for a name under .invalid or, when a test's kubectl state names them, in
# its "unresolvable" list; every name asked is recorded in that state.
import os
import pytest
import tempfile

_SYNTHETIC_GETENT = """#!/usr/bin/env python3
import ipaddress, json, os, pathlib, sys
a = sys.argv[1:]
if a[:1] != ["ahosts"] or len(a) != 2: sys.exit(1)
name = a[1]
state = os.environ.get("TEST_KUBECTL_STATE")
s = json.loads(pathlib.Path(state).read_text()) if state and os.path.exists(state) else {}
if state and os.path.exists(state):
    s.setdefault("resolved", []).append(name); pathlib.Path(state).write_text(json.dumps(s))
try:
    ip = ipaddress.ip_address(name); print(f"{ip} STREAM {name}"); sys.exit(0)
except ValueError: pass
if name.endswith(".invalid") or name in s.get("unresolvable", []): sys.exit(2)
n = sum(name.encode()) % 200 + 10
print(f"203.0.113.{n} STREAM {name}"); print(f"203.0.113.{n} DGRAM {name}")
"""


@pytest.fixture(scope="session", autouse=True)
def synthetic_resolver():
    directory = tempfile.mkdtemp(prefix="gsj-synthetic-resolver-")
    getent = Path(directory) / "getent"
    getent.write_text(_SYNTHETIC_GETENT)
    getent.chmod(0o755)
    previous = os.environ.get("PATH", "")
    os.environ["PATH"] = directory + os.pathsep + previous
    yield
    os.environ["PATH"] = previous
