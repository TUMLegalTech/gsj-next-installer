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
