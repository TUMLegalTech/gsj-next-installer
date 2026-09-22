"""The pinned product, for tests: read from Git objects at web-pin.json's commit.

Nothing here reads a working tree. `chart()` materializes the pinned chart
once per process; `show()` returns one pinned file's bytes. Tests that need
the pinned product declare `needs_web`, which skips them cleanly when no Git
directory here carries the commit (README: how to stage one). The full suite,
run by a maintainer with the siblings in place, skips nothing.
"""
import atexit
import importlib.util
from pathlib import Path
import tempfile

import pytest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("gsj_installer_webpin", ROOT / "ops/installer/webpin.py")
webpin = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(webpin)

PIN = webpin.load()
AVAILABLE = webpin.available()
needs_web = pytest.mark.skipif(
    not AVAILABLE, reason="the pinned gsj-next-web commit is in no Git directory here (see README, Building and testing)")

_materialized = None


def chart() -> Path:
    """The pinned chart directory, materialized once per test process."""
    global _materialized
    if _materialized is None:
        _materialized = tempfile.TemporaryDirectory(prefix="gsj-pinned-web-")
        atexit.register(_materialized.cleanup)
        webpin.archive("chart", Path(_materialized.name), PIN)
    return Path(_materialized.name) / "chart"


def show(path: str) -> bytes:
    return webpin.show(path, PIN)


def tree(path: str) -> str:
    return webpin.tree(path, PIN)
