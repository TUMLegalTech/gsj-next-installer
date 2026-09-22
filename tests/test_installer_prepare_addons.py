"""prepare-addons.py's output guard: a previous preparation is admitted (its
own inventory.json included), a foreign file is refused, before any download."""
import importlib.util
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "ops/installer/prepare-addons.py"
_spec = importlib.util.spec_from_file_location("gsj_prepare_addons", SCRIPT)
prepare_addons = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(prepare_addons)
PAYLOADS = [item[0] for item in prepare_addons.SOURCES.values()]


class _Fetched(Exception):
    """Raised by the stubbed download: the guard admitted the directory."""


def _run(monkeypatch, output):
    monkeypatch.setattr(sys, "argv", ["prepare-addons.py", "--output", str(output)])
    def fetch(*args, **kwargs):
        raise _Fetched(args[0][:2])
    monkeypatch.setattr(prepare_addons.subprocess, "run", fetch)
    prepare_addons.main()


@pytest.mark.parametrize("state", ["absent", "empty", "previous-preparation", "partial"])
def test_the_guard_admits_an_absent_empty_partial_or_previous_output(tmp_path, monkeypatch, state):
    output = tmp_path / "addons"
    if state != "absent":
        output.mkdir()
    if state == "previous-preparation":
        for name in [*PAYLOADS, "inventory.json"]:
            (output / name).write_bytes(b"bytes of " + name.encode())
    if state == "partial":
        (output / PAYLOADS[0]).write_bytes(b"a partial fetch")
    with pytest.raises(_Fetched) as fetched:
        _run(monkeypatch, output)
    assert fetched.value.args[0] == ["curl", "--fail"], "the guard passed and the first download began"


def test_a_foreign_file_in_the_output_is_refused_before_any_download(tmp_path, monkeypatch, capsys):
    output = tmp_path / "addons"
    output.mkdir()
    (output / "notes.txt").write_text("not an addon\n")
    with pytest.raises(SystemExit) as stopped:
        _run(monkeypatch, output)
    assert stopped.value.code == 2
    assert "only these fixed addon files and inventory.json" in capsys.readouterr().err
