"""prepare-addons.py writes only into a directory it created or that this user
plainly owns, never through a link, and refuses everything else by name
before any write.

The reproduction: an `inventory.json` that is a symlink to a file
elsewhere. The previous guard admitted the name, and the write at the end
replaced the link's TARGET. Downloads are stubbed here (fixed bytes with their
real hashes), so the run reaches its writes without the network."""
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import sys
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "ops/installer/prepare-addons.py"
_spec = importlib.util.spec_from_file_location("gsj_prepare_addons", SCRIPT)
prepare_addons = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(prepare_addons)
REAL_PAYLOADS = [item[0] for item in prepare_addons.SOURCES.values()]


@pytest.fixture
def stubbed(monkeypatch):
    """Two synthetic add-ons whose 'downloads' are fixed bytes; the run then
    writes exactly `a.tgz`, `b.tgz` and `inventory.json`."""
    bytes_by_url = {"https://example.test/a.tgz": b"synthetic addon a\n", "https://example.test/b.tgz": b"synthetic addon b\n"}
    sources = {"traefik": ("a.tgz", "https://example.test/a.tgz", hashlib.sha256(bytes_by_url["https://example.test/a.tgz"]).hexdigest()),
               "certManager": ("b.tgz", "https://example.test/b.tgz", hashlib.sha256(bytes_by_url["https://example.test/b.tgz"]).hexdigest())}
    monkeypatch.setattr(prepare_addons, "SOURCES", sources)
    monkeypatch.setattr(prepare_addons, "PAYLOADS", frozenset(item[0] for item in sources.values()), raising=False)  # absent before the fix
    monkeypatch.setattr(prepare_addons.subprocess, "run", lambda args, **kw: SimpleNamespace(stdout=bytes_by_url[args[-1]]))
    return bytes_by_url


def _run(monkeypatch, output):
    monkeypatch.setattr(sys, "argv", ["prepare-addons.py", "--output", str(output)])
    prepare_addons.main()


def _refused(monkeypatch, output, capsys):
    with pytest.raises(SystemExit) as stopped:
        _run(monkeypatch, output)
    assert stopped.value.code == 2
    return capsys.readouterr().err


def test_a_symlinked_inventory_is_refused_by_name_and_its_target_untouched(stubbed, tmp_path, monkeypatch, capsys):
    """THE REPRODUCTION. A pre-seeded output directory whose
    inventory.json is a symlink to a sentinel file elsewhere: the run must be
    refused before any write, and the sentinel must be byte-identical."""
    sentinel = tmp_path / "elsewhere" / "sentinel"
    sentinel.parent.mkdir()
    sentinel.write_bytes(b"the sentinel's own bytes\n")
    output = tmp_path / "addons"
    output.mkdir(mode=0o700)
    (output / "inventory.json").symlink_to(sentinel)
    try:
        _run(monkeypatch, output)
        refused = False
    except SystemExit as stopped:
        refused = stopped.code == 2
    assert sentinel.read_bytes() == b"the sentinel's own bytes\n", "the write followed the link and replaced the sentinel"
    assert refused, "the run was not refused"
    assert "inventory.json" in capsys.readouterr().err
    assert sorted(p.name for p in output.iterdir()) == ["inventory.json"], "something was written before the refusal"


@pytest.mark.parametrize("target", ["dangling", "existing"])
def test_a_symlinked_payload_name_dangling_or_not_is_refused(stubbed, tmp_path, monkeypatch, capsys, target):
    output = tmp_path / "addons"
    output.mkdir(mode=0o700)
    if target == "dangling":
        (output / "a.tgz").symlink_to(tmp_path / "nowhere")      # exists() is False: a plain write would create the target
    else:
        (tmp_path / "elsewhere").write_bytes(b"another file's bytes\n")
        (output / "a.tgz").symlink_to(tmp_path / "elsewhere")    # exists() is True: a plain compare-or-write would read or replace it
    err = _refused(monkeypatch, output, capsys)
    assert "a.tgz is not a plain file" in err, err
    assert not (tmp_path / "nowhere").exists()
    if target == "existing":
        assert (tmp_path / "elsewhere").read_bytes() == b"another file's bytes\n"


def test_a_symlinked_ancestor_of_another_users_is_refused_but_this_users_is_not(stubbed, tmp_path, monkeypatch, capsys):
    """Another local user's symlink higher up the path (a shared /tmp) would
    carry the output elsewhere: refused by name. This user's own symlink is
    the path as intended (root's system links -- macOS's /tmp and /var -- are
    admitted by the same rule; the documented `mktemp -d` recipe runs through
    one)."""
    if os.geteuid() == 0:
        pytest.skip("the uid move below needs a non-root euid: root's own symlinks are admitted by the rule")
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    link = tmp_path / "planted"
    link.symlink_to(real)
    output = link / "addons"
    _run(monkeypatch, output)                              # this user's own symlink: admitted
    assert (real / "addons" / "inventory.json").is_file()
    owner = os.lstat(link).st_uid
    (real / "other").mkdir(mode=0o700)                    # really this user's; the moved uid below only changes what the checks see
    monkeypatch.setattr(os, "geteuid", lambda: owner + 1)
    err = _refused(monkeypatch, link / "other", capsys)
    assert f"{link} is a symlink owned by uid {owner}, neither root nor this user" in err, err
    assert list((real / "other").iterdir()) == []


def test_a_missing_parent_is_not_created(stubbed, tmp_path, monkeypatch, capsys):
    err = _refused(monkeypatch, tmp_path / "absent" / "addons", capsys)
    assert "does not exist (this run creates only the output directory itself)" in err, err
    assert not (tmp_path / "absent").exists()


def test_a_symlinked_output_directory_is_refused(stubbed, tmp_path, monkeypatch, capsys):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "addons"
    link.symlink_to(real)
    err = _refused(monkeypatch, link, capsys)
    assert "it is a symlink" in err, err
    assert list(real.iterdir()) == []


def test_a_directory_owned_by_another_user_is_refused(stubbed, tmp_path, monkeypatch, capsys):
    """This user cannot create a directory owned by someone else, so the
    check's notion of 'this user' is moved instead: the directory, really
    owned by us, then reads as another user's."""
    output = tmp_path / "addons"
    output.mkdir(mode=0o700)
    monkeypatch.setattr(os, "geteuid", lambda: os.getuid() + 1)
    err = _refused(monkeypatch, output, capsys)
    assert f"owned by uid {os.getuid()}, not by this user" in err, err
    assert list(output.iterdir()) == []


def test_a_group_or_world_writable_directory_is_refused(stubbed, tmp_path, monkeypatch, capsys):
    output = tmp_path / "addons"
    output.mkdir(mode=0o777)
    os.chmod(output, 0o777)
    err = _refused(monkeypatch, output, capsys)
    assert "writable by group or others" in err, err


def test_a_foreign_file_in_the_output_is_refused_before_any_download(tmp_path, monkeypatch, capsys):
    """Without the download stub: the refusal comes before the first curl."""
    monkeypatch.setattr(prepare_addons.subprocess, "run", lambda *a, **k: pytest.fail("a download began after a refusal was due"))
    output = tmp_path / "addons"
    output.mkdir(mode=0o700)
    (output / "notes.txt").write_text("not an addon\n")
    err = _refused(monkeypatch, output, capsys)
    assert "it holds notes.txt" in err, err


def test_a_fresh_run_creates_a_private_directory_and_writes_plain_files(stubbed, tmp_path, monkeypatch):
    output = tmp_path / "addons"
    _run(monkeypatch, output)
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    for name, content in (("a.tgz", b"synthetic addon a\n"), ("b.tgz", b"synthetic addon b\n")):
        assert (output / name).read_bytes() == content and not (output / name).is_symlink()
    assert (output / "inventory.json").is_file() and not (output / "inventory.json").is_symlink()


def test_a_second_run_over_the_same_directory_is_refused_the_recipe_removes_it_first(stubbed, tmp_path, monkeypatch, capsys):
    output = tmp_path / "addons"
    _run(monkeypatch, output)
    err = _refused(monkeypatch, output, capsys)
    assert "it holds inventory.json" in err, err


def test_a_partial_fetch_of_this_users_plain_files_resumes(stubbed, tmp_path, monkeypatch):
    output = tmp_path / "addons"
    output.mkdir(mode=0o700)
    (output / "a.tgz").write_bytes(b"synthetic addon a\n")
    _run(monkeypatch, output)
    assert (output / "b.tgz").read_bytes() == b"synthetic addon b\n" and (output / "inventory.json").is_file()


def test_a_partial_fetch_with_different_bytes_is_refused_without_replacing_it(stubbed, tmp_path, monkeypatch):
    output = tmp_path / "addons"
    output.mkdir(mode=0o700)
    (output / "a.tgz").write_bytes(b"other bytes\n")
    with pytest.raises(ValueError, match="refusing to replace a different existing addon payload"):
        _run(monkeypatch, output)
    assert (output / "a.tgz").read_bytes() == b"other bytes\n"


def test_the_real_payload_names_are_the_admitted_ones():
    assert prepare_addons.PAYLOADS == frozenset(REAL_PAYLOADS)
    assert "inventory.json" not in prepare_addons.PAYLOADS
