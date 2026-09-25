"""Operation-bound restore with actual archives, SQLite, files and killed writers."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import sqlite3
import stat
import subprocess
import sys
import tarfile
import time
from types import SimpleNamespace

import pytest

from gsj_deploy import backup


HELPER = Path(__file__).resolve().parents[1] / "ops/installer/restore-files.py"
spec = importlib.util.spec_from_file_location("restore_files_helper", HELPER)
restore = importlib.util.module_from_spec(spec)
spec.loader.exec_module(restore)


@pytest.fixture
def bundle(tmp_path):
    tmp_path = tmp_path.resolve()
    sources = {}
    volumes = {}
    for role in sorted(backup.VOLUMES):
        root = tmp_path / "source" / role
        database = root / backup.SQLITE_PATHS[role]
        database.parent.mkdir(parents=True)
        with sqlite3.connect(database) as db:
            db.execute("CREATE TABLE synthetic (value TEXT)")
            db.execute("INSERT INTO synthetic VALUES (?)", (role,))
        root.chmod(0o750)
        sources[role] = str(root)
        target = tmp_path / "target" / role
        target.mkdir(parents=True)
        volumes[role] = {"name": role + "-pvc", "uid": role + "-pvc-uid", "pv_name": role + "-pv",
                         "pv_uid": role + "-pv-uid", "root": str(target)}
    source = Path(sources["gsj"])
    (source / "nested").mkdir()
    (source / "nested").chmod(0o750)          # set, never mkdir's mode: under umask 077 that made 0700, and the drift below to 0700 changed nothing
    (source / "nested" / "payload").write_bytes(b"synthetic restore sentinel\n" * 100)
    (source / "nested" / "payload").chmod(0o640)
    (source / "alias").symlink_to("nested/payload")
    # A previous operation's journal is ordinary backed-up application data.
    old = source / (".gsj-restore-" + "b" * 24)
    old.mkdir(mode=0o700)
    (old / "binding.json").write_text('{"synthetic":"prior operation"}')
    large = Path(sources["chroma"]) / "000-large"
    large.write_bytes(b"synthetic block!\n" * (256 * 1024))
    archive = tmp_path / "snapshot.tar.gz"
    proof = backup.create(archive, sources, {"release_identity": "synthetic-release", "generation": "synthetic:1", "quiesced": True})
    settings = {"format": "gsj.restore-files/1", "operation": "a" * 24,
                "archive_sha256": proof["archive_sha256"], "encrypted_archive_sha256": "e" * 64,
                "release_identity": "synthetic-release", "namespace_uid": "synthetic-namespace-uid", "volumes": volumes}
    settings_path = tmp_path / "settings.json"
    settings_path.write_text(json.dumps(settings, indent=2) + "\n"); settings_path.chmod(0o600)
    return SimpleNamespace(archive=archive, settings=settings, settings_path=settings_path,
                           sources=sources, proof=proof, tmp=tmp_path)


def run(bundle, *, event=None, settings=None, raw_sha=None):
    return restore.restore_files(bundle.archive, settings or bundle.settings,
            settings_file_sha256=raw_sha or hashlib.sha256(bundle.settings_path.read_bytes()).hexdigest(), on_event=event)


def root(bundle, role="gsj"):
    return Path(bundle.settings["volumes"][role]["root"])


def journal(bundle):
    return root(bundle) / (".gsj-restore-" + bundle.settings["operation"])


def assert_payload(bundle):
    with tarfile.open(bundle.archive) as archive:
        manifest = json.load(archive.extractfile("GSJ-BACKUP.json"))
    for record in manifest["entries"]:
        role, *parts = record["path"].split("/")
        restore.matches(root(bundle, role).joinpath(*parts), record)
    for role in backup.VOLUMES:
        with sqlite3.connect(root(bundle, role) / backup.SQLITE_PATHS[role]) as db:
            assert db.execute("SELECT value FROM synthetic").fetchall() == [(role,)]
        assert not (root(bundle, role) / (".gsj-restore-" + "a" * 24 + ".staging")).exists()


def test_complete_restore_and_replay_preserve_inventory_metadata_links_and_raw_binding(bundle):
    first = run(bundle)
    assert first["status"] == "complete" and first["restored"] is True and first["resumed"] is False
    assert first["settings_file_sha256"] == hashlib.sha256(bundle.settings_path.read_bytes()).hexdigest()
    assert first["manifest_sha256"] == bundle.proof["manifest_sha256"]
    assert first["entries"] == bundle.proof["entries"]
    assert first["capacity"]["filesystems"] == 1
    assert_payload(bundle)
    again = run(bundle)
    assert again["resumed"] is True
    assert {k: v for k, v in first.items() if k not in {"resumed", "capacity"}} == \
           {k: v for k, v in again.items() if k not in {"resumed", "capacity"}}
    assert_payload(bundle)


def test_cli_uses_exact_settings_bytes_and_logs_no_content(bundle):
    result = subprocess.run([sys.executable, "-B", str(HELPER), "--archive", str(bundle.archive),
                             "--settings", str(bundle.settings_path)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["settings_file_sha256"] == hashlib.sha256(bundle.settings_path.read_bytes()).hexdigest()
    assert "synthetic restore sentinel" not in result.stdout + result.stderr
    bundle.settings_path.write_text(json.dumps(bundle.settings))
    refused = subprocess.run([sys.executable, "-B", str(HELPER), "--archive", str(bundle.archive),
                              "--settings", str(bundle.settings_path)], capture_output=True, text=True)
    assert refused.returncode == 1 and "identity differs" in refused.stderr


@pytest.mark.parametrize("foreign", ["file", "matching", "symlink"])
def test_first_run_never_adopts_existing_payload(bundle, foreign):
    path = root(bundle) / "unowned"
    if foreign == "symlink": path.symlink_to("missing")
    elif foreign == "matching": path.write_bytes((Path(bundle.sources["gsj"]) / "nested/payload").read_bytes())
    else: path.write_bytes(b"keep foreign bytes")
    before = path.lstat()
    with pytest.raises(restore.RestoreError, match="foreign"):
        run(bundle)
    assert path.lstat().st_ino == before.st_ino
    assert not journal(bundle).exists()


@pytest.mark.parametrize("field", ["operation", "archive_sha256", "encrypted_archive_sha256", "release_identity", "namespace_uid",
                                  "name", "uid", "pv_name", "pv_uid", "raw-settings"])
def test_changed_identity_preserves_completed_payload(bundle, field):
    run(bundle)
    before = (root(bundle) / "nested/payload").read_bytes()
    changed = copy.deepcopy(bundle.settings)
    raw = None
    if field in {"name", "uid", "pv_name", "pv_uid"}: changed["volumes"]["gsj"][field] += "-changed"
    elif field == "raw-settings": raw = "f" * 64
    elif field == "operation": changed[field] = "c" * 24
    elif field.endswith("sha256"): changed[field] = "f" * 64
    else: changed[field] += "-changed"
    with pytest.raises(restore.RestoreError): run(bundle, settings=changed, raw_sha=raw)
    assert (root(bundle) / "nested/payload").read_bytes() == before


CHILD = '''import hashlib,importlib.util,json,os,signal,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location("restore_helper",sys.argv[1]); module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
raw=Path(sys.argv[3]).read_bytes()
def event(stage,detail):
 wanted=sys.argv[4].split(":")
 if stage==wanted[0] and (len(wanted)==1 or (detail.get("type")==wanted[1] and str(detail.get("step"))==wanted[2])): os.kill(os.getpid(),signal.SIGKILL)
module.restore_files(Path(sys.argv[2]),json.loads(raw),settings_file_sha256=hashlib.sha256(raw).hexdigest(),on_event=event)
'''


def killed(bundle, event):
    script = bundle.tmp / "kill-restore.py"
    script.write_text(CHILD)
    result = subprocess.run([sys.executable, "-B", str(script), str(HELPER), str(bundle.archive),
                             str(bundle.settings_path), event], capture_output=True, text=True)
    assert result.returncode == -signal.SIGKILL, result.stderr
    assert "synthetic restore sentinel" not in result.stderr


@pytest.mark.parametrize("event", ["directory-created", "temporary-created", "file-progress", "file-published",
                                   "metadata-applied", "metadata-applied:file:3", "metadata-applied:file:5",
                                   "metadata-applied:dir:1", "metadata-applied:dir:3", "metadata-applied:dir:5",
                                   "metadata-applied:symlink:1", "metadata-applied:symlink:3", "metadata-applied:symlink:5",
                                   "staging-removed", "result-published"])
def test_real_sigkill_resumes_exact_owned_prefix_or_publication(bundle, event):
    killed(bundle, event)
    assert run(bundle)["resumed"] is True
    assert_payload(bundle)


@pytest.mark.parametrize("drift", ["bytes", "inode", "mode", "extra"])
def test_interrupted_temporary_drift_is_preserved_and_refused(bundle, drift):
    killed(bundle, "file-progress")
    stage = root(bundle, "chroma") / (".gsj-restore-" + "a" * 24 + ".staging")
    path = next(stage.iterdir())
    if drift == "bytes":
        with path.open("r+b") as stream: stream.write(b"unexplained prefix")
    elif drift == "inode":
        old = path.read_bytes(); path.unlink(); path.write_bytes(old)
    elif drift == "mode": path.chmod(0o644)
    else: (stage / "unknown").write_bytes(b"foreign")
    before = {p.name: (p.lstat().st_ino, p.read_bytes(), stat.S_IMODE(p.stat().st_mode)) for p in stage.iterdir()}
    with pytest.raises(restore.RestoreError): run(bundle)
    assert before == {p.name: (p.lstat().st_ino, p.read_bytes(), stat.S_IMODE(p.stat().st_mode)) for p in stage.iterdir()}
    assert not (root(bundle) / "nested/payload").exists()


@pytest.mark.parametrize("drift", ["bytes", "mode", "mtime", "missing", "directory-mode", "directory-mtime", "extra"])
def test_completed_payload_drift_never_gets_repaired(bundle, drift):
    run(bundle)
    path = root(bundle) / "nested/payload"
    if drift == "bytes": path.write_bytes(b"foreign replacement")
    elif drift == "mode": path.chmod(0o600)
    elif drift == "mtime": os.utime(path, ns=(1, 1))
    elif drift == "missing": path.unlink()
    elif drift == "directory-mode": (root(bundle) / "nested").chmod(0o700)
    elif drift == "directory-mtime": os.utime(root(bundle) / "nested", ns=(1, 1))
    else: (root(bundle) / "foreign").write_bytes(b"foreign")
    before = path.read_bytes() if path.exists() else None
    with pytest.raises(restore.RestoreError): run(bundle)
    assert (path.read_bytes() if path.exists() else None) == before


def test_busy_cli_uses_nonblocking_process_lock(bundle):
    killed(bundle, "file-progress")
    import fcntl
    with (journal(bundle) / "lock").open("rb") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = subprocess.run([sys.executable, "-B", str(HELPER), "--archive", str(bundle.archive),
                                 "--settings", str(bundle.settings_path)], capture_output=True, text=True)
    assert result.returncode == 78 and json.loads(result.stdout) == {"status": "busy"}
    assert run(bundle)["status"] == "complete"


def test_control_lost_link_reply_recovers_only_exact_inode(tmp_path):
    path = tmp_path / "control.json"; pending = tmp_path / "control.json.pending"
    value = {"synthetic": True}; pending.write_bytes(restore.canonical(value)); pending.chmod(0o600)
    os.link(pending, path)
    restore.publish_control(path, value)
    assert path.stat().st_nlink == 1 and not pending.exists()
    pending.write_bytes(path.read_bytes()); pending.chmod(0o600)
    with pytest.raises(restore.RestoreError): restore.publish_control(path, value)
    assert pending.exists()


@pytest.mark.parametrize("capacity", ["bytes", "inodes", "unknown"])
def test_insufficient_or_unknown_capacity_blocks_all_payload_writes(bundle, monkeypatch, capacity):
    actual = os.statvfs(root(bundle))
    values = {name: getattr(actual, name) for name in ("f_frsize", "f_bavail", "f_files", "f_favail")}
    values[{"bytes": "f_bavail", "inodes": "f_favail", "unknown": "f_files"}[capacity]] = 0
    monkeypatch.setattr(restore.os, "statvfs", lambda path: SimpleNamespace(**values))
    with pytest.raises(restore.RestoreError, match="capacity|insufficient"):
        run(bundle)
    assert list(root(bundle, "forgejo").iterdir()) == []
    assert list(root(bundle, "chroma").iterdir()) == []
    assert list(root(bundle).iterdir()) == [journal(bundle)]


def test_shared_filesystem_free_bytes_counted_once_and_partial_cost_is_conservative(bundle, monkeypatch):
    """The capacity check reads the filesystem ONCE for every volume root on
    it. Measured against a controlled statvfs (the previous form
    compared two live readings and failed once when free space moved by
    4,096 bytes between them): the available bytes are exactly the one
    reading's, and the partial cost exceeds the entries' sizes."""
    with tarfile.open(bundle.archive) as archive: records = json.load(archive.extractfile("GSJ-BACKUP.json"))["entries"]
    roots = {name: root(bundle, name) for name in backup.VOLUMES}
    actual = os.statvfs(root(bundle))
    frozen = SimpleNamespace(**{name: getattr(actual, name) for name in ("f_frsize", "f_bavail", "f_files", "f_favail")})
    monkeypatch.setattr(restore.os, "statvfs", lambda path: frozen)
    data = restore.capacity_check(roots, {r["path"]: r for r in records}, {})
    assert data["filesystems"] == 1
    assert data["available_bytes"] == frozen.f_bavail * frozen.f_frsize
    assert data["required_bytes"] > sum(r.get("size", 0) for r in records)


def test_archive_corruption_fails_before_target_claim(bundle):
    with bundle.archive.open("r+b") as stream: stream.seek(40); stream.write(b"corrupt synthetic archive")
    with pytest.raises((restore.RestoreError, ValueError, tarfile.TarError, EOFError)): run(bundle)
    assert all(not any(root(bundle, role).iterdir()) for role in backup.VOLUMES)


@pytest.mark.parametrize("complete_line", [False, True])
def test_journal_truncated_tail_resumes_but_malformed_complete_event_refuses(bundle, complete_line):
    killed(bundle, "file-progress")
    events = journal(bundle) / "events.jsonl"
    with events.open("ab") as stream: stream.write(b'{"sequence":' + (b"\n" if complete_line else b""))
    if complete_line:
        before = events.read_bytes()
        with pytest.raises(restore.RestoreError, match="malformed"): run(bundle)
        assert events.read_bytes() == before
    else:
        assert run(bundle)["status"] == "complete"
        assert_payload(bundle)


def test_mounted_root_inode_replacement_cannot_adopt_old_journal(bundle):
    killed(bundle, "file-progress")
    current = root(bundle); old = current.with_name("old-gsj")
    current.rename(old); current.mkdir()
    (old / journal(bundle).name).rename(journal(bundle))
    with pytest.raises(restore.RestoreError, match="mounted filesystem identity"):
        run(bundle)
    assert old.exists() and journal(bundle).exists()


def test_archive_replaced_after_verification_fails_before_payload_or_claim(bundle, monkeypatch):
    changed = bundle.tmp / "changed.tar.gz"
    (Path(bundle.sources["gsj"]) / "nested/payload").write_bytes(b"different synthetic archive")
    backup.create(changed, bundle.sources, {"release_identity": "synthetic-release", "generation": "synthetic:1", "quiesced": True})
    verify = backup.verify
    def replace_after_verify(path):
        result = verify(path)
        changed.replace(path)
        return result
    monkeypatch.setattr(restore.backup, "verify", replace_after_verify)
    with pytest.raises(restore.RestoreError, match="manifest changed"):
        run(bundle)
    assert all(not any(root(bundle, role).iterdir()) for role in backup.VOLUMES)


def test_final_result_and_directory_timestamps_are_stable_after_lost_response(bundle):
    killed(bundle, "result-published")
    before = (journal(bundle) / "result.json").read_bytes()
    timestamps = {role: root(bundle, role).stat().st_mtime_ns for role in backup.VOLUMES}
    result = run(bundle)
    assert result["resumed"] is True and (journal(bundle) / "result.json").read_bytes() == before
    assert {role: root(bundle, role).stat().st_mtime_ns for role in backup.VOLUMES} == timestamps
    assert_payload(bundle)


def test_cli_archive_errors_do_not_emit_traceback_or_payload(bundle):
    bundle.archive.write_bytes(b"invalid synthetic archive\n")
    result = subprocess.run([sys.executable, "-B", str(HELPER), "--archive", str(bundle.archive),
                             "--settings", str(bundle.settings_path)], capture_output=True, text=True)
    assert result.returncode == 1 and "Traceback" not in result.stderr
    assert "invalid synthetic archive" not in result.stderr
