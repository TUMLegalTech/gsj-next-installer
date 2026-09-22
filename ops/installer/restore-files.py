#!/usr/bin/env python3
"""Operation-bound, resumable restore into three externally quiesced PVCs.

This signed installer helper uses the product's public backup verifier. It
never contacts Kubernetes or changes unrelated paths. The runtime supplies and
revalidates namespace/PVC/PV identities and prevents all other writers.
"""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import tarfile
import time
import zlib

from gsj_deploy import backup

ROLES = {"forgejo", "gsj", "chroma"}


class RestoreError(ValueError):
    pass


class RestoreBusy(RestoreError):
    pass


def require(condition, message):
    if not condition:
        raise RestoreError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode()


def digest_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def fsync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def identity(path):
    info = path.lstat()
    return {"device": info.st_dev, "inode": info.st_ino}


def metadata(path):
    info = path.lstat()
    return {"uid": info.st_uid, "gid": info.st_gid, "mode": stat.S_IMODE(info.st_mode)}


def regular_private(path, *, links=1):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == links,
            "restore control file ownership differs")


def validate_settings(settings):
    require(isinstance(settings, dict) and set(settings) == {
        "format", "operation", "archive_sha256", "encrypted_archive_sha256", "release_identity",
        "namespace_uid", "volumes"} and settings["format"] == "gsj.restore-files/1",
        "unsupported restore settings")
    require(isinstance(settings["operation"], str) and re.fullmatch(r"[a-f0-9]{24}", settings["operation"]),
            "invalid restore operation")
    for key in ("archive_sha256", "encrypted_archive_sha256"):
        require(isinstance(settings[key], str) and re.fullmatch(r"[a-f0-9]{64}", settings[key]),
                "invalid restore archive identity")
    for key in ("release_identity", "namespace_uid"):
        require(isinstance(settings[key], str) and settings[key] and "\0" not in settings[key],
                "invalid restore target identity")
    require(isinstance(settings["volumes"], dict) and set(settings["volumes"]) == ROLES,
            "restore requires exactly three volume bindings")
    roots = {}
    for role, value in settings["volumes"].items():
        require(isinstance(value, dict) and set(value) == {"name", "uid", "pv_name", "pv_uid", "root"}
                and all(isinstance(x, str) and x and "\0" not in x for x in value.values()),
                "invalid restore volume binding")
        raw = Path(value["root"])
        require(raw.is_absolute() and raw.is_dir() and not raw.is_symlink()
                and raw == raw.resolve(), "restore roots must be existing physical absolute directories")
        roots[role] = raw
    for role, root in roots.items():
        require(not any(role != other and (root == target or root.is_relative_to(target))
                        for other, target in roots.items()), "restore roots overlap")
    for key in ("name", "uid", "pv_name", "pv_uid"):
        require(len({v[key] for v in settings["volumes"].values()}) == 3,
                "restore volume identities overlap")
    return roots


def publish_control(path, value):
    """Publish a fixed control value without ever replacing a different one."""
    wanted = canonical(value)
    pending = path.with_name(path.name + ".pending")
    if path.exists() or path.is_symlink():
        linked = pending.exists() or pending.is_symlink()
        regular_private(path, links=2 if linked else 1)
        require(path.read_bytes() == wanted, "restore control identity differs")
        if linked:
            require(identity(pending) == identity(path), "restore control temporary inode differs")
            pending.unlink(); fsync_directory(path.parent)
        return
    if pending.exists():
        regular_private(pending)
        prefix = pending.read_bytes()
        require(wanted.startswith(prefix), "unexplained restore control temporary data")
    else:
        fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        prefix = b""
    with pending.open("ab") as stream:
        stream.write(wanted[len(prefix):]); stream.flush(); os.fsync(stream.fileno())
    os.link(pending, path, follow_symlinks=False)
    fsync_directory(path.parent)
    pending.unlink(); fsync_directory(path.parent)


class Journal:
    def __init__(self, directory, binding):
        self.directory = directory
        self.previous = hashlib.sha256(canonical(binding)).hexdigest()
        self.states = {}; self.sequence = 0
        path = directory / "events.jsonl"
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        self.stream = os.fdopen(fd, "r+b", buffering=0)
        regular_private(path)
        valid = 0
        for line in self.stream:
            if not line.endswith(b"\n"):
                # Only an interrupted tail append is discarded. Prior durable
                # intents still constrain every possible published path.
                self.stream.truncate(valid); os.fsync(fd); break
            try:
                event = json.loads(line)
                checksum = event.pop("sha256")
            except (ValueError, KeyError, TypeError):
                raise RestoreError("restore journal is malformed") from None
            require(event.get("sequence") == self.sequence + 1 and event.get("previous") == self.previous
                    and checksum == hashlib.sha256(canonical(event)).hexdigest()
                    and isinstance(event.get("entry"), str) and isinstance(event.get("state"), dict),
                    "restore journal chain differs")
            self.previous = checksum; self.sequence += 1
            self.states[event["entry"]] = event["state"]
            valid += len(line)
        self.stream.seek(0, os.SEEK_END)
        fsync_directory(directory)

    def put(self, entry, state):
        event = {"sequence": self.sequence + 1, "previous": self.previous, "entry": entry, "state": state}
        checksum = hashlib.sha256(canonical(event)).hexdigest()
        payload = canonical({**event, "sha256": checksum}) + b"\n"
        view = memoryview(payload)
        while view:
            view = view[os.write(self.stream.fileno(), view):]
        os.fsync(self.stream.fileno())
        self.sequence += 1; self.previous = checksum; self.states[entry] = state

    def close(self):
        self.stream.close()


@contextmanager
def claim(roots, settings, settings_sha256, manifest_sha256, journal_name):
    directory = roots["gsj"] / journal_name
    new = not directory.exists()
    if new:
        require(all(not any(root.iterdir()) for root in roots.values()),
                "first restore requires empty targets; existing payload is foreign")
        try:
            directory.mkdir(mode=0o700)
        except FileExistsError:
            new = False
        fsync_directory(roots["gsj"])
    info = directory.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) == 0o700, "restore journal directory ownership differs")
    fd = os.open(directory / "lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    journal = None
    try:
        regular_private(directory / "lock")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RestoreBusy("another restore helper owns the operation") from None
        require(set(p.name for p in directory.iterdir()) <= {
            "lock", "binding.json", "binding.json.pending", "events.jsonl", "result.json", "result.json.pending"},
            "unexplained restore journal entries")
        path = directory / "binding.json"
        current_roots = {role: {**identity(root), **metadata(root)} for role, root in roots.items()}
        if path.exists():
            regular_private(path, links=2 if path.with_name(path.name + ".pending").exists() else 1)
            try: binding = json.loads(path.read_bytes())
            except (ValueError, UnicodeError): raise RestoreError("restore binding is malformed") from None
            require(binding.get("format") == "gsj.restore-files-binding/1" and binding.get("settings") == settings
                    and binding.get("settings_file_sha256") == settings_sha256
                    and binding.get("manifest_sha256") == manifest_sha256,
                    "restore operation or archive identity differs")
            require(all({key: binding.get("roots", {}).get(role, {}).get(key) for key in ("device", "inode")}
                        == identity(root) for role, root in roots.items()), "restore mounted filesystem identity differs")
            publish_control(path, binding)
        else:
            # An interruption while creating the empty control directory has
            # not authorized any payload writes. Refuse every other entry.
            require(all(set(root.iterdir()) <= ({directory} if role == "gsj" else set())
                        for role, root in roots.items()), "unbound restore target contains foreign payload")
            binding = {"format": "gsj.restore-files-binding/1", "settings": settings,
                       "settings_file_sha256": settings_sha256,
                       "manifest_sha256": manifest_sha256, "roots": current_roots}
            publish_control(path, binding)
        journal = Journal(directory, binding)
        yield journal, binding, not new
    finally:
        if journal: journal.close()
        os.close(fd)


def type_matches(path, kind):
    mode = path.lstat().st_mode
    return {"file": stat.S_ISREG, "dir": stat.S_ISDIR, "symlink": stat.S_ISLNK}[kind](mode)


def matches(path, record, *, full=True, links=1):
    require(type_matches(path, record["type"]), "restored path type differs")
    info = path.lstat()
    require(metadata(path) == {k: record[k] for k in ("mode", "uid", "gid")},
            "restored ownership or mode differs")
    if full:
        require(info.st_mtime_ns == record["mtime_ns"], "restored timestamp differs")
    if record["type"] == "file":
        require(info.st_size == record["size"] and digest_file(path) == record["sha256"]
                and info.st_nlink == links, "restored payload checksum or link identity differs")
    elif record["type"] == "symlink":
        require(os.readlink(path) == record["target"] and info.st_nlink == links,
                "restored symlink target or link identity differs")


def check_metadata_prefix(path, record, state):
    """Only the declared POSIX metadata transitions may be resumed."""
    initial = state["initial_metadata"]
    actual = metadata(path); step = state.get("metadata_step", 0)
    old_owner = (initial["uid"], initial["gid"])
    new_owner = (record["uid"], record["gid"])
    owners = {old_owner} if step == 0 else {old_owner, new_owner} if step == 1 else {new_owner}
    modes = {initial["mode"]}
    if step >= 1: modes.add(initial["mode"] & ~0o6000)  # chown may clear set-ID bits.
    if step >= 3: modes.add(record["mode"])
    if step >= 4: modes = {record["mode"]}
    require((actual["uid"], actual["gid"]) in owners and actual["mode"] in modes,
            "owned restore metadata is outside the declared transition")
    if step == 6:
        require(path.lstat().st_mtime_ns == record["mtime_ns"], "restored timestamp differs")


def capacity_check(roots, records, states):
    """Conservative remaining physical cost, without double-counting shared free space."""
    groups = {}; roles = {}
    for role, root in roots.items():
        device = root.stat().st_dev; info = os.statvfs(root)
        require(info.f_frsize > 0 and info.f_bavail >= 0 and info.f_files > 0 and info.f_favail >= 0,
                "restore filesystem capacity is unknown")
        available = info.f_bavail * info.f_frsize
        group = groups.setdefault(device, {"available_bytes": available, "available_inodes": info.f_favail,
                                          "required_bytes": 0, "required_inodes": 0, "block": info.f_frsize})
        # Multiple mounts of one backing filesystem cannot contribute free
        # space twice. The smaller same-process view is the safe bound.
        group["available_bytes"] = min(group["available_bytes"], available)
        group["available_inodes"] = min(group["available_inodes"], info.f_favail)
        group["block"] = max(group["block"], info.f_frsize); roles[role] = group
    for name, record in records.items():
        group = roles[name.split("/")[0]]; state = states.get(name, {})
        if record["type"] == "file" and not state.get("published"):
            # A full remaining file is conservative even when an owned prefix
            # already occupies blocks. Publication hard-links the same inode.
            size = record["size"]
            group["required_bytes"] += ((size + group["block"] - 1) // group["block"]) * group["block"]
        if name not in ROLES and not state.get("identity"):
            group["required_inodes"] += 1
            if record["type"] != "file": group["required_bytes"] += group["block"]
    # Journal updates, directory growth and pending control publications need
    # their own reserve; this preflight is evidence, not a space reservation.
    for role, group in roles.items():
        count = sum(name == role or name.startswith(role + "/") for name in records)
        group["required_bytes"] += count * 4096 + 1024 * 1024
        group["required_inodes"] += 2
    roles["gsj"]["required_bytes"] += sum(12 * (len(canonical(record)) + 1024) for record in records.values())
    roles["gsj"]["required_inodes"] += 8
    require(all(g["available_bytes"] >= g["required_bytes"] and
                g["available_inodes"] >= g["required_inodes"] for g in groups.values()),
            "insufficient restore filesystem bytes or inodes")
    return {"filesystems": len(groups), **{key: sum(g[key] for g in groups.values()) for key in
            ("available_bytes", "available_inodes", "required_bytes", "required_inodes")}}


def restore_files(archive_path, settings, *, settings_file_sha256, on_event=None):
    roots = validate_settings(settings)
    require(isinstance(settings_file_sha256, str) and re.fullmatch(r"[a-f0-9]{64}", settings_file_sha256),
            "invalid protected settings digest")
    archive_path = Path(archive_path)
    require(archive_path.is_absolute() and archive_path.is_file() and not archive_path.is_symlink()
            and not any(archive_path.resolve().is_relative_to(root) for root in roots.values()),
            "archive must be a physical file outside target volumes")
    try: verified = backup.verify(archive_path)
    except (backup.BackupError, OSError, tarfile.TarError): raise RestoreError("backup verification failed") from None
    require(verified["archive_sha256"] == settings["archive_sha256"]
            and verified["metadata"]["release_identity"] == settings["release_identity"],
            "restore archive or release identity differs")
    journal_name = ".gsj-restore-" + settings["operation"]
    stage_name = journal_name + ".staging"
    with tarfile.open(archive_path, "r:*") as archive:
        manifest = json.load(archive.extractfile("GSJ-BACKUP.json"))
        require(hashlib.sha256(canonical(manifest)).hexdigest() == verified["manifest_sha256"],
                "archive manifest changed after verification")
        records = {r["path"]: r for r in manifest["entries"]}
        require(all(not (r.split("/")[1:2] == [stage_name] or r.split("/")[1:2] == [journal_name])
                    for r in records), "archive collides with current restore control names")
        require(os.geteuid() == 0 or all(r["uid"] == os.geteuid() and
                r["gid"] in set(os.getgroups()) | {os.getegid()} for r in records.values()),
                "restore needs root to preserve archived UID/GID ownership")
        require(hasattr(os, "lchmod") or all(r["type"] != "symlink" or r["mode"] == 0o777 for r in records.values()),
                "platform cannot preserve archived symlink permissions")
        with claim(roots, settings, settings_file_sha256, verified["manifest_sha256"], journal_name) as (journal, binding, resumed):
            stages = {role: root / stage_name for role, root in roots.items()}
            progress_bytes = 0; last_progress = time.monotonic()
            def emit(stage, **detail):
                nonlocal progress_bytes, last_progress
                progress_bytes += detail.get("bytes", 0)
                if time.monotonic() - last_progress >= 30:
                    print(json.dumps({"restore_written_bytes": progress_bytes}), file=sys.stderr, flush=True)
                    last_progress = time.monotonic()
                if on_event: on_event(stage, detail)
            def finish_metadata(name, path, record):
                state = journal.states[name]
                check_metadata_prefix(path, record, state)
                for pending, done in ((1, 2), (3, 4), (5, 6)):
                    if state.get("metadata_step", 0) >= done: continue
                    state = {**state, "metadata_step": pending}; journal.put(name, state)
                    if pending == 1:
                        os.chown(path, record["uid"], record["gid"], follow_symlinks=False)
                    elif pending == 3:
                        if record["type"] != "symlink": os.chmod(path, record["mode"])
                        elif hasattr(os, "lchmod"): os.lchmod(path, record["mode"])
                        else: require(metadata(path)["mode"] == record["mode"],
                                      "platform cannot preserve archived symlink permissions")
                    else:
                        os.utime(path, ns=(record["mtime_ns"], record["mtime_ns"]), follow_symlinks=False)
                    if record["type"] != "symlink":
                        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                        try: os.fsync(fd)
                        finally: os.close(fd)
                    fsync_directory(path.parent); emit("metadata-applied", step=pending, type=record["type"])
                    state = {**state, "metadata_step": done}; journal.put(name, state)
            def destination(name):
                role, *parts = name.split("/")
                return roots[role].joinpath(*parts)
            def parents(path):
                role = next(role for role, root in roots.items() if path.is_relative_to(root))
                current = path.parent
                while current != roots[role]:
                    require(type_matches(current, "dir"), "restore parent became a symlink or non-directory")
                    key = role + "/" + current.relative_to(roots[role]).as_posix()
                    require(journal.states.get(key, {}).get("identity") == identity(current),
                            "restore parent identity differs")
                    current = current.parent
            def scan():
                seen = set()
                def visit(path, name):
                    if path == journal.directory or path in stages.values(): return
                    require(name in records, "foreign entry exists in restore target")
                    seen.add(name)
                    record = records[name]
                    state = journal.states.get(name)
                    if name not in ROLES:
                        require(state is not None, "existing payload has no durable restore intent")
                        require(type_matches(path, record["type"]), "existing restore entry type differs")
                        if state.get("identity"):
                            require(identity(path) == state["identity"], "existing restore entry inode differs")
                    if record["type"] == "dir":
                        if state and state.get("initial_metadata"):
                            check_metadata_prefix(path, record, state)
                        elif name in ROLES:
                            require(metadata(path) == {k: binding["roots"][name][k] for k in ("uid", "gid", "mode")},
                                    "restore root ownership changed before first payload write")
                    else:
                        require(state.get("identity") == identity(path), "published restore inode differs")
                        temp = stages[name.split("/")[0]] / state["temporary"]
                        linked = temp.exists() or temp.is_symlink()
                        if linked: require(identity(temp) == identity(path), "restore temporary inode differs")
                        require(state.get("published") or linked, "restore publication has no owned temporary proof")
                        matches(path, record, links=2 if linked else 1)
                    if path.is_dir() and not path.is_symlink():
                        for child in path.iterdir(): visit(child, name + "/" + child.name)
                for role, root in roots.items(): visit(root, role)
                return seen
            seen = scan()
            for name, state in journal.states.items():
                if name in records and (state.get("published") or records[name]["type"] == "dir" and state.get("identity")):
                    require(name in seen, "previously restored payload disappeared")
            capacity = capacity_check(roots, records, journal.states)
            print(json.dumps({"restore_capacity": capacity}), file=sys.stderr, flush=True)
            # Stage roots are capability directories. Their inodes are recorded
            # before a payload temporary can be created inside them.
            for role, stage in stages.items():
                key = "@stage/" + role; state = journal.states.get(key)
                if state and state.get("removed"):
                    require(not stage.exists(), "removed staging directory reappeared")
                    continue
                if state is None:
                    require(not stage.exists(), "foreign restore staging directory exists")
                    journal.put(key, {"intent": True}); state = journal.states[key]
                if not stage.exists():
                    if state.get("removing"):
                        require(all(journal.states.get(name, {}).get("published") for name, r in records.items()
                                    if name.startswith(role + "/") and r["type"] != "dir"),
                                "missing staging directory has unfinished payload")
                        journal.put(key, {**state, "removed": True}); continue
                    require(not state.get("identity"), "owned staging directory disappeared")
                    stage.mkdir(mode=0o700); os.chmod(stage, 0o700); fsync_directory(stage.parent)
                require(type_matches(stage, "dir") and metadata(stage)["mode"] == 0o700
                        and metadata(stage)["uid"] == os.geteuid(), "staging directory ownership differs")
                if state.get("identity"):
                    require(state["identity"] == identity(stage) and metadata(stage) == state["initial_metadata"],
                            "staging directory inode or ownership differs")
                else:
                    require(not any(stage.iterdir()), "unrecorded staging directory is not empty")
                    journal.put(key, {"intent": True, "identity": identity(stage), "initial_metadata": metadata(stage)})
                expected = {s["temporary"] for name, s in journal.states.items()
                            if name.startswith(role + "/") and "temporary" in s}
                require({p.name for p in stage.iterdir()} <= expected, "unexplained restore temporary exists")
                for name, record in records.items():
                    state = journal.states.get(name, {})
                    if not name.startswith(role + "/") or "temporary" not in state: continue
                    temporary = stage / state["temporary"]
                    if not temporary.exists() and not temporary.is_symlink():
                        require(not state.get("identity") or state.get("published"), "owned restore temporary disappeared")
                        continue
                    if state.get("identity"):
                        require(identity(temporary) == state["identity"], "restore temporary inode differs")
                        check_metadata_prefix(temporary, record, state)
                    else:
                        require(metadata(temporary)["uid"] == os.geteuid(), "unrecorded temporary owner differs")
                        if record["type"] == "file":
                            require(temporary.stat().st_size == 0 and metadata(temporary)["mode"] == 0o600,
                                    "unrecorded restore temporary contains unexplained data")
                    if record["type"] == "file":
                        require(type_matches(temporary, "file") and temporary.stat().st_size <= record["size"],
                                "restore temporary size or type differs")
                        require(temporary.stat().st_nlink == (2 if destination(name).exists() else 1),
                                "restore temporary links differ")
                        with archive.extractfile(name) as source, temporary.open("rb") as prefix:
                            for block in iter(lambda: prefix.read(1024 * 1024), b""):
                                require(block == source.read(len(block)), "restore temporary is not the expected payload prefix")
                        if state.get("metadata_step", 0):
                            require(temporary.stat().st_size == record["size"], "completed restore temporary was truncated")
                    else:
                        require(type_matches(temporary, "symlink") and os.readlink(temporary) == record["target"],
                                "restore temporary symlink differs")
                        require(temporary.lstat().st_nlink == (2 if destination(name).is_symlink() else 1),
                                "restore temporary symlink links differ")
            directories = sorted((r for r in records.values() if r["type"] == "dir"),
                                 key=lambda r: (r["path"].count("/"), r["path"]))
            for record in directories:
                name = record["path"]; path = destination(name); state = journal.states.get(name)
                if name in ROLES:
                    if state is None: journal.put(name, {"identity": identity(path), "initial_metadata": metadata(path)})
                    continue
                parents(path)
                if state is None:
                    require(not path.exists(), "foreign directory exists at restore destination")
                    journal.put(name, {"intent": True}); state = journal.states[name]
                if not path.exists():
                    require(not state.get("identity"), "owned restore directory disappeared")
                    path.mkdir(mode=0o700); os.chmod(path, 0o700); fsync_directory(path.parent); emit("directory-created")
                require(type_matches(path, "dir"), "restore directory type differs")
                if state.get("identity"):
                    require(state["identity"] == identity(path), "restore directory inode differs")
                else:
                    require(not any(path.iterdir()) and metadata(path)["mode"] == 0o700
                            and metadata(path)["uid"] == os.geteuid(),
                            "unrecorded restore directory is not an owned empty prefix")
                    journal.put(name, {"identity": identity(path), "initial_metadata": metadata(path)})
            files = total_bytes = 0
            for record in records.values():
                if record["type"] == "dir": continue
                name = record["path"]; path = destination(name); parents(path)
                role = name.split("/")[0]; state = journal.states.get(name)
                if state is None:
                    require(not path.exists() and not path.is_symlink(), "foreign payload exists at restore destination")
                    state = {"temporary": "entry-" + secrets.token_hex(16), "intent": True}
                    journal.put(name, state)
                temporary = stages[role] / state["temporary"]
                exists = path.exists() or path.is_symlink()
                if exists:
                    require(state.get("identity") == identity(path), "published restore inode differs")
                    # A lost link-publication response is proven by the exact
                    # staged inode. No matching-but-unowned file is adopted.
                    if not state.get("published"):
                        require((temporary.exists() or temporary.is_symlink()) and identity(temporary) == identity(path),
                                "restore publication has no owned temporary proof")
                    linked = temporary.exists() or temporary.is_symlink()
                    if linked:
                        require(identity(temporary) == identity(path), "restore temporary inode differs")
                    matches(path, record, links=2 if linked else 1)
                    if not state.get("published"):
                        state = {**state, "published": True}; journal.put(name, state)
                    if linked:
                        temporary.unlink(); fsync_directory(temporary.parent)
                    matches(path, record)
                else:
                    require(not state.get("published"), "published restore payload disappeared")
                    require(stages[role].is_dir(), "restore staging state ended before publication")
                    if not temporary.exists() and not temporary.is_symlink():
                        require(not state.get("identity"), "owned restore temporary disappeared")
                        if record["type"] == "file":
                            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600); os.close(fd)
                        else: os.symlink(record["target"], temporary)
                        fsync_directory(temporary.parent); emit("temporary-created")
                    require(type_matches(temporary, record["type"]), "restore temporary type differs")
                    if state.get("identity"):
                        require(state["identity"] == identity(temporary), "restore temporary inode differs")
                    else:
                        if record["type"] == "file":
                            require(temporary.stat().st_size == 0 and metadata(temporary)["mode"] == 0o600
                                    and metadata(temporary)["uid"] == os.geteuid(),
                                "unrecorded restore temporary contains unexplained data")
                        else: require(os.readlink(temporary) == record["target"], "restore temporary symlink differs")
                        state = {**state, "identity": identity(temporary), "initial_metadata": metadata(temporary)}
                        journal.put(name, state)
                    if record["type"] == "file":
                        require(temporary.stat().st_nlink == 1 and temporary.stat().st_size <= record["size"],
                                "restore temporary size or links differ")
                        with archive.extractfile(name) as source, temporary.open("rb") as prefix:
                            for block in iter(lambda: prefix.read(1024 * 1024), b""):
                                require(block == source.read(len(block)), "restore temporary is not the expected payload prefix")
                            fd = os.open(temporary, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
                            with os.fdopen(fd, "ab") as target:
                                for block in iter(lambda: source.read(1024 * 1024), b""):
                                    target.write(block); target.flush()
                                    emit("file-progress", bytes=len(block))
                                os.fsync(target.fileno())
                        require(digest_file(temporary) == record["sha256"], "restored temporary checksum differs")
                    else: require(os.readlink(temporary) == record["target"], "restore temporary symlink differs")
                    finish_metadata(name, temporary, record); state = journal.states[name]
                    os.link(temporary, path, follow_symlinks=False)
                    fsync_directory(path.parent); emit("file-published")
                    state = {**state, "published": True}; journal.put(name, state)
                    temporary.unlink(); fsync_directory(temporary.parent)
                    matches(path, record)
                files += record["type"] == "file"; total_bytes += record.get("size", 0)
            for role, stage in stages.items():
                key = "@stage/" + role; state = journal.states[key]
                if not state.get("removed"):
                    journal.put(key, {**state, "removing": True})
                    if stage.exists():
                        require(identity(stage) == state["identity"] and not any(stage.iterdir()),
                                "restore staging residue remains")
                        stage.rmdir(); fsync_directory(stage.parent); emit("staging-removed")
                    journal.put(key, {**state, "removed": True})
            for record in reversed(directories):
                path = destination(record["path"])
                require(identity(path) == journal.states[record["path"]]["identity"], "restore directory was replaced")
                finish_metadata(record["path"], path, record)
            require(scan() == set(records), "restored inventory differs")
            for record in records.values(): matches(destination(record["path"]), record)
            require(digest_file(archive_path) == settings["archive_sha256"], "archive changed during restore")
            result = {"format": "gsj.restore-files-result/1", "status": "complete", "restored": True,
                      **{k: settings[k] for k in ("operation", "archive_sha256", "encrypted_archive_sha256", "release_identity", "namespace_uid")},
                      "binding_sha256": hashlib.sha256(canonical(settings)).hexdigest(),
                      "settings_file_sha256": settings_file_sha256,
                      "manifest_sha256": verified["manifest_sha256"], "entries": len(records), "files": files, "bytes": total_bytes}
            publish_control(journal.directory / "result.json", result)
            emit("result-published")
            return {**result, "resumed": resumed, "capacity": capacity}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True)
    parser.add_argument("--settings", required=True)
    args = parser.parse_args(argv)
    try:
        raw = Path(args.settings).read_bytes()
        settings = json.loads(raw)
        result = restore_files(args.archive, settings, settings_file_sha256=hashlib.sha256(raw).hexdigest())
    except RestoreBusy:
        print(json.dumps({"status": "busy"})); return 78
    except (RestoreError, OSError, ValueError, tarfile.TarError, EOFError, KeyError, TypeError, zlib.error) as exc:
        message = str(exc) if isinstance(exc, RestoreError) else "restore filesystem or input validation failed"
        print(json.dumps({"status": "failed", "error": message}), file=sys.stderr); return 1
    print(json.dumps(result, sort_keys=True)); return 0


if __name__ == "__main__":
    raise SystemExit(main())
