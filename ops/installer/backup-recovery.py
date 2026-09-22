"""Preserve an abandoned maintenance Pod before retiring its exec writers.

The installer first proves the exact owned Pod UID/image/mount specification.
This helper refuses any PID-1 command other than the maintenance sleep. It
never opens source PVCs. Only /transfer is archived, always into an encrypted
pipe controlled by the caller. No customer filenames are printed on failure.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import stat
import sys
import tarfile
import time

MANIFEST = "GSJ-TRANSFER.json"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def process(pid):
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        return {"pid": pid, "state": fields[0], "parent": int(fields[1]), "start": fields[19]}
    except FileNotFoundError:
        return None


def maintenance_processes():
    if Path("/proc/1/cmdline").read_bytes().rstrip(b"\0").split(b"\0") != [b"sleep", b"86400"]:
        raise ValueError("not a dedicated maintenance container")
    excluded, parent = {1, os.getpid()}, os.getppid()
    while parent > 1 and parent not in excluded:
        excluded.add(parent)
        info = process(parent)
        parent = info["parent"] if info else 0
    return [info for path in Path("/proc").iterdir()
            if path.name.isdigit() and int(path.name) not in excluded
            and (info := process(int(path.name))) and info["state"] != "Z"]


def stop_processes(items, *, inspect=process, send=os.kill):
    for item in items:
        actual = inspect(item["pid"])
        if not actual:
            continue
        if actual["start"] != item["start"]:
            raise ValueError("exec process identity changed")
        try:
            send(item["pid"], signal.SIGSTOP)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        ready = True
        for item in items:
            actual = inspect(item["pid"])
            if actual and actual["start"] != item["start"]:
                raise ValueError("exec process identity changed")
            if actual and actual["state"] not in ("T", "t", "Z"):
                ready = False
        if ready:
            return
        time.sleep(0.05)
    raise ValueError("maintenance exec writer did not stop")


def quiet():
    if any(item["state"] not in ("T", "t") for item in maintenance_processes()):
        raise ValueError("maintenance still has an active exec process")


def inventory(root):
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("transfer root is unavailable")
    records, pending, processed, last = [], [(root, ".")], 0, time.monotonic()
    while pending:
        path, name = pending.pop()
        info = path.lstat()
        record = {"name": name, "mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid,
                  "gid": info.st_gid, "mtime_ns": info.st_mtime_ns}
        if stat.S_ISDIR(info.st_mode):
            record["kind"] = "dir"
            pending.extend((p, p.relative_to(root).as_posix()) for p in sorted(path.iterdir()))
        elif stat.S_ISREG(info.st_mode):
            digest = hashlib.sha256()
            with path.open("rb") as source:
                for block in iter(lambda: source.read(1024 * 1024), b""):
                    digest.update(block)
                    processed += len(block)
                    if time.monotonic() - last >= 30:
                        print(f"[backup-recovery] inspected {processed} bytes", file=sys.stderr, flush=True)
                        last = time.monotonic()
            record.update(kind="file", size=info.st_size, sha256=digest.hexdigest())
            after = path.lstat()
            if (info.st_ino, info.st_size, info.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns):
                raise ValueError("transfer content changed")
        else:
            raise ValueError("transfer contains an unsupported entry")
        if name == MANIFEST:
            raise ValueError("reserved transfer manifest already exists")
        records.append(record)
    return sorted(records, key=lambda value: value["name"])


def summary(records):
    size = sum(r.get("size", 0) for r in records)
    # Two times metadata plus a PAX header allowance for every small transfer
    # entry. The large file payloads are counted without assuming compression.
    raw = size + len(canonical(records)) * 2 + len(records) * 8192 + 65536
    bound = raw + (raw >> 12) + (raw >> 14) + (raw >> 25) + 128
    return {"format": "gsj.transfer/1", "entries": len(records), "logical_bytes": size,
            "archive_upper_bound_bytes": bound,
            "manifest_sha256": hashlib.sha256(canonical(records)).hexdigest()}


def archive(root, output):
    records = inventory(root)
    with tarfile.open(fileobj=output, mode="w|gz", dereference=False) as bundle:
        data = canonical(records)
        member = tarfile.TarInfo(MANIFEST)
        member.size, member.mode = len(data), 0o600
        bundle.addfile(member, io.BytesIO(data))
        for record in records:
            path = Path(root) / record["name"]
            member = bundle.gettarinfo(str(path), arcname=record["name"])
            member.uname = member.gname = ""
            if record["kind"] == "file":
                member.type, member.linkname, member.size = tarfile.REGTYPE, "", record["size"]
                with path.open("rb") as source:
                    bundle.addfile(member, source)
            else:
                bundle.addfile(member)
    if inventory(root) != records:
        raise ValueError("transfer content changed while preserving it")


def verify(root, source):
    expected = inventory(root)
    names, found = {v["name"]: v for v in expected}, set()
    with tarfile.open(fileobj=source, mode="r|gz") as bundle:
        first = bundle.next()
        if first.name != MANIFEST or not first.isfile() or first.size > 16 * 1024 * 1024:
            raise ValueError("transfer manifest is missing")
        if json.load(bundle.extractfile(first)) != expected:
            raise ValueError("preserved transfer manifest differs")
        member = bundle.next()
        while member is not None:
            record = names.get(member.name)
            if record is None or member.name in found:
                raise ValueError("unexpected transfer entry")
            found.add(member.name)
            if member.mode != record["mode"] or member.uid != record["uid"] or member.gid != record["gid"]:
                raise ValueError("preserved metadata differs")
            if record["kind"] == "file":
                if not member.isfile() or member.size != record["size"]:
                    raise ValueError("preserved file type or length differs")
                digest = hashlib.sha256()
                with bundle.extractfile(member) as payload:
                    for block in iter(lambda: payload.read(1024 * 1024), b""):
                        digest.update(block)
                if digest.hexdigest() != record["sha256"]:
                    raise ValueError("preserved file bytes differ")
            elif not member.isdir():
                raise ValueError("preserved directory type differs")
            member = bundle.next()
    if found != set(names) or inventory(root) != expected:
        raise ValueError("preserved transfer is incomplete or changed")
    return summary(expected)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("freeze", "inspect", "archive", "verify"))
    parser.add_argument("--root", default="/transfer")
    args = parser.parse_args()
    try:
        if args.action == "freeze":
            # Repeat enumeration: a writer could have forked just before STOP.
            for _ in range(3):
                stop_processes(maintenance_processes())
            quiet()
            print(json.dumps({"format": "gsj.exec-freeze/1", "frozen": True}))
        else:
            quiet()
            if args.action == "archive":
                archive(args.root, sys.stdout.buffer)
            else:
                result = (verify(args.root, sys.stdin.buffer) if args.action == "verify"
                          else summary(inventory(args.root)))
                quiet()
                print(json.dumps(result, sort_keys=True))
    except (OSError, ValueError, tarfile.TarError, EOFError):
        print("backup recovery could not prove stopped writers and preserved transfer bytes", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
