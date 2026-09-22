"""Read-only capacity measurement supplied by the signed installer over stdin.

Only aggregate counts leave this process. No file payload, SQLite query, or
credential is read. Tar sizing matches the backup helper's PAX metadata and
its deliberate expansion of sparse files and hard links. A live scan is an
estimate; repeat it with stopped writers before checkpoint/archive creation.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import time

ROLES = {"gsj": "db/gsj.db", "forgejo": "gitea/gitea.db", "chroma": "chroma.sqlite3"}
MIB = 1024 * 1024
RESOURCE_RESERVE = 512 * MIB
METADATA_RESERVE = 16 * MIB


class CapacityError(ValueError):
    pass


def filesystem(path):
    info = os.statvfs(path)
    if info.f_frsize <= 0 or info.f_bavail < 0 or info.f_favail < 0 or info.f_files <= 0:
        raise CapacityError("filesystem free bytes or inodes are unknown")
    return {"filesystem_id": format(info.f_fsid & ((1 << 64) - 1), "x"),
            "available_bytes": info.f_bavail * info.f_frsize,
            "available_inodes": info.f_favail, "block_bytes": info.f_frsize}


def padded(size, unit=512):
    return (size + unit - 1) // unit * unit


def scan_volume(role, root):
    root = Path(root)
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise CapacityError("a source mount root is absent, unsafe or not a directory")
    database = root / ROLES[role]
    if database.is_symlink() or not database.is_file() or database.stat().st_size < 16:
        raise CapacityError("a required source database is absent from its recorded mount root")
    device = root.stat().st_dev
    result = {"role": role, "logical_bytes": 0, "allocated_bytes": 0,
              "entries": 0, "files": 0, "wal_bytes": 0,
              "tar_bytes": 0, "manifest_bytes": 0, **filesystem(root)}
    pending, last_report = [(root, role)], time.monotonic()
    while pending:
        path, name = pending.pop()
        info = path.lstat()
        if info.st_dev != device:
            raise CapacityError("a nested source filesystem has no recorded volume identity")
        member = tarfile.TarInfo(name)
        member.mode, member.uid, member.gid = stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid
        member.mtime = info.st_mtime
        record = {"path": name, "mode": member.mode, "uid": member.uid,
                  "gid": member.gid, "mtime_ns": info.st_mtime_ns}
        if stat.S_ISDIR(info.st_mode):
            record["type"], member.type = "dir", tarfile.DIRTYPE
            with os.scandir(path) as children:
                pending.extend((Path(child.path), name + "/" + child.name) for child in children)
        elif stat.S_ISREG(info.st_mode):
            record.update(type="file", size=info.st_size, sha256="0" * 64)
            member.type, member.size = tarfile.REGTYPE, info.st_size
            result["files"] += 1
            result["logical_bytes"] += info.st_size
            result["tar_bytes"] += padded(info.st_size)
            if path.name.endswith("-wal"):
                result["wal_bytes"] += info.st_size
        elif stat.S_ISLNK(info.st_mode):
            record["type"], member.type = "symlink", tarfile.SYMTYPE
            record["target"] = member.linkname = os.readlink(path)
        else:
            raise CapacityError("a source volume contains an unsupported file type")
        result["allocated_bytes"] += info.st_blocks * 512
        result["entries"] += 1
        result["tar_bytes"] += len(member.tobuf(tarfile.PAX_FORMAT, encoding="utf-8", errors="surrogateescape"))
        result["manifest_bytes"] += len(json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()) + 1
        if time.monotonic() - last_report >= 30:
            print(json.dumps({"stage": "capacity-scanning", "role": role,
                              "entries": result["entries"], "logical_bytes": result["logical_bytes"]}),
                  file=sys.stderr, flush=True)
            last_report = time.monotonic()
    return result


def qualify(volumes, transfer, hosts, minimum, mode="create", *, quiesced=False):
    if set(volumes) != set(ROLES) or mode not in ("create", "reuse") or minimum < 0:
        raise CapacityError("invalid capacity input")
    roots = [Path(p).resolve() for p in volumes.values()]
    if any(a == b or a in b.parents or b in a.parents for n, a in enumerate(roots) for b in roots[n + 1:]):
        raise CapacityError("source mount roots overlap")
    if set(hosts) != {"backup", "work"}:
        raise CapacityError("both script-host filesystems must be measured")
    measurements = [scan_volume(role, volumes[role]) for role in sorted(ROLES)]
    # Include all current WAL bytes even though backup excludes them after
    # checkpointing. Include ample bounded release/controller metadata too.
    raw = padded(sum(v["tar_bytes"] + v["manifest_bytes"] for v in measurements)
                 + METADATA_RESERVE + 4096, tarfile.RECORDSIZE)
    # zlib compressBound's default deflate bound, plus gzip wrapper, bounded
    # mkstemp filename (<40 bytes), and AES salt/header/block padding. This
    # does not assume useful compression.
    archive = raw + (raw >> 12) + (raw >> 14) + (raw >> 25) + 128
    growth = max(256 * MIB, (archive + 3) // 4)
    archive_budget = archive + growth
    transfer_info = {"role": "transfer", **filesystem(transfer)}
    groups = {}

    def allocate(record, required, inodes):
        for key in ("available_bytes", "available_inodes", "block_bytes"):
            if type(record.get(key)) is not int or record[key] < 0:
                raise CapacityError("filesystem capacity is unknown")
        fid = record.get("filesystem_id")
        if not isinstance(fid, str) or not fid or any(c not in "0123456789abcdef" for c in fid):
            raise CapacityError("filesystem identity is unknown")
        fid = fid.lstrip("0") or "0"
        group = groups.setdefault(fid, {"filesystem_id": fid, "roles": [],
                                       "available_bytes": record["available_bytes"],
                                       "available_inodes": record["available_inodes"],
                                       "required_bytes": 0, "required_inodes": 0})
        group["roles"].append(record["role"])
        group["available_bytes"] = min(group["available_bytes"], record["available_bytes"])
        group["available_inodes"] = min(group["available_inodes"], record["available_inodes"])
        group["required_bytes"] += required
        group["required_inodes"] += inodes

    # Growth/checkpoint allowances add on a shared filesystem; the configured
    # minimum is a floor for that filesystem, not a fictional pool per PVC.
    for item in measurements:
        allocate(item, (item["logical_bytes"] + 4) // 5 + 2 * item["wal_bytes"], 1024)
    for group in groups.values():
        group["required_bytes"] = max(minimum, group["required_bytes"])
    allocate(transfer_info, 2 * archive_budget + METADATA_RESERVE if mode == "create" else 0, 32)
    for role, item in hosts.items():
        amount = ((archive_budget + RESOURCE_RESERVE) if role == "backup" else RESOURCE_RESERVE) if mode == "create" else 0
        allocate({"role": "host_" + role, **item}, amount, 64)
    report = {"format": "gsj.capacity/1", "measured_at": datetime.now(timezone.utc).isoformat(),
              "measurement": "quiesced" if quiesced else "live-estimate", "mode": mode,
              "archive_upper_bound_bytes": archive, "archive_budget_bytes": archive_budget,
              "resource_reserve_bytes": RESOURCE_RESERVE, "volumes": measurements,
              "filesystems": list(groups.values()), "physical_backend_independence": "unverified",
              "grouping": "equal observed filesystem IDs grouped conservatively; cross-host equality may overreserve",
              "reservation": False,
              "status": "passed"}
    for item in report["filesystems"]:
        item["passed"] = (item["available_bytes"] >= item["required_bytes"]
                          and item["available_inodes"] >= item["required_inodes"])
        if not item["passed"]:
            report["status"] = "insufficient"
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--volumes", required=True)
    parser.add_argument("--transfer", required=True)
    parser.add_argument("--hosts", required=True)
    parser.add_argument("--minimum", required=True, type=int)
    parser.add_argument("--mode", choices=("create", "reuse"), default="create")
    parser.add_argument("--quiesced", action="store_true")
    args = parser.parse_args()
    try:
        result = qualify(json.loads(args.volumes), args.transfer, json.loads(args.hosts),
                         args.minimum, args.mode, quiesced=args.quiesced)
    except (OSError, ValueError, OverflowError):
        # Exceptions can contain customer filenames; never emit their text.
        print(json.dumps({"format": "gsj.capacity/1", "status": "unknown",
                          "reason": "a filesystem, source layout or capacity could not be measured"}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
