# GSJ_RUNTIME_HELPER: stage-vectors.py
"""Publish released corpus vectors beside the copied shards, proven first.

Runs INSIDE the application pod with the data volume mounted. The installer
sends the manifest and the blocks it names as one uncompressed tar on stdin -
the blocks are already gzip, so the envelope adds no second codec.

The MANIFEST is proven BEFORE json.loads ever sees it: its sha256 must equal
the one the site declared as corpus.vectors_sha256, so a substituted manifest
is never parsed. Only members that manifest names are written, each checked
against its size and digest, and every name must be a plain file in the corpus
root - a member carrying a path separator or a parent reference is refused
rather than sanitised.

The seven blocks are published as separate release assets, so the installer
fetches a 2.4 KB manifest and seven objects rather than one 1.6 GB one. The
root of trust moved from a digest over the whole tarball to a digest over the
manifest - the same depth, since the tarball's digest only ever reached the
members THROUGH that manifest, which was already the thing every member was
checked against.

This is a staging step, not a trust decision: the initializer verifies the set
again, against the ids IT derives, before a single vector is stored.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile


def sha(data):
    return hashlib.sha256(data).hexdigest()


def publish(path, data):
    """Write on the destination filesystem and persist the directory entry."""
    fd, temp = tempfile.mkstemp(prefix=".pending-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.chmod(temp, 0o644)
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def main():
    destination, expected = Path(sys.argv[1]), sys.argv[2]
    raw = sys.stdin.buffer.read()
    if not destination.is_dir() or destination.is_symlink():
        raise ValueError("corpus destination is not an ordinary directory")
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tar:
        entries = {member.name: member for member in tar.getmembers() if member.isfile()}
        for name in entries:
            if Path(name).name != name or name in ("", ".", ".."):
                raise ValueError("vectors archive carries a path, not a plain corpus file")
        if "vectors.json" not in entries:
            raise ValueError("vectors archive has no vectors.json")
        manifest_bytes = tar.extractfile(entries["vectors.json"]).read()
        if sha(manifest_bytes) != expected:
            raise ValueError("staged vectors manifest differs from its recorded sha256")
        manifest = json.loads(manifest_bytes)
        shards = {item["archive"]: item for item in manifest.get("shards", [])}
        if set(entries) != {"vectors.json"} | set(shards):
            raise ValueError("vectors archive contents differ from its own manifest")
        written = 0
        for name, shard in sorted(shards.items()):
            member = entries[name]
            if member.size != shard["bytes"]:
                raise ValueError(f"{name}: size differs from the vectors manifest")
            data = tar.extractfile(member).read()
            if sha(data) != shard["sha256"]:
                raise ValueError(f"{name}: sha256 differs from the vectors manifest")
            publish(destination / name, data)
            written += shard["vectors"]
        # The manifest lands LAST: the initializer keys off vectors.json, so it
        # must never be visible before the blocks it describes are all on disk.
        publish(destination / "vectors.json", manifest_bytes)
    print(json.dumps({"format": "gsj.vectors-staged/1", "vectors": written,
                      "shards": len(shards), "bytes": len(raw),
                      "corpus_fingerprint": manifest.get("corpus_fingerprint", ""),
                      "fingerprint": manifest.get("fingerprint", "")}, sort_keys=True))


if __name__ == "__main__":
    main()
