#!/usr/bin/env python3
"""Fetch fixed upstream addon payloads and produce the dedicated local-path profile."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess


SOURCES = {
    "traefik": ("traefik-41.5.0.tgz", "https://traefik.github.io/charts/traefik/traefik-41.5.0.tgz", "30f8db73182019b2764179d7fc0a7efc9505670204f847ffc3a779bacaae3a1a"),
    "certManager": ("cert-manager-v1.21.2.tgz", "https://charts.jetstack.io/charts/cert-manager-v1.21.2.tgz", "73a56e1728edd6c99f1f31082618c3259d279a76b7ebd3d4bdc5475c2442d34a"),
    "localPath": ("local-path-v0.0.37-gsj.yaml", "https://raw.githubusercontent.com/rancher/local-path-provisioner/v0.0.37/deploy/local-path-storage.yaml", "9781b39c24f3f651bd6d6e41b561e04e4904bbdb6d4f8c7a6009df3a702dcd65"),
}
IMAGES = {
    "traefik": {"traefik": "docker.io/traefik@sha256:f86a2cab1b5c649070c49f883c743dd32d8485a56e3368c5f93b9e91f1e91259"},
    "certManager": {
        "controller": "quay.io/jetstack/cert-manager-controller@sha256:70f532fd9cfde0b09d55687200942399d89838bc2d5d5b45152eb799a15912b8",
        "cainjector": "quay.io/jetstack/cert-manager-cainjector@sha256:c85268c64f2e0e76684bf5fe8906caff34b82523561c6affe0fae3546bd87562",
        "webhook": "quay.io/jetstack/cert-manager-webhook@sha256:a60e2dac46dbb8a7f3df95c54ce941012f54c2fe022f0ee55aaa1ab40ed957ae",
        "startupapicheck": "quay.io/jetstack/cert-manager-startupapicheck@sha256:46e75b6866359ffb5d82624f41e3ed1c70b2994982702ced547ce5edb418a8f5",
        "acmesolver": "quay.io/jetstack/cert-manager-acmesolver@sha256:699b40d622211ab7accad8a21b04c5fbaa1841ef7a12621e8de492dbe27b2503",
    },
    "localPath": {
        "provisioner": "docker.io/rancher/local-path-provisioner@sha256:e757967a5ec338f6a9b371c5a9688bedaa8c3578ea3dd4db329ea0084be0a86f",
        "helper": "docker.io/library/busybox@sha256:9db7b59979c38555a39def84a31fb98b5296952f9e3afd4f6f11f05b07adfab0",
    },
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def local_path(data):
    text = data.decode()
    docs = re.split(r"^---\s*$", text, flags=re.M)
    selected = [doc for doc in docs if not re.search(r"^kind: StorageClass\s*$", doc, re.M)]
    if len(docs) - len(selected) != 1:
        raise ValueError("expected exactly one upstream StorageClass")
    text = "---\n".join(selected).replace("local-path-storage", "gsj-storage")
    # ClusterRole/Binding names must coexist with kind's built-in provisioner.
    text = text.replace("local-path-provisioner-role", "gsj-local-path-provisioner-role")
    text = text.replace("local-path-provisioner-bind", "gsj-local-path-provisioner-bind")
    replacements = {
        "image: docker.io/rancher/local-path-provisioner:v0.0.37": "image: " + IMAGES["localPath"]["provisioner"],
        "image: docker.io/library/busybox\n": "image: " + IMAGES["localPath"]["helper"] + "\n",
        "            - start\n": "            - start\n            - --provisioner-name\n            - rancher.io/gsj-local-path\n",
        "/opt/local-path-provisioner": "/var/local-path-provisioner/gsj-managed",
        "kind: Namespace\nmetadata:\n  name: gsj-storage": "kind: Namespace\nmetadata:\n  name: gsj-storage\n  labels:\n    app.kubernetes.io/managed-by: gsj-installer\n    pod-security.kubernetes.io/enforce: privileged",
    }
    for old, new in replacements.items():
        if text.count(old) != 1:
            raise ValueError("upstream local-path transform precondition changed")
        text = text.replace(old, new)
    return text.encode()


PAYLOADS = frozenset(item[0] for item in SOURCES.values())


def own_directory(path):
    """The output directory: created here, private, or an existing plain
    directory this user owns, not writable by group or others, holding nothing
    but plain files this user owns, named as add-on payloads (a partial fetch
    resumes; a previous run's inventory.json is not admitted). Anything else
    is refused by name BEFORE any write: a symlink in place of the directory
    or of an entry would otherwise turn a write here into a write elsewhere.
    So would a symlink another user planted higher up the path (a shared
    /tmp): a symlinked ancestor is admitted only when root or this user owns
    it, and no ancestor is created here. Every check is an lstat. Returns the
    refusal, or None."""
    for ancestor in path.absolute().parents:
        try:
            link = os.lstat(ancestor)
        except FileNotFoundError:
            return f"refusing {path}: its parent {ancestor} does not exist (this run creates only the output directory itself)"
        if stat.S_ISLNK(link.st_mode) and link.st_uid not in (0, os.geteuid()):
            return f"refusing {path}: {ancestor} is a symlink owned by uid {link.st_uid}, neither root nor this user"
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        os.mkdir(path, 0o700)
        return None
    if stat.S_ISLNK(info.st_mode):
        return f"refusing {path}: it is a symlink"
    if not stat.S_ISDIR(info.st_mode):
        return f"refusing {path}: not a directory"
    if info.st_uid != os.geteuid():
        return f"refusing {path}: owned by uid {info.st_uid}, not by this user (uid {os.geteuid()})"
    if info.st_mode & 0o022:
        return f"refusing {path}: writable by group or others (mode {stat.S_IMODE(info.st_mode):o})"
    with os.scandir(path) as entries:
        for entry in sorted(entries, key=lambda item: item.name):
            found = entry.stat(follow_symlinks=False)
            if entry.name not in PAYLOADS:
                return f"refusing {path}: it holds {entry.name}; only an empty directory or a partial fetch of the fixed add-on files is admitted"
            if stat.S_ISLNK(found.st_mode) or not stat.S_ISREG(found.st_mode):
                return f"refusing {path}: {entry.name} is not a plain file"
            if found.st_uid != os.geteuid():
                return f"refusing {path}: {entry.name} is owned by uid {found.st_uid}, not by this user"
    return None


def write_new(path, data):
    """Create-only: O_EXCL fails on any existing name, a link included, and
    O_NOFOLLOW never opens through one."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)
    with os.fdopen(descriptor, "wb") as output:
        output.write(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    refusal = own_directory(args.output)
    if refusal:
        parser.error(refusal)
    addons, inputs = {}, {}
    for name, (filename, url, expected) in SOURCES.items():
        raw = subprocess.run(["curl", "--fail", "--silent", "--show-error", "--location", "--retry", "3", "--max-time", "120", url], check=True, capture_output=True).stdout
        if digest(raw) != expected:
            raise ValueError("upstream addon hash mismatch: " + name)
        data = local_path(raw) if name == "localPath" else raw
        target = args.output / filename
        if target.exists():    # a partial fetch: own_directory admitted it as a plain file of this user's
            if target.read_bytes() != data:
                raise ValueError("refusing to replace a different existing addon payload")
        else:
            write_new(target, data)
        addon = {"path": "addons/" + filename, "sha256": digest(data), "sourceUrl": url, "sourceSha256": expected, "images": IMAGES[name]}
        if name == "localPath":
            addon.update(namespace="gsj-storage", provisioner="rancher.io/gsj-local-path", dataPath="/var/local-path-provisioner/gsj-managed", storageClassIncluded=False)
        addons[name] = addon
        inputs[filename] = {"path": str(target.resolve()), "sha256": digest(data)}
    write_new(args.output / "inventory.json", (json.dumps({"addons": addons, "buildAddons": inputs}, sort_keys=True, indent=2) + "\n").encode())
    print(args.output / "inventory.json")


if __name__ == "__main__":
    main()
