#!/usr/bin/env python3
"""The product pin: which gsj-next-web commit this installer builds against.

`web-pin.json` at the repository root names ONE commit of gsj-next-web and
records the identity of what the installer takes from it: the chart's version,
its Git tree hash and the sha256 of the chart as `build.py` packages it, the
gsj_deploy package's tree hash, the core library tag that commit ships, and,
once the product half has a release, the release name and its image digests.

Nothing here reads a working tree. The chart and every other product file are
read from Git objects at the pinned commit, so a sibling checkout that sits on
another branch, or carries uncommitted edits, cannot leak into a build or a
test. The Git directory that holds the commit is, in order: the environment's
GSJ_NEXT_WEB_GIT_DIR, the staged bare clone `ops/.build/gsj-next-web.git`, or
the sibling checkout `../gsj-next-web`.

This is engineering tooling for the installer's builds and tests. The
generated installer never needs it.
"""
from __future__ import annotations

import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
PIN_FILE = ROOT / "web-pin.json"
SCHEMA = "gsj.web-pin/1"
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
IMAGE_ROLES = ("web", "runner", "mcp", "decisionsData")


def fail(message: str):
    raise ValueError(message)


def load(path: Path = PIN_FILE) -> dict:
    pin = json.loads(path.read_text())
    if pin.get("schema") != SCHEMA:
        fail("web-pin.json: schema must be " + SCHEMA)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*", pin.get("repository", "")):
        fail("web-pin.json: repository must be owner/name")
    if not COMMIT.fullmatch(pin.get("commit", "")):
        fail("web-pin.json: commit must be a full 40-hex commit id")
    release = pin.get("release", "")
    if release != "" and not re.fullmatch(r"v\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?", release):
        fail("web-pin.json: release is empty (no product release yet) or a v-prefixed release tag")
    chart = pin.get("chart", {})
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?", chart.get("version", "")):
        fail("web-pin.json: chart.version must be the chart's SemVer")
    if not COMMIT.fullmatch(chart.get("tree", "")) or not HEX.fullmatch(chart.get("sha256", "")):
        fail("web-pin.json: chart.tree (git tree id) and chart.sha256 (normalized package) are required")
    if not COMMIT.fullmatch(pin.get("gsj_deploy", {}).get("tree", "")):
        fail("web-pin.json: gsj_deploy.tree (git tree id) is required")
    if not re.fullmatch(r"v[0-9A-Za-z._-]+", pin.get("core", {}).get("tag", "")):
        fail("web-pin.json: core.tag must be the library tag the pinned product ships")
    images = pin.get("images", {})
    if not isinstance(images, dict) or (images and set(images) != set(IMAGE_ROLES)):
        fail("web-pin.json: images is empty until the product half has a release, then exactly " + ", ".join(IMAGE_ROLES))
    for role, image in images.items():
        if not re.fullmatch(r"[a-z0-9][a-z0-9._:/-]*", image.get("repository", "")) or "@" in image["repository"]:
            fail(f"web-pin.json: images.{role}.repository is invalid")
        if not DIGEST.fullmatch(image.get("digest", "")):
            fail(f"web-pin.json: images.{role}.digest must be an immutable sha256 digest")
    if bool(release) != bool(images):
        fail("web-pin.json: release and images are set together, at promotion")
    return pin


def git_dir(pin: dict | None = None) -> Path:
    """The Git directory holding the pinned commit, or a ValueError naming the recipe."""
    pin = pin or load()
    candidates = []
    if os.environ.get("GSJ_NEXT_WEB_GIT_DIR"):
        candidates.append(Path(os.environ["GSJ_NEXT_WEB_GIT_DIR"]))
    candidates += [ROOT / "ops/.build/gsj-next-web.git", ROOT.parent / "gsj-next-web"]
    for candidate in candidates:
        if not candidate.exists():
            continue
        probe = subprocess.run(["git", "-C", str(candidate), "cat-file", "-e", pin["commit"] + "^{commit}"],
                               capture_output=True)
        if probe.returncode == 0:
            return candidate
    fail("the pinned gsj-next-web commit " + pin["commit"][:12] + " is in no Git directory here; "
         "stage one with `git clone --bare <gsj-next-web> ops/.build/gsj-next-web.git` "
         "(or set GSJ_NEXT_WEB_GIT_DIR, or keep a ../gsj-next-web sibling that carries the commit)")


def available() -> bool:
    try:
        git_dir()
        return True
    except (ValueError, OSError):
        return False


def _git(directory: Path, *args: str) -> bytes:
    return subprocess.run(["git", "-C", str(directory), *args], check=True, capture_output=True).stdout


def tree(path: str, pin: dict | None = None) -> str:
    """The Git tree (or blob) id of `path` at the pinned commit."""
    pin = pin or load()
    return _git(git_dir(pin), "rev-parse", pin["commit"] + ":" + path).decode().strip()


def show(path: str, pin: dict | None = None) -> bytes:
    """The bytes of one file at the pinned commit."""
    pin = pin or load()
    return _git(git_dir(pin), "show", pin["commit"] + ":" + path)


def archive(path: str, destination: Path, pin: dict | None = None) -> Path:
    """Materialize one directory of the pinned commit under `destination`.

    Modes travel (the chart's scripts keep their executable bit); nothing else
    from the archive is trusted: every member must be a regular file or a
    directory below `path`."""
    pin = pin or load()
    data = _git(git_dir(pin), "archive", "--format=tar", pin["commit"], path)
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tar:
        for member in tar.getmembers():
            name = member.name
            if not (member.isfile() or member.isdir()) or name.startswith("/") or ".." in name.split("/"):
                fail("refusing an archive member that is not a plain file below the path: " + name)
            if name != path and not name.startswith(path + "/"):
                fail("archive member outside the requested path: " + name)
        tar.extractall(destination, filter="data")
    return destination / path


def core_tag(pin: dict | None = None) -> str:
    """The gsj-next tag the pinned product ships, read from ITS pin home."""
    pin = pin or load()
    text = show("requirements-local.txt", pin).decode()
    match = re.search(r"(?m)^gsj\[cli\] @ git\+file://[^\n]+@([^\s]+)$", text)
    if not match:
        fail("the pinned gsj-next-web requirements-local.txt carries no gsj pin line")
    return match.group(1)


def chart_version(pin: dict | None = None) -> str:
    pin = pin or load()
    text = show("chart/Chart.yaml", pin).decode()
    versions = re.findall(r"(?m)^version:\s*['\"]?([^\s'\"]+)['\"]?\s*$", text)
    if len(versions) != 1:
        fail("the pinned chart/Chart.yaml must carry exactly one version line")
    return versions[0]


if __name__ == "__main__":
    value = load()
    print(json.dumps({"commit": value["commit"], "chart_version": value["chart"]["version"],
                      "git_dir": str(git_dir(value)), "core_tag": core_tag(value)}, indent=2))
