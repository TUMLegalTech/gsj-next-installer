#!/usr/bin/env python3
"""Build the single-file installer; sign/verify its detached release descriptor.

Engineering tool only. The generated installer does not require host Python.
"""
from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path, PurePosixPath
import re
import shlex
import subprocess
import sys
import tarfile
import tempfile


HERE = Path(__file__).resolve().parent
_webpin_spec = importlib.util.spec_from_file_location("gsj_installer_webpin", HERE / "webpin.py")
webpin = importlib.util.module_from_spec(_webpin_spec)
_webpin_spec.loader.exec_module(webpin)
MIB = 1024 * 1024
# Measured on the real corpus's largest shard (263,992 chunks x 768 dims)
# inside the release's own web image:
#   read_shard_vectors transient high-water   1,732 MiB
#   the id -> row index the importer now holds     7.5 MiB
#   (the retired {id: [768 python floats]} form  7,797 MiB, 30,970 B/row)
# BASE covers everything that is not the shard's own vectors: interpreter, the
# pinned ONNX encoder `startup` loads even when released vectors make it
# unnecessary, the Chroma client, the ids/documents this site re-derives from
# its own XML, and the page cache the import holds against its own cgroup.
#
# Set from the full-install measurement, not the microbenchmark. On a
# reference k3s cluster, importing the real 1,141,170-vector corpus under the
# shipped defaults, the corpus-initialize container's cAdvisor figures peaked
# at:
#     container_memory_working_set_bytes   2,166 MiB
#     container_memory_max_usage_bytes     3,864 MiB   (cache-inclusive)
# The working set is what the OOM killer acts on and page cache is reclaimed
# before a kill, so the true floor is between the two. 3 GiB of base puts the
# declared requirement at 4,619 MiB for this corpus -- about 20% above the
# cache-inclusive peak, so the number the preflight refuses below is one the
# import provably never needed to exceed.
INITIALIZER_BASE_BYTES = 3072 * MIB
# float32 (4) + the float16 view it is upcast from (2), plus slack for the
# gzip input that is live across the decompress.
INITIALIZER_ROW_BYTES = 8
ROOT = HERE.parent.parent
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")
IMAGE_ROLES = {"web", "runner", "mcp", "forgejo", "chroma", "decisionsData"}
MARKER = "__GSJ_PAYLOAD_BELOW__"
RUNTIME_HELPERS = {"verification-cleanup.sh", "capacity.py", "backup-recovery.py", "restore-files.py", "startup-source-proof.py", "startup-recovery.sh", "startup-runtime-preflight.py", "stage-vectors.py"}


def fail(message: str):
    raise ValueError(message)


def canonical(value) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_manifest(path: Path) -> dict:
    value = json.loads(path.read_text())
    if not isinstance(value, dict) or value.get("schema") != "gsj.release/1":
        fail("manifest schema must be gsj.release/1")
    if not re.fullmatch(r"v?\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?", value.get("version", "")):
        fail("manifest version must be a release version")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value.get("identity", "")):
        fail("manifest identity must be an explicit stable release identity")
    core = value.get("core", {})
    if not re.fullmatch(r"v[0-9A-Za-z._-]+", core.get("tag", "")) or not re.fullmatch(r"[0-9a-f]{40}", core.get("commit", "")):
        fail("core must record its exact tag and full commit")
    corpus = value.get("corpus", {})
    for name in ("manifest_sha256", "fingerprint", "source_sha256"):
        if not HEX.fullmatch(corpus.get(name, "")):
            fail(f"corpus.{name}: exact fingerprint required")
    if any(type(corpus.get(name)) is not int or corpus[name] < 1 for name in ("rows", "chunks")):
        fail("corpus rows and chunks must be explicit positive counts")
    model = value.get("model", {})
    if set(model) != {"model", "revision", "manifest_sha256", "dimensions", "distance", "encoding"} or not HEX.fullmatch(model.get("manifest_sha256", "")) or not re.fullmatch(r"[a-f0-9]{40}", model.get("revision", "")) or type(model.get("dimensions")) is not int or model["dimensions"] < 1 or model.get("distance") != "cosine" or not model.get("model") or not isinstance(model.get("encoding"), str) or not model["encoding"]:
        fail("model must record the exact model, revision, file manifest hash, dimensions, cosine metric and encoding identity")
    schema_asset = value.get("schema_asset", {})
    if schema_asset.get("path") != "gsj/assets/schema_registry/snapshot.json.gz" or not HEX.fullmatch(schema_asset.get("sha256", "")):
        fail("schema_asset must identify the exact packaged core schema registry")
    distribution = value.get("release_base_url")
    if not isinstance(distribution, str) or (not distribution.startswith("https://") and not (distribution == "" and value.get("qualification") is True)):
        fail("release_base_url must be explicit HTTPS; only qualification may leave upgrade distribution unavailable")
    platforms = value.get("platforms")
    if not isinstance(platforms, list) or not platforms or len(set(platforms)) != len(platforms):
        fail("manifest platforms must be a nonempty unique list")
    if set(platforms) - {"linux/amd64", "linux/arm64"}:
        fail("only native Linux amd64/arm64 release platforms are currently supported")
    images = value.get("images", {})
    if set(images) != IMAGE_ROLES:
        fail("manifest must inventory exactly six images: " + ", ".join(sorted(IMAGE_ROLES)))
    for role, image in images.items():
        repository = image.get("repository", "")
        if not re.fullmatch(r"[a-z0-9][a-z0-9._:/-]*", repository) or "@" in repository:
            fail(f"{role}: invalid repository")
        if not DIGEST.fullmatch(image.get("digest", "")):
            fail(f"{role}: immutable image digest required")
        if set(image.get("platforms", {})) != set(platforms):
            fail(f"{role}: exact manifest for every declared native platform required")
        for platform, digest in image["platforms"].items():
            if not DIGEST.fullmatch(digest):
                fail(f"{role}/{platform}: invalid platform digest")
        if (repository.startswith("localhost:") or repository.startswith("127.0.0.1:")) and value.get("qualification") is not True:
            fail("loopback registry images require qualification=true")
    clients = value.get("clients", {})
    if not {"helm", "kubectl", "jq"}.issubset(clients):
        fail("clients must include helm, kubectl and jq")
    for tool, targets in clients.items():
        if not re.fullmatch(r"[a-z][a-z0-9-]*", tool):
            fail("invalid client name")
        if not set(platforms).issubset(targets):
            fail(f"{tool}: missing native client download")
        for platform, item in targets.items():
            if not re.fullmatch(r"(?:linux|darwin)/(?:amd64|arm64)", platform):
                fail(f"{tool}: invalid client platform")
            if not item.get("url", "").startswith("https://") or not HEX.fullmatch(item.get("sha256", "")):
                fail(f"{tool}/{platform}: HTTPS URL and SHA256 required")
    addons = value.get("addons", {})
    if set(addons) != {"traefik", "certManager", "localPath"}:
        fail("addons must inventory traefik, certManager and localPath")
    for name, item in addons.items():
        path = safe_name(item.get("path", ""))
        if not path.startswith("addons/") or not HEX.fullmatch(item.get("sha256", "")):
            fail(f"{name}: addon payload path and hash required")
        if not item.get("images") or not all(re.fullmatch(r"[a-z0-9][a-z0-9._:/-]*@sha256:[a-f0-9]{64}", ref) for ref in item["images"].values()):
            fail(f"{name}: every addon/helper image must have a fixed digest")
    return value


def client_table(clients: dict) -> str:
    lines = ["gsj_client_info() {", '  case "$1:$2" in']
    for tool, platforms in sorted(clients.items()):
        for platform, item in sorted(platforms.items()):
            lines.append("    " + shlex.quote(f"{tool}:{platform}") + ") printf '%s\\t%s\\n' " + shlex.quote(item["url"]) + " " + shlex.quote(item["sha256"]) + ";;")
    lines += ["    *) return 1;;", "  esac", "}"]
    return "\n".join(lines)


def safe_name(name: str) -> str:
    path = PurePosixPath(name)
    if not name or path.is_absolute() or ".." in path.parts or "\\" in name or str(path) != name:
        fail(f"unsafe payload path: {name!r}")
    return name


def runtime_helpers(runtime: str, build: dict, manifest_path: Path) -> dict[str, tuple[bytes, int]]:
    helpers = dict(build.get("helpers", {}))
    # An overridden historical runtime must retain its original payload. Only
    # explicit references add defaults; a marker names stdin-fed Python helpers.
    referenced = set(re.findall(r'^\s*(?:source|\.)\s+"\$GSJ_PAYLOAD/helpers/([^"\n]+)"\s*$', runtime, re.M))
    referenced.update(re.findall(r'^\s*# GSJ_RUNTIME_HELPER: ([^\s]+)\s*$', runtime, re.M))
    for name in sorted(referenced):
        if name not in helpers:
            if name not in RUNTIME_HELPERS:
                fail(f"runtime references an undeclared helper: {name}")
            path = HERE / name
            if not path.is_file() or path.is_symlink():
                fail(f"required runtime helper is missing or not a regular file: {name}")
            helpers[name] = {"path": str(path), "sha256": sha(path.read_bytes())}
    files = {}
    for name, item in sorted(helpers.items()):
        target = "helpers/" + safe_name(name)
        path = resolve(item["path"], manifest_path)
        if not path.is_file() or path.is_symlink():
            fail(f"helper is missing or not a regular file: {name}")
        data = path.read_bytes()
        if not HEX.fullmatch(item.get("sha256", "")) or sha(data) != item["sha256"]:
            fail(f"helper hash mismatch: {name}")
        files[target] = (data, 0o755 if item.get("executable") else 0o644)
    names = set(files)
    for name in names:
        if any(str(parent) in names for parent in PurePosixPath(name).parents):
            fail(f"helper payload file/directory collision: {name}")
    return files


def compressed_tar(files: dict[str, tuple[bytes, int]]) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, (data, mode) in sorted(files.items()):
            safe_name(name)
            member = tarfile.TarInfo(name)
            member.size, member.mode, member.mtime = len(data), mode, 0
            member.uid = member.gid = 0
            member.uname = member.gname = ""
            archive.addfile(member, io.BytesIO(data))
    compressed = io.BytesIO()
    with gzip.GzipFile(filename="", fileobj=compressed, mode="wb", compresslevel=9, mtime=0) as zipped:
        zipped.write(raw.getvalue())
    return compressed.getvalue()


def normalized_chart(path: Path, version: str) -> bytes:
    if path.is_dir():
        with tempfile.TemporaryDirectory(prefix="gsj-chart-") as temp:
            result = subprocess.run(["helm", "package", str(path), "--destination", temp], text=True, capture_output=True)
            if result.returncode:
                fail("helm package failed: " + result.stderr.strip())
            packages = list(Path(temp).glob("*.tgz"))
            if len(packages) != 1:
                fail("helm package did not emit exactly one chart")
            return normalized_chart(packages[0], version)
    files = {}
    with tarfile.open(path, "r:gz") as archive:
        for member in archive.getmembers():
            name = safe_name(member.name.rstrip("/"))
            if member.isdir():
                continue
            if not member.isfile() or name in files:
                fail("chart may contain only unique regular files")
            parts = PurePosixPath(name).parts
            if any(p in {"__pycache__", ".git", ".pytest_cache", ".DS_Store"} for p in parts) or name.endswith((".pyc", ".pyo")):
                fail(f"non-release file in chart: {name}")
            data = archive.extractfile(member).read()
            files[name] = (data, 0o755 if member.mode & 0o111 else 0o644)
    charts = [data for name, (data, _) in files.items() if len(PurePosixPath(name).parts) == 2 and name.endswith("/Chart.yaml")]
    if len(charts) != 1:
        fail("chart must contain exactly one root Chart.yaml")
    chart_text = charts[0].decode()
    for field in ("version", "appVersion"):
        matches = re.findall(r"^" + field + r":\s*['\"]?([^\s'\"]+)['\"]?\s*$", chart_text, re.M)
        if matches != [version.removeprefix("v")]:
            fail(f"chart {field} must match manifest version")
    return compressed_tar(files)


def public_key(path: Path) -> bytes:
    result = subprocess.run(["openssl", "rsa", "-pubin", "-in", str(path), "-text", "-noout"], capture_output=True, text=True)
    bits = re.search(r"\((\d+) bit\)", result.stdout)
    if result.returncode or not bits or int(bits[1]) < 3072:
        fail("trusted key must be an RSA public key of at least 3072 bits")
    return path.read_bytes()


def resolve(path: str, manifest_path: Path) -> Path:
    value = Path(path)
    return value if value.is_absolute() else manifest_path.resolve().parent / value


def bind_images_to_pin(images: dict, pin: dict):
    """A published build ships the pinned product release's images and no
    others. web-pin.json fills `release` and `images` together at promotion:
    until then every published build is refused here, and afterwards a manifest
    image that is not the pinned repository at the pinned digest is refused by
    name with both values -- so a manifest whose product-image repository or
    digest was edited after `ci/release.py build` wrote it can be neither built
    nor signed. Of the six images only these four are held to the pin: Forgejo
    and Chroma are approved upstream digests. The pin's one other hold is the
    chart, in prepare(): packaged from the pinned commit and refused unless it
    hashes to chart.sha256, its Chart.yaml holding this manifest's version.
    Nothing else is measured against the pin."""
    if not pin["release"] or not pin["images"]:
        fail("web-pin.json names no product release yet (release and images are empty): a published build waits for promotion to fill them; a proof build declares qualification: true")
    for role, pinned in sorted(pin["images"].items()):
        actual = images.get(role) or {}
        if (actual.get("repository"), actual.get("digest")) != (pinned["repository"], pinned["digest"]):
            named = str(actual.get("repository", "<missing>")) + "@" + str(actual.get("digest", "<missing>"))
            fail(f"images.{role}: the manifest names {named}, web-pin.json pins {pinned['repository']}@{pinned['digest']}")


def prepare(manifest_path: Path) -> tuple[dict, bytes, dict[str, tuple[bytes, int]]]:
    manifest = load_manifest(manifest_path)
    build = manifest.get("_build", {})
    status = subprocess.run(["git", "-C", str(ROOT), "status", "--porcelain", "--untracked-files=all"], check=True, capture_output=True, text=True).stdout
    if status.strip() and manifest.get("qualification") is not True:
        fail("published release packaging requires a clean worktree; use an explicitly qualified snapshot during development")
    # A PUBLISHED build is held to web-pin.json HERE, in the preparation that
    # `build` and `sign` share, not only in the hand-run release preparation
    # that writes the manifest. A qualification build is exempt: it names
    # loopback or proof images on purpose, and the pin may still be empty.
    published = manifest.get("qualification") is not True
    pin = webpin.load() if published or "chart" not in build else None
    if published:
        bind_images_to_pin(manifest["images"], pin)
    corpus_path = resolve(build.get("corpus_manifest", ""), manifest_path)
    if not corpus_path.is_file():
        fail("_build.corpus_manifest must identify the validated data-image source manifest")
    corpus_bytes = corpus_path.read_bytes()
    corpus = json.loads(corpus_bytes)
    fingerprint = sha(json.dumps({k: v for k, v in corpus.items() if k != "fingerprint"}, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode())
    if corpus.get("format") != "gsj.corpus/1" or corpus.get("fingerprint") != fingerprint:
        fail("corpus manifest fingerprint mismatch")
    if sha(corpus_bytes) != manifest["corpus"]["manifest_sha256"] or any(corpus.get(k) != manifest["corpus"].get(k) for k in ("fingerprint", "source_sha256", "rows", "chunks")):
        fail("release corpus identity does not match the validated source manifest")
    if corpus.get("core_commit") != manifest["core"]["commit"]:
        fail("corpus parser pin does not match the release core pin")
    if corpus.get("embedding") != manifest["model"]:
        fail("model identity does not match the corpus embedding contract")
    if len(corpus.get("files", [])) != corpus["rows"] or sum(f.get("chunks", 0) for f in corpus.get("files", [])) != corpus["chunks"]:
        fail("corpus file inventory does not match its aggregate counts")
    # The release DECLARES what its own corpus costs the
    # initializer, so a site can be refused BEFORE the install rather than
    # OOMKilled three shards in. The initializer holds one shard at a time:
    # read_shard_vectors decompresses the block, views it as float16 and
    # upcasts to float32, so the transient is the vector count times the
    # dimension times (4 + 2) bytes with slack, over a base that covers the
    # interpreter, the pinned ONNX encoder that startup loads even on the
    # released path, the Chroma client, and the ids and manifest this site
    # derives itself. Measured on the real corpus.
    # A corpus whose inventory does not name shards is treated as ONE shard --
    # the conservative reading, because the requirement then covers the whole
    # corpus at once. This never blocks a build: a declaration the installer
    # uses to refuse early must not itself become a new way for packaging to
    # fail.
    shard_chunks = {}
    for item in corpus["files"]:
        shard = item.get("shard") if isinstance(item.get("shard"), str) and item.get("shard") else ""
        shard_chunks[shard] = shard_chunks.get(shard, 0) + item["chunks"]
    manifest["corpus"]["max_shard_chunks"] = max(shard_chunks.values()) if shard_chunks else corpus["chunks"]
    manifest["corpus"]["initializer_memory_bytes"] = (
        INITIALIZER_BASE_BYTES
        + manifest["corpus"]["max_shard_chunks"] * manifest["model"]["dimensions"] * INITIALIZER_ROW_BYTES)
    if corpus.get("publication_ready") is not True and manifest.get("qualification") is not True:
        fail("qualification corpus cannot be packaged as a published release")
    if manifest.get("qualification") is not True and (not corpus.get("release_owner") or not corpus.get("source_provenance")):
        fail("published corpus requires its release owner and authoritative source provenance")
    trust_path = resolve(manifest.get("trust_key_file") or build.get("trust_key_file", ""), manifest_path)
    if not trust_path.is_file():
        fail("trust_key_file must identify the release public key")
    trust = public_key(trust_path)
    core_git = resolve(build["core_git_dir"], manifest_path) if "core_git_dir" in build else ROOT / "ops/.build/gsj-next.git"
    schema_asset = subprocess.run(["git", "--git-dir=" + str(core_git), "show", manifest["core"]["commit"] + ":" + manifest["schema_asset"]["path"]], check=True, capture_output=True).stdout
    if sha(schema_asset) != manifest["schema_asset"]["sha256"]:
        fail("packaged schema asset does not match the exact core git object")
    runtime_path = resolve(build["runtime"], manifest_path) if "runtime" in build else HERE / "runtime.sh"
    runtime = runtime_path.read_text()
    if runtime.count("@CLIENT_TABLE@") != 1:
        fail("runtime must contain exactly one @CLIENT_TABLE@ placeholder")
    if len(re.findall(r"^" + MARKER + r"$", runtime, re.M)) != 1:
        fail("runtime must contain exactly one payload marker line")
    header, trailing = runtime.rsplit(MARKER, 1)
    if trailing.strip():
        fail("the payload marker must be the last content in the runtime template")
    runtime = header.replace("@CLIENT_TABLE@", client_table(manifest["clients"])) + MARKER + "\n"
    files: dict[str, tuple[bytes, int]] = {"trust/release.pem": (trust, 0o644), "release.schema.json": ((HERE / "release.schema.json").read_bytes(), 0o644), "core-schema/snapshot.json.gz": (schema_asset, 0o644)}
    for name in ("site.schema.json", "defaults.json", "validate.jq", "compile.jq"):
        source = resolve(build[name], manifest_path) if name in build else HERE / name
        data = source.read_bytes()
        if name.endswith(".json"):
            json.loads(data)
        files[name] = (data, 0o644)
    # THE CHART IS THE PINNED PRODUCT'S, read from Git objects at web-pin.json's
    # commit — never a working tree. An explicit `_build.chart` is a
    # qualification-only override (a proof build against an edited chart); a
    # published release packages the pinned chart and refuses any other bytes.
    if "chart" in build:
        if manifest.get("qualification") is not True:
            fail("_build.chart overrides the pinned chart; only a qualification build may do that")
        files["chart.tgz"] = (normalized_chart(resolve(build["chart"], manifest_path), manifest["version"]), 0o644)
        web_commit = None
    else:
        with tempfile.TemporaryDirectory(prefix="gsj-pinned-chart-") as temp:
            chart_bytes = normalized_chart(webpin.archive("chart", Path(temp), pin), manifest["version"])
        if sha(chart_bytes) != pin["chart"]["sha256"]:
            fail("the chart at the pinned gsj-next-web commit does not hash to web-pin.json chart.sha256")
        files["chart.tgz"] = (chart_bytes, 0o644)
        web_commit = pin["commit"]
    for name, item in sorted(build.get("addons", {}).items()):
        target = "addons/" + safe_name(name)
        data = resolve(item["path"], manifest_path).read_bytes()
        if not HEX.fullmatch(item.get("sha256", "")) or sha(data) != item["sha256"]:
            fail(f"addon hash mismatch: {name}")
        files[target] = (data, 0o644)
    files.update(runtime_helpers(runtime, build, manifest_path))
    for name, item in manifest["addons"].items():
        if item["path"] not in files or sha(files[item["path"]][0]) != item["sha256"]:
            fail(f"{name}: public addon inventory does not match packaged bytes")
    public = {k: v for k, v in manifest.items() if k not in {"_build", "trust_key_file"}}
    public["payloadInventory"] = {name: {"sha256": sha(data), "bytes": len(data)} for name, (data, _) in sorted(files.items())}
    public["runtimeSha256"] = sha(runtime.encode())
    public["trustKeySha256"] = sha(trust)
    public["source"] = {**public.get("source", {}), "runtime_sha256": public["runtimeSha256"], "chart_sha256": sha(files["chart.tgz"][0])}
    if web_commit:
        public["source"]["web_commit"] = web_commit
    public["upgrade_distribution_available"] = bool(public["release_base_url"])
    public["identity_base"] = manifest["identity"]
    identity_hash = sha(canonical({k: v for k, v in public.items() if k != "identity"}))
    public["identity"] = manifest["identity"][:111] + "-" + identity_hash[:16]
    files["release.json"] = (canonical(public), 0o644)
    inventory = "".join(f"{sha(data)}  {name}\n" for name, (data, _) in sorted(files.items()))
    files["SHA256SUMS"] = (inventory.encode(), 0o644)
    return public, runtime.encode(), files


def write_new(path: Path, data: bytes, mode: int):
    # Exclusive creation prevents accidental replacement of an existing release.
    with path.open("xb") as output:
        output.write(data)
    path.chmod(mode)


def build_installer(args):
    public, runtime, files = prepare(args.manifest)
    payload = compressed_tar(files)
    installer = runtime + base64.encodebytes(payload)
    with tempfile.NamedTemporaryFile(prefix="gsj-installer-check-", suffix=".sh") as check:
        check.write(runtime[:runtime.rfind((MARKER + "\n").encode())])
        check.flush()
        subprocess.run(["bash", "-n", check.name], check=True)
    write_new(args.output, installer, 0o755)
    print(json.dumps({"installer": str(args.output), "sha256": sha(installer), "bytes": len(installer), "version": public["version"], "payloadFiles": len(files)}, sort_keys=True))


def sign(args):
    public, runtime, files = prepare(args.manifest)
    key_path = args.private_key.resolve()
    if any((parent / ".git").exists() for parent in (key_path.parent, *key_path.parents)):
        fail("the signing private key must be outside every repository")
    if key_path.stat().st_mode & 0o077:
        fail("the signing private key must be private (mode 0600 or stricter)")
    with tempfile.TemporaryDirectory(prefix="gsj-sign-") as temp:
        derived = Path(temp) / "public.pem"
        subprocess.run(["openssl", "pkey", "-in", str(key_path), "-pubout", "-out", str(derived)], check=True, capture_output=True)
        if sha(public_key(derived)) != public["trustKeySha256"]:
            fail("private key does not match the embedded release trust key")
    installer = args.installer.read_bytes()
    if installer != runtime + base64.encodebytes(compressed_tar(files)):
        fail("installer bytes do not match this manifest and its current build inputs")
    descriptor = canonical({"schema": "gsj.installer-descriptor/1", "version": public["version"], "releaseId": public["identity"], "qualification": public.get("qualification", False), "manifestSha256": sha(canonical(public)), "trustKeySha256": public["trustKeySha256"], "installer": {"name": args.installer.name, "sha256": sha(installer), "bytes": len(installer)}, "signature": "RSA-SHA256"})
    if args.descriptor.exists() or args.signature.exists():
        fail("refusing to replace an existing descriptor or signature")
    with tempfile.TemporaryDirectory(prefix="gsj-sign-") as temp:
        desc, signature = Path(temp) / "descriptor.json", Path(temp) / "signature.sig"
        desc.write_bytes(descriptor)
        subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(key_path), "-out", str(signature), str(desc)], check=True, capture_output=True)
        write_new(args.descriptor, descriptor, 0o644)
        write_new(args.signature, signature.read_bytes(), 0o644)
    print("Signed detached descriptor; private key was not embedded.")


def verify(args):
    trusted = public_key(args.public_key)
    result = subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(args.public_key), "-signature", str(args.signature), str(args.descriptor)], capture_output=True)
    if result.returncode:
        fail("descriptor signature verification failed")
    descriptor = json.loads(args.descriptor.read_text())
    if descriptor.get("schema") != "gsj.installer-descriptor/1" or descriptor.get("signature") != "RSA-SHA256":
        fail("unsupported release descriptor")
    if descriptor.get("trustKeySha256") != sha(trusted):
        fail("descriptor does not match the supplied trusted key")
    installer = args.installer.read_bytes()
    if descriptor.get("installer", {}).get("sha256") != sha(installer) or descriptor["installer"].get("bytes") != len(installer):
        fail("installer does not match the signed descriptor")
    print("Verified signed descriptor and exact installer bytes; installer was not executed.")


def main():
    if len(sys.argv) > 1 and sys.argv[1] in {"sign", "verify"}:
        command = sys.argv.pop(1)
    else:
        command = "build"
    parser = argparse.ArgumentParser(description=__doc__)
    if command == "build":
        parser.add_argument("--manifest", required=True, type=Path)
        parser.add_argument("--output", required=True, type=Path)
        action = build_installer
    elif command == "sign":
        for option in ("manifest", "installer", "private-key", "descriptor", "signature"):
            parser.add_argument("--" + option, required=True, type=Path)
        action = sign
    else:
        for option in ("installer", "descriptor", "signature", "public-key"):
            parser.add_argument("--" + option, required=True, type=Path)
        action = verify
    try:
        action(parser.parse_args())
    except (ValueError, OSError, KeyError, TypeError, subprocess.CalledProcessError, tarfile.TarError) as error:
        print(f"gsj release packaging: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
