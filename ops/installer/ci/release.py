#!/usr/bin/env python3
"""Release engineering: approved inputs + the pinned product -> the six-image inventory.

No image is built here. The four product images (web, runner, mcp and the
decisions-data image) are published by the product repository's own release
and PINNED here by digest (web-pin.json, filled at promotion); Forgejo and
Chroma are the approved upstream digests. This script inspects every one of
them in the registry, reads the corpus manifest out of the pinned
decisions-data image, and writes the release manifest build.py signs.

No Kubernetes installation lives here. Qualification invokes the distributed
installer; publication is a separate, hand-run step after the qualification
gates. Releases are hand-run: nothing here reads a CI secret.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[3]
_webpin_spec = importlib.util.spec_from_file_location("gsj_installer_webpin", ROOT / "ops/installer/webpin.py")
webpin = importlib.util.module_from_spec(_webpin_spec)
_webpin_spec.loader.exec_module(webpin)
ROLES = {"web": "gsj-web", "runner": "gsj-agent-runner", "mcp": "gsj-next-mcp",
         "forgejo": "gsj-forgejo", "chroma": "gsj-chroma", "decisionsData": "gsj-decisions-data"}
HEX = re.compile(r"[a-f0-9]{64}\Z")
DIGEST = re.compile(r"sha256:[a-f0-9]{64}\Z")
PLATFORM = "linux/amd64"
FROM = re.compile(r"\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?\s*", re.I)


def require(value, message):
    if not value:
        raise ValueError(message)


def run(*args, capture=False, **kw):
    return subprocess.run(list(map(str, args)), check=True, text=True,
                          stdout=subprocess.PIPE if capture else None, **kw).stdout


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def save(path, value):
    Path(path).write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError("release inputs must use their final HTTPS origin; redirects are refused")


class PublicHttpsRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        require(parsed.scheme == "https" and parsed.hostname and not parsed.username and not parsed.password,
                "public client redirect must remain credential-free HTTPS")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(item, target, token="", *, allow_public_redirects=False):
    parsed = urllib.parse.urlsplit(item["url"])
    require(parsed.scheme == "https" and parsed.hostname and not parsed.username
            and not parsed.password and not parsed.fragment, "invalid release input URL")
    require(HEX.fullmatch(item["sha256"]), "release input requires SHA256")
    target = Path(target)
    require(not target.exists(), "release input destination must be fresh")
    target.parent.mkdir(parents=True, exist_ok=True)
    headers = {"Authorization": "Bearer " + token} if token else {}
    require(not (token and allow_public_redirects), "authenticated release inputs cannot redirect")
    opener = urllib.request.build_opener(PublicHttpsRedirect() if allow_public_redirects else NoRedirect())
    with opener.open(urllib.request.Request(item["url"], headers=headers), timeout=120) as response, target.open("xb") as output:
        shutil.copyfileobj(response, output, 1024 * 1024)
    require(sha(target) == item["sha256"], "release input hash mismatch")


def clients(destination, tools=("helm",)):
    """Native engineering clients from ops/installer/clients.json, hash-verified.

    The release builder packages the chart with this Helm, never an action-installed one.
    """
    catalog = json.loads((ROOT / "ops/installer/clients.json").read_bytes())
    destination.mkdir(parents=True)
    for tool in tools:
        archive = destination / (tool + ".download")
        download(catalog[tool][PLATFORM], archive, allow_public_redirects=True)
        if tool == "helm":
            with tarfile.open(archive, "r:gz") as tar:
                member = tar.getmember("linux-amd64/helm")
                require(member.isfile(), "Helm archive executable is not a regular file")
                data = tar.extractfile(member).read()
        else:
            data = archive.read_bytes()
        (destination / tool).write_bytes(data)
        (destination / tool).chmod(0o500)
        archive.unlink()


def inputs(destination):
    require(not destination.exists(), "release input directory must be fresh")
    destination.mkdir(parents=True)
    required = ("GSJ_RELEASE_MANIFEST_URL", "GSJ_RELEASE_MANIFEST_SHA256")
    require(all(os.environ.get(name, "").strip() for name in required), "approved release inputs are missing")
    token = os.environ.get("GSJ_RELEASE_INPUT_TOKEN", "")
    origin = urllib.parse.urlsplit(os.environ[required[0]])
    def input_token(url):
        other = urllib.parse.urlsplit(url)
        return token if (other.scheme, other.hostname, other.port or 443) == (origin.scheme, origin.hostname, origin.port or 443) else ""
    download({"url": os.environ[required[0]], "sha256": os.environ[required[1]]}, destination / "inputs.json", token)
    catalog = json.loads((destination / "inputs.json").read_bytes())
    require(catalog.get("schema") == "gsj.release-inputs/1", "unsupported release input catalog")
    require(not ({"images", "corpus", "core", "_build", "qualification"} & catalog.keys()),
            "approved inputs must not supply application image refs or generated release identities")
    require(set(catalog.get("upstreamImages", {})) == {"forgejo", "chroma"}, "approved upstream image pair is required")
    for reference in catalog["upstreamImages"].values():
        require(re.fullmatch(r"[a-z0-9][a-z0-9._:/-]*@sha256:[a-f0-9]{64}", reference), "upstream image must be immutable")
    require(set(catalog.get("addons", {})) == {"traefik", "certManager", "localPath"}, "all three approved addons are required")
    for role, item in catalog["addons"].items():
        name = PurePosixPath(item["path"])
        require(str(name) == item["path"] and len(name.parts) == 2 and name.parts[0] == "addons",
                "addon destination must be directly inside addons/")
        download(item, destination / item["path"], input_token(item["url"]))
    require(set(catalog.get("clients", {})) >= {"helm", "kubectl", "jq"}, "client catalog is incomplete")
    for tool, platforms in catalog["clients"].items():
        require(re.fullmatch(r"[a-z][a-z0-9-]*", tool) and PLATFORM in platforms, "native installer client missing")
        for platform, item in platforms.items():
            require(re.fullmatch(r"(?:linux|darwin)/(?:amd64|arm64)", platform), "invalid client platform")
            download(item, destination / "client-checks" / tool / platform.replace("/", "-"), allow_public_redirects=True)
    download(catalog["trust"], destination / "release.pem", input_token(catalog["trust"]["url"]))
    baseline = catalog.get("qualificationSource", {})
    require(set(baseline) == {"installer", "descriptor", "signature", "trust"}, "signed populated-upgrade source bundle is required")
    for role, item in baseline.items():
        download(item, destination / "baseline" / {"installer": "gsj-install.sh", "descriptor": "installer-descriptor.json", "signature": "installer-descriptor.sig", "trust": "release.pem"}[role], input_token(item["url"]))


def inspect_image(reference, *, allow_additional_platforms=False):
    digest = run("docker", "buildx", "imagetools", "inspect", reference, "--format", "{{.Manifest.Digest}}", capture=True).strip()
    require(DIGEST.fullmatch(digest), "remote image digest is unavailable")
    repository = reference.rsplit("@", 1)[0] if "@" in reference else reference.rsplit(":", 1)[0]
    require("@" not in reference or reference.rsplit("@", 1)[1] == digest, "remote image differs from its approved digest")
    immutable = repository + "@" + digest
    raw = json.loads(run("docker", "buildx", "imagetools", "inspect", immutable, "--raw", capture=True))
    if "manifests" in raw:
        children = {x["platform"]["os"] + "/" + x["platform"]["architecture"]: x["digest"]
                    for x in raw["manifests"] if x.get("platform", {}).get("os") != "unknown"}
        require(PLATFORM in children and (allow_additional_platforms or set(children) == {PLATFORM}), "unexpected native image platform inventory")
        child = children[PLATFORM]
    else:
        child = digest
    run("docker", "pull", "--platform", PLATFORM, repository + "@" + child)
    actual = run("docker", "image", "inspect", repository + "@" + child,
                 "--format", "{{.Os}}/{{.Architecture}}", capture=True).strip()
    require(actual == PLATFORM, "remote image platform does not match the release")
    return {"repository": repository, "digest": digest, "platforms": {PLATFORM: child}}


def base_images(dockerfile):
    """Resolve every external FROM reference immediately before its build."""
    froms = [match for match in map(FROM.fullmatch, dockerfile.read_text().splitlines()) if match]
    stages = {match[2].lower() for match in froms if match[2]}
    require(froms and froms[-1][1].lower() not in stages, "final build stage must extend an external base image")
    external = dict.fromkeys(match[1] for match in froms if match[1].lower() not in stages)
    return [{"reference": ref, "final": ref == froms[-1][1], **inspect_image(ref, allow_additional_platforms=True)}
            for ref in external]


def installed(reference, bases):
    """Bind the final base as a layer prefix; list installed packages offline."""
    def layers(image):
        return json.loads(run("docker", "image", "inspect", image, "--format", "{{json .RootFS.Layers}}", capture=True))
    final = next(base for base in bases if base["final"])
    prefix = layers(final["repository"] + "@" + final["platforms"][PLATFORM])
    require(layers(reference)[:len(prefix)] == prefix, "built image does not extend its resolved base image")
    offline = ("docker", "run", "--rm", "--network", "none", "--read-only", "--entrypoint")
    return {"bases": bases,
            "python": run(*offline, "python", reference, "-m", "pip", "freeze", "--all",
                          "--disable-pip-version-check", capture=True).splitlines(),
            "system": run(*offline, "dpkg-query", reference, "-W", "-f", "${binary:Package}=${Version}\\n",
                          capture=True).splitlines()}


def corpus_manifest_from_image(reference, destination):
    """Copy /corpus/manifest.json out of the pinned decisions-data image, and
    require the image's own label to name the same bytes. Nothing runs."""
    manifest_sha = run("docker", "image", "inspect", reference, "--format",
                       '{{index .Config.Labels "io.gsj.corpus.manifest-sha256"}}', capture=True).strip()
    require(HEX.fullmatch(manifest_sha), "the decisions-data image carries no corpus manifest label")
    container = run("docker", "create", "--platform", PLATFORM, reference, capture=True).strip()
    try:
        run("docker", "cp", container + ":/corpus/manifest.json", destination / "manifest.json")
    finally:
        run("docker", "rm", "-f", container, capture=True)
    require(sha(destination / "manifest.json") == manifest_sha, "the decisions-data image's corpus manifest differs from its label")
    return json.loads((destination / "manifest.json").read_bytes())


def build(destination):
    """The six-image inventory of a release, from the pinned product and the
    approved inputs; no image is built or pushed here.

    web, runner, mcp and decisionsData are the product release's published
    digests (web-pin.json `images`, filled at promotion); forgejo and chroma
    are the approved upstream digests from the input catalog. The corpus
    manifest is read out of the pinned decisions-data image. The release
    version is the pinned product release's, so build.py's chart-version check
    binds the packaged chart to it."""
    catalog = json.loads((destination / "inputs.json").read_bytes())
    pin = webpin.load()
    require(pin["release"] and pin["images"],
            "web-pin.json names no product release yet: a published installer waits for promotion to fill "
            "`release` and `images`; a qualification build is a hand-assembled manifest (README)")
    version = pin["release"]
    require(re.fullmatch(r"v0\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?", version), "v1 and later stay blocked until the product records its v1.0.0 gate")
    require(version == "v" + pin["chart"]["version"], "web-pin.json: release and chart.version disagree")
    commit = run("git", "-C", ROOT, "rev-parse", "HEAD", capture=True).strip()
    require(not run("git", "-C", ROOT, "status", "--porcelain", "--untracked-files=all", capture=True).strip(), "release source must be clean")
    core_tag = webpin.core_tag(pin)
    require(core_tag == pin["core"]["tag"], "the pinned product ships a library tag web-pin.json does not record")
    core_git = ROOT / "ops/.build/gsj-next.git"
    require(core_git.exists(), "stage the library: git clone --bare <gsj-next> ops/.build/gsj-next.git")
    core_commit = run("git", "--git-dir=" + str(core_git), "rev-parse", core_tag + "^{commit}", capture=True).strip()
    # Managed add-on controller/helper digests get the same registry and native
    # platform check as the application images, before signing.
    addon_images = {role: {name: inspect_image(ref, allow_additional_platforms=True) for name, ref in item["images"].items()}
                    for role, item in catalog["addons"].items()}
    references = {role: image["repository"] + "@" + image["digest"] for role, image in pin["images"].items()}
    references.update({role: source for role, source in catalog["upstreamImages"].items()})
    require(set(references) == set(ROLES), "six-image release inventory is incomplete")
    inventory = {role: inspect_image(reference) for role, reference in references.items()}
    # The product's Dockerfiles at the pin name each image's base; the base
    # is verified as a layer prefix of the published image, and the installed
    # Python and Debian packages are listed offline, as evidence.
    dockerfiles = destination / "dockerfiles"
    dockerfiles.mkdir()
    (dockerfiles / "web").write_bytes(webpin.show("ops/Dockerfile", pin))
    (dockerfiles / "runner").write_bytes(webpin.show("ops/Dockerfile.runner", pin))
    (dockerfiles / "mcp").write_bytes(run("git", "--git-dir=" + str(core_git), "show", core_commit + ":services/mcp/Dockerfile", capture=True).encode())
    dependencies = {role: installed(references[role], base_images(dockerfiles / role)) for role in ("web", "runner", "mcp")}
    (destination / "corpus").mkdir()
    corpus = corpus_manifest_from_image(references["decisionsData"], destination / "corpus")
    require(corpus.get("format") == "gsj.corpus/1", "the decisions-data image carries no gsj.corpus/1 manifest")
    require(corpus["embedding"] == catalog["model"], "approved model contract differs from the corpus the data image carries")
    require(corpus.get("core_commit") == core_commit, "the corpus was built at another library commit than the pinned product ships")
    schema_asset = subprocess.run(["git", "--git-dir=" + str(core_git), "show", core_commit + ":gsj/assets/schema_registry/snapshot.json.gz"],
                                  check=True, capture_output=True).stdout
    manifest = {"schema": "gsj.release/1", "identity": version + "-" + commit[:12], "version": version,
                "core": {"tag": core_tag, "commit": core_commit}, "platforms": [PLATFORM], "images": inventory,
                "clients": catalog["clients"], "model": corpus["embedding"],
                "schema_asset": {"path": "gsj/assets/schema_registry/snapshot.json.gz",
                                 "sha256": hashlib.sha256(schema_asset).hexdigest()},
                "corpus": {k: corpus[k] for k in ("fingerprint", "source_sha256", "rows", "chunks")},
                "addons": {role: {k: item[k] for k in ("path", "sha256", "images")} for role, item in catalog["addons"].items()},
                "supported_sources": catalog.get("supported_sources", []), "release_base_url": catalog["release_base_url"],
                "build": {"installer_commit": commit, "product_commit": pin["commit"], "product_release": version,
                          "input_catalog_sha256": sha(destination / "inputs.json")},
                "source": {"commit": commit, "dirty": False, "web_commit": pin["commit"], "core_commit": core_commit},
                "_build": {"corpus_manifest": "corpus/manifest.json", "trust_key_file": "release.pem",
                           "core_git_dir": str(core_git),
                           "addons": {PurePosixPath(item["path"]).name: {"path": item["path"], "sha256": item["sha256"]} for item in catalog["addons"].values()}}}
    manifest["corpus"]["manifest_sha256"] = sha(destination / "corpus/manifest.json")
    save(destination / "manifest.json", manifest)
    save(destination / "image-inventory.json", {"schema": "gsj.image-inventory/1", "installer_commit": commit,
         "product_commit": pin["commit"], "product_release": version, "images": inventory, "addon_images": addon_images,
         "dependencies": dependencies, "all_remote_manifests_verified": True})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("inputs", "build", "clients"))
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        {"inputs": inputs, "build": build, "clients": clients}[args.command](args.output.resolve())
    except Exception as exc:
        # Transport exceptions may contain signed URLs; report type only.
        print("Release preparation failed: " + type(exc).__name__, file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
