"""`init`: one command that prepares a customer's box -- fetches the rest of
its own release, verifies itself, checks every tool at once, checks what it
can reach and what the box has, prepares the working folder, runs `inspect`
unchanged and writes ONE report to send back.

These tests drive the REAL entry point (`bash gsj-install.sh init`) of a real
installer: the branch's runtime.sh over a synthetic signed payload, on a
HERMETIC PATH (the precedent is test_installer_clients._tools) that holds the
real utilities, a recording kubectl that refuses every mutating verb, a
recording helm that answers only `version`, a fake curl that serves a release
directory from a map, and a uname, df, id and date that make the box a
synthetic Linux machine wherever the tests run. No cluster, no network, no
credential, and an environment built from nothing.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys

import pytest

from tests.test_installer import INSTALLER, runtime  # noqa: F401
from tests.test_installer_build import builder, keypair  # noqa: F401
from tests.test_installer_clients import _tools, FLOORS

ROOT = Path(__file__).resolve().parents[1]
VERSION = "v1.2.3"
IDENTITY = "synthetic-init-release-0123456789abcdef"
BASE = "https://releases.example/dl"
CANARY = "ZZSECRET-CANARY"
COMPANIONS = ("verify-release.sh", "release.pem", "installer-descriptor.json", "installer-descriptor.sig")
# What bootstrap(), init and inspect_cluster need from the box, symlinked from
# the system directories; nothing else is reachable. `jq` is real (inspect
# runs it); openssl is wrapped like the clients tests do.
UTILITIES = ("bash", "tar", "gzip", "base64", "awk", "cut", "mktemp", "sync", "sed", "head", "tail", "tr",
             "cat", "sha256sum", "shasum", "chmod", "mkdir", "cp", "mv", "rm", "ln", "stat", "getconf",
             "dirname", "basename", "grep", "wc", "sort", "sysctl", "env", "readlink", "perl", "sleep")
SYSTEM_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
# Every diagnostic bash or a tool prints when a script walks into a trap; no
# run may carry one, whatever it reports.
BASH_TRAPS = ("command not found", "unbound variable", "cannot overwrite", ": line ", "syntax error", "No such file or directory", "Permission denied")

FAKE_KUBECTL = '''#!/usr/bin/env python3
"""The RECORDING kubectl: every argv is appended to TEST_KUBE_LOG; the four
read-only verbs init and inspect use are answered; ANY other verb exits 99
with a marker, which the read-only proof asserts never happened. Every
diagnostic carries the canary the way a real kubectl quotes its kubeconfig.
TEST_KUBECTL_BROKEN=1 makes it a binary that cannot run at all."""
import json, os, sys
if os.environ.get("TEST_KUBECTL_BROKEN") == "1": sys.exit(126)
a = sys.argv[1:]
with open(os.environ["TEST_KUBE_LOG"], "a") as log: log.write(json.dumps(a) + "\\n")
canary = os.environ.get("TEST_CANARY", "") + " " + os.environ.get("KUBECONFIG", "")
flags = {"--context": 1, "--namespace": 1, "-n": 1, "--request-timeout": 1, "-l": 1, "-o": 1, "-A": 0, "--all-namespaces": 0,
         "--no-headers": 0, "--ignore-not-found": 0, "--client": 0}
verbs, i = [], 0
while i < len(a):
    if a[i] in flags: i += 1 + flags[a[i]]
    elif a[i].startswith("-o") or a[i].startswith("--"): i += 1
    else: verbs.append(a[i]); i += 1
client = {"clientVersion": {"gitVersion": "v" + os.environ["TEST_KUBECTL_VERSION"]}}
server = os.environ.get("TEST_KUBE_SERVER", "")
if verbs[:2] == ["config", "current-context"]:
    ctx = os.environ.get("TEST_KUBE_CONTEXT", "")
    if not ctx: print("error: current-context is not set " + canary, file=sys.stderr); sys.exit(1)
    print(ctx)
elif verbs[:1] == ["version"]:
    if "--client" in a: print(json.dumps(client, indent=2))
    elif os.environ.get("TEST_KUBE_PLUGIN") == "1":
        print(json.dumps(client, indent=2)); print("Unable to connect to the server: getting credentials: exec plugin " + canary, file=sys.stderr); sys.exit(1)
    elif server: print(json.dumps({**client, "serverVersion": {"major": "1", "minor": server.split(".")[1], "gitVersion": server}}, indent=2))
    else:
        print(json.dumps(client, indent=2)); print("The connection to the server " + canary + " was refused", file=sys.stderr); sys.exit(1)
elif verbs[:1] == ["get"]:
    if "custom-columns" in " ".join(a): pass
    elif verbs[1:2] == ["configmap"] and "local-path-config" in verbs: print("Error from server (NotFound) " + canary, file=sys.stderr); sys.exit(1)
    elif verbs[1:2] == ["nodes"]: print(json.dumps({"items": [{"metadata": {"name": "node-a"}, "status": {"nodeInfo": {"architecture": os.environ.get("TEST_NODE_ARCH", "amd64")}}}]}))
    else: print(json.dumps({"items": []}))
elif verbs[:2] == ["top", "nodes"]: print("error: Metrics API not available " + canary, file=sys.stderr); sys.exit(1)
else:
    print("MUTATION-REFUSED " + json.dumps(a), file=sys.stderr); sys.exit(99)
'''

FAKE_HELM = '''#!/usr/bin/env python3
"""The RECORDING helm: argv logged to TEST_HELM_LOG; only `version` answers."""
import json, os, sys
a = sys.argv[1:]
with open(os.environ["TEST_HELM_LOG"], "a") as log: log.write(json.dumps(a) + "\\n")
if a[:1] == ["version"]: print("v" + os.environ["TEST_HELM_VERSION"] + "+gdeadbee"); sys.exit(0)
print("MUTATION-REFUSED helm " + json.dumps(a), file=sys.stderr); sys.exit(99)
'''

FAKE_CURL = '''#!/usr/bin/env python3
"""A fake curl. A reachability probe (--write-out, --output /dev/null) answers
200 (401 for ghcr); a download (-o FILE) copies the asset named by the URL's
last segment from TEST_CURL_MAP, or answers 404 (rc 22) when the map has no
such name. TEST_CURL_OFFLINE=1 makes every request fail like a box without a
network -- code 000 on stdout, a canary on stderr, the way a proxy's error
page would ride. TEST_CURL_PROXY=407 answers like a proxy that wants
credentials (http_code 000, http_connect 407, rc 22 for downloads).
TEST_CURL_REDIRECT_HTTP=1 answers like an origin redirecting to plain HTTP
(rc 1, code 302). TEST_CURL_PLANT=DIR writes a file at DIR/NAME just before
serving NAME. Every argv is logged. The write-out is '%{http_code}
%{http_connect}' as init asks for it."""
import json, os, pathlib, shutil, sys
a = sys.argv[1:]
with open(os.environ["TEST_CURL_LOG"], "a") as log: log.write(json.dumps(a) + "\\n")
canary = os.environ.get("TEST_CANARY", "")
if a[:1] == ["--version"] or a[:2] == ["-q", "--version"]: print("curl 8.0.0 (synthetic)"); sys.exit(0)
url = next((v for v in a if v.startswith("http")), "")
offline = os.environ.get("TEST_CURL_OFFLINE") == "1"
proxy = os.environ.get("TEST_CURL_PROXY", "")
if "-o" in a and "--write-out" in a:
    out = a[a.index("-o") + 1]
    if offline: sys.stdout.write("000 000"); print("curl: (6) Could not resolve host: " + canary, file=sys.stderr); sys.exit(6)
    if proxy: sys.stdout.write("000 " + proxy); print("curl: (22) The requested URL returned error: 407 " + canary, file=sys.stderr); sys.exit(22)
    if os.environ.get("TEST_CURL_REDIRECT_HTTP") == "1": sys.stdout.write("302 000"); print("curl: (1) Protocol http not supported " + canary, file=sys.stderr); sys.exit(1)
    lookup = json.loads(pathlib.Path(os.environ["TEST_CURL_MAP"]).read_text())
    name = url.rsplit("/", 1)[-1]
    if name not in lookup or not url.startswith(os.environ["TEST_CURL_BASE"] + "/"):
        sys.stdout.write("404 000"); print("curl: (22) The requested URL returned error: 404 " + canary, file=sys.stderr); sys.exit(22)
    plant = os.environ.get("TEST_CURL_PLANT", "")
    if plant:
        target = pathlib.Path(plant) / name
        if os.environ.get("TEST_CURL_PLANT_LINK"): target.symlink_to(os.environ["TEST_CURL_PLANT_LINK"])
        else: target.write_text("operator's own copy of " + name)
    shutil.copyfile(lookup[name], out); sys.stdout.write("200 000"); sys.exit(0)
if "--write-out" in a:
    if offline: sys.stdout.write("000 000"); print("curl: (7) Failed to connect " + canary, file=sys.stderr); sys.exit(7)
    if proxy: sys.stdout.write("000 " + proxy); print("curl: (56) Received HTTP code 407 from proxy " + canary, file=sys.stderr); sys.exit(56)
    # TEST_CURL_GHCR_CODE / TEST_CURL_GITHUB_CODE: what the origin answers the probe
    code = os.environ.get("TEST_CURL_GHCR_CODE", "401") if "ghcr" in url else os.environ.get("TEST_CURL_GITHUB_CODE", "200")
    sys.stdout.write(code + " 000"); sys.exit(0)
print("unexpected curl invocation " + canary, file=sys.stderr); sys.exit(97)
'''

FAKE_DF = '''#!/usr/bin/env python3
"""A fake `df -Pk PATH...`: one row per existing path, its device and free
KiB from TEST_DF (a JSON list of {prefix, device, free_kib, mount}, longest
prefix wins; the default is one big root filesystem)."""
import json, os, sys
paths = [p for p in sys.argv[1:] if not p.startswith("-")]
table = json.loads(os.environ.get("TEST_DF", "[]")) + [{"prefix": "/", "device": "/dev/synthetic-root", "free_kib": 600000000, "mount": "/"}]
print("Filesystem 1024-blocks Used Available Capacity Mounted on")
rc = 0
for p in paths:
    if not os.path.exists(p): print("df: " + p + ": No such file or directory", file=sys.stderr); rc = 1; continue
    row = max((t for t in table if os.path.realpath(p).startswith(t["prefix"])), key=lambda t: len(t["prefix"]))
    print(row["device"], 900000000, 300000000, row["free_kib"], "34%", row.get("mount", row["prefix"]))
sys.exit(rc)
'''


def _installer(directory, keypair, *, base=BASE, version=VERSION, identity=IDENTITY, clients=None):
    """A REAL installer: the branch's runtime.sh over a synthetic payload,
    signed the way build.py sign() signs (canonical descriptor, RSA-SHA256).
    The four companions are written into `directory/assets` -- a staged
    release directory the fake curl serves."""
    private, public = keypair
    pem = public.read_bytes()
    clients = clients or {tool: {"linux/amd64": {"url": "https://example.test/" + tool, "sha256": "a" * 64}} for tool in ("helm", "kubectl", "jq")}
    release = builder.canonical({"schema": "gsj.release/1", "version": version, "identity": identity, "qualification": True,
                                 "release_base_url": base, "trustKeySha256": builder.sha(pem), "platforms": ["linux/amd64"],
                                 "clients": clients})
    source = (INSTALLER / "runtime.sh").read_text()
    header, trailing = source.rsplit(builder.MARKER, 1)
    assert not trailing.strip()
    runtime = (header.replace("@CLIENT_TABLE@", builder.client_table(clients)) + builder.MARKER + "\n").encode()
    files = {"trust/release.pem": (pem, 0o644), "release.json": (release, 0o644),
             "helpers/verification-cleanup.sh": (b"", 0o644), "helpers/startup-recovery.sh": (b"", 0o644)}
    files["SHA256SUMS"] = ("".join(f"{builder.sha(data)}  {name}\n" for name, (data, _) in sorted(files.items())).encode(), 0o644)
    installer = runtime + base64.encodebytes(builder.compressed_tar(files))
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "gsj-install.sh"
    path.write_bytes(installer)
    path.chmod(0o755)
    descriptor = builder.canonical({"schema": "gsj.installer-descriptor/1", "version": version, "releaseId": identity, "qualification": True,
                                    "manifestSha256": builder.sha(release), "trustKeySha256": builder.sha(pem),
                                    "installer": {"name": "gsj-install.sh", "sha256": builder.sha(installer), "bytes": len(installer)},
                                    "signature": "RSA-SHA256"})
    assets = directory / "assets"
    assets.mkdir(exist_ok=True)
    (assets / "installer-descriptor.json").write_bytes(descriptor)
    _sign(private, assets / "installer-descriptor.json", assets / "installer-descriptor.sig")
    (assets / "release.pem").write_bytes(pem)
    shutil.copyfile(INSTALLER / "verify-release.sh", assets / "verify-release.sh")
    return path, assets


def _sign(private, descriptor, signature):
    subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(private), "-out", str(signature), str(descriptor)], check=True, capture_output=True)


def _other_key(tmp_path, name="other"):
    private = tmp_path / f"{name}-private.pem"
    subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(private)], check=True, capture_output=True)
    public = subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout"], check=True, capture_output=True).stdout
    return private, public


def _sandbox(tmp_path, **versions):
    """The hermetic PATH: real utilities, the real jq, an openssl wrapper, the
    recording kubectl and helm, the fake curl, df, uname, id and date. A tool
    mapped to None is absent. Returns the directory's path (a string)."""
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    for utility in UTILITIES:
        found = shutil.which(utility, path=SYSTEM_PATH)
        if found and not (bindir / utility).exists():
            (bindir / utility).symlink_to(found)
    (bindir / "python3").symlink_to(sys.executable)
    real = {name: shutil.which(name, path=SYSTEM_PATH) for name in ("uname", "id", "date")}
    (bindir / "uname").write_text('#!/bin/sh\ncase "$*" in -s) echo "${TEST_UNAME_S:-Linux}";; -m) echo x86_64;; -sr) echo "${TEST_UNAME_S:-Linux} 6.1.0-synthetic";; *) echo "${TEST_UNAME_S:-Linux}";; esac\n')
    (bindir / "id").write_text(f'#!/bin/sh\nif [ "$1" = -u ] && [ -n "${{TEST_UID:-}}" ]; then echo "$TEST_UID"; else exec {real["id"]} "$@"; fi\n')
    (bindir / "date").write_text(f'#!/bin/sh\nif [ "$*" = "-u +%Y%m%dT%H%M%SZ" ] && [ -n "${{TEST_DATE_STAMP:-}}" ]; then echo "$TEST_DATE_STAMP"; else exec {real["date"]} "$@"; fi\n')
    for name in ("uname", "id", "date"):
        (bindir / name).chmod(0o755)
    versions.setdefault("jq", "real")
    versions.setdefault("helm", "4.2.2")
    versions.setdefault("kubectl", "1.35.8")
    versions.setdefault("openssl", "OpenSSL 3.0.13 30 Jan 2024")
    versions.setdefault("curl", "fake")
    versions.setdefault("df", "fake")
    real_openssl = shutil.which("openssl")
    for tool, version in versions.items():
        target = bindir / tool
        if version is None:
            continue
        if tool == "jq":
            target.symlink_to(shutil.which("jq"))
            continue                                                  # a link: chmod would follow it
        elif tool == "openssl":
            target.write_text(f'#!/bin/sh\nif [ "${{1:-}}" = version ]; then printf "%s\\n" \'{version}\'; else exec {real_openssl} "$@"; fi\n')
        elif tool == "helm":
            target.write_text(FAKE_HELM)
        elif tool == "kubectl":
            target.write_text(FAKE_KUBECTL)
        elif tool == "curl":
            target.write_text(FAKE_CURL)
        elif tool == "df":
            target.write_text(FAKE_DF)
        target.chmod(0o755)
    return str(bindir)


class Box:
    """One synthetic customer box: its PATH, HOME, logs and staged release."""

    def __init__(self, tmp_path, keypair, **tools):
        self.tmp = tmp_path
        self.keypair = keypair
        self.installer, self.assets = _installer(tmp_path / "release", keypair)
        self.home = tmp_path / "home"
        self.home.mkdir(mode=0o700)
        self.tmpdir = tmp_path / "tmp"
        self.tmpdir.mkdir()
        self.kube_log = tmp_path / "kubectl.log"
        self.helm_log = tmp_path / "helm.log"
        self.curl_log = tmp_path / "curl.log"
        self.curl_map = tmp_path / "curl-map.json"
        self.serve(self.assets)
        self.path = _sandbox(tmp_path, **tools)
        self.env = {"PATH": self.path, "HOME": str(self.home), "TMPDIR": str(self.tmpdir), "XDG_CACHE_HOME": str(tmp_path / "cache"),
                    "LANG": "C", "KUBECONFIG": str(tmp_path / (CANARY + "-kubeconfig")), "TEST_CANARY": CANARY,
                    "TEST_KUBE_LOG": str(self.kube_log), "TEST_HELM_LOG": str(self.helm_log), "TEST_CURL_LOG": str(self.curl_log),
                    "TEST_CURL_MAP": str(self.curl_map), "TEST_CURL_BASE": BASE + "/" + VERSION, "TEST_KUBE_CONTEXT": "synthetic-context",
                    "TEST_KUBE_SERVER": "v1.35.8", "TEST_KUBECTL_VERSION": tools.get("kubectl") or "1.35.8",
                    "TEST_HELM_VERSION": tools.get("helm") or "4.2.2"}

    def serve(self, assets, names=COMPANIONS):
        self.curl_map.write_text(json.dumps({name: str(assets / name) for name in names}))

    def run(self, *args, cwd=None, script=None, **extra):
        env = {**self.env, **extra}
        cwd = str(cwd or self.installer.parent)
        result = subprocess.run([shutil.which("bash", path=SYSTEM_PATH), script or str(self.installer), "init", *args],
                                env=env, cwd=cwd, capture_output=True, text=True, timeout=180)
        work = self.home / "gsj-operator"
        result.reports = sorted(work.glob("gsj-init-report-*.json")) if work.is_dir() else []
        for trap in BASH_TRAPS:
            assert trap not in result.stderr, result.stderr
        return result

    def kube_calls(self):
        return [json.loads(line) for line in self.kube_log.read_text().splitlines()] if self.kube_log.exists() else []

    def helm_calls(self):
        return [json.loads(line) for line in self.helm_log.read_text().splitlines()] if self.helm_log.exists() else []

    def curl_calls(self):
        return [json.loads(line) for line in self.curl_log.read_text().splitlines()] if self.curl_log.exists() else []

    def downloads(self):
        return [next(v for v in call if v.startswith("http")) for call in self.curl_calls() if "-o" in call and "--write-out" in call]

    def place(self, *names, into=None):
        for name in names:
            shutil.copyfile(self.assets / name, (into or self.installer.parent) / name)

    def beside(self):
        return sorted(p.name for p in self.installer.parent.iterdir() if p.name != "gsj-install.sh" and p.name != "assets")


def _report(result):
    assert len(result.reports) == 1, (result.reports, result.stdout, result.stderr)
    report = json.loads(result.reports[0].read_text())
    assert report["schema"] == "gsj.init/1"
    assert result.reports[0].stat().st_mode & 0o077 == 0
    assert str(result.reports[0]) in result.stdout
    return report


def _check(report, name):
    rows = [row for row in report["checks"] if row["name"] == name]
    assert len(rows) == 1, (name, [r["name"] for r in report["checks"]])
    return rows[0]


def _stop(result, *words):
    """A named refusal: exit 1, exactly one GSJ: line carrying every word, no report."""
    assert result.returncode == 1, result.stderr + result.stdout
    lines = [l for l in result.stderr.splitlines() if l.startswith("GSJ:")]
    assert len(lines) == 1, result.stderr
    for word in words:
        assert word in lines[0], (word, lines[0])
    assert result.reports == []
    return lines[0]


def _no_leak(box, result):
    text = result.stdout + result.stderr + "".join(p.read_text() for p in result.reports)
    assert CANARY not in text, text
    assert "/dl/" not in text and "releases.example/dl" not in text, text     # no URL beyond its origin
    for path in list(box.tmp.rglob("*")):
        if path.is_file() and "gsj-operator" in path.parts and CANARY in path.read_text(errors="ignore"):
            raise AssertionError(f"the canary reached {path}")


# --- 1. the rest of its own release ------------------------------------------

def test_missing_companions_are_downloaded_checked_verified_then_saved(tmp_path, keypair):
    box = Box(tmp_path, keypair)
    result = box.run()
    assert result.returncode == 0, result.stderr + result.stdout
    for name in COMPANIONS:
        assert (box.installer.parent / name).is_file() and not (box.installer.parent / name).is_symlink(), name
        assert (box.installer.parent / name).read_bytes() == (box.assets / name).read_bytes()
    assert sorted(url.rsplit("/", 1)[-1] for url in box.downloads()) == sorted(COMPANIONS)
    assert all(url.startswith(BASE + "/" + VERSION + "/") for url in box.downloads())
    for call in box.curl_calls():
        if "-o" not in call and "--connect-timeout" not in call:
            continue                                                  # `curl --version` (the tool row) and inspect's own probes
        assert call[0] == "-q", call                                  # no ~/.curlrc can loosen init's policy
        if "-o" in call:
            assert "--proto" in call and call[call.index("--proto") + 1] == "=https" and "--connect-timeout" in call and "--max-filesize" in call, call
    report = _report(result)
    assert report["verification"] == {"status": "PASS", "companions_present": 0, "companions_downloaded": 4, "companions_saved": 4,
                                      "saved_in": str(box.installer.parent), "missing": "", "limit": report["verification"]["limit"]}
    assert "modified installer could skip its own check" in report["verification"]["limit"]
    assert "init: the published verify-release.sh confirms the signed descriptor and the exact bytes of this installer" in result.stdout
    assert report["installer"] == {"name": "gsj-install.sh", "version": VERSION, "identity": IDENTITY,
                                   "sha256": builder.sha(box.installer.read_bytes()), "platform": "linux/amd64"}
    assert report["summary"]["ready"] is True and report["summary"]["egress"] == "full"
    assert "Limit:" in result.stdout and "Send this one file back:" in result.stdout
    _no_leak(box, result)


def test_present_companions_are_used_and_never_downloaded_again(tmp_path, keypair):
    box = Box(tmp_path, keypair)
    box.place(*COMPANIONS)
    before = {name: (box.installer.parent / name).read_bytes() for name in COMPANIONS}
    result = box.run(TEST_CURL_MAP=str(tmp_path / "no-such-map.json"))       # a download would crash the fake
    assert result.returncode == 0, result.stderr + result.stdout
    assert box.downloads() == []
    assert {name: (box.installer.parent / name).read_bytes() for name in COMPANIONS} == before
    report = _report(result)
    assert report["verification"]["companions_present"] == 4 and report["verification"]["companions_downloaded"] == 0


def test_the_key_in_the_guides_trust_folder_is_found_but_a_verifier_there_is_not_read(tmp_path, keypair):
    """The guide's trust/ lasts across releases: one key serves the line, so it
    is looked for there; a verifier there may be an older release's, so it is
    neither executed nor refused -- this release's own is downloaded."""
    box = Box(tmp_path, keypair)
    work = box.home / "gsj-operator"
    work.mkdir(mode=0o700)
    (work / "trust").mkdir(mode=0o700)
    box.place("release.pem", into=work / "trust")
    (work / "trust" / "verify-release.sh").write_bytes(b"#!/usr/bin/env bash\n# an older release's verifier\n")
    box.place("installer-descriptor.json", "installer-descriptor.sig")
    result = box.run()
    assert result.returncode == 0, result.stderr + result.stdout
    assert [url.rsplit("/", 1)[-1] for url in box.downloads()] == ["verify-release.sh"]
    assert box.beside() == ["installer-descriptor.json", "installer-descriptor.sig", "verify-release.sh"]
    report = _report(result)
    assert report["verification"]["companions_present"] == 3 and report["verification"]["companions_downloaded"] == 1
    assert (work / "trust" / "verify-release.sh").read_bytes().startswith(b"#!/usr/bin/env bash\n# an older")


@pytest.mark.parametrize("foreign", ["installer-descriptor.json", "installer-descriptor.sig", "release.pem", "verify-release.sh", "same-version-other-build"])
def test_a_companion_from_another_release_is_refused_by_name_never_replaced(tmp_path, keypair, foreign):
    box = Box(tmp_path, keypair)
    name = "installer-descriptor.json" if foreign == "same-version-other-build" else foreign
    if foreign == "installer-descriptor.json":
        other = json.loads((box.assets / name).read_text()); other["version"] = "v9.9.9"; foreign_bytes = builder.canonical(other)
        words = ("belongs to release v9.9.9", VERSION, "never replaced")
    elif foreign == "same-version-other-build":
        other = json.loads((box.assets / name).read_text()); other["releaseId"] = "another-build-of-the-same-version"; foreign_bytes = builder.canonical(other)
        words = ("describes build another-build-of-the-same-version", IDENTITY, "never replaced")
    elif foreign == "installer-descriptor.sig":
        private, _ = _other_key(tmp_path)
        foreign_bytes = subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(private), str(box.assets / "installer-descriptor.json")], check=True, capture_output=True).stdout
        words = ("installer-descriptor.sig does not sign installer-descriptor.json", "never replaced")
    elif foreign == "release.pem":
        _, foreign_bytes = _other_key(tmp_path)
        words = ("release.pem is not the key this installer carries", "never replaced")
    else:
        foreign_bytes = (box.assets / name).read_bytes() + b"\n# a line from another release\n"
        words = ("verify-release.sh is not the verifier published with release", "will not execute it", "never replaced")
    (box.installer.parent / name).write_bytes(foreign_bytes)
    result = box.run()
    _stop(result, *words)
    assert (box.installer.parent / name).read_bytes() == foreign_bytes
    if foreign != "installer-descriptor.sig":                       # a lone signature is judged once the descriptor is there
        assert box.downloads() == [], "nothing is downloaded once a foreign companion is found"
    assert box.kube_calls() == []
    assert box.beside() == [name], "a refusal wrote beside the installer"
    _no_leak(box, result)


@pytest.mark.parametrize("field", ["version", "releaseId"])
def test_a_served_descriptor_whose_identity_is_not_a_version_or_identity_is_not_repeated(tmp_path, keypair, field):
    """The refusal names a foreign version or build only when it has that
    shape; anything else -- text a hostile origin put there -- is 'unreadable'."""
    box = Box(tmp_path, keypair)
    other = json.loads((box.assets / "installer-descriptor.json").read_text())
    other[field] = "token " + CANARY
    (box.assets / "installer-descriptor.json").write_bytes(builder.canonical(other))
    result = box.run()
    _stop(result, "descriptor published at https://releases.example", "of an unreadable " + ("version" if field == "version" else "identity"))
    assert box.beside() == []
    _no_leak(box, result)


def test_altered_installer_bytes_fail_verification_and_init_stops_before_inspect(tmp_path, keypair):
    box = Box(tmp_path, keypair)
    # one byte of the runtime changed, the payload intact: exactly what a swapped
    # or edited installer looks like (a corrupt payload dies in bootstrap instead)
    altered = box.installer.read_bytes().replace(b"# Generated GSJ release installer.", b"# Generated GSJ release installer!", 1)
    assert altered != box.installer.read_bytes()
    box.installer.write_bytes(altered)
    result = box.run()
    _stop(result, "release verification FAILED", "SHA-256 differs from the signed descriptor", "ask for the release again")
    assert box.kube_calls() == [], "inspect ran on a refused installer"
    assert box.beside() == [], "a download was saved beside a refused installer"
    _no_leak(box, result)


def test_the_published_verifier_runs_after_the_internal_check_and_its_own_refusal_stops_init(tmp_path, keypair):
    """A descriptor with a second installer sha256 line passes init's own
    reading (the first line) and is refused by verify-release.sh, whose sed
    demands one unique digest: the verifier is a check of its own, and its
    refusal stops init before inspect."""
    box = Box(tmp_path, keypair)
    box.place(*COMPANIONS)
    result = box.run()
    assert result.returncode == 0, result.stderr
    # the verifier's own success line ("The installer was not executed") is
    # not forwarded: init IS the installer, running -- init says in its own
    # words what the verifier established
    assert "was not executed" not in result.stdout + result.stderr
    assert "init: the published verify-release.sh confirms the signed descriptor and the exact bytes of this installer" in result.stdout
    assert result.stderr.index("init: running the published verify-release.sh") < result.stderr.index("init: running inspect")
    descriptor = json.loads((box.assets / "installer-descriptor.json").read_text())
    descriptor["zz"] = {"sha256": "0" * 64}
    (box.assets / "installer-descriptor.json").write_bytes(builder.canonical(descriptor))
    _sign(box.keypair[0], box.assets / "installer-descriptor.json", box.assets / "installer-descriptor.sig")
    again = Box(tmp_path / "again", keypair)
    again.serve(box.assets)
    result = again.run()
    _stop(result, "release verification FAILED: verify-release.sh refused this installer")
    assert "Descriptor has no unique installer/key digest" in result.stderr          # the published verifier's own line
    assert again.kube_calls() == [] and again.beside() == []


def test_a_wrong_key_published_at_the_origin_is_refused_and_nothing_is_saved(tmp_path, keypair):
    box = Box(tmp_path, keypair)
    _, public = _other_key(tmp_path)
    (box.assets / "release.pem").write_bytes(public)
    result = box.run()
    _stop(result, "release.pem published at https://releases.example", "ask for the release again")
    assert box.kube_calls() == []
    assert box.beside() == [], "a download was saved before it was checked"
    again = box.run()
    _stop(again, "release.pem published at https://releases.example")
    _no_leak(box, result)


def test_a_verifier_published_at_the_origin_that_is_not_this_releases_is_not_executed(tmp_path, keypair):
    box = Box(tmp_path, keypair)
    (box.assets / "verify-release.sh").write_bytes(b"#!/usr/bin/env bash\necho " + CANARY.encode() + b"\n")
    result = box.run()
    _stop(result, "verify-release.sh published at https://releases.example", "not executed", "ask for the release again")
    assert box.beside() == []
    _no_leak(box, result)


def test_an_html_page_in_place_of_a_companion_is_a_failed_download_not_a_foreign_release(tmp_path, keypair):
    box = Box(tmp_path, keypair)
    (box.assets / "verify-release.sh").write_bytes(b"<html><body>Blocked by policy " + CANARY.encode() + b"</body></html>\n")
    result = box.run()
    assert result.returncode == 3, result.stderr + result.stdout
    row = _check(_report(result), "release-verification")
    assert row["status"] == "UNKNOWN" and "something that is not verify-release.sh" in row["detail"] and "proxy or portal" in row["detail"]
    assert box.beside() == []
    _no_leak(box, result)


def test_a_present_companion_this_user_cannot_read_is_named_not_called_foreign(tmp_path, keypair):
    box = Box(tmp_path, keypair)
    box.place(*COMPANIONS)
    os.chmod(box.installer.parent / "release.pem", 0)
    try:
        result = box.run()
    finally:
        os.chmod(box.installer.parent / "release.pem", 0o644)
    if os.geteuid() == 0:
        assert result.returncode == 0                                   # root reads anything
    else:
        _stop(result, "release.pem cannot be read by this user", "never replaced")
        assert "another release" not in result.stderr


def test_a_missing_or_libressl_openssl_is_refused_by_bootstrap_before_init_runs(runtime, tmp_path):
    run, state, work = runtime
    for banner in ("LibreSSL 3.3.6", None):
        path = _tools(tmp_path / f"tools-{banner is None}", **FLOORS, openssl=banner)
        result = run("COMMAND=init; FETCH_TOOLS=false; bootstrap; echo REACHED", PATH=path)
        assert result.returncode != 0 and "REACHED" not in result.stdout
        if banner:
            assert "requires OpenSSL" in result.stderr and "LibreSSL" in result.stderr and "--fetch-tools does not supply OpenSSL" in result.stderr
        else:
            assert "bootstrap utility required: openssl" in result.stderr
    assert json.loads(state.read_text())["calls"] == []


def test_a_box_without_a_sha256_tool_is_named_for_init_and_unchanged_for_every_other_verb(runtime, tmp_path):
    """init names the missing tool; every other verb keeps its refusal as it
    was (the payload check, which blames the payload)."""
    run, _, _ = runtime
    path = _tools(tmp_path / "tools", **FLOORS)
    for name in ("sha256sum", "shasum"):
        (Path(path) / name).unlink(missing_ok=True)
    result = run("COMMAND=init; FETCH_TOOLS=false; bootstrap; echo REACHED", PATH=path)
    assert result.returncode != 0 and "REACHED" not in result.stdout
    assert "bootstrap utility required: sha256sum or shasum" in result.stderr and "integrity" not in result.stderr
    other = run("COMMAND=install; FETCH_TOOLS=false; bootstrap; echo REACHED", PATH=path)
    assert other.returncode != 0 and "sha256sum or shasum" not in other.stderr


def test_bootstrap_skips_only_the_client_refusal_for_init(runtime, tmp_path):
    """init reports missing clients instead of stopping on the first one; every
    other verb keeps the ten-second refusal."""
    run, _, _ = runtime
    path = _tools(tmp_path / "tools", **{**FLOORS, "helm": None})
    refused = run("COMMAND=install; FETCH_TOOLS=false; bootstrap; echo REACHED", PATH=path)
    assert refused.returncode != 0 and "requires helm" in refused.stderr
    reached = run("COMMAND=init; FETCH_TOOLS=false; bootstrap; echo REACHED", PATH=path)
    assert "requires helm" not in reached.stderr, reached.stderr        # it went on to the payload step (none under the fixture)
    assert "REACHED" not in reached.stdout


def test_init_refuses_fetch_tools_by_name_before_bootstrap_downloads_anything(tmp_path, keypair):
    box = Box(tmp_path, keypair, helm=None)
    result = box.run("--fetch-tools")
    _stop(result, "run it without --fetch-tools")
    assert box.curl_calls() == [] and box.kube_calls() == []
    assert not (box.home / "gsj-operator").exists()


# --- 2. every tool against its floor, all at once ------------------------------

def test_several_missing_tools_are_all_named_in_one_run(tmp_path, keypair):
    box = Box(tmp_path, keypair, helm=None, kubectl=None, jq=None)
    result = box.run()
    assert result.returncode == 3, result.stderr + result.stdout
    report = _report(result)
    for tool in ("helm", "kubectl", "jq"):
        row = _check(report, tool)
        assert row["status"] == "FAIL" and f"requires {tool} >= {FLOORS[tool]}" in row["detail"] and "none on PATH" in row["detail"], row
        assert "any other command accepts --fetch-tools" in row["fix"] and f"pins a {tool} for linux/amd64" in row["fix"], row
        assert f"FAIL    {tool}" in result.stdout
    assert _check(report, "openssl")["status"] == "PASS" and "--fetch-tools does not supply OpenSSL" in _check(report, "openssl")["detail"]
    assert _check(report, "cluster")["status"] == "UNKNOWN"
    assert _check(report, "inspect")["status"] == "UNKNOWN" and report["inspect"]["unavailable"] is True
    assert report["verification"]["status"] == "PASS", "verification needs no jq"
    assert "Fix before an install:" in result.stdout
    assert report["summary"]["ready"] is False and report["summary"]["fail"] >= 3
    _no_leak(box, result)


def test_the_fetch_tools_advice_says_what_this_release_pins_for_this_platform(tmp_path, keypair):
    box = Box(tmp_path, keypair, helm=None, jq=None)
    clients = {"helm": {"linux/arm64": {"url": "https://example.test/helm", "sha256": "a" * 64}},
               "kubectl": {"linux/amd64": {"url": "https://example.test/kubectl", "sha256": "a" * 64}},
               "jq": {"linux/amd64": {"url": "https://example.test/jq", "sha256": "a" * 64}}}
    box.installer, box.assets = _installer(tmp_path / "release", keypair, clients=clients)
    box.serve(box.assets)
    report = _report(box.run())
    assert "--fetch-tools cannot help here: this release pins no helm for linux/amd64" in _check(report, "helm")["fix"]
    assert "any other command accepts --fetch-tools (this release pins a jq for linux/amd64" in _check(report, "jq")["fix"]


def test_a_too_old_client_is_named_with_floor_and_finding(tmp_path, keypair):
    box = Box(tmp_path, keypair, helm="3.11.3")
    result = box.run()
    assert result.returncode == 3
    row = _check(_report(result), "helm")
    assert row["status"] == "FAIL" and "found 3.11.3" in row["detail"] and FLOORS["helm"] in row["detail"]


def test_a_client_that_reports_no_version_is_named(tmp_path, keypair):
    box = Box(tmp_path, keypair)
    (Path(box.path) / "helm").write_text('#!/bin/sh\necho "not a version"\n')
    result = box.run()
    assert result.returncode == 3
    row = _check(_report(result), "helm")
    assert row["status"] == "FAIL" and "did not report a version" in row["detail"]


def test_a_kubectl_that_cannot_run_is_named_and_the_cluster_row_does_not_blame_the_kubeconfig(tmp_path, keypair):
    box = Box(tmp_path, keypair)
    result = box.run(TEST_KUBECTL_BROKEN="1")
    assert result.returncode == 3
    report = _report(result)
    assert "did not report a version" in _check(report, "kubectl")["detail"]
    assert _check(report, "cluster")["status"] == "UNKNOWN" and "kubectl did not report a version" in _check(report, "cluster")["detail"]


# --- 3. what it can reach ---------------------------------------------------------

def test_the_cluster_is_named_by_its_context_and_server_version(tmp_path, keypair):
    box = Box(tmp_path, keypair)
    result = box.run("--context", "named-context", TEST_KUBE_CONTEXT="")
    assert result.returncode == 0, result.stderr + result.stdout
    report = _report(result)
    row = _check(report, "cluster")
    assert row["status"] == "PASS" and "named-context" in row["detail"] and "1.35.8" in row["detail"]
    assert _check(report, "kubectl-skew")["status"] == "PASS"
    assert _check(report, "node-architecture")["status"] == "PASS" and "linux/amd64" in _check(report, "node-architecture")["found"]
    assert report["inspect"]["schema"] == "gsj.inspect/1" and report["inspect"]["context"] == "named-context"
    assert all(("current-context" not in call) for call in box.kube_calls()), "--context was given; current-context was still read"


def test_a_node_of_an_architecture_the_release_has_no_images_for_is_named(tmp_path, keypair):
    box = Box(tmp_path, keypair)
    result = box.run(TEST_NODE_ARCH="arm64")
    assert result.returncode == 3
    row = _check(_report(result), "node-architecture")
    assert row["status"] == "FAIL" and "linux/arm64" in row["detail"] and "linux/amd64" in row["detail"]


def test_an_unreachable_api_server_is_a_finding_and_inspect_is_not_attempted(tmp_path, keypair):
    box = Box(tmp_path, keypair)
    result = box.run(TEST_KUBE_SERVER="")
    assert result.returncode == 3, result.stderr + result.stdout
    report = _report(result)
    row = _check(report, "cluster")
    assert row["status"] == "FAIL" and "synthetic-context" in row["detail"] and "no_proxy" in row["fix"]
    assert _check(report, "kubectl-skew")["status"] == "UNKNOWN"
    assert _check(report, "inspect")["status"] == "UNKNOWN" and report["inspect"]["unavailable"] is True
    assert not any("get" in call for call in box.kube_calls()), "inspect's gets ran against a server that did not answer"
    _no_leak(box, result)


def test_a_credential_plugin_that_did_not_finish_is_named_without_its_words(tmp_path, keypair):
    box = Box(tmp_path, keypair)
    result = box.run(TEST_KUBE_PLUGIN="1")
    assert result.returncode == 3
    row = _check(_report(result), "cluster")
    assert row["status"] == "FAIL" and "credential plugin" in row["detail"] and "by hand" in row["fix"]
    _no_leak(box, result)


def test_no_kubeconfig_context_is_a_finding_that_must_be_fixed(tmp_path, keypair):
    box = Box(tmp_path, keypair)
    result = box.run(TEST_KUBE_CONTEXT="")
    assert result.returncode == 3, result.stderr + result.stdout
    report = _report(result)
    assert _check(report, "cluster")["status"] == "FAIL" and "KUBECONFIG" in _check(report, "cluster")["fix"]
    assert _check(report, "inspect")["status"] == "UNKNOWN"
    _no_leak(box, result)


def test_a_server_below_the_floor_is_named(tmp_path, keypair):
    box = Box(tmp_path, keypair, kubectl="1.26.0")
    result = box.run(TEST_KUBE_SERVER="v1.26.9")
    assert result.returncode == 3
    row = _check(_report(result), "cluster")
    assert row["status"] == "FAIL" and "below the floor 1.27" in row["detail"]


@pytest.mark.parametrize("client", ["1.24.0", "1.23.0"])
def test_kubectl_skew_beyond_one_minor_is_named_with_both_versions_even_below_the_floor(tmp_path, keypair, client):
    box = Box(tmp_path, keypair, kubectl=client)
    result = box.run(TEST_KUBE_SERVER="v1.36.4+k3s1")
    assert result.returncode == 3
    report = _report(result)
    row = _check(report, "kubectl-skew")
    assert row["status"] == "FAIL" and client in row["detail"] and "1.36.4" in row["detail"]
    if client == "1.23.0":
        assert _check(report, "kubectl")["status"] == "FAIL" and _check(report, "inspect")["status"] == "UNKNOWN"


def test_without_a_network_the_report_still_comes_from_local_files(tmp_path, keypair):
    box = Box(tmp_path, keypair)
    result = box.run(TEST_CURL_OFFLINE="1")
    assert result.returncode == 3, result.stderr + result.stdout
    report = _report(result)
    assert report["verification"]["status"] == "UNKNOWN"
    assert report["verification"]["missing"] == "verify-release.sh, release.pem (not tried), installer-descriptor.json (not tried), installer-descriptor.sig (not tried)"
    assert len(box.downloads()) == 1, "after the first transport failure the others are not tried"
    assert "did not resolve" in _check(report, "release-verification")["detail"]
    assert _check(report, "egress-github")["status"] == "FAIL" and _check(report, "egress-ghcr")["status"] == "FAIL"
    assert report["summary"]["egress"] == "none" and report["summary"]["ready"] is False
    assert "This installer is NOT verified" in result.stdout
    assert "corpus.vectors_path" in result.stdout and "registry.base" in result.stdout and "--fetch-tools cannot download" in result.stdout
    for tool in ("helm", "kubectl", "jq", "openssl"):
        assert _check(report, tool)["status"] == "PASS"
    assert _check(report, "working-folder")["status"] == "PASS" and _check(report, "inspect")["status"] == "PASS"
    assert report["inspect"]["profile"]["networking"]["egress"]["endpoints"], "inspect's own probes are in the profile"
    assert box.beside() == [], "a partial download stayed beside the installer"
    _no_leak(box, result)


def test_a_proxy_that_wants_credentials_is_named_as_the_proxy_not_as_no_egress(tmp_path, keypair):
    box = Box(tmp_path, keypair)
    result = box.run(TEST_CURL_PROXY="407", HTTPS_PROXY=f"http://u:{CANARY}@proxy.example:3128")
    assert result.returncode == 3, result.stderr + result.stdout
    report = _report(result)
    row = _check(report, "release-verification")
    assert row["status"] == "UNKNOWN" and "the proxy this machine uses answered HTTP 407" in row["detail"] and "does not publish" not in row["detail"]
    assert "proxy answered HTTP 407" in _check(report, "egress-github")["found"] and _check(report, "egress-ghcr")["status"] == "FAIL"
    assert report["summary"]["egress"] == "partial" and "No internet" not in result.stdout
    _no_leak(box, result)


def test_a_redirect_to_plain_http_is_named_as_refused_not_as_a_failed_download(tmp_path, keypair):
    box = Box(tmp_path, keypair)
    result = box.run(TEST_CURL_REDIRECT_HTTP="1")
    assert result.returncode == 3
    row = _check(_report(result), "release-verification")
    assert "redirected to a location that is not HTTPS (HTTP 302)" in row["detail"]
    assert box.beside() == []


def test_a_file_the_origin_does_not_publish_is_named_without_the_no_egress_advice(tmp_path, keypair):
    box = Box(tmp_path, keypair)
    box.serve(box.assets, names=("installer-descriptor.json", "installer-descriptor.sig", "release.pem"))
    result = box.run()
    assert result.returncode == 3
    report = _report(result)
    row = _check(report, "release-verification")
    assert row["status"] == "UNKNOWN" and "does not publish that file" in row["detail"] and "HTTP 404" in row["detail"]
    assert report["verification"]["missing"] == "verify-release.sh"
    assert report["summary"]["egress"] == "full" and "No internet" not in result.stdout
    assert box.beside() == [], "the three good files were saved although the release stays unverified"
    _no_leak(box, result)


def test_a_qualification_build_without_a_release_directory_says_so(tmp_path, keypair):
    box = Box(tmp_path, keypair)
    box.installer, box.assets = _installer(tmp_path / "release", keypair, base="")
    result = box.run()
    assert result.returncode == 3, result.stderr + result.stdout
    report = _report(result)
    assert report["verification"]["status"] == "UNKNOWN" and "release_base_url is empty" in _check(report, "release-verification")["detail"]
    assert box.downloads() == []


# --- 4 and 5. the box and the working folder ---------------------------------------

def test_the_working_folder_and_its_credentials_folder_are_created_private(tmp_path, keypair):
    box = Box(tmp_path, keypair)
    result = box.run()
    assert result.returncode == 0, result.stderr
    work = box.home / "gsj-operator"
    assert stat.S_IMODE(work.stat().st_mode) == 0o700 and stat.S_IMODE((work / "credentials").stat().st_mode) == 0o700
    report = _report(result)
    assert _check(report, "working-folder")["status"] == "PASS" and "created" in _check(report, "working-folder")["detail"]
    assert _check(report, "credentials-folder")["status"] == "PASS"
    assert _check(report, "os")["status"] == "PASS" and _check(report, "architecture")["found"] == "linux/amd64"
    assert _check(report, "disk")["status"] == "PASS" and "3.5 GB" in _check(report, "disk")["detail"]
    assert result.stdout.count("Send this one file back:") == 1


def test_a_box_that_is_not_linux_is_named(tmp_path, keypair):
    box = Box(tmp_path, keypair)
    result = box.run(TEST_UNAME_S="Darwin")
    assert result.returncode == 3
    report = _report(result)
    assert _check(report, "os")["status"] == "FAIL" and "run the installer from a Linux machine" in _check(report, "os")["fix"]
    assert _check(report, "architecture")["status"] == "UNKNOWN"


@pytest.mark.parametrize("layout,status", [("same-device-short", "FAIL"), ("split-devices-ok", "PASS"), ("split-devices-short", "FAIL")])
def test_the_disk_rule_is_stage_vectors_rule_and_names_mount_points_not_devices(tmp_path, keypair, layout, status):
    """One filesystem holds the blocks and their envelope at once (about
    3.5 GB); two filesystems need about 1.9 GB under TMPDIR and 1.7 GB under
    the cache. df's source column (a remote path, a URL) is never printed."""
    box = Box(tmp_path, keypair)
    cache_root = str(tmp_path / "cache")
    (tmp_path / "cache").mkdir()
    if layout == "same-device-short":
        table = [{"prefix": "/", "device": f"nfs01.example:/vol/{CANARY}", "free_kib": 3000000, "mount": "/"}]
    elif layout == "split-devices-ok":
        table = [{"prefix": cache_root, "device": f"https://u:{CANARY}@dav.example/x", "free_kib": 1800000, "mount": "/cache"},
                 {"prefix": str(box.tmpdir), "device": "/dev/work", "free_kib": 2000000, "mount": "/work"}]
    else:
        table = [{"prefix": cache_root, "device": "/dev/cache", "free_kib": 1500000, "mount": "/cache"},
                 {"prefix": str(box.tmpdir), "device": "/dev/work", "free_kib": 2000000, "mount": "/work"}]
    result = box.run(TEST_DF=json.dumps(table))
    row = _check(_report(result), "disk")
    assert row["status"] == status, row
    if status == "FAIL":
        assert "XDG_CACHE_HOME" in row["fix"] and result.returncode == 3
    if layout.startswith("split"):
        assert "different filesystems" in row["detail"] and "1.9 GB and 1.7 GB" in row["detail"] and "/work" in row["found"]
    _no_leak(box, result)


def test_an_existing_plain_folder_of_this_user_is_used_as_it_is(tmp_path, keypair):
    box = Box(tmp_path, keypair)
    work = box.home / "gsj-operator"
    work.mkdir(mode=0o700)
    (work / "site.json").write_text("{}")
    (work / "credentials").mkdir()
    os.chmod(work / "credentials", 0o750)
    result = box.run()
    assert result.returncode == 3, result.stderr + result.stdout
    report = _report(result)
    assert "existing" in _check(report, "working-folder")["detail"]
    row = _check(report, "credentials-folder")
    assert row["status"] == "FAIL" and "chmod 700" in row["fix"] and "750" in row["detail"]
    assert stat.S_IMODE((work / "credentials").stat().st_mode) == 0o750, "init changed a customer's folder"
    assert (work / "site.json").read_text() == "{}"


def test_the_fix_command_for_the_credentials_folder_is_quoted(tmp_path, keypair):
    box = Box(tmp_path, keypair)
    home = tmp_path / "home dir"
    home.mkdir(mode=0o700)
    (home / "gsj-operator").mkdir(mode=0o700)
    (home / "gsj-operator" / "credentials").mkdir()
    os.chmod(home / "gsj-operator" / "credentials", 0o750)
    result = box.run(HOME=str(home))
    result.reports = sorted((home / "gsj-operator").glob("gsj-init-report-*.json"))
    row = _check(_report(result), "credentials-folder")
    assert row["fix"] == "chmod 700 " + str(home / "gsj-operator" / "credentials").replace(" ", "\\ ")


@pytest.mark.parametrize("shape", ["symlink", "file", "group-writable", "credentials-symlink", "credentials-file", "other-owner", "other-owner-ancestor-link"])
def test_a_preseeded_or_symlinked_working_folder_is_refused_before_any_write(tmp_path, keypair, shape):
    """Refused by name BEFORE anything is written beside the installer or
    under $HOME: not into the folder, not through the link, and no companion
    beside the installer (bootstrap's payload extraction into the run's own
    private temporary directory, removed on exit, is the one write before
    it -- what the guide now says). The owner rules are exercised with an
    `id -u` that answers another uid."""
    box = Box(tmp_path, keypair)
    work = box.home / "gsj-operator"
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    extra = {}
    if shape == "symlink":
        work.symlink_to(elsewhere)
    elif shape == "file":
        work.write_text("not a folder")
    elif shape == "group-writable":
        work.mkdir()
        os.chmod(work, 0o775)
    elif shape == "credentials-symlink":
        work.mkdir(mode=0o700)
        (work / "credentials").symlink_to(elsewhere)
    elif shape == "credentials-file":
        work.mkdir(mode=0o700)
        (work / "credentials").write_text("not a folder")
    elif shape == "other-owner":
        work.mkdir(mode=0o700)
        extra = {"TEST_UID": "4242"}
    else:
        real_home = tmp_path / "real-home"
        real_home.mkdir(mode=0o700)
        linked = tmp_path / "linked-home"
        linked.symlink_to(real_home)
        extra = {"TEST_UID": "4242", "HOME": str(linked)}
        work = linked / "gsj-operator"
    result = box.run(**extra)
    result.reports = sorted(Path(extra.get("HOME", box.home)).glob("gsj-operator/gsj-init-report-*.json"))
    line = _stop(result, "GSJ: refusing", str(work))
    assert {"symlink": "is a symlink", "file": "is not a directory", "group-writable": "writable by group or others (mode 775); chmod go-w",
            "credentials-symlink": "credentials: " + str(work / "credentials") + " is a symlink", "credentials-file": "is not a directory",
            "other-owner": "not by this user (uid 4242)", "other-owner-ancestor-link": "is a symlink owned by uid"}[shape] in line
    assert not list(elsewhere.iterdir()), "init wrote through the link"
    assert box.downloads() == [] and box.beside() == [] and box.kube_calls() == []
    if shape == "file":
        assert work.read_text() == "not a folder"
    if shape == "other-owner-ancestor-link":
        assert not list((tmp_path / "real-home").iterdir())


def test_home_unset_is_a_named_stop(tmp_path, keypair):
    box = Box(tmp_path, keypair)
    env = {k: v for k, v in box.env.items() if k != "HOME"}
    result = subprocess.run([shutil.which("bash", path=SYSTEM_PATH), str(box.installer), "init"], env=env, cwd=str(box.installer.parent),
                            capture_output=True, text=True, timeout=180)
    result.reports = []
    _stop(result, "HOME is not set")
    for trap in BASH_TRAPS:
        assert trap not in result.stderr, result.stderr


def test_two_runs_in_the_same_second_write_two_reports_and_a_link_at_the_next_name_is_skipped(tmp_path, keypair):
    box = Box(tmp_path, keypair)
    stamp = "20260101T000000Z"
    first = box.run(TEST_DATE_STAMP=stamp)
    assert first.returncode == 0, first.stderr
    kept = first.reports[0].read_bytes()
    assert first.reports[0].name == f"gsj-init-report-{stamp}.json"
    decoy = tmp_path / "decoy.json"
    decoy.write_text("not a report")
    (box.home / "gsj-operator" / f"gsj-init-report-{stamp}-2.json").symlink_to(decoy)
    second = box.run(TEST_DATE_STAMP=stamp)
    assert second.returncode == 0, second.stderr
    names = {p.name for p in second.reports if not p.is_symlink()}
    assert names == {f"gsj-init-report-{stamp}.json", f"gsj-init-report-{stamp}-3.json"}, names
    assert (box.home / "gsj-operator" / f"gsj-init-report-{stamp}.json").read_bytes() == kept
    assert decoy.read_text() == "not a report", "the report was written through the link"


def test_an_installer_folder_that_cannot_be_written_keeps_the_verified_copies_in_the_working_folder(tmp_path, keypair):
    box = Box(tmp_path, keypair)
    os.chmod(box.installer.parent, 0o555)
    try:
        result = box.run()
    finally:
        os.chmod(box.installer.parent, 0o755)
    assert result.returncode == 0, result.stderr + result.stdout
    report = _report(result)
    assert report["verification"]["status"] == "PASS" and report["verification"]["companions_downloaded"] == 4 and report["verification"]["companions_saved"] == 4
    if os.geteuid() == 0:
        assert report["verification"]["saved_in"] == str(box.installer.parent)     # root writes through mode 555
    else:
        kept = box.home / "gsj-operator" / "releases" / VERSION
        assert report["verification"]["saved_in"] == str(kept) and str(kept) in _check(report, "release-verification")["detail"]
        assert sorted(p.name for p in kept.iterdir()) == sorted(COMPANIONS)
        assert stat.S_IMODE(kept.stat().st_mode) == 0o700
        assert box.beside() == []


def test_a_file_that_appears_beside_the_installer_during_the_download_is_never_replaced(tmp_path, keypair):
    box = Box(tmp_path, keypair)
    result = box.run(TEST_CURL_PLANT=str(box.installer.parent))
    assert result.returncode == 0, result.stderr + result.stdout
    report = _report(result)
    assert report["verification"]["status"] == "PASS" and report["verification"]["companions_saved"] == 0
    for name in COMPANIONS:
        assert (box.installer.parent / name).read_text() == "operator's own copy of " + name
    assert result.stderr.count("appeared during the download and was not replaced") == 4


def test_a_link_that_appears_beside_the_installer_is_never_written_through(tmp_path, keypair):
    box = Box(tmp_path, keypair)
    target = tmp_path / "precious"
    target.write_text("precious")
    result = box.run(TEST_CURL_PLANT=str(box.installer.parent), TEST_CURL_PLANT_LINK=str(target))
    assert result.returncode == 0, result.stderr + result.stdout
    assert target.read_text() == "precious"
    assert _report(result)["verification"]["companions_saved"] == 0


def test_run_through_a_symlink_beside_the_installer_means_beside_the_file(tmp_path, keypair):
    box = Box(tmp_path, keypair)
    box.place(*COMPANIONS)
    links = tmp_path / "bin-of-operator"
    links.mkdir()
    (links / "gsj-install.sh").symlink_to(box.installer)
    result = box.run(script=str(links / "gsj-install.sh"), cwd=links)
    assert result.returncode == 0, result.stderr + result.stdout
    assert box.downloads() == [] and _report(result)["verification"]["companions_present"] == 4
    assert sorted(p.name for p in links.iterdir()) == ["gsj-install.sh"]


# --- the read-only proof and the secrets rule ---------------------------------------

READ_ONLY = {("config", "current-context"), ("version",), ("get",), ("top", "nodes")}


def _verb(argv):
    flags = {"--context": 1, "--namespace": 1, "-n": 1, "--request-timeout": 1, "-l": 1, "-o": 1}
    verbs, i = [], 0
    while i < len(argv):
        if argv[i] in flags:
            i += 1 + flags[argv[i]]
        elif argv[i].startswith("-"):
            i += 1
        else:
            verbs.append(argv[i]); i += 1
    return tuple(verbs[:2]) if verbs[:1] in (["config"], ["top"]) else tuple(verbs[:1])


def test_init_is_read_only_against_the_cluster(tmp_path, keypair):
    """The recording kubectl exits 99 on any verb outside the four read-only
    ones; this asserts that never happened AND that every recorded verb is
    one of them -- no create, apply, delete, patch, exec, run, label, scale,
    no Lease, no --raw, no --watch -- even with an operator's exported
    leftovers that cleanup_exit would otherwise act on. The process-group
    leftovers name a sentinel this test owns; it must outlive the run. helm
    is recorded too and answers only `version --short`."""
    box = Box(tmp_path, keypair)
    sentinel = subprocess.Popen([shutil.which("sleep", path=SYSTEM_PATH), "300"], start_new_session=True)
    try:
        result = box.run(PROBE_POD="leftover-probe", OPERATION="leftover-op", LEASE_ACQUIRED="true", TRANSFER_HANDBACK_POD="leftover-pod",
                         RENEWER=str(sentinel.pid), HELM_PID=str(sentinel.pid), GSJ_ADDON_COMMAND_PID=str(sentinel.pid),
                         CONTEXT="c", NAMESPACE="ns", RELEASE="r", SITE="/nonexistent")
        assert sentinel.poll() is None, "init's exit signalled a process group it did not own"
    finally:
        sentinel.kill()
        sentinel.wait()
    assert result.returncode == 0, result.stderr + result.stdout
    calls = box.kube_calls()
    assert calls, "inspect made no cluster reads at all"
    assert "MUTATION-REFUSED" not in result.stderr
    assert {_verb(call) for call in calls} <= READ_ONLY, sorted({_verb(call) for call in calls})
    assert not any(flag in call for call in calls for flag in ("--watch", "-w", "--raw", "exec", "delete", "replace", "create", "apply", "patch"))
    assert box.helm_calls() and all(call == ["version", "--short"] for call in box.helm_calls()), box.helm_calls()


def test_leftover_variables_never_reach_a_cluster_even_when_init_stops_before_its_own_code(runtime):
    """A recovery bundle refuses init after the exit trap exists: the unset
    lives in main, before the trap, so the leftovers are gone by then."""
    run, state, work = runtime
    payload = work / "payload"
    (payload / "helpers").mkdir(parents=True)
    (payload / "helpers" / "lease-repair-source-release.json").write_text("{}")
    for name in ("verification-cleanup.sh", "startup-recovery.sh"):
        (payload / "helpers" / name).write_text("")
    result = run('GSJ_PAYLOAD="$TEST_WORK/payload"\nbootstrap() { :; }\ninit_box() { touch "$TEST_WORK/init-ran"; }\nmain init\n',
                 PROBE_POD="leftover-probe", OPERATION="leftover-op", LEASE_ACQUIRED="true")
    assert result.returncode != 0 and "supports only inspect and lease-repair" in result.stderr
    assert not (work / "init-ran").exists()
    assert json.loads(state.read_text())["calls"] == [], "the exit trap acted on an exported leftover"


def test_no_secret_or_full_url_reaches_any_message_or_the_report(tmp_path, keypair):
    """The canary rides in every place untrusted text could come from: the
    release URL's path and userinfo, kubectl's and curl's stderr, the
    kubeconfig's path (every kubectl diagnostic quotes it), a proxy URL's
    userinfo, a pod env value. None of it may reach the screen, the report,
    or anything under the working folder."""
    box = Box(tmp_path, keypair)
    base = f"https://u:{CANARY}@releases.example/{CANARY}/dl"
    box.installer, box.assets = _installer(tmp_path / "release", keypair, base=base)
    box.serve(box.assets)
    result = box.run(TEST_CURL_BASE=f"{base}/{VERSION}", TEST_KUBE_SERVER="",
                     HTTPS_PROXY=f"https://user:{CANARY}@proxy.example:3128/{CANARY}")
    assert result.returncode == 3, result.stderr + result.stdout
    _no_leak(box, result)
    assert _report(result)["release_origin"] == "https://releases.example"


def test_a_hostile_context_name_survives_json_escaping(tmp_path, keypair):
    box = Box(tmp_path, keypair)
    name = 'ctx "quoted" \\ back\tslash'
    result = box.run("--context", name)
    assert result.returncode == 0, result.stderr + result.stdout
    report = _report(result)
    assert _check(report, "cluster")["found"] == 'context ctx "quoted" \\ back slash, Kubernetes 1.35.8'


def test_cdpath_does_not_move_where_beside_the_installer_is(tmp_path, keypair):
    box = Box(tmp_path, keypair)
    decoy = tmp_path / "decoy" / "release"
    decoy.mkdir(parents=True)
    result = box.run(CDPATH=str(tmp_path / "decoy"), cwd=tmp_path, script=os.path.relpath(box.installer, tmp_path))
    assert result.returncode == 0, result.stderr + result.stdout
    assert box.beside() == sorted(COMPANIONS) and not list(decoy.iterdir())


def test_help_lists_init_and_the_verifier_and_inspect_are_pinned(runtime):
    run, _, _ = runtime
    result = run("main help")
    assert "gsj-install.sh init [--context NAME]" in result.stdout
    assert "any command but init also accepts --fetch-tools" in result.stdout
    source = (INSTALLER / "runtime.sh").read_text()
    assert "if [[ $COMMAND == init ]]; then init_box; return; fi" in source
    assert "[[ ${COMMAND:-} == init ]] || client_preflight" in source
    # the verifier init executes is exactly the one this repository publishes
    pinned = re.search(r"^INIT_VERIFIER_SHA256=([0-9a-f]{64})$", source, re.M).group(1)
    assert pinned == hashlib.sha256((INSTALLER / "verify-release.sh").read_bytes()).hexdigest(), \
        "verify-release.sh changed: update INIT_VERIFIER_SHA256 in runtime.sh (init executes only the published verifier)"
    # inspect_cluster is byte-identical to the text init was built on: the
    # base head be7b2e7, whose proxy field goes through url_origin_only
    # (re-pinned deliberately at that merge; before it, base 833fe99's text)
    body = source[source.index("\ninspect_cluster() {"):source.index("\nquantity_bytes() {")]
    assert hashlib.sha256(body.encode()).hexdigest() == "861eee2b780591f89ea8dc1b7c1d07082554717af04d98278aa337744c629788", "inspect_cluster changed; init runs it unchanged -- re-pin deliberately"


def test_the_guides_check_table_names_exactly_the_checks_init_writes():
    """The guide's table of init's checks and init's checks must say the same
    things: every check name the runtime writes appears in the delimited
    table of OPERATOR.md, and nothing else does."""
    source = (INSTALLER / "runtime.sh").read_text()
    block = source[source.index("init_box() {"):source.index("# ---------------------------------------------------------------- /init --")]
    in_code = set(re.findall(r'init_row ([a-z][a-z0-9-]*) ', block)) | {"helm", "kubectl", "jq", "tar", "gzip", "base64"}
    guide = (INSTALLER / "OPERATOR.md").read_text()
    table = guide[guide.index("<!-- init: checks -->"):guide.index("<!-- /init: checks -->")]
    in_guide = set(re.findall(r"^\| `([a-z][a-z0-9-]*)` \|", table, re.M))
    assert in_guide == in_code, (sorted(in_guide - in_code), sorted(in_code - in_guide))


def test_a_recovery_bundle_refuses_init_like_every_verb_but_inspect_and_lease_repair(runtime):
    run, _, work = runtime
    payload = work / "payload"
    (payload / "helpers").mkdir(parents=True)
    (payload / "helpers" / "lease-repair-source-release.json").write_text("{}")
    for name in ("verification-cleanup.sh", "startup-recovery.sh"):
        (payload / "helpers" / name).write_text("")
    result = run('GSJ_PAYLOAD="$TEST_WORK/payload"\nbootstrap() { :; }\ninstall_exit_traps() { :; }\ninit_box() { touch "$TEST_WORK/init-ran"; }\nmain init\n')
    assert result.returncode != 0 and "supports only inspect and lease-repair" in result.stderr
    assert not (work / "init-ran").exists()


@pytest.mark.parametrize("code,status", [("200", "PASS"), ("301", "PASS"), ("403", "FAIL"), ("429", "FAIL"), ("500", "FAIL"), ("503", "FAIL")])
def test_the_github_row_reports_what_the_answer_established(tmp_path, keypair, code, status):
    """The row said "the corpus release can be downloaded from
    this machine" and PASSED on ANY answer -- a 403 from a portal, a 500 --
    and the summary said ready. A 2xx/3xx is the open route; a 4xx is a
    refusal by github.com or by something between, a 5xx an error there or
    between: named as that, FAIL, and the box is not ready."""
    box = Box(tmp_path, keypair)
    result = box.run(TEST_CURL_GITHUB_CODE=code)
    report = _report(result)
    row = _check(report, "egress-github")
    assert row["status"] == status and row["found"] == f"HTTP {code}", row
    if status == "PASS":
        assert result.returncode == 0 and report["summary"]["ready"] is True
        assert "route the corpus release is downloaded over" in row["detail"] and "not proved" not in row["detail"]
    else:
        assert result.returncode == 3 and report["summary"]["ready"] is False
        assert "not proved downloadable" in row["detail"] and "can be downloaded" not in row["detail"]
        assert ("refused" in row["detail"]) == (code[0] == "4") and ("error at github.com" in row["detail"]) == (code[0] == "5")
        assert "corpus.vectors_path" in row["fix"]
    assert report["summary"]["egress"] == "full"          # an answer is an answer: the egress class is about reach
    _no_leak(box, result)


@pytest.mark.parametrize("code,status", [("401", "PASS"), ("200", "PASS"), ("403", "FAIL"), ("500", "FAIL")])
def test_the_ghcr_row_reports_what_the_answer_established(tmp_path, keypair, code, status):
    """The same rule for ghcr.io, whose PASS includes 401 -- how a registry
    answers an anonymous request."""
    box = Box(tmp_path, keypair)
    result = box.run(TEST_CURL_GHCR_CODE=code)
    report = _report(result)
    row = _check(report, "egress-ghcr")
    assert row["status"] == status and row["found"] == f"HTTP {code}", row
    assert (result.returncode == 0) == (status == "PASS") and report["summary"]["ready"] is (status == "PASS")
    if code == "401":
        assert "anonymous request" in row["detail"]
    if status == "FAIL":
        assert "registry.base" in row["fix"]
    _no_leak(box, result)


def test_the_full_report_carries_only_the_proxy_s_origin(tmp_path, keypair):
    """Review B2: a full init run -- inspect included, its profile spliced
    into the report -- with a proxy whose URL carries userinfo, a path, a
    query and a fragment, each a canary. The report's
    .inspect.profile.networking.egress.proxy_origin is the origin alone (the
    review's run wrote `proxy.example?REVIEW_PROXY_QUERY_SECRET` there: the
    previous canary test ran without inspect and never saw it), and no
    canary reaches the screen, the report or any file under the working
    folder."""
    box = Box(tmp_path, keypair)
    result = box.run(HTTPS_PROXY=f"http://u:{CANARY}@proxy.example:3128/{CANARY}?REVIEW_PROXY_QUERY_SECRET={CANARY}#{CANARY}")
    assert result.returncode == 0, result.stderr + result.stdout
    report = _report(result)
    assert _check(report, "inspect")["status"] == "PASS"
    egress = report["inspect"]["profile"]["networking"]["egress"]
    assert egress["proxy_configured"] is True and egress["proxy_origin"] == "proxy.example:3128", egress
    text = json.dumps(report) + result.stdout + result.stderr
    assert "REVIEW_PROXY_QUERY_SECRET" not in text and "3128/" not in text and "?" not in egress["proxy_origin"]
    _no_leak(box, result)


def test_the_full_report_keeps_the_origin_of_a_scheme_less_proxy_with_a_query(tmp_path, keypair):
    """The review's exact shape: `proxy.example?REVIEW_PROXY_QUERY_SECRET`."""
    box = Box(tmp_path, keypair)
    result = box.run(HTTPS_PROXY="proxy.example?REVIEW_PROXY_QUERY_SECRET")
    assert result.returncode == 0, result.stderr + result.stdout
    report = _report(result)
    assert report["inspect"]["profile"]["networking"]["egress"]["proxy_origin"] == "proxy.example"
    assert "REVIEW_PROXY_QUERY_SECRET" not in json.dumps(report) + result.stdout + result.stderr
    _no_leak(box, result)
