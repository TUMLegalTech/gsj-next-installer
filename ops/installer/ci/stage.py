#!/usr/bin/env python3
"""Create immutable HTTPS candidate objects before selected-version qualification.

No installer code is executed. The origin must guarantee atomic conditional PUT;
read-back can detect inconsistent responses, not prove a remote implementation.
"""
import argparse
import base64
import hashlib
import http.client
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import ssl
import stat
import subprocess
import sys
import tarfile
import tempfile
from urllib.parse import urlsplit

FILES = ("gsj-install.sh", "installer-descriptor.sig", "installer-descriptor.json")
MARKER = b"__GSJ_PAYLOAD_BELOW__\n"
MAX_INSTALLER = 128 * 1024 * 1024
MAX_PAYLOAD = 256 * 1024 * 1024
VERSION = re.compile(r"v?\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?\Z")


class Refused(ValueError):
    """Only fixed, secret-free codes may reach the command's error output."""


def require(condition, code):
    if not condition:
        raise Refused(code)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def decode(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate-json-key")
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique)


def read(path, limit, *, private=False):
    # O_NOFOLLOW + fstat avoids following a substituted final symlink.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= limit, "invalid-input-file")
        require(not private or info.st_mode & 0o077 == 0, "credential-file-not-private")
        data = stream.read(limit + 1)
    require(len(data) <= limit, "input-budget-exceeded")
    return data


def verify_signature(key, descriptor, signature):
    with tempfile.TemporaryDirectory(prefix="gsj-stage-trust-") as temp:
        paths = [Path(temp) / name for name in ("public.pem", "descriptor.json", "signature.sig")]
        for path, value in zip(paths, (key, descriptor, signature)):
            path.write_bytes(value)
        result = subprocess.run(["openssl", "rsa", "-pubin", "-in", str(paths[0]), "-text", "-noout"], capture_output=True)
        bits = re.search(rb"\((\d+) bit\)", result.stdout)
        require(result.returncode == 0 and bits and int(bits[1]) >= 3072, "invalid-trusted-key")
        result = subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(paths[0]),
                                 "-signature", str(paths[2]), str(paths[1])], capture_output=True)
        require(result.returncode == 0, "descriptor-signature-invalid")


def authenticated_bundle(directory, trusted):
    """Authenticate immutable local snapshots, then inspect a bounded tar stream."""
    values = {name: read(directory / name, MAX_INSTALLER if name == FILES[0] else 65536) for name in FILES}
    verify_signature(trusted, values[FILES[2]], values[FILES[1]])
    descriptor = decode(values[FILES[2]])
    require(descriptor.get("schema") == "gsj.installer-descriptor/1" and descriptor.get("signature") == "RSA-SHA256",
            "descriptor-schema-invalid")
    require(descriptor.get("trustKeySha256") == sha(trusted), "descriptor-trust-mismatch")
    installer = values[FILES[0]]
    require(descriptor.get("installer") == {"name": FILES[0], "sha256": sha(installer), "bytes": len(installer)},
            "installer-descriptor-mismatch")
    require(installer.count(b"\n" + MARKER) == 1, "payload-marker-invalid")
    header, encoded = installer.split(b"\n" + MARKER)
    header += b"\n" + MARKER
    payload = base64.b64decode(b"".join(encoded.splitlines()), validate=True)
    inventory, selected, total = {}, {}, 0
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r|gz") as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            require(member.isfile() and member.name and not path.is_absolute() and ".." not in path.parts
                    and "\\" not in member.name and str(path) == member.name and member.name not in inventory,
                    "unsafe-payload-member")
            require(0 <= member.size <= MAX_INSTALLER and len(inventory) < 10000, "payload-budget-exceeded")
            total += member.size
            require(total <= MAX_PAYLOAD, "payload-budget-exceeded")
            data = archive.extractfile(member).read(member.size + 1)
            require(len(data) == member.size, "payload-member-truncated")
            inventory[member.name] = {"sha256": sha(data), "bytes": len(data)}
            if member.name in {"release.json", "trust/release.pem", "SHA256SUMS"}:
                selected[member.name] = data
    require(set(selected) == {"release.json", "trust/release.pem", "SHA256SUMS"}, "payload-metadata-missing")
    manifest = decode(selected["release.json"])
    require(manifest.get("schema") == "gsj.release/1" and descriptor.get("manifestSha256") == sha(selected["release.json"]),
            "manifest-descriptor-mismatch")
    require(descriptor.get("version") == manifest.get("version") and VERSION.fullmatch(manifest.get("version", ""))
            and descriptor.get("releaseId") == manifest.get("identity")
            and descriptor.get("qualification", False) == manifest.get("qualification", False), "manifest-identity-mismatch")
    require(manifest.get("runtimeSha256") == sha(header), "runtime-hash-mismatch")
    require(selected["trust/release.pem"] == trusted and manifest.get("trustKeySha256") == sha(trusted), "embedded-trust-mismatch")
    require(manifest.get("payloadInventory") == {k: v for k, v in inventory.items() if k not in {"release.json", "SHA256SUMS"}},
            "payload-inventory-mismatch")
    checksums = "".join(f"{value['sha256']}  {name}\n" for name, value in sorted(inventory.items()) if name != "SHA256SUMS")
    require(selected["SHA256SUMS"] == checksums.encode(), "payload-checksum-mismatch")
    return {"manifest": manifest, "descriptor": descriptor, "files": values, "trust": trusted}


def base_url(value):
    parsed = urlsplit(value)
    require(parsed.scheme == "https" and parsed.hostname and not parsed.username and not parsed.password
            and not parsed.query and not parsed.fragment and not value.endswith("/")
            and re.fullmatch(r"[A-Za-z0-9/._~-]*", parsed.path)
            and all(part not in {".", ".."} for part in parsed.path.split("/")), "invalid-delivery-base")
    return parsed


def header(path):
    data = read(path, 8192, private=True).removesuffix(b"\n")
    require(data.startswith(b"Authorization: ") and len(data) > 15
            and all(32 <= char < 127 for char in data), "invalid-authorization-file")
    return data[15:].decode("ascii")


def resolve(root, value):
    require(isinstance(value, str) and value, "delivery-file-missing")
    path = Path(value)
    path = path if path.is_absolute() else root / path
    require(path.resolve().is_relative_to(root.resolve()), "delivery-file-outside-protected-inputs")
    return path


def access(profile, root):
    require(isinstance(profile, dict), "delivery-profile-missing")
    require(set(profile) <= {"ca_file", "auth_header_file"}, "delivery-profile-unsupported")
    token = header(resolve(root, profile.get("auth_header_file")))
    context = ssl.create_default_context()
    if profile.get("ca_file"):
        context.load_verify_locations(cadata=read(resolve(root, profile["ca_file"]), 1024 * 1024).decode("ascii"))
    return token, context


def read_site(site_path, protected_root):
    site_path = site_path.absolute()
    site = decode(read(site_path, 1024 * 1024, private=True))
    profile = site.get("delivery", {})
    require(isinstance(profile, dict) and set(profile) <= {"ca_file", "auth_header_file"}
            and not site.get("proxy"), "delivery-profile-unsupported")
    # Runtime resolves relative file paths against site.json's directory.
    # Resolve first there, then confine to the protected archive root.
    bound = {key: str(site_path.parent / val) if not Path(val).is_absolute() else val
             for key, val in profile.items() if key in {"ca_file", "auth_header_file"} and val}
    return access(bound, protected_root)


def read_profiles(qualification):
    readers = {}
    for mode in ("upgrade", "restore"):
        site_path = qualification / mode / "site.json"
        readers[mode] = read_site(site_path, qualification)
    return readers


def settings(path, qualification):
    value = decode(read(path, 65536, private=True))
    require(set(value) == {"schema", "base_url", "atomic_conditional_put", "write"}
            and value["schema"] == "gsj.release-staging-settings/1"
            and value["atomic_conditional_put"] is True, "conditional-origin-contract-required")
    writer = access(value["write"], path.parent)
    readers = read_profiles(qualification)
    require(all(auth[0] != writer[0] for auth in readers.values()), "write-and-read-credentials-must-differ")
    return value, writer, readers


class Origin:
    """Direct HTTPS only: no inherited proxy, redirect or response body logging."""
    def __init__(self, base, auth, timeout=120):
        self.url = base_url(base)
        self.auth, self.context = auth
        self.timeout = timeout

    def request(self, method, path, expected, body=None):
        conn = http.client.HTTPSConnection(self.url.hostname, self.url.port or 443,
                                          context=self.context, timeout=self.timeout)
        headers = {"Authorization": self.auth, "Accept-Encoding": "identity", "Cache-Control": "no-cache"}
        if method == "PUT":
            headers.update({"If-None-Match": "*", "Content-Type": "application/octet-stream"})
        try:
            conn.request(method, path, body=body, headers=headers)
            response = conn.getresponse()
            status = response.status
            require(not 300 <= status < 400, "delivery-redirect-refused")
            if method == "GET":
                require(status in {200, 404}, "delivery-read-access-failed")
                if status == 404:
                    return False
                require(response.getheader("Content-Encoding", "identity") == "identity", "delivery-encoding-invalid")
                digest, size = hashlib.sha256(), 0
                while True:
                    block = response.read(min(65536, len(expected) + 1 - size))
                    if not block:
                        break
                    size += len(block)
                    require(size <= len(expected), "remote-object-collision")
                    digest.update(block)
                require(size == len(expected) and digest.hexdigest() == sha(expected), "remote-object-collision")
                return True
            # 200/204 cannot prove a new resource was created under this contract.
            require(status in {201, 412}, "conditional-put-not-confirmed")
            return status
        finally:
            conn.close()


def stage(source, target, settings_path, qualification, *, read_only=False, config_path=None):
    require(not any(os.environ.get(name) for name in (
        "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")),
        "proxy-delivery-profile-unsupported")
    trusted = read(source / "release.pem", 65536)
    before = authenticated_bundle(source, trusted)
    after = authenticated_bundle(target, before["trust"])
    old, new = before["manifest"], after["manifest"]
    require(old["version"] != new["version"] and old["identity"] != new["identity"]
            and old["identity"] in new.get("supported_sources", []), "distinct-supported-source-required")
    base = old.get("release_base_url")
    parsed = base_url(base)
    if read_only:
        require(config_path is not None or qualification is not None, "read-profile-required")
        reader_auth = ({config_path.parent.name: read_site(config_path, config_path.parent.parent)}
                       if config_path is not None else read_profiles(qualification))
        writer = None
    else:
        require(settings_path is not None and qualification is not None and config_path is None, "write-settings-required")
        config, writer_auth, reader_auth = settings(settings_path, qualification)
        require(config["base_url"] == base, "staging-base-differs-from-signed-source")
        writer = Origin(base, writer_auth)
    readers = {name: Origin(base, auth) for name, auth in reader_auth.items()}
    prefix = parsed.path + "/" + new["version"] + "/"
    values = after["files"]  # Authenticated byte snapshots cannot change mid-upload.
    def read_all(name):
        verdicts = [reader.request("GET", prefix + name, values[name]) for reader in readers.values()]
        require(len(set(verdicts)) == 1, "reader-visibility-disagrees")
        return verdicts[0]
    present = {name: read_all(name) for name in FILES}
    require(not read_only or all(present.values()), "staged-delivery-unavailable")
    require(not present[FILES[2]] or all(present.values()), "committed-delivery-incomplete")
    results = {}
    for name in FILES:  # Descriptor is deliberately the last write/commit point.
        if present[name]:
            results[name] = "identical-existing"
            continue
        if name == FILES[2]:
            require(all(read_all(item) for item in FILES[:2]), "uncommitted-payload-unavailable")
        status = writer.request("PUT", prefix + name, values[name], body=values[name])
        require(read_all(name), "created-object-not-readable")
        results[name] = "created" if status == 201 else "identical-concurrent"
    require(all(read_all(name) for name in FILES), "committed-delivery-unavailable")
    return {"schema": "gsj.release-staging/1", "status": "passed", "operation": "readback" if read_only else "stage",
            "source_identity": old["identity"],
            "source_version": old["version"], "target_identity": new["identity"], "target_version": new["version"],
            "source_installer_sha256": before["descriptor"]["installer"]["sha256"],
            "target_installer_sha256": after["descriptor"]["installer"]["sha256"],
            "target_manifest_sha256": after["descriptor"]["manifestSha256"], "trust_sha256": sha(trusted),
            "base_url": base, "version_url": base + "/" + new["version"],
            "transport": "direct-https",
            "read_profiles": sorted(readers),
            "descriptor_published_last": True if not read_only and results[FILES[2]] == "created" else None,
            "descriptor_commit_policy": "after-payload-readback",
            "origin_atomic_conditional_put": "required-service-guarantee",
            "files": {name: {"sha256": sha(values[name]), "bytes": len(values[name]), "outcome": results[name]} for name in FILES}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "target", "report"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--settings", type=Path)
    parser.add_argument("--qualification-inputs", type=Path)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--read-only", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        require(not args.report.exists(), "report-already-exists")
        report = stage(args.source, args.target, args.settings, args.qualification_inputs,
                       read_only=args.read_only, config_path=args.config)
        with args.report.open("x") as output:
            json.dump(report, output, sort_keys=True, indent=2)
            output.write("\n")
        print(json.dumps({"status": "passed", "target_installer_sha256": report["target_installer_sha256"]}))
    except Exception as error:
        # Never include URLs returned by the server, provider errors, or headers.
        print(json.dumps({"status": "failed", "code": str(error) if isinstance(error, Refused) else "staging-io-or-format-failed"}), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
