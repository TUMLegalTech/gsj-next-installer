"""Real loopback HTTPS staging, signed payloads, and interrupted immutable writes."""
import base64
from contextlib import contextmanager
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import io
import json
from pathlib import Path
import ssl
import subprocess
import threading

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("release_stage", ROOT / "ops/installer/ci/stage.py")
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)
spec = importlib.util.spec_from_file_location("release_stage_builder", ROOT / "ops/installer/build.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


def command(*args):
    return subprocess.run(list(map(str, args)), check=True, capture_output=True).stdout


@pytest.fixture(scope="module")
def keys(tmp_path_factory):
    path = tmp_path_factory.mktemp("stage-keys")
    key, cert, public, other = [path / name for name in ("private.pem", "cert.pem", "public.pem", "other.pem")]
    command("openssl", "req", "-x509", "-newkey", "rsa:3072", "-nodes", "-days", "1", "-keyout", key,
            "-out", cert, "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1")
    command("openssl", "pkey", "-in", key, "-pubout", "-out", public)
    command("openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", other)
    return key, cert, public, other


class Server(ThreadingHTTPServer):
    daemon_threads = True


@contextmanager
def https_origin(keys):
    objects, events, lock = {}, [], threading.Lock()
    state = {"objects": objects, "events": events, "fault": None, "put_count": 0, "seen_gets": 0}
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def log_message(self, *args): pass
        def send(self, status, data=b"", **headers):
            self.send_response(status)
            self.send_header("Content-Length", str(len(data)))
            for name, value in headers.items(): self.send_header(name, value)
            self.end_headers()
            if data: self.wfile.write(data)
        def do_GET(self):
            state["seen_gets"] += 1
            auth = self.headers.get("Authorization")
            assert auth != "Bearer PRIVATE-WRITER-SENTINEL"
            events.append(("GET", self.path))
            if auth not in {"Bearer PRIVATE-UPGRADE-SENTINEL", "Bearer PRIVATE-RESTORE-SENTINEL"}:
                return self.send(401)
            if state["fault"] == "redirect": return self.send(302, Location="https://foreign.invalid/secret")
            if state["fault"] == "restore-denied" and auth.endswith("RESTORE-SENTINEL"): return self.send(403)
            if self.path in objects:
                data = objects[self.path]
                if state["fault"] == "readback-tamper" and state["put_count"]: data += b"tamper"
                return self.send(200, data)
            self.send(404)
        def do_PUT(self):
            assert self.headers.get("Authorization") == "Bearer PRIVATE-WRITER-SENTINEL"
            assert self.headers.get("If-None-Match") == "*"
            body = self.rfile.read(int(self.headers["Content-Length"]))
            with lock:
                events.append(("PUT", self.path))
                state["put_count"] += 1
                if state["fault"] == "write-denied": return self.send(403)
                if state["fault"] == "signature-interrupted" and self.path.endswith(".sig"):
                    return self.send(503)
                if state["fault"] == "race-identical":
                    objects[self.path] = body
                    return self.send(412)
                if state["fault"] == "race-conflict":
                    objects[self.path] = b"existing concurrent unrelated bytes"
                    return self.send(412)
                if self.path in objects: return self.send(412)
                objects[self.path] = body
                if state["fault"] == "ignored-precondition": return self.send(200)
                if state["fault"] == "lost-response" or (state["fault"] == "descriptor-lost-response" and self.path.endswith("descriptor.json")):
                    self.close_connection = True
                    return
                self.send(201)
    server = Server(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(keys[1], keys[0])
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield "https://127.0.0.1:" + str(server.server_port) + "/approved/source", state
    finally:
        server.shutdown(); server.server_close(); thread.join(5)


def bundle(path, keys, version, identity, base, *, source="source-id", signing_key=None, damage=None):
    path.mkdir()
    key, _, public, _ = keys
    trusted = public.read_bytes()
    header = b"#!/bin/sh\nexit 97 # This authenticated header must never execute.\n" + stage.MARKER
    files = {"trust/release.pem": (trusted, 0o644), "synthetic": (b"harmless fixture", 0o644)}
    if damage == "unsafe-path": files["../escaped"] = (b"bad", 0o644)
    manifest = {"schema": "gsj.release/1", "identity": identity, "version": version, "release_base_url": base,
                "runtimeSha256": stage.sha(header), "trustKeySha256": stage.sha(trusted), "supported_sources": [source],
                "payloadInventory": {name: {"sha256": stage.sha(data), "bytes": len(data)} for name, (data, _) in files.items()}}
    if damage == "runtime": manifest["runtimeSha256"] = "0" * 64
    if damage == "inventory": manifest["payloadInventory"]["synthetic"]["sha256"] = "0" * 64
    files["release.json"] = (builder.canonical(manifest), 0o644)
    files["SHA256SUMS"] = ("".join(f"{stage.sha(data)}  {name}\n" for name, (data, _) in sorted(files.items())).encode(), 0o644)
    if damage == "unsafe-path":
        import tarfile
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
            for name, (data, _) in files.items():
                member = tarfile.TarInfo(name); member.size = len(data)
                tar.addfile(member, io.BytesIO(data))
        archive = buffer.getvalue()
    else: archive = builder.compressed_tar(files)
    installer = header + base64.encodebytes(archive)
    descriptor = {"schema": "gsj.installer-descriptor/1", "signature": "RSA-SHA256", "version": version,
                  "releaseId": identity, "manifestSha256": stage.sha(files["release.json"][0]), "trustKeySha256": stage.sha(trusted),
                  "installer": {"name": "gsj-install.sh", "sha256": stage.sha(installer), "bytes": len(installer)}}
    if damage == "manifest": descriptor["manifestSha256"] = "0" * 64
    (path / "gsj-install.sh").write_bytes(installer)
    (path / "installer-descriptor.json").write_bytes(builder.canonical(descriptor))
    command("openssl", "dgst", "-sha256", "-sign", signing_key or key, "-out", path / "installer-descriptor.sig", path / "installer-descriptor.json")
    (path / "release.pem").write_bytes(trusted)
    return path


@pytest.fixture
def setup(tmp_path, keys):
    with https_origin(keys) as (base, state):
        source = bundle(tmp_path / "source", keys, "v0.9.0", "source-id", base)
        target = bundle(tmp_path / "target", keys, "v0.10.0-beta.1", "target-id", "https://different-target.invalid/releases")
        protected = tmp_path / "protected"; protected.mkdir()
        for mode in ("upgrade", "restore"):
            root = protected / mode; root.mkdir()
            (root / "read.header").write_text("Authorization: Bearer PRIVATE-" + mode.upper() + "-SENTINEL\n")
            (root / "read.header").chmod(0o600)
            (root / "ca.pem").write_bytes(keys[1].read_bytes())
            (root / "site.json").write_text(json.dumps({"delivery": {"auth_header_file": "read.header", "ca_file": "ca.pem"}}))
            (root / "site.json").chmod(0o600)
        (protected / "write.header").write_text("Authorization: Bearer PRIVATE-WRITER-SENTINEL\n")
        (protected / "write.header").chmod(0o600)
        (protected / "ca.pem").write_bytes(keys[1].read_bytes())
        config = protected / "settings.json"
        config.write_text(json.dumps({"schema": "gsj.release-staging-settings/1", "base_url": base,
            "atomic_conditional_put": True, "write": {"auth_header_file": "write.header", "ca_file": "ca.pem"}}))
        config.chmod(0o600)
        yield {"source": source, "target": target, "settings_path": config, "qualification": protected}, state


def test_descriptor_last_real_https_and_identical_resume_use_source_url_and_literal_version(setup):
    args, state = setup
    result = stage.stage(**args)
    puts = [path for method, path in state["events"] if method == "PUT"]
    assert puts == ["/approved/source/v0.10.0-beta.1/" + name for name in stage.FILES]
    descriptor_at = state["events"].index(("PUT", puts[2]))
    assert all(state["events"][:descriptor_at].count(("GET", name)) >= 4 for name in puts[:2])
    count = state["put_count"]
    resumed = stage.stage(**args)
    assert state["put_count"] == count and all(x["outcome"] == "identical-existing" for x in resumed["files"].values())
    assert resumed["descriptor_published_last"] is None
    assert result["read_profiles"] == ["restore", "upgrade"] and result["target_version"].startswith("v")
    assert "SENTINEL" not in json.dumps(result)


@pytest.mark.parametrize("fault", ["signature-interrupted", "lost-response"])
def test_interruption_preserves_exact_prefix_and_resumes_without_overwrite(setup, fault):
    args, state = setup; state["fault"] = fault
    with pytest.raises(Exception): stage.stage(**args)
    old = dict(state["objects"])
    assert len(old) == 1 and not any(name.endswith("descriptor.json") for name in old)
    state["fault"] = None
    report = stage.stage(**args)
    assert report["status"] == "passed" and all(state["objects"][k] == v for k, v in old.items())
    assert [path for method, path in state["events"] if method == "PUT"].count(next(iter(old))) == 1


@pytest.mark.parametrize("fault,code", [("write-denied", "conditional-put-not-confirmed"),
    ("restore-denied", "delivery-read-access-failed"), ("redirect", "delivery-redirect-refused"),
    ("ignored-precondition", "conditional-put-not-confirmed"), ("readback-tamper", "remote-object-collision"),
    ("race-conflict", "remote-object-collision")])
def test_fail_closed_access_redirect_server_contract_and_collision(setup, fault, code):
    args, state = setup; state["fault"] = fault
    with pytest.raises(stage.Refused, match=code): stage.stage(**args)
    assert not any(path.endswith("descriptor.json") for method, path in state["events"] if method == "PUT")
    if fault in {"restore-denied", "redirect"}: assert state["put_count"] == 0


def test_concurrent_identical_precondition_failure_is_read_verified(setup):
    args, state = setup; state["fault"] = "race-identical"
    report = stage.stage(**args)
    assert all(value["outcome"] == "identical-concurrent" for value in report["files"].values())
    assert report["descriptor_published_last"] is None


@pytest.mark.parametrize("name", stage.FILES)
def test_existing_collision_is_detected_before_any_write(setup, name):
    args, state = setup
    path = "/approved/source/v0.10.0-beta.1/" + name
    state["objects"][path] = b"unrelated immutable existing bytes"
    with pytest.raises(stage.Refused, match="remote-object-collision"): stage.stage(**args)
    assert state["put_count"] == 0 and state["objects"][path] == b"unrelated immutable existing bytes"


def test_existing_commit_with_missing_payload_refuses_to_backfill(setup):
    args, state = setup
    state["objects"]["/approved/source/v0.10.0-beta.1/installer-descriptor.json"] = (args["target"] / "installer-descriptor.json").read_bytes()
    with pytest.raises(stage.Refused, match="committed-delivery-incomplete"): stage.stage(**args)
    assert state["put_count"] == 0


@pytest.mark.parametrize("damage", ["runtime", "inventory", "manifest", "unsafe-path", "wrong-signature", "installer"])
def test_failed_target_trust_or_payload_is_rejected_before_network(setup, keys, tmp_path, damage):
    args, state = setup
    if damage == "installer":
        with (args["target"] / "gsj-install.sh").open("ab") as output: output.write(b"tamper")
    else:
        args["target"] = bundle(tmp_path / "damaged", keys, "v0.10.0-beta.1", "target-id", "https://target.invalid/base",
            damage=damage, signing_key=keys[3] if damage == "wrong-signature" else None)
    with pytest.raises(stage.Refused): stage.stage(**args)
    assert not state["events"]


@pytest.mark.parametrize("fault", ["writer-mode", "read-missing", "contract-missing", "wrong-base", "same-credential"])
def test_all_protected_inputs_are_required_before_any_network(setup, fault):
    args, state = setup; root = args["qualification"]
    config = json.loads(args["settings_path"].read_text())
    if fault == "writer-mode": (root / "write.header").chmod(0o644)
    if fault == "read-missing": (root / "restore/read.header").unlink()
    if fault == "contract-missing": config["atomic_conditional_put"] = False
    if fault == "wrong-base": config["base_url"] = "https://foreign.invalid/releases"
    if fault == "same-credential": (root / "write.header").write_bytes((root / "upgrade/read.header").read_bytes())
    args["settings_path"].write_text(json.dumps(config))
    with pytest.raises((stage.Refused, OSError)): stage.stage(**args)
    assert not state["events"]


def test_same_version_repair_is_not_public_upgrade_qualification(setup, keys, tmp_path):
    args, state = setup
    args["target"] = bundle(tmp_path / "same", keys, "v0.9.0", "different-id", "https://target.invalid/base")
    with pytest.raises(stage.Refused, match="distinct-supported-source-required"): stage.stage(**args)
    assert not state["events"]


def test_cli_failure_never_prints_auth_provider_body_or_traceback(setup):
    args, state = setup; state["fault"] = "write-denied"
    result = subprocess.run(["python3", "-B", str(ROOT / "ops/installer/ci/stage.py"),
        "--source", str(args["source"]), "--target", str(args["target"]), "--settings", str(args["settings_path"]),
        "--qualification-inputs", str(args["qualification"]), "--report", str(args["qualification"] / "report.json")], capture_output=True, text=True)
    assert result.returncode == 1 and not result.stdout
    assert json.loads(result.stderr) == {"status": "failed", "code": "conditional-put-not-confirmed"}
    assert "SENTINEL" not in result.stderr and "Traceback" not in result.stderr


def test_qualification_network_readback_needs_no_writer_and_never_puts(setup):
    args, state = setup
    stage.stage(**args)
    (args["qualification"] / "write.header").unlink()
    args["settings_path"].unlink()
    args["settings_path"] = None
    state["events"].clear()
    report = stage.stage(**args, read_only=True)
    assert report["operation"] == "readback" and report["descriptor_published_last"] is None
    assert all(method == "GET" for method, _ in state["events"])
    del state["objects"][next(iter(state["objects"]))]
    with pytest.raises(stage.Refused, match="staged-delivery-unavailable"):
        stage.stage(**args, read_only=True)
    assert all(method == "GET" for method, _ in state["events"])


def test_unknown_ca_is_not_accepted_as_a_network_fallback(setup):
    args, state = setup
    config = json.loads(args["settings_path"].read_text())
    config["write"]["ca_file"] = ""
    args["settings_path"].write_text(json.dumps(config))
    with pytest.raises(ssl.SSLCertVerificationError): stage.stage(**args)
    assert state["put_count"] == 0


def test_single_site_cli_preflight_uses_only_actual_delivery_reader(setup):
    args, state = setup
    stage.stage(**args)
    (args["qualification"] / "write.header").unlink()
    (args["qualification"] / "restore/read.header").unlink()
    args["settings_path"].unlink()
    state["events"].clear()
    result = subprocess.run(["python3", "-B", str(ROOT / "ops/installer/ci/stage.py"), "--read-only",
        "--source", "source", "--target", "target", "--config", "protected/upgrade/site.json",
        "--report", "protected/preflight.json"], cwd=args["source"].parent, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    report = json.loads((args["qualification"] / "preflight.json").read_bytes())
    assert report["operation"] == "readback" and report["read_profiles"] == ["upgrade"]
    assert all(method == "GET" for method, _ in state["events"])


def test_lost_descriptor_response_rechecks_commit_without_another_write(setup):
    args, state = setup
    state["fault"] = "descriptor-lost-response"
    with pytest.raises(Exception): stage.stage(**args)
    assert len(state["objects"]) == 3
    count, saved = state["put_count"], dict(state["objects"])
    state["fault"] = None
    result = stage.stage(**args)
    assert result["status"] == "passed" and result["descriptor_published_last"] is None
    assert state["put_count"] == count and state["objects"] == saved


def test_tampered_source_is_rejected_before_any_request(setup):
    args, state = setup
    with (args["source"] / "gsj-install.sh").open("ab") as output: output.write(b"tampered header")
    with pytest.raises(stage.Refused, match="installer-descriptor-mismatch"): stage.stage(**args)
    assert not state["events"]


@pytest.mark.parametrize('proxy', ['environment', 'delivery-profile'])
def test_proxy_profile_is_explicitly_unsupported_before_network(setup, monkeypatch, proxy):
    args, state = setup
    if proxy == 'environment':
        monkeypatch.setenv('HTTPS_PROXY', 'https://PRIVATE-PROXY-SENTINEL.invalid')
    else:
        site = args['qualification'] / 'upgrade/site.json'
        value = json.loads(site.read_bytes())
        value['delivery']['proxy'] = 'https://PRIVATE-PROXY-SENTINEL.invalid'
        site.write_text(json.dumps(value))
    with pytest.raises(stage.Refused, match='(?:proxy-delivery-profile-unsupported|delivery-profile-unsupported)'):
        stage.stage(**args)
    assert not state['events']
