"""Real local HTTP/TLS transfers exercise the distributable Bash functions."""
import hashlib
import http.server
import json
import shutil
import ssl
import subprocess
import threading
from pathlib import Path

import pytest

from tests.test_installer import _site, runtime  # noqa: F401


@pytest.fixture
def server(tmp_path):
    state = {"requests": [], "objects": {}, "interrupt": False, "corrupt": False}
    content = b"synthetic resumable payload\n" * 4096

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_PUT(self):
            state["requests"].append(("PUT", self.path, self.headers.get("Authorization")))
            state["objects"][self.path] = self.rfile.read(int(self.headers["Content-Length"]))
            self.send_response(201)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_GET(self):
            state["requests"].append(("GET", self.path, self.headers.get("Authorization")))
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "/must-not-receive-credentials")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            data = state["objects"].get(self.path, content)
            if state["corrupt"]:
                data += b"changed"
            offset = int(self.headers.get("Range", "bytes=0-").split("=")[1].split("-")[0])
            state["last_offset"] = offset
            # a per-path queue of statuses to serve first (readiness is the
            # listener answering, never a dependency, so /readyz answers 503
            # while the door warms up), then the ordinary 200/206
            queued = state.get("status", {}).get(self.path)
            self.send_response(queued.pop(0) if queued else (206 if offset else 200))
            if offset:
                self.send_header("Content-Range", f"bytes {offset}-{len(data)-1}/{len(data)}")
            self.send_header("Content-Length", str(len(data)-offset))
            for name, value in state.get("headers", {}).get(self.path, {}).items():
                self.send_header(name, value)
            self.end_headers()
            if state["interrupt"]:
                state["interrupt"] = False
                self.wfile.write(data[:len(data)//2])
                self.wfile.flush()
                self.close_connection = True
                return
            self.wfile.write(data[offset:])

    key, cert = tmp_path / "key.pem", tmp_path / "ca.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=localhost",
                    "-addext", "subjectAltName=DNS:localhost"], check=True, capture_output=True)
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield state, f"https://localhost:{httpd.server_port}", cert, content
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join()


def actual_curl():
    # The parent fixture deliberately stubs curl. These tests opt into the real
    # binary, confined to the ephemeral local server and a generated test CA.
    return 'curl() { command "$TEST_CURL" "$@"; }\n'


def test_interrupted_download_retains_bytes_and_resumes_verified_range(runtime, server):
    run, _, work = runtime
    state, origin, cert, content = server
    state["interrupt"] = True
    body = actual_curl() + 'fetch "$TEST_URL/payload" "$TEST_WORK/download" "$TEST_SHA"\n'
    env = dict(TEST_CURL=shutil.which("curl"), TEST_URL=origin, CURL_CA_BUNDLE=str(cert),
               TEST_SHA=hashlib.sha256(content).hexdigest())
    first = run(body, **env)
    assert first.returncode != 0
    partial = work / "download.partial"
    assert partial.read_bytes() == content[:len(content)//2]
    second = run(body, **env)
    assert second.returncode == 0, second.stderr
    assert state["last_offset"] == len(content)//2
    assert (work / "download").read_bytes() == content
    assert not partial.exists()


def test_artifact_auth_is_origin_scoped_and_redirects_fail_without_forwarding(runtime, server):
    run, _, work = runtime
    state, origin, cert, _ = server
    header = work / "authorization"
    header.write_text("Authorization: Bearer synthetic-bound-token\n")
    header.chmod(0o600)
    setup = actual_curl() + 'DOWNLOAD_AUTH_FILE="$TEST_WORK/authorization"\nDOWNLOAD_AUTH_ORIGIN="$TEST_ORIGIN"\n'
    env = dict(TEST_CURL=shutil.which("curl"), TEST_ORIGIN=origin, CURL_CA_BUNDLE=str(cert))
    result = run(setup + 'download_curl --silent --show-error --location "$TEST_ORIGIN/redirect" -o "$TEST_WORK/out"\n', **env)
    assert result.returncode != 0
    assert state["requests"] == [("GET", "/redirect", "Bearer synthetic-bound-token")]
    result = run(setup + 'download_curl https://another-origin.invalid/object -o "$TEST_WORK/out"\n', **env)
    assert result.returncode != 0
    assert len(state["requests"]) == 1
    assert "synthetic-bound-token" not in result.stdout + result.stderr


@pytest.mark.parametrize("value", ["Authorization: ", "Authorization: token\nX-Key: injected", "Authorization: token\r\n"])
def test_authentication_header_rejects_empty_and_multiple_headers(runtime, value):
    run, _, work = runtime
    header = work / "header"
    header.write_text(value)
    header.chmod(0o600)
    result = run('header_file "$TEST_WORK/header"\n')
    assert result.returncode != 0
    assert value not in result.stdout + result.stderr


@pytest.mark.parametrize("corrupt", [False, True])
def test_offbox_backup_requires_authenticated_readback_of_every_member(runtime, server, corrupt):
    run, _, work = runtime
    state, origin, cert, _ = server
    state["corrupt"] = corrupt
    header = work / "backup-auth"
    header.write_text("Authorization: Bearer synthetic-backup-token\n")
    header.chmod(0o600)
    site = _site()
    site["backup"].update(offbox_url=origin+"/backups", ca_file=str(cert), auth_header_file=str(header))
    (work / "site.json").write_text(json.dumps(site))
    archive = work / "synthetic.enc"
    for suffix in ("", ".resources.enc", ".json"):
        Path(str(archive)+suffix).write_bytes(("encrypted-test"+suffix).encode())
    result = run(actual_curl() + 'SITE="$TEST_WORK/site.json"\noffbox_backup "$TEST_WORK/synthetic.enc"\n',
                 TEST_CURL=shutil.which("curl"), CURL_CA_BUNDLE=str(cert))
    assert (result.returncode != 0) == corrupt, result.stderr
    assert all(r[2] == "Bearer synthetic-backup-token" for r in state["requests"])
    assert "synthetic-backup-token" not in result.stdout + result.stderr
    record = work / "synthetic.enc.offbox.json"
    if corrupt:
        assert not record.exists()
    else:
        assert json.loads(record.read_text())["readback_verified"] is True
        assert len(state["objects"]) == 3
        assert len(state["requests"]) == 6


@pytest.mark.parametrize("damage", [None, "headers", "asset-fallback"])
def test_public_verification_checks_tls_spa_headers_and_real_assets(runtime, server, damage):
    run, _, work = runtime
    state, origin, cert, _ = server
    state["objects"].update({"/readyz": b'{"ok":true}',
                             "/": b'<html><div id="root"></div><script type="module" src="/assets/app.js"></script></html>',
                             "/assets/app.js": b'console.log("synthetic app")'})
    state["headers"] = {"/": {"Content-Security-Policy": "default-src 'none'; script-src 'self'",
                               "X-Content-Type-Options": "nosniff"}}
    if damage == "headers":
        state["headers"] = {}
    elif damage == "asset-fallback":
        state["objects"]["/assets/app.js"] = b'<!doctype html><html>fallback</html>'
    site = _site()
    site["public_url"] = origin
    site["verification"]["ca_file"] = str(cert)
    (work / "site.json").write_text(json.dumps(site))
    result = run(actual_curl()+'public_verify\n', TEST_CURL=shutil.which("curl"))
    assert (result.returncode == 0) == (damage is None), result.stderr
    if damage is None:
        report = json.loads((work / "public-check.json").read_text())
        assert report["tls_verified"] and report["security_headers"] and report["spa"]
        assert report["assets_verified"] == 1
    else:
        assert not (work / "public-check.json").exists()


@pytest.mark.parametrize("warmup", ["passes", "never", "unreachable"])
def test_public_verification_waits_for_readyz_through_the_warmup(runtime, server, warmup):
    """Readiness is the listener answering, never a dependency, so a Ready
    Deployment no longer implies /readyz ok — the door's embedding warm-up
    answers 503 for a while. public_verify waits for the strict /readyz
    (bounded by the site's dependency deadline) instead of asserting it once;
    on the unfixed installer the first 503 ended the whole operation with
    curl's exit 22 and no named refusal. Never ready within the bound -> the
    named failure. A TRANSPORT failure (nothing listens, DNS, TLS, the wrong
    CA) is not a warm-up: after three consecutive attempts curl's own exit
    code names it, within seconds, instead of the whole dependency deadline
    passing and a readiness sentence describing a route fault."""
    run, _, work = runtime
    state, origin, cert, _ = server
    state["objects"].update({"/readyz": b'{"ok":true}',
                             "/": b'<html><div id="root"></div><script type="module" src="/assets/app.js"></script></html>',
                             "/assets/app.js": b'console.log("synthetic app")'})
    state["headers"] = {"/": {"Content-Security-Policy": "default-src 'none'; script-src 'self'",
                               "X-Content-Type-Options": "nosniff"}}
    state["status"] = {"/readyz": [503, 503] if warmup == "passes" else [503] * 50}
    site = _site()
    site["public_url"] = "https://127.0.0.1:9" if warmup == "unreachable" else origin   # port 9: nothing listens
    site["verification"]["ca_file"] = str(cert)
    site["deadlines"]["dependencies_seconds"] = {"passes": 12, "never": 1, "unreachable": 30}[warmup]
    (work / "site.json").write_text(json.dumps(site))
    result = run(actual_curl()+'public_verify\n', TEST_CURL=shutil.which("curl"))
    readyz = [r for r in state["requests"] if r[1] == "/readyz"]
    if warmup == "passes":
        assert result.returncode == 0, result.stderr
        assert len(readyz) == 3 and "not ready yet (HTTP 503)" in result.stderr
        assert json.loads((work / "public-check.json").read_text())["assets_verified"] == 1
    elif warmup == "never":
        assert result.returncode == 1 and "did not reach ready application (last HTTP 503)" in result.stderr, result.stderr
        assert not (work / "public-check.json").exists()
    else:
        assert result.returncode == 1, result.stderr
        assert "public HTTPS route is unreachable (curl exit 7 on 3 consecutive attempts)" in result.stderr, result.stderr
        assert readyz == [] and not (work / "public-check.json").exists()


def test_local_ca_repair_keeps_keys_subject_serial_and_existing_leaf(runtime):
    run, _, work = runtime
    ca_key, ca_cert = work / "ca.key", work / "ca.crt"
    def openssl(*args, check=True):
        return subprocess.run(["openssl", *map(str,args)], check=check, capture_output=True)
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=GSJ sandbox local CA", "-addext", "basicConstraints=critical,CA:TRUE",
            "-keyout", ca_key, "-out", ca_cert)
    ca_key.chmod(0o600)
    key_bytes = ca_key.read_bytes()
    leaf_key, leaf_csr, leaf_cert = work / "leaf.key", work / "leaf.csr", work / "leaf.crt"
    openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=legal.example",
            "-keyout", leaf_key, "-out", leaf_csr)
    extensions = work / "leaf.ext"
    extensions.write_text("subjectAltName=DNS:legal.example\nbasicConstraints=critical,CA:FALSE\n"
                          "keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")
    openssl("x509", "-req", "-in", leaf_csr, "-CA", ca_cert, "-CAkey", ca_key,
            "-CAcreateserial", "-days", "1", "-extfile", extensions, "-out", leaf_cert)
    leaf_bytes = leaf_cert.read_bytes()
    assert openssl("verify", "-x509_strict", "-CAfile", ca_cert, leaf_cert, check=False).returncode != 0
    repaired = work / "repaired.crt"
    result = run('reissue_local_ca "$TEST_WORK" "$TEST_WORK/repaired.crt"\n')
    assert result.returncode == 0, result.stderr
    openssl("verify", "-x509_strict", "-verify_hostname", "legal.example", "-CAfile", repaired, leaf_cert)
    for field in ("-subject", "-serial", "-pubkey"):
        assert openssl("x509", "-in", repaired, "-noout", field).stdout == openssl("x509", "-in", ca_cert, "-noout", field).stdout
    assert ca_key.read_bytes() == key_bytes
    assert leaf_cert.read_bytes() == leaf_bytes
