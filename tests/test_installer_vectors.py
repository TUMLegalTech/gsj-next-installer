"""The released vector sidecar arrives as a manifest plus the blocks it names.

The release splits one 1.6 GB object into a 2.4 KB manifest and seven blocks,
each published as a separate release asset. These tests drive the real
`stage_vectors` Bash function against a real local HTTPS origin and the real
`ops/installer/stage-vectors.py`, so every refusal below is the one a site
would actually see.
"""
import hashlib
import http.server
import json
import shutil
import ssl
import subprocess
import threading
from pathlib import Path

import pytest

from tests.test_installer import INSTALLER, runtime  # noqa: F401


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def manifest_for(blocks):
    """A gsj.corpus-vectors/1 manifest over `blocks`, stamped like the real one."""
    value = {
        "format": "gsj.corpus-vectors/1", "parser_version": 1,
        "chunk_chars": 500, "chunk_overlap": 80,
        "collection": "gsj_synthetic_decisions", "core_commit": "c" * 40,
        "corpus_fingerprint": "f" * 64, "dtype": "float16", "codec": "gzip",
        "embedding": {"dimensions": 768, "distance": "cosine", "encoding": "synthetic-v1",
                      "manifest_sha256": "9" * 64, "model": "Synthetic/model", "revision": "r" * 40},
        "vectors": sum(count for _, _, count in blocks),
        "shards": [{"id": sid, "archive": f"vectors-{sid}.f16.gz", "bytes": len(data),
                    "sha256": sha(data), "vectors": count, "ids_sha256": sha(sid.encode())}
                   for sid, data, count in blocks],
    }
    value["fingerprint"] = sha(canonical(value))
    return value


@pytest.fixture
def published(tmp_path):
    """Eight-asset-shaped publication: a manifest and the blocks beside it."""
    blocks = [("01", b"synthetic block one\n" * 512, 17), ("02", b"synthetic block two\n" * 256, 11)]
    root = tmp_path / "published"
    root.mkdir()
    for sid, data, _ in blocks:
        (root / f"vectors-{sid}.f16.gz").write_bytes(data)
    manifest = manifest_for(blocks)
    (root / "vectors.json").write_bytes(canonical(manifest))
    return root, manifest


@pytest.fixture
def origin(tmp_path, published):
    """A real HTTPS origin serving the published assets, recording every request."""
    root, _ = published
    state = {"requests": [], "tamper": set()}

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            name = self.path.rsplit("/", 1)[-1]
            state["requests"].append((self.path, self.headers.get("Authorization")))
            target = root / name
            if not target.is_file():
                self.send_error(404)
                return
            data = target.read_bytes()
            if name in state["tamper"]:
                data = data[:-1] + bytes([data[-1] ^ 0xFF])
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

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
        yield state, f"https://localhost:{httpd.server_port}/release", cert
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join()


def stage(run, work, *, url="", path="", expected, prefix="", ca=None, **extra):
    """Run the real stage_vectors with the pod machinery stubbed and the REAL helper."""
    site = json.loads((work / "site.json").read_text())
    site["corpus"] = {"allow_update": False, "repair_generation": 0,
                      "vectors_url": url, "vectors_path": path, "vectors_sha256": expected}
    (work / "site.json").write_text(json.dumps(site))
    payload = work / "payload"
    (payload / "helpers").mkdir(parents=True, exist_ok=True)
    shutil.copyfile(INSTALLER / "stage-vectors.py", payload / "helpers" / "stage-vectors.py")
    (payload / "release.json").write_text(json.dumps(
        {"corpus": {"manifest_sha256": "a" * 64},
         "images": {"web": {"repository": "synthetic/web", "digest": "sha256:" + "b" * 64}}}))
    destination = work / "volumes"
    destination.mkdir(exist_ok=True)
    # `fetch` is content-addressed: a block already proved under its own digest
    # is never re-fetched. That cache must be the test's, never the developer's.
    cache = work / "cache"
    cache.mkdir(exist_ok=True)
    extra["XDG_CACHE_HOME"] = str(cache)
    body = (actual_curl() if url else "") + prefix + f'''GSJ_PAYLOAD="$TEST_WORK/payload"; OPERATION=synthetic-operation
maintenance_pod() {{ :; }}
transfer_handback() {{ :; }}
# The staging exec is the only one that matters here: it runs the REAL helper,
# against a real directory, exactly as the pod would.
k() {{
  if [[ $1 == exec && $* == *"python -B"* ]]; then
    # $8 is the pod-side corpus root; the test gives the helper a real one.
    python3 "$TEST_WORK/payload/helpers/stage-vectors.py" "{destination}" "$9"
  elif [[ $1 == exec || $1 == delete ]]; then cat >/dev/null
  else return 0; fi
}}
stage_vectors
'''
    if ca:
        extra["CURL_CA_BUNDLE"] = str(ca)
        extra["TEST_CURL"] = shutil.which("curl")
    return run(body, **extra), destination


def actual_curl():
    return 'curl() { command "$TEST_CURL" "$@"; }\n'


def test_url_leg_fetches_the_manifest_then_every_block_it_names(runtime, published, origin):
    run, _, work = runtime
    root, manifest = published
    state, base, cert = origin
    expected = sha((root / "vectors.json").read_bytes())
    result, destination = stage(run, work, url=f"{base}/vectors.json", expected=expected, ca=cert)
    assert result.returncode == 0, result.stderr
    # The manifest first, then exactly the blocks it names, as its siblings.
    assert [path for path, _ in state["requests"]] == [
        "/release/vectors.json", "/release/vectors-01.f16.gz", "/release/vectors-02.f16.gz"]
    for shard in manifest["shards"]:
        assert (destination / shard["archive"]).read_bytes() == (root / shard["archive"]).read_bytes()
    # The manifest lands LAST and byte-identical, so a half-arrived set is
    # never mistaken for a complete one.
    assert (destination / "vectors.json").read_bytes() == (root / "vectors.json").read_bytes()
    assert json.loads((work / "vectors-staged.json").read_text())["shards"] == len(manifest["shards"])


def test_a_public_corpus_never_receives_the_release_delivery_credential(runtime, published, origin):
    """download_curl's origin guard would fail this fetch by name; honouring it
    means sending no credential to a public origin, never relaxing the guard."""
    run, _, work = runtime
    root, _ = published
    state, base, cert = origin
    header = work / "authorization"
    header.write_text("Authorization: Bearer synthetic-release-token\n")
    header.chmod(0o600)
    expected = sha((root / "vectors.json").read_bytes())
    prefix = 'DOWNLOAD_AUTH_FILE="$TEST_WORK/authorization"; DOWNLOAD_AUTH_ORIGIN=https://releases.invalid\n'
    result, _ = stage(run, work, url=f"{base}/vectors.json", expected=expected,
                      ca=cert, prefix=prefix)
    assert result.returncode == 0, result.stderr
    assert state["requests"], "the corpus was never fetched"
    assert all(auth is None for _, auth in state["requests"]), state["requests"]
    assert "synthetic-release-token" not in result.stdout + result.stderr


def test_a_corpus_mirrored_on_the_release_origin_keeps_its_credential(runtime, published, origin):
    """The narrowing is about origins, not about the corpus: an operator who
    mirrors the artifact on their OWN authenticated release origin is fetching
    their own distribution, and the credential belongs there."""
    run, _, work = runtime
    root, _ = published
    state, base, cert = origin
    header = work / "authorization"
    header.write_text("Authorization: Bearer synthetic-release-token\n")
    header.chmod(0o600)
    expected = sha((root / "vectors.json").read_bytes())
    prefix = ('DOWNLOAD_AUTH_FILE="$TEST_WORK/authorization"\n'
              'DOWNLOAD_AUTH_ORIGIN="$(url_origin "%s/vectors.json")"\n' % base)
    result, _ = stage(run, work, url=f"{base}/vectors.json", expected=expected,
                      ca=cert, prefix=prefix)
    assert result.returncode == 0, result.stderr
    assert state["requests"], "the corpus was never fetched"
    assert all(auth == "Bearer synthetic-release-token" for _, auth in state["requests"]), state["requests"]


def test_a_tampered_block_refuses_by_hash_and_publishes_nothing(runtime, published, origin):
    run, _, work = runtime
    root, _ = published
    state, base, cert = origin
    state["tamper"].add("vectors-02.f16.gz")
    expected = sha((root / "vectors.json").read_bytes())
    result, destination = stage(run, work, url=f"{base}/vectors.json", expected=expected, ca=cert)
    assert result.returncode != 0
    assert "artifact hash mismatch" in result.stdout + result.stderr
    assert not (destination / "vectors.json").exists()


def test_a_block_that_is_simply_not_there_refuses_by_name(runtime, published, origin):
    """A transport failure returns curl's own exit code. Without a named
    refusal errexit turns that into a bare non-zero exit naming nothing, and
    the operator cannot tell which of eight objects went missing."""
    run, _, work = runtime
    root, _ = published
    state, base, cert = origin
    (root / "vectors-02.f16.gz").unlink()          # the origin now 404s for it
    expected = sha((root / "vectors.json").read_bytes())
    result, destination = stage(run, work, url=f"{base}/vectors.json", expected=expected, ca=cert)
    assert result.returncode != 0
    output = result.stdout + result.stderr
    assert "vector block vectors-02.f16.gz could not be acquired" in output, output
    assert list(destination.iterdir()) == []


def test_a_manifest_that_is_not_the_declared_one_is_never_parsed(runtime, published, origin):
    run, _, work = runtime
    state, base, cert = origin
    root, _ = published
    state["tamper"].add("vectors.json")
    expected = sha((root / "vectors.json").read_bytes())
    result, destination = stage(run, work, url=f"{base}/vectors.json", expected=expected, ca=cert)
    assert result.returncode != 0
    assert "artifact hash mismatch" in result.stdout + result.stderr
    assert list(destination.iterdir()) == []


def test_the_path_leg_reads_the_blocks_beside_the_staged_manifest(runtime, published):
    run, _, work = runtime
    root, manifest = published
    (root / "vectors.json").chmod(0o600)
    expected = sha((root / "vectors.json").read_bytes())
    result, destination = stage(run, work, path=str(root / "vectors.json"), expected=expected)
    assert result.returncode == 0, result.stderr
    assert sorted(p.name for p in destination.iterdir()) == \
        ["vectors-01.f16.gz", "vectors-02.f16.gz", "vectors.json"]


def test_the_path_leg_refuses_a_block_that_disagrees_with_the_manifest(runtime, published):
    run, _, work = runtime
    root, _ = published
    (root / "vectors.json").chmod(0o600)
    block = root / "vectors-01.f16.gz"
    block.write_bytes(block.read_bytes() + b"appended")
    expected = sha((root / "vectors.json").read_bytes())
    result, destination = stage(run, work, path=str(root / "vectors.json"), expected=expected)
    assert result.returncode != 0
    assert "vectors-01.f16.gz does not match its sha256" in result.stdout + result.stderr
    assert list(destination.iterdir()) == []


def test_the_path_leg_refuses_a_block_the_manifest_names_but_nobody_staged(runtime, published):
    run, _, work = runtime
    root, _ = published
    (root / "vectors.json").chmod(0o600)
    (root / "vectors-02.f16.gz").unlink()
    expected = sha((root / "vectors.json").read_bytes())
    result, destination = stage(run, work, path=str(root / "vectors.json"), expected=expected)
    assert result.returncode != 0
    assert "vectors-02.f16.gz, which is not a plain file beside the staged manifest" \
        in result.stdout + result.stderr


@pytest.mark.parametrize("archive", [
    "../escape.f16.gz", "nested/block.f16.gz", ".hidden",
    # These become bare `tar` operands. A leading dash would be read as a flag,
    # and --checkpoint-action runs a command on the installer host.
    "--checkpoint-action=exec=touch /tmp/gsj-pwned", "-C", "--exclude=x",
])
def test_a_manifest_naming_a_path_is_refused_rather_than_sanitised(runtime, tmp_path, published, archive):
    run, _, work = runtime
    root, _ = published
    manifest = json.loads((root / "vectors.json").read_bytes())
    manifest["shards"][0]["archive"] = archive
    manifest["fingerprint"] = sha(canonical({k: v for k, v in manifest.items() if k != "fingerprint"}))
    (root / "vectors.json").write_bytes(canonical(manifest))
    (root / "vectors.json").chmod(0o600)
    expected = sha((root / "vectors.json").read_bytes())
    result, destination = stage(run, work, path=str(root / "vectors.json"), expected=expected)
    assert result.returncode != 0
    assert "names a path, not a plain corpus file" in result.stdout + result.stderr
    assert list(destination.iterdir()) == []


def test_a_source_without_a_digest_is_refused_before_anything_is_fetched(runtime, published, origin):
    run, _, work = runtime
    _, base, cert = origin
    result, _ = stage(run, work, url=f"{base}/vectors.json", expected="", ca=cert)
    assert result.returncode != 0
    assert "corpus.vectors_sha256 is required" in result.stdout + result.stderr


def test_no_configured_source_leaves_the_ordinary_embed_path_untouched(runtime):
    run, _, work = runtime
    result, destination = stage(run, work, expected="")
    assert result.returncode == 0, result.stderr
    assert list(destination.iterdir()) == []
