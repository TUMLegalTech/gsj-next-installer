"""Artifact identity and signing gates, independent of a running cluster."""
import base64
import copy
import hashlib
import importlib.util
import io
import json
import os
import shutil
from pathlib import Path
import subprocess
import tarfile

import pytest


ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "ops/installer/build.py"
spec = importlib.util.spec_from_file_location("installer_builder", BUILDER)
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


@pytest.fixture(scope="module")
def keypair(tmp_path_factory):
    directory = tmp_path_factory.mktemp("installer-signing")
    private, public = directory / "private.pem", directory / "public.pem"
    subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", str(private)], check=True, capture_output=True)
    private.chmod(0o600)
    subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)], check=True, capture_output=True)
    return private, public


@pytest.fixture
def release(tmp_path, keypair):
    runtime = tmp_path / "runtime.sh"
    runtime.write_text('#!/usr/bin/env bash\nset -euo pipefail\n@CLIENT_TABLE@\nif [[ ${1:-} == info ]]; then gsj_client_info jq linux/arm64; fi\nexit 0\n__GSJ_PAYLOAD_BELOW__\n')
    chart = tmp_path / "chart.tgz"
    chart.write_bytes(builder.compressed_tar({"gsj/Chart.yaml": (b"apiVersion: v2\nname: gsj\nversion: 0.10.0-beta.1\nappVersion: 0.10.0-beta.1\n", 0o644)}))
    core_repo = tmp_path / "core"
    core_repo.mkdir()
    subprocess.run(["git", "init", "-q", str(core_repo)], check=True)
    schema_asset = core_repo / "gsj/assets/schema_registry/snapshot.json.gz"
    schema_asset.parent.mkdir(parents=True)
    schema_asset.write_bytes(b"synthetic schema registry asset")
    subprocess.run(["git", "-C", str(core_repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(core_repo), "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "synthetic pinned schema"], check=True)
    core = subprocess.check_output(["git", "-C", str(core_repo), "rev-parse", "HEAD"], text=True).strip()
    model = {"model": "synthetic/model", "revision": "a" * 40, "manifest_sha256": "b" * 64, "dimensions": 768, "distance": "cosine", "encoding": "synthetic-encoding-v1"}
    corpus = {"format": "gsj.corpus/1", "core_commit": core, "source_sha256": "d" * 64, "rows": 1, "chunks": 1, "files": [{"chunks": 1}], "publication_ready": False, "embedding": model}
    corpus["fingerprint"] = hashlib.sha256(json.dumps(corpus, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    corpus_file = tmp_path / "corpus.json"
    corpus_file.write_bytes(builder.canonical(corpus))
    platform = {"linux/arm64": "sha256:" + "b" * 64}
    client = {"linux/arm64": {"url": "https://example.test/fixed-binary", "sha256": "a" * 64}}
    addon = tmp_path / "addon.yaml"
    addon.write_text("apiVersion: v1\nkind: List\nitems: []\n")
    addon_hash = builder.sha(addon.read_bytes())
    value = {
        "schema": "gsj.release/1", "identity": "test-qualification", "version": "0.10.0-beta.1", "qualification": True,
        "core": {"tag": "v4.9.2-deployment", "commit": core}, "platforms": list(platform),
        "model": model, "schema_asset": {"path": "gsj/assets/schema_registry/snapshot.json.gz", "sha256": builder.sha(schema_asset.read_bytes())}, "release_base_url": "",
        "images": {role: {"repository": "localhost:5001/" + role.lower(), "digest": "sha256:" + "a" * 64, "platforms": platform} for role in builder.IMAGE_ROLES},
        "clients": {tool: client for tool in ("helm", "kubectl", "jq")},
        "corpus": {key: corpus[key] for key in ("fingerprint", "source_sha256", "rows", "chunks")},
        "addons": {name: {"path": "addons/addon.yaml", "sha256": addon_hash, "images": {"controller": "example/controller@sha256:" + "e" * 64}} for name in ("traefik", "certManager", "localPath")},
        "_build": {"runtime": str(runtime), "chart": str(chart), "core_git_dir": str(core_repo / ".git"), "corpus_manifest": str(corpus_file), "trust_key_file": str(keypair[1]), "addons": {"addon.yaml": {"path": str(addon), "sha256": addon_hash}}},
    }
    value["corpus"]["manifest_sha256"] = builder.sha(corpus_file.read_bytes())
    for name in ("site.schema.json", "defaults.json", "validate.jq", "compile.jq"):
        path = tmp_path / name
        path.write_text("{}\n" if name.endswith(".json") else ".\n")
        value["_build"][name] = str(path)
    manifest = tmp_path / "release.json"
    manifest.write_bytes(builder.canonical(value))
    return manifest, value


def run(*args):
    return subprocess.run(["python3", "-B", str(BUILDER), *map(str, args)], text=True, capture_output=True)


def test_reproducible_artifact_and_complete_hash_inventory(release, tmp_path):
    manifest, value = release
    outputs = [tmp_path / "one.sh", tmp_path / "two.sh"]
    for output in outputs:
        result = run("--manifest", manifest, "--output", output)
        assert result.returncode == 0, result.stderr
    assert outputs[0].read_bytes() == outputs[1].read_bytes()
    runtime, payload = outputs[0].read_bytes().split(b"\n__GSJ_PAYLOAD_BELOW__\n")
    with tarfile.open(fileobj=io.BytesIO(base64.decodebytes(payload)), mode="r:gz") as archive:
        files = {member.name: archive.extractfile(member).read() for member in archive}
    expected = dict(line.split("  ", 1)[::-1] for line in files["SHA256SUMS"].decode().splitlines())
    assert set(expected) == set(files) - {"SHA256SUMS"}
    assert all(builder.sha(files[name]) == digest for name, digest in expected.items())
    public = json.loads(files["release.json"])
    assert "_build" not in public
    assert "trust_key_file" not in public
    assert public["runtimeSha256"] == builder.sha(runtime + b"\n__GSJ_PAYLOAD_BELOW__\n")
    assert "PRIVATE KEY" not in "".join(data.decode(errors="ignore") for data in files.values())
    result = subprocess.run([str(outputs[0]), "info"], capture_output=True, text=True)
    assert result.stdout.strip() == "https://example.test/fixed-binary\t" + "a" * 64


@pytest.mark.parametrize("mutation", [
    lambda m: m["images"].pop("decisionsData"),
    lambda m: m["images"]["web"].update(digest="latest"),
    lambda m: m["images"]["web"].update(platforms={"linux/amd64": "sha256:" + "a" * 64}),
    lambda m: m["clients"]["jq"]["linux/arm64"].update(sha256="bad"),
    lambda m: m["addons"]["localPath"].update(path="addons/../escape"),
    lambda m: m["corpus"].update(rows=2),
    lambda m: m.pop("model"),
    lambda m: m["schema_asset"].update(sha256="a" * 64),
])
def test_incomplete_or_inconsistent_inventory_emits_no_artifact(release, tmp_path, mutation):
    manifest, value = release
    value = copy.deepcopy(value)
    mutation(value)
    manifest.write_bytes(builder.canonical(value))
    output = tmp_path / "installer.sh"
    result = run("--manifest", manifest, "--output", output)
    assert result.returncode != 0
    assert not output.exists()


def test_cannot_overwrite_an_existing_release(release, tmp_path):
    manifest, _ = release
    output = tmp_path / "installer.sh"
    output.write_bytes(b"existing-release")
    assert run("--manifest", manifest, "--output", output).returncode != 0
    assert output.read_bytes() == b"existing-release"


def test_runtime_and_chart_repairs_receive_new_release_identities(release):
    manifest, value = release
    original, _, _ = builder.prepare(manifest)
    assert builder.prepare(manifest)[0]["identity"] == original["identity"]
    runtime = Path(value["_build"]["runtime"])
    runtime.write_text(runtime.read_text().replace("set -euo pipefail", "set -euo pipefail\n# runtime repair"))
    repaired, _, _ = builder.prepare(manifest)
    assert repaired["identity"] != original["identity"]
    assert repaired["source"]["runtime_sha256"] != original["source"]["runtime_sha256"]
    assert repaired["source"]["chart_sha256"] == original["source"]["chart_sha256"]
    chart = Path(value["_build"]["chart"])
    chart.write_bytes(builder.compressed_tar({"gsj/Chart.yaml": (b"apiVersion: v2\nname: gsj\nversion: 0.10.0-beta.1\nappVersion: 0.10.0-beta.1\ndescription: repaired chart\n", 0o644)}))
    revised, _, _ = builder.prepare(manifest)
    assert revised["identity"] not in {original["identity"], repaired["identity"]}
    assert revised["identity_base"] == original["identity_base"]
    assert revised["source"]["chart_sha256"] != original["source"]["chart_sha256"]


@pytest.mark.parametrize("helper_name", ["verification-cleanup.sh", "startup-recovery.sh"])
def test_runtime_helper_is_conditional_and_missing_default_fails(tmp_path, monkeypatch, helper_name):
    monkeypatch.setattr(builder, "HERE", tmp_path)
    assert builder.runtime_helpers("# historical runtime\n", {}, tmp_path / "manifest.json") == {}
    reference = f'source "$GSJ_PAYLOAD/helpers/{helper_name}"\n'
    with pytest.raises(ValueError, match="required runtime helper is missing"):
        builder.runtime_helpers(reference, {}, tmp_path / "manifest.json")
    (tmp_path / helper_name).write_text("# frozen helper\n")
    files = builder.runtime_helpers(reference, {}, tmp_path / "manifest.json")
    assert files == {"helpers/" + helper_name: (b"# frozen helper\n", 0o644)}


def test_explicit_frozen_runtime_helper_overrides_default_and_rejects_tamper(tmp_path, monkeypatch):
    monkeypatch.setattr(builder, "HERE", tmp_path)
    (tmp_path / "verification-cleanup.sh").write_text("# current helper\n")
    frozen = tmp_path / "old.sh"
    frozen.write_text("# frozen helper\n")
    reference = 'source "$GSJ_PAYLOAD/helpers/verification-cleanup.sh"\n'
    build = {"helpers": {"verification-cleanup.sh": {"path": str(frozen), "sha256": builder.sha(frozen.read_bytes())}}}
    assert builder.runtime_helpers(reference, build, tmp_path / "manifest.json")["helpers/verification-cleanup.sh"][0] == frozen.read_bytes()
    frozen.write_text("# tampered frozen helper\n")
    with pytest.raises(ValueError, match="helper hash mismatch"):
        builder.runtime_helpers(reference, build, tmp_path / "manifest.json")


@pytest.mark.parametrize("helper_name", ["capacity.py", "backup-recovery.py", "restore-files.py", "startup-source-proof.py", "startup-runtime-preflight.py"])
def test_stdin_runtime_helper_marker_is_required_and_hashes_frozen_override(tmp_path, monkeypatch, helper_name):
    monkeypatch.setattr(builder, "HERE", tmp_path)
    reference = f"# GSJ_RUNTIME_HELPER: {helper_name}\n"
    with pytest.raises(ValueError, match="required runtime helper is missing"):
        builder.runtime_helpers(reference, {}, tmp_path / "manifest.json")
    source = tmp_path / helper_name
    source.write_text("print('capacity')\n")
    assert builder.runtime_helpers(reference, {}, tmp_path / "manifest.json") == {
        "helpers/" + helper_name: (source.read_bytes(), 0o644)
    }
    frozen = tmp_path / "frozen-capacity.py"
    frozen.write_text("print('frozen')\n")
    build = {"helpers": {helper_name: {"path": str(frozen), "sha256": builder.sha(frozen.read_bytes())}}}
    assert builder.runtime_helpers(reference, build, tmp_path / "manifest.json")["helpers/" + helper_name][0] == frozen.read_bytes()
    frozen.write_text("print('tampered')\n")
    with pytest.raises(ValueError, match="helper hash mismatch"):
        builder.runtime_helpers(reference, build, tmp_path / "manifest.json")
    with pytest.raises(ValueError, match="undeclared helper"):
        builder.runtime_helpers("# GSJ_RUNTIME_HELPER: unknown.py\n", {}, tmp_path / "manifest.json")


def test_runtime_helper_directory_collision_is_refused(tmp_path):
    source = tmp_path / "helper"
    source.write_text("# helper\n")
    item = {"path": str(source), "sha256": builder.sha(source.read_bytes())}
    build = {"helpers": {"verification-cleanup.sh": item, "verification-cleanup.sh/nested": item}}
    with pytest.raises(ValueError, match="file/directory collision"):
        builder.runtime_helpers('source "$GSJ_PAYLOAD/helpers/verification-cleanup.sh"\n', build, tmp_path / "manifest.json")


@pytest.mark.parametrize("helper_name", ["verification-cleanup.sh", "startup-source-proof.py", "startup-recovery.sh"])
def test_runtime_helper_hash_is_in_inventory_and_release_identity(release, tmp_path, helper_name):
    manifest, value = release
    runtime = Path(value["_build"]["runtime"])
    reference = f'source "$GSJ_PAYLOAD/helpers/{helper_name}"' if helper_name.endswith('.sh') else f'# GSJ_RUNTIME_HELPER: {helper_name}'
    runtime.write_text(runtime.read_text().replace("exit 0", reference + '\nexit 0'))
    helper = tmp_path / "frozen-helper.sh"
    helper.write_text("# helper one\n")
    value["_build"]["helpers"] = {helper_name: {"path": str(helper), "sha256": builder.sha(helper.read_bytes())}}
    manifest.write_bytes(builder.canonical(value))
    first, _, files = builder.prepare(manifest)
    name = "helpers/" + helper_name
    assert first["payloadInventory"][name]["sha256"] == builder.sha(helper.read_bytes())
    assert builder.sha(helper.read_bytes()).encode() + b"  " + name.encode() in files["SHA256SUMS"][0]
    helper.write_text("# helper two\n")
    value["_build"]["helpers"][helper_name]["sha256"] = builder.sha(helper.read_bytes())
    manifest.write_bytes(builder.canonical(value))
    second, _, _ = builder.prepare(manifest)
    assert second["identity"] != first["identity"]
    assert second["runtimeSha256"] == first["runtimeSha256"]


def test_signature_rejects_tampered_installer_without_execution(release, tmp_path, keypair):
    manifest, _ = release
    output, descriptor, signature = (tmp_path / name for name in ("installer.sh", "descriptor.json", "signature.sig"))
    assert run("--manifest", manifest, "--output", output).returncode == 0
    result = run("sign", "--manifest", manifest, "--installer", output, "--private-key", keypair[0], "--descriptor", descriptor, "--signature", signature)
    assert result.returncode == 0, result.stderr
    assert json.loads(descriptor.read_text())["releaseId"].startswith("test-qualification-")
    verify = ["verify", "--installer", output, "--descriptor", descriptor, "--signature", signature, "--public-key", keypair[1]]
    assert run(*verify).returncode == 0
    shell = ["bash", str(ROOT / "ops/installer/verify-release.sh"), str(output), str(descriptor), str(signature), str(keypair[1])]
    result = subprocess.run(shell, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    output.write_bytes(output.read_bytes() + b"\n# changed after signing\n")
    assert run(*verify).returncode != 0
    assert subprocess.run(shell, capture_output=True).returncode != 0


def test_chart_cannot_hide_traversal_or_compiled_cache(tmp_path):
    for name in ("../escape", "gsj/scripts/__pycache__/helper.pyc"):
        path = tmp_path / "bad.tgz"
        with tarfile.open(path, "w:gz") as archive:
            entry = tarfile.TarInfo(name)
            entry.size = 1
            archive.addfile(entry, io.BytesIO(b"x"))
        with pytest.raises(ValueError):
            builder.normalized_chart(path, "0.10.0-beta.1")




# --- the pin's images are held in the SHARED preparation --------------------
#
# A published (non-qualification) build ships the pinned product release's
# images and nothing else. Until the review that found it, only the hand-run
# release preparation (ci/release.py build) looked at web-pin.json; build.py
# and build.py sign accepted whatever images a manifest named, from an empty
# pin and from a mismatched one. The tests below drive the two entry points
# through main() -- argv, dispatch, the error report -- against a synthetic
# pin, a synthetic pinned chart and a clean synthetic worktree, so they run
# anywhere helm does and never read this repository's own pin or Git state.

needs_helm = pytest.mark.skipif(shutil.which("helm") is None, reason="helm not installed")


def _pinned_chart(directory, version):
    """A synthetic chart directory standing in for the pinned product's chart."""
    (directory / "chart").mkdir(parents=True)
    (directory / "chart" / "Chart.yaml").write_text(f"apiVersion: v2\nname: gsj\nversion: {version}\nappVersion: {version}\n")
    return directory / "chart"


def _pin(release, images, chart_sha256):
    return {"schema": "gsj.web-pin/1", "repository": "example/product", "commit": "f" * 40, "release": release,
            "chart": {"version": "0.10.0-beta.1", "tree": "1" * 40, "sha256": chart_sha256},
            "gsj_deploy": {"tree": "2" * 40}, "core": {"tag": "v4.9.2-deployment"}, "images": images}


@pytest.fixture
def published(release, tmp_path, monkeypatch):
    """A PUBLISHED manifest (no `qualification`), its pinned chart and a clean
    worktree, with the pin left for the test to set through `set_pin`.

    Returns (manifest_path, value, set_pin): `set_pin(release, images)`
    installs a synthetic web-pin.json in the builder; `images` is a mapping
    of the four product roles to {repository, digest}, or {} for the state
    before promotion."""
    manifest, value = release
    value = copy.deepcopy(value)
    del value["qualification"]
    del value["_build"]["chart"]                      # a published build packages the pinned chart, never an override
    value["release_base_url"] = "https://releases.example.test/gsj"
    for role in value["images"]:
        value["images"][role]["repository"] = "registry.example.test/" + role.lower()
    corpus_file = Path(value["_build"]["corpus_manifest"])
    corpus = json.loads(corpus_file.read_bytes())
    corpus.update(publication_ready=True, release_owner="Example Owner", source_provenance="synthetic source")
    corpus["fingerprint"] = hashlib.sha256(json.dumps({k: v for k, v in corpus.items() if k != "fingerprint"},
                                                      sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    corpus_file.write_bytes(builder.canonical(corpus))
    value["corpus"].update({k: corpus[k] for k in ("fingerprint", "source_sha256", "rows", "chunks")})
    value["corpus"]["manifest_sha256"] = builder.sha(corpus_file.read_bytes())
    manifest.write_bytes(builder.canonical(value))
    # the clean worktree a published build requires: a synthetic repository, not this one
    clean = tmp_path / "clean-worktree"
    clean.mkdir()
    subprocess.run(["git", "init", "-q", str(clean)], check=True)
    monkeypatch.setattr(builder, "ROOT", clean)
    chart = _pinned_chart(tmp_path / "pinned", value["version"])
    monkeypatch.setattr(builder.webpin, "archive", lambda path, destination, pin=None: chart)
    chart_sha256 = builder.sha(builder.normalized_chart(chart, value["version"]))

    def set_pin(release_tag, images):
        pin = _pin(release_tag, images, chart_sha256)
        monkeypatch.setattr(builder.webpin, "load", lambda path=None: pin)
        return pin
    return manifest, value, set_pin


def _pinned_images(value):
    return {role: {"repository": value["images"][role]["repository"], "digest": value["images"][role]["digest"]}
            for role in builder.webpin.IMAGE_ROLES}


def _main(monkeypatch, capsys, *argv):
    """build.py's own entry: argv in, exit status and the stderr report out."""
    monkeypatch.setattr(builder.sys, "argv", ["build.py", *map(str, argv)])
    status = builder.main()
    return status, capsys.readouterr().err


def _sign_argv(manifest, tmp_path, keypair):
    output = tmp_path / "signed-installer.sh"
    return output, ["sign", "--manifest", manifest, "--installer", output, "--private-key", keypair[0],
                    "--descriptor", tmp_path / "descriptor.json", "--signature", tmp_path / "signature.sig"]


@needs_helm
@pytest.mark.parametrize("entry", ["build", "sign"])
def test_a_published_build_is_refused_while_the_pin_names_no_release(published, tmp_path, keypair, monkeypatch, capsys, entry):
    """Before promotion web-pin.json carries release "" and images {}: a
    published build and a signing both stop in the shared preparation, before
    any output exists, and the report names the pin file."""
    manifest, value, set_pin = published
    set_pin("", {})
    output = tmp_path / "installer.sh"
    if entry == "build":
        argv = ["--manifest", manifest, "--output", output]
    else:
        output, argv = _sign_argv(manifest, tmp_path, keypair)
        output.write_bytes(b"an installer that must not be signed")
    status, err = _main(monkeypatch, capsys, *argv)
    assert status == 1
    assert "web-pin.json names no product release yet" in err, err
    if entry == "build":
        assert not output.exists()
    else:
        assert not (tmp_path / "descriptor.json").exists() and not (tmp_path / "signature.sig").exists()


@needs_helm
@pytest.mark.parametrize("entry", ["build", "sign"])
@pytest.mark.parametrize("field", ["digest", "repository"])
def test_a_published_build_refuses_an_image_that_differs_from_the_pin(published, tmp_path, keypair, monkeypatch, capsys, entry, field):
    """The pin is filled; the manifest names another digest (or repository)
    for one product image. Refused by name, with the manifest's value and the
    pin's value both in the report, through build and through sign."""
    manifest, value, set_pin = published
    set_pin("v0.10.0-beta.1", _pinned_images(value))
    pinned = value["images"]["web"][field]
    value["images"]["web"][field] = "sha256:" + "b" * 64 if field == "digest" else "registry.example.test/other-web"
    manifest.write_bytes(builder.canonical(value))
    if entry == "build":
        output = tmp_path / "installer.sh"
        argv = ["--manifest", manifest, "--output", output]
    else:
        output, argv = _sign_argv(manifest, tmp_path, keypair)
        output.write_bytes(b"an installer that must not be signed")
    status, err = _main(monkeypatch, capsys, *argv)
    assert status == 1
    assert "images.web: the manifest names" in err, err
    assert value["images"]["web"][field] in err and pinned in err, err
    if entry == "build":
        assert not output.exists()
    else:
        assert not (tmp_path / "descriptor.json").exists() and not (tmp_path / "signature.sig").exists()


@needs_helm
def test_a_published_build_at_the_pin_builds_signs_and_verifies(published, tmp_path, keypair, monkeypatch, capsys):
    """The binding must not refuse what it should accept: a manifest whose
    product images ARE the pinned ones goes through build, sign and verify,
    and the public release.json records the pinned product commit."""
    manifest, value, set_pin = published
    pin = set_pin("v0.10.0-beta.1", _pinned_images(value))
    output = tmp_path / "installer.sh"
    status, err = _main(monkeypatch, capsys, "--manifest", manifest, "--output", output)
    assert status == 0, err
    _, payload = output.read_bytes().split(b"\n__GSJ_PAYLOAD_BELOW__\n")
    with tarfile.open(fileobj=io.BytesIO(base64.decodebytes(payload)), mode="r:gz") as archive:
        public = json.loads(archive.extractfile("release.json").read())
    assert public["source"]["web_commit"] == pin["commit"]
    assert "qualification" not in public
    descriptor, signature = tmp_path / "descriptor.json", tmp_path / "signature.sig"
    status, err = _main(monkeypatch, capsys, "sign", "--manifest", manifest, "--installer", output, "--private-key", keypair[0],
                        "--descriptor", descriptor, "--signature", signature)
    assert status == 0, err
    assert json.loads(descriptor.read_text())["qualification"] is False
    status, err = _main(monkeypatch, capsys, "verify", "--installer", output, "--descriptor", descriptor,
                        "--signature", signature, "--public-key", keypair[1])
    assert status == 0, err


@needs_helm
@pytest.mark.parametrize("pin_state", ["empty", "other-images"])
def test_a_qualification_build_is_not_held_to_the_pin_images(release, tmp_path, monkeypatch, capsys, pin_state):
    """Qualification builds keep working: with an EMPTY pin (today's, before
    promotion) and with a pin whose images differ from the proof images the
    manifest names. Only the pinned CHART is read -- here a synthetic one --
    and a qualification build that names `_build.chart` reads no pin at all
    (the existing tests above prove that path against this repository's own
    pin)."""
    manifest, value = release
    value = copy.deepcopy(value)
    del value["_build"]["chart"]
    manifest.write_bytes(builder.canonical(value))
    chart = _pinned_chart(tmp_path / "pinned", value["version"])
    monkeypatch.setattr(builder.webpin, "archive", lambda path, destination, pin=None: chart)
    chart_sha256 = builder.sha(builder.normalized_chart(chart, value["version"]))
    images = {} if pin_state == "empty" else {role: {"repository": "registry.example.test/" + role.lower(), "digest": "sha256:" + "c" * 64}
                                             for role in builder.webpin.IMAGE_ROLES}
    pin = _pin("" if pin_state == "empty" else "v0.10.0-beta.1", images, chart_sha256)
    monkeypatch.setattr(builder.webpin, "load", lambda path=None: pin)
    clean = tmp_path / "clean-worktree"                # this repository's own Git state stays out of it
    clean.mkdir()
    subprocess.run(["git", "init", "-q", str(clean)], check=True)
    monkeypatch.setattr(builder, "ROOT", clean)
    output = tmp_path / "installer.sh"
    status, err = _main(monkeypatch, capsys, "--manifest", manifest, "--output", output)
    assert status == 0, err
    assert output.exists()


# --- Measured: a verifier that cannot run is not a forged release ----

def _verify_shell(output, descriptor, signature, public, *, env=None):
    shell = ["bash", str(ROOT / "ops/installer/verify-release.sh"), str(output), str(descriptor), str(signature), str(public)]
    return subprocess.run(shell, capture_output=True, text=True, env=env)


def _signed(release, tmp_path, keypair):
    manifest, _ = release
    output, descriptor, signature = (tmp_path / name for name in ("installer.sh", "descriptor.json", "signature.sig"))
    assert run("--manifest", manifest, "--output", output).returncode == 0
    assert run("sign", "--manifest", manifest, "--installer", output, "--private-key", keypair[0], "--descriptor", descriptor, "--signature", signature).returncode == 0
    return output, descriptor, signature


def test_a_missing_openssl_is_named_and_never_called_an_invalid_signature(release, tmp_path, keypair):
    """`openssl … || fail 'Descriptor signature is invalid.'` told a customer
    whose machine lacks openssl that the release was forged."""
    output, descriptor, signature = _signed(release, tmp_path, keypair)
    bare = tmp_path / "bare-bin"; bare.mkdir()
    for tool in ("bash", "sed", "cut", "printf", "sha256sum", "shasum"):
        found = shutil.which(tool)
        if found:
            (bare / tool).symlink_to(found)
    result = _verify_shell(output, descriptor, signature, keypair[1], env={"PATH": str(bare)})
    assert result.returncode == 1
    assert "Descriptor signature is invalid" not in result.stderr
    assert "openssl" in result.stderr


def test_an_unreadable_public_key_is_named_and_never_called_an_invalid_signature(release, tmp_path, keypair):
    output, descriptor, signature = _signed(release, tmp_path, keypair)
    bad = tmp_path / "not-a-key.pem"; bad.write_text("this is not a PEM public key\n")
    result = _verify_shell(output, descriptor, signature, bad)
    assert result.returncode == 1
    assert "Descriptor signature is invalid" not in result.stderr
    assert "public key" in result.stderr.lower()


def test_a_wrong_key_and_a_tampered_descriptor_are_still_refused(release, tmp_path, keypair):
    output, descriptor, signature = _signed(release, tmp_path, keypair)
    other = tmp_path / "other.pem"
    subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(tmp_path / "other-private.pem")], check=True, capture_output=True)
    subprocess.run(["openssl", "pkey", "-in", str(tmp_path / "other-private.pem"), "-pubout", "-out", str(other)], check=True, capture_output=True)
    result = _verify_shell(output, descriptor, signature, other)
    assert result.returncode == 1 and "Descriptor signature is invalid" in result.stderr
    descriptor.write_bytes(descriptor.read_bytes() + b"\n")
    result = _verify_shell(output, descriptor, signature, keypair[1])
    assert result.returncode == 1 and "Descriptor signature is invalid" in result.stderr
