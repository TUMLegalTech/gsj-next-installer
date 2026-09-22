"""Owned ACME setup and encrypted restore with synthetic keys; no ACME network."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import subprocess

import pytest

from tests.test_installer import runtime, _restore_fixture, _backup_fixture


@pytest.fixture(scope="module")
def synthetic_tls(tmp_path_factory):
    folder = tmp_path_factory.mktemp("acme-keys")
    key, cert = folder / "key.pem", folder / "cert.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:3072", "-nodes", "-days", "1",
                    "-subj", "/CN=legal.example", "-addext", "subjectAltName=DNS:legal.example",
                    "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True)
    return key.read_bytes(), cert.read_bytes()


def _site(site):
    site["target"].update(namespace="synthetic-namespace", release="synthetic-release")
    site["public_url"] = "https://legal.example"
    site["tls"].update(profile="managed-acme", issuer="legal-acme", email="operator@example.invalid",
                       acme_server="https://acme.invalid/directory", secret="synthetic-release-tls",
                       certificate_file="", private_key_file="", ca_file="")
    return site


def _configure(runtime):
    run, state, work = runtime
    site = _site(json.loads((work / "site.json").read_text()))
    (work / "site.json").write_text(json.dumps(site))
    state.write_text(json.dumps({"lease": None, "calls": [], "resources": {}}))
    return run, state, work


def _secret(name, key, cert=None, owner=""):
    data = {"tls.key": base64.b64encode(key).decode()}
    if cert is not None: data["tls.crt"] = base64.b64encode(cert).decode()
    return {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": name,
            "namespace": "synthetic-namespace", "labels": {"gsj.io/acme-owner": owner}},
            "type": "Opaque" if cert is None else "kubernetes.io/tls", "data": data}


def _writes(state):
    return [a for a in json.loads(state.read_text())["calls"] if a[0] in ("create", "apply", "replace", "delete")]


def test_fresh_acme_creates_owned_account_then_reuses_exact_key(runtime):
    run, state, work = _configure(runtime)
    result = run("managed_acme")
    assert result.returncode == 0, result.stderr
    resources = json.loads(state.read_text())["resources"]
    account = resources["Secret/legal-acme-account"]
    issuer = resources["Issuer/legal-acme"]
    certificate = resources["Certificate/synthetic-release-tls"]
    assert issuer["spec"]["acme"]["disableAccountKeyGeneration"] is True
    assert certificate["spec"]["privateKey"]["rotationPolicy"] == "Never"
    assert resources["ConfigMap/synthetic-release-acme-owner"]["immutable"] is True
    assert base64.b64decode(account["data"]["tls.key"]).startswith(b"-----BEGIN PRIVATE KEY-----")
    state.write_text(json.dumps({"lease": None, "calls": [], "resources": resources}))
    result = run("managed_acme")
    assert result.returncode == 0, result.stderr
    assert json.loads(state.read_text())["resources"]["Secret/legal-acme-account"] == account
    assert _writes(state) == []
    assert "PRIVATE KEY" not in result.stdout + result.stderr


def test_interrupted_fresh_key_creation_reuses_durable_staged_key(runtime):
    run, state, work = _configure(runtime)
    state.write_text(json.dumps({"lease": None, "calls": [], "resources": {}, "fail_create": "Secret/legal-acme-account"}))
    result = run("managed_acme")
    assert result.returncode == 31, result.stderr
    staged = list((work / "acme").glob("*-account.key"))
    assert len(staged) == 1
    original = staged[0].read_bytes()
    s = json.loads(state.read_text()); del s["fail_create"]; s["calls"] = []
    state.write_text(json.dumps(s))
    result = run("managed_acme")
    assert result.returncode == 0, result.stderr
    account = json.loads(state.read_text())["resources"]["Secret/legal-acme-account"]
    assert base64.b64decode(account["data"]["tls.key"]) == original
    assert not staged[0].exists()


@pytest.mark.parametrize("kind,name", [("Issuer", "legal-acme"), ("Certificate", "synthetic-release-tls"),
                                        ("Secret", "legal-acme-account"), ("Secret", "synthetic-release-tls")])
def test_foreign_acme_objects_refuse_before_any_write(runtime, kind, name):
    run, state, work = _configure(runtime)
    obj = {"kind": kind, "metadata": {"name": name}, "data": {"private": "foreign"}}
    state.write_text(json.dumps({"lease": None, "calls": [], "resources": {kind + "/" + name: obj}}))
    result = run("managed_acme")
    assert result.returncode != 0
    assert _writes(state) == []


@pytest.mark.parametrize("change", ["account-missing", "account-owner", "issuer-spec", "profile"])
def test_established_acme_never_resets_lost_or_changed_account(runtime, change):
    run, state, work = _configure(runtime)
    result = run("managed_acme")
    assert result.returncode == 0, result.stderr
    resources = json.loads(state.read_text())["resources"]
    if change == "account-missing": del resources["Secret/legal-acme-account"]
    elif change == "account-owner": resources["Secret/legal-acme-account"]["metadata"]["labels"] = {}
    elif change == "issuer-spec": resources["Issuer/legal-acme"]["spec"]["acme"]["server"] = "https://other.invalid"
    else:
        site = json.loads((work / "site.json").read_text()); site["tls"]["email"] = "changed@example.invalid"
        (work / "site.json").write_text(json.dumps(site))
    state.write_text(json.dumps({"lease": None, "calls": [], "resources": resources}))
    result = run("managed_acme")
    assert result.returncode != 0
    assert _writes(state) == []
    assert json.loads(state.read_text())["resources"] == resources


def _owned_bundle(run, work, site, uid, tls):
    (work / "source-acme-site.json").write_text(json.dumps(site))
    result = run(f'acme_documents "$TEST_WORK/source-acme-site.json" "{uid}" "$TEST_WORK/source-acme"')
    assert result.returncode == 0, result.stderr
    objects = [json.loads((work / ("source-acme-" + role + ".json")).read_text())
               for role in ("owner", "issuer", "certificate")]
    owner = objects[0]["metadata"]["labels"]["gsj.io/acme-owner"]
    objects[0]["data"]["account_key_sha256"] = hashlib.sha256(tls[0]).hexdigest()
    objects += [_secret("legal-acme-account", tls[0], owner=owner),
                _secret("synthetic-release-tls", *tls, owner=owner)]
    return objects


def test_backup_captures_only_exact_acme_account_and_config(runtime, synthetic_tls):
    run, state, work = runtime
    resources = _backup_fixture(state, work)
    installed = json.loads((work / "installed.json").read_text())
    _site(installed["site"]); installed["namespace_uid"] = "source-namespace-uid"
    (work / "installed.json").write_text(json.dumps(installed))
    objects = _owned_bundle(run, work, installed["site"], installed["namespace_uid"], synthetic_tls)
    for obj in objects: resources[obj["kind"] + "/" + obj["metadata"]["name"]] = obj
    resources["Secret/foreign-acme-account"] = _secret("foreign-acme-account", synthetic_tls[0], owner="foreign")
    state.write_text(json.dumps({"lease": None, "calls": [], "resources": resources}))
    result = run("backup_resources")
    assert result.returncode == 0, result.stderr
    bundle = json.loads((work / "cluster-private.json").read_text())
    saved = {o["kind"] + "/" + o["metadata"]["name"]: o for o in bundle["items"]}
    assert all(obj["kind"] + "/" + obj["metadata"]["name"] in saved for obj in objects)
    assert "Secret/foreign-acme-account" not in saved
    assert saved["Secret/legal-acme-account"]["data"] == objects[-2]["data"]
    assert "PRIVATE KEY" not in result.stdout + result.stderr


def _acme_restore(runtime, tmp_path, tls, damage=None):
    run, state, work = runtime
    saved = {}
    def transform(documents, target, work):
        site = _site(documents["installed.json"]["site"])
        _site(target)
        uid = documents["installed.json"]["namespace_uid"]
        objects = _owned_bundle(run, work, site, uid, tls)
        saved.update({o["kind"] + "/" + o["metadata"]["name"]: o for o in objects})
        items = documents["cluster-private.json"]["items"]
        items[:] = [o for o in items if o["kind"] + "/" + o["metadata"]["name"] not in saved] + objects
        documents["site_inputs.json"]["entries"][:] = [e for e in documents["site_inputs.json"]["entries"]
            if not e["name"].startswith("managed_tls.") and e["name"] not in ("tls.certificate_file", "tls.private_key_file", "tls.ca_file")]
        if damage == "missing-account": items[:] = [o for o in items if o["metadata"]["name"] != "legal-acme-account"]
        elif damage == "foreign-owner": saved["Issuer/legal-acme"]["metadata"]["labels"] = {}
        elif damage == "wrong-source":
            profile = json.loads(saved["ConfigMap/synthetic-release-acme-owner"]["data"]["identity.json"])
            profile["owner"]["namespace_uid"] = "foreign-source-uid"
            saved["ConfigMap/synthetic-release-acme-owner"]["data"]["identity.json"] = json.dumps(profile)
        elif damage == "account-key": saved["Secret/legal-acme-account"]["data"]["tls.key"] = base64.b64encode(b"bad private key").decode()
        elif damage == "key-binding": saved["ConfigMap/synthetic-release-acme-owner"]["data"]["account_key_sha256"] = "f" * 64
        elif damage == "solver": target["ingress"]["class"] = "different-controller"
        elif damage == "account-server": target["tls"]["acme_server"] = "https://other.invalid/directory"
    invoke, inputs = _restore_fixture(runtime, tmp_path, transform=transform)
    return invoke, saved


def test_restore_acme_keeps_credential_bytes_and_rebinds_only_owner(runtime, tmp_path, synthetic_tls):
    invoke, saved = _acme_restore(runtime, tmp_path, synthetic_tls)
    run, state, work = runtime
    result = invoke()
    assert result.returncode == 0, result.stderr
    resources = json.loads(state.read_text())["resources"]
    for name in ("legal-acme-account", "synthetic-release-tls"):
        assert resources["Secret/" + name]["data"] == saved["Secret/" + name]["data"]
    owner = resources["ConfigMap/synthetic-release-acme-owner"]
    assert json.loads(owner["data"]["identity.json"])["owner"]["namespace_uid"] == "target-namespace-uid"
    # The restore harness skips controller deployment. Run the actual ACME
    # reconstruction against those restored Secrets and prove no resets.
    result = run('SITE="$TEST_WORK/target-site.json"\nmanaged_acme')
    assert result.returncode == 0, result.stderr
    actual = json.loads(state.read_text())["resources"]
    assert actual["Secret/legal-acme-account"] == resources["Secret/legal-acme-account"]
    assert actual["Secret/synthetic-release-tls"] == resources["Secret/synthetic-release-tls"]
    assert actual["Issuer/legal-acme"]["spec"] == saved["Issuer/legal-acme"]["spec"]
    assert "PRIVATE KEY" not in result.stdout + result.stderr


@pytest.mark.parametrize("damage", ["missing-account", "foreign-owner", "wrong-source", "account-key", "key-binding", "solver", "account-server"])
def test_acme_restore_refuses_unproven_source_before_mutation(runtime, tmp_path, synthetic_tls, damage):
    invoke, saved = _acme_restore(runtime, tmp_path, synthetic_tls, damage)
    result = invoke()
    assert result.returncode != 0
    assert _writes(runtime[1]) == []
    assert not (runtime[2] / "restoration.json").exists()


def test_restore_acme_refuses_existing_target_account_without_overwrite(runtime, tmp_path, synthetic_tls):
    invoke, saved = _acme_restore(runtime, tmp_path, synthetic_tls)
    state = runtime[1]
    foreign = _secret("legal-acme-account", synthetic_tls[0], owner="foreign-target")
    s = json.loads(state.read_text()); s["resources"]["Secret/legal-acme-account"] = foreign
    state.write_text(json.dumps(s))
    result = invoke()
    assert result.returncode != 0
    assert _writes(state) == []
    assert json.loads(state.read_text())["resources"]["Secret/legal-acme-account"] == foreign


def test_restored_owner_with_lost_key_never_registers_replacement(runtime, tmp_path, synthetic_tls):
    invoke, saved = _acme_restore(runtime, tmp_path, synthetic_tls)
    run, state, work = runtime
    result = invoke()
    assert result.returncode == 0, result.stderr
    s = json.loads(state.read_text()); del s["resources"]["Secret/legal-acme-account"]; s["calls"] = []
    state.write_text(json.dumps(s))
    result = run('SITE="$TEST_WORK/target-site.json"\nmanaged_acme')
    assert result.returncode != 0
    assert _writes(state) == []
    assert not (work / "acme").exists()
