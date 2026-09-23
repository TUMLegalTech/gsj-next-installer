"""Fail-closed release intake, artifact binding and ordinary verifier gates."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
from types import SimpleNamespace

import pytest

from tests.pinned_web import needs_web

ROOT = Path(__file__).resolve().parents[1]
CI = ROOT / "ops/installer/ci"


@pytest.fixture
def modules(monkeypatch):
    monkeypatch.syspath_prepend(str(CI))
    values = []
    for name in ("release", "qualify"):
        spec = importlib.util.spec_from_file_location(name, CI / (name + ".py"))
        module = importlib.util.module_from_spec(spec)
        monkeypatch.setitem(sys.modules, name, module)
        spec.loader.exec_module(module)
        values.append(module)
    return values


@pytest.mark.parametrize("url", ["http://example.test/data", "https://key@example.test/data", "https://example.test/data#fragment"])
def test_release_intake_requires_final_credential_free_https(modules, tmp_path, url):
    with pytest.raises(ValueError):
        modules[0].download({"url": url, "sha256": "a" * 64}, tmp_path / "file", "secret")


def test_authenticated_download_cannot_enable_public_redirects(modules, tmp_path):
    with pytest.raises(ValueError, match="authenticated"):
        modules[0].download({"url": "https://example.test/file", "sha256": "a" * 64},
                            tmp_path / "file", "secret", allow_public_redirects=True)


def test_public_client_redirect_cannot_downgrade_https(modules):
    handler = modules[0].PublicHttpsRedirect()
    with pytest.raises(ValueError, match="HTTPS"):
        handler.redirect_request(None, None, 302, "", {}, "http://example.test/file")


def test_clients_extracts_helm_from_its_archive_and_pins_it_read_only(modules, tmp_path, monkeypatch):
    """`clients` is what the test workflow and the release preparation install
    Helm with; it reads the catalog, downloads by hash and unpacks the one
    executable. FALSIFY: drop the tarfile import -> NameError here."""
    import tarfile, io
    module = modules[0]
    def fake_download(item, target, token="", *, allow_public_redirects=False):
        assert allow_public_redirects and not token and item["url"].startswith("https://")
        with tarfile.open(target, "w:gz") as tar:
            data = b"#!/bin/sh\necho helm\n"
            member = tarfile.TarInfo("linux-amd64/helm"); member.size = len(data); member.mode = 0o755
            tar.addfile(member, io.BytesIO(data))
    monkeypatch.setattr(module, "download", fake_download)
    module.clients(tmp_path / "clients", ("helm",))
    helm = tmp_path / "clients" / "helm"
    assert helm.read_bytes() == b"#!/bin/sh\necho helm\n" and oct(helm.stat().st_mode & 0o777) == "0o500"
    assert not (tmp_path / "clients" / "helm.download").exists()


def test_unapproved_inputs_cannot_start_any_download(modules, tmp_path, monkeypatch):
    monkeypatch.delenv("GSJ_RELEASE_MANIFEST_URL", raising=False)
    monkeypatch.setattr(modules[0], "download", lambda *a, **k: pytest.fail("unapproved input was downloaded"))
    with pytest.raises(ValueError, match="approved release inputs"):
        modules[0].inputs(tmp_path / "out")


def test_a_release_build_refuses_a_pin_without_a_product_release(modules, tmp_path, monkeypatch):
    """The installer builds against the PINNED product release's published
    image digests. Until promotion fills web-pin.json `release` and `images`,
    a build is refused before any registry, Git or Docker call."""
    (tmp_path / "inputs.json").write_text("{}")
    pin = dict(modules[0].webpin.load())
    pin.update(release="", images={})
    monkeypatch.setattr(modules[0].webpin, "load", lambda path=None: pin)
    monkeypatch.setattr(modules[0], "run", lambda *a, **k: pytest.fail("nothing may run before the pin is checked"))
    monkeypatch.setattr(modules[0], "inspect_image", lambda *a, **k: pytest.fail("no registry call before the pin is checked"))
    with pytest.raises(ValueError, match="names no product release"):
        modules[0].build(tmp_path)


def test_the_preparation_reports_its_own_refusal_in_words_and_a_transport_error_by_type_only(modules, tmp_path, monkeypatch, capsys):
    """`main` used to print only the exception's type, hiding the sentence a
    refusal carries (the pin's). Its own refusals are `Refused`, fixed
    sentences with no URL: they are printed. Anything else -- a transport
    error, a library ValueError quoting a header or a URL -- stays a bare
    type name."""
    module = modules[0]
    (tmp_path / "inputs.json").write_text("{}")
    pin = dict(module.webpin.load())
    pin.update(release="", images={})
    monkeypatch.setattr(module.webpin, "load", lambda path=None: pin)
    monkeypatch.setattr(sys, "argv", ["release.py", "build", "--output", str(tmp_path)])
    with pytest.raises(SystemExit) as stopped:
        module.main()
    assert stopped.value.code == 1
    assert "Release preparation failed: web-pin.json names no product release yet" in capsys.readouterr().err
    import urllib.error
    monkeypatch.setattr(module, "build", lambda destination: (_ for _ in ()).throw(urllib.error.URLError("https://token@origin.example/signed")))
    with pytest.raises(SystemExit):
        module.main()
    err = capsys.readouterr().err
    assert err.strip() == "Release preparation failed: URLError" and "token@" not in err
    monkeypatch.setattr(module, "inputs", lambda destination: (_ for _ in ()).throw(ValueError("Invalid header value b'Bearer s3cr3t\\r'")))
    monkeypatch.setattr(sys, "argv", ["release.py", "inputs", "--output", str(tmp_path / "inputs")])
    with pytest.raises(SystemExit):
        module.main()
    err = capsys.readouterr().err
    assert err.strip() == "Release preparation failed: ValueError" and "s3cr3t" not in err


def test_a_digest_mismatch_names_the_image_and_both_digests_through_the_cli(modules, tmp_path, monkeypatch, capsys):
    """The registry serves a digest other than the approved one: the refusal
    names the image, the digest the registry serves and the approved one, and
    the CLI prints that sentence -- it is the refusal whose values the
    maintainer most needs."""
    module = modules[0]
    served, approved = "sha256:" + "1" * 64, "sha256:" + "2" * 64
    monkeypatch.setattr(module, "run", lambda *args, **kwargs: served + "\n")
    with pytest.raises(module.Refused) as refused:
        module.inspect_image("registry.example/gsj-web@" + approved)
    sentence = str(refused.value)
    assert "registry.example/gsj-web" in sentence and served in sentence and approved in sentence, sentence
    monkeypatch.setattr(module, "build", lambda destination: module.inspect_image("registry.example/gsj-web@" + approved))
    monkeypatch.setattr(sys, "argv", ["release.py", "build", "--output", str(tmp_path)])
    with pytest.raises(SystemExit) as stopped:
        module.main()
    assert stopped.value.code == 1
    err = capsys.readouterr().err
    assert "Release preparation failed: remote image differs from its approved digest: registry.example/gsj-web is " + served in err and approved in err, err


def installed_state(module):
    manifest = {"identity": "target-identity", "images": {"web": "fixed"}, "corpus": {"fingerprint": "a" * 64}}
    report = {"status": "passed", "cleanup_users": "passed", "case_and_pat_cleanup": "passed",
              "expected_corpus_fingerprint": "a" * 64,
              "checks": [{"name": name, "status": "passed"} for name in module.expected_checks()]}
    state = {"status": "complete", "manifest": manifest,
             "verification": {"application": report, "public": {"status": "passed", "tls_verified": True}, "network": {"status": "passed"}}}
    return state, copy.deepcopy(manifest)


def test_fixture_preservation_records_unreachable_gc_without_ignoring_durable_state(modules):
    module = modules[1]
    before = {"contract": "gsj.upgrade-fixture/2", "coverage": module.UPGRADE_FIXTURE_COVERAGE,
              "repository": {"refs_sha256": "a" * 64, "reachable_sha256": "b" * 64},
              "diagnostics": {"unreachable_count": 2}}
    after = copy.deepcopy(before)
    after["diagnostics"] = {"unreachable_count": 0}
    report = {}
    module.fixture_preservation(before, after, "upgrade", report)
    record = report["fixture_preservation"][0]
    assert record["stage"] == "upgrade" and len(record["preserved_sha256"]) == 64
    assert record["diagnostics"] == {"unreachable_count": 0}
    assert before["diagnostics"]["unreachable_count"] == 2


@pytest.mark.parametrize("fault", ["refs", "reachable", "missing", "nested-diagnostics", "coverage"])
def test_fixture_preservation_fails_on_reachable_history_or_contract_drift(modules, fault):
    module = modules[1]
    before = {"contract": "gsj.upgrade-fixture/2", "coverage": module.UPGRADE_FIXTURE_COVERAGE,
              "repository": {"refs": "a", "reachable": "b", "diagnostics": "durable"}}
    after = copy.deepcopy(before)
    if fault in ("refs", "reachable"):
        after["repository"][fault] = "changed"
    elif fault == "missing":
        after.pop("repository")
    elif fault == "nested-diagnostics":
        after["repository"]["diagnostics"] = "changed"
    else:
        after["coverage"] = []
    report = {}
    with pytest.raises(ValueError):
        module.fixture_preservation(before, after, "upgrade", report)
    assert not report


@needs_web
@pytest.mark.parametrize("failure", ["missing", "skipped", "cleanup", "corpus", "tls", "images"])
def test_ordinary_gate_requires_every_real_contract(modules, failure):
    module = modules[1]
    state, manifest = installed_state(module)
    module.check_application(state, manifest)
    if failure == "missing": state["verification"]["application"]["checks"].pop()
    elif failure == "skipped": state["verification"]["application"]["checks"][0]["status"] = "skipped"
    elif failure == "cleanup": state["verification"]["application"]["cleanup_users"] = "pending"
    elif failure == "corpus": state["verification"]["application"]["expected_corpus_fingerprint"] = "b" * 64
    elif failure == "tls": state["verification"]["public"]["tls_verified"] = False
    elif failure == "images": state["manifest"]["images"]["web"] = "different"
    with pytest.raises(ValueError):
        module.check_application(state, manifest)


def qualified_hardfault(images):
    import hardfault
    uid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    nsuid = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
    namespace = "gsj-qualification-fixture"
    nonce = "a" * 20
    _, pod = hardfault.helper_resources(namespace, nsuid, "qualified-node",
        images["web"]["repository"] + "@" + images["web"]["digest"], [], nonce)
    targets = [{"name": name, "container_id": char * 64,
                "image": images[role]["repository"] + "@" + images[role]["digest"], "restart_count": 0}
               for name, role, char in (("agent-runner", "runner", "a"), ("gsj-mcp", "mcp", "c"), ("gsj-web", "web", "b"))]
    created = [{"kind": kind, "name": "gsj-hardfault-" + nonce, "uid": value}
               for kind, value in (("NetworkPolicy", "cccccccc-dddd-eeee-ffff-aaaaaaaaaaaa"),
                                   ("Pod", "dddddddd-eeee-ffff-aaaa-bbbbbbbbbbbb"))]
    return {"schema": "gsj.hardfault/1", "status": "passed", "namespace": namespace,
            "namespace_uid": nsuid, "pod_uid": uid, "node": "qualified-node", "admission_dry_run": "passed",
            "helper_cleanup": "exact-uid-observed-absent", "policy_cleanup": "exact-uid-observed-absent",
            "target_plan": {"schema": "gsj.hardfault-process/1", "pod_uid": uid, "targets": targets},
            "process": {"schema": "gsj.hardfault-process-result/1", "status": "passed", "pod_uid": uid,
                        "ancestor_namespace": True, "targets": [{"name": t["name"], "container_id": t["container_id"],
                        "pod_uid": uid, "pid": 100 + i, "namespace_pids": [100 + i, 1], "start_ticks": 10000 + i,
                        "signal_sent": "SIGKILL", "pidfd_exit_observed": True} for i, t in enumerate(targets)]},
            "created": created, "admitted_helper": {"uid": created[1]["uid"], "name": created[1]["name"],
                "namespace_uid": nsuid, "projection": hardfault.helper_projection(pod)},
            "process_helper_sha256": hashlib.sha256(Path(hardfault.__file__).with_name("hardfault_process.py").read_bytes()).hexdigest()}


def qualified_files(module, tmp_path, monkeypatch):
    images = {role: {"repository": "example.test/" + role, "digest": "sha256:" + "a" * 64} for role in ("web", "runner", "mcp", "forgejo", "chroma", "decisionsData")}
    manifest = {"identity": "target", "images": images, "supported_sources": ["source"]}
    data = json.dumps(manifest, sort_keys=True, indent=2) + "\n"
    (tmp_path / "manifest.json").write_text(data)
    (tmp_path / "image-inventory.json").write_text(json.dumps({"images": images, "all_remote_manifests_verified": True}))
    descriptor = {"qualification": False, "releaseId": "target", "version": "1.1.0", "manifestSha256": hashlib.sha256(data.encode()).hexdigest(),
                  "installer": {"sha256": "c" * 64}}
    staged = staged_release()
    (tmp_path / "staging.json").write_text(json.dumps(staged))
    monkeypatch.setattr(module, "bundle", lambda path: descriptor)
    reports = []
    for mode, names in {"ordinary": ["fresh-full-corpus-install", "same-bundle-repeat"],
                        "upgrade": ["populated-source-created", "full-populated-source-to-target-upgrade", "source-backup-and-preservation",
                                    "selected-version-repeat-converges", "hard-restart-cookie-and-attempt", "fresh-restore-to-target-acceptance"]}.items():
        report = {"schema": "gsj.installer-qualification/1", "mode": mode, "status": "passed", "disposable_target_cleanup": "passed",
                  "release_identity": "target", "installer_sha256": "c" * 64,
                  "checks": [{"name": name, "status": "passed"} for name in names]}
        if mode == "upgrade":
            fault = qualified_hardfault(images)
            report["restart"] = {"pod_uid": fault["pod_uid"], "attempt_id": "c" * 32,
                                 "cookie_invalidated": True, "interrupted_attempt_disclosed": True, "fault": fault,
                                 "exit_codes": {"agent-runner": 137, "gsj-mcp": 137, "gsj-web": 137}}
            report["upgrade_source"] = {"release_identity": "source", "version": "1.0.0",
                                        "installer_sha256": "b" * 64, "requested_target_version": "1.1.0",
                                        "entrypoint": "source-installer upgrade --to VERSION"}
            report["populated_fixture"] = {"contract": "gsj.upgrade-fixture/2",
                                           "coverage": module.UPGRADE_FIXTURE_COVERAGE,
                                           "snapshot_sha256": "e" * 64}
            report["release_readback"] = {profile: readback_receipt(staged, profile)
                                           for profile in ("upgrade", "restore")}
        path = tmp_path / (mode + ".json")
        path.write_text(json.dumps(report))
        reports.append(path)
    return descriptor, reports


@pytest.mark.parametrize("fault", ["missing", "no-death", "wrong-image", "wrong-pod", "wrong-count", "cleanup", "admission", "privilege", "helper-hash", "missing-pod", "non-string-pod",
                                   "mcp-missing", "mcp-exit", "exit-missing"])
def test_release_gate_requires_actual_exact_hardfault_receipt(modules, tmp_path, monkeypatch, fault):
    module = modules[1]
    _, reports = qualified_files(module, tmp_path, monkeypatch)
    value = json.loads(reports[1].read_bytes()); proof = value["restart"]["fault"]
    if fault == "missing": value["restart"].pop("fault")
    elif fault == "mcp-missing":
        for key in ("target_plan", "process"):
            proof[key]["targets"] = [t for t in proof[key]["targets"] if t["name"] != "gsj-mcp"]
    elif fault == "mcp-exit": value["restart"]["exit_codes"]["gsj-mcp"] = 143
    elif fault == "exit-missing": value["restart"].pop("exit_codes")
    elif fault == "no-death": proof["process"]["targets"][0]["pidfd_exit_observed"] = False
    elif fault == "wrong-image": proof["target_plan"]["targets"][0]["image"] = "different"
    elif fault == "wrong-pod": proof["process"]["pod_uid"] = "ffffffff-ffff-ffff-ffff-ffffffffffff"
    elif fault == "wrong-count": proof["process"]["targets"].pop()
    elif fault == "cleanup": proof["helper_cleanup"] = "delete-requested"
    elif fault == "admission": proof["admission_dry_run"] = "unverified"
    elif fault == "privilege": proof["admitted_helper"]["projection"]["container"]["securityContext"]["privileged"] = True
    elif fault == "helper-hash": proof["process_helper_sha256"] = "f" * 64
    elif fault == "missing-pod": value["restart"].pop("pod_uid")
    elif fault == "non-string-pod": value["restart"]["pod_uid"] = 123
    reports[1].write_text(json.dumps(value))
    with pytest.raises(ValueError): module.gate(tmp_path, reports)


def staged_release():
    return {"schema": "gsj.release-staging/1", "status": "passed", "operation": "stage",
            "transport": "direct-https",
            "source_identity": "source", "source_version": "1.0.0", "target_identity": "target",
            "target_version": "1.1.0", "source_installer_sha256": "b" * 64,
            "target_installer_sha256": "c" * 64, "target_manifest_sha256": "d" * 64,
            "trust_sha256": "e" * 64, "base_url": "https://releases.example.test/gsj",
            "version_url": "https://releases.example.test/gsj/1.1.0",
            "read_profiles": ["restore", "upgrade"], "descriptor_published_last": True,
            "descriptor_commit_policy": "after-payload-readback",
            "origin_atomic_conditional_put": "required-service-guarantee",
            "files": {name: {"sha256": "f" * 64, "bytes": 123, "outcome": "created"}
                      for name in ("gsj-install.sh", "installer-descriptor.sig", "installer-descriptor.json")}}


def readback_receipt(staged, profile):
    receipt = copy.deepcopy(staged)
    receipt.update(operation="readback", read_profiles=[profile], descriptor_published_last=None)
    for value in receipt["files"].values():
        value["outcome"] = "identical-existing"
    return receipt


@pytest.mark.parametrize("profile", ["upgrade", "restore"])
def test_qualification_delivery_preflight_uses_real_site_before_returning_receipt(modules, tmp_path, monkeypatch, profile):
    module = modules[1]
    source, target = tmp_path / "baseline", tmp_path / "candidate"
    target.mkdir()
    site = tmp_path / profile / "site.json"
    staged = staged_release()
    (target / "staging.json").write_text(json.dumps(staged))
    receipt = readback_receipt(staged, profile)
    calls = []
    def execute(*args):
        calls.append(args)
        assert args[:-1] == (sys.executable, "-B", CI / "stage.py", "--read-only",
                            "--source", source, "--target", target, "--config", site, "--report")
        args[-1].write_text(json.dumps(receipt))
    monkeypatch.setattr(module, "run", execute)
    assert module.release_readback(source, target, site, profile) == receipt
    assert len(calls) == 1 and not calls[0][-1].exists()


def test_failed_delivery_preflight_prevents_source_install_or_cluster_mutation(modules, tmp_path, monkeypatch):
    module = modules[1]
    target = tmp_path / "candidate"
    target.mkdir()
    manifest = {"identity": "target", "supported_sources": ["source"],
                "corpus": {"fingerprint": "f" * 64, "rows": 3, "chunks": 3}}
    (target / "manifest.json").write_text(json.dumps(manifest))
    (target / "gsj-install.sh").write_text("must not execute")
    site = tmp_path / "upgrade/site.json"
    site.parent.mkdir()
    site.write_text(json.dumps({"target": {"context": "disposable", "namespace": "gsj-qualification-test", "release": "gsj"}}))
    site.chmod(0o600)
    descriptors = {target: {"releaseId": "target", "version": "1.1.0", "installer": {"sha256": "a" * 64}},
                   target / "baseline": {"releaseId": "source", "version": "1.0.0", "installer": {"sha256": "b" * 64}}}
    monkeypatch.setattr(module, "bundle", lambda path: descriptors[path])
    monkeypatch.setattr(module, "expected_checks", lambda: {"synthetic-check"})   # the environment's concern, tested on its own
    def unavailable(*args):
        raise ValueError("delivery readback unavailable")
    monkeypatch.setattr(module, "release_readback", unavailable)
    calls = []
    def read_only(*args, **kwargs):
        calls.append(args)
        assert args == ("kubectl", "--context", "disposable", "--namespace", "gsj-qualification-test",
                        "get", "namespace", "gsj-qualification-test", "-o", "json", "--ignore-not-found")
        return ""
    monkeypatch.setattr(module, "run", read_only)
    report = tmp_path / "report.json"
    with pytest.raises(ValueError, match="qualification did not pass"):
        module.qualify(SimpleNamespace(bundle=target, config=site, report=report, mode="upgrade", disposable_target=True))
    assert len(calls) == 1
    assert json.loads(report.read_bytes())["status"] == "failed"


@pytest.mark.parametrize("failure", [RuntimeError, KeyboardInterrupt])
def test_populated_fixture_uses_ca_materialized_by_source_installer(modules, tmp_path, monkeypatch, failure):
    import base64
    module = modules[1]
    monkeypatch.setattr(module, "expected_checks", lambda: {"synthetic-check"})   # the harness environment's concern, tested on its own
    target = tmp_path / "candidate"
    target.mkdir()
    (target / "manifest.json").write_text(json.dumps({"identity": "target", "supported_sources": ["source"],
        "corpus": {"fingerprint": "f" * 64, "rows": 3, "chunks": 3}}))
    (target / "gsj-install.sh").write_text("synthetic candidate")
    site = tmp_path / "upgrade/site.json"
    site.parent.mkdir()
    password = site.parent / "password"
    password.write_text("synthetic-fixture-password")
    ca = site.parent / "generated-ca.pem"
    ca.write_bytes(b"synthetic generated public CA bytes")
    config = {"target": {"context": "disposable", "namespace": "gsj-qualification-test", "release": "gsj"},
              "public_url": "https://application.example", "operator": {"login": "operator", "password_file": str(password)},
              "deadlines": {"verification_seconds": 60}, "llm": {"base_url": "https://model.example/v1", "model": "synthetic"},
              "verification": {"ca_file": ""}}
    site.write_text(json.dumps(config)); site.chmod(0o600)
    descriptors = {target: {"releaseId": "target", "version": "1.1.0", "installer": {"sha256": "a" * 64}},
                   target / "baseline": {"releaseId": "source", "version": "1.0.0", "installer": {"sha256": "b" * 64}}}
    monkeypatch.setattr(module, "bundle", lambda path: descriptors[path])
    monkeypatch.setattr(module, "release_readback", lambda *args: {})
    namespace_reads = 0
    captured = []
    cleaned = []
    def execute(*args, **kwargs):
        nonlocal namespace_reads
        if args[0] == "bash":
            # Actual managed-local-ca behavior rewrites the saved site on install.
            config["verification"]["ca_file"] = str(ca)
            site.write_text(json.dumps(config))
            return ""
        tail = args[5:]
        if tail[:2] == ("get", "namespace"):
            namespace_reads += 1
            return "" if namespace_reads == 1 else json.dumps({"metadata": {"uid": "owned"}})
        if tail[:2] == ("get", "configmap"):
            return json.dumps({"data": {"installed.json": json.dumps({"status": "complete", "manifest": {"identity": "source"}})}})
        if tail[:2] == ("get", "pods"):
            return json.dumps({"items": [{"metadata": {"name": "source-pod"}, "status": {"phase": "Running"}}]})
        if tail[0] == "exec":
            code = kwargs["input"]
            assert base64.b64encode(ca.read_bytes()).decode() in code
            assert "'ca_file': '/tmp/gsj-qualification-" in code
            captured.append(True)
            raise failure("synthetic-sensitive-exception-must-not-be-reported")
        pytest.fail("unexpected command")
    monkeypatch.setattr(module, "run", execute)
    monkeypatch.setattr(module, "delete_owned_namespace", lambda *args: cleaned.append(args))
    with pytest.raises(ValueError, match="qualification did not pass"):
        module.qualify(SimpleNamespace(bundle=target, config=site, report=tmp_path / "report.json", mode="upgrade", disposable_target=True))
    assert captured == [True]
    assert cleaned == [("disposable", "gsj-qualification-test", "owned")]
    report = json.loads((tmp_path / "report.json").read_bytes())
    assert report["status"] == ("interrupted" if failure is KeyboardInterrupt else "failed")
    assert report["failure_phase"] == "populated-fixture-create"
    assert report["error_type"] == failure.__name__
    assert report["disposable_target_cleanup"] == "passed"
    assert "synthetic-sensitive-exception" not in json.dumps(report)


@pytest.mark.parametrize("number", [signal.SIGINT, signal.SIGTERM])
def test_cancellation_signal_saves_interruption_before_owned_cleanup(modules, tmp_path, monkeypatch, number):
    module = modules[1]
    monkeypatch.setattr(module, "expected_checks", lambda: {"synthetic-check"})   # the harness environment's concern, tested on its own
    target = tmp_path / "candidate"
    target.mkdir()
    (target / "manifest.json").write_text(json.dumps({"identity": "target",
        "corpus": {"fingerprint": "f" * 64, "rows": 3, "chunks": 3}}))
    (target / "gsj-install.sh").write_text("synthetic candidate")
    site = tmp_path / "ordinary/site.json"
    site.parent.mkdir()
    site.write_text(json.dumps({"target": {"context": "disposable", "namespace": "gsj-qualification-test", "release": "gsj"}}))
    site.chmod(0o600)
    monkeypatch.setattr(module, "bundle", lambda path: {"releaseId": "target"})
    report = tmp_path / "report.json"
    namespace_reads, seen, unwinding = 0, [], []
    def cancel(number):
        # A missing handler must fail this test, not terminate the pytest process.
        assert signal.getsignal(number) not in (signal.SIG_DFL, signal.default_int_handler)
        os.kill(os.getpid(), number)
    def execute(*args, **kwargs):
        nonlocal namespace_reads
        if args[0] == "bash": return ""
        if args[5:7] == ("get", "namespace"):
            namespace_reads += 1
            return "" if namespace_reads == 1 else json.dumps({"metadata": {"uid": "owned"}})
        assert args[5:7] == ("get", "configmap")
        try:
            cancel(number)  # the operator cancels a long installer phase
        finally:
            # An inner cleanup (the hardfault helper's) can run long while unwinding.
            unwinding.append(json.loads(report.read_bytes()))
        pytest.fail("the cancellation signal did not unwind the running qualification")
    def cleanup(*owned):
        seen.append((owned, json.loads(report.read_bytes())))
        cancel(signal.SIGTERM)  # a follow-up cancellation signal must not abort cleanup
    monkeypatch.setattr(module, "run", execute)
    monkeypatch.setattr(module, "delete_owned_namespace", cleanup)
    handlers = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}
    with pytest.raises(ValueError, match="qualification did not pass"):
        module.qualify(SimpleNamespace(bundle=target, config=site, report=report, mode="ordinary", disposable_target=True))
    assert {number: signal.getsignal(number) for number in handlers} == handlers
    # The handler itself persisted the interruption before any unwinding ran.
    [early] = unwinding
    assert early["status"] == "interrupted" and early["failure_phase"] == early["phase"] == "ordinary-install"
    assert early["signal"] == signal.Signals(number).name
    [(owned, saved)] = seen
    assert owned == ("disposable", "gsj-qualification-test", "owned")
    # Persisted before the slow namespace wait that a SIGKILL can cut short.
    assert saved["status"] == "interrupted" and saved["failure_phase"] == "ordinary-install"
    assert saved["signal"] == signal.Signals(number).name and saved["disposable_target_cleanup"] == "in-progress"
    final = json.loads(report.read_bytes())
    assert final["status"] == "interrupted" and final["disposable_target_cleanup"] == "passed"
    assert final["signal"] == "SIGTERM"


@pytest.mark.parametrize("fault", [None, "mcp-not-restarted", "mcp-other-exit", "mcp-later-crash"])
def test_populated_hard_restart_kills_web_runner_and_mcp_with_proven_sigkill(modules, tmp_path, monkeypatch, fault):
    import httpx
    import hardfault
    module = modules[1]
    monkeypatch.setattr(module, "expected_checks", lambda: {"synthetic-check"})   # the harness environment's concern, tested on its own
    images = {role: {"repository": "example.test/" + role, "digest": "sha256:" + "a" * 64}
              for role in ("web", "runner", "mcp", "forgejo", "chroma", "decisionsData")}
    target = tmp_path / "candidate"
    (target / "baseline").mkdir(parents=True)
    (target / "manifest.json").write_text(json.dumps({"identity": "target", "supported_sources": ["source"],
        "images": images, "corpus": {"fingerprint": "f" * 64, "rows": 3, "chunks": 3}}))
    (target / "gsj-install.sh").write_text("synthetic candidate")
    site = tmp_path / "upgrade/site.json"
    site.parent.mkdir()
    (site.parent / "password").write_text("synthetic-fixture-password")
    backups = tmp_path / "backups"
    backups.mkdir()
    # The restore archive is absent, so the run ends right after the restart checks.
    (backups / "source.tar.gz.enc.json").write_text(json.dumps({"format": "gsj.backup/1", "verified": True,
        "release_identity": "source", "operation": "synthetic-operation", "archive": str(tmp_path / "absent")}))
    site.write_text(json.dumps({"target": {"context": "disposable", "namespace": "gsj-qualification-test", "release": "gsj"},
        "public_url": "https://application.example", "backup": {"directory": str(backups)},
        "operator": {"login": "operator", "password_file": str(site.parent / "password")},
        "deadlines": {"verification_seconds": 0}, "llm": {"base_url": "https://model.example/v1", "model": "synthetic"},
        "verification": {"ca_file": ""}}))
    site.chmod(0o600)
    descriptors = {target: {"releaseId": "target", "version": "1.1.0", "installer": {"sha256": "a" * 64}},
                   target / "baseline": {"releaseId": "source", "version": "1.0.0", "installer": {"sha256": "b" * 64}}}
    monkeypatch.setattr(module, "bundle", lambda path: descriptors[path])
    monkeypatch.setattr(module, "release_readback", lambda *args: {})
    monkeypatch.setattr(module, "check_application", lambda *args: None)
    monkeypatch.setattr(module, "delete_owned_namespace", lambda *args: None)
    ids = {"agent-runner": "a" * 64, "gsj-mcp": "c" * 64, "gsj-web": "b" * 64}
    state = {"killed": False, "session": False, "namespace_reads": 0}

    def application_pod():
        statuses = []
        for name, cid in ids.items():
            status = {"name": name, "ready": True, "restartCount": 0, "containerID": "containerd://" + cid,
                      "state": {"running": {"startedAt": "2026-09-14T00:00:00Z"}}}
            if state["killed"] and not (name == "gsj-mcp" and fault == "mcp-not-restarted"):
                ended = {"exitCode": 143 if name == "gsj-mcp" and fault == "mcp-other-exit" else 137,
                         "containerID": "containerd://" + ("d" * 64 if name == "gsj-mcp" and fault == "mcp-later-crash" else cid)}
                status.update(restartCount=1, containerID="containerd://" + "e" * 64, lastState={"terminated": ended})
            statuses.append(status)
        return {"metadata": {"uid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "name": "application"},
                "spec": {"containers": [{"name": name, "image": images[role]["repository"] + "@" + images[role]["digest"]}
                                        for name, role in hardfault.TARGETS.items()]},
                "status": {"containerStatuses": statuses}}

    def execute(*args, **kwargs):
        if args[0] == "bash": return ""
        command = args[5:]
        if command[:2] == ("get", "namespace"):
            state["namespace_reads"] += 1
            return "" if state["namespace_reads"] == 1 else json.dumps({"metadata": {"uid": "owned"}})
        if command[:2] == ("get", "configmap"):
            return json.dumps({"data": {"installed.json": json.dumps({"status": "complete", "manifest": {"identity": "source"},
                "storage": {}, "namespace_uid": "owned", "site": {}, "operation": "synthetic-operation"})}})
        if command[:2] == ("get", "secrets"): return json.dumps({"items": []})
        if command[:2] == ("get", "pods"):
            return json.dumps({"items": [{"metadata": {"name": "application"}, "status": {"phase": "Running"}}]})
        if command[:2] == ("get", "pod"): return json.dumps(application_pod())
        assert command[0] == "exec"
        if "ACTION='start-interrupted'" in kwargs["input"] or "ACTION='read-interrupted'" in kwargs["input"]:
            return json.dumps({"case_id": "a" * 12, "attempt_id": "f" * 32})
        return json.dumps({"contract": "gsj.upgrade-fixture/2", "coverage": module.UPGRADE_FIXTURE_COVERAGE})

    injected = []
    def inject(**kwargs):
        injected.append(hardfault.target_plan(kwargs["pod"], kwargs["images"]))
        state.update(killed=True, session=False)
        return {"target_plan": injected[-1]}

    def web(req):
        if req.url.path == "/api/login": state["session"] = True
        elif req.url.path == "/api/logout": state["session"] = False
        else:
            assert req.url.path == "/api/me"
            return httpx.Response(200 if state["session"] else 401, json={})
        return httpx.Response(200, json={})
    real_client = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda **kw: real_client(transport=httpx.MockTransport(web), **kw))
    monkeypatch.setattr(hardfault, "inject", inject)
    monkeypatch.setattr(hardfault, "validate_receipt", lambda *args: True)
    monkeypatch.setattr(module, "run", execute)
    report = tmp_path / "report.json"
    with pytest.raises(ValueError, match="qualification did not pass"):
        module.qualify(SimpleNamespace(bundle=target, config=site, report=report, mode="upgrade", disposable_target=True))
    value = json.loads(report.read_bytes())
    assert [t["name"] for t in injected[0]["targets"]] == ["agent-runner", "gsj-mcp", "gsj-web"]
    if fault:
        assert value["failure_phase"] == "hard-restart" and "restart" not in value
        return
    assert value["failure_phase"] == "restore-preflight"
    assert "hard-restart-cookie-and-attempt" in {check["name"] for check in value["checks"]}
    assert "hard-restart" in {row["stage"] for row in value["fixture_preservation"]}
    assert value["restart"]["exit_codes"] == {"agent-runner": 137, "gsj-mcp": 137, "gsj-web": 137}


@pytest.mark.parametrize("fault", ["target", "permissions", "symlink"])
def test_refreshed_site_refuses_changed_identity_or_unprotected_file(modules, tmp_path, fault):
    module = modules[1]
    path = tmp_path / "site.json"
    value = {"target": {"context": "owned", "namespace": "gsj-qualification-test", "release": "gsj"}}
    if fault == "target": value["target"]["context"] = "foreign"
    path.write_text(json.dumps(value)); path.chmod(0o600)
    if fault == "permissions": path.chmod(0o644)
    if fault == "symlink":
        real = tmp_path / "real.json"; path.rename(real); path.symlink_to(real)
    with pytest.raises(ValueError):
        module.read_site(path, ("owned", "gsj-qualification-test", "gsj"))


@pytest.mark.parametrize("fault", [None, "gone", "replaced-before-read", "replaced-before-delete", "terminating", "timeout"])
def test_disposable_cleanup_uses_server_uid_precondition_and_never_deletes_replacements(modules, monkeypatch, fault):
    module = modules[1]
    calls = []
    reads = 0
    def execute(*args, **kwargs):
        nonlocal reads
        calls.append(args)
        assert args[:3] == ("kubectl", "--context", "isolated")
        if args[3] == "get":
            reads += 1
            if fault == "gone" or (reads > 1 and fault != "timeout"): return ""
            metadata = {"uid": "replacement" if fault == "replaced-before-read" else "owned"}
            if fault in {"terminating", "timeout"}: metadata["deletionTimestamp"] = "synthetic"
            return json.dumps({"metadata": metadata})
        assert args[3:] == ("delete", "--raw", "/api/v1/namespaces/gsj-qualification-owned", "-f", "-")
        assert json.loads(kwargs["input"]) == {"apiVersion": "v1", "kind": "DeleteOptions",
            "preconditions": {"uid": "owned"}, "propagationPolicy": "Foreground"}
        if fault == "replaced-before-delete": raise subprocess.CalledProcessError(1, args)
        return "{}"
    monkeypatch.setattr(module, "run", execute)
    monkeypatch.setattr(module.time, "sleep", lambda _: None)
    if fault in {"replaced-before-read", "replaced-before-delete", "timeout"}:
        with pytest.raises((ValueError, subprocess.CalledProcessError)):
            module.delete_owned_namespace("isolated", "gsj-qualification-owned", "owned", timeout=0)
    else:
        module.delete_owned_namespace("isolated", "gsj-qualification-owned", "owned")
    deletes = [args for args in calls if args[3] == "delete"]
    assert len(deletes) == (1 if fault in {None, "replaced-before-delete"} else 0)


@pytest.mark.parametrize("fault", ["missing", "wrong-profile", "write", "publication-claim", "wrong-source",
                                   "wrong-target", "wrong-version", "wrong-key", "wrong-url", "missing-file", "changed-bytes"])
def test_qualification_gate_rejects_unproved_actual_delivery_readback(modules, tmp_path, monkeypatch, fault):
    module = modules[1]
    _, reports = qualified_files(module, tmp_path, monkeypatch)
    report = json.loads(reports[1].read_bytes())
    receipt = report["release_readback"]["restore"]
    if fault == "missing": report["release_readback"].pop("restore")
    elif fault == "wrong-profile": receipt["read_profiles"] = ["upgrade"]
    elif fault == "write": receipt["operation"] = "stage"
    elif fault == "publication-claim": receipt["descriptor_published_last"] = True
    elif fault == "missing-file": receipt["files"].pop("gsj-install.sh")
    elif fault == "changed-bytes": receipt["files"]["gsj-install.sh"]["sha256"] = "0" * 64
    else:
        key = {"wrong-source": "source_identity", "wrong-target": "target_identity",
               "wrong-version": "target_version", "wrong-key": "trust_sha256", "wrong-url": "version_url"}[fault]
        receipt[key] = "changed"
    reports[1].write_text(json.dumps(report))
    with pytest.raises(ValueError, match="readback"):
        module.gate(tmp_path, reports)


def test_selected_upgrade_uses_prior_installer_and_explicit_version(modules, tmp_path, monkeypatch):
    calls = []
    module = modules[1]
    monkeypatch.setattr(module, "run", lambda *args: calls.append(args))
    module.selected_upgrade(tmp_path / "source", "1.1.0", tmp_path / "site.json")
    assert calls == [("bash", tmp_path / "source/gsj-install.sh", "upgrade", "--to", "1.1.0",
                      "--config", tmp_path / "site.json", "--non-interactive")]


@pytest.mark.parametrize("fault", ["missing", "local-target", "same-version", "same-identity", "same-bytes",
                                   "wrong-target-version", "unlisted-source", "missing-repeat"])
def test_publish_gate_requires_selected_upgrade_and_repeat(modules, tmp_path, monkeypatch, fault):
    module = modules[1]
    descriptor, reports = qualified_files(module, tmp_path, monkeypatch)
    value = json.loads(reports[1].read_bytes())
    source = value["upgrade_source"]
    if fault == "missing": value.pop("upgrade_source")
    elif fault == "local-target": source["entrypoint"] = "target-installer upgrade"
    elif fault == "same-version": source["version"] = descriptor["version"]
    elif fault == "same-identity": source["release_identity"] = descriptor["releaseId"]
    elif fault == "same-bytes": source["installer_sha256"] = descriptor["installer"]["sha256"]
    elif fault == "wrong-target-version": source["requested_target_version"] = "1.2.0"
    elif fault == "unlisted-source": source["release_identity"] = "unknown-source"
    else: value["checks"] = [x for x in value["checks"] if x["name"] != "selected-version-repeat-converges"]
    reports[1].write_text(json.dumps(value))
    with pytest.raises(ValueError): module.gate(tmp_path, reports)


@pytest.mark.parametrize("fault", ["missing", "old-contract", "missing-document", "missing-firm-card",
                                   "missing-history", "missing-permissions", "duplicate", "missing-hash"])
def test_publish_gate_requires_complete_populated_fixture(modules, tmp_path, monkeypatch, fault):
    module = modules[1]
    _, reports = qualified_files(module, tmp_path, monkeypatch)
    value = json.loads(reports[1].read_text())
    fixture = value["populated_fixture"]
    if fault == "missing": value.pop("populated_fixture")
    elif fault == "old-contract": fixture["contract"] = "gsj.upgrade-fixture/1"
    elif fault == "duplicate": fixture["coverage"].append(fixture["coverage"][0])
    elif fault == "missing-hash": fixture.pop("snapshot_sha256")
    else:
        key = {"missing-document": "generated-document", "missing-firm-card": "firm-card",
               "missing-history": "repository-history", "missing-permissions": "repository-permissions"}[fault]
        fixture["coverage"].remove(key)
    reports[1].write_text(json.dumps(value))
    with pytest.raises(ValueError, match="populated fixture"):
        module.gate(tmp_path, reports)


@pytest.mark.parametrize("failure", ["one-report", "skipped", "stale-bytes", "qualification", "missing-image", "manifest-tamper", "residue", "restart-skipped", "restore-missing"])
def test_publish_gate_rejects_incomplete_or_stale_evidence(modules, tmp_path, monkeypatch, failure):
    module = modules[1]
    descriptor, reports = qualified_files(module, tmp_path, monkeypatch)
    module.gate(tmp_path, reports)
    if failure == "one-report": reports.pop()
    elif failure == "qualification": descriptor["qualification"] = True
    elif failure == "manifest-tamper": (tmp_path / "manifest.json").write_text('{"identity":"other"}')
    elif failure == "missing-image":
        value = json.loads((tmp_path / "image-inventory.json").read_text())
        value["images"].pop("decisionsData")
        (tmp_path / "image-inventory.json").write_text(json.dumps(value))
    elif failure in {"restart-skipped", "restore-missing"}:
        value = json.loads(reports[1].read_text())
        if failure == "restart-skipped":
            next(row for row in value["checks"] if row["name"] == "hard-restart-cookie-and-attempt")["status"] = "skipped"
        else:
            value["checks"] = [row for row in value["checks"] if row["name"] != "fresh-restore-to-target-acceptance"]
        reports[1].write_text(json.dumps(value))
    else:
        value = json.loads(reports[0].read_text())
        if failure == "skipped": value["checks"][0]["status"] = "skipped"
        elif failure == "stale-bytes": value["installer_sha256"] = "d" * 64
        else: value["disposable_target_cleanup"] = "pending"
        reports[0].write_text(json.dumps(value))
    with pytest.raises(ValueError):
        module.gate(tmp_path, reports)


def bind_delivery_staging(module, directory):
    manifest = json.loads((directory / "manifest.json").read_bytes())
    descriptor = {"releaseId": manifest["identity"], "version": manifest["version"],
                  "manifestSha256": module.sha(directory / "manifest.json"),
                  "trustKeySha256": module.sha(directory / "release.pem"),
                  "installer": {"name": "gsj-install.sh", "sha256": module.sha(directory / "gsj-install.sh"),
                                "bytes": (directory / "gsj-install.sh").stat().st_size}}
    (directory / "installer-descriptor.json").write_text(json.dumps(descriptor))
    staged = staged_release()
    staged.update(target_identity=manifest["identity"], target_version=manifest["version"],
                  target_installer_sha256=descriptor["installer"]["sha256"],
                  target_manifest_sha256=descriptor["manifestSha256"], trust_sha256=descriptor["trustKeySha256"],
                  version_url=staged["base_url"] + "/" + manifest["version"])
    for name in staged["files"]:
        staged["files"][name].update(sha256=module.sha(directory / name), bytes=(directory / name).stat().st_size)
    (directory / "staging.json").write_text(json.dumps(staged))
    upgrade = {"upgrade_source": {"release_identity": staged["source_identity"], "version": staged["source_version"],
                                  "installer_sha256": staged["source_installer_sha256"]},
               "release_readback": {profile: readback_receipt(staged, profile) for profile in ("upgrade", "restore")}}
    (directory / "upgrade.json").write_text(json.dumps(upgrade))






# --- the hand-run chain: ci/release.py build -> build.py, under the pin -------

def _bare_core(tmp_path, staged, tag):
    """A bare library repository with one commit carrying the two files the
    release preparation and the builder read from it, tagged `tag`, cloned
    bare to `staged` (where the release preparation expects the library)."""
    work = tmp_path / "core-work"
    work.mkdir()
    (work / "gsj/assets/schema_registry").mkdir(parents=True)
    (work / "gsj/assets/schema_registry/snapshot.json.gz").write_bytes(b"synthetic schema registry asset")
    (work / "services/mcp").mkdir(parents=True)
    (work / "services/mcp/Dockerfile").write_text("FROM example.test/base@sha256:" + "0" * 64 + "\n")
    git = ["git", "-C", str(work), "-c", "user.name=Test", "-c", "user.email=test@example.invalid"]
    subprocess.run(["git", "init", "-q", str(work)], check=True)
    subprocess.run([*git, "add", "."], check=True)
    subprocess.run([*git, "commit", "-qm", "synthetic core"], check=True)
    subprocess.run([*git, "tag", tag], check=True)
    staged.parent.mkdir(parents=True)
    subprocess.run(["git", "clone", "-q", "--bare", str(work), str(staged)], check=True)
    return staged, subprocess.check_output(["git", "-C", str(work), "rev-parse", "HEAD"], text=True).strip()


@pytest.mark.skipif(shutil.which("helm") is None, reason="helm not installed")
def test_the_manifest_the_release_preparation_writes_builds_under_the_pin_and_a_tampered_one_does_not(modules, tmp_path, monkeypatch):
    """The whole hand-run chain, with a FILLED synthetic pin: `ci/release.py
    build` writes the release manifest from the pin's images (the registry
    reads are stubbed; Git is real), and build.py's shared preparation accepts
    that manifest -- the binding refuses nothing the chain produces. Then one
    digest is edited in the written manifest, and the preparation refuses it
    by name, with both values."""
    import importlib.util as util
    release = modules[0]
    spec = util.spec_from_file_location("installer_builder_chain", ROOT / "ops/installer/build.py")
    builder = util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    version, core_tag = "v0.10.0-beta.1", "v4.9.2-synthetic"
    # the installer repository the preparation reads: a clean synthetic one, with the staged library
    source = tmp_path / "installer-repo"
    source.mkdir()
    subprocess.run(["git", "init", "-q", str(source)], check=True)
    (source / "README").write_text("synthetic installer repository\n")
    (source / ".gitignore").write_text("ops/.build\n")   # the staged library is build material, ignored as in this repository
    subprocess.run(["git", "-C", str(source), "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "add", "README", ".gitignore"], check=True)
    subprocess.run(["git", "-C", str(source), "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "synthetic installer"], check=True)
    core_git, core_commit = _bare_core(tmp_path, source / "ops/.build/gsj-next.git", core_tag)
    monkeypatch.setattr(release, "ROOT", source)
    monkeypatch.setattr(builder, "ROOT", source)
    # the pin, filled as promotion fills it
    images = {role: {"repository": "registry.example.test/" + role.lower(), "digest": "sha256:" + char * 64}
              for role, char in zip(release.webpin.IMAGE_ROLES, "1234")}
    chart = tmp_path / "pinned/chart"
    chart.mkdir(parents=True)
    (chart / "Chart.yaml").write_text(f"apiVersion: v2\nname: gsj\nversion: {version[1:]}\nappVersion: {version[1:]}\n")
    pin = {"schema": "gsj.web-pin/1", "repository": "example/product", "commit": "f" * 40, "release": version,
           "chart": {"version": version[1:], "tree": "1" * 40, "sha256": builder.sha(builder.normalized_chart(chart, version[1:]))},
           "gsj_deploy": {"tree": "2" * 40}, "core": {"tag": core_tag}, "images": images}
    for webpin in (release.webpin, builder.webpin):
        monkeypatch.setattr(webpin, "load", lambda path=None: pin)
        monkeypatch.setattr(webpin, "archive", lambda path, destination, pin=None: chart)
        monkeypatch.setattr(webpin, "core_tag", lambda pin=None: core_tag)
        monkeypatch.setattr(webpin, "show", lambda path, pin=None: b"FROM example.test/base@sha256:" + b"0" * 64 + b"\n")
    # the registry, stubbed: every image answers with its approved digest on linux/amd64
    def inspect_image(reference, *, allow_additional_platforms=False, pull=False):
        repository, digest = reference.rsplit("@", 1)
        return {"repository": repository, "digest": digest, "platforms": {release.PLATFORM: digest}}
    monkeypatch.setattr(release, "inspect_image", inspect_image)
    monkeypatch.setattr(release, "base_images", lambda dockerfile: [])
    monkeypatch.setattr(release, "installed", lambda image, bases: {"bases": bases, "python": [], "system": []})
    model = {"model": "synthetic/model", "revision": "a" * 40, "manifest_sha256": "b" * 64, "dimensions": 768, "distance": "cosine", "encoding": "synthetic-encoding-v1"}
    def corpus_manifest_from_image(reference, destination):
        corpus = {"format": "gsj.corpus/1", "core_commit": core_commit, "source_sha256": "d" * 64, "rows": 1, "chunks": 1,
                  "files": [{"chunks": 1}], "publication_ready": True, "release_owner": "Example Owner",
                  "source_provenance": "synthetic source", "embedding": model}
        corpus["fingerprint"] = hashlib.sha256(json.dumps(corpus, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
        (destination / "manifest.json").write_bytes(builder.canonical(corpus))
        return corpus
    monkeypatch.setattr(release, "corpus_manifest_from_image", corpus_manifest_from_image)
    # the approved inputs, as `inputs` would have staged them
    destination = tmp_path / "release"
    (destination / "addons").mkdir(parents=True)
    addons = {}
    for role, name in (("traefik", "traefik.tgz"), ("certManager", "cert-manager.tgz"), ("localPath", "local-path.yaml")):
        (destination / "addons" / name).write_bytes(b"synthetic addon " + name.encode())
        addons[role] = {"path": "addons/" + name, "sha256": builder.sha((destination / "addons" / name).read_bytes()),
                        "images": {"controller": "example/controller@sha256:" + "e" * 64}}
    client = {release.PLATFORM: {"url": "https://example.test/fixed-binary", "sha256": "a" * 64}}
    catalog = {"schema": "gsj.release-inputs/1", "upstreamImages": {"forgejo": "registry.example.test/forgejo@sha256:" + "5" * 64,
                                                                    "chroma": "registry.example.test/chroma@sha256:" + "6" * 64},
               "addons": addons, "clients": {tool: client for tool in ("helm", "kubectl", "jq")}, "model": model,
               "release_base_url": "https://releases.example.test/gsj"}
    (destination / "inputs.json").write_text(json.dumps(catalog))
    private, public = destination / "private.pem", destination / "release.pem"
    subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", str(private)], check=True, capture_output=True)
    subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)], check=True, capture_output=True)
    release.build(destination)
    written = json.loads((destination / "manifest.json").read_text())
    assert {role: {"repository": written["images"][role]["repository"], "digest": written["images"][role]["digest"]}
            for role in images} == images
    assert "qualification" not in written
    public_manifest, _, _ = builder.prepare(destination / "manifest.json")
    assert public_manifest["source"]["web_commit"] == pin["commit"]
    assert public_manifest["version"] == version
    tampered = copy.deepcopy(written)
    tampered["images"]["mcp"]["digest"] = "sha256:" + "9" * 64
    (destination / "manifest.json").write_text(json.dumps(tampered))
    with pytest.raises(ValueError, match=r"images\.mcp: the manifest names .*9{64}, web-pin\.json pins .*3{64}"):
        builder.prepare(destination / "manifest.json")


def test_the_preparation_pulls_only_the_four_product_images_and_inspects_only_native_children_on_a_clean_engine(modules, tmp_path, monkeypatch):
    """PROMOTION's `ci/release.py build` failed twice on a clean engine and
    once more on Docker Hub's budget: `installed()` and
    `corpus_manifest_from_image()` ran `docker image inspect` on the INDEX
    digest the pin records, while `inspect_image` had pulled only the amd64
    CHILD (a single-platform engine never holds the index by that name), and
    every base image of every Dockerfile plus every add-on image was pulled
    by digest on every run. Here the engine starts EMPTY and is modelled
    strictly: a local inspect, create or run of anything not pulled -- or of
    an index reference -- is "No such image", and every pull is counted. The
    whole preparation must complete, pulling exactly the four product
    children once; a second run on the now-populated engine pulls nothing."""
    release = modules[0]
    version, core_tag = "v0.10.0-beta.1", "v4.9.2-synthetic"
    source = tmp_path / "installer-repo"
    source.mkdir()
    subprocess.run(["git", "init", "-q", str(source)], check=True)
    (source / "README").write_text("synthetic installer repository\n")
    (source / ".gitignore").write_text("ops/.build\n")
    git = ["git", "-C", str(source), "-c", "user.name=Test", "-c", "user.email=test@example.invalid"]
    subprocess.run([*git, "add", "README", ".gitignore"], check=True)
    subprocess.run([*git, "commit", "-qm", "synthetic installer"], check=True)
    core_git, core_commit = _bare_core(tmp_path, source / "ops/.build/gsj-next.git", core_tag)
    monkeypatch.setattr(release, "ROOT", source)
    index = {role: "sha256:" + char * 64 for role, char in zip(release.webpin.IMAGE_ROLES, "1234")}
    child = {digest: "sha256:" + digest[7] + "c" * 63 for digest in index.values()}   # the amd64 child of each product index
    images = {role: {"repository": "registry.example.test/" + role.lower(), "digest": digest} for role, digest in index.items()}
    pin = {"schema": "gsj.web-pin/1", "repository": "example/product", "commit": "f" * 40, "release": version,
           "chart": {"version": version[1:], "tree": "1" * 40, "sha256": "0" * 64},
           "gsj_deploy": {"tree": "2" * 40}, "core": {"tag": core_tag}, "images": images}
    base = "example.test/base@sha256:" + "0" * 64
    monkeypatch.setattr(release.webpin, "load", lambda path=None: pin)
    monkeypatch.setattr(release.webpin, "core_tag", lambda pin=None: core_tag)
    monkeypatch.setattr(release.webpin, "show", lambda path, pin=None: ("FROM node:22 AS spa\nFROM " + base + "\n").encode())
    upstream = {"forgejo": "registry.example.test/forgejo@sha256:" + "5" * 64, "chroma": "registry.example.test/chroma@sha256:" + "6" * 64}
    addon_image = "example/controller@sha256:" + "e" * 64
    single = {upstream["forgejo"], upstream["chroma"], base, addon_image}        # single-platform manifests: child == digest
    tag_digest = {"node:22": "sha256:" + "7" * 64}                               # a multi-platform tag resolves to an index
    tag_child = {"sha256:" + "7" * 64: "sha256:" + "7" + "c" * 63}
    model = {"model": "synthetic/model", "revision": "a" * 40, "manifest_sha256": "b" * 64, "dimensions": 768, "distance": "cosine", "encoding": "synthetic-encoding-v1"}
    corpus = {"format": "gsj.corpus/1", "core_commit": core_commit, "source_sha256": "d" * 64, "rows": 1, "chunks": 1,
              "files": [{"chunks": 1}], "publication_ready": True, "release_owner": "Example Owner",
              "source_provenance": "synthetic source", "embedding": model}
    corpus["fingerprint"] = hashlib.sha256(json.dumps(corpus, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    corpus_bytes = (json.dumps(corpus, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode()
    engine = {"pulled": set(), "pulls": [], "local_refs": [], "config_reads": []}
    layers = ["sha256:" + "a" * 64, "sha256:" + "b" * 64]

    def no_such_image(reference):
        raise subprocess.CalledProcessError(1, ["docker", "image", "inspect", reference], stderr="Error: No such image: " + reference)

    def resolve(reference):
        """What the registry serves for a reference: (index digest, child digest)."""
        if "@" in reference:
            digest = reference.rsplit("@", 1)[1]
            if reference in single: return digest, digest
            if digest in child: return digest, child[digest]
            if digest in tag_child: return digest, tag_child[digest]
            if digest in child.values() or digest in tag_child.values(): return digest, digest   # a child named directly
            raise AssertionError("unknown reference " + reference)
        digest = tag_digest[reference.rsplit(":", 1)[1] and reference]
        return digest, tag_child[digest]

    def fake_run(*args, capture=False, **kw):
        args = list(map(str, args))
        if args[0] == "git":
            return subprocess.run(args, check=True, text=True, stdout=subprocess.PIPE if capture else None, **kw).stdout
        assert args[0] == "docker", args
        if args[1:4] == ["buildx", "imagetools", "inspect"]:
            reference = args[4]
            digest, native = resolve(reference)
            if args[5:] == ["--format", "{{.Manifest.Digest}}"]:
                return digest + "\n"
            if args[5:] == ["--raw"]:
                if digest == native:
                    return json.dumps({"schemaVersion": 2, "config": {"digest": "sha256:" + "f" * 64}})
                return json.dumps({"manifests": [{"platform": {"os": "linux", "architecture": "amd64"}, "digest": native},
                                                 {"platform": {"os": "unknown", "architecture": "unknown"}, "digest": "sha256:" + "9" * 64}]})
            if args[5:] == ["--format", "{{json .Image}}"]:
                engine["config_reads"].append(reference)
                # a multi-platform reference answers a MAP per platform, as buildx does; only a child answers one config
                if digest != native:
                    return json.dumps({"linux/amd64": {"os": "linux", "architecture": "amd64", "rootfs": {"diff_ids": layers}}})
                return json.dumps({"os": "linux", "architecture": "amd64", "rootfs": {"diff_ids": layers}})
            raise AssertionError("unexpected imagetools call " + " ".join(args))
        if args[1] == "pull":
            reference = args[-1]
            assert args[2:4] == ["--platform", release.PLATFORM]
            digest, native = resolve(reference)
            assert reference.rsplit("@", 1)[1] == native, "pulled by index, not by the native child: " + reference
            engine["pulls"].append(reference); engine["pulled"].add(reference)
            return ""
        # everything below is LOCAL: the engine holds only what was pulled, by its child reference
        if args[1:3] == ["image", "inspect"]:
            reference = args[3]
            engine["local_refs"].append(reference)
            if reference not in engine["pulled"]: no_such_image(reference)
            fmt = args[args.index("--format") + 1] if "--format" in args else ""
            if fmt == "{{.Os}}/{{.Architecture}}": return "linux/amd64\n"
            if fmt == "{{json .RootFS.Layers}}": return json.dumps(layers + ["sha256:" + "d" * 64])
            if "manifest-sha256" in fmt: return hashlib.sha256(corpus_bytes).hexdigest() + "\n"
            return ""
        if args[1] == "create":
            reference = args[-1]
            engine["local_refs"].append(reference)
            if reference not in engine["pulled"]: no_such_image(reference)
            return "synthetic-container\n"
        if args[1] == "cp":
            Path(args[3]).write_bytes(corpus_bytes)
            return ""
        if args[1] == "rm":
            return ""
        if args[1] == "run":
            reference = args[args.index("--entrypoint") + 2]
            engine["local_refs"].append(reference)
            if reference not in engine["pulled"]: no_such_image(reference)
            return "synthetic-package=1\n"
        raise AssertionError("unexpected docker call " + " ".join(args))

    monkeypatch.setattr(release, "run", fake_run)

    def inputs(destination):
        (destination / "addons").mkdir(parents=True)
        addons = {}
        for role, name in (("traefik", "traefik.tgz"), ("certManager", "cert-manager.tgz"), ("localPath", "local-path.yaml")):
            (destination / "addons" / name).write_bytes(b"synthetic addon " + name.encode())
            addons[role] = {"path": "addons/" + name, "sha256": hashlib.sha256((destination / "addons" / name).read_bytes()).hexdigest(),
                            "images": {"controller": addon_image}}
        client = {release.PLATFORM: {"url": "https://example.test/fixed-binary", "sha256": "a" * 64}}
        catalog = {"schema": "gsj.release-inputs/1", "upstreamImages": upstream, "addons": addons,
                   "clients": {tool: client for tool in ("helm", "kubectl", "jq")}, "model": model,
                   "release_base_url": "https://releases.example.test/gsj"}
        (destination / "inputs.json").write_text(json.dumps(catalog))
        return destination

    release.build(inputs(tmp_path / "release-1"))
    written = json.loads((tmp_path / "release-1/manifest.json").read_text())
    product_children = sorted(images[role]["repository"] + "@" + child[index[role]] for role in images)
    assert sorted(engine["pulls"]) == product_children                       # the four product children, each once
    assert all(ref in engine["pulled"] for ref in engine["local_refs"])       # nothing local was ever asked about an index or an unpulled image
    assert {ref.rsplit("@", 1)[1] for ref in engine["local_refs"]} == set(child.values())
    assert written["images"]["web"] == {"repository": images["web"]["repository"], "digest": index["web"], "platforms": {release.PLATFORM: child[index["web"]]}}
    assert written["images"]["forgejo"]["platforms"][release.PLATFORM] == "sha256:" + "5" * 64
    inventory = json.loads((tmp_path / "release-1/image-inventory.json").read_text())
    assert inventory["all_remote_manifests_verified"] is True
    assert inventory["dependencies"]["web"]["bases"][-1]["reference"] == base and inventory["dependencies"]["web"]["python"] == ["synthetic-package=1"]
    # the base of every Dockerfile and the add-on image were read from the registry only: never pulled, never inspected locally
    assert all(ref in engine["config_reads"] for ref in (base, addon_image)) and base not in engine["pulled"]
    assert json.loads((tmp_path / "release-1/corpus/manifest.json").read_bytes()) == corpus
    # a second preparation on the now-populated engine pulls nothing
    engine["pulls"].clear()
    release.build(inputs(tmp_path / "release-2"))
    assert engine["pulls"] == []
    assert json.loads((tmp_path / "release-2/manifest.json").read_text())["images"] == written["images"]


def test_qualification_refuses_a_missing_pinned_git_directory_in_its_first_second_and_in_words(modules, tmp_path, monkeypatch, capsys):
    """PROMOTION's first ordinary run reached `expected_checks()` after a
    two-hour install and died on a bare `ValueError` because the launch
    shell carried no GSJ_NEXT_WEB_GIT_DIR. The check list is now the first
    thing `qualify` resolves: with no Git directory it refuses before the
    bundle is verified, before any kubectl, and the CLI prints the recipe
    webpin names rather than a type name."""
    module = modules[1]
    def missing(path, pin=None):
        raise ValueError("the pinned gsj-next-web commit 228ba86b8b69 is in no Git directory here; stage one with `git clone --bare <gsj-next-web> ops/.build/gsj-next-web.git` (or set GSJ_NEXT_WEB_GIT_DIR, or keep a ../gsj-next-web sibling that carries the commit)")
    monkeypatch.setattr(module.webpin, "show", missing)
    monkeypatch.setattr(module, "bundle", lambda path: pytest.fail("the bundle was verified before the environment was"))
    monkeypatch.setattr(module, "run", lambda *args, **kwargs: pytest.fail("a subprocess ran before the environment was checked: " + " ".join(map(str, args))))
    site = tmp_path / "ordinary/site.json"
    site.parent.mkdir()
    site.write_text(json.dumps({"target": {"context": "disposable", "namespace": "gsj-qualification-test", "release": "gsj"}}))
    site.chmod(0o600)
    report = tmp_path / "report.json"
    args = SimpleNamespace(bundle=tmp_path / "candidate", config=site, report=report, mode="ordinary", disposable_target=True)
    with pytest.raises(module.Refused, match="GSJ_NEXT_WEB_GIT_DIR"):
        module.qualify(args)
    assert not report.exists()                                              # nothing was written, nothing ran
    monkeypatch.setattr(sys, "argv", ["qualify.py", "run", "--bundle", str(tmp_path / "candidate"), "--config", str(site),
                                      "--report", str(report), "--mode", "ordinary", "--disposable-target"])
    with pytest.raises(SystemExit) as stopped:
        module.main()
    assert stopped.value.code == 1
    err = capsys.readouterr().err
    assert "Installer qualification failed: the pinned product's check list cannot be read before the install: the pinned gsj-next-web commit 228ba86b8b69 is in no Git directory here" in err
    assert "ops/.build/gsj-next-web.git" in err and "GSJ_NEXT_WEB_GIT_DIR" in err
    # with the directory present, the same launch proceeds to the cluster (the first read is the namespace)
    monkeypatch.setattr(module.webpin, "show", lambda path, pin=None: b"REQUIRED_CHECKS = {\"synthetic-check\"}\n")
    monkeypatch.setattr(module, "bundle", lambda path: {"releaseId": "target", "version": "1.1.0", "installer": {"sha256": "a" * 64}})
    (tmp_path / "candidate").mkdir()
    (tmp_path / "candidate/manifest.json").write_text(json.dumps({"identity": "target", "corpus": {"fingerprint": "f" * 64, "rows": 3, "chunks": 3}}))
    (tmp_path / "candidate/gsj-install.sh").write_text("must not execute")
    calls = []
    def cluster(*args, **kwargs):
        calls.append(args)
        raise RuntimeError("synthetic cluster unavailable")
    monkeypatch.setattr(module, "run", cluster)
    monkeypatch.setattr(module, "sha", lambda path: "a" * 64)
    with pytest.raises(ValueError, match="qualification did not pass"):
        module.qualify(args)
    assert calls and calls[0][:7] == ("kubectl", "--context", "disposable", "--namespace", "gsj-qualification-test", "get", "namespace")
    assert json.loads(report.read_bytes())["failure_phase"] == "target-preflight"
