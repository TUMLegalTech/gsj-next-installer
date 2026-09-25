#!/usr/bin/env python3
"""Qualify the exact distributable installer on an explicitly disposable cluster.

The protected input archive supplies ordinary/site.json, upgrade/site.json,
and their credential/CA/kubeconfig files. Only metadata reports leave this run.
"""
import argparse
import ast
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import signal
import subprocess
import sys
import tarfile
import tempfile
import time

from release import ROOT, Refused, download, require, run, save, sha, webpin


def prepare(destination):
    require(not destination.exists(), "qualification input directory must be fresh")
    destination.mkdir(parents=True, mode=0o700)
    archive = destination / "inputs.tar"
    download({"url": os.environ["GSJ_QUALIFICATION_CONFIG_ARCHIVE_URL"],
              "sha256": os.environ["GSJ_QUALIFICATION_CONFIG_ARCHIVE_SHA256"]}, archive,
              os.environ.get("GSJ_QUALIFICATION_INPUT_TOKEN", ""))
    with tarfile.open(archive, "r:*") as source:
        seen = set()
        for member in source:
            path = PurePosixPath(member.name)
            require(not path.is_absolute() and ".." not in path.parts and "\\" not in member.name,
                    "unsafe protected configuration path")
            if member.isdir():
                continue
            require(member.isfile() and member.name not in seen and member.size < 8 * 1024 * 1024,
                    "protected configuration archive has an invalid member")
            seen.add(member.name)
            target = destination / path
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with target.open("xb") as output:
                output.write(source.extractfile(member).read())
            target.chmod(0o600)
    archive.unlink()
    for mode in ("ordinary", "upgrade", "restore"):
        require((destination / mode / "site.json").is_file(), "ordinary, upgrade and fresh restore site configurations are required")


def expected_checks():
    """The verifier's check list, read from the PINNED product commit
    (web-pin.json), never from a working tree.

    It needs a Git directory carrying that commit -- GSJ_NEXT_WEB_GIT_DIR, the
    staged bare clone or the ../gsj-next-web sibling (webpin.git_dir) -- which
    is a fact about the machine the harness runs on, not about the installer.
    qualify() therefore resolves it ONCE, in its first second, before the
    bundle is verified or the cluster is touched: the first release
    qualification reached this call after a two-hour install and died on a
    bare ValueError.
    Here a missing directory is this harness's own refusal, in words."""
    try:
        source = webpin.show("gsj_deploy/verify.py").decode()
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        raise Refused("the pinned product's check list cannot be read before the install: " + str(exc)) from None
    syntax = ast.parse(source)
    return next(ast.literal_eval(node.value) for node in syntax.body if isinstance(node, ast.Assign)
                and any(isinstance(name, ast.Name) and name.id == "REQUIRED_CHECKS" for name in node.targets))


UPGRADE_FIXTURE_COVERAGE = sorted({
    "pdf-and-index", "notes", "annotations", "instructions", "settings",
    "personal-card", "firm-card", "generated-document", "agent-history",
    "conversations", "repository-history", "repository-permissions",
})


def check_fixture_contract(snapshot):
    require(snapshot.get("contract") == "gsj.upgrade-fixture/2"
            and snapshot.get("coverage") == UPGRADE_FIXTURE_COVERAGE,
            "populated fixture does not cover the required preserved data")


def fixture_preservation(before, after, stage, report):
    """Compare durable content; unreachable Git objects are GC diagnostics."""
    check_fixture_contract(before)
    check_fixture_contract(after)
    expected = {key: value for key, value in before.items() if key != "diagnostics"}
    actual = {key: value for key, value in after.items() if key != "diagnostics"}
    require(expected == actual, stage + " changed populated fixture state")
    report.setdefault("fixture_preservation", []).append({
        "stage": stage,
        "preserved_sha256": hashlib.sha256(json.dumps(actual, sort_keys=True,
                                                      separators=(",", ":")).encode()).hexdigest(),
        "diagnostics": after.get("diagnostics", {}),
    })


def check_application(installed, manifest, expected=None):
    """`expected` is the pinned check list qualify() resolved before the
    install; a caller without one reads it now."""
    expected = expected_checks() if expected is None else expected
    require(installed.get("status") == "complete" and installed["manifest"]["identity"] == manifest["identity"],
            "installer did not commit the expected installed identity")
    require(installed["manifest"]["images"] == manifest["images"] and installed["manifest"]["corpus"] == manifest["corpus"],
            "installed image or full corpus inventory differs")
    verdict = installed["verification"]
    report = verdict["application"]
    checks = report.get("checks", [])
    require(report.get("status") == "passed" and report.get("cleanup_users") == "passed"
            and report.get("case_and_pat_cleanup") == "passed"
            and len(checks) == len(expected)
            and {c["name"] for c in checks if c.get("status") == "passed"} == expected,
            "ordinary application verification failed, skipped checks, or left cleanup")
    require(report.get("expected_corpus_fingerprint") == manifest["corpus"]["fingerprint"], "application corpus binding differs")
    require(verdict["public"].get("status") == "passed" and verdict["public"].get("tls_verified") is True
            and verdict["network"].get("status") == "passed", "public TLS or real NetworkPolicy gate failed")


def bundle(directory):
    run(sys.executable, "-B", ROOT / "ops/installer/build.py", "verify", "--installer", directory / "gsj-install.sh",
        "--descriptor", directory / "installer-descriptor.json", "--signature", directory / "installer-descriptor.sig", "--public-key", directory / "release.pem")
    descriptor = json.loads((directory / "installer-descriptor.json").read_bytes())
    return descriptor


def selected_upgrade(source, version, site_path):
    # Use the installed release to acquire and authenticate the requested
    # immutable successor. A locally supplied target script cannot prove this.
    run("bash", source / "gsj-install.sh", "upgrade", "--to", version,
        "--config", site_path, "--non-interactive")


def check_release_readback(receipt, staged, profile):
    """Bind the actual qualification reader to the staged immutable bytes."""
    require(staged.get("schema") == "gsj.release-staging/1"
            and staged.get("status") == "passed" and staged.get("operation") == "stage"
            and staged.get("transport") == "direct-https"
            and staged.get("read_profiles") == ["restore", "upgrade"],
            "immutable release staging evidence is missing")
    require(receipt.get("schema") == "gsj.release-staging/1"
            and receipt.get("status") == "passed" and receipt.get("operation") == "readback"
            and receipt.get("read_profiles") == [profile]
            and receipt.get("descriptor_published_last", False) is None,
            "qualification release readback evidence is missing")
    fields = ("source_identity", "source_version", "target_identity", "target_version",
              "source_installer_sha256", "target_installer_sha256", "target_manifest_sha256",
              "trust_sha256", "base_url", "version_url", "descriptor_commit_policy",
              "origin_atomic_conditional_put", "transport")
    require(all(key in staged and receipt.get(key) == staged[key] for key in fields),
            "qualification release readback identity differs")
    names = {"gsj-install.sh", "installer-descriptor.sig", "installer-descriptor.json"}
    require(set(receipt.get("files", {})) == names == set(staged.get("files", {})),
            "qualification release readback inventory differs")
    for name in names:
        expected, actual = staged["files"][name], receipt["files"][name]
        require(actual.get("outcome") == "identical-existing"
                and all(key in expected and actual.get(key) == expected[key] for key in ("sha256", "bytes")),
                "qualification release readback bytes differ")


def release_readback(source, target, site_path, profile):
    # This uses the qualification runner's actual DNS, CA and read credentials
    # against the protected direct HTTPS origin. No installer runs here.
    require(site_path.parent.name == profile, "qualification delivery profile differs")
    with tempfile.TemporaryDirectory(prefix="gsj-release-readback-") as temporary:
        path = Path(temporary) / "report.json"
        run(sys.executable, "-B", ROOT / "ops/installer/ci/stage.py", "--read-only",
            "--source", source, "--target", target, "--config", site_path, "--report", path)
        receipt = json.loads(path.read_bytes())
    check_release_readback(receipt, json.loads((target / "staging.json").read_bytes()), profile)
    return receipt


def delete_owned_namespace(context, namespace, uid, *, timeout=600):
    """Delete a disposable namespace with an API-enforced UID precondition."""
    require(re.fullmatch(r"gsj-qualification-[a-z0-9-]+", namespace)
            and isinstance(uid, str) and uid, "disposable namespace ownership is missing")
    command = ("kubectl", "--context", context)
    deadline = time.monotonic() + timeout
    while True:
        value = run(*command, "get", "namespace", namespace, "-o", "json", "--ignore-not-found", capture=True)
        if not value.strip():
            return
        actual = json.loads(value)
        require(actual["metadata"]["uid"] == uid, "disposable namespace identity changed")
        if not actual["metadata"].get("deletionTimestamp"):
            options = {"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": uid},
                       "propagationPolicy": "Foreground"}
            # A read/check followed by an ordinary kubectl delete has a race:
            # a replacement namespace can appear between those requests.
            run(*command, "delete", "--raw", "/api/v1/namespaces/" + namespace, "-f", "-",
                input=json.dumps(options), capture=True)
        require(time.monotonic() < deadline, "disposable namespace remains")
        time.sleep(2)


def read_site(path, target=None):
    require(path.is_file() and not path.is_symlink() and not path.stat().st_mode & 0o077,
            "qualification site configuration must be private")
    value = json.loads(path.read_bytes())
    if target is not None:
        require(tuple(value.get("target", {}).get(key) for key in ("context", "namespace", "release")) == target,
                "installer changed the qualification target identity")
    return value


from contextlib import contextmanager


@contextmanager
def connection_route(config):
    """The verifier's TCP route override (gsj_deploy/verify.py connection_route),
    duplicated so this harness never puts the repository on sys.path: URL, Host
    and TLS SNI stay canonical; only this process's dial moves."""
    import socket
    from urllib.parse import urlsplit
    original = socket.getaddrinfo
    if config.get("connect_host"):
        origin = urlsplit(config["web_url"])
        port = origin.port or (443 if origin.scheme == "https" else 80)
        target_port = config.get("connect_port")
        require(type(target_port) is int and 1 <= target_port <= 65535, "invalid connection override")
        def resolve(host, service, *args, **kwargs):
            if host == origin.hostname and service == port:
                host, service = config["connect_host"], target_port
            return original(host, service, *args, **kwargs)
        socket.getaddrinfo = resolve
    try:
        yield
    finally:
        socket.getaddrinfo = original


def qualify(args):
    start = time.monotonic()
    # The pinned check list before anything else: its Git directory is the one
    # prerequisite this harness cannot learn from the bundle or the cluster,
    # so it is refused here, in the first second, never after the install.
    expected = expected_checks()
    target = args.bundle.resolve()
    descriptor = bundle(target)
    manifest = json.loads((target / "manifest.json").read_bytes())
    require(descriptor["releaseId"] == manifest["identity"], "candidate manifest differs from signed bundle")
    site_path = args.config.resolve()
    site = read_site(site_path)
    context, namespace, release = (site["target"][k] for k in ("context", "namespace", "release"))
    require(args.disposable_target and namespace.startswith("gsj-qualification-"), "qualification requires an explicitly disposable namespace")
    args.report.parent.mkdir(parents=True, exist_ok=True)
    report = {"schema": "gsj.installer-qualification/1", "mode": args.mode, "status": "running", "checks": [],
              "installer_sha256": sha(target / "gsj-install.sh"), "release_identity": manifest["identity"],
              "corpus_fingerprint": manifest["corpus"]["fingerprint"], "rows": manifest["corpus"]["rows"],
              "chunks": manifest["corpus"]["chunks"], "disposable_target_cleanup": "pending"}
    save(args.report, report)
    namespace_uid = None
    owned_namespaces = []

    def k(*argv, capture=True, **kw):
        return run("kubectl", "--context", context, "--namespace", namespace, *argv, capture=capture, **kw)

    def mark(name):
        report["checks"].append({"name": name, "status": "passed"})
        save(args.report, report)

    def phase(name):
        report["phase"] = name
        save(args.report, report)
        print(json.dumps({"stage": "qualification-phase", "phase": name}), flush=True)

    def install(directory, command):
        nonlocal site
        # This is the same entrypoint and bytes the customer receives. No Helm
        # shortcut, direct application deployment, or reduced corpus is allowed.
        run("bash", directory / "gsj-install.sh", command, "--config", site_path, "--non-interactive")
        # Managed local TLS and schema migrations can materialize protected
        # paths in the saved configuration. Later clients must use those paths.
        site = read_site(site_path, (context, namespace, release))

    def upgrade(source, version):
        nonlocal site
        selected_upgrade(source, version, site_path)
        site = read_site(site_path, (context, namespace, release))

    def installed():
        return json.loads(json.loads(k("get", "configmap", release + "-installed", "-o", "json"))["data"]["installed.json"])

    def pod():
        pods = json.loads(k("get", "pods", "-l", "app.kubernetes.io/instance=" + release + ",app.kubernetes.io/component=gsj", "-o", "json"))
        names = [p["metadata"]["name"] for p in pods["items"] if p.get("status", {}).get("phase") == "Running"]
        require(len(names) == 1, "qualification requires exactly one application pod")
        return names[0]

    def capture_state():
        # Hash credentials only in memory for equality; no credential or its
        # hash is emitted in the ordinary qualification report.
        credentials = json.loads(k("get", "secrets", "-o", "json"))
        stable = {s["metadata"]["name"]: s.get("data", {}) for s in credentials["items"]
                  if s.get("type") != "helm.sh/release.v1" and s.get("type") != "kubernetes.io/service-account-token"}
        state = installed()
        return {"storage": state["storage"], "namespace_uid": state["namespace_uid"], "site": state["site"],
                "credentials": hashlib.sha256(json.dumps(stable, sort_keys=True).encode()).hexdigest()}

    def fixture(action, run_id, **extra):
        def resolve(path):
            value = Path(path)
            return value if value.is_absolute() else site_path.parent / value
        cfg = {"run_id": run_id, "web_url": site["public_url"], "operator_login": site["operator"]["login"],
               "forge_url": "http://" + release + "-forgejo:3000",
               "operator_password": resolve(site["operator"]["password_file"]).read_text().rstrip("\r\n"),
               "timeout_seconds": site["deadlines"]["verification_seconds"], "llm_url": site["llm"]["base_url"],
               "llm_model": site["llm"]["model"], "connect_host": site.get("verification", {}).get("connect_host", ""),
               "connect_port": site.get("verification", {}).get("connect_port", 0)}
        cfg.update(extra)
        ca = site.get("verification", {}).get("ca_file")
        prelude = ""
        if ca:
            encoded = base64.b64encode(resolve(ca).read_bytes()).decode()
            remote = "/tmp/gsj-qualification-" + run_id + ".pem"
            prelude = "import base64,os\nos.umask(0o077)\nopen(" + repr(remote) + ",'wb').write(base64.b64decode(" + repr(encoded) + "))\n"
            cfg["ca_file"] = remote
        code = prelude + "CONFIG=" + repr(cfg) + "\nACTION=" + repr(action) + "\n" + (Path(__file__).with_name("fixture.py")).read_text()
        output = k("exec", "-i", pod(), "-c", "gsj-web", "--", "python", "-B", "-", input=code)
        return json.loads(output)

    def hard_restart(run_id):
        # The client stays in this engineering process's memory while the web
        # process dies. No session cookie/PAT is persisted or emitted.
        import httpx
        import ssl
        from hardfault import TARGETS, inject, validate_receipt
        route = {"web_url": site["public_url"], **site.get("verification", {})}
        ca = route.get("ca_file")
        ca = (Path(ca) if Path(ca).is_absolute() else site_path.parent / ca) if ca else None
        password_path = Path(site["operator"]["password_file"])
        if not password_path.is_absolute(): password_path = site_path.parent / password_path
        credentials = {"user": site["operator"]["login"], "password": password_path.read_text().rstrip("\r\n")}
        with connection_route(route), httpx.Client(base_url=site["public_url"], timeout=30,
                verify=ssl.create_default_context(cafile=ca)) as session:
            response = session.post("/api/login", json=credentials)
            require(response.status_code == 200 and session.get("/api/me").status_code == 200, "restart session could not be established")
            attempt = fixture("start-interrupted", run_id)
            name = pod()
            original = json.loads(k("get", "pod", name, "-o", "json"))
            before = {c["name"]: c["restartCount"] for c in original["status"]["containerStatuses"]}
            require(all(key in before for key in TARGETS), "hard-fault container identity missing")
            require(session.get("/api/me").status_code == 200, "restart cookie was invalid before fault")
            # Namespace PID 1 can ignore SIGKILL sent from a sibling process
            # inside that namespace. Prove exact process death from its ancestor
            # PID namespace before waiting for Kubernetes to recover containers.
            fault = inject(context=context, namespace=namespace, namespace_uid=namespace_uid,
                release=release, pod=original, images=manifest["images"],
                report_path=args.report.with_name(args.report.stem + ".hardfault.json"))
            validate_receipt(fault, manifest["images"], original["metadata"]["uid"])
            deadline = time.monotonic() + site["deadlines"]["verification_seconds"]
            while True:
                actual = json.loads(k("get", "pod", name, "-o", "json"))
                require(actual["metadata"]["uid"] == original["metadata"]["uid"], "restart changed the qualified pod identity")
                containers = {c["name"]: c for c in actual["status"].get("containerStatuses", [])}
                if all(containers.get(key, {}).get("ready") is True and containers[key]["restartCount"] > before[key]
                       for key in TARGETS):
                    break
                require(time.monotonic() < deadline, "hard-restarted containers did not recover")
                time.sleep(2)
            # Each restart must end the exact container the fault killed with
            # SIGKILL's 137, not a later crash or an unrelated termination.
            killed = {t["name"]: "containerd://" + t["container_id"] for t in fault["target_plan"]["targets"]}
            ended = {key: containers[key].get("lastState", {}).get("terminated", {}) for key in TARGETS}
            require(all(ended[key].get("exitCode") == 137 and ended[key].get("containerID") == killed[key]
                        for key in TARGETS), "hard-restarted containers did not exit from the proven SIGKILL")
            require(session.get("/api/me").status_code == 401, "old web cookie survived process restart")
            require(session.post("/api/login", json=credentials).status_code == 200
                    and session.get("/api/me").status_code == 200, "uncached post-restart login failed")
            require(session.post("/api/logout").status_code == 200, "post-restart logout failed")
            recovered = fixture("read-interrupted", run_id, expected_attempt=attempt["attempt_id"])
            require(recovered["case_id"] == attempt["case_id"], "recovered attempt case differs")
        return {"pod_uid": original["metadata"]["uid"], "attempt_id": attempt["attempt_id"],
                "cookie_invalidated": True, "interrupted_attempt_disclosed": True, "fault": fault,
                "exit_codes": {key: ended[key]["exitCode"] for key in TARGETS}}

    def interrupt(signum, _frame):
        # Cancelling this hand-run qualification sends SIGINT, then SIGTERM and
        # SIGKILL seconds later.
        # Persist the interruption and phase at once, because unwinding can
        # itself be slow (the hardfault helper cleanup), then unwind into owned
        # cleanup. A later signal is only recorded, so that cleanup continues
        # until the process dies.
        report["signal"] = signal.Signals(signum).name
        if report["status"] == "running":
            report.update(status="interrupted", failure_phase=report.get("phase", "unknown"))
            save(args.report, report)
            raise KeyboardInterrupt

    previous = {number: signal.signal(number, interrupt) for number in (signal.SIGINT, signal.SIGTERM)}
    try:
        phase("target-preflight")
        existing = k("get", "namespace", namespace, "-o", "json", "--ignore-not-found")
        require(not existing.strip(), "qualification refuses an existing namespace")
        if args.mode == "ordinary":
            phase("ordinary-install")
            install(target, "install")
            namespace_uid = json.loads(k("get", "namespace", namespace, "-o", "json"))["metadata"]["uid"]
            owned_namespaces.append((context, namespace, namespace_uid))
            check_application(installed(), manifest, expected)
            mark("fresh-full-corpus-install")
            before = capture_state()
            phase("ordinary-repeat")
            install(target, "install")
            check_application(installed(), manifest, expected)
            require(before == capture_state(), "repeated installer changed credentials, configuration or storage")
            mark("same-bundle-repeat")
        else:
            source = target / "baseline"
            source_descriptor = bundle(source)
            require(source_descriptor["releaseId"] != descriptor["releaseId"]
                    and source_descriptor["version"] != descriptor["version"]
                    and source_descriptor["installer"]["sha256"] != descriptor["installer"]["sha256"]
                    and source_descriptor["releaseId"] in manifest["supported_sources"], "a distinct supported upgrade source is required")
            report["upgrade_source"] = {
                "release_identity": source_descriptor["releaseId"],
                "version": source_descriptor["version"],
                "installer_sha256": source_descriptor["installer"]["sha256"],
                "requested_target_version": descriptor["version"],
                "entrypoint": "source-installer upgrade --to VERSION",
            }
            phase("upgrade-release-readback")
            report["release_readback"] = {"upgrade": release_readback(source, target, site_path, "upgrade")}
            save(args.report, report)
            phase("source-install")
            install(source, "install")
            namespace_uid = json.loads(k("get", "namespace", namespace, "-o", "json"))["metadata"]["uid"]
            owned_namespaces.append((context, namespace, namespace_uid))
            source_state = installed()
            require(source_state["status"] == "complete" and source_state["manifest"]["identity"] == source_descriptor["releaseId"], "source installer did not complete")
            run_id = secrets.token_hex(6)
            phase("populated-fixture-create")
            before_fixture = fixture("seed", run_id)
            check_fixture_contract(before_fixture)
            report["populated_fixture"] = {
                "contract": before_fixture["contract"], "coverage": before_fixture["coverage"],
                "snapshot_sha256": hashlib.sha256(json.dumps(before_fixture, sort_keys=True,
                                                              separators=(",", ":")).encode()).hexdigest(),
            }
            before = capture_state()
            mark("populated-source-created")
            phase("selected-upgrade")
            upgrade(source, descriptor["version"])
            phase("upgrade-preservation")
            check_application(installed(), manifest, expected)
            require(before == capture_state(), "upgrade changed credentials, configuration or storage")
            fixture_preservation(before_fixture, fixture("read", run_id), "upgrade", report)
            backup_dir = Path(site["backup"]["directory"])
            if not backup_dir.is_absolute():
                backup_dir = site_path.parent / backup_dir
            receipts = [json.loads(path.read_bytes()) for path in backup_dir.glob("*.tar.gz.enc.json")]
            backups = [x for x in receipts if x.get("format") == "gsj.backup/1" and x.get("verified") is True
                       and x.get("release_identity") == source_descriptor["releaseId"]
                       and x.get("operation") == installed()["operation"]]
            require(len(backups) == 1, "populated upgrade has no unique verified source backup")
            mark("full-populated-source-to-target-upgrade")
            mark("source-backup-and-preservation")
            phase("selected-upgrade-repeat")
            upgrade(source, descriptor["version"])
            check_application(installed(), manifest, expected)
            require(before == capture_state(), "repeated upgrade changed credentials, configuration or storage")
            fixture_preservation(before_fixture, fixture("read", run_id), "repeated-upgrade", report)
            mark("selected-version-repeat-converges")
            phase("hard-restart")
            report["restart"] = hard_restart(run_id)
            phase("hard-restart-preservation")
            fixture_preservation(before_fixture, fixture("read", run_id), "hard-restart", report)
            mark("hard-restart-cookie-and-attempt")
            phase("restore-preflight")
            # Source restore is performed by that exact shipped source installer
            # into an empty target; the accepted installer then upgrades it and
            # re-runs its complete ordinary acceptance. No manual Helm path.
            archive = Path(backups[0]["archive"])
            require(archive.is_file(), "verified restore archive is missing")
            original_context, original_namespace, original_release = context, namespace, release
            site_path = site_path.parent.parent / "restore/site.json"
            site = read_site(site_path)
            context, namespace, release = (site["target"][key] for key in ("context", "namespace", "release"))
            require(namespace == original_namespace and release == original_release and context != original_context,
                    "restore profile requires a distinct disposable context preserving namespace/release identity")
            require(not k("get", "namespace", namespace, "-o", "json", "--ignore-not-found").strip(),
                    "restore qualification refuses an existing target namespace")
            report["release_readback"]["restore"] = release_readback(source, target, site_path, "restore")
            save(args.report, report)
            phase("source-restore")
            run("bash", source / "gsj-install.sh", "restore", "--archive", archive,
                "--config", site_path, "--non-interactive")
            site = read_site(site_path, (context, namespace, release))
            namespace_uid = json.loads(k("get", "namespace", namespace, "-o", "json"))["metadata"]["uid"]
            owned_namespaces.append((context, namespace, namespace_uid))
            require(namespace_uid != before["namespace_uid"], "restore reused the source namespace")
            require(installed()["manifest"]["identity"] == source_descriptor["releaseId"], "restored source identity differs")
            phase("restore-preservation")
            fixture_preservation(before_fixture, fixture("read", run_id), "restore", report)
            restored = capture_state()
            require(restored["credentials"] == before["credentials"], "restore changed credential bytes")
            phase("restored-selected-upgrade")
            upgrade(source, descriptor["version"])
            check_application(installed(), manifest, expected)
            require(restored == capture_state(), "restored source upgrade changed credentials or storage")
            fixture_preservation(before_fixture, fixture("read", run_id), "restored-upgrade", report)
            mark("fresh-restore-to-target-acceptance")
        report["status"] = "passed"
    except BaseException as exc:
        report["status"] = "interrupted" if isinstance(exc, (KeyboardInterrupt, SystemExit)) else "failed"
        report["failure_phase"] = report.get("phase", "unknown")
        report["error_type"] = type(exc).__name__
        save(args.report, report)
    finally:
        if owned_namespaces:
            report["disposable_target_cleanup"] = "in-progress"
            try:
                for owned_context, owned_namespace, owned_uid in reversed(owned_namespaces):
                    # Each wait can outlive a cancelled job; keep the report current.
                    save(args.report, report)
                    delete_owned_namespace(owned_context, owned_namespace, owned_uid)
                report["disposable_target_cleanup"] = "passed"
            except Exception:
                report["disposable_target_cleanup"] = "failed"
                report["status"] = "failed"
        else:
            report["disposable_target_cleanup"] = "unproven"
            report["status"] = "failed"
        report["elapsed_seconds"] = round(time.monotonic() - start, 2)
        save(args.report, report)
        for number, handler in previous.items():
            signal.signal(number, handler)
    require(report["status"] == "passed", "qualification did not pass every required phase")


def check_initializer_qualification(directory, manifest):
    """The initializer qualification (ci/qualify-initializer.py) beside the
    release output: passed, run on the manifest's own web and chroma images by
    digest, and the (initialize.py, corpus.py) pair it measured inside the
    image registered in startup-runtime-preflight.py. Registering a pair
    records a claim; this report is what backs it."""
    import importlib.util
    path = directory / "initializer-qualification.json"
    require(path.is_file(), "the initializer qualification report is missing (ci/qualify-initializer.py)")
    report = json.loads(path.read_bytes())
    require(report.get("schema") == "gsj.initializer-qualification/1" and report.get("status") == "passed",
            "the initializer qualification did not pass")
    for name in ("web", "chroma"):
        image = manifest["images"][name]
        ran = (report.get("images") or {}).get(name) or {}
        require(ran.get("digest") == f"{image['repository']}@{image['digest']}" and ran.get("local") is False,
                f"the initializer qualification did not run on the release's {name} image by digest")
    pair = report.get("pair") or {}
    spec = importlib.util.spec_from_file_location("gsj_startup_runtime_preflight", ROOT / "ops/installer/startup-runtime-preflight.py")
    registry = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(registry)
    require(pair.get("registered") is True
            and (pair.get("initialize_sha256"), pair.get("corpus_sha256")) in registry.QUALIFIED_SOURCE_RUNTIMES,
            "the initializer pair the qualification measured is not a registered runtime")
    cases = report.get("cases") or {}
    require(all(isinstance(cases.get(name), dict) and cases[name].get("status") == "passed"
                for name in ("import", "readback", "core", "block", "restage", "restage-valid")), "an initializer qualification case did not pass")


def gate(directory, reports):
    descriptor = bundle(directory)
    require(descriptor.get("qualification") is False, "qualification-only artifact cannot be publicly released")
    manifest = json.loads((directory / "manifest.json").read_bytes())
    canonical = (json.dumps(manifest, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode()
    require(hashlib.sha256(canonical).hexdigest() == descriptor["manifestSha256"], "public manifest differs from its signed descriptor")
    inventory = json.loads((directory / "image-inventory.json").read_bytes())
    require(inventory.get("all_remote_manifests_verified") is True and inventory.get("images") == manifest["images"]
            and set(inventory["images"]) == {"web", "runner", "mcp", "forgejo", "chroma", "decisionsData"},
            "complete current-build image inventory is missing")
    required = {"ordinary": {"fresh-full-corpus-install", "same-bundle-repeat"},
                "upgrade": {"populated-source-created", "full-populated-source-to-target-upgrade", "source-backup-and-preservation",
                            "selected-version-repeat-converges", "hard-restart-cookie-and-attempt", "fresh-restore-to-target-acceptance"}}
    require(len(reports) == 2, "both installer qualification reports are required")
    check_initializer_qualification(directory, manifest)
    seen = set()
    for path in reports:
        report = json.loads(path.read_bytes())
        mode = report.get("mode")
        require(mode in required and mode not in seen, "duplicate or unknown qualification mode")
        seen.add(mode)
        require(report.get("schema") == "gsj.installer-qualification/1" and report.get("status") == "passed"
                and report.get("disposable_target_cleanup") == "passed"
                and report.get("installer_sha256") == descriptor["installer"]["sha256"]
                and report.get("release_identity") == descriptor["releaseId"], "qualification report does not bind the candidate bytes")
        require(len(report.get("checks", [])) == len(required[mode])
                and {x["name"] for x in report["checks"] if x.get("status") == "passed"} == required[mode],
                "required installer qualification was skipped or failed")
        if mode == "upgrade":
            from hardfault import TARGETS, validate_receipt
            restart = report.get("restart", {})
            require(restart.get("cookie_invalidated") is True
                    and restart.get("interrupted_attempt_disclosed") is True
                    and re.fullmatch(r"[a-f0-9]{32}", restart.get("attempt_id", ""))
                    and restart.get("exit_codes") == dict.fromkeys(TARGETS, 137),
                    "hard restart cookie, interrupted-attempt or SIGKILL exit evidence is missing")
            validate_receipt(restart.get("fault", {}), manifest["images"], restart.get("pod_uid"))
            source = report.get("upgrade_source", {})
            require(source.get("entrypoint") == "source-installer upgrade --to VERSION"
                    and source.get("requested_target_version") == descriptor["version"]
                    and isinstance(source.get("version"), str) and source["version"] != descriptor["version"]
                    and isinstance(source.get("release_identity"), str)
                    and source["release_identity"] != descriptor["releaseId"]
                    and source["release_identity"] in manifest.get("supported_sources", [])
                    and isinstance(source.get("installer_sha256"), str)
                    and len(source["installer_sha256"]) == 64
                    and all(c in "0123456789abcdef" for c in source["installer_sha256"])
                    and source["installer_sha256"] != descriptor["installer"]["sha256"],
                    "selected-version upgrade source evidence is missing or invalid")
            check_fixture_contract(report.get("populated_fixture", {}))
            fingerprint = report["populated_fixture"].get("snapshot_sha256", "")
            require(isinstance(fingerprint, str) and len(fingerprint) == 64
                    and all(c in "0123456789abcdef" for c in fingerprint),
                    "populated fixture snapshot identity is missing")
            readbacks = report.get("release_readback", {})
            require(set(readbacks) == {"upgrade", "restore"}, "both qualification release readbacks are required")
            staged = json.loads((directory / "staging.json").read_bytes())
            for profile, receipt in readbacks.items():
                check_release_readback(receipt, staged, profile)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "run", "gate"))
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--mode", choices=("ordinary", "upgrade"))
    parser.add_argument("--report", type=Path, action="append", default=[])
    parser.add_argument("--disposable-target", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if args.command == "prepare":
            prepare(args.output.resolve())
        elif args.command == "gate":
            gate(args.bundle.resolve(), args.report)
        else:
            require(len(args.report) == 1, "one report path required")
            args.report = args.report[0]
            qualify(args)
    except Refused as exc:
        # This harness's own refusal sentences (release.Refused) are said in
        # words: they carry no URL, token or file content.
        print("Installer qualification failed: " + str(exc), file=sys.stderr)
        raise SystemExit(1)
    except Exception as exc:
        print("Installer qualification failed: " + type(exc).__name__, file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
