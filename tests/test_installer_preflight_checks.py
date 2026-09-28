"""test_installer_preflight_checks — what an install or an upgrade reads about
the site's own references before the Lease.

Each condition here used to be met only after the Lease had been taken -- by
managed_dependencies (the TLS Secret, the certificate files), by secret_file
(the operator Secret, which an upgrade reached after its backup had already
quiesced the application) or by managed_helm_addon (leftover add-on CRDs) --
or hours in, at the acceptance check (a controller namespace that holds no
controller, a host another Ingress already serves, an expired certificate).
Each is now a named refusal before the first write, or, where the check cannot
be made or decides nothing on its own, a logged line. Every test asserts that
no write reached the cluster, and the recovery verbs are exempt.
"""
import base64
import json
import os
import subprocess

import pytest

from tests.test_installer import _runtime

WRITES = ("create", "replace", "apply", "delete", "scale", "exec", "patch", "label")
HOST = "legal.example"                        # _site()'s public_url host
NAMESPACE = "synthetic-namespace"             # the runtime fixture's target namespace
CLASS = "gsj-ingress"                         # _site()'s ingress.class
VERSIONS = {"clientVersion": {"gitVersion": "v1.33.1"}, "serverVersion": {"gitVersion": "v1.33.6+k3s1"}}
PASSWORD = "synthetic-operator-password"
OWNER = "a" * 40

# The shared fake answers `get pods`, and `get ingresses` without -A, with
# every object in the cluster whatever namespace kubectl was given, a named
# `get secret` by its name alone, and under namespace_absent every namespace as
# absent, so a check that read the wrong namespace would pass on it. This front
# keeps that namespace: a list holds only the objects that live there (-A lists
# them all), a Secret is found only in the namespace _cluster keyed it under,
# and namespace_absent names the namespaces that do not exist, every other one
# does (read -o name, as preflight_site_checks reads it). Every call still
# reaches the shared fake, which records it.
NAMESPACED = '''#!/usr/bin/env python3
import json, os, pathlib, subprocess, sys
args, namespace = sys.argv[1:], "default"
while args and args[0] in ("--context", "--namespace", "-n"):
    namespace = namespace if args[0] == "--context" else args[1]
    args = args[2:]
answer = subprocess.run([@SHARED@, *sys.argv[1:]], stdout=subprocess.PIPE)
listed, code = answer.stdout, answer.returncode
state = json.loads(pathlib.Path(os.environ["TEST_KUBECTL_STATE"]).read_text())
named = args[:1] == ["get"] and len(args) > 2 and not args[2].startswith("-")
missing = b"", 0 if "--ignore-not-found" in args else 1
if code == 0 and args[:2] in (["get", "pods"], ["get", "ingresses"]) and not {"-A", "--all-namespaces"} & set(args):
    document = json.loads(listed)
    document["items"] = [o for o in document["items"] if o["metadata"].get("namespace", "default") == namespace]
    listed = json.dumps(document).encode()
elif named and args[1] in ("secret", "secrets"):
    found = state.get("resources", {}).get("Secret/" + namespace + "/" + args[2])
    listed, code = (json.dumps(found).encode(), 0) if found else missing
elif named and args[1] == "namespace" and "namespace_absent" in state and not state.get("namespace_read_fails"):
    listed, code = missing if args[2] in state["namespace_absent"] else (f"namespace/{args[2]}".encode(), 0)
sys.stdout.buffer.write(listed)
sys.exit(code)
'''


@pytest.fixture
def runtime(tmp_path):
    run, state, work = _runtime(tmp_path)
    fake = tmp_path / "bin" / "kubectl"
    shared = fake.rename(tmp_path / "bin" / "kubectl-shared")
    fake.write_text(NAMESPACED.replace("@SHARED@", repr(str(shared))))
    fake.chmod(0o755)
    return run, state, work


def _b64(data):
    return base64.b64encode(data if isinstance(data, bytes) else data.encode()).decode()


def _openssl(*args):
    subprocess.run(["openssl", *map(str, args)], check=True, capture_output=True)


def _self_signed(tmp_path, name, host=HOST):
    key, crt = tmp_path / f"{name}.key", tmp_path / f"{name}.crt"
    _openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", f"/CN={host}",
             "-addext", f"subjectAltName=DNS:{host}", "-keyout", key, "-out", crt)
    key.chmod(0o600)
    return crt, key


def _expired(tmp_path):
    """A certificate for HOST whose validity ended in 2020. `openssl ca` takes
    explicit dates on every OpenSSL 3; req's -not_after needs 3.4."""
    directory = tmp_path / "expired"; directory.mkdir()
    key, csr, crt = directory / "tls.key", directory / "tls.csr", directory / "tls.crt"
    _openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={HOST}", "-keyout", key, "-out", csr)
    (directory / "index.txt").write_text("")
    (directory / "serial").write_text("01\n")
    (directory / "ca.cnf").write_text(
        f"[ca]\ndefault_ca=d\n[d]\ndatabase={directory}/index.txt\nnew_certs_dir={directory}\n"
        f"serial={directory}/serial\ndefault_md=sha256\npolicy=p\nx509_extensions=e\n"
        f"[p]\ncommonName=supplied\n[e]\nsubjectAltName=DNS:{HOST}\n")
    _openssl("ca", "-batch", "-config", directory / "ca.cnf", "-selfsign", "-keyfile", key, "-in", csr,
             "-startdate", "20200101000000Z", "-enddate", "20200201000000Z", "-notext", "-out", crt)
    return crt, key


def _authority(tmp_path, name):
    key, crt = tmp_path / f"{name}.key", tmp_path / f"{name}.crt"
    _openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", f"/CN={name}",
             "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
             "-keyout", key, "-out", crt)
    return crt, key


def _issued(tmp_path, ca_crt, ca_key):
    """A leaf for HOST with the extensions strict verification requires."""
    key, csr, crt, ext = (tmp_path / f"leaf.{s}" for s in ("key", "csr", "crt", "ext"))
    _openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={HOST}", "-keyout", key, "-out", csr)
    ext.write_text(f"subjectAltName=DNS:{HOST}\nbasicConstraints=critical,CA:FALSE\n"
                   "keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n"
                   "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n")
    _openssl("x509", "-req", "-in", csr, "-CA", ca_crt, "-CAkey", ca_key, "-CAcreateserial", "-days", "1",
             "-sha256", "-extfile", ext, "-out", crt)
    return crt, key


def _intermediate(tmp_path, ca_crt, ca_key):
    """An authority issued by ca_crt, with the extensions strict verification
    requires of a CA that is not self-signed."""
    key, csr, crt, ext = (tmp_path / f"intermediate.{s}" for s in ("key", "csr", "crt", "ext"))
    _openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=intermediate-ca", "-keyout", key, "-out", csr)
    ext.write_text("basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n"
                   "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n")
    _openssl("x509", "-req", "-in", csr, "-CA", ca_crt, "-CAkey", ca_key, "-CAcreateserial", "-days", "1",
             "-sha256", "-extfile", ext, "-out", crt)
    return crt, key


def _tls_secret(crt, key, kind="kubernetes.io/tls", name="gsj-tls", namespace=NAMESPACE):
    return {"apiVersion": "v1", "kind": "Secret", "type": kind, "metadata": {"name": name, "namespace": namespace},
            "data": {"tls.crt": _b64(crt.read_bytes()), "tls.key": _b64(key.read_bytes())}}


def _operator_secret(password, namespace=NAMESPACE):
    return {"apiVersion": "v1", "kind": "Secret", "type": "Opaque", "metadata": {"name": "gsj-operator", "namespace": namespace},
            "data": {"password": _b64(password)}}


def _pod(name, image, phase="Running", namespace="gsj-ingress"):
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "namespace": namespace},
            "spec": {"containers": [{"name": "main", "image": image}]}, "status": {"phase": phase}}


CONTROLLER = _pod("ingress-nginx-controller-5d8f7c", "registry.k8s.io/ingress-nginx/controller:v1.12.1")


def _ingress(namespace, name, host, class_name=None, annotated=None):
    """class_name is spec.ingressClassName; annotated is the older
    kubernetes.io/ingress.class annotation."""
    ingress = {"apiVersion": "networking.k8s.io/v1", "kind": "Ingress", "metadata": {"name": name, "namespace": namespace},
               "spec": {"rules": [{"host": host}]}}
    if class_name:
        ingress["spec"]["ingressClassName"] = class_name
    if annotated:
        ingress["metadata"]["annotations"] = {"kubernetes.io/ingress.class": annotated}
    return ingress


def _site(work, change=None):
    site = json.loads((work / "site.json").read_text())
    if change:
        change(site)
    (work / "site.json").write_text(json.dumps(site))


def _cluster(state, *objects, **flags):
    """Keyed by namespace too where an object has one, so two Ingresses of one
    name in two namespaces are two objects. Every Secret names its namespace:
    the front finds one only there, so a Secret without one would pass a
    refusal test as missing for no reason the test meant."""
    assert all(o["metadata"].get("namespace") for o in objects if o["kind"] == "Secret"), objects
    state.write_text(json.dumps({"lease": None, "calls": [], **flags, "resources": {
        "/".join(filter(None, (o["kind"], o["metadata"].get("namespace"), o["metadata"]["name"]))): o for o in objects}}))


def _baseline(tmp_path, state, work, *objects, password=PASSWORD + "\n", **flags):
    """A site that matches its cluster: the TLS Secret for HOST, a running
    ingress controller in ingress.namespace, the operator password file."""
    crt, key = _self_signed(tmp_path, "served")
    (work / "operator-password").write_text(password)
    (work / "operator-password").chmod(0o600)
    _cluster(state, _tls_secret(crt, key), CONTROLLER, *objects, **flags)


def _checks(run, versions=VERSIONS, before=""):
    return run(before + 'OP_PASSWORD="$TEST_WORK/operator-password"\n'
               'preflight_site_checks "$TEST_VERSIONS" && echo ADMITTED\n', TEST_VERSIONS=json.dumps(versions))


def _no_write(state):
    calls = json.loads(state.read_text())["calls"]
    assert not [c for c in calls if c[:1] and c[0] in WRITES], calls


def _admitted(result, state):
    assert result.returncode == 0 and "ADMITTED" in result.stdout, result.stderr
    _no_write(state)


def _logged(result, anchor, *words):
    """The one log line that carries anchor, holding every word."""
    lines = [l for l in result.stderr.splitlines() if anchor in l and not l.startswith("GSJ:")]
    assert len(lines) == 1, result.stderr
    for word in words:
        assert word in lines[0], (word, lines[0])
    assert "https://" not in lines[0], lines[0]
    return lines[0]


def _refusal(result, state, *words):
    assert result.returncode != 0 and "ADMITTED" not in result.stdout, result.stderr
    line = [l for l in result.stderr.splitlines() if l.startswith("GSJ:")][-1]
    for word in words:
        assert word in line, (word, line)
    assert "https://" not in line, line
    _no_write(state)
    return line


def test_a_site_that_matches_its_cluster_passes_every_check_without_a_write(runtime, tmp_path):
    run, state, work = runtime
    _baseline(tmp_path, state, work, _operator_secret(PASSWORD), _ingress("synthetic-namespace", "synthetic-release-web", HOST),
              password=PASSWORD + "\n\n")
    result = _checks(run)
    _admitted(result, state)
    assert result.stderr == "", "a matching site logs nothing"


# --- tls.profile existing: the Secret, its host, its expiry ---------------------------

@pytest.mark.parametrize("secret", ["gsj-tls", "public-certificate"])
def test_a_missing_tls_secret_is_refused_with_the_way_to_create_it(runtime, tmp_path, secret):
    """The copy recipe reads a Secret of any name in another namespace and
    creates it under tls.secret here."""
    run, state, work = runtime
    _baseline(tmp_path, state, work)
    _site(work, lambda s: s["tls"].update(secret=secret))
    _cluster(state, CONTROLLER)
    line = _refusal(_checks(run), state, "TLS Secret is unavailable", secret, "synthetic-namespace",
                    "kubectl create namespace synthetic-namespace",
                    f"kubectl -n OTHER get secret NAME -o json | jq '{{apiVersion,kind,type,data,metadata:{{name:\"{secret}\"}}}}'"
                    " | kubectl -n synthetic-namespace create -f -")
    assert line.index("TLS Secret is unavailable") == len("GSJ: ")
    assert "name:.metadata.name" not in line, "the copy is made under tls.secret whatever the source Secret is named"


@pytest.mark.parametrize("change", ["type", "key", "crt"])
def test_an_incomplete_tls_secret_is_refused(runtime, tmp_path, change):
    run, state, work = runtime
    _baseline(tmp_path, state, work)
    crt, key = _self_signed(tmp_path, "incomplete")
    secret = _tls_secret(crt, key, kind="Opaque" if change == "type" else "kubernetes.io/tls")
    if change == "key":
        secret["data"]["tls.key"] = ""
    if change == "crt":
        secret["data"]["tls.crt"] = _b64("not a certificate")
    _cluster(state, secret, CONTROLLER)
    _refusal(_checks(run), state, "TLS Secret is incomplete", "gsj-tls", "synthetic-namespace")


# Under tls.profile existing the ruled check is that the Secret exists, of its
# type and with both keys. A site whose TLS terminates at a proxy in front of
# the cluster may keep a placeholder certificate in it, for another host or
# long expired, and must keep installing and upgrading: those two are said,
# and the run goes on. Where the controller does serve that certificate, the
# installer's own public HTTPS check (curl, verifying) meets it before the
# Pod's acceptance check does, and stops the run with its own refusal.
PUBLIC_CHECK = ("the install stops, hours in, at the installer's own public HTTPS check",
                "public HTTPS route is unreachable")

def test_a_tls_secret_for_another_host_is_warned_about_without_repeating_the_certificate(runtime, tmp_path):
    run, state, work = runtime
    _baseline(tmp_path, state, work)
    crt, key = _self_signed(tmp_path, "other", host="other.example")
    _cluster(state, _tls_secret(crt, key), CONTROLLER)
    result = _checks(run)
    _admitted(result, state)
    line = _logged(result, "does not name public_url's host", "Secret gsj-tls", "synthetic-namespace", HOST,
                   *PUBLIC_CHECK, "a proxy in front of the cluster", "The run goes on")
    assert "origin-tls-failed" not in line, line
    assert "other.example" not in result.stderr


def test_an_expired_tls_secret_is_warned_about_and_not_also_as_a_chain(runtime, tmp_path):
    run, state, work = runtime
    _baseline(tmp_path, state, work)
    crt, key = _expired(tmp_path)
    _cluster(state, _tls_secret(crt, key), CONTROLLER)
    _site(work, lambda s: s["verification"].update(ca_file=str(crt)))
    result = _checks(run)
    _admitted(result, state)
    line = _logged(result, "is past its expiry date", "Secret gsj-tls", "synthetic-namespace", HOST,
                   *PUBLIC_CHECK, "a proxy in front of the cluster", "The run goes on")
    assert "origin-tls-failed" not in line, line
    assert "2020" not in result.stderr, "the certificate's own dates are not repeated"
    assert "strict verification" not in result.stderr, "an expired certificate needs a current one, not another CA"


@pytest.mark.parametrize("trusted", [True, False])
def test_a_certificate_that_fails_strict_verification_is_warned_about_not_refused(runtime, tmp_path, trusted):
    run, state, work = runtime
    _baseline(tmp_path, state, work)
    ca_crt, ca_key = _authority(tmp_path, "synthetic-ca")
    other_crt, _ = _authority(tmp_path, "other-ca")
    crt, key = _issued(tmp_path, ca_crt, ca_key)
    _cluster(state, _tls_secret(crt, key), CONTROLLER)
    _site(work, lambda s: s["verification"].update(ca_file=str(ca_crt if trusted else other_crt)))
    result = _checks(run)
    _admitted(result, state)
    if trusted:
        assert "origin-tls-failed" not in result.stderr, result.stderr
    else:
        assert "origin-tls-failed" in result.stderr and "strict" in result.stderr, result.stderr


def _chain(tmp_path):
    """tls.crt as a controller serves it: the leaf for HOST first, then the
    certificate that issued it."""
    ca_crt, ca_key = _authority(tmp_path, "chain-ca")
    crt, key = _issued(tmp_path, ca_crt, ca_key)
    chain = tmp_path / "chain.crt"
    chain.write_bytes(crt.read_bytes() + ca_crt.read_bytes())
    return chain, key, ca_crt


def test_a_ca_file_holding_the_issuing_intermediate_passes_strict_verification(runtime, tmp_path):
    """The acceptance check's Python (3.13 on) sets VERIFY_X509_PARTIAL_CHAIN
    in its default context, so a CA file holding only the intermediate that
    issued the certificate is trusted there; openssl verify reaches the same
    verdict only with -partial_chain."""
    run, state, work = runtime
    _baseline(tmp_path, state, work)
    root_crt, root_key = _authority(tmp_path, "root-ca")
    middle_crt, middle_key = _intermediate(tmp_path, root_crt, root_key)
    crt, key = _issued(tmp_path, middle_crt, middle_key)
    served = tmp_path / "served-chain.crt"
    served.write_bytes(crt.read_bytes() + middle_crt.read_bytes())
    _cluster(state, _tls_secret(served, key), CONTROLLER)
    _site(work, lambda s: s["verification"].update(ca_file=str(middle_crt)))
    result = _checks(run)
    _admitted(result, state)
    assert "strict verification" not in result.stderr, result.stderr


@pytest.mark.parametrize("profile", ["existing", "files"])
def test_a_certificate_followed_by_its_chain_is_judged_by_its_leaf(runtime, tmp_path, profile):
    run, state, work = runtime
    _baseline(tmp_path, state, work)
    chain, key, ca_crt = _chain(tmp_path)
    if profile == "files":
        _files_site(work, chain, key)
        _cluster(state, CONTROLLER)
    else:
        _cluster(state, _tls_secret(chain, key), CONTROLLER)
    _site(work, lambda s: s["verification"].update(ca_file=str(ca_crt)))
    result = _checks(run)
    _admitted(result, state)
    assert "origin-tls-failed" not in result.stderr, result.stderr


def test_a_tls_secret_that_lives_only_in_ingress_namespace_is_refused_as_missing_in_the_target_namespace(runtime, tmp_path):
    """The Ingress names tls.secret in target.namespace, the one namespace
    managed_dependencies reads it from; the same name elsewhere is not it."""
    run, state, work = runtime
    _baseline(tmp_path, state, work)
    crt, key = _self_signed(tmp_path, "elsewhere")
    _cluster(state, _tls_secret(crt, key, namespace="gsj-ingress"), CONTROLLER)
    _refusal(_checks(run), state, "TLS Secret is unavailable", f"namespace {NAMESPACE} holds none of that name")


# --- tls.profile files: the file, its host, an existing Secret ------------------------

def _files_site(work, crt, key):
    (work / "tls.crt").write_bytes(crt.read_bytes())
    (work / "tls.key").write_bytes(key.read_bytes()); (work / "tls.key").chmod(0o600)
    _site(work, lambda s: s["tls"].update(profile="files", certificate_file="tls.crt", private_key_file="tls.key"))


@pytest.mark.parametrize("existing", ["absent", "equal"])
def test_certificate_files_for_the_host_pass_and_nothing_is_created(runtime, tmp_path, existing):
    run, state, work = runtime
    _baseline(tmp_path, state, work)
    crt, key = _self_signed(tmp_path, "files")
    _files_site(work, crt, key)
    _cluster(state, CONTROLLER, *([_tls_secret(crt, key)] if existing == "equal" else []))
    _admitted(_checks(run), state)


def test_an_unreadable_certificate_file_is_refused_before_the_lease(runtime, tmp_path):
    run, state, work = runtime
    _baseline(tmp_path, state, work)
    crt, key = _self_signed(tmp_path, "files")
    _files_site(work, crt, key)
    (work / "tls.crt").write_text("not a certificate\n")
    _refusal(_checks(run), state, "tls.certificate_file is not a readable PEM certificate")


@pytest.mark.parametrize("existing", ["absent", "equal"])
@pytest.mark.parametrize("field, name", [("tls.certificate_file", "tls.crt"), ("tls.private_key_file", "tls.key")])
def test_a_certificate_or_key_file_this_account_cannot_read_is_refused_by_name(runtime, tmp_path, field, name, existing):
    """Refused as unreadable, with the remedy, rather than as no certificate or
    as a Secret that differs; and jq's words about the file are not printed."""
    if os.geteuid() == 0:
        pytest.skip("root reads every file")
    run, state, work = runtime
    _baseline(tmp_path, state, work)
    crt, key = _self_signed(tmp_path, "files")
    _files_site(work, crt, key)
    _cluster(state, CONTROLLER, *([_tls_secret(crt, key)] if existing == "equal" else []))
    (work / name).chmod(0)
    result = _checks(run)
    line = _refusal(result, state, f"{field} ({name}) cannot be read by the account that runs the installer",
                    "run the same command again")
    if field == "tls.private_key_file":
        assert "0600 or 0400" in line, line
    assert "not a readable PEM certificate" not in result.stderr and "differs from supplied credential" not in result.stderr
    assert "jq:" not in result.stderr and "Permission denied" not in result.stderr, result.stderr


def test_a_certificate_file_for_another_host_is_refused_before_the_lease(runtime, tmp_path):
    run, state, work = runtime
    _baseline(tmp_path, state, work)
    crt, key = _self_signed(tmp_path, "files", host="other.example")
    _files_site(work, crt, key)
    result = _checks(run)
    _refusal(result, state, "TLS certificate host mismatch", "tls.certificate_file", HOST)
    assert "other.example" not in result.stderr


def test_an_existing_tls_secret_that_differs_from_the_files_is_refused_with_secret_file_s_words(runtime, tmp_path):
    run, state, work = runtime
    _baseline(tmp_path, state, work)
    crt, key = _self_signed(tmp_path, "files")
    served_crt, served_key = _self_signed(tmp_path, "renewed")
    _files_site(work, crt, key)
    _cluster(state, _tls_secret(served_crt, served_key), CONTROLLER)
    _refusal(_checks(run), state,
             "Secret gsj-tls differs from supplied credential; use explicit credential repair/rotation, never implicit overwrite")


# --- ingress.profile reuse: the controller's namespace --------------------------------

@pytest.mark.parametrize("name, image, recognized", [
    ("edge-7f9c", "docker.io/library/traefik:v3.3.6", True),            # by its image alone
    ("haproxy-edge-7f9c", "registry.example/edge/proxy:2.9", True),     # by its name alone
    ("edge-7f9c", "registry.example/edge/proxy:2.9", False)])           # by neither
def test_a_controller_is_recognized_by_its_name_or_its_image_alone(runtime, tmp_path, name, image, recognized):
    run, state, work = runtime
    _baseline(tmp_path, state, work)
    crt, key = _self_signed(tmp_path, "served2")
    _cluster(state, _tls_secret(crt, key), _pod(name, image))
    result = _checks(run)
    _admitted(result, state)
    if recognized:
        assert result.stderr == "", result.stderr
    else:
        line = _logged(result, "ingress.namespace gsj-ingress holds 1 Running Pod(s)", "none of them is an ingress controller",
                       "The run goes on")
        assert name not in line and "registry.example" not in line, line


def test_an_ingress_namespace_that_does_not_exist_is_refused_while_the_target_namespace_exists(runtime, tmp_path):
    run, state, work = runtime
    _baseline(tmp_path, state, work, namespace_absent=["gsj-ingress"])
    _refusal(_checks(run), state, "ingress.namespace gsj-ingress does not exist", "kubectl get pods -A")


def test_a_target_namespace_that_does_not_exist_yet_is_not_read_as_ingress_namespace(runtime, tmp_path):
    """A first install creates target.namespace under the Lease; the namespace
    that must already exist is ingress.namespace, read by its own name."""
    run, state, work = runtime
    _baseline(tmp_path, state, work)
    crt, key = _self_signed(tmp_path, "files")
    _files_site(work, crt, key)
    _cluster(state, CONTROLLER, namespace_absent=[NAMESPACE])
    _admitted(_checks(run), state)


def test_an_ingress_namespace_without_a_running_pod_is_refused_by_counts(runtime, tmp_path):
    run, state, work = runtime
    _baseline(tmp_path, state, work)
    crt, key = _self_signed(tmp_path, "served2")
    _cluster(state, _tls_secret(crt, key), _pod("migrate-7xk2q", "docker.io/library/postgres:16", phase="Succeeded"),
             _pod("ingress-nginx-controller-5d8f7c", "registry.k8s.io/ingress-nginx/controller:v1.12.1", phase="Pending"))
    _refusal(_checks(run), state, "ingress.namespace gsj-ingress runs no ingress controller", "no Running Pod",
             "2 Pod(s) in all", "NetworkPolicy", "kubectl get pods -A")


def test_an_empty_ingress_namespace_is_refused(runtime, tmp_path):
    run, state, work = runtime
    _baseline(tmp_path, state, work)
    crt, key = _self_signed(tmp_path, "served2")
    _cluster(state, _tls_secret(crt, key))
    _refusal(_checks(run), state, "ingress.namespace gsj-ingress runs no ingress controller", "no Running Pod", "0 Pod(s) in all")


def test_a_controller_that_runs_outside_ingress_namespace_is_not_counted_for_it(runtime, tmp_path):
    """The Pods are read in ingress.namespace alone: a controller in another
    namespace is not what the application's NetworkPolicy admits."""
    run, state, work = runtime
    _baseline(tmp_path, state, work)
    crt, key = _self_signed(tmp_path, "served2")
    _cluster(state, _tls_secret(crt, key), _pod("ingress-nginx-controller-5d8f7c",
                                                "registry.k8s.io/ingress-nginx/controller:v1.12.1", namespace="ingress-nginx"))
    _refusal(_checks(run), state, "ingress.namespace gsj-ingress runs no ingress controller", "no Running Pod", "0 Pod(s) in all")


# Controllers whose Pods carry none of the names and images the rule knows:
# Kong's controller image, and OpenShift's router, whose image is a release
# payload digest. Each is recognized by the IngressClass that names it.
KONG = _pod("kong-controller-6c4f9d", "kong/kubernetes-ingress-controller:3.4")
ROUTER = _pod("router-default-5b7c9d", "quay.io/openshift-release-dev/ocp-v4.0-art-dev@sha256:" + "c" * 64,
              namespace="openshift-ingress")
CONTROLLERS = {"kong": ("konghq.com/ingress-controller", KONG), "router": ("openshift.io/ingress-to-route", ROUTER)}


def _reused(tmp_path, state, work, controller, ingress_class):
    """ingress.namespace holding only `controller`'s Pod, and the IngressClass
    preflight saved naming `ingress_class`'s controller (None: no class)."""
    pod = CONTROLLERS[controller][1]
    _baseline(tmp_path, state, work)
    crt, key = _self_signed(tmp_path, "served2")
    _cluster(state, _tls_secret(crt, key), pod)
    _site(work, lambda s: s["ingress"].update(namespace=pod["metadata"]["namespace"]))
    if ingress_class:
        (work / "ingress-class.json").write_text(json.dumps({
            "apiVersion": "networking.k8s.io/v1", "kind": "IngressClass", "metadata": {"name": "gsj-ingress"},
            "spec": {"controller": CONTROLLERS[ingress_class][0]}}))
    return pod["metadata"]["namespace"]


@pytest.mark.parametrize("controller, ingress_class", [("kong", None), ("kong", "router"), ("router", None), ("router", "kong")])
def test_running_pods_no_rule_recognizes_are_warned_about_and_passed(runtime, tmp_path, controller, ingress_class):
    """A site behind a controller the rule does not know works, and must keep
    installing and upgrading. The application's NetworkPolicy admits the
    whole namespace, so it is said, and the run goes on."""
    run, state, work = runtime
    namespace = _reused(tmp_path, state, work, controller, ingress_class)
    result = _checks(run)
    _admitted(result, state)
    line = _logged(result, f"ingress.namespace {namespace} holds 1 Running Pod(s)", "none of them is an ingress controller",
                   "admits every Pod in that namespace", "public HTTPS route check", "The run goes on")
    assert CONTROLLERS[controller][1]["metadata"]["name"] not in line and "konghq" not in line and "openshift.io" not in line, line


@pytest.mark.parametrize("controller", sorted(CONTROLLERS))
def test_a_controller_its_ingress_class_names_is_recognized_without_a_warning(runtime, tmp_path, controller):
    run, state, work = runtime
    _reused(tmp_path, state, work, controller, controller)
    result = _checks(run)
    _admitted(result, state)
    assert "Running Pod" not in result.stderr, result.stderr


def test_a_reused_controller_in_the_target_namespace_itself_is_checked_there(runtime, tmp_path):
    run, state, work = runtime
    _baseline(tmp_path, state, work, _pod("ingress-nginx-controller-5d8f7c", "registry.k8s.io/ingress-nginx/controller:v1.12.1",
                                          namespace="synthetic-namespace"))
    _site(work, lambda s: s["ingress"].update(namespace="synthetic-namespace"))
    result = _checks(run)
    _admitted(result, state)
    assert "Running Pod" not in result.stderr, result.stderr
    calls = json.loads(state.read_text())["calls"]
    assert ["get", "namespace", "synthetic-namespace", "-o", "name", "--ignore-not-found"] in calls, calls


def test_managed_traefik_in_the_target_namespace_is_refused_before_the_lease(runtime, tmp_path):
    """managed_helm_addon installs an add-on only in a namespace of its own and
    refused this one after the Lease."""
    run, state, work = runtime
    _baseline(tmp_path, state, work)
    _site(work, lambda s: s["ingress"].update(profile="managed-traefik", namespace="synthetic-namespace"))
    _refusal(_checks(run, before=_addon_reads({"items": []}, {"items": []}, {"items": []})), state,
             "ingress.namespace synthetic-namespace", "managed-traefik", "a namespace of its own",
             "run the same command again")


@pytest.mark.parametrize("unreadable", ["namespace", "pods"])
def test_an_ingress_namespace_this_credential_cannot_read_is_logged_and_passed(runtime, tmp_path, unreadable):
    run, state, work = runtime
    _baseline(tmp_path, state, work, namespace_read_fails=unreadable == "namespace")
    before = ('kubectl() { case "$*" in *"get pods -o json") echo "Error from server (Forbidden): crafted text" >&2; return 1;;'
              ' *) command kubectl "$@";; esac; }\n') if unreadable == "pods" else ""
    result = _checks(run, before=before)
    _admitted(result, state)
    assert "gsj-ingress was not checked" in result.stderr and "crafted text" not in result.stderr, result.stderr


# --- a host another Ingress already serves --------------------------------------------

def test_an_ingress_of_another_deployment_on_the_same_host_is_refused_by_name(runtime, tmp_path):
    run, state, work = runtime
    _baseline(tmp_path, state, work, _ingress("synthetic-namespace", "synthetic-release-web", HOST),
              _ingress("other-namespace", "other-web", HOST, CLASS), _ingress("third", "third-web", "elsewhere.example", CLASS))
    line = _refusal(_checks(run), state, "is already served by Ingress other-namespace/other-web",
                    "two deployments cannot share one host", "public_url")
    assert "synthetic-release-web" not in line and "third-web" not in line


@pytest.mark.parametrize("marked", ["field", "annotation"])
def test_an_ingress_of_this_site_s_ingress_class_on_the_host_is_refused(runtime, tmp_path, marked):
    run, state, work = runtime
    _baseline(tmp_path, state, work, _ingress("other-namespace", "other-web", HOST,
                                              **{"class_name" if marked == "field" else "annotated": "gsj-ingress"}))
    _refusal(_checks(run), state, "is already served by Ingress other-namespace/other-web", "ingress.class gsj-ingress",
             "two deployments cannot share one host")


def _saved_class(work, default):
    """The IngressClass preflight saved for ingress.class under reuse; default
    is its ingressclass.kubernetes.io/is-default-class annotation (None:
    none)."""
    annotations = {} if default is None else {"ingressclass.kubernetes.io/is-default-class": default}
    (work / "ingress-class.json").write_text(json.dumps({
        "apiVersion": "networking.k8s.io/v1", "kind": "IngressClass",
        "metadata": {"name": CLASS, "annotations": annotations}, "spec": {"controller": "k8s.io/ingress-nginx"}}))


def test_an_ingress_of_no_class_on_the_host_is_refused_when_this_site_s_class_is_the_cluster_default(runtime, tmp_path):
    """A class-less Ingress goes to the cluster's default class, which is
    this site's here, so this site's controller serves it."""
    run, state, work = runtime
    _baseline(tmp_path, state, work, _ingress("other-namespace", "other-web", HOST))
    _saved_class(work, "true")
    result = _checks(run)
    _refusal(result, state, "is already served by Ingress other-namespace/other-web", "or of no class",
             "the cluster's default ingress class")
    assert "another controller" not in result.stderr, result.stderr


@pytest.mark.parametrize("default", [None, "false", "True"])
def test_an_ingress_of_no_class_on_the_host_is_logged_when_a_reused_class_is_not_the_cluster_default(runtime, tmp_path, default):
    """The default class takes a class-less Ingress, and the annotation marks
    it only as the exact string "true": short of that it is no collision. The
    log line said nothing routed to it here, but a reused controller can serve
    class-less Ingresses without being marked the default (OpenShift's
    ingress-to-route turns them into Routes), so it says that one may."""
    run, state, work = runtime
    _baseline(tmp_path, state, work, _ingress("other-namespace", "other-web", HOST))
    _saved_class(work, default)
    result = _checks(run)
    _admitted(result, state)
    _logged(result, "also named by Ingress other-namespace/other-web", f"public_url's host {HOST}", "of no ingress class",
            "may still be served by this site's controller if that controller serves Ingresses without a class",
            "The run goes on")
    assert "nothing routes to it here" not in result.stderr and "another controller's" not in result.stderr, result.stderr
    assert "already served" not in result.stderr, result.stderr


def test_an_ingress_of_no_class_on_the_host_is_logged_under_managed_traefik(runtime, tmp_path):
    """The managed Traefik is never the default class and serves its own class
    alone, whatever IngressClass an earlier reuse run saved."""
    run, state, work = runtime
    _baseline(tmp_path, state, work, _ingress("other-namespace", "other-web", HOST))
    _saved_class(work, "true")
    _site(work, MANAGED["traefik"])
    result = _checks(run, before=_addon_reads({"items": []}, {"items": []}, {"items": []}))
    _admitted(result, state)
    _logged(result, "also served by another controller's Ingress other-namespace/other-web", "nothing routes to it here",
            "The run goes on")
    assert "already served" not in result.stderr, result.stderr


def test_an_ingress_of_the_managed_traefik_s_class_on_the_host_is_refused(runtime, tmp_path):
    run, state, work = runtime
    _baseline(tmp_path, state, work, _ingress("other-namespace", "other-web", HOST, CLASS))
    _site(work, MANAGED["traefik"])
    _refusal(_checks(run, before=_addon_reads({"items": []}, {"items": []}, {"items": []})), state,
             "is already served by Ingress other-namespace/other-web", "ingress.class gsj-ingress")


@pytest.mark.parametrize("marked", ["field", "annotation"])
def test_an_ingress_of_another_class_on_the_host_is_logged_and_passed(runtime, tmp_path, marked):
    """Another controller serves it; this site's controller routes nothing to
    it, so it is named in a log line and the run goes on."""
    run, state, work = runtime
    _baseline(tmp_path, state, work, _ingress("other-namespace", "other-web", HOST,
                                              **{"class_name" if marked == "field" else "annotated": "nginx-public"}))
    result = _checks(run)
    _admitted(result, state)
    line = _logged(result, "also served by another controller's Ingress other-namespace/other-web", f"public_url's host {HOST}",
                   "nothing routes to it here", "The run goes on")
    assert "nginx-public" not in line and "already served" not in result.stderr, line


def test_ingresses_of_this_class_and_of_another_on_the_host_are_refused_and_logged_apart(runtime, tmp_path):
    run, state, work = runtime
    _baseline(tmp_path, state, work, _ingress("other-namespace", "other-web", HOST, class_name="nginx-public"),
              _ingress("third", "third-web", HOST, class_name="gsj-ingress"))
    result = _checks(run)
    line = _refusal(result, state, "is already served by Ingress third/third-web")
    assert "other-namespace/other-web" not in line, line
    _logged(result, "also served by another controller's Ingress other-namespace/other-web", "nothing routes to it here")


def test_the_deployment_s_own_ingress_name_in_another_namespace_is_a_collision(runtime, tmp_path):
    """Only this deployment's own namespace and name is exempt."""
    run, state, work = runtime
    _baseline(tmp_path, state, work, _ingress("synthetic-namespace", "synthetic-release-web", HOST),
              _ingress("other-namespace", "synthetic-release-web", HOST, CLASS))
    line = _refusal(_checks(run), state, "is already served by Ingress other-namespace/synthetic-release-web")
    assert "synthetic-namespace/" not in line, line


def _solver(namespace, name, labelled=True):
    """cert-manager gives its solver the class the issuer names: this site's."""
    ingress = _ingress(namespace, name, HOST, CLASS)
    if labelled:
        ingress["metadata"]["labels"] = {"acme.cert-manager.io/http01-solver": "true"}
    return ingress


@pytest.mark.parametrize("passing", ["solver", "deleting"])
def test_an_acme_solver_or_a_deleting_ingress_on_the_host_is_not_a_collision(runtime, tmp_path, passing):
    """cert-manager's HTTP-01 solver serves public_url's host from the
    deployment's own namespace while a renewal is pending, and removing it
    would fight cert-manager; an Ingress being deleted is on its way out."""
    run, state, work = runtime
    if passing == "solver":
        other = _solver("synthetic-namespace", "cm-acme-http-solver-x7k2p")
    else:
        other = _ingress("other-namespace", "other-web", HOST, CLASS)
        other["metadata"]["deletionTimestamp"] = "2026-01-01T00:00:00Z"
    _baseline(tmp_path, state, work, _ingress("synthetic-namespace", "synthetic-release-web", HOST), other)
    _admitted(_checks(run), state)


def test_an_ingress_named_like_a_solver_without_its_label_is_a_collision(runtime, tmp_path):
    run, state, work = runtime
    _baseline(tmp_path, state, work, _solver("other-namespace", "cm-acme-http-solver-x7k2p", labelled=False))
    _refusal(_checks(run), state, "is already served by Ingress other-namespace/cm-acme-http-solver-x7k2p")


def test_an_ingress_list_this_credential_may_not_read_is_logged_and_passed(runtime, tmp_path):
    run, state, work = runtime
    _baseline(tmp_path, state, work, _ingress("other-namespace", "other-web", HOST))
    result = _checks(run, before='kubectl() { case "$*" in *"get ingresses -A -o json") echo "crafted text" >&2; return 1;;'
                                 ' *) command kubectl "$@";; esac; }\n')
    _admitted(result, state)
    assert "was not checked" in result.stderr and "crafted text" not in result.stderr, result.stderr


def test_a_public_url_with_a_port_is_checked_by_its_host_alone(runtime, tmp_path):
    run, state, work = runtime
    _baseline(tmp_path, state, work, _ingress("other-namespace", "other-web", HOST, CLASS))
    _site(work, lambda s: s.update(public_url=f"https://{HOST}:30443/"))
    line = _refusal(_checks(run), state, f"public_url's host {HOST} is already served by Ingress other-namespace/other-web")
    assert "30443" not in line


def test_ingresses_without_rules_or_hosts_are_passed_over(runtime, tmp_path):
    run, state, work = runtime
    marked = {"kubernetes.io/ingress.class": CLASS}
    bare = {"apiVersion": "networking.k8s.io/v1", "kind": "Ingress",
            "metadata": {"name": "bare", "namespace": "third", "annotations": marked}}
    backend = {**bare, "metadata": {"name": "backend", "namespace": "third", "annotations": marked},
               "spec": {"defaultBackend": {"service": {"name": "x"}}}}
    hostless = {**bare, "metadata": {"name": "hostless", "namespace": "third", "annotations": marked},
                "spec": {"rules": [{"http": {"paths": []}}]}}
    _baseline(tmp_path, state, work, bare, backend, hostless)
    _admitted(_checks(run), state)
    _baseline(tmp_path, state, work, bare, backend, hostless, _ingress("other-namespace", "other-web", HOST, CLASS))
    line = _refusal(_checks(run), state, "is already served by Ingress other-namespace/other-web")
    assert "third/" not in line, line


# --- the operator Secret -------------------------------------------------------------

def test_an_operator_secret_that_differs_from_the_password_file_is_refused_with_secret_file_s_words(runtime, tmp_path):
    run, state, work = runtime
    _baseline(tmp_path, state, work, _operator_secret("the-previous-password"))
    result = _checks(run)
    _refusal(result, state, "Secret gsj-operator differs from supplied credential; use explicit credential repair/rotation, never implicit overwrite")
    assert PASSWORD not in result.stderr and "the-previous-password" not in result.stderr


@pytest.mark.parametrize("namespace", ["gsj-ingress", "other-namespace"])
def test_an_operator_secret_that_lives_only_in_another_namespace_is_not_compared(runtime, tmp_path, namespace):
    """secret_file creates and compares the operator Secret in target.namespace
    alone: one of that name elsewhere, holding another password, is another
    deployment's and stops nothing."""
    run, state, work = runtime
    _baseline(tmp_path, state, work, _operator_secret("the-previous-password", namespace=namespace))
    result = _checks(run)
    _admitted(result, state)
    assert result.stderr == "", result.stderr


def test_an_operator_password_with_a_control_character_is_refused(runtime, tmp_path):
    run, state, work = runtime
    _baseline(tmp_path, state, work, password="synthetic\tpassword\n")
    result = _checks(run)
    _refusal(result, state, "operator.password_file", "control character")
    assert "\tpassword" not in result.stderr


def test_an_operator_password_file_this_account_cannot_read_is_refused_by_name(runtime, tmp_path):
    if os.geteuid() == 0:
        pytest.skip("root reads every file")
    run, state, work = runtime
    _baseline(tmp_path, state, work, _operator_secret(PASSWORD))
    (work / "operator-password").chmod(0)
    result = _checks(run)
    _refusal(result, state, "operator.password_file (operator-password) cannot be read by the account that runs the installer",
             "0600 or 0400", "run the same command again")
    assert "control character" not in result.stderr and "differs from supplied credential" not in result.stderr
    assert "jq:" not in result.stderr and "Permission denied" not in result.stderr, result.stderr


@pytest.mark.parametrize("read, kept", [("-Rs", "preflight-operator-password.err"), ("--rawfile crt", "preflight-tls-files.err")])
def test_what_jq_says_about_a_site_file_is_kept_in_the_state_directory_not_printed(runtime, tmp_path, read, kept):
    """A jq that fails on a file it could open (a stand-in here) prints its
    words into a private file, not onto the terminal."""
    run, state, work = runtime
    _baseline(tmp_path, state, work)
    crt, key = _self_signed(tmp_path, "files")
    _files_site(work, crt, key)
    _cluster(state, CONTROLLER, _tls_secret(crt, key))
    result = _checks(run, before=f'jq() {{ if [[ " $* " == *" {read} "* ]]; then echo "jq: crafted text" >&2; return 2; fi; command jq "$@"; }}\n')
    _refusal(result, state)
    assert "crafted text" not in result.stderr, result.stderr
    assert "crafted text" in (work / kept).read_text()
    assert (work / kept).stat().st_mode & 0o777 == 0o600


# --- leftover managed add-on CRDs ------------------------------------------------------

def _crd(name, owner=OWNER):
    """A CRD's name is its plural and its API group, and spec.group is the group."""
    return {"metadata": {"name": name, "labels": {"gsj.io/addon-owner": owner}}, "spec": {"group": name.split(".", 1)[1]}}


def _addon_reads(crds, records, homes):
    """kubectl for the three add-on reads; every other call reaches the fake."""
    return ('kubectl() { case "$*" in\n'
            '  *"get customresourcedefinitions -l gsj.io/addon-owner -o json") printf x >> "$TEST_WORK/crd-reads"; ' +
            ('return 1;;\n' if crds is None else f"printf '%s' '{json.dumps(crds)}';;\n") +
            f'  *"get configmaps -A -l gsj.io/addon-owner={OWNER} -o json") printf \'%s\' \'{json.dumps(records)}\';;\n'
            f'  *"get namespaces -l gsj.io/addon-owner={OWNER} -o json") printf \'%s\' \'{json.dumps(homes)}\';;\n'
            '  *) command kubectl "$@";; esac; }\n')


MANAGED = {"traefik": lambda s: s["ingress"].update(profile="managed-traefik"),
           "acme": lambda s: s["tls"].update(profile="managed-acme")}
# Each add-on's CRD groups, as the pinned charts render them (traefik.io and
# hub.traefik.io; cert-manager.io and acme.cert-manager.io) and as an earlier
# Traefik chart did (traefik.containo.us), and the namespace it lives in.
LEFTOVERS = {"traefik": ["ingressroutes.traefik.io", "accesscontrolpolicies.hub.traefik.io", "middlewares.traefik.containo.us"],
             "acme": ["certificates.cert-manager.io", "orders.acme.cert-manager.io"]}
HOMES = {"traefik": "gsj-ingress", "acme": "gsj-cert-manager"}
OTHER = {"traefik": "acme", "acme": "traefik"}


def _leftovers(addon, owner=OWNER):
    return [_crd(name, owner) for name in LEFTOVERS[addon]]


@pytest.mark.parametrize("profile", sorted(MANAGED))
def test_leftover_crds_of_the_selected_add_on_without_an_owner_record_are_refused_with_their_teardown(runtime, tmp_path, profile):
    run, state, work = runtime
    _baseline(tmp_path, state, work)
    _site(work, MANAGED[profile])
    names, home = LEFTOVERS[profile], HOMES[profile]
    line = _refusal(_checks(run, before=_addon_reads({"items": _leftovers(profile)}, {"items": []},
                                                     {"items": [{"metadata": {"name": home}}]})), state,
                    *names, f"add-on namespace: {home}", f"helm -n {home} uninstall", f"kubectl delete namespace {home}",
                    f"kubectl get {names[0]} -A", "kubectl delete customresourcedefinition " + " ".join(names),
                    "deletes nothing")
    assert line.startswith("GSJ: managed add-on CustomResourceDefinitions"), line


@pytest.mark.parametrize("profile", sorted(MANAGED))
def test_leftover_crds_of_an_add_on_the_site_does_not_select_are_named_in_a_log_line_and_passed(runtime, tmp_path, profile):
    """managed_helm_addon collides only with the CRDs of the chart it renders,
    so the other add-on's leftovers stop nothing: they are named, with the same
    teardown, and the run goes on."""
    run, state, work = runtime
    _baseline(tmp_path, state, work)
    _site(work, MANAGED[profile])
    other = OTHER[profile]
    names, home = LEFTOVERS[other], HOMES[other]
    result = _checks(run, before=_addon_reads({"items": _leftovers(other)}, {"items": []},
                                              {"items": [{"metadata": {"name": home}}]}))
    _admitted(result, state)
    line = [l for l in result.stderr.splitlines() if "CustomResourceDefinitions" in l][-1]
    for word in (*names, "does not select", "The run goes on", f"add-on namespace: {home}", f"helm -n {home} uninstall",
                 f"kubectl delete namespace {home}", f"kubectl get {names[0]} -A",
                 "kubectl delete customresourcedefinition " + " ".join(names), "deletes nothing"):
        assert word in line, (word, line)


def test_a_managed_traefik_site_refuses_leftover_traefik_crds_and_only_names_leftover_cert_manager_ones(runtime, tmp_path):
    run, state, work = runtime
    _baseline(tmp_path, state, work)
    _site(work, MANAGED["traefik"])
    crds = {"items": _leftovers("traefik") + _leftovers("acme", owner="b" * 40)}
    result = _checks(run, before=_addon_reads(crds, {"items": []}, {"items": [{"metadata": {"name": "gsj-ingress"}}]}))
    line = _refusal(result, state, *LEFTOVERS["traefik"],
                    "kubectl delete customresourcedefinition " + " ".join(LEFTOVERS["traefik"]))
    assert not any(name in line for name in LEFTOVERS["acme"]), line
    assert all(name in result.stderr for name in LEFTOVERS["acme"]), result.stderr


def test_a_group_that_only_ends_in_the_same_letters_is_not_the_add_on_s(runtime, tmp_path):
    run, state, work = runtime
    _baseline(tmp_path, state, work)
    _site(work, MANAGED["traefik"])
    _site(work, MANAGED["acme"])
    crds = {"items": [_crd("widgets.nottraefik.io"), _crd("issuers.example-cert-manager.io")]}
    result = _checks(run, before=_addon_reads(crds, {"items": []}, {"items": []}))
    _admitted(result, state)
    assert "widgets.nottraefik.io" in result.stderr and "no add-on namespace is left" in result.stderr, result.stderr


def test_add_on_crds_whose_owner_record_exists_pass(runtime, tmp_path):
    run, state, work = runtime
    _baseline(tmp_path, state, work)
    _site(work, MANAGED["traefik"])
    records = {"items": [{"metadata": {"name": "gsj-addon-owner", "namespace": "gsj-ingress",
                                       "labels": {"gsj.io/addon-owner": OWNER}}}]}
    _admitted(_checks(run, before=_addon_reads({"items": [_crd("ingressroutes.traefik.io")]}, records, {"items": []})), state)


def test_a_crd_list_this_credential_may_not_read_is_logged_and_passed(runtime, tmp_path):
    run, state, work = runtime
    _baseline(tmp_path, state, work)
    _site(work, MANAGED["traefik"])
    result = _checks(run, before=_addon_reads(None, {"items": []}, {"items": []}))
    _admitted(result, state)
    assert "were not checked" in result.stderr, result.stderr


def test_a_site_that_selects_no_managed_add_on_does_not_list_crds(runtime, tmp_path):
    run, state, work = runtime
    _baseline(tmp_path, state, work)
    _admitted(_checks(run, before=_addon_reads({"items": [_crd("ingressroutes.traefik.io")]}, {"items": []}, {"items": []})), state)
    assert not (work / "crd-reads").exists()


# --- kubectl's distance from the server -------------------------------------------------

SKEWED = {"clientVersion": {"gitVersion": "v1.30.2"}, "serverVersion": {"gitVersion": "v1.33.6+k3s1"}}


@pytest.mark.parametrize("fetched", ["helm kubectl jq", "kubectl"])
def test_a_fetched_kubectl_more_than_one_minor_from_the_server_is_refused(runtime, tmp_path, fetched):
    """The remedy works on a machine with no kubectl of its own, or one below
    the floor, where client_preflight points at --fetch-tools=kubectl: every
    --fetch-tools that fetches kubectl brings this same pin back, so a kubectl
    within one minor is installed here first."""
    run, state, work = runtime
    _baseline(tmp_path, state, work)
    line = _refusal(_checks(run, SKEWED, before=f'FETCH_SET="{fetched}"\n'), state,
                    "the kubectl --fetch-tools downloaded for this run is 1.30.2 and the server is 1.33.6",
                    "any --fetch-tools that fetches kubectl downloads it again",
                    "Install a kubectl within one minor of 1.33.6 on this machine, then run without --fetch-tools,"
                    " or with --fetch-tools=helm, which fetches only Helm and keeps this machine's kubectl")
    assert "k3s1" not in line


@pytest.mark.parametrize("fetched", ["", "helm jq"])
def test_this_machine_s_kubectl_more_than_one_minor_from_the_server_is_warned_about(runtime, tmp_path, fetched):
    run, state, work = runtime
    _baseline(tmp_path, state, work)
    result = _checks(run, SKEWED, before=f'FETCH_SET="{fetched}"\n' if fetched else "unset FETCH_SET\n")
    _admitted(result, state)
    assert "kubectl 1.30.2" in result.stderr and "1.33.6" in result.stderr and "within one minor" in result.stderr


@pytest.mark.parametrize("client, skewed", [("v1.30.2-eks-4f4795d", True), ("v1.34.0-dirty", False), ("v1.33.1+k3s1", False)])
def test_a_kubectl_version_with_a_build_suffix_is_compared_by_its_numbers(runtime, tmp_path, client, skewed):
    run, state, work = runtime
    _baseline(tmp_path, state, work)
    versions = {"clientVersion": {"gitVersion": client}, "serverVersion": {"gitVersion": "v1.33.6-gke.1024000"}}
    result = _checks(run, versions, before='FETCH_SET="kubectl"\n')
    if skewed:
        line = _refusal(result, state, "1.30.2", "1.33.6")
        assert "eks" not in line and "gke" not in line, line
    else:
        _admitted(result, state)
        assert "minor" not in result.stderr, result.stderr


@pytest.mark.parametrize("client, fetched, verdict", [
    ("v1.31.9", "kubectl", "refused"), ("v1.31.9", "", "warned"), ("v1.35.0", "kubectl", "refused"),
    ("v1.32.4", "kubectl", "silent"), ("v1.32.4", "", "silent")])
def test_the_skew_boundary_is_one_minor_either_side_of_the_server(runtime, tmp_path, client, fetched, verdict):
    run, state, work = runtime
    _baseline(tmp_path, state, work)
    versions = {"clientVersion": {"gitVersion": client}, "serverVersion": {"gitVersion": "v1.33.6+k3s1"}}
    result = _checks(run, versions, before=f'FETCH_SET="{fetched}"\n' if fetched else "unset FETCH_SET\n")
    if verdict == "refused":
        _refusal(result, state, client[1:], "1.33.6", "more than one minor apart")
    else:
        _admitted(result, state)
        assert ("within one minor" in result.stderr) is (verdict == "warned"), result.stderr


def test_a_fetched_kubectl_within_one_minor_passes_silently(runtime, tmp_path):
    run, state, work = runtime
    _baseline(tmp_path, state, work)
    close = {"clientVersion": {"gitVersion": "v1.34.0"}, "serverVersion": {"gitVersion": "v1.33.6+k3s1"}}
    result = _checks(run, close, before='FETCH_SET="kubectl"\n')
    _admitted(result, state)
    assert "minor" not in result.stderr


# --- only install and upgrade are refused on these -------------------------------------

def _preflight(run, work, command, denied=""):
    """preflight over the fake, every `auth can-i` recorded in can-i and
    answered yes but `denied`."""
    (work / "release.json").write_text(json.dumps({"platforms": ["linux/amd64"]}))
    nodes = json.dumps({"items": [{"metadata": {"name": "synthetic-node"}, "status": {"nodeInfo": {"architecture": "amd64"}}}]})
    return run(f'''GSJ_PAYLOAD="$TEST_WORK"; COMMAND={command}; OP_PASSWORD="$TEST_WORK/operator-password"
k() {{ case "$*" in
  cluster-info) return 0;;
  "version -o json") printf '%s' "$TEST_VERSIONS";;
  "auth can-i "*) printf '%s\\n' "${{*:3}}" >> "$TEST_WORK/can-i"; if [[ "${{*:3}}" == "{denied}" ]]; then printf 'no\\n'; else printf 'yes\\n'; fi;;
  "get nodes -o json") printf '%s' '{nodes}';;
  "get storageclass "*) printf '%s' '{{"provisioner":"rancher.io/local-path"}}';;
  "get ingressclass "*) printf '{{}}';;
  *) kubectl --context "$CONTEXT" --namespace "$NAMESPACE" "$@";;
esac; }}
preflight && echo ADMITTED
''', TEST_VERSIONS=json.dumps(VERSIONS))


@pytest.mark.parametrize("command", ["install", "upgrade"])
def test_preflight_refuses_install_and_upgrade_on_the_site_checks(runtime, tmp_path, command):
    run, state, work = runtime
    _baseline(tmp_path, state, work)
    _cluster(state, CONTROLLER)
    _refusal(_preflight(run, work, command), state, "TLS Secret is unavailable")


# What preflight asks `kubectl auth can-i` in the target namespace, in order.
# ReplicaSets are read to prove the initializer Pod's owner, so only the verbs
# that wait for the initializer ask for them; the others ask what the previous
# release asked, and a Role that ran them then runs them now.
PERMISSIONS = ["get pods", "create pods", "create secrets", "create configmaps", "create leases.coordination.k8s.io",
               "patch deployments.apps", "get replicasets.apps", "create jobs.batch", "get persistentvolumeclaims",
               "create persistentvolumeclaims", "create networkpolicies.networking.k8s.io"]
INITIALIZING = ["install", "upgrade", "resume", "repair", "restore", "restore-repair"]
NOT_INITIALIZING = ["backup", "backup-repair", "sweep", "abandon", "lease-repair", "credential-repair", "tls-repair",
                    "addon-repair"]


@pytest.mark.parametrize("command", INITIALIZING + NOT_INITIALIZING)
def test_preflight_asks_for_every_namespace_permission_in_its_first_seconds(runtime, tmp_path, command):
    run, state, work = runtime
    _baseline(tmp_path, state, work)
    _admitted(_preflight(run, work, command), state)
    expected = PERMISSIONS if command in INITIALIZING else [p for p in PERMISSIONS if p != "get replicasets.apps"]
    assert (work / "can-i").read_text().splitlines() == expected


@pytest.mark.parametrize("command", INITIALIZING)
def test_a_credential_that_may_not_read_replicasets_is_warned_and_runs(runtime, tmp_path, command):
    """The previous release never asked for get on replicasets.apps, so a Role
    that ran these verbs then still runs them: preflight names the missing read
    once, and the initializer wait judges the Pod by its labels instead."""
    run, state, work = runtime
    _baseline(tmp_path, state, work)
    result = _preflight(run, work, command, denied="get replicasets.apps")
    _admitted(result, state)
    _logged(result, "get replicasets.apps", "may not", "labels", "Grant")


@pytest.mark.parametrize("command", NOT_INITIALIZING)
def test_a_verb_that_never_waits_for_the_initializer_runs_without_replicasets(runtime, tmp_path, command):
    """A least-privilege Role that ran these verbs on the previous release,
    without get on replicasets.apps, still runs them."""
    run, state, work = runtime
    _baseline(tmp_path, state, work)
    _admitted(_preflight(run, work, command, denied="get replicasets.apps"), state)


EXEMPT = ["restore", "restore-repair", "backup", "backup-repair", "resume", "repair", "sweep", "abandon",
          "credential-repair", "tls-repair", "lease-repair", "addon-repair"]


@pytest.mark.parametrize("command", EXEMPT)
def test_the_recovery_verbs_are_not_refused_on_the_site_checks(runtime, tmp_path, command):
    run, state, work = runtime
    _baseline(tmp_path, state, work)
    _cluster(state, _ingress("other-namespace", "other-web", HOST, CLASS))     # no TLS Secret, the host taken
    result = _preflight(run, work, command)
    _admitted(result, state)
    calls = json.loads(state.read_text())["calls"]
    assert not [c for c in calls if c[:2] in (["get", "ingresses"], ["get", "secret"], ["get", "pods"])], calls
