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
import subprocess

import pytest

from tests.test_installer import runtime  # noqa: F401  (fixture)

WRITES = ("create", "replace", "apply", "delete", "scale", "exec", "patch", "label")
HOST = "legal.example"                        # _site()'s public_url host
VERSIONS = {"clientVersion": {"gitVersion": "v1.33.1"}, "serverVersion": {"gitVersion": "v1.33.6+k3s1"}}
PASSWORD = "synthetic-operator-password"
OWNER = "a" * 40


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


def _tls_secret(crt, key, kind="kubernetes.io/tls", name="gsj-tls"):
    return {"apiVersion": "v1", "kind": "Secret", "type": kind, "metadata": {"name": name},
            "data": {"tls.crt": _b64(crt.read_bytes()), "tls.key": _b64(key.read_bytes())}}


def _operator_secret(password):
    return {"apiVersion": "v1", "kind": "Secret", "type": "Opaque", "metadata": {"name": "gsj-operator"},
            "data": {"password": _b64(password)}}


def _pod(name, image, phase="Running", namespace="gsj-ingress"):
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "namespace": namespace},
            "spec": {"containers": [{"name": "main", "image": image}]}, "status": {"phase": phase}}


CONTROLLER = _pod("ingress-nginx-controller-5d8f7c", "registry.k8s.io/ingress-nginx/controller:v1.12.1")


def _ingress(namespace, name, host):
    return {"apiVersion": "networking.k8s.io/v1", "kind": "Ingress", "metadata": {"name": name, "namespace": namespace},
            "spec": {"rules": [{"host": host}]}}


def _site(work, change=None):
    site = json.loads((work / "site.json").read_text())
    if change:
        change(site)
    (work / "site.json").write_text(json.dumps(site))


def _cluster(state, *objects, **flags):
    state.write_text(json.dumps({"lease": None, "calls": [], **flags,
                                 "resources": {o["kind"] + "/" + o["metadata"]["name"]: o for o in objects}}))


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
    assert "kubectl" not in result.stderr, "a matching site logs nothing"


# --- tls.profile existing: the Secret, its host, its expiry ---------------------------

def test_a_missing_tls_secret_is_refused_with_the_way_to_create_it(runtime, tmp_path):
    run, state, work = runtime
    _baseline(tmp_path, state, work)
    _cluster(state, CONTROLLER)
    line = _refusal(_checks(run), state, "TLS Secret is unavailable", "gsj-tls", "synthetic-namespace",
                    "kubectl create namespace synthetic-namespace",
                    "jq '{apiVersion,kind,type,data,metadata:{name:.metadata.name}}' | kubectl -n synthetic-namespace create -f -")
    assert line.index("TLS Secret is unavailable") == len("GSJ: ")


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


def test_a_tls_secret_for_another_host_is_refused_without_repeating_the_certificate(runtime, tmp_path):
    run, state, work = runtime
    _baseline(tmp_path, state, work)
    crt, key = _self_signed(tmp_path, "other", host="other.example")
    _cluster(state, _tls_secret(crt, key), CONTROLLER)
    result = _checks(run)
    _refusal(result, state, "TLS certificate host mismatch", "gsj-tls", HOST)
    assert "other.example" not in result.stderr


def test_an_expired_tls_secret_is_refused(runtime, tmp_path):
    run, state, work = runtime
    _baseline(tmp_path, state, work)
    crt, key = _expired(tmp_path)
    _cluster(state, _tls_secret(crt, key), CONTROLLER)
    result = _checks(run)
    _refusal(result, state, "TLS certificate expired", "gsj-tls", "synthetic-namespace")
    assert "2020" not in result.stderr, "the certificate's own dates are not repeated"


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

def test_a_controller_recognized_by_its_image_alone_passes(runtime, tmp_path):
    run, state, work = runtime
    _baseline(tmp_path, state, work)
    crt, key = _self_signed(tmp_path, "served2")
    _cluster(state, _tls_secret(crt, key), _pod("edge-7f9c", "docker.io/library/traefik:v3.3.6"))
    _admitted(_checks(run), state)


def test_an_ingress_namespace_that_does_not_exist_is_refused(runtime, tmp_path):
    run, state, work = runtime
    _baseline(tmp_path, state, work, namespace_absent=True)
    _refusal(_checks(run), state, "ingress.namespace gsj-ingress does not exist", "kubectl get pods -A")


def test_an_ingress_namespace_without_a_running_controller_is_refused_by_counts(runtime, tmp_path):
    run, state, work = runtime
    _baseline(tmp_path, state, work)
    crt, key = _self_signed(tmp_path, "served2")
    _cluster(state, _tls_secret(crt, key), _pod("postgres-0", "docker.io/library/postgres:16"),
             _pod("ingress-nginx-controller-5d8f7c", "registry.k8s.io/ingress-nginx/controller:v1.12.1", phase="Pending"))
    _refusal(_checks(run), state, "ingress.namespace gsj-ingress runs no ingress controller", "2 Pod(s)", "1 of them Running",
             "NetworkPolicy")


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
              _ingress("other-namespace", "other-web", HOST), _ingress("third", "third-web", "elsewhere.example"))
    line = _refusal(_checks(run), state, "is already served by Ingress other-namespace/other-web",
                    "two deployments cannot share one host", "public_url")
    assert "synthetic-release-web" not in line and "third-web" not in line


def test_an_ingress_list_this_credential_may_not_read_is_logged_and_passed(runtime, tmp_path):
    run, state, work = runtime
    _baseline(tmp_path, state, work, _ingress("other-namespace", "other-web", HOST))
    result = _checks(run, before='kubectl() { case "$*" in *"get ingresses -A -o json") echo "crafted text" >&2; return 1;;'
                                 ' *) command kubectl "$@";; esac; }\n')
    _admitted(result, state)
    assert "was not checked" in result.stderr and "crafted text" not in result.stderr, result.stderr


# --- the operator Secret -------------------------------------------------------------

def test_an_operator_secret_that_differs_from_the_password_file_is_refused_with_secret_file_s_words(runtime, tmp_path):
    run, state, work = runtime
    _baseline(tmp_path, state, work, _operator_secret("the-previous-password"))
    result = _checks(run)
    _refusal(result, state, "Secret gsj-operator differs from supplied credential; use explicit credential repair/rotation, never implicit overwrite")
    assert PASSWORD not in result.stderr and "the-previous-password" not in result.stderr


def test_an_operator_password_with_a_control_character_is_refused(runtime, tmp_path):
    run, state, work = runtime
    _baseline(tmp_path, state, work, password="synthetic\tpassword\n")
    result = _checks(run)
    _refusal(result, state, "operator.password_file", "control character")
    assert "\tpassword" not in result.stderr


# --- leftover managed add-on CRDs ------------------------------------------------------

def _crd(name, owner=OWNER):
    return {"metadata": {"name": name, "labels": {"gsj.io/addon-owner": owner}}}


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


@pytest.mark.parametrize("profile", sorted(MANAGED))
def test_leftover_add_on_crds_without_an_owner_record_are_refused_with_their_teardown(runtime, tmp_path, profile):
    run, state, work = runtime
    _baseline(tmp_path, state, work)
    _site(work, MANAGED[profile])
    crds = {"items": [_crd("ingressroutes.traefik.io"), _crd("middlewares.traefik.io")]}
    homes = {"items": [{"metadata": {"name": "gsj-ingress"}}]}
    line = _refusal(_checks(run, before=_addon_reads(crds, {"items": []}, homes)), state,
                    "ingressroutes.traefik.io", "middlewares.traefik.io", "gsj-ingress", "helm -n gsj-ingress uninstall",
                    "kubectl delete namespace gsj-ingress", "kubectl get ingressroutes.traefik.io -A",
                    "kubectl delete customresourcedefinition ingressroutes.traefik.io middlewares.traefik.io",
                    "deletes nothing")
    assert line.startswith("GSJ: managed add-on CustomResourceDefinitions"), line


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


def test_a_fetched_kubectl_more_than_one_minor_from_the_server_is_refused(runtime, tmp_path):
    run, state, work = runtime
    _baseline(tmp_path, state, work)
    line = _refusal(_checks(run, SKEWED, before='FETCH_SET="helm kubectl jq"\n'), state,
                    "1.30.2", "1.33.6", "without --fetch-tools", "--fetch-tools=helm")
    assert "k3s1" not in line


@pytest.mark.parametrize("fetched", ["", "helm jq"])
def test_this_machine_s_kubectl_more_than_one_minor_from_the_server_is_warned_about(runtime, tmp_path, fetched):
    run, state, work = runtime
    _baseline(tmp_path, state, work)
    result = _checks(run, SKEWED, before=f'FETCH_SET="{fetched}"\n' if fetched else "unset FETCH_SET\n")
    _admitted(result, state)
    assert "kubectl 1.30.2" in result.stderr and "1.33.6" in result.stderr and "within one minor" in result.stderr


def test_a_fetched_kubectl_within_one_minor_passes_silently(runtime, tmp_path):
    run, state, work = runtime
    _baseline(tmp_path, state, work)
    close = {"clientVersion": {"gitVersion": "v1.34.0"}, "serverVersion": {"gitVersion": "v1.33.6+k3s1"}}
    result = _checks(run, close, before='FETCH_SET="kubectl"\n')
    _admitted(result, state)
    assert "minor" not in result.stderr


# --- only install and upgrade are refused on these -------------------------------------

def _preflight(run, work, command):
    (work / "release.json").write_text(json.dumps({"platforms": ["linux/amd64"]}))
    nodes = json.dumps({"items": [{"metadata": {"name": "synthetic-node"}, "status": {"nodeInfo": {"architecture": "amd64"}}}]})
    return run(f'''GSJ_PAYLOAD="$TEST_WORK"; COMMAND={command}; OP_PASSWORD="$TEST_WORK/operator-password"
k() {{ case "$*" in
  cluster-info) return 0;;
  "version -o json") printf '%s' "$TEST_VERSIONS";;
  "auth can-i "*) printf 'yes\\n';;
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


EXEMPT = ["restore", "restore-repair", "backup", "backup-repair", "resume", "repair", "sweep", "abandon",
          "credential-repair", "tls-repair", "lease-repair", "addon-repair"]


@pytest.mark.parametrize("command", EXEMPT)
def test_the_recovery_verbs_are_not_refused_on_the_site_checks(runtime, tmp_path, command):
    run, state, work = runtime
    _baseline(tmp_path, state, work)
    _cluster(state, _ingress("other-namespace", "other-web", HOST))     # no TLS Secret, the host taken
    result = _preflight(run, work, command)
    _admitted(result, state)
    calls = json.loads(state.read_text())["calls"]
    assert not [c for c in calls if c[:2] in (["get", "ingresses"], ["get", "secret"], ["get", "pods"])], calls
