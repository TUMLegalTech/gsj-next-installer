"""Drive the real wizard through a controlling terminal, using a fake cluster."""
import fcntl
import json
import os
import pty
import select
import shutil
import subprocess
import termios
import time

import pytest

from tests.test_installer import INSTALLER, runtime  # noqa: F401


def test_wizard_discovers_missing_addons_and_saves_protected_reusable_inputs(runtime):
    _, _, work = runtime
    payload = work / "payload"
    payload.mkdir()
    for name in ("defaults.json", "site.schema.json", "validate.jq"):
        shutil.copyfile(INSTALLER / name, payload / name)
    config = work / "site-input.json"
    script = '''source "$TEST_FUNCTIONS"
GSJ_WORK="$TEST_WORK"; GSJ_PAYLOAD="$TEST_WORK/payload"; CONFIG="$TEST_CONFIG"; CONTEXT_ARG=''
kubectl() {
 case "$*" in
  'config current-context') printf synthetic-context;;
  *'get nodes -o json') printf '%s' '{"items":[{"metadata":{"name":"synthetic-control-plane"}}]}';;
  *'get storageclasses -o json') printf '%s' '{"items":[]}';;
  *'get ingressclasses -o json') printf '%s' '{"items":[]}';;
  *) return 99;;
 esac
}
wizard
'''
    master, slave = pty.openpty()
    def terminal():
        os.setsid()
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)
    process = subprocess.Popen(["bash", "-c", script], stdin=slave, stdout=slave, stderr=slave,
                               env={**os.environ, "TEST_FUNCTIONS": str(work.parent / "functions.sh"),
                                    "TEST_WORK": str(work), "TEST_CONFIG": str(config)},
                               preexec_fn=terminal)
    os.close(slave)
    transcript, pending = bytearray(), bytearray()
    answered = []
    deadline = time.monotonic()+60
    try:
        while process.poll() is None and time.monotonic() < deadline:
            if not select.select([master], [], [], 0.2)[0]:
                continue
            try:
                chunk = os.read(master, 65536)
            except OSError:
                break
            transcript.extend(chunk)
            pending.extend(chunk)
            prompt = bytes(pending).decode(errors="replace")
            if not prompt.endswith(": "):
                continue
            answer = ""
            if "Initial operator password:" in prompt:
                answer = "synthetic-hidden-password"
            elif "llm API key:" in prompt:
                answer = "synthetic-hidden-api-key"
            elif "llm authentication (" in prompt:
                answer = "enter"
            elif "llm.base_url [" in prompt:
                answer = "https://llm.example/v1"
            elif "llm.model [" in prompt:
                answer = "synthetic-model"
            elif "ocr.url [" in prompt:
                answer = "https://ocr.example/v1/chat/completions"
            elif "public_url [" in prompt:
                # The removed sandbox branch used to derive this from
                # GSJ_SANDBOX_NAME. An operator answers it, so the test
                # answers it too.
                answer = "https://legal.example"
            elif "Backup directory outside" in prompt:
                answer = str(work / "off-cluster-backups")
            answered.append(prompt)
            os.write(master, (answer+"\n").encode())
            pending.clear()
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=5)
    finally:
        os.close(master)
        if process.poll() is None:
            process.kill()
            process.wait()
    assert process.returncode == 0, transcript.decode(errors="replace")
    site = json.loads(config.read_text())
    assert site["target"]["context"] == "synthetic-context"
    assert site["storage"]["profile"] == "managed-local-path"
    assert site["storage"]["node"] == "synthetic-control-plane"
    assert site["ingress"]["profile"] == "managed-traefik"
    # The deleted sandbox branch used to derive the service type, the TLS
    # profile, the public URL and the verification host. Discovery never
    # touched them, so only the operator's own answer survives here; the
    # rest keep their schema defaults. service_type is read in exactly one
    # place (the managed-traefik branch), and OPERATOR.md already tells the
    # operator to pick NodePort where no load-balancer implementation exists.
    assert site["ingress"]["service_type"] == "LoadBalancer"
    assert site["public_url"] == "https://legal.example"
    assert site["llm"]["allowed_origins"] == ["https://llm.example"]
    assert site["ocr"]["credential"] == {"file": "", "secret": ""}
    for file, expected in ((site["operator"]["password_file"], b"synthetic-hidden-password"),
                           (site["llm"]["credential"]["file"], b"synthetic-hidden-api-key")):
        from pathlib import Path
        path = Path(file)
        assert path.read_bytes() == expected
        assert path.stat().st_mode & 0o077 == 0
        assert expected not in transcript
        assert expected not in config.read_bytes()
    assert config.stat().st_mode & 0o077 == 0
    assert any("authentication" in prompt for prompt in answered)


def _workload(kind, namespace, name, image):
    return {"kind": kind, "metadata": {"namespace": namespace, "name": name},
            "spec": {"template": {"spec": {"containers": [{"name": "main", "image": image}]}}}}


NGINX = _workload("Deployment", "ingress-nginx", "ingress-nginx-controller",
                  "registry.k8s.io/ingress-nginx/controller:v1.12.1@sha256:" + "c" * 64)
BUNDLED_TRAEFIK = _workload("Deployment", "kube-system", "traefik", "rancher/mirrored-library-traefik:3.3.6")


@pytest.mark.parametrize("controller,annotation,workloads,expected", [
    # the controller's Pods run in its own namespace; no Helm annotation on the class
    ("k8s.io/ingress-nginx", None, [BUNDLED_TRAEFIK, NGINX], "ingress-nginx"),
    # the class's Helm record names another namespace than the one the Pods run in
    ("traefik.io/ingress-controller", "platform-charts",
     [_workload("DaemonSet", "edge", "edge-proxy", "docker.io/library/traefik:v3.3.6"), NGINX], "edge"),
    # no controller of the class's family: the Helm annotation, then the default
    ("haproxy.org/ingress-controller/haproxy", "haproxy-controller", [NGINX], "haproxy-controller"),
    ("projectcontour.io/ingress-controller", None, [NGINX], "gsj-ingress"),
    # two of the family in two namespaces decide nothing
    ("k8s.io/ingress-nginx", "helm-home",
     [NGINX, _workload("Deployment", "second", "ingress-nginx-controller", "registry.k8s.io/ingress-nginx/controller:v1.12.1")],
     "helm-home"),
    # the workloads cannot be listed: the annotation still answers
    ("k8s.io/ingress-nginx", "helm-home", None, "helm-home"),
])
def test_wizard_takes_the_ingress_namespace_from_where_the_class_s_controller_runs(runtime, controller, annotation,
                                                                                  workloads, expected):
    """With exactly one IngressClass, ingress.namespace is the namespace the
    application's NetworkPolicy admits, so it must be where the controller's
    Pods run: the Deployment or DaemonSet inspect recognizes as a controller
    whose image is of the class's family. The class's Helm release namespace
    names where its chart was recorded, and a class installed from plain
    manifests has none; both are only the fallback now."""
    run, _, work = runtime
    shutil.copyfile(INSTALLER / "defaults.json", work / "wizard.json")
    ingress_class = {"metadata": {"name": "edge-class", **({"annotations": {"meta.helm.sh/release-namespace": annotation}}
                                                           if annotation else {})},
                     "spec": {"controller": controller}}
    result = run('''WIZARD="$TEST_WORK/wizard.json"
kubectl() {
 case "$*" in
  *'get nodes -o json') printf '%s' '{"items":[]}';;
  *'get storageclasses -o json') printf '%s' '{"items":[{"metadata":{"name":"local-path"}}]}';;
  *'get ingressclasses -o json') printf '%s' "$TEST_CLASSES";;
  *'get deployments,daemonsets -A -o json') [[ -n $TEST_WORKLOADS ]] || { echo 'Error from server (Forbidden)' >&2; return 1; }; printf '%s' "$TEST_WORKLOADS";;
  *) return 99;;
 esac
}
wizard_discover synthetic-context
''', TEST_CLASSES=json.dumps({"items": [ingress_class]}),
                 TEST_WORKLOADS="" if workloads is None else json.dumps({"items": workloads}))
    assert result.returncode == 0, result.stderr
    site = json.loads((work / "wizard.json").read_text())
    assert site["ingress"]["class"] == "edge-class"
    assert site["ingress"]["namespace"] == expected
    assert "Forbidden" not in result.stderr
