"""Read-only inspector exposes useful storage facts, never arbitrary resource data."""
import json
import os
import pathlib
import shutil
import subprocess
import shlex
import sys

import pytest

from tests.test_installer import runtime  # noqa: F401


SENTINEL = "synthetic-sensitive-value-must-not-be-emitted"


def objects():
    def metadata(name, namespace=None):
        return {"name": name, "namespace": namespace, "uid": "uid-" + name,
                "annotations": {"arbitrary/provider-credential": SENTINEL},
                "labels": {"arbitrary/customer-secret": SENTINEL}}
    return {
        "nodes": {"items": [{"metadata": metadata("storage-node"), "status": {
            "nodeInfo": {"osImage": "synthetic-node-os", "architecture": "arm64", "kernelVersion": "synthetic-kernel",
                         "kubeletVersion": "v1.35.8"}, "capacity": {"cpu": "8", "memory": "16Gi"},
            "allocatable": {"cpu": "7", "memory": "15Gi"}, "conditions": [{"type": "Ready", "status": "True"}]}}]},
        "pods": {"items": [{"metadata": metadata("worker", "example"), "spec": {"nodeName": "storage-node",
            "containers": [{"name": "app", "resources": {"requests": {"cpu": "1", "memory": "1Gi"}},
                            "env": [{"name": "INLINE_SECRET", "value": SENTINEL}]}]}, "status": {"phase": "Running"}}]},
        "persistentvolumeclaims": {"items": [{"metadata": metadata("data", "example"), "spec": {
            "volumeName": "volume", "storageClassName": "local", "volumeMode": "Filesystem", "accessModes": ["ReadWriteOnce"],
            "resources": {"requests": {"storage": "10Gi"}}, "arbitrary": SENTINEL}, "status": {
            "phase": "Bound", "capacity": {"storage": "10Gi"}, "allocatedResources": {"storage": "12Gi"},
            "conditions": [{"type": "FileSystemResizePending", "status": "True", "message": SENTINEL}]}}]},
        "persistentvolumes": {"items": [{"metadata": metadata("volume"), "spec": {
            "storageClassName": "local", "volumeMode": "Filesystem", "accessModes": ["ReadWriteOnce"],
            "capacity": {"storage": "10Gi"}, "persistentVolumeReclaimPolicy": "Retain",
            "claimRef": {"name": "data", "namespace": "example", "uid": "uid-data", "kind": "PersistentVolumeClaim", "arbitrary": SENTINEL},
            "csi": {"driver": "synthetic.csi.example", "fsType": "ext4", "readOnly": False,
                    "volumeHandle": SENTINEL, "volumeAttributes": {"password": SENTINEL, "tier": SENTINEL},
                    "nodeStageSecretRef": {"name": SENTINEL}},
            "nfs": {"server": SENTINEL, "path": SENTINEL}, "local": {"path": SENTINEL},
            "nodeAffinity": {"required": {"nodeSelectorTerms": [{"matchExpressions": [
                {"key": "kubernetes.io/hostname", "operator": "In", "values": ["storage-node"]},
                {"key": "arbitrary.provider/placement", "operator": "In", "values": [SENTINEL]}],
                "matchFields": [{"key": "metadata.name", "operator": "In", "values": ["storage-node"]}]}]}}},
            "status": {"phase": "Bound", "message": SENTINEL}}]},
        "storageclasses": {"items": [{"metadata": {**metadata("local"), "annotations": {
            "storageclass.kubernetes.io/is-default-class": "true", "arbitrary/secret": SENTINEL}},
            "provisioner": "synthetic.csi.example", "reclaimPolicy": "Retain", "volumeBindingMode": "WaitForFirstConsumer",
            "allowVolumeExpansion": True, "parameters": {"password": SENTINEL, "endpoint": SENTINEL},
            "allowedTopologies": [{"matchLabelExpressions": [
                {"key": "topology.kubernetes.io/zone", "values": ["synthetic-zone"]},
                {"key": "driver.example/placement", "values": [SENTINEL]}]}]}]},
        "ingressclasses": {"items": [{"metadata": {**metadata("edge"), "annotations": {
            "ingressclass.kubernetes.io/is-default-class": "true", "arbitrary/secret": SENTINEL}},
            "spec": {"controller": "traefik.io/ingress-controller", "parameters": {"apiGroup": "example.invalid",
                "kind": "Parameters", "name": "edge-policy", "scope": "Namespace", "namespace": "example",
                "inline": SENTINEL}, "arbitrary": SENTINEL}}]},
    }


def inspect(runtime, data, unavailable=()):
    run, _, work = runtime
    source = work / "inspection-input.json"
    source.write_text(json.dumps(data))
    script = work / "inspection-kubectl.py"
    script.write_text('''import json,os,pathlib,sys
a=sys.argv[1:]
while a and a[0] in ("--context","--namespace"): a=a[2:]
if a[:1]==["version"]: print(json.dumps({"serverVersion":{"gitVersion":"v1.35.8"}}))
elif a[:2]==["top","nodes"]: raise SystemExit(1)
elif a[:1]==["get"]:
 if a[1] in json.loads(os.environ['INSPECT_UNAVAILABLE']):
  print('synthetic-sensitive-value-must-not-be-emitted',file=sys.stderr);raise SystemExit(1)
 print(json.dumps(json.loads(pathlib.Path(os.environ['INSPECT_INPUT']).read_text())[a[1]]))
else: raise SystemExit(99)
''')
    result = run(f'''
CONTEXT_ARG=synthetic-context; GSJ_PLATFORM=synthetic-installer-host
kubectl() {{ {shlex.quote(sys.executable)} {shlex.quote(str(script))} "$@"; }}
helm() {{ printf 'v4.2.2+synthetic'; }}
getconf() {{ printf '2'; }}
inspect_cluster
''', INSPECT_INPUT=str(source), INSPECT_UNAVAILABLE=json.dumps(list(unavailable)))
    assert result.returncode == 0, result.stderr
    assert SENTINEL not in result.stdout + result.stderr
    return json.loads(result.stdout)


def test_inspector_allowlist_retains_capacity_binding_driver_and_safe_topology(runtime):
    report = inspect(runtime, objects())
    assert report["installer_host"]["platform"] == "synthetic-installer-host"
    assert report["installer_host"]["cores"] == 2
    assert report["nodes"][0]["architecture"] == "arm64"
    assert report["nodes"][0]["capacity"]["cpu"] == "8"
    assert report["requested_by_pods"][0]["containers"][0]["resources"]["requests"]["memory"] == "1Gi"
    claim = report["claims"]["items"][0]
    assert claim["metadata"]["uid"] == "uid-data"
    assert claim["spec"]["volumeName"] == "volume"
    assert claim["spec"]["resources"]["requests"]["storage"] == "10Gi"
    assert claim["status"]["capacity"]["storage"] == "10Gi"
    assert claim["status"]["conditions"] == [{"type": "FileSystemResizePending", "status": "True"}]
    pv = report["volumes"]["items"][0]
    assert pv["spec"]["claimRef"]["uid"] == "uid-data"
    assert pv["spec"]["capacity"]["storage"] == "10Gi"
    assert pv["spec"]["backend_sources"] == ["csi", "local", "nfs"]
    assert pv["spec"]["csi"] == {"driver": "synthetic.csi.example", "fsType": "ext4", "readOnly": False,
                                    "volume_attribute_names": ["password", "tier"]}
    terms = pv["spec"]["nodeAffinity"]["required"]["nodeSelectorTerms"]
    assert terms[0]["matchExpressions"][0]["values"] == ["storage-node"]
    assert terms[0]["matchExpressions"][1] == {"key": "arbitrary.provider/placement", "operator": "In", "value_count": 1}
    sc = report["storage_classes"]["items"][0]
    assert sc["provisioner"] == "synthetic.csi.example" and sc["is_default"] is True
    assert sc["parameter_names"] == ["endpoint", "password"]
    assert sc["volumeBindingMode"] == "WaitForFirstConsumer" and sc["allowVolumeExpansion"] is True
    assert sc["allowedTopologies"][0]["matchLabelExpressions"][0]["values"] == ["synthetic-zone"]
    ingress = report["ingress_classes"]["items"][0]
    assert ingress["is_default"] is True and ingress["spec"]["parameters"]["name"] == "edge-policy"
    assert ingress["spec"]["controller"] == "traefik.io/ingress-controller"
    assert "Unavailable" in report["node_live_usage"]


@pytest.mark.parametrize("resource,field", [
    ("persistentvolumeclaims", "claims"), ("persistentvolumes", "volumes"),
    ("storageclasses", "storage_classes"), ("ingressclasses", "ingress_classes"),
])
def test_inspector_preserves_unavailable_api_reason_without_raw_error(runtime, resource, field):
    report = inspect(runtime, objects(), unavailable=(resource,))
    assert report[field] == {"unavailable": True, "reason": "missing access or API"}


def test_inspector_distinguishes_empty_inventory_from_unavailable(runtime):
    report = inspect(runtime, {key: {"items": []} for key in objects()})
    for name in ("claims", "volumes", "storage_classes", "ingress_classes"):
        assert report[name] == {"items": []}


# Learned from a real install: on a cluster that already runs an ingress
# controller, the ingress is a CLUSTER-PROVIDED prerequisite, not something the
# installer creates. The inventory alone made the operator read the item
# list to find that out; inspect now states the verdict outright, because a
# cluster with no ingress controller cannot serve the site at all.
def test_inspector_reports_the_cluster_provided_ingress_as_ready(runtime):
    report = inspect(runtime, objects())
    assert report["ingress_available"] == {"ready": True, "classes": ["edge"]}


def test_inspector_reports_no_cluster_ingress_when_none_is_installed(runtime):
    report = inspect(runtime, {key: {"items": []} for key in objects()})
    assert report["ingress_available"]["ready"] is False
    assert "ingress" in report["ingress_available"]["reason"]


def test_inspector_reports_ingress_readiness_unknown_when_the_api_refuses(runtime):
    report = inspect(runtime, objects(), unavailable=("ingressclasses",))
    assert report["ingress_available"] == {"ready": False, "reason": "missing access or API"}


# ---------------------------------------------------------------------------
# THE ENVIRONMENT PROFILE.
#
# The fixture above carries no Service, Ingress, Deployment, DaemonSet,
# NetworkPolicy, Namespace or CRD, so every new profile section rendered EMPTY
# and the SENTINEL never touched one of them. These objects are populated, each
# with the sentinel in the places a careless projection would pick up.
# ---------------------------------------------------------------------------


def profile_objects():
    data = objects()

    def metadata(name, namespace=None):
        return {"name": name, "namespace": namespace, "uid": "uid-" + name,
                "annotations": {"arbitrary/provider-credential": SENTINEL},
                "labels": {"arbitrary/customer-secret": SENTINEL}}

    def workload(name, namespace, image):
        return {"metadata": metadata(name, namespace), "spec": {"template": {"spec": {
            "containers": [{"name": "c", "image": image,
                            "args": [SENTINEL], "command": [SENTINEL],
                            "env": [{"name": "TOKEN", "value": SENTINEL}]}]}}}}

    data["namespaces"] = {"items": [{"metadata": metadata("kube-system")},
                                    {"metadata": metadata("tenant-alpha")}]}
    data["services"] = {"items": [
        {"metadata": metadata("edge", "ingress"), "spec": {
            "type": "LoadBalancer", "ports": [{"nodePort": 30080, "port": 80}],
            "externalIPs": [SENTINEL]},
         "status": {"loadBalancer": {"ingress": [{"ip": "10.0.0.9"}]}}},
        {"metadata": metadata("internal", "tenant-alpha"), "spec": {
            "type": "ClusterIP", "ports": [{"port": 8080}]}, "status": {"loadBalancer": {}}}]}
    data["ingresses"] = {"items": [{"metadata": metadata("site", "tenant-alpha"), "spec": {
        "rules": [{"host": "taken.example.invalid", "http": {"paths": [{"backend": SENTINEL}]}}],
        "tls": [{"hosts": ["taken.example.invalid"], "secretName": SENTINEL}]}}]}
    data["networkpolicies"] = {"items": [{"metadata": metadata("default-deny", "tenant-alpha"), "spec": {
        "policyTypes": ["Ingress"], "podSelector": {"matchLabels": {"secret": SENTINEL}}}}]}
    data["daemonsets"] = {"items": [workload("calico-node", "kube-system", "docker.io/calico/node:v3.27.0")]}
    data["deployments"] = {"items": [
        workload("ingress-nginx-controller", "ingress", "registry.k8s.io/ingress-nginx/controller:v1.11.2"),
        workload("cert-manager", "cert-manager", "quay.io/jetstack/cert-manager-controller:v1.21.2")]}
    data["customresourcedefinitions"] = {"items": [
        {"metadata": metadata("issuers.cert-manager.io"), "spec": {"group": "cert-manager.io", "names": SENTINEL}},
        {"metadata": metadata("widgets.example.invalid"), "spec": {"group": "example.invalid"}}]}
    return data


def test_profile_projects_every_new_section_without_leaking_arbitrary_values(runtime):
    """The sentinel assertion lives in inspect(); this test exists to make the
    new sections actually RENDER so that assertion has something to bite on."""
    profile = inspect(runtime, profile_objects())["profile"]
    assert profile["schema"] == "gsj.environment-profile/1"
    assert profile["networking"]["ingress"]["hosts_in_use"] == ["taken.example.invalid"]
    assert profile["networking"]["ingress"]["nodeports_allocated"] == [30080]
    assert profile["networking"]["ingress"]["load_balancer_satisfied"].startswith("yes")
    assert [w["name"] for w in profile["networking"]["cni"]["workloads"]] == ["calico-node"]
    assert profile["networking"]["cni"]["workloads"][0]["images"] == ["docker.io/calico/node:v3.27.0"]
    assert profile["networking"]["cni"]["in_process"] is False
    assert profile["networking"]["tls"]["cert_manager_present"] is True
    assert profile["occupancy"]["namespaces"] == ["kube-system", "tenant-alpha"]
    assert "cert-manager.io" in profile["occupancy"]["custom_resource_groups"]
    assert [p["name"] for p in profile["occupancy"]["network_policies"]] == ["default-deny"]
    controllers = [c["name"] for c in profile["networking"]["ingress"]["controllers"]]
    assert "ingress-nginx-controller" in controllers


def test_profile_reports_a_denied_read_as_denied_not_as_an_empty_cluster(runtime):
    """A scoped read-only token and an empty cluster must never look alike: an
    operator who reads 'no NodePorts taken' and picks 30080 has been misled."""
    report = inspect(runtime, profile_objects(), unavailable=("services", "deployments"))
    access = report["profile"]["access"]
    assert access["complete"] is False
    assert "services" in access["denied"] and "deployments" in access["denied"]
    assert "nodes" in access["readable"]
    # the Secret read is never granted by this fixture, so it must show as denied
    assert report["profile"]["occupancy"]["helm_releases_readable"] is False


def test_profile_access_is_complete_when_every_probe_answered(runtime):
    report = inspect(runtime, profile_objects())
    access = report["profile"]["access"]
    assert "services" not in access["denied"]
    assert "nodes" not in access["denied"]


def test_profile_degrades_on_api_valid_but_awkward_objects(runtime):
    """inspect promises every probe degrades rather than failing the run. Three
    shapes broke that on ordinary, API-valid input:
      - a container with no `image` (valid until defaulted) made
        `.image|split("@")` throw `split input and separator must be strings`;
      - a workload whose SECOND container also matched emitted the workload
        twice, because the disjunct was a generator, not a predicate;
      - a hand-edited local-path config with `paths` as a bare string made
        `.paths[]` throw `Cannot iterate over string`.
    """
    data = profile_objects()
    # two matching containers plus one with no image at all
    data["daemonsets"]["items"][0]["spec"]["template"]["spec"]["containers"] = [
        {"name": "a", "image": "docker.io/calico/node:v3.27.0"},
        {"name": "b", "image": "docker.io/calico/cni:v3.27.0"},
        {"name": "c"},
    ]
    data["configmap"] = {"items": [{"metadata": {"name": "local-path-config", "namespace": "kube-system"},
                                    "data": {"config.json": json.dumps(
                                        {"nodePathMap": [{"node": "DEFAULT", "paths": "/not-a-list"}]})}}]}
    report = inspect(runtime, data)
    profile = report["profile"]
    workloads = profile["networking"]["cni"]["workloads"]
    assert len(workloads) == 1, f"one workload, not one row per matching container: {workloads}"
    assert workloads[0]["images"] == [
        "docker.io/calico/node:v3.27.0", "docker.io/calico/cni:v3.27.0", ""], workloads[0]["images"]
    # and the run produced a document rather than dying
    assert profile["schema"] == "gsj.environment-profile/1"
    assert profile["storage"]["local_path_node_paths"]["known"] in (True, False)


_RELEASE_ROLLUP = r"""
[$releases|rtrimstr("\n")|split("\n")[]|select(length>0)|select(test("GSJ-DENIED")|not)|
  (split(" ")|map(select(length>0)))|select(length>=4)|
  {namespace:.[0],name:.[1],revision:.[2],status:.[3]}]
  |group_by(.namespace+"/"+.name)
  |map((max_by(.revision|tonumber? // 0)) as $latest |
       {namespace:$latest.namespace,name:$latest.name,
        revision:$latest.revision,status:$latest.status,
        revision_records:length})
"""


@pytest.mark.skipif(shutil.which("jq") is None, reason="jq not installed")
def test_helm_release_inventory_is_one_row_per_release_not_per_revision(tmp_path):
    """Helm keeps one labelled Secret per REVISION. A release with a long
    history would otherwise fill occupancy.helm_releases with one row per
    revision and bury the name collisions the field exists to show. The gap
    between `revision` and `revision_records` is signal in its own right: Helm
    prunes release Secrets to its history limit (ten by default), so a
    deployment whose revision number is past that limit shows fewer records
    than revisions. The latest revision is chosen numerically: 10 outranks 9,
    where a lexical maximum would pick 9. The values below are synthetic.

    The rollup asserted here is the one the shipped runtime.sh carries; the
    structural assertion below keeps the two from drifting apart.
    """
    rows = tmp_path / "rows.txt"
    rows.write_text("example-ns sample 8 superseded\n"
                    "example-ns sample 9 superseded\n"
                    "example-ns sample 10 deployed\n"
                    "other app 1 deployed\n")
    out = subprocess.run(["jq", "-n", "--rawfile", "releases", str(rows), _RELEASE_ROLLUP],
                         capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    releases = json.loads(out.stdout)
    assert len(releases) == 2, releases
    latest = next(r for r in releases if r["name"] == "sample")
    assert latest == {"namespace": "example-ns", "name": "sample", "revision": "10",
                      "status": "deployed", "revision_records": 3}


def test_the_shipped_rollup_matches_the_one_asserted_above():
    source = (pathlib.Path(__file__).parent.parent
              / "ops" / "installer" / "runtime.sh").read_text()
    for fragment in ("group_by(.namespace+\"/\"+.name)",
                     "max_by(.revision|tonumber? // 0)",
                     "revision_records:length"):
        assert fragment in source, f"the shipped helm rollup no longer contains: {fragment}"


@pytest.mark.skipif(shutil.which("jq") is None, reason="jq not installed")
def test_a_denied_helm_read_yields_no_rows_rather_than_a_fabricated_one(tmp_path):
    rows = tmp_path / "denied.txt"
    rows.write_text("GSJ-DENIED\n")
    out = subprocess.run(["jq", "-n", "--rawfile", "releases", str(rows), _RELEASE_ROLLUP],
                         capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert json.loads(out.stdout) == []
