#!/usr/bin/env bash
# Stand up a rehearsal cluster shaped like a consumer's, from their profile.
#
# `gsj-install.sh inspect` produces one read-only document (`profile`, schema
# gsj.environment-profile/1). This reads that document and creates a local k3d
# cluster carrying the fields that TRANSFER, so the install can be rehearsed
# before the consumer runs anything.
#
#   ops/installer/rehearsal.sh up   <profile.json> [name]
#   ops/installer/rehearsal.sh plan <profile.json>        # print, create nothing
#   ops/installer/rehearsal.sh down <name>
#
# WHAT TRANSFERS (and is therefore set here):
#   - the Kubernetes distribution and server version  -> the k3s image tag
#   - whether it is single-node                       -> server/agent counts
#   - the default StorageClass shape: provisioner, reclaim policy, binding
#     mode, and the node path local-path writes to    -> local-path-config
#   - whether an ingress controller exists, and its IngressClass name and
#     controller string                               -> an IngressClass object
#   - whether cert-manager is present
#   - the CNI, which on k3s/rke2 comes with the distribution and brings its
#     own drop-versus-reject behaviour for a denied NetworkPolicy
#   - release and namespace name collisions           -> placeholder namespaces
#
# WHAT DOES NOT TRANSFER, and cannot be faked by anything in this file:
#   - their hardware: cores, memory, disk throughput, CPU microarchitecture
#   - their network: latency, bandwidth, a corporate proxy, an egress unlock
#   - multi-node scheduling and real ReadWriteOnce contention
#   - the real free space on their filesystems, and the node-root capacity wall
#   - other tenants competing for the node, and a live deployment that must
#     not be perturbed
# A green rehearsal proves the install LOGIC, not the consumer environment.
set -Eeuo pipefail

fail() { printf 'rehearsal: %s\n' "$*" >&2; exit 1; }
note() { printf '[rehearsal] %s\n' "$*" >&2; }

read_profile() {
 [[ -f $1 ]] || fail "no such profile: $1"
 command -v jq >/dev/null || fail 'jq is required'
 jq -e '.profile.schema=="gsj.environment-profile/1"' "$1" >/dev/null \
   || fail "$1 is not a gsj.environment-profile/1 document (run: gsj-install.sh inspect)"
}

# Every value the plan needs, pulled once, with the UNKNOWNs made explicit.
plan_of() {
 jq -r '
   .profile as $p |
   ($p.kubernetes.server_version // "unknown") as $server |
   # k3d takes the k3s image tag, which spells +k3s1 as -k3s1
   ($server | sub("\\+";"-")) as $image_tag |
   ([$p.storage.classes[]? | select(.is_default)] | first) as $class |
   ([$p.networking.ingress.classes[]?] | first) as $ingress |
   {distribution: ($p.kubernetes.distribution // "unknown"),
    server_version: $server,
    k3s_image: ("rancher/k3s:" + $image_tag),
    single_node: ($p.kubernetes.single_node // true),
    node_count: ($p.kubernetes.node_count // 1),
    storage_class: ($class.name // "local-path"),
    provisioner: ($class.provisioner // "rancher.io/local-path"),
    reclaim_policy: ($class.reclaim_policy // "Delete"),
    binding_mode: ($class.binding_mode // "WaitForFirstConsumer"),
    node_local: ($class.node_local // true),
    local_path: (($p.storage.local_path_node_paths.paths // [])[0] // "unknown"),
    ingress_class: ($ingress.name // ""),
    ingress_controller: ($ingress.controller // ""),
    cert_manager: ($p.networking.tls.cert_manager_present // false),
    cni_in_process: ($p.networking.cni.in_process // false),
    namespaces: [$p.occupancy.namespaces[]? | select(. | test("^(kube-|default$)") | not)],
    releases: [$p.occupancy.helm_releases[]? | .namespace + "/" + .name] | unique,
    host_cores: ($p.host.cores // 0),
    host_memory_gib: (($p.host.memory_bytes // 0) / 1073741824 | floor)}
 ' "$1"
}

print_plan() {
 local plan=$1
 printf '\n  REHEARSAL PLAN (from the profile)\n'
 jq -r '
   "    distribution        " + .distribution + " " + .server_version,
   "    k3d image           " + .k3s_image,
   "    topology            " + (if .single_node then "single node" else (.node_count|tostring) + " nodes -- NOT reproduced, see below" end),
   "    default StorageClass " + .storage_class + "  " + .provisioner,
   "                        reclaim " + .reclaim_policy + ", binding " + .binding_mode + (if .node_local then ", node-local" else "" end),
   "    local-path writes to " + .local_path,
   "    IngressClass        " + (if .ingress_class == "" then "NONE -- the cluster provides no ingress controller" else .ingress_class + "  (" + .ingress_controller + ")" end),
   "    cert-manager        " + (if .cert_manager then "present" else "absent" end),
   "    CNI                 " + (if .cni_in_process then "the distribution built-in (k3s/rke2: flannel + kube-router), in-process" else "a CNI workload; see the profile" end),
   "    occupied namespaces " + ((.namespaces|length)|tostring) + "  " + (.namespaces|join(", ")),
   "    helm releases here  " + ((.releases|length)|tostring) + "  " + (.releases|join(", ")),
   "",
   "  NOT REPRODUCED (the profile records them; a rehearsal cannot carry them)",
   "    host cores          " + (.host_cores|tostring) + "  -- the rehearsal has whatever this machine has",
   "    host memory         " + (.host_memory_gib|tostring) + " GiB  -- likewise",
   "    filesystem free space, disk throughput, network latency, a proxy,",
   "    multi-node scheduling, other tenants, and a live deployment beside you."
 ' <<< "$plan"
 printf '\n'
}

cluster_up() {
 local plan=$1 name=$2 image tag path class controller
 command -v k3d >/dev/null || fail 'k3d is required to stand up a rehearsal cluster'
 image=$(jq -r .k3s_image <<< "$plan")
 [[ $image != rancher/k3s:unknown ]] || fail 'the profile records no server version; cannot choose a k3s image'
 # Only a genuine k3s gitVersion (vX.Y.Z+k3sN) maps onto a rancher/k3s tag that
 # exists. An EKS/GKE/AKS/kubeadm version would build a tag that does not, and
 # k3d only discovers that on the image pull -- AFTER it has created the
 # cluster's Docker network, volumes and server container, leaving a half-built
 # cluster to remove by hand. Refuse before any of that, and say what a
 # rehearsal for that distribution would and would not be worth.
 local distribution; distribution=$(jq -r .distribution <<< "$plan")
 if [[ $distribution != k3s ]]; then
   fail "this rehearsal builds k3s clusters with k3d, and the profile records distribution '$distribution' (server $(jq -r .server_version <<< "$plan")). There is no rancher/k3s image for that version, so $image would fail on the pull. Rehearse the STORAGE and INGRESS shape on the nearest k3s minor by hand, and treat the distribution itself as a difference the rehearsal does not carry -- its CNI, its admission controllers and its LoadBalancer behaviour are all its own."
 fi
 note "creating k3d cluster $name on $image"
 # --no-lb: k3d's own front proxy is not part of the consumer's shape. k3s's
 # ServiceLB stays, because the profile distinguishes a cluster that can
 # satisfy a LoadBalancer Service from one that leaves it <pending> forever.
 k3d cluster create "$name" --image "$image" --servers 1 --agents 0 --no-lb \
   --k3s-arg '--disable=traefik@server:0' --wait --timeout 600s >&2
 export KUBECONFIG; KUBECONFIG=$(k3d kubeconfig write "$name")
 # The local-path node path: the /-versus-/data difference that decided PVC
 # sizing on one measured box and transfer_path on the other.
 path=$(jq -r .local_path <<< "$plan")
 if [[ $path != unknown ]]; then
   # k3s writes local-path-config from its bundled manifests AFTER the cluster
   # reports ready, so this waits for the object rather than for a duration.
   local waited=0
   until kubectl -n kube-system get configmap local-path-config >/dev/null 2>&1; do
     (( ++waited < 120 )) || fail 'local-path-config never appeared; this k3s image may not bundle local-path'
     sleep 1
   done
   note "pointing local-path at $path (as the profile records)"
   kubectl -n kube-system get configmap local-path-config -o json \
     | jq --arg p "$path" '.data["config.json"]=({nodePathMap:[{node:"DEFAULT_PATH_FOR_NON_LISTED_NODES",paths:[$p]}]}|tojson)' \
     | kubectl apply -f - >&2
   kubectl -n kube-system rollout restart deployment local-path-provisioner >&2 2>/dev/null || true
 fi
 # The ingress controller belongs to the CLUSTER. The chart's reuse profile
 # requires the CLASS to exist; a rehearsal reproduces that shape, and says
 # plainly that no real proxy sits behind it.
 class=$(jq -r .ingress_class <<< "$plan"); controller=$(jq -r .ingress_controller <<< "$plan")
 if [[ -n $class ]]; then
   note "creating IngressClass $class ($controller) -- SHAPE ONLY, no controller behind it"
   kubectl apply -f - >&2 <<YAML
apiVersion: networking.k8s.io/v1
kind: IngressClass
metadata:
  name: $class
  annotations: {gsj.io/rehearsal: "shape only: no ingress controller is running behind this class"}
spec:
  controller: ${controller:-k8s.io/ingress-nginx}
YAML
 else
   note 'the profile records NO IngressClass; leaving this cluster without one, as theirs is'
 fi
 # Name collisions are part of the shape: a release the installer would refuse
 # to take over must be refusable here too.
 local ns
 while IFS= read -r ns; do
   [[ -n $ns ]] || continue
   kubectl get namespace "$ns" >/dev/null 2>&1 || kubectl create namespace "$ns" >&2
 done < <(jq -r '.namespaces[]?' <<< "$plan")
 note "rehearsal cluster $name is up; KUBECONFIG=$KUBECONFIG"
 printf '%s\n' "$KUBECONFIG"
}

case "${1:-}" in
  plan) read_profile "${2:?profile path}"; print_plan "$(plan_of "$2")";;
  up)   read_profile "${2:?profile path}"
        plan=$(plan_of "$2"); print_plan "$plan"
        cluster_up "$plan" "${3:-gsj-rehearsal}";;
  down) command -v k3d >/dev/null || fail 'k3d is required'
        k3d cluster delete "${2:?cluster name}" >&2;;
  *) fail 'usage: rehearsal.sh plan <profile.json> | up <profile.json> [name] | down <name>';;
esac
