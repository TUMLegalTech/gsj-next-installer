"""test_installer_headroom — the schedulable-headroom preflight's two scoping
rules.

The check was added to refuse, in an install's first seconds, a node that cannot
place the deployment's Pods. As first written it refused its own repair: it
counted the deployment's OWN already-scheduled Pods as competition for the
request they already held (measured on a second cluster: refused at 8,377Mi
free against 8,448Mi needed — by its own 8,448Mi). And because `preflight` runs
ABOVE the verb dispatch, it also gated `abandon` and `sweep` — step 1 of the
documented decommission, run while the deployment is still up.

Both rules are pinned here, and both were red on the build that introduced
the check, before its fix.
"""
import json

import pytest

from tests.test_installer import runtime  # noqa: F401  (fixture)

GI = 1024 ** 3
NODE = "synthetic-node"          # _site() sets storage.node to this
OWN_NAMESPACE = "synthetic-namespace"   # the fixture's NAMESPACE

# What the shipped defaults make the scheduler place: max(initializer 4Gi,
# web 2Gi + mcp 1Gi + runner 512Mi) + chroma 4Gi + forgejo 256Mi.
DEPLOYMENT_REQUEST = int(8.25 * GI)


def _node(name=NODE, allocatable="16Gi", **spec):
    return {"metadata": {"name": name}, "spec": spec,
            "status": {"allocatable": {"memory": allocatable},
                       "conditions": [{"type": "Ready", "status": "True"}]}}


def _pod(name, namespace, memory, node=NODE, phase="Running", init=None):
    spec = {"nodeName": node, "containers": [{"name": "c", "resources": {"requests": {"memory": memory}}}]}
    if init:
        spec["initContainers"] = [{"name": "i", "resources": {"requests": {"memory": init}}}]
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "namespace": namespace},
            "spec": spec, "status": {"phase": phase}}


def _own_deployment():
    """This deployment, already running: exactly the Pods a repair, an upgrade
    or a decommission finds on the node."""
    return [_pod("synthetic-release-web", OWN_NAMESPACE, "3584Mi", init="4Gi"),
            _pod("synthetic-release-chroma", OWN_NAMESPACE, "4Gi"),
            _pod("synthetic-release-forgejo", OWN_NAMESPACE, "256Mi")]


def _check(run, state, work, tmp_path, *, command, nodes, pods):
    payload = tmp_path / "payload"
    payload.mkdir(exist_ok=True)
    (payload / "release.json").write_text(json.dumps({"corpus": {"initializer_memory_bytes": 4 * GI, "max_shard_chunks": 1},
                                                      "model": {"dimensions": 768}}))
    (work / "nodes.json").write_text(json.dumps({"items": nodes}))
    state.write_text(json.dumps({"lease": None, "calls": [],
                                 "resources": {"Pod/" + pod["metadata"]["namespace"] + "." + pod["metadata"]["name"]: pod for pod in pods}}))
    return run(f'GSJ_PAYLOAD="{payload}"; COMMAND={command}; initializer_memory_check "$(cat "$TEST_WORK/nodes.json")"')


# --- rule 1: a deployment is not its own competition -------------------------------

def test_an_upgrade_is_not_refused_by_the_pods_it_is_upgrading(runtime, tmp_path):
    """16Gi node, 6Gi of foreign requests, and this deployment's own 8.25Gi
    already placed. Counting the own Pods leaves 1.75Gi and refuses; they are
    the very request under test, so 10Gi is what is really unreserved."""
    run, state, work = runtime
    result = _check(run, state, work, tmp_path, command="upgrade", nodes=[_node()],
                    pods=_own_deployment() + [_pod("someone-else", "other-namespace", "6Gi")])
    assert result.returncode == 0, result.stderr


def test_the_exclusion_is_by_namespace_and_nothing_wider(runtime, tmp_path):
    """The positive control, without which rule 1 could pass by the check
    being dead: the same 14.25Gi of requests, all FOREIGN, must still refuse."""
    run, state, work = runtime
    foreign = [_pod("a", "other-namespace", "8448Mi"), _pod("b", "other-namespace", "6Gi")]
    result = _check(run, state, work, tmp_path, command="install", nodes=[_node()], pods=foreign)
    assert result.returncode != 0
    assert "no node has room for this deployment" in result.stderr
    assert "8448Mi" in result.stderr, "the refusal states the request in the operator's units"


def test_a_fresh_install_on_a_node_with_room_passes(runtime, tmp_path):
    run, state, work = runtime
    result = _check(run, state, work, tmp_path, command="install", nodes=[_node()],
                    pods=[_pod("someone-else", "other-namespace", "6Gi")])
    assert result.returncode == 0, result.stderr


# --- rule 2: only the verbs that SCHEDULE ask the scheduler's question ----------------

RECOVERY_AND_DECOMMISSION = ["abandon", "sweep", "resume", "repair", "credential-repair", "tls-repair",
                             "lease-repair", "addon-repair", "backup", "backup-repair", "restore", "restore-repair"]


@pytest.mark.parametrize("command", RECOVERY_AND_DECOMMISSION)
def test_a_full_node_never_blocks_recovery_or_decommission(runtime, tmp_path, command):
    """`preflight` runs above the verb dispatch, so without a gate every one of
    these met the capacity check. None of them schedules anything — and
    `abandon` is step 1 of removing a deployment, run while it is still up and
    still reserving its 8.25Gi. The node here has NO room at all."""
    run, state, work = runtime
    full = _own_deployment() + [_pod("someone-else", "other-namespace", "15Gi")]
    result = _check(run, state, work, tmp_path, command=command, nodes=[_node()], pods=full)
    assert result.returncode == 0, f"{command} was refused on capacity: {result.stderr}"


@pytest.mark.parametrize("command", ["install", "upgrade"])
def test_the_two_verbs_that_schedule_are_still_refused_on_that_same_full_node(runtime, tmp_path, command):
    run, state, work = runtime
    full = _own_deployment() + [_pod("someone-else", "other-namespace", "15Gi")]
    result = _check(run, state, work, tmp_path, command=command, nodes=[_node()], pods=full)
    assert result.returncode != 0
    assert "no node has room for this deployment" in result.stderr


# --- the corpus-limit half is NOT capacity and stays on for every verb -----------------

@pytest.mark.parametrize("command", ["install", "repair", "abandon"])
def test_an_initializer_limit_below_the_release_s_corpus_is_refused_whatever_the_verb(runtime, tmp_path, command):
    """The verb gate covers the scheduler's question only. A limit the corpus
    cannot fit in is a fact about the site file, true for every verb, and a
    repair is exactly where an operator corrects it."""
    run, state, work = runtime
    site = json.loads((work / "site.json").read_text())
    site["resources"]["initializer"]["limits"]["memory"] = "2Gi"
    site["resources"]["initializer"]["requests"]["memory"] = "1Gi"
    (work / "site.json").write_text(json.dumps(site))
    result = _check(run, state, work, tmp_path, command=command, nodes=[_node()], pods=[])
    assert result.returncode != 0
    assert "the corpus initializer needs 4096Mi" in result.stderr
