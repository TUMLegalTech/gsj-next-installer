"""Exact process identity and capability boundaries of the hard fault the
hand-run qualification injects into a disposable cluster (ci/hardfault*.py)."""
import importlib.util
import os
from pathlib import Path
import signal
import copy
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / 'ops/installer/ci/hardfault_process.py'
spec = importlib.util.spec_from_file_location('gsj_hardfault_process', PATH)
process = importlib.util.module_from_spec(spec); spec.loader.exec_module(process)
UID = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'


def plan():
    return {'schema': 'gsj.hardfault-process/1', 'pod_uid': UID,
            'targets': [{'name': 'agent-runner', 'container_id': 'a'*64}, {'name': 'gsj-mcp', 'container_id': 'c'*64},
                        {'name': 'gsj-web', 'container_id': 'b'*64}]}


def targets(root):
    return [proc(root, 20, UID, 'a'*64), proc(root, 25, UID, 'c'*64), proc(root, 30, UID, 'b'*64)]


def proc(root, pid, uid, cid, *, init=True, start=123):
    directory = root / str(pid); directory.mkdir()
    (directory / 'cgroup').write_text('0::/../../kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-burstable-pod' + uid.replace('-', '_') + '.slice/cri-containerd-' + cid + '.scope\n')
    (directory / 'status').write_text('Name:\tpython\nNSpid:\t' + str(pid) + '\t' + ('1' if init else '4') + '\n')
    (directory / 'stat').write_text(str(pid) + ' (worker with (odd) name) S ' + '0 '*18 + str(start) + ' 0 0\n')
    return directory


def test_matches_actual_systemd_cgroup_shape_but_never_pid1_or_noninit(tmp_path):
    proc(tmp_path, 20, UID, 'a'*64)
    assert process.identity(tmp_path, 20, UID, 'a'*64)['start_ticks'] == 123
    assert process.identity(tmp_path, 20, UID, 'a'*63+'c') is None
    assert process.identity(tmp_path, 20, 'bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee', 'a'*64) is None
    assert process.identity(tmp_path, 1, UID, 'a'*64) is None
    proc(tmp_path, 30, UID, 'b'*64, init=False)
    assert process.identity(tmp_path, 30, UID, 'b'*64) is None


def test_every_pidfd_and_identity_is_proven_before_any_signal(tmp_path):
    targets(tmp_path)
    actions = []
    def openfd(pid, flags):
        actions.append(('open', pid)); return os.open(os.devnull, os.O_RDONLY)
    def send(fd, sig, info, flags):
        assert [x[0] for x in actions[:3]] == ['open'] * 3
        assert sig == signal.SIGKILL
        actions.append(('kill', fd))
    result = process.signal_targets(plan(), proc=tmp_path, pidfd_open=openfd, send=send, wait=lambda fd: True)
    assert result['status'] == 'passed'
    assert [x[0] for x in actions] == ['open'] * 3 + ['kill'] * 3
    assert {x['name'] for x in result['targets']} == {'agent-runner', 'gsj-mcp', 'gsj-web'}
    assert all(x['pidfd_exit_observed'] for x in result['targets'])


@pytest.mark.parametrize('fault', ['wrong-pod', 'duplicate', 'missing', 'missing-mcp', 'changed-start'])
def test_drift_or_nonunique_target_never_sends_any_signal(tmp_path, fault):
    first = targets(tmp_path)[0]
    settings = plan(); calls = []
    if fault == 'wrong-pod': settings['pod_uid'] = 'bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee'
    if fault == 'duplicate': proc(tmp_path, 40, UID, 'a'*64)
    if fault == 'missing': (tmp_path / '30/status').unlink()
    if fault == 'missing-mcp': (tmp_path / '25/status').unlink()
    def openfd(pid, flags):
        if fault == 'changed-start': (first / 'stat').write_text('20 (changed) S ' + '0 '*18 + '124 0\n')
        return os.open(os.devnull, os.O_RDONLY)
    with pytest.raises(ValueError):
        process.signal_targets(settings, proc=tmp_path, pidfd_open=openfd, send=lambda *a: calls.append(a), wait=lambda _: True)
    assert calls == []


def test_signal_delivery_without_observed_death_is_not_a_pass(tmp_path):
    targets(tmp_path)
    with pytest.raises(ValueError, match='confirm target death'):
        process.signal_targets(plan(), proc=tmp_path, pidfd_open=lambda *a: os.open(os.devnull, os.O_RDONLY), send=lambda *a: None, wait=lambda _: False)


@pytest.mark.parametrize('fault', ['roles', 'duplicate-id', 'short-id', 'short-uid', 'missing-mcp', 'extra'])
def test_plan_is_exactly_the_three_distinct_runtime_container_identities(fault):
    value = plan()
    if fault == 'roles': value['targets'][0]['name'] = 'node-init'
    if fault == 'duplicate-id': value['targets'][1]['container_id'] = 'a'*64
    if fault == 'short-id': value['targets'][0]['container_id'] = 'a'*12
    if fault == 'short-uid': value['pod_uid'] = 'bad'
    if fault == 'missing-mcp': value['targets'].pop(1)
    if fault == 'extra': value['targets'].append({'name': 'forgejo', 'container_id': 'd'*64})
    with pytest.raises(ValueError): process.settings_check(value)


@pytest.mark.parametrize('fault', [None, 'missing-mcp', 'mcp-image', 'mcp-not-ready'])
def test_fault_plan_covers_web_runner_and_mcp_from_their_exact_release_images(monkeypatch, fault):
    monkeypatch.syspath_prepend(str(ROOT/'ops/installer/ci'))
    import hardfault
    images = {role: {'repository': 'example.test/' + role, 'digest': 'sha256:' + 'a'*64} for role in ('web', 'runner', 'mcp')}
    ids = {'agent-runner': 'a'*64, 'gsj-mcp': 'c'*64, 'gsj-web': 'b'*64}
    pod = {'metadata': {'uid': UID},
           'spec': {'containers': [{'name': name, 'image': images[role]['repository'] + '@' + images[role]['digest']}
                                   for name, role in hardfault.TARGETS.items()]},
           'status': {'containerStatuses': [{'name': name, 'ready': True, 'restartCount': 0,
                                             'state': {'running': {'startedAt': '2026-09-14T00:00:00Z'}},
                                             'containerID': 'containerd://' + cid} for name, cid in ids.items()]}}
    if fault == 'missing-mcp': pod['spec']['containers'].pop(1); pod['status']['containerStatuses'].pop(1)
    elif fault == 'mcp-image': pod['spec']['containers'][1]['image'] = 'example.test/web@sha256:' + 'a'*64
    elif fault == 'mcp-not-ready': pod['status']['containerStatuses'][1]['ready'] = False
    if fault:
        with pytest.raises(ValueError): hardfault.target_plan(pod, images)
        return
    value = hardfault.target_plan(pod, images)
    assert [(t['name'], t['container_id']) for t in value['targets']] == list(ids.items())
    process.settings_check(value)  # exactly what the hostPID helper accepts


@pytest.mark.parametrize('fault', ['sidecar', 'init', 'ephemeral', 'privileged', 'image', 'command', 'resources', 'user', 'seccomp', 'hostpath', 'token'])
def test_admitted_helper_projection_detects_expanded_privilege_or_runtime(monkeypatch, fault):
    monkeypatch.syspath_prepend(str(ROOT/'ops/installer/ci'))
    import hardfault
    _, pod = hardfault.helper_resources('gsj-qualification-test', UID, 'node', 'example.test/web@sha256:'+'a'*64, [], 'a'*20)
    expected = hardfault.helper_projection(pod); bad = copy.deepcopy(pod); spec = bad['spec']; container = spec['containers'][0]
    if fault == 'sidecar': spec['containers'].append(copy.deepcopy(container))
    elif fault == 'init': spec['initContainers'] = [copy.deepcopy(container)]
    elif fault == 'ephemeral': spec['ephemeralContainers'] = [copy.deepcopy(container)]
    elif fault == 'privileged': container['securityContext']['privileged'] = True
    elif fault == 'image': container['image'] = 'foreign'
    elif fault == 'command': container['command'] = ['sh']
    elif fault == 'resources': container['resources']['limits']['memory'] = '1Gi'
    elif fault == 'user': spec['securityContext']['runAsUser'] = 999
    elif fault == 'seccomp': spec['securityContext']['seccompProfile'] = {'type':'Unconfined'}
    elif fault == 'hostpath': spec['volumes'] = [{'name':'host','hostPath':{'path':'/'}}]
    elif fault == 'token': spec['automountServiceAccountToken'] = True
    try: actual = hardfault.helper_projection(bad)
    except ValueError: return
    assert actual != expected
