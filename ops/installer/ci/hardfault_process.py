"""Qualification helper: kill three exact container namespace inits from an ancestor PID namespace.

This file is sent on stdin to a short-lived, tokenless hostPID Pod. No product
package, runtime credential or model is imported. It never guesses from names.
"""
import json
import os
from pathlib import Path
import re
import select
import signal
import time


def require(value, message):
    if not value:
        raise ValueError(message)


ROLES = {'gsj-web', 'agent-runner', 'gsj-mcp'}


def settings_check(settings):
    require(settings.get('schema') == 'gsj.hardfault-process/1', 'unsupported process plan')
    require(re.fullmatch(r'[a-f0-9-]{36}', settings.get('pod_uid', '')), 'invalid Pod UID')
    targets = settings.get('targets', [])
    require(len(targets) == len(ROLES) and {t.get('name') for t in targets} == ROLES, 'exact target roles required')
    require(all(re.fullmatch(r'[a-f0-9]{64}', t.get('container_id', '')) for t in targets)
            and len({t['container_id'] for t in targets}) == len(ROLES), 'exact distinct runtime IDs required')


def identity(proc, pid, pod_uid, container_id):
    if pid <= 1:
        return None
    root = Path(proc) / str(pid)
    try:
        cgroup = (root / 'cgroup').read_text()
        pod = '(?:' + re.escape(pod_uid) + '|' + re.escape(pod_uid.replace('-', '_')) + ')'
        if not re.search(r'(?:^|/)[^/\n]*pod' + pod + r'(?:\.slice|/|$)', cgroup, re.M):
            return None
        if not re.search(r'(?:cri-containerd-|/)' + re.escape(container_id) + r'(?:\.scope|/|$)', cgroup):
            return None
        status = (root / 'status').read_text()
        line = next((x for x in status.splitlines() if x.startswith('NSpid:')), '')
        nspid = [int(x) for x in line.split()[1:]]
        if len(nspid) < 2 or nspid[0] != pid or nspid[-1] != 1:
            return None
        stat = (root / 'stat').read_text()
        # comm can contain spaces and parentheses; fields after its final ')' begin at3.
        fields = stat.rsplit(')', 1)[1].split()
        start_ticks = int(fields[19])
        return {'pid': pid, 'namespace_pids': nspid, 'start_ticks': start_ticks,
                'pod_uid': pod_uid, 'container_id': container_id}
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return None


def signal_targets(settings, *, proc='/proc', pidfd_open=None, send=None, wait=None):
    settings_check(settings)
    pidfd_open = pidfd_open or getattr(os, 'pidfd_open', None)
    send = send or getattr(signal, 'pidfd_send_signal', None)
    require(pidfd_open is not None and send is not None, 'kernel/Python pidfd support is required')
    discovered = []
    for target in settings['targets']:
        matches = []
        for entry in Path(proc).iterdir():
            if entry.name.isdigit():
                found = identity(proc, int(entry.name), settings['pod_uid'], target['container_id'])
                if found:
                    matches.append(found)
        require(len(matches) == 1, 'target is not one uniquely identified ancestor-visible namespace init')
        discovered.append({'name': target['name'], **matches[0]})
    fds = []
    try:
        # Every identity and pidfd must be established before any signal.
        for target in discovered:
            fds.append(pidfd_open(target['pid'], 0))
        for target in discovered:
            require(identity(proc, target['pid'], settings['pod_uid'], target['container_id']) ==
                    {k: v for k, v in target.items() if k != 'name'}, 'target identity changed before signal')
        for target, fd in zip(discovered, fds):
            send(fd, signal.SIGKILL, None, 0)
            target['signal_sent'] = 'SIGKILL'
        for target, fd in zip(discovered, fds):
            if wait is None:
                poller = select.poll(); poller.register(fd, select.POLLIN)
                dead = bool(poller.poll(15000))
            else:
                dead = wait(fd)
            require(dead, 'pidfd did not confirm target death')
            target['pidfd_exit_observed'] = True
        return {'schema': 'gsj.hardfault-process-result/1', 'status': 'passed', 'pod_uid': settings['pod_uid'],
                'ancestor_namespace': True, 'targets': discovered}
    finally:
        for fd in fds:
            os.close(fd)


if __name__ == '__main__':
    try:
        result = signal_targets(SETTINGS)
    except Exception as error:
        print(json.dumps({'schema': 'gsj.hardfault-process-result/1', 'status': 'refused',
                          'error': type(error).__name__, 'reason': str(error)}), flush=True)
        raise SystemExit(1)
    print(json.dumps(result), flush=True)
