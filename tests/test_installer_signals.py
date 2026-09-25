"""Terminating a real Bash client must retain its initializer's operation owner."""
import json
import os
from pathlib import Path
import signal
import subprocess
import time

import pytest

from tests.test_installer import INSTALLER, _lease, _release, runtime


@pytest.mark.parametrize('sig,code', [(signal.SIGTERM,143),(signal.SIGINT,130),(signal.SIGHUP,129)])
def test_signal_retains_lease_and_removes_private_work(tmp_path, sig, code):
    functions=tmp_path/'functions.sh'
    functions.write_text((INSTALLER/'runtime.sh').read_text().split('# ENTRY POINT',1)[0].replace('@CLIENT_TABLE@',''))
    work=tmp_path/'private'; work.mkdir()
    ready=tmp_path/'ready'
    released=tmp_path/'released'
    script='''source "$FUNCTIONS"
GSJ_WORK="$PRIVATE"; STATE_DIR="$STATE"; OPERATION=synthetic; LEASE_ACQUIRED=true
release_operation() { touch "$RELEASED"; }
install_exit_traps
touch "$READY"
while true; do sleep 0.05; done
'''
    p=subprocess.Popen(['bash','-c',script],stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                       env={**os.environ,'FUNCTIONS':str(functions),'PRIVATE':str(work),'STATE':str(tmp_path),
                            'READY':str(ready),'RELEASED':str(released)})
    try:
        deadline=time.monotonic()+5
        while not ready.exists() and time.monotonic()<deadline: time.sleep(.01)
        assert ready.exists()
        p.send_signal(sig)
        out,err=p.communicate(timeout=5)
        assert p.returncode==code,err
        assert not released.exists()
        assert not work.exists()
        assert b'incomplete' in err
    finally:
        if p.poll() is None: p.kill(); p.wait()


def _recovery(runtime):
    run,state,work=runtime
    source=_release()
    payload=work/'payload'; payload.mkdir()
    (payload/'release.json').write_text(json.dumps(source))
    operation='a'*24
    (work/'operation.json').write_text(json.dumps({'operation':operation,'target':source['identity'],'status':'initializing'}))
    (work/'site.pending.json').write_bytes((work/'site.json').read_bytes())
    lease=_lease(); lease['spec']['renewTime']='2020-01-01T00:00:00.000000Z'
    deployment={'apiVersion':'apps/v1','kind':'deployment','metadata':{'name':'synthetic-release-web','uid':'deployment-id',
                'annotations':{'meta.helm.sh/release-name':'synthetic-release','meta.helm.sh/release-namespace':'synthetic-namespace'},
                'labels':{'app.kubernetes.io/instance':'synthetic-release'}},'spec':{'template':{'spec':{
                'containers':[{'name':('agent-runner' if role=='runner' else 'gsj-'+role),'image':image['repository']+'@'+image['digest']}
                              for role,image in source['images'].items() if role in {'web','runner','mcp'}],
                'initContainers':[{'name':'corpus-initialize','image':source['images']['web']['repository']+'@'+source['images']['web']['digest']},
                                  {'name':'corpus-copy','image':source['images']['decisionsData']['repository']+'@'+source['images']['decisionsData']['digest'],
                                   'args':['--destination','/source','--manifest-sha256',source['corpus']['manifest_sha256']]}]}}}}
    state.write_text(json.dumps({'lease':lease,'calls':[],'resources':{'deployment/synthetic-release-web':deployment}}))
    return run,state,work,payload,operation


@pytest.mark.parametrize('fault',[None,'holder','fresh','target','phase','image','corpus','namespace','cas'])
def test_lease_repair_is_exact_source_cas_and_never_mutates_deployment(runtime,fault):
    run,state,work,payload,operation=_recovery(runtime)
    current=json.loads(state.read_text())
    obj=current['resources']['deployment/synthetic-release-web']
    if fault=='holder': current['lease']['spec']['holderIdentity']='different-owner'
    if fault=='fresh': current['lease']['spec']['renewTime']='2999-01-01T00:00:00Z'
    if fault=='cas': current['conflict_replace']=True
    if fault=='image': obj['spec']['template']['spec']['containers'][0]['image']='registry.invalid/changed@sha256:'+'b'*64
    if fault=='corpus': obj['spec']['template']['spec']['initContainers'][1]['args'][-1]='c'*64
    if fault=='namespace': obj['metadata']['annotations']['meta.helm.sh/release-namespace']='other'
    if fault in {'target','phase'}:
        saved=json.loads((work/'operation.json').read_text()); saved[{'target':'target','phase':'status'}[fault]]='different'
        (work/'operation.json').write_text(json.dumps(saved))
    state.write_text(json.dumps(current))
    result=run('GSJ_PAYLOAD="$PAYLOAD"; RESUME_ID="$RECOVERY_OPERATION"; lease_repair',PAYLOAD=str(payload),RECOVERY_OPERATION=operation)
    actual=json.loads(state.read_text())
    assert (result.returncode==0)==(fault is None),result.stderr
    assert actual['resources']==current['resources']
    if fault is None:
        assert actual['lease']['spec']['holderIdentity']==operation
        assert actual['lease']['spec']['renewTime']==current['lease']['spec']['renewTime']
        assert json.loads((work/'lease-repair.json').read_text())['status']=='repaired'
    else:
        assert actual['lease']==current['lease']
    assert all(a[0] in {'get','replace'} for a in actual['calls'])

@pytest.mark.parametrize('fault',[None,'holder','fresh','target','config','profile'])
def test_named_addon_repair_retains_original_operation_and_never_applies_app(runtime,fault):
    run,state,work=runtime
    operation='a'*24
    lease=_lease(operation);lease['spec']['renewTime']='2020-01-01T00:00:00.000000Z'
    if fault=='holder': lease['spec']['holderIdentity']='different-owner'
    if fault=='fresh': lease['spec']['renewTime']='2999-01-01T00:00:00Z'
    state.write_text(json.dumps({'lease':lease,'calls':[]}))
    site=json.loads((work/'site.json').read_text());site['ingress']['profile']='managed-traefik'
    if fault=='profile':site['ingress']['profile']='reuse'
    (work/'site.json').write_text(json.dumps(site))
    (work/'site.pending.json').write_bytes((work/'site.json').read_bytes())
    if fault=='config':(work/'site.pending.json').write_text('{}')
    (work/'operation.json').write_text(json.dumps({'operation':operation,'target':'different' if fault=='target' else 'synthetic-release','status':'owned'}))
    result=run('''RESUME_ID=aaaaaaaaaaaaaaaaaaaaaaaa; ADDON=traefik; REVISION=1
managed_dependencies() { printf repaired > "$TEST_WORK/repaired"; }
addon_repair_operation
''')
    actual=json.loads(state.read_text())
    assert (result.returncode==0)==(fault is None),result.stderr
    assert (work/'repaired').exists()==(fault is None)
    assert actual['lease']['spec']==lease['spec']
    assert json.loads((work/'operation.json').read_text())['status']=='owned'
    assert not any(a[0] in ['create','delete','patch'] for a in actual['calls'])


def _running(pid):
    value = subprocess.run(['ps', '-p', str(pid), '-o', 'stat='], capture_output=True, text=True)
    return value.returncode == 0 and value.stdout.strip() and not value.stdout.strip().startswith('Z')


@pytest.mark.parametrize('worker_kind', ['helm', 'renewal'])
@pytest.mark.parametrize('ignore_term', [False, True])
def test_sigterm_stops_owned_worker_group_including_grandchild(tmp_path, worker_kind, ignore_term):
    """Real forked writers, including a TERM-resistant descendant, cannot survive."""
    import sys
    functions = tmp_path / 'functions.sh'
    functions.write_text((INSTALLER / 'runtime.sh').read_text().split('# ENTRY POINT', 1)[0].replace('@CLIENT_TABLE@', ''))
    private = tmp_path / 'private'; private.mkdir()
    (tmp_path / 'operation.json').write_text('{}')
    worker = tmp_path / 'worker.py'
    worker.write_text('''import json,os,pathlib,signal,subprocess,sys,time
root=pathlib.Path(os.environ['TEST_TREE'])
ignore=os.environ['IGNORE_TERM']=='1'
child_code="""import os,pathlib,signal,time
if os.environ['IGNORE_TERM']=='1':signal.signal(signal.SIGTERM,signal.SIG_IGN)
p=pathlib.Path(os.environ['TEST_TREE'])/'writes'
while True:
 with p.open('a') as out:out.write('synthetic\\\\n');out.flush()
 time.sleep(.01)
"""
if ignore:signal.signal(signal.SIGTERM,signal.SIG_IGN)
child=subprocess.Popen([sys.executable,'-B','-c',child_code])
(root/'tree.json').write_text(json.dumps({'worker':os.getpid(),'child':child.pid,'group':os.getpgrp()}))
while True:time.sleep(.02)
''')
    script = '''source "$FUNCTIONS"
GSJ_WORK="$PRIVATE"; STATE_DIR="$TEST_TREE"; OPERATION=synthetic; LEASE_ACQUIRED=true
GSJ_PAYLOAD="$PRIVATE"; RELEASE=synthetic
assert_owner() { :; }
read_installed() { :; }
stage_operation_config() { :; }
helm_application_prepare() { :; }; helm_application_validate() { :; }
j() { printf 300; }
k() { :; }
sleep() { command sleep .025; }
release_operation() { touch "$TEST_TREE/released"; }
install_exit_traps
if [[ $WORKER_KIND == helm ]]; then
 h() { "$TEST_PYTHON" -B "$WORKER"; }
 helm_apply
else
 lease_read() { "$TEST_PYTHON" -B "$WORKER"; }
 start_renewal
 while true; do sleep .1; done
fi
'''
    proc = subprocess.Popen(['bash', '-c', script], stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
        env={**os.environ, 'FUNCTIONS': str(functions), 'PRIVATE': str(private), 'TEST_TREE': str(tmp_path),
             'TEST_PYTHON': sys.executable, 'WORKER': str(worker), 'WORKER_KIND': worker_kind,
             'IGNORE_TERM': '1' if ignore_term else '0'})
    tree = {}
    try:
        deadline = time.monotonic() + 5
        while not (tmp_path / 'tree.json').exists() and time.monotonic() < deadline: time.sleep(.01)
        tree = json.loads((tmp_path / 'tree.json').read_text())
        assert tree['group'] != os.getpgid(proc.pid)
        assert os.getpgid(tree['worker']) == os.getpgid(tree['child']) == tree['group']
        # the FIRST WRITE, never the file's creation: the writer opens the file
        # (it exists, empty) before its first write lands, and the signal must
        # find a writer that writes
        while not ((tmp_path / 'writes').exists() and (tmp_path / 'writes').stat().st_size > 0) and time.monotonic() < deadline: time.sleep(.01)
        assert (tmp_path / 'writes').stat().st_size > 0
        proc.send_signal(signal.SIGTERM)
        if ignore_term:
            time.sleep(.1)
            proc.send_signal(signal.SIGTERM)  # teardown must retain its original exit status
        _, err = proc.communicate(timeout=8)
        assert proc.returncode == 143, err
        assert not (tmp_path / 'released').exists()
        assert not private.exists()
        assert not _running(tree['worker']) and not _running(tree['child'])
        before = (tmp_path / 'writes').stat().st_size
        time.sleep(.08)
        assert (tmp_path / 'writes').stat().st_size == before
    finally:
        if tree:
            try: os.killpg(tree['group'], signal.SIGKILL)
            except ProcessLookupError: pass
        if proc.poll() is None: proc.kill(); proc.wait()


@pytest.mark.parametrize('worker_kind', ['helm', 'renewal'])
def test_signal_between_fork_and_pid_registration_still_drains_owned_group(tmp_path, worker_kind):
    functions = tmp_path / 'functions.sh'
    functions.write_text((INSTALLER / 'runtime.sh').read_text().split('# ENTRY POINT', 1)[0].replace('@CLIENT_TABLE@', ''))
    private = tmp_path / 'private'; private.mkdir()
    (tmp_path / 'operation.json').write_text('{}')
    worker = tmp_path / 'worker.sh'
    worker.write_text('''#!/bin/bash
trap '' TERM
printf '%s' "$$" > "$TEST_TREE/writer-pid"
while true; do printf x >> "$TEST_TREE/writes"; sleep .02; done
''')
    script = '''source "$FUNCTIONS"
GSJ_WORK="$PRIVATE"; STATE_DIR="$TEST_TREE"; OPERATION=synthetic; LEASE_ACQUIRED=true
GSJ_PAYLOAD="$PRIVATE"; RELEASE=synthetic
assert_owner() { :; }; read_installed() { :; }; stage_operation_config() { :; }
helm_application_prepare() { :; }; helm_application_validate() { :; }
j() { printf 300; }; k() { :; }; sleep() { command sleep .025; }
release_operation() { touch "$TEST_TREE/released"; }
install_exit_traps
set -T
trap 'case "$BASH_COMMAND" in "HELM_PID=\\$!"|"RENEWER=\\$!")
 while [[ ! -s $TEST_TREE/writes ]]; do command sleep .01; done
 printf gap > "$TEST_TREE/gap"
 kill -TERM "$$";; esac' DEBUG
if [[ $WORKER_KIND == helm ]]; then
 h() { bash "$WORKER"; }; helm_apply
else
 lease_read() { bash "$WORKER"; }; start_renewal
fi
exit 99
'''
    proc = subprocess.Popen(['bash', '-c', script], stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
        env={**os.environ, 'FUNCTIONS': str(functions), 'PRIVATE': str(private), 'TEST_TREE': str(tmp_path),
             'WORKER': str(worker), 'WORKER_KIND': worker_kind})
    writer = None
    try:
        deadline = time.monotonic() + 5
        while (not (tmp_path / 'writer-pid').exists() or not (tmp_path / 'writer-pid').stat().st_size) and time.monotonic() < deadline: time.sleep(.01)
        writer = int((tmp_path / 'writer-pid').read_text())
        _, err = proc.communicate(timeout=8)
        assert proc.returncode == 143, err
        assert (tmp_path / 'gap').read_text() == 'gap'
        assert not _running(writer)
        assert not (tmp_path / 'released').exists() and not private.exists()
        before = (tmp_path / 'writes').stat().st_size; time.sleep(.08)
        assert (tmp_path / 'writes').stat().st_size == before
    finally:
        if writer and _running(writer):
            try: os.killpg(os.getpgid(writer), signal.SIGKILL)
            except ProcessLookupError: pass
        if proc.poll() is None: proc.kill(); proc.wait()
