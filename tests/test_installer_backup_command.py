"""Standalone backup resumes only the captured source and its original replicas."""
import json

import pytest

from tests.test_installer import _lease, runtime
from tests.test_installer_backup_retry import maintenance, _cluster, _snapshot


def test_backup_restart_restores_original_mixed_replica_counts(maintenance):
    m=maintenance
    def original(s):
        s['controllers']['items'][1]['spec']['replicas']=0
        s['ready_on_scale']=True
    _cluster(m,original)
    assert m['run']('quiesce').returncode==0
    snapshot=_snapshot(m).read_bytes()
    site=json.loads((m['state']/'site.pending.json').read_text())
    site['deadlines']={'initialization_seconds':1}
    (m['state']/'site.pending.json').write_text(json.dumps(site))
    result=m['run']('restart_backup_source')
    assert result.returncode==0,result.stderr
    actual=json.loads(m['cluster'].read_text())
    assert [v['spec']['replicas'] for v in actual['controllers']['items']]==[1,0,1]
    assert _snapshot(m).read_bytes()==snapshot
    assert json.loads((m['state']/'operation.json').read_text())['status']=='backup-complete'
    assert all(a[0] in {'get','scale'} for a in actual['calls'])


@pytest.mark.parametrize('mutation',['uid','image','storage'])
def test_backup_restart_refuses_replaced_source_before_scaling(maintenance,mutation):
    m=maintenance
    assert m['run']('quiesce').returncode==0
    def change(s):
        s['calls']=[]
        if mutation=='uid': s['controllers']['items'][0]['metadata']['uid']='other'
        if mutation=='image': s['controllers']['items'][0]['spec']['template']['spec']['containers'][0]['image']='other'
        if mutation=='storage': s['storage'][0]['uid']='other'
    _cluster(m,change)
    result=m['run']('restart_backup_source')
    assert result.returncode!=0
    assert not any(v[0]=='scale' for v in json.loads(m['cluster'].read_text())['calls'])


@pytest.mark.parametrize('phase,expected',[
    ('owned',['backup','restart']),('backup-verified',['backup','restart']),
    ('backup-restarting',['verify-original','restart']),('backup-complete',[])])
def test_named_backup_resume_never_enters_helm_or_verification_mutations(runtime,phase,expected):
    run,state,work=runtime
    operation='a'*24
    lease=_lease(operation); lease['spec']['renewTime']='2020-01-01T00:00:00.000000Z'
    state.write_text(json.dumps({'lease':lease,'calls':[]}))
    (work/'operation.json').write_text(json.dumps({'operation':operation,'target':'synthetic-release','kind':'backup','status':phase}))
    (work/'site.pending.json').write_bytes((work/'site.json').read_bytes())
    result=run('''RESUME_ID=aaaaaaaaaaaaaaaaaaaaaaaa; BACKUP_DIR="$TEST_WORK/backups"
read_installed() { :; }
backup() { echo backup; }
restart_backup_source() { echo restart; }
verified_backup_reuse() { echo verify-original; }
helm_apply() { exit 91; }
verify_application() { exit 92; }
resume_operation
''')
    assert result.returncode==0,result.stderr
    assert result.stdout.splitlines()==expected
