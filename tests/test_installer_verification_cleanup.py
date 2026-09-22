"""Exercise the real Bash handoff with a durable synthetic Kubernetes API."""
import json
import os
from pathlib import Path
import shlex
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "ops/installer/verification-cleanup.sh"


@pytest.fixture
def cleanup_client(tmp_path):
    work, state, binary = (tmp_path / name for name in ("work", "state", "bin"))
    for path in (work, state, binary): path.mkdir()
    cluster = tmp_path / "cluster.json"
    owned = {"generation": "old-generation", "run_id": "1234abcd", "users": [{"login": "gsj-verify-1234abcd-a", "id": 42}]}
    provision = {"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": "gsj-provision", "labels": {"app.kubernetes.io/instance": "gsj"}},
        "spec": {"parallelism": 1, "completions": 1, "template": {"metadata": {"labels": {"app.kubernetes.io/instance": "gsj"}}, "spec": {
            "restartPolicy": "Never", "containers": [{"name": "provision", "image": "registry.invalid/web@sha256:" + "a" * 64,
                "env": [{"name": "GSJ_DEPLOYMENT_GENERATION", "value": "new-generation"},
                        {"name": "GSJ_FORGE_TOKEN", "valueFrom": {"secretKeyRef": {"name": "current-A", "key": "token"}}}]}],
            "volumes": [{"name": "scripts", "configMap": {"name": "gsj-scripts", "defaultMode": 420}}]}}}}
    cluster.write_text(json.dumps({"owned": owned, "resources": {"job/gsj-provision": provision}, "calls": [], "resume_code": 75, "finalize_code": 77}))
    fake = binary / "kubectl"
    fake.write_text('''#!/usr/bin/env python3
import json,os,pathlib,sys
p=pathlib.Path(os.environ['VC_CLUSTER']);s=json.loads(p.read_text());a=sys.argv[1:]
assert a[:4]==['--context','synthetic','--namespace','legal'];a=a[4:]
s['calls'].append(a);out=None;code=0
def save():p.write_text(json.dumps(s))
def resource(kind,name):return s['resources'].get(('configmap' if kind in ('configmap','configmaps') else 'job' if kind in ('job','jobs') else 'pod' if kind=='pods' else kind)+'/'+name)
if a[:2]==['get','namespace']:out={'metadata':{'uid':'namespace-original'}}
elif a[:2]==['get','lease']:out={'spec':{'holderIdentity':s.get('holder','operation')}}
elif a[0]=='exec':
 if '--resume' in a:code=s['resume_code']
 elif '--finalize-cleanup' in a:
  if s.get('bad_finalize'):code=1
  else:
   code=s['finalize_code']
   if code in (0,77):s['resume_code']=code
 elif '-i' in a:s['remote_result']=json.load(sys.stdin)
 elif a[-2]=='cat' and a[-1].endswith('/cleanup-users.json'):
  if s.get('fail_owned_read'):code=55
  else:out=s['owned']
 elif a[-2]=='cat' and a[-1].endswith('/report.json'):out={'status':'passed' if s['resume_code']==0 else 'cleaned-reverify-required'}
 else:raise AssertionError(a)
elif a[0]=='get' and (a[1] in ('configmap','configmaps','job','jobs','pod') or (a[1]=='pods' and not a[2].startswith('-'))):
 out=resource(a[1],a[2])
 if out and a[1] in ('configmap','configmaps') and s.get('forget_job_uid'):
  out=json.loads(json.dumps(out));out['metadata'].setdefault('annotations',{}).pop('gsj.io/job-uid',None)
 if out is None and '--ignore-not-found' not in a:code=44
elif a[:2]==['get','pods']:
 selected=a[a.index('-l')+1].split('=',1)[1] if '-l' in a else None
 for key,j in list(s['resources'].items()):
  if not key.startswith('job/gsj-verify') or (selected and key!='job/'+selected):continue
  uid=j['metadata']['uid'];name=j['metadata']['name'];phase='Failed' if any(c['type']=='Failed' for c in j['status']['conditions']) else 'Succeeded'
  if s.get('running_control_pod'):phase='Running'
  pod={'metadata':{'name':name+'-pod','uid':'pod-'+uid,'ownerReferences':[{'kind':'Job','uid':uid}]},
       'status':{'phase':phase,'containerStatuses':[{'name':'provision','state':{'running':{}} if phase=='Running' else {'terminated':{'exitCode':1 if phase=='Failed' else 0}}}]}}
  s['resources']['pod/'+pod['metadata']['name']]=pod
 out={'items':[v for key,v in s['resources'].items() if key.startswith('pod/') and (not selected or v['metadata']['name']==selected+'-pod')]}
elif a[0]=='create':
 value=json.loads(pathlib.Path(a[a.index('-f')+1]).read_text());kind=value['kind'].lower();name=value['metadata']['name'];key=kind+'/'+name
 if key in s['resources']:code=1
 else:
  value['metadata'].update(uid=kind+'-'+name,resourceVersion='1')
  if kind=='job':
   env=value['spec']['template']['spec']['containers'][0]['env'];assert [v for v in env if v['name']=='GSJ_DEPLOYMENT_GENERATION']==[{'name':'GSJ_DEPLOYMENT_GENERATION','value':'old-generation'}]
   if value['spec']['template']['spec'].get('initContainers')==[]:value['spec']['template']['spec'].pop('initContainers')
   attempt=int(name[-1]);phase='Failed' if attempt<=s.get('failed_attempts',0) else 'Complete'
   value['status']={'conditions':[] if s.get('active') else [{'type':phase,'status':'True'}]}
   value['spec']['selector']={'matchLabels':{'controller-uid':value['metadata']['uid']}}
   value['spec']['template']['metadata']['labels']['batch.kubernetes.io/job-name']=name
   if s.get('drift_job'):value['spec']['template']['spec']['containers'][0]['image']='unexpected/image'
  s['resources'][key]=value;out=value
  if s.get('lose_'+kind+'_create'):
   s['lose_'+kind+'_create']=False;out=None;code=31
elif a[0]=='patch':
 value=resource(a[1],a[2]);patch=json.loads(pathlib.Path(a[a.index('--patch-file')+1]).read_text())
 assert patch[0]['value']==value['metadata']['uid'] and patch[1]['value']==value['metadata']['resourceVersion']
 key=patch[2]['path'].split('/annotations/')[1].replace('~1','/')
 if key=='gsj.io/finalized-code' and s.get('fail_mark_finalized'):
  s['fail_mark_finalized']=False;code=53
 else:
  value['metadata']['annotations'][key]=patch[2]['value'];value['metadata']['resourceVersion']=str(int(value['metadata']['resourceVersion'])+1);out=value
elif a[0]=='wait':
 name=next(x for x in a if x.startswith('job/')).split('/',1)[1];value=resource('job',name)
 if s.get('wait_stays_active'):code=1
 else:value['status']={'conditions':[{'type':'Complete','status':'True'}]};s['active']=False
elif a[0]=='logs':
 out={'generation':s['owned']['generation'],'users':[{**u,'already_absent':True} for u in s['owned']['users']]}
 if s.get('wrong_result'):out['users'][0]['id']+=1
elif a[:2]==['delete','--raw']:
 uri=a[2];parts=uri.split('/');kind={'jobs':'job','configmaps':'configmap','pods':'pod'}[parts[-2]];name=parts[-1]
 value=resource(kind,name);body=json.loads(pathlib.Path(a[a.index('-f')+1]).read_text())
 assert body['kind']=='DeleteOptions' and body['propagationPolicy']=='Foreground'
 s.setdefault('deletions',[]).append({'kind':kind,'name':name,'body':body})
 if s.get('replace_on_delete'):
  value['metadata']['uid']='replacement-uid';s['replace_on_delete']=False
 if value and value['metadata']['uid']!=body['preconditions']['uid']:code=1
 elif kind=='configmap' and s.get('fail_delete_configmap'):
  s['fail_delete_configmap']=False;code=54
 elif value:
  del s['resources'][kind+'/'+name]
  for key in list(s['resources']):
   if key.startswith('pod/') and any(x.get('uid')==body['preconditions']['uid'] for x in s['resources'][key]['metadata'].get('ownerReferences',[])):del s['resources'][key]
else:raise AssertionError(a)
save()
if out is not None:print(json.dumps(out,separators=(',',':')))
raise SystemExit(code)
''')
    fake.chmod(0o700)
    def run(env=None,**changes):
        # env: what the RUNTIME exports around the helper (repair's new-round signal).
        value = json.loads(cluster.read_bytes()); value.update(changes); cluster.write_text(json.dumps(value))
        # The caller deliberately disables errexit for the function call.
        command = f'source {shlex.quote(str(HELPER))}; rc=0; verification_account_cleanup web-pod 1234abcd /data/verification/1234abcd old-generation || rc=$?; exit "$rc"'
        return subprocess.run(['bash','-c',command], capture_output=True, text=True, timeout=20,
            env={**os.environ,'PATH':str(binary)+os.pathsep+os.environ['PATH'],'VC_CLUSTER':str(cluster),
                 'CONTEXT':'synthetic','NAMESPACE':'legal','RELEASE':'gsj','STATE_DIR':str(state),'OPERATION':'operation','GSJ_WORK':str(work),
                 **(env or {})})
    return run, cluster, state


@pytest.mark.parametrize('code',[0,77])
def test_sealed_job_uses_old_generation_and_uid_preconditioned_cleanup(cleanup_client,code):
    run,cluster,state=cleanup_client
    result=run(finalize_code=code)
    assert result.returncode==code,result.stderr
    value=json.loads(cluster.read_bytes())
    assert [x['kind'] for x in value['deletions']]==['job','pod','configmap']
    assert all(x['body']['preconditions']['uid'] for x in value['deletions'])
    assert list(value['resources'])==['job/gsj-provision']
    assert (state/'verification.json').is_file()
    assert not any('apply' in x or 'replace' in x for x in value['calls'])


def test_busy_or_unsealed_verifier_never_creates_an_admin_job(cleanup_client):
    run,cluster,_=cleanup_client
    assert run(resume_code=78).returncode==78
    assert run(resume_code=1).returncode==1
    assert not any(c[0] in ('create','patch','delete') for c in json.loads(cluster.read_bytes())['calls'])


def test_read_failure_is_closed_even_when_outer_function_is_in_or_list(cleanup_client):
    run,cluster,_=cleanup_client
    assert run(fail_owned_read=True).returncode==55
    assert not any(c[0]=='create' for c in json.loads(cluster.read_bytes())['calls'])


def test_failed_attempt_evidence_is_preserved_then_stopped_controls_retire_after_account_proof(cleanup_client):
    run,cluster,state=cleanup_client
    result=run(failed_attempts=1)
    assert result.returncode==77,result.stderr
    value=json.loads(cluster.read_bytes())
    assert 'job/gsj-verify-1234abcd-a1' not in value['resources']
    assert 'configmap/gsj-verify-1234abcd-a1' not in value['resources']
    assert (state/'verification-cleanup-1234abcd/attempt-1-job.json').is_file()
    assert json.loads((state/'verification-cleanup-1234abcd/control-report.json').read_bytes())['status']=='clean'
    creates=[c for c in value['calls'] if c[0]=='create']
    assert len(creates)==4
    assert len(value['deletions'])==6


def test_three_failed_attempts_are_terminal_across_retry(cleanup_client):
    """Only repair may open one new bounded account-cleanup round: a spent round
    still refuses every unsignalled re-entry, and names the command that actually
    reopens it. Exit 80 is that refusal, so the runtime can point at repair
    instead of back at resume."""
    run,cluster,state=cleanup_client
    first=run(failed_attempts=3)
    assert first.returncode==80,first.stderr
    assert 'repair --operation' in first.stderr
    before=json.loads(cluster.read_bytes());created=len([c for c in before['calls'] if c[0]=='create'])
    assert created==6
    second=run()
    assert second.returncode==80,second.stderr
    after=json.loads(cluster.read_bytes())
    assert len([c for c in after['calls'] if c[0]=='create'])==created
    assert len([k for k in after['resources'] if k.startswith('job/gsj-verify')])==3
    assert not after.get('deletions')
    assert not (state/'verification-cleanup-1234abcd/round-1').exists()


def test_repair_opens_one_new_round_that_archives_and_retires_the_spent_one(cleanup_client):
    """The sanctioned exit from a spent ladder: repair's explicit signal retires
    the spent round's stopped controls by recorded UID, ARCHIVES its evidence
    under round-1/ and runs three fresh attempts under round-suffixed names."""
    run,cluster,state=cleanup_client
    assert run(failed_attempts=3).returncode==80
    spent=json.loads(cluster.read_bytes())
    uids={k:v['metadata']['uid'] for k,v in spent['resources'].items() if k.startswith(('job/gsj-verify','configmap/gsj-verify'))}
    assert len(uids)==6
    saved=state/'verification-cleanup-1234abcd'
    result=run(failed_attempts=0,env={'GSJ_CLEANUP_NEW_ROUND':'1'})
    assert result.returncode==77,result.stderr
    value=json.loads(cluster.read_bytes())
    # the spent round: retired in the cluster by recorded UID, retained on disk
    assert not [k for k in value['resources'] if k.startswith(('job/gsj-verify','configmap/gsj-verify'))]
    assert set(uids.values()) <= {x['body']['preconditions']['uid'] for x in value['deletions']}
    archived=sorted(p.name for p in (saved/'round-1').iterdir())
    assert {'owned-users.json','attempt-1.json','attempt-1-job.json','attempt-3.json','control-report.json'} <= set(archived)
    assert json.loads((saved/'round-1/attempt-1.json').read_text())['metadata']['name']=='gsj-verify-1234abcd-a1'
    assert json.loads((saved/'round-1/control-report.json').read_bytes())['status']=='clean'
    # the new round: fresh immutable names, a receipt that says round 2
    assert len([c for c in value['calls'] if c[0]=='create'])==8
    plan=json.loads((saved/'attempt-1.json').read_text())
    assert plan['metadata']['name']=='gsj-verify-1234abcd-r2-a1'
    receipt=json.loads(plan['data']['receipt.json'])
    assert (receipt['round'],receipt['attempt'],receipt['max_attempts'])==(2,1,3)
    assert json.loads((saved/'control-report.json').read_bytes())['status']=='clean'
    assert (state/'verification.json').is_file()


def test_the_third_round_is_the_cap_and_no_signal_opens_a_fourth(cleanup_client):
    run,cluster,state=cleanup_client
    saved=state/'verification-cleanup-1234abcd'
    for spent in (1,2): (saved/f'round-{spent}').mkdir(parents=True)
    result=run(failed_attempts=3,env={'GSJ_CLEANUP_NEW_ROUND':'1'})
    assert result.returncode==1,result.stderr
    assert 'bounded cleanup rounds are exhausted' in result.stderr
    value=json.loads(cluster.read_bytes())
    assert sorted(k for k in value['resources'] if k.startswith('job/gsj-verify'))==[
        'job/gsj-verify-1234abcd-r3-a1','job/gsj-verify-1234abcd-r3-a2','job/gsj-verify-1234abcd-r3-a3']
    assert not (saved/'round-3').exists()
    assert not value.get('deletions')


@pytest.mark.parametrize('fault',['drift_job','wrong_result','replace_on_delete'])
def test_template_identity_result_and_uid_replacement_refuse(cleanup_client,fault):
    run,cluster,_=cleanup_client
    assert run(**{fault:True}).returncode==1
    value=json.loads(cluster.read_bytes())
    if fault=='replace_on_delete':
        assert value['resources']['job/gsj-verify-1234abcd-a1']['metadata']['uid']=='replacement-uid'
    else:
        assert not value.get('deletions')
        assert not any('--finalize-cleanup' in c for c in value['calls'])


def test_lost_job_create_reply_reuses_actual_job_and_active_retry_does_not_create(cleanup_client):
    run,cluster,_=cleanup_client
    first=run(lose_job_create=True,active=True,wait_stays_active=True)
    assert first.returncode==1,first.stderr
    before=json.loads(cluster.read_bytes());count=len([c for c in before['calls'] if c[0]=='create'])
    second=run(wait_stays_active=False)
    assert second.returncode==77,second.stderr
    after=json.loads(cluster.read_bytes())
    assert len([c for c in after['calls'] if c[0]=='create'])==count


def test_missing_old_job_consumes_an_attempt_without_recreation(cleanup_client):
    run,cluster,_=cleanup_client
    assert run(active=True,wait_stays_active=True).returncode==1
    value=json.loads(cluster.read_bytes());del value['resources']['job/gsj-verify-1234abcd-a1'];cluster.write_text(json.dumps(value))
    result=run(active=False,wait_stays_active=False)
    assert result.returncode==77,result.stderr
    value=json.loads(cluster.read_bytes())
    assert 'configmap/gsj-verify-1234abcd-a1' not in value['resources']
    assert len([c for c in value['calls'] if c[0]=='create'])==4


@pytest.mark.parametrize('fault', ['fail_mark_finalized', 'fail_delete_configmap'])
def test_terminal_resume_retires_controls_without_recreating_admin_work(cleanup_client, fault):
    run, cluster, state = cleanup_client
    first = run(**{fault: True})
    assert first.returncode not in (0, 77), first.stderr
    before = json.loads(cluster.read_bytes())
    assert before['resume_code'] == 77
    creates = len([c for c in before['calls'] if c[0] == 'create'])
    second = run()
    assert second.returncode == 77, second.stderr
    after = json.loads(cluster.read_bytes())
    assert len([c for c in after['calls'] if c[0] == 'create']) == creates
    assert list(after['resources']) == ['job/gsj-provision']
    assert (state / 'verification-cleanup-1234abcd/cleanup-result.json').is_file()


def test_lost_configmap_reply_preserves_the_intent_on_retry_and_retires_it_at_the_terminal_when_no_job_exists(cleanup_client):
    """A plan whose Job UID was never recorded. On RETRY the intent is preserved
    (the create may have happened); at the TERMINAL the cluster is asked by the
    Job's deterministic name — absent means no Job ever existed under this intent,
    so the plan is retired and the run can claim clean. Before this, the retirement
    refused with `unknown cleanup Job UID` for ever."""
    run, cluster, state = cleanup_client
    result = run(lose_configmap_create=True)
    assert result.returncode == 77, result.stderr
    assert 'has an unknown missing Job; preserving intent' in result.stderr
    assert 'unknown cleanup Job UID' not in result.stderr
    report = json.loads((state/'verification-cleanup-1234abcd/control-report.json').read_bytes())
    assert report['status'] == 'clean'
    assert any(r['kind'] == 'Job' and r['name'] == 'gsj-verify-1234abcd-a1' and r['phase'] == 'never-created' for r in report['resources'])
    value = json.loads(cluster.read_bytes())
    assert 'configmap/gsj-verify-1234abcd-a1' not in value['resources']
    assert 'job/gsj-verify-1234abcd-a1' not in value['resources']
    assert len([c for c in value['calls'] if c[0] == 'create']) == 3


def test_a_job_whose_uid_was_never_recorded_is_adopted_by_exact_identity_before_retirement(cleanup_client):
    """The other half of an unrecorded Job UID: the plan lost its Job UID but the
    Job exists under the plan's exact identity (labels, namespace UID, ownership
    digest, owner reference, template). The terminal retirement adopts that UID —
    recording it on the plan with the same CAS write the create path makes — and
    then retires by it."""
    run, cluster, state = cleanup_client
    result = run(forget_job_uid=True)   # the ordinary terminal path, with every plan read forgetting its recorded Job UID
    assert result.returncode == 77, result.stderr
    assert 'unknown cleanup Job UID' not in result.stderr
    value = json.loads(cluster.read_bytes())
    adoptions = [c for c in value['calls'] if c[0] == 'patch' and c[1] == 'configmap']
    assert adoptions, 'the adopted UID must be recorded on the plan before anything is deleted'
    report = json.loads((state/'verification-cleanup-1234abcd/control-report.json').read_bytes())
    assert report['status'] == 'clean'
    assert any(r['kind'] == 'Job' and r['phase'] == 'adopted' and r['disposition'] == 'recorded' for r in report['resources'])
    assert not [k for k in value['resources'] if k.startswith('job/gsj-verify') or k.startswith('configmap/gsj-verify')]


def test_a_saved_intent_belonging_to_another_round_is_refused(cleanup_client):
    """The receipt now carries its round, and the plan identity check reads it:
    an intent of a different round can never be adopted by this ladder."""
    run, cluster, _ = cleanup_client
    assert run(active=True, wait_stays_active=True).returncode == 1
    value = json.loads(cluster.read_bytes())
    plan = value['resources']['configmap/gsj-verify-1234abcd-a1']
    receipt = json.loads(plan['data']['receipt.json']); receipt['round'] = 2
    plan['data']['receipt.json'] = json.dumps(receipt)
    cluster.write_text(json.dumps(value))
    creates = len([c for c in value['calls'] if c[0] == 'create'])
    result = run(active=False, wait_stays_active=False)
    assert result.returncode == 1, result.stderr
    assert 'cleanup attempt budget record differs' in result.stderr
    after = json.loads(cluster.read_bytes())
    assert len([c for c in after['calls'] if c[0] == 'create']) == creates
    assert not after.get('deletions')


@pytest.mark.parametrize('fault', ['uid', 'ownership', 'generation', 'budget', 'job_uid'])
def test_saved_intent_or_job_identity_cannot_drift_between_retries(cleanup_client, fault):
    run, cluster, _ = cleanup_client
    assert run(active=True, wait_stays_active=True).returncode == 1
    value = json.loads(cluster.read_bytes())
    plan = value['resources']['configmap/gsj-verify-1234abcd-a1']
    if fault == 'uid': plan['metadata']['uid'] = 'replacement-intent'
    elif fault == 'ownership': plan['data']['owned-users.json'] = '{}'
    elif fault == 'job_uid': value['resources']['job/gsj-verify-1234abcd-a1']['metadata']['uid'] = 'replacement-job'
    else:
        receipt = json.loads(plan['data']['receipt.json'])
        receipt['generation' if fault == 'generation' else 'max_attempts'] = 'wrong' if fault == 'generation' else 30
        plan['data']['receipt.json'] = json.dumps(receipt)
    cluster.write_text(json.dumps(value))
    creates = len([c for c in value['calls'] if c[0] == 'create'])
    assert run().returncode == 1
    after = json.loads(cluster.read_bytes())
    assert len([c for c in after['calls'] if c[0] == 'create']) == creates
    assert not after.get('deletions')


def test_lease_loss_prevents_even_a_fresh_admin_job(cleanup_client):
    run, cluster, _ = cleanup_client
    assert run(holder='different-operation').returncode == 1
    assert not any(c[0] in ('exec', 'create', 'patch', 'delete') for c in json.loads(cluster.read_bytes())['calls'])


def test_terminal_with_no_accounts_performs_no_admin_work(cleanup_client):
    run, cluster, _ = cleanup_client
    value = json.loads(cluster.read_bytes()); value['owned']['users'] = []; cluster.write_text(json.dumps(value))
    result = run(resume_code=77)
    assert result.returncode == 77, result.stderr
    assert not any(c[0] in ('create', 'patch', 'delete') for c in json.loads(cluster.read_bytes())['calls'])


def test_live_orphan_pod_prevents_terminal_cleanup_until_exact_owner_pod_stops(cleanup_client):
    run, cluster, state = cleanup_client
    assert run(active=True, wait_stays_active=True).returncode == 1
    value = json.loads(cluster.read_bytes())
    job = value['resources']['job/gsj-verify-1234abcd-a1']; uid = job['metadata']['uid']
    del value['resources']['job/gsj-verify-1234abcd-a1']
    value['resources']['pod/orphan'] = {'metadata': {'name': 'orphan', 'uid': 'orphan-uid', 'ownerReferences': [{'kind': 'Job', 'uid': uid}]},
        'status': {'phase': 'Running', 'containerStatuses': [{'name': 'provision', 'state': {'running': {}}}]}}
    cluster.write_text(json.dumps(value))
    result = run(resume_code=77)
    assert result.returncode == 1 and 'has not stopped' in result.stderr
    value = json.loads(cluster.read_bytes()); assert not value.get('deletions')
    value['resources']['pod/orphan']['status'] = {'phase': 'Failed', 'containerStatuses': [{'name': 'provision', 'state': {'terminated': {'exitCode': 137}}}]}
    cluster.write_text(json.dumps(value))
    result = run()
    assert result.returncode == 77, result.stderr
    value = json.loads(cluster.read_bytes())
    assert 'pod/orphan' not in value['resources'] and 'configmap/gsj-verify-1234abcd-a1' not in value['resources']
    proof = json.loads((state/'verification-cleanup-1234abcd/control-report.json').read_bytes())
    assert proof['status'] == 'clean'
    assert any(r['uid'] == 'orphan-uid' and r['disposition'] == 'removed' for r in proof['resources'])
