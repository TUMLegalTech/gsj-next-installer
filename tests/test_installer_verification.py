"""Exercise installer decisions across verifier interruptions and stale handoffs."""
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess

import pytest

from tests.test_installer import INSTALLER, _release, _site


@pytest.fixture
def verification(tmp_path):
    source=(INSTALLER/'runtime.sh').read_text().split('# ENTRY POINT',1)[0].replace('@CLIENT_TABLE@','')
    functions=tmp_path/'functions.sh'; functions.write_text(source)
    work=tmp_path/'work'; work.mkdir()
    payload=work/'payload';payload.mkdir()  # bootstrap's layout: this installer's own payload
    site=_site(); site['verification'].update(ca_file='',connect_host='')
    (work/'site.json').write_text(json.dumps(site))
    release=_release(); release['corpus'].update(fingerprint='b'*64,rows=3)
    (payload/'release.json').write_text(json.dumps(release))
    (work/'operation.json').write_text(json.dumps({'operation':'a'*24,'target':'synthetic-release','status':'initializing'}))
    password=tmp_path/'password';password.write_text('SYNTHETIC_PASSWORD_DO_NOT_ECHO');password.chmod(0o600)
    api=tmp_path/'api.py'
    api.write_text('''import json,os,pathlib,sys
root=pathlib.Path(os.environ['TEST_ROOT']); a=sys.argv[1:]
s=json.loads((root/'api.json').read_text()); mode=os.environ.get('ACTION','k')
def path(p): return root/'remote'/p.lstrip('/')
def finish(): (root/'api.json').write_text(json.dumps(s))
if mode=='cleanup':
 remote=a[2]; code=s.get('cleanup_code',0)
 p=path(remote+'/report.json'); data=json.loads(p.read_text())
 if data['status'] in ['passed','cleaned-reverify-required']:
  s['calls'].append('retire'); code=0 if data['status']=='passed' else 77
 else:
  s['calls'].append('cleanup'); data['status']='passed' if code==0 else 'cleaned-reverify-required'; p.write_text(json.dumps(data))
 control=root/'work'/('verification-cleanup-'+a[1]);control.mkdir(exist_ok=True)
 (control/'control-report.json').write_text(json.dumps({'format':'gsj.verification-control-cleanup/1','run_id':a[1],'namespace_uid':'namespace-id','status':'clean'}))
 finish(); raise SystemExit(code)
if a[:2]==['get','namespace']: print(json.dumps({'metadata':{'uid':'namespace-id'}}))
elif a[:2]==['get','pods']: print(json.dumps({'items':[{'metadata':{'name':'synthetic-pod'},'status':{'phase':'Running'}}]}))
elif a[:2]==['get','cm']: print(json.dumps({'data':{'generation':'new-generation'}}))
elif a[:1]==['exec']:
 c=a[a.index('--')+1:]
 if c[:3]==['python','-m','gsj_deploy.verify']:
  arg=next((v for v in ['--bot-negative','--finish','--cleanup','--resume'] if v in c),'initial')
  s['calls'].append(arg)
  code=s['codes'].pop(0)
  if '--bot-negative' in c:
   print('{}')
  elif code!=78:
   settings=json.loads(path(c[c.index('--settings')+1]).read_text())
   directory=path(settings['report_dir']); directory.mkdir(parents=True,exist_ok=True)
   ledger=directory/'ledger.json'
   if not ledger.exists(): ledger.write_text(json.dumps({'generation':settings['generation'],'run_id':settings['run_id'],'cases':[{'id':'case-id','owner':'owner'}],'users':[{'login':'owner','id':1}]}))
   (directory/'report.json').write_text(json.dumps({'run_id':settings['run_id'],'status':'passed' if code==0 else ('cleaned-reverify-required' if code==77 else 'pending')}))
   s.setdefault('bindings',[]).append({k:settings[k] for k in ['generation','run_id','expected_corpus_fingerprint','lock_dir','connect_host','connect_port']})
  finish(); raise SystemExit(code)
 elif c[:2]==['python','-c']:
  if 'sys.stdin.buffer.read()' in c[2]:
   p=path(c[3]);p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(sys.stdin.buffer.read())
  elif 'ledger.json' in c[2]: print(json.dumps(path(c[3]+'/ledger.json').is_file()))
  elif 'create_connection' in c[2]:
   staged=json.loads(path(c[3]).read_text())
   s.setdefault('probes',[]).append({k:staged.get(k) for k in ['web_url','connect_host','connect_port','ca_file']})
   code=s['probe_codes'].pop(0) if s.get('probe_codes') else 0
   if code==74: print(s.get('probe_reason',''))  # the refused handshake's reason, as the real probe prints it
   finish(); raise SystemExit(code)
  else: raise SystemExit('unknown private staging command')
 elif c[:1]==['cat']: sys.stdout.buffer.write(path(c[1]).read_bytes())
 elif c[:2]==['rm','-f']:
  for name in c[2:]: path(name).unlink(missing_ok=True)
  if s.pop('fail_after_remove',False):
   for name in c[2:]:
    if name.endswith('/settings.json'):(root/'work/verification'/pathlib.Path(name).parent.name/'settings.json').unlink(missing_ok=True)
   finish();raise SystemExit(29)
 elif c[:2]==['sh','-c']:
  text=c[2]
  if 'cat > ' in text:
   dest=text.split('cat > ',1)[1].strip("' ")
   p=path(dest);p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(sys.stdin.buffer.read())
  else: raise SystemExit('unknown shell staging command')
 else: raise SystemExit('unknown exec command')
else: raise SystemExit('unknown Kubernetes command')
finish()
''')
    state=tmp_path/'api.json'; state.write_text(json.dumps({'codes':[],'calls':[]}))
    def run(codes,cleanup_code=0,probe_codes=(),prelude='',probe_reason=''):
        # The Pod-side route preflight answers 0 unless probe_codes says otherwise;
        # an exit 74 prints probe_reason (the handshake's verify message or error class).
        # prelude runs just before verify_application (a continuation's target override).
        s=json.loads(state.read_text());s.update(codes=codes,cleanup_code=cleanup_code,probe_codes=list(probe_codes),probe_reason=probe_reason);state.write_text(json.dumps(s))
        body=f'''source {shlex.quote(str(functions))}
trap 'printf "RECOVERY_HINT=%s\\n" "${{RECOVERY_HINT:-}}" >&2' EXIT
assert_owner() {{ :; }}
k() {{ python3 {shlex.quote(str(api))} "$@"; }}
public_verify() {{ :; }}
network_verify() {{ :; }}
verification_account_cleanup() {{ ACTION=cleanup python3 {shlex.quote(str(api))} "$@"; }}
{prelude}
verify_application
'''
        env={**os.environ,'TEST_ROOT':str(tmp_path),'GSJ_WORK':str(work),'STATE_DIR':str(work),'GSJ_PAYLOAD':str(payload),
             'SITE':str(work/'site.json'),'OP_PASSWORD':str(password),'OPERATION':'a'*24,'RELEASE_ID':'synthetic-release','RELEASE':'gsj','NAMESPACE':'synthetic-namespace'}
        return subprocess.run(['bash','-c',body],env=env,text=True,capture_output=True,timeout=20)
    return run,state,work,tmp_path


def hint(result):
    """The RECOVERY_HINT the installer's EXIT trap would print ('' = default resume)."""
    return [line for line in result.stderr.splitlines() if line.startswith('RECOVERY_HINT=')][-1].split('=',1)[1]


def edit_site(work,change):
    site=json.loads((work/'site.json').read_text()); change(site); (work/'site.json').write_text(json.dumps(site))


def set_route(work,host,port):
    edit_site(work,lambda site:site['verification'].update(connect_host=host,connect_port=port))


@pytest.mark.parametrize('code',[78,1])
def test_unresolved_verifier_never_uses_stale_account_cleanup(verification,code):
    run,state,work,root=verification
    (work/'cleanup-users.json').write_text('{"stale":true}')
    result=run([code])
    assert result.returncode!=0
    assert json.loads(state.read_text())['calls']==['initial']
    assert json.loads((work/'verification-active.json').read_text())['status']=='active'
    assert 'SYNTHETIC_PASSWORD_DO_NOT_ECHO' not in result.stdout+result.stderr


def test_finish_cleanup_retains_public_ledger_and_removes_only_protected_settings(verification):
    run,state,work,root=verification
    result=run([76,0,75])
    assert result.returncode==0,result.stderr
    assert json.loads(state.read_text())['calls']==['initial','--bot-negative','--finish','cleanup']
    active=json.loads((work/'verification-active.json').read_text());rid=active['run_id']
    assert active['status']=='complete'
    assert (root/'remote/data/verification'/rid/'ledger.json').exists()
    assert not (root/'remote/data/verification'/rid/'settings.json').exists()
    assert not (work/'verification'/rid/'settings.json').exists()
    assert json.loads((work/'verification.json').read_text())['status']=='passed'
    public = json.loads((work/'verification'/rid/'public-settings.json').read_text())
    assert public['db_path'] == '/data/db/gsj.db'
    assert json.loads((work/'verification.json').read_text())['control_cleanup']['status']=='clean'
    assert 'operator_password' not in json.loads((work/'verification'/rid/'public-settings.json').read_text())


def test_failed_owned_run_is_cleaned_then_requires_new_named_attempt(verification):
    run,state,work,root=verification
    failed=run([75],77)
    assert failed.returncode!=0
    prior=json.loads((work/'verification-active.json').read_text())
    assert prior['status']=='cleaned'
    assert not (work/'verification.json').exists()
    retried=run([77,75],0)
    assert retried.returncode==0,retried.stderr
    current=json.loads((work/'verification-active.json').read_text())
    assert current['run_id']!=prior['run_id']
    assert json.loads((work/'operation.json').read_text())['verification_attempts']==2


def test_a_spent_cleanup_round_names_repair_instead_of_sending_resume_back(verification):
    """Only repair may open one new bounded account-cleanup round: the helper's
    exit 80 says its three durable account-cleanup attempts are spent. Named
    resume re-enters the same ladder, so the installer must name repair — the
    one command that opens a new bounded round — instead of the generic 'use
    named resume', which running it showed to be a dead end."""
    run,state,work,root=verification
    result=run([75],80)
    assert result.returncode!=0
    assert 'named resume would only repeat them' in result.stderr
    assert 'repair --operation '+'a'*24 in result.stderr
    assert hint(result)=='repair --operation '+'a'*24
    assert 'use named resume' not in result.stderr
    assert json.loads((work/'verification-active.json').read_text())['status']=='active'
    assert not (work/'verification.json').exists()


def test_named_resume_uses_original_run_and_does_not_recreate_users(verification):
    run,state,work,root=verification
    result=run([1]);assert result.returncode!=0
    prior=json.loads((work/'verification-active.json').read_text())
    result=run([75]);assert result.returncode==0,result.stderr
    assert json.loads(state.read_text())['calls']==['initial','--resume','cleanup']
    assert json.loads((work/'verification-active.json').read_text())['run_id']==prior['run_id']


def test_changed_release_cleans_old_binding_before_fresh_acceptance(verification):
    run,state,work,root=verification
    assert run([1]).returncode!=0
    active_path=work/'verification-active.json';old=json.loads(active_path.read_text())
    old['release']='older-release';old['generation']='older-generation';active_path.write_text(json.dumps(old))
    settings=work/'verification'/old['run_id']/'settings.json';data=json.loads(settings.read_text())
    data['generation']='older-generation';data['expected_corpus_fingerprint']='c'*64;settings.write_text(json.dumps(data))
    result=run([77,75])
    assert result.returncode==0,result.stderr
    actual=json.loads(state.read_text())
    assert actual['calls']==['initial','--cleanup','retire','initial','cleanup']
    assert actual['bindings'][1]['generation']=='older-generation'
    assert actual['bindings'][1]['expected_corpus_fingerprint']=='c'*64
    assert actual['bindings'][2]['generation']=='new-generation'
    assert actual['bindings'][2]['run_id']!=old['run_id']


def test_missing_started_ledger_is_not_silently_recreated(verification):
    run,state,work,root=verification
    assert run([1]).returncode!=0
    active=json.loads((work/'verification-active.json').read_text())
    (root/'remote/data/verification'/active['run_id']/'ledger.json').unlink()
    result=run([75]);assert result.returncode!=0
    assert json.loads(state.read_text())['calls']==['initial']
    assert 'ownership ledger is missing' in result.stderr


def test_retry_budget_is_persistent_before_any_new_verifier_mutation(verification):
    run,state,work,root=verification
    op=json.loads((work/'operation.json').read_text());op['verification_attempts']=3
    (work/'operation.json').write_text(json.dumps(op))
    result=run([75]);assert result.returncode!=0
    assert json.loads(state.read_text())['calls']==[]


def test_terminal_reconnect_after_private_settings_removed_revalidates_same_run(verification):
    run,state,work,root=verification
    api=json.loads(state.read_text());api['fail_after_remove']=True;state.write_text(json.dumps(api))
    interrupted=run([75]);assert interrupted.returncode!=0
    active=json.loads((work/'verification-active.json').read_text());rid=active['run_id']
    assert active['status']=='complete'
    assert active['report_sha256'] and active['control_sha256']
    assert not (work/'verification'/rid/'settings.json').exists()
    assert not (root/'remote/data/verification'/rid/'settings.json').exists()
    resumed=run([0]);assert resumed.returncode==0,resumed.stderr
    assert json.loads(state.read_text())['calls']==['initial','cleanup','--resume','retire']
    assert json.loads((work/'verification-active.json').read_text())['run_id']==rid
    assert json.loads((work/'operation.json').read_text())['verification_attempts']==1


@pytest.mark.parametrize('codes',[[79],[76,79],[76,0,79]])
def test_terminal_bot_check_code_stops_without_resume_advice_or_cleanup(verification,codes):
    run,state,work,root=verification
    result=run(codes)
    assert result.returncode!=0
    assert 'terminal' in result.stderr and 'use named resume' not in result.stderr
    assert 'cleanup' not in json.loads(state.read_text())['calls']
    assert json.loads((work/'verification-active.json').read_text())['status']=='active'
    assert 'SYNTHETIC_PASSWORD_DO_NOT_ECHO' not in result.stdout+result.stderr


def test_operator_password_is_staged_off_the_data_volume_and_removed_on_completion(verification):
    run,state,work,root=verification
    assert run([1]).returncode!=0
    rid=json.loads((work/'verification-active.json').read_text())['run_id']
    staged=root/'remote/tmp/gsj-verification'/rid/'settings.json'
    assert json.loads(staged.read_text())['operator_password']=='SYNTHETIC_PASSWORD_DO_NOT_ECHO'
    assert not any(b'SYNTHETIC_PASSWORD_DO_NOT_ECHO' in path.read_bytes()
                   for path in (root/'remote/data').rglob('*') if path.is_file())
    assert run([75]).returncode==0
    assert not staged.exists()


def test_unreachable_route_fails_fast_before_any_verifier(verification):
    # The replayed restore: the tools vantage passed, the Pod cannot dial the route.
    run,state,work,root=verification
    set_route(work,'host.docker.internal',18446)
    result=run([],probe_codes=[73])
    assert result.returncode!=0
    api=json.loads(state.read_text())
    assert api['calls']==[]
    assert api['probes']==[{'web_url':'https://legal.example','connect_host':'host.docker.internal','connect_port':18446,'ca_file':''}]
    for text in ('origin-unreachable','verification route host.docker.internal:18446','verification.connect_host',
                 'verification.connect_port','30443','No verifier was started'):
        assert text in result.stderr
    assert hint(result)=='resume --operation '+'a'*24+' after correcting verification.connect_host/connect_port'
    active=json.loads((work/'verification-active.json').read_text())
    assert active['status']=='active' and active['launched'] is False
    assert not (root/'remote/data/verification'/active['run_id']/'ledger.json').exists()
    assert json.loads((work/'operation.json').read_text())['verification_attempts']==1
    assert 'SYNTHETIC_PASSWORD_DO_NOT_ECHO' not in result.stdout+result.stderr
    set_route(work,'node-control-plane',30443)
    resumed=run([0])
    assert resumed.returncode==0,resumed.stderr
    api=json.loads(state.read_text())
    assert api['calls']==['initial','retire']
    assert (api['probes'][-1]['connect_host'],api['probes'][-1]['connect_port'])==('node-control-plane',30443)
    assert json.loads((work/'verification-active.json').read_text())['run_id']==active['run_id']
    assert json.loads((work/'operation.json').read_text())['verification_attempts']==1


CA_REASON='CA cert does not include key usage extension'
WAIT='each needs the operation Lease unrenewed for 180 seconds, so wait 3 minutes before each'
SERVED='once the certificate served for https://legal.example passes strict verification from the Pod'


def managed_ca(work,produced_by_tls_repair=False):
    """The managed local CA's saved bytes; with tls-repair's receipt when that command produced them."""
    ca=work/'tls'/'ca.crt'; ca.parent.mkdir(exist_ok=True); ca.write_bytes(b'synthetic managed CA\n')
    if produced_by_tls_repair:
        (work/'tls-repair.json').write_text(json.dumps({'after_ca_sha256':hashlib.sha256(ca.read_bytes()).hexdigest()}))


@pytest.mark.parametrize('profile,reason,produced,named',[
    ('managed-local-ca',CA_REASON,False,True),
    ('managed-local-ca','Basic Constraints of CA cert not marked critical',False,True),
    ('managed-local-ca','Missing Subject Key Identifier',False,True),
    ('managed-local-ca',CA_REASON,True,False),  # tls-repair already produced this CA: never a loop
    ('managed-local-ca','Missing Authority Key Identifier',False,False),  # the served leaf, which tls-repair keeps
    ('managed-local-ca','unable to get local issuer certificate',False,False),  # a wrong trust anchor
    ('managed-local-ca','TimeoutError',False,False),
    ('files',CA_REASON,False,False),
])
def test_tls_preflight_names_tls_repair_only_for_a_managed_ca_defect_it_repairs(verification,profile,reason,produced,named):
    run,state,work,root=verification
    edit_site(work,lambda site:site['tls'].update(profile=profile))
    managed_ca(work,produced)
    result=run([],probe_codes=[74],probe_reason=reason)
    assert result.returncode!=0 and json.loads(state.read_text())['calls']==[]
    assert f'({reason}; origin-tls-failed)' in result.stderr and 'verification.ca_file' in result.stderr
    assert 'No verifier was started' in result.stderr
    operation='a'*24
    if named:
        assert hint(result)==f'tls-repair --operation {operation}, then resume --operation {operation}; {WAIT}'
        assert 'No installer command replaces this certificate' not in result.stderr
    else:
        assert 'tls-repair' not in result.stderr
        assert hint(result)==f'resume --operation {operation} {SERVED}'
        assert ('No installer command replaces this certificate: correct it in TLS Secret gsj-tls or the contents of '
                'verification.ca_file at their source, keeping the configured paths, or, if the route reaches another '
                'endpoint, correct verification.connect_host/connect_port; then resume') in result.stderr
    active=json.loads((work/'verification-active.json').read_text())
    assert active['status']=='active' and active['launched'] is False
    assert 'SYNTHETIC_PASSWORD_DO_NOT_ECHO' not in result.stdout+result.stderr


def test_a_ca_refusal_launches_nothing_and_one_resume_after_tls_repair_completes(verification):
    # The strict-TLS incident: the Pod refuses the managed CA before any
    # verifier exists. tls-repair rewrites only the CA bytes and records them; a
    # second refusal of that CA names no tls-repair; the resume that passes
    # reuses the unlaunched run on its first attempt.
    run,state,work,root=verification
    edit_site(work,lambda site:site['tls'].update(profile='managed-local-ca'))
    managed_ca(work)
    refused=run([],probe_codes=[74],probe_reason=CA_REASON)
    assert refused.returncode!=0 and hint(refused).startswith('tls-repair --operation')
    assert json.loads(state.read_text())['calls']==[]
    active=json.loads((work/'verification-active.json').read_text());rid=active['run_id']
    assert active['status']=='active' and active['launched'] is False
    assert (root/'remote/tmp/gsj-verification'/rid/'settings.json').exists()  # staged before the check
    assert not (root/'remote/data/verification'/rid/'ledger.json').exists()
    assert 'SYNTHETIC_PASSWORD_DO_NOT_ECHO' not in refused.stdout+refused.stderr
    (work/'tls'/'ca.crt').write_bytes(b'synthetic reissued managed CA\n')
    managed_ca_receipt={'after_ca_sha256':hashlib.sha256(b'synthetic reissued managed CA\n').hexdigest()}
    (work/'tls-repair.json').write_text(json.dumps(managed_ca_receipt))
    again=run([],probe_codes=[74],probe_reason=CA_REASON)
    assert again.returncode!=0 and 'tls-repair' not in again.stderr and hint(again)==f'resume --operation {"a"*24} {SERVED}'
    resumed=run([75])
    assert resumed.returncode==0,resumed.stderr
    assert json.loads(state.read_text())['calls']==['initial','cleanup']
    assert json.loads((work/'verification-active.json').read_text())['run_id']==rid
    assert json.loads((work/'operation.json').read_text())['verification_attempts']==1


@pytest.mark.parametrize('recovery,attempts',[('repair',1),('continuation',2)])
def test_a_refused_run_whose_binding_changed_is_retired_and_its_successor_charged_once(verification,recovery,attempts):
    # One rule for an unlaunched run: its own binding reuses it at no charge
    # (above); after a Helm re-apply changed the binding it is retired without
    # cleanup and this binding's fresh run is charged one attempt, against the
    # budget repair resets and a startup continuation keeps.
    run,state,work,root=verification
    edit_site(work,lambda site:site['tls'].update(profile='managed-local-ca'))
    managed_ca(work)
    assert run([],probe_codes=[74],probe_reason='Missing Authority Key Identifier').returncode!=0
    active_path=work/'verification-active.json';old=json.loads(active_path.read_text());rid=old['run_id']
    old['generation']='generation-before-helm';active_path.write_text(json.dumps(old))
    if recovery=='repair':
        set_route(work,'node-control-plane',30443)  # repair publishes the corrected site
        op=json.loads((work/'operation.json').read_text());del op['verification_attempts']
        (work/'operation.json').write_text(json.dumps(op))
    result=run([75])
    assert result.returncode==0,result.stderr
    assert f'Prior verification run {rid} was never launched; retired without cleanup' in result.stderr
    assert 'ownership ledger is missing' not in result.stderr
    api=json.loads(state.read_text())
    assert api['calls']==['initial','cleanup']
    current=json.loads(active_path.read_text())
    assert current['run_id']!=rid and current['generation']=='new-generation' and current['status']=='complete'
    assert (api['bindings'][0]['run_id'],api['bindings'][0]['generation'])==(current['run_id'],'new-generation')
    if recovery=='repair':
        assert (api['bindings'][0]['connect_host'],api['bindings'][0]['connect_port'])==('node-control-plane',30443)
    assert json.loads((work/'operation.json').read_text())['verification_attempts']==attempts


@pytest.mark.parametrize('code',[2,127])
def test_preflight_that_cannot_run_keeps_the_default_recovery(verification,code):
    run,state,work,root=verification
    result=run([],probe_codes=[code])
    assert result.returncode!=0
    assert f'could not run in the application Pod (exit {code})' in result.stderr
    assert hint(result)=='' and json.loads(state.read_text())['calls']==[]


@pytest.mark.parametrize('scenario',['complete','cleaned','old-binding'])
def test_only_an_active_run_dials_the_origin_before_its_verifier(verification,scenario):
    run,state,work,root=verification
    if scenario=='complete':
        api=json.loads(state.read_text());api['fail_after_remove']=True;state.write_text(json.dumps(api))
        assert run([75]).returncode!=0
        assert run([0]).returncode==0
        expected=(['initial','cleanup','--resume','retire'],1)
    elif scenario=='cleaned':
        assert run([75],77).returncode!=0
        assert run([77,75],0).returncode==0
        expected=(['initial','cleanup','--resume','retire','initial','cleanup'],2)
    else:
        assert run([1]).returncode!=0
        active_path=work/'verification-active.json';old=json.loads(active_path.read_text())
        old['release']='older-release';active_path.write_text(json.dumps(old))
        assert run([77,75]).returncode==0
        expected=(['initial','--cleanup','retire','initial','cleanup'],3)
    api=json.loads(state.read_text())
    assert (api['calls'],len(api['probes']))==expected


@pytest.mark.parametrize('launched',[False,True,'missing'])
def test_only_an_unlaunched_old_binding_retires_without_cleanup(verification,launched):
    run,state,work,root=verification
    assert run([],probe_codes=[73]).returncode!=0
    active_path=work/'verification-active.json';old=json.loads(active_path.read_text());rid=old['run_id']
    old['generation']='old-generation'
    if launched=='missing': del old['launched']
    else: old['launched']=launched
    active_path.write_text(json.dumps(old))
    staged=root/'remote/tmp/gsj-verification'/rid/'settings.json';settings=work/'verification'/rid/'settings.json'
    result=run([75])
    if launched is False:
        assert result.returncode==0,result.stderr
        assert json.loads(state.read_text())['calls']==['initial','cleanup']
        assert f'Prior verification run {rid} was never launched; retired without cleanup' in result.stderr
        assert not staged.exists() and not settings.exists()
        current=json.loads(active_path.read_text())
        assert current['run_id']!=rid and current['status']=='complete'
        assert json.loads((work/'operation.json').read_text())['verification_attempts']==2
    else:
        assert result.returncode!=0 and 'ownership ledger is missing after launch' in result.stderr
        assert json.loads(state.read_text())['calls']==[]
        assert json.loads(active_path.read_text())['status']=='active' and settings.exists()


def test_staging_refreshes_the_route_for_the_same_origin_on_every_pass(verification):
    run,state,work,root=verification
    set_route(work,'host.docker.internal',18446)
    assert run([],probe_codes=[73]).returncode!=0
    rid=json.loads((work/'verification-active.json').read_text())['run_id']
    public=work/'verification'/rid/'public-settings.json';original=public.read_bytes()
    assert json.loads(original)['connect_host']=='host.docker.internal'
    set_route(work,'node-control-plane',30443)
    assert run([1]).returncode!=0
    staged=json.loads((root/'remote/tmp/gsj-verification'/rid/'settings.json').read_text())
    assert (staged['connect_host'],staged['connect_port'])==('node-control-plane',30443)
    assert staged['operator_password']=='SYNTHETIC_PASSWORD_DO_NOT_ECHO'
    # A rebuild from the secret-free record under an upgrade/repair identity:
    # the old binding's cleanup also dials the current route for this origin.
    (work/'verification'/rid/'settings.json').unlink()
    active_path=work/'verification-active.json';old=json.loads(active_path.read_text())
    old['release']='older-release';active_path.write_text(json.dumps(old))
    result=run([77,75])
    assert result.returncode==0,result.stderr
    api=json.loads(state.read_text())
    assert api['calls']==['initial','--cleanup','retire','initial','cleanup']
    assert [(p['connect_host'],p['connect_port']) for p in api['probes']]==[('host.docker.internal',18446)]+[('node-control-plane',30443)]*3
    assert [(b['connect_host'],b['connect_port']) for b in api['bindings']]==[('node-control-plane',30443)]*3
    assert api['bindings'][0]['run_id']==api['bindings'][1]['run_id']==rid
    assert api['bindings'][0]['generation']==api['bindings'][1]['generation']
    assert public.read_bytes()==original


def test_a_run_for_another_origin_keeps_its_original_route(verification):
    run,state,work,root=verification
    set_route(work,'host.docker.internal',18446)
    assert run([],probe_codes=[73]).returncode!=0
    rid=json.loads((work/'verification-active.json').read_text())['run_id']
    for name in ('settings.json','public-settings.json'):
        path=work/'verification'/rid/name;data=json.loads(path.read_text());data['web_url']='https://old.example'
        path.write_text(json.dumps(data))
    set_route(work,'node-control-plane',30443)
    for code in (73,74):
        result=run([],probe_codes=[code])
        assert result.returncode!=0
        assert json.loads(state.read_text())['probes'][-1]=={'web_url':'https://old.example','connect_host':'host.docker.internal',
                                                               'connect_port':18446,'ca_file':''}
        # Correcting the current site cannot reach this run, so no correction is named.
        assert 'belongs to an earlier public_url, whose route the current site does not control' in result.stderr
        assert 'Set verification.connect_host' not in result.stderr and 'correct verification.connect_host' not in result.stderr
        assert hint(result)==''


RESTORE_FRESH=('restore its verified archive with the exact source installer in another Kubernetes context '
               'whose namespace synthetic-namespace is empty')


@pytest.mark.parametrize('continuation,older,resume,fresh',[
    ('CONTINUE_HELM_INSTALLER=/synthetic/older/gsj-install.sh',True,"with the operation's exact target installer",
     'install afresh into an empty namespace'),
    ('CONTINUE_HELM_INSTALLER=/synthetic/same/gsj-install.sh',False,"with the operation's exact target installer",
     'install afresh into an empty namespace'),
    ('RESTORE_PROGRAM_ACTIVE=true',True,'with this installer',RESTORE_FRESH),
    # The continuation's own named resume carries no flag; its saved intent
    # (a file, or any link where it would be) binds the site as resume_operation reads it.
    ('mkdir -p "$STATE_DIR/startup-helm-$OPERATION"; printf {} > "$STATE_DIR/startup-helm-$OPERATION/intent.json"',False,
     "with the operation's exact target installer",'install afresh into an empty namespace'),
    ('mkdir -p "$STATE_DIR/startup-helm-$OPERATION"; ln -sfn absent "$STATE_DIR/startup-helm-$OPERATION/intent.json"',False,
     "with the operation's exact target installer",'install afresh into an empty namespace'),
])
def test_a_continued_operation_names_no_route_correction(verification,continuation,older,resume,fresh):
    # A restore-program receipt or a startup Helm continuation (its flag, or on
    # its resume the saved intent) binds the exact saved site: no command
    # corrects its route. Resume once the route answers, or keep the operation
    # and take the fresh path. tls-repair rewrites only the managed CA's bytes,
    # which neither binds, so a CA defect it repairs still names it; a served
    # certificate or trust file corrected at its path is not saved configuration.
    run,state,work,root=verification
    target=root/'target-payload';target.mkdir()
    release=json.loads((work/'payload/release.json').read_text());release['identity']='older-release'
    (target/'release.json').write_text(json.dumps(release))
    if older: continuation+=f'; GSJ_PAYLOAD={shlex.quote(str(target))}; RELEASE_ID=older-release'
    operation='a'*24
    managed_ca(work)
    for code,profile,reason in ((73,'managed-local-ca',''),(74,'files',CA_REASON),
                                (74,'managed-local-ca','Missing Authority Key Identifier'),(74,'managed-local-ca',CA_REASON)):
        edit_site(work,lambda site:site['tls'].update(profile=profile))
        result=run([],probe_codes=[code],prelude=continuation,probe_reason=reason)
        assert result.returncode!=0 and json.loads(state.read_text())['calls']==[]
        assert 'keeps its exact saved configuration, so no command corrects its verification route' in result.stderr
        assert 'Set verification.connect_host' not in result.stderr and 'correct verification.connect_host' not in result.stderr
        assert f'otherwise keep operation {operation} retained and {fresh}. No verifier was started' in result.stderr
        if (profile,reason)==('managed-local-ca',CA_REASON):
            assert (f'With the managed local CA, run tls-repair --operation {operation}, which changes no saved configuration, '
                    f'then resume --operation {operation} {resume}; {WAIT}') in result.stderr
            assert 'repair' not in result.stderr.replace('tls-repair','')
            assert hint(result)==f'tls-repair --operation {operation}, then resume --operation {operation} {resume}; {WAIT}'
            continue
        assert 'repair' not in result.stderr
        if code==74:
            assert ('No installer command replaces this certificate: correct it in TLS Secret gsj-tls or the contents of '
                    f'verification.ca_file at their source, keeping the configured paths, then resume --operation {operation} '
                    f'{resume}; otherwise keep operation {operation} retained and {fresh}') in result.stderr
            assert hint(result)==f'resume --operation {operation} {resume} {SERVED}; otherwise keep operation {operation} retained and {fresh}'
        else:
            assert f'If the failure was transient, resume --operation {operation} {resume} once the route is reachable' in result.stderr
            assert hint(result)==(f'resume --operation {operation} {resume} once the route is reachable, if the failure was transient; '
                                  f'otherwise keep operation {operation} retained and {fresh}')
    assert json.loads((work/'verification-active.json').read_text())['release']==('older-release' if older else 'synthetic-release')
