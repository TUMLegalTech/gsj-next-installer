"""Authenticate predecessor bytes and prove source control without inventing readiness."""
import base64
from copy import deepcopy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shlex
import subprocess
import tarfile

import pytest

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / 'ops/installer/runtime.sh'
HELPER = ROOT / 'ops/installer/startup-recovery.sh'
OP = 'a' * 24
IDENTITY = 'signed-first-startup'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


@pytest.fixture
def shell(tmp_path):
    work = tmp_path / 'work'; work.mkdir()
    state = tmp_path / 'state'; state.mkdir()
    payload = tmp_path / 'payload'; payload.mkdir(); (payload / 'trust').mkdir()
    funcs = tmp_path / 'functions.sh'
    funcs.write_text(RUNTIME.read_text().split('# ENTRY POINT')[0].replace('@CLIENT_TABLE@', '# client table omitted'))
    env = {**os.environ, 'GSJ_WORK': str(work), 'STATE_DIR': str(state), 'GSJ_PAYLOAD': str(payload),
           'OPERATION': OP, 'RESUME_ID': OP, 'RELEASE': 'gsj', 'NAMESPACE': 'source-ns', 'CONTEXT': 'synthetic'}
    def run(body):
        script = f'source {shlex.quote(str(funcs))}\nsource {shlex.quote(str(HELPER))}\n' + body
        return subprocess.run(['bash', '-c', script], env=env, text=True, capture_output=True, timeout=35)
    return {'work': work, 'state': state, 'payload': payload, 'env': env, 'run': run, 'tmp': tmp_path}


@pytest.fixture(scope='module')
def signing_key(tmp_path_factory):
    p = tmp_path_factory.mktemp('startup-signing')
    subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:3072', '-out', str(p/'private.pem')], check=True, capture_output=True)
    subprocess.run(['openssl', 'pkey', '-in', str(p/'private.pem'), '-pubout', '-out', str(p/'public.pem')], check=True, capture_output=True)
    return p


def signed_bundle(shell, signing_key, *, unsafe=None):
    parent = shell['tmp'] / 'prior'; parent.mkdir()
    trust = (signing_key/'public.pem').read_bytes(); (shell['payload']/'trust/release.pem').write_bytes(trust)
    runtime = ('#!/usr/bin/env bash\ntouch '+shlex.quote(str(shell['tmp']/'MUST-NOT-EXECUTE'))+'\n__GSJ_PAYLOAD_BELOW__\n').encode()
    files = {'chart.tgz': b'signed chart bytes'}
    manifest = {'identity': IDENTITY, 'version': '0.1.0', 'runtimeSha256': digest(runtime), 'trustKeySha256': digest(trust),
                'payloadInventory': {name: {'sha256': digest(data), 'bytes': len(data)} for name, data in files.items()}}
    files['release.json'] = encoded(manifest)
    files['SHA256SUMS'] = ''.join(f'{digest(data)}  {name}\n' for name, data in files.items()).encode()
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode='w:gz') as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(name); info.size = len(data); tar.addfile(info, io.BytesIO(data))
        if unsafe:
            info = tarfile.TarInfo('../escape' if unsafe == 'path' else 'chart.tgz' if unsafe == 'duplicate' else 'link')
            if unsafe == 'symlink': info.type = tarfile.SYMTYPE; info.linkname = '../escape'
            tar.addfile(info, io.BytesIO(b''))
    installer = runtime + base64.encodebytes(archive.getvalue())
    (parent/'gsj-install.sh').write_bytes(installer)
    descriptor = {'schema': 'gsj.installer-descriptor/1', 'version': '0.1.0', 'releaseId': IDENTITY,
                  'manifestSha256': digest(files['release.json']), 'trustKeySha256': digest(trust),
                  'installer': {'name': 'gsj-install.sh', 'sha256': digest(installer), 'bytes': len(installer)}, 'signature': 'RSA-SHA256'}
    (parent/'installer-descriptor.json').write_bytes(encoded(descriptor))
    subprocess.run(['openssl', 'dgst', '-sha256', '-sign', str(signing_key/'private.pem'), '-out', str(parent/'installer-descriptor.sig'), str(parent/'installer-descriptor.json')], check=True, capture_output=True)
    return parent


def test_authentication_extracts_verified_bytes_without_executing_predecessor(shell, signing_key):
    parent = signed_bundle(shell, signing_key)
    result = shell['run'](f'authenticate_predecessor {shlex.quote(str(parent/"gsj-install.sh"))} {IDENTITY} "$GSJ_WORK/prior"')
    assert result.returncode == 0, result.stderr
    assert not (shell['tmp']/'MUST-NOT-EXECUTE').exists()
    assert (shell['work']/'prior/payload/chart.tgz').read_bytes() == b'signed chart bytes'


@pytest.mark.parametrize('fault', ['installer', 'signature', 'descriptor', 'identity', 'symlink', 'path', 'duplicate'])
def test_authentication_refuses_tampering_or_unsafe_signed_payload(shell, signing_key, fault):
    parent = signed_bundle(shell, signing_key, unsafe=fault if fault in {'symlink', 'path', 'duplicate'} else None)
    if fault in {'installer', 'signature', 'descriptor'}:
        target = parent / {'installer': 'gsj-install.sh', 'signature': 'installer-descriptor.sig', 'descriptor': 'installer-descriptor.json'}[fault]
        raw = target.read_bytes()
        target.write_bytes(bytes([raw[0]^1])+raw[1:] if fault == 'signature' else raw+b'x')
    identity = 'another-release' if fault == 'identity' else IDENTITY
    result = shell['run'](f'authenticate_predecessor {shlex.quote(str(parent/"gsj-install.sh"))} {identity} "$GSJ_WORK/prior"')
    assert result.returncode != 0
    assert not (shell['tmp']/'MUST-NOT-EXECUTE').exists() and not (shell['work']/'escape').exists()


@pytest.fixture
def control(shell):
    m = shell; path = m['tmp']/'cluster.json'; binpath=m['tmp']/'bin'; binpath.mkdir()
    m['env']['PATH']=str(binpath)+os.pathsep+m['env']['PATH']; m['env']['CLUSTER']=str(path)
    source=m['work']/'source'; source.mkdir(); (source/'chart.tgz').write_bytes(b'qualified signed source chart')
    (source/'release.json').write_bytes(encoded({'identity':IDENTITY}))
    directory=m['work']/'control'; directory.mkdir()
    values={'deployment': {'identity': IDENTITY}}; (m['work']/'values.json').write_bytes(encoded(values))
    (m['work']/'site.json').write_bytes(encoded({'target': {'release':'gsj','namespace':'source-ns'}}));(m['work']/'storage.json').write_text('[]')
    (m['state']/'operation.json').write_bytes(encoded({'operation':OP,'kind':'install','target':IDENTITY,'status':'initializing'}))
    labels={'app.kubernetes.io/instance':'gsj'}
    def metadata(name):
        return {'name':name,'namespace':'source-ns','uid':name+'-uid','generation':1,'annotations':{'meta.helm.sh/release-name':'gsj','meta.helm.sh/release-namespace':'source-ns'},'labels':labels}
    objects=[]
    for name, containers in [('web',['gsj-web','agent-runner','gsj-mcp']),('forgejo',['forgejo']),('chroma',['chroma'])]:
        objects.append({'apiVersion':'apps/v1','kind':'Deployment','metadata':metadata('gsj-'+name),'spec':{'replicas':1,'selector':{'matchLabels':labels},'template':{'metadata':{'labels':labels},'spec':{'containers':[{'name':c,'image':c+'@sha256:'+'1'*64,'env':[{'name':'GSJ_DEPLOYMENT_GENERATION','value':IDENTITY+':1'}]} for c in containers]}}}})
    objects.append({'apiVersion':'batch/v1','kind':'Job','metadata':metadata('gsj-provision'),'spec':{'template':{'metadata':{'labels':labels},'spec':{'containers':[{'name':'provision','image':'web@sha256:'+'1'*64}]}}},'status':{'succeeded':1,'conditions':[{'type':'Complete','status':'True'}]}})
    objects.append({'apiVersion':'v1','kind':'ConfigMap','metadata':metadata('gsj-scripts'),'data':{'initializer.json':'{}','provision.py':'signed immutable source code'}})
    stored={'name':'gsj','namespace':'source-ns','version':1,'info':{'status':'deployed'},'chart':{'metadata':{'name':'gsj'},'templates':[{'name':'gsj.yaml','data':'trusted'}]},'config':values}
    cluster={'objects':objects,'expected':deepcopy(objects),'stored':stored,'rendered':deepcopy(stored),'calls':[]}
    path.write_bytes(encoded(cluster))
    fake=m['tmp']/'fake.py'
    fake.write_text('''import base64,gzip,json,os,sys
from pathlib import Path
p=Path(os.environ['CLUSTER']);s=json.loads(p.read_text());a=sys.argv[1:];s['calls'].append(a);p.write_text(json.dumps(s))
if a[0]=='helm': result=s['rendered']
elif a[:2]==['get','secrets']:
 raw=base64.b64encode(base64.b64encode(gzip.compress(json.dumps(s['stored']).encode()))).decode()
 result={'items':[{'type':'helm.sh/release.v1','metadata':{'name':'sh.helm.release.v1.gsj.v1','uid':'history-uid','labels':{'owner':'helm','name':'gsj','version':'1','status':s['stored']['info']['status']}},'data':{'release':raw}}]}
elif a[:2]==['get','secret']: result=s.get('tls_secret')
elif a[:2]==['get','lease']: result=s.get('lease')
elif a[:2]==['get','namespace']: result={'metadata':{'uid':s.get('namespace_uid','namespace-uid')}}
elif a[:2]==['get','configmap'] and a[2] in ('gsj-installed','gsj-ready-state'): result=s.get('existing_record')
elif a[:2]==['get','configmap'] and a[2]=='gsj-provisioned': result={'data':{'status':'provisioned','generation':s.get('marker_generation','signed-first-startup:1'),'release_identity':'signed-first-startup'}}
elif a[0]=='get': result=next(x for x in s['objects'] if x['kind']==a[1] and x['metadata']['name']==a[2])
elif a[0]=='create' and '--dry-run=client' in a: result={'kind':'List','items':s['expected']}
else: raise RuntimeError(a)
if result is not None: print(json.dumps(result))
''')
    (binpath/'helm').write_text('#!/bin/sh\nexec '+shlex.quote(os.sys.executable)+' '+shlex.quote(str(fake))+' helm "$@"\n');(binpath/'helm').chmod(0o755)
    body=f'''k() {{ {shlex.quote(os.sys.executable)} {shlex.quote(str(fake))} "$@"; }}
h() {{ :; }}
capacity_source_identity() {{ printf '[]' > "$1-bindings.json"; }}
startup_source_control {shlex.quote(str(directory))} {shlex.quote(str(source))} "$GSJ_WORK/values.json" "$GSJ_WORK/site.json"
'''
    return {**m,'cluster':path,'control':directory,'body':body}


def test_legacy_source_control_proves_identity_without_ready_or_intent(control):
    m=control; result=m['run'](m['body']); assert result.returncode==0,result.stderr
    source=json.loads((m['work']/'installed.json').read_text())
    assert source['status']=='startup-unverified' and source['application_readiness_verified'] is False
    assert all(a[0] in ('get','helm') or '--dry-run=client' in a for a in json.loads(m['cluster'].read_text())['calls'])


@pytest.mark.parametrize('fault',['image','command','env','script','provision','pending_helm','stored_chart','stored_values','marker','ready_record'])
def test_legacy_control_refuses_source_drift_without_mutation(control,fault):
    m=control;s=json.loads(m['cluster'].read_text())
    if fault in ('image','command','env'):
        container=s['objects'][0]['spec']['template']['spec']['containers'][0]
        container[{'image':'image','command':'command','env':'env'}[fault]]={'image':'foreign@sha256:'+'2'*64,'command':['foreign'],'env':[{'name':'GSJ_DEPLOYMENT_GENERATION','value':'another:1'}]}[fault]
    elif fault=='script':s['objects'][-1]['data']['provision.py']='changed'
    elif fault=='provision':s['objects'][-2]['status']={'active':1}
    elif fault=='pending_helm':s['stored']['info']['status']='pending-install'
    elif fault=='stored_chart':s['stored']['chart']['templates'][0]['data']='changed'
    elif fault=='stored_values':s['stored']['config']['unexpected']=True
    elif fault=='marker':s['marker_generation']='another:1'
    else:s['existing_record']={'data':{'installed.json':'{}'}}
    m['cluster'].write_bytes(encoded(s));result=m['run'](m['body']);assert result.returncode!=0
    assert all(a[0] in ('get','helm') or '--dry-run=client' in a for a in json.loads(m['cluster'].read_text())['calls'])


@pytest.mark.parametrize("record,restoration,selected", [
    ({'kind': 'install', 'status': 'initializing'}, False, True),
    ({'status': 'initializing'}, False, True),  # operation records written by earlier installers carry no kind
    ({'status': 'initializing', 'backup': '/backups/a.tar.gz.enc'}, False, False),
    ({'status': 'initializing'}, True, False),
    ({'kind': 'install', 'status': 'initializing'}, True, True),  # a stale restore checkpoint never blocks a real install
    ({'kind': 'upgrade', 'status': 'initializing'}, False, False),
    ({'status': 'complete'}, False, False),
])
def test_first_install_recovery_admits_only_first_installs_including_legacy_records(shell, record, restoration, selected):
    m = shell
    (m['state']/'operation.json').write_bytes(encoded({'operation': OP, 'target': IDENTITY, **record}))
    if restoration:
        (m['state']/'restoration.json').write_bytes(encoded({'format': 'gsj.restore/1'}))
    result = m['run'](f'''SOURCE_INSTALLER=/synthetic/prior/gsj-install.sh; OPERATION={OP}
authenticate_predecessor() {{ fail 'reached predecessor authentication'; }}
startup_source_select
''')
    assert result.returncode != 0
    assert ('reached predecessor authentication' in result.stderr) is selected, result.stderr


def test_explicit_source_selection_does_not_replace_an_existing_ready_record(shell):
    m=shell;(m['state']/'operation.json').write_bytes(encoded({'operation':OP,'kind':'install','target':IDENTITY}))
    result=m['run']('''SOURCE_INSTALLER=/synthetic/prior/gsj-install.sh; BACKUP_ROUND=''
read_installed() { printf '{"status":"verification-pending"}' > "$GSJ_WORK/installed.json"; }
startup_source_select() { fail 'must not replace existing ready state'; }
read_repair_backup_source
''')
    assert result.returncode==0,result.stderr
    assert json.loads((m['work']/'installed.json').read_text())['status']=='verification-pending'


def test_explicit_source_is_selected_only_when_ready_records_are_absent(shell):
    m=shell;(m['state']/'operation.json').write_bytes(encoded({'operation':OP,'kind':'install','target':IDENTITY}))
    result=m['run']('''SOURCE_INSTALLER=/synthetic/prior/gsj-install.sh; BACKUP_ROUND=''
read_installed() { : > "$GSJ_WORK/installed.json"; }
startup_source_select() { printf '{"status":"startup-unverified","application_readiness_verified":false}' > "$GSJ_WORK/installed.json"; }
read_repair_backup_source
''')
    assert result.returncode==0,result.stderr
    assert json.loads((m['work']/'installed.json').read_text())=={'status':'startup-unverified','application_readiness_verified':False}


@pytest.mark.parametrize('preflight',['failed','passed_without_complete'])
def test_incomplete_source_preflight_prevents_any_controller_scale(shell,preflight):
    m=shell;saved=m['state']/('startup-source-'+OP);saved.mkdir()
    (saved/'control.json').write_text('{}');(saved/'quiescence-intent.json').write_bytes(encoded({'credential_fingerprint':'0'*64}))
    (m['work']/'installed.json').write_bytes(encoded({'manifest':{'core':{'commit':'c'*40}}}))
    (m['payload']/'helpers').mkdir();(m['payload']/'helpers/startup-runtime-preflight.py').write_text('# synthetic preflight\n')
    (m['state']/'operation.json').write_bytes(encoded({'operation':OP,'startup_source':{'control_sha256':digest(b'{}')}}))
    status='failed' if preflight=='failed' else 'passed'
    body='''assert_owner() { :; }
backup_credential_fingerprint() { printf '%064d\n' 0; }
startup_prepare_data_pod() { printf 'readonly-preflight-pod\n' >> "$STATE_DIR/actions"; }
addon_owned_run() { printf '%s' '{"status":"STATUS","startup_complete":false}' > "$1"; }
k() { printf '%s\n' "$*" >> "$STATE_DIR/mutations"; return 31; }
startup_source_complete
'''.replace('STATUS',status)
    result=m['run'](body)
    assert result.returncode!=0 and 'no source writer was stopped' in result.stderr
    assert not (m['state']/'mutations').exists() and not (saved/'source.json').exists()


def test_startup_reuses_original_replica_snapshot_without_claiming_ready(shell):
    m=shell;saved=m['state']/('startup-source-'+OP);saved.mkdir()
    source={'status':'startup-complete','application_readiness_verified':False,'manifest':{'identity':IDENTITY}}
    controllers={'items':[{'metadata':{'name':'gsj-'+name,'uid':name,'generation':1},'spec':{'replicas':1}} for name in ('web','forgejo','chroma')]}
    intent={'format':'gsj.quiescence/1','operation':OP,'round':0,'credential_fingerprint':'0'*64,'installed':{'status':'startup-unverified'},'controllers':controllers}
    (saved/'control.json').write_text('{}');(saved/'source.json').write_bytes(encoded(source));(saved/'quiescence-intent.json').write_bytes(encoded(intent))
    (m['state']/'operation.json').write_bytes(encoded({'operation':OP,'target':IDENTITY,'backup_round':0,'startup_source':{'control_sha256':digest(b'{}')}}))
    result=m['run']('''assert_owner() { :; }
backup_credential_fingerprint() { printf '%064d\n' 0; }
k() { fail 'completed private proof must not create readiness metadata'; }
startup_source_complete
''')
    assert result.returncode==0,result.stderr
    snapshot=json.loads((m['state']/('quiescence-'+OP+'.json')).read_text())
    assert snapshot['controllers']==controllers and snapshot['installed']==source
    assert not (m['state']/'ready.json').exists()


def modern_intents(m):
    result=m['run'](m['body']);assert result.returncode==0,result.stderr
    attempt='b'*24;directory=m['state']/'helm-applications'/OP/attempt;directory.mkdir(parents=True)
    values=(m['work']/'values.json').read_bytes();expected=(m['control']/'expected.json').read_bytes()
    (directory/'values.json').write_bytes(values);(directory/'expected.json').write_bytes(expected)
    intent={'format':'gsj.helm-application/1','operation':OP,'attempt':attempt,'namespace_uid':'namespace-uid','target':IDENTITY,
            'chart_sha256':digest((m['work']/'source/chart.tgz').read_bytes()),'revision':1,'prior_job_uid':'old-job',
            'values_sha256':digest(values),'expected_sha256':digest(expected)}
    (directory/'intent.json').write_bytes(encoded(intent))
    op=json.loads((m['state']/'operation.json').read_text());op['helm_application']=attempt;(m['state']/'operation.json').write_bytes(encoded(op))
    (m['work']/'runtime.sh').write_text('helm_application_prepare() {\n}\ncreate_operation_intent() {\n}\n')
    oi=m['state']/'operation-intents'/OP;oi.mkdir(parents=True)
    site=(m['work']/'site.json').read_bytes();release=(m['work']/'source/release.json').read_bytes()
    for name,data in [('site.json',site),('values.json',values),('release.json',release)]: (oi/name).write_bytes(data)
    operation_intent={'format':'gsj.operation-intent/1','record':{'operation':OP,'target':IDENTITY,'kind':'install'},'context':'synthetic','namespace':'source-ns','namespace_uid':'namespace-uid','release':'gsj','site_sha256':digest(site),'values_sha256':digest(values),'release_sha256':digest(release),'acquire_time':'2026-09-13T00:00:00.000000Z','prior_lease_uid':''}
    (oi/'intent.json').write_bytes(encoded(operation_intent))
    state=json.loads(m['cluster'].read_text());state['lease']={'metadata':{'uid':'lease-uid','annotations':{'gsj.io/operation-intent-sha256':digest(encoded(operation_intent))}},'spec':{'holderIdentity':OP,'acquireTime':operation_intent['acquire_time']}}
    m['cluster'].write_bytes(encoded(state))
    return directory,oi


def test_modern_source_requires_both_original_intents_and_lease_binding(control):
    m=control;modern_intents(m);result=m['run'](m['body']);assert result.returncode==0,result.stderr
    assert json.loads((m['work']/'installed.json').read_text())['status']=='startup-unverified'


@pytest.mark.parametrize('damage',['missing_helm','missing_operation','chart','expected','old_job','lease','site','namespace'])
def test_modern_intent_cannot_silently_fall_back_to_legacy(control,damage):
    m=control;hi,oi=modern_intents(m)
    if damage=='missing_helm':
        op=json.loads((m['state']/'operation.json').read_text());op.pop('helm_application');(m['state']/'operation.json').write_bytes(encoded(op))
    elif damage=='missing_operation':(oi/'intent.json').unlink()
    elif damage in {'chart','old_job'}:
        intent=json.loads((hi/'intent.json').read_text());intent['chart_sha256' if damage=='chart' else 'prior_job_uid']='f'*64 if damage=='chart' else 'gsj-provision-uid';(hi/'intent.json').write_bytes(encoded(intent))
    elif damage=='expected':(hi/'expected.json').write_text('[]')
    elif damage=='site':(oi/'site.json').write_text('{}')
    else:
        state=json.loads(m['cluster'].read_text())
        if damage=='lease':state['lease']['metadata']['annotations']['gsj.io/operation-intent-sha256']='0'*64
        else:state['namespace_uid']='replacement-namespace'
        m['cluster'].write_bytes(encoded(state))
    result=m['run'](m['body']);assert result.returncode!=0
    assert all(a[0] in ('get','helm') or '--dry-run=client' in a for a in json.loads(m['cluster'].read_text())['calls'])


def test_authenticated_installer_can_have_a_local_renamed_path(shell, signing_key):
    parent = signed_bundle(shell, signing_key)
    renamed = parent / 'retained-predecessor.sh'
    (parent / 'gsj-install.sh').rename(renamed)
    result = shell['run'](f'authenticate_predecessor {shlex.quote(str(renamed))} {IDENTITY} "$GSJ_WORK/prior"')
    assert result.returncode == 0, result.stderr


@pytest.fixture
def pods(shell):
    m = shell
    saved = m['state'] / ('startup-source-' + OP); saved.mkdir()
    (m['state'] / 'operation.json').write_bytes(encoded({'startup_source': {'control_sha256': 'b'*64}}))
    path = m['tmp'] / 'pods.json'
    path.write_bytes(encoded({'calls': [], 'object': None}))
    fake = m['tmp'] / 'pods.py'
    fake.write_text('''import json,sys
from pathlib import Path
p=Path(sys.argv[1]);s=json.loads(p.read_text());a=sys.argv[2:];s['calls'].append(a)
def save():p.write_text(json.dumps(s))
if a[:2]==['get','pod']:
 save()
 if s['object'] is not None: print(json.dumps(s['object']))
elif a[0]=='create':
 o=json.loads(Path(a[a.index('-f')+1]).read_text());o['metadata'].update(uid='owned-uid',resourceVersion='1');o['status']={'phase':'Running'}
 for c in o['spec']['containers']:
  for part in c.get('resources',{}).values():
   if part.get('cpu')=='1000m':part['cpu']='1'
   if part.get('memory')=='1024Mi':part['memory']='1Gi'
 # Faithful admission boundary: standard auto-mounted arrays are absent only
 # when our intent disables automatic ServiceAccount injection.
 if o['spec'].get('automountServiceAccountToken',True):
  o['spec'].setdefault('volumes',[]).append({'name':'kube-api-access-injected','projected':{'sources':[]}})
  for c in o['spec']['containers']:c.setdefault('volumeMounts',[]).append({'name':'kube-api-access-injected','mountPath':'/var/run/secrets/kubernetes.io/serviceaccount','readOnly':True})
 s['object']=o;save()
 if s.pop('lose_create',False):save();sys.exit(9)
 print(json.dumps(o))
elif a[0]=='delete':
 d=json.loads(Path(a[a.index('-f')+1]).read_text())
 assert d['preconditions']['uid']==s['object']['metadata']['uid']
 s['object']=None;save()
 if s.pop('lose_delete',False):save();sys.exit(9)
elif a[0]=='wait':save()
else:raise RuntimeError(a)
''')
    document = {'apiVersion':'v1','kind':'Pod','metadata':{'name':'gsj-proof'},'spec':{'restartPolicy':'Never','automountServiceAccountToken':False,'containers':[{'name':'proof','image':'signed@sha256:'+'1'*64,'command':['sleep','60']} ]}}
    (m['work'] / 'pod.json').write_bytes(encoded(document))
    prefix = 'assert_owner() { :; }\nk() { '+shlex.quote(os.sys.executable)+' '+shlex.quote(str(fake))+' '+shlex.quote(str(path))+' "$@"; }\n'
    return {**m,'saved':saved,'cluster':path,'prefix':prefix}


def test_lost_create_response_recovers_only_the_recorded_pod_template(pods):
    m=pods;s=json.loads(m['cluster'].read_text());s['lose_create']=True;m['cluster'].write_bytes(encoded(s))
    body=m['prefix']+'startup_owned_pod gsj-proof "$GSJ_WORK/pod.json"'
    first=m['run'](body);assert first.returncode!=0
    assert (m['saved']/'pods/gsj-proof.json').is_file() and not (m['saved']/'pods/gsj-proof.uid').exists()
    second=m['run'](body);assert second.returncode==0,second.stderr
    assert (m['saved']/'pods/gsj-proof.uid').read_text().strip()=='owned-uid'
    assert sum(a[0]=='create' for a in json.loads(m['cluster'].read_text())['calls'])==1


@pytest.mark.parametrize('damage',['foreign_name','foreign_template','changed_uid','terminating','terminal'])
def test_proof_pod_identity_or_lifecycle_change_prevents_exec(pods,damage):
    m=pods;body=m['prefix']+'startup_owned_pod gsj-proof "$GSJ_WORK/pod.json"'
    if damage!='foreign_name':
        result=m['run'](body);assert result.returncode==0,result.stderr
    s=json.loads(m['cluster'].read_text());s['calls']=[]
    if damage=='foreign_name':s['object']={'metadata':{'name':'gsj-proof','uid':'foreign'}}
    elif damage=='foreign_template':s['object']['spec']['containers'][0]['image']='foreign'
    elif damage=='changed_uid':s['object']['metadata']['uid']='replacement'
    elif damage=='terminating':s['object']['metadata']['deletionTimestamp']='2026-09-13T00:00:00Z'
    else:s['object']['status']['phase']='Failed'
    m['cluster'].write_bytes(encoded(s));result=m['run'](body);assert result.returncode!=0
    assert all(a[0]=='get' for a in json.loads(m['cluster'].read_text())['calls'])


def test_lost_delete_response_reconciles_exact_uid_absence(pods):
    m=pods;result=m['run'](m['prefix']+'startup_owned_pod gsj-proof "$GSJ_WORK/pod.json"');assert result.returncode==0,result.stderr
    s=json.loads(m['cluster'].read_text());s['lose_delete']=True;m['cluster'].write_bytes(encoded(s))
    body=m['prefix']+'startup_delete_pod gsj-proof'
    assert m['run'](body).returncode!=0
    result=m['run'](body);assert result.returncode==0,result.stderr
    assert (m['saved']/'pods/gsj-proof.deleted').read_text().strip()=='owned-uid'
    assert sum(a[0]=='delete' for a in json.loads(m['cluster'].read_text())['calls'])==1


def test_cleanup_refuses_a_replaced_same_name_pod(pods):
    m=pods;result=m['run'](m['prefix']+'startup_owned_pod gsj-proof "$GSJ_WORK/pod.json"');assert result.returncode==0,result.stderr
    s=json.loads(m['cluster'].read_text());s['object']['metadata']['uid']='replacement';s['calls']=[];m['cluster'].write_bytes(encoded(s))
    result=m['run'](m['prefix']+'startup_delete_pod gsj-proof');assert result.returncode!=0
    assert all(a[0]=='get' for a in json.loads(m['cluster'].read_text())['calls'])


def test_credentials_pod_has_deterministic_serviceaccount_projection(pods):
    m=pods
    job={'kind':'Job','spec':{'template':{'spec':{'serviceAccountName':'gsj-provision','containers':[{'name':'provision','image':'source-image','env':[{'name':'SECRET_A','value':'admin-token'}],'volumeMounts':[{'name':'scripts','mountPath':'/scripts','readOnly':True}]}],'volumes':[{'name':'scripts','configMap':{'name':'gsj-scripts'}}]}}}}
    (m['saved']/'actual.json').write_bytes(encoded([job]))
    # Stop after the actual generated Pod has passed the strict comparator.
    body=m['prefix']+'''addon_owned_run() { exit 37; }
startup_source_credentials "$STATE_DIR/startup-source-$OPERATION"
'''
    result=m['run'](body);assert result.returncode==37,result.stderr
    actual=json.loads(m['cluster'].read_text())['object'];spec=actual['spec']
    assert spec['serviceAccountName']=='gsj-provision' and spec['automountServiceAccountToken'] is False
    assert len(spec['volumes'])==2 and len(spec['containers'][0]['volumeMounts'])==2
    projection=spec['volumes'][-1]['projected'];assert projection['defaultMode']==420
    assert projection['sources'][0]=={'serviceAccountToken':{'path':'token','expirationSeconds':3600}}
    assert projection['sources'][1]['configMap']=={'name':'kube-root-ca.crt','items':[{'key':'ca.crt','path':'ca.crt'}]}
    assert projection['sources'][2]['downwardAPI']['items'][0]['fieldRef']=={'apiVersion':'v1','fieldPath':'metadata.namespace'}
    assert spec['containers'][0]['volumeMounts'][-1]=={'name':'gsj-startup-api','mountPath':'/var/run/secrets/kubernetes.io/serviceaccount','readOnly':True}


@pytest.mark.parametrize('damage',['same','different','symlink'])
def test_interrupted_local_evidence_never_replaces_existing_bytes(shell,damage):
    m=shell;source=m['work']/'input';target=m['state']/'receipt';source.write_text('new')
    old='new' if damage=='same' else 'retained-evidence'
    if damage=='symlink':
        external=m['tmp']/'external';external.write_text(old);target.symlink_to(external)
    else:target.write_text(old)
    result=m['run']('startup_intent_file "$GSJ_WORK/input" "$STATE_DIR/receipt"')
    assert (result.returncode==0)==(damage=='same') and target.read_text()==old


def test_progress_transport_keeps_one_receipt_and_only_safe_metadata(shell):
    m=shell;saved=m['state']/('startup-source-'+OP);saved.mkdir()
    emitter=m['tmp']/'emit.py'
    emitter.write_text('''import json,sys,time
print('SENSITIVE-TRANSPORT-ERROR',file=sys.stderr,flush=True)
print(json.dumps({'event':'source-shard-start','shard':'00001','rows':3,'vectors':4}),file=sys.stderr,flush=True)
print(json.dumps({'event':'source-shard-start','shard':'00001','rows':3,'vectors':4,'private':'SENSITIVE'}),file=sys.stderr,flush=True)
time.sleep(1.1)
print(json.dumps({'event':'source-shard-verified','shard':'00001','rows':3,'vectors':4}),file=sys.stderr,flush=True)
print(json.dumps({'format':'synthetic-final-receipt','status':'startup-complete'}))
''')
    body='assert_owner() { :; }\nstartup_proof_run "$GSJ_WORK/result.json" '+shlex.quote(os.sys.executable)+' '+shlex.quote(str(emitter))
    result=m['run'](body);assert result.returncode==0,result.stderr
    assert json.loads((m['work']/'result.json').read_text())=={'format':'synthetic-final-receipt','status':'startup-complete'}
    assert 'SENSITIVE' not in result.stdout+result.stderr
    progress=[json.loads(line) for line in (saved/'progress.jsonl').read_text().splitlines()]
    assert [x['event'] for x in progress]==['source-shard-start','source-shard-verified']
    assert result.stderr.count('source-shard-start')==1 and result.stderr.count('source-shard-verified')==1
    assert 'SENSITIVE-TRANSPORT-ERROR' in (m['work']/'result.json.progress-private').read_text()


def test_source_proof_lost_lease_stops_transport_descendants(shell):
    m=shell;(m['state']/('startup-source-'+OP)).mkdir()
    emitter=m['tmp']/'owned-worker.py'
    emitter.write_text('''import os,time
from pathlib import Path
state=Path(os.environ['STATE_DIR'])
if os.fork()==0:
 time.sleep(2.5);(state/'DESCENDANT-SURVIVED').write_text('bad');os._exit(0)
(state/'lose-owner').touch()
time.sleep(60)
''')
    body='''assert_owner() { [[ ! -f $STATE_DIR/lose-owner ]]; }
startup_proof_run "$GSJ_WORK/result.json" '''+shlex.quote(os.sys.executable)+' '+shlex.quote(str(emitter))
    result=m['run'](body)
    assert result.returncode!=0 and 'lost operation ownership' in result.stderr
    assert not (m['state']/'DESCENDANT-SURVIVED').exists()
    assert (m['work']/'result.json').read_text()==''


@pytest.fixture(scope='module')
def local_ca_material(tmp_path_factory):
    p=tmp_path_factory.mktemp('startup-local-ca')
    def run(*args):subprocess.run(['openssl',*args],check=True,capture_output=True)
    run('req','-x509','-newkey','rsa:2048','-sha256','-nodes','-days','2','-subj','/CN=GSJ sandbox local CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign','-keyout',str(p/'ca.key'),'-out',str(p/'ca.crt'))
    run('req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=source.example.test','-keyout',str(p/'tls.key'),'-out',str(p/'tls.csr'))
    (p/'extensions').write_text('subjectAltName=DNS:source.example.test\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature,keyEncipherment\nbasicConstraints=critical,CA:FALSE\n')
    run('x509','-req','-in',str(p/'tls.csr'),'-CA',str(p/'ca.crt'),'-CAkey',str(p/'ca.key'),'-CAcreateserial','-days','1','-sha256','-extfile',str(p/'extensions'),'-out',str(p/'tls.crt'))
    return p


@pytest.fixture
def derived_ca_source(control,local_ca_material):
    m=control;site={'target':{'release':'gsj','namespace':'source-ns'},'public_url':'https://source.example.test','tls':{'profile':'managed-local-ca','secret':'gsj-tls','ca_file':''},'verification':{'ca_file':''}}
    (m['work']/'site.json').write_bytes(encoded(site));hi,oi=modern_intents(m)
    tls=m['state']/'tls';tls.mkdir(mode=0o700)
    for name in ['ca.key','ca.crt','tls.key','tls.crt']:
        (tls/name).write_bytes((local_ca_material/name).read_bytes());(tls/name).chmod(0o600)
    site['tls']['ca_file']=site['verification']['ca_file']=str(tls/'ca.crt');(m['work']/'site.json').write_bytes(encoded(site))
    s=json.loads(m['cluster'].read_text());s['calls']=[];s['tls_secret']={'apiVersion':'v1','kind':'Secret','metadata':{'name':'gsj-tls','namespace':'source-ns','uid':'exact-tls-uid'},'type':'kubernetes.io/tls','data':{name:base64.b64encode((tls/name).read_bytes()).decode() for name in ['tls.key','tls.crt']}}
    m['cluster'].write_bytes(encoded(s))
    return {**m,'tls':tls,'original_intent':oi,'original_sha':digest((oi/'intent.json').read_bytes()),'original_site_sha':digest((oi/'site.json').read_bytes())}


def test_original_empty_local_ca_paths_reconcile_only_owned_matching_material(derived_ca_source):
    m=derived_ca_source;result=m['run'](m['body']);assert result.returncode==0,result.stderr
    proof=json.loads((m['control']/'control.json').read_text())['derived_local_ca']
    assert proof=={'format':'gsj.startup-derived-local-ca/1','namespace_uid':'namespace-uid','original_site_sha256':m['original_site_sha'],'ca_sha256':digest((m['tls']/'ca.crt').read_bytes()),'certificate_sha256':digest((m['tls']/'tls.crt').read_bytes()),'tls_secret':{'name':'gsj-tls','uid':'exact-tls-uid'},'chain_verified':True,'private_key_match':True}
    assert digest((m['original_intent']/'intent.json').read_bytes())==m['original_sha']
    assert digest((m['original_intent']/'site.json').read_bytes())==m['original_site_sha']
    assert all(a[0] in ('get','helm') or '--dry-run=client' in a for a in json.loads(m['cluster'].read_text())['calls'])


@pytest.mark.parametrize('damage',['wrongfile','unowned_directory','mismatch_secret','nonempty_original','mode_changed','other_field','key_permissions','directory_permissions','certificate_permissions','ca_key_mismatch','leaf_hostname','secret_namespace','secret_uid'])
def test_derived_ca_does_not_hide_unowned_material_or_other_source_drift(derived_ca_source,damage):
    m=derived_ca_source;site=json.loads((m['work']/'site.json').read_text());s=json.loads(m['cluster'].read_text())
    if damage=='wrongfile':site['tls']['ca_file']=site['verification']['ca_file']=str(m['tmp']/'foreign-ca.crt')
    elif damage=='unowned_directory':
        original=m['tls'];renamed=m['state']/'foreign';original.rename(renamed);original.symlink_to(renamed,target_is_directory=True)
    elif damage=='mismatch_secret':s['tls_secret']['data']['tls.crt']=base64.b64encode(b'foreign certificate').decode()
    elif damage=='nonempty_original':
        oi=m['original_intent'];old=json.loads((oi/'site.json').read_text());old['tls']['ca_file']=old['verification']['ca_file']='prior-explicit-ca.crt';(oi/'site.json').write_bytes(encoded(old))
        intent=json.loads((oi/'intent.json').read_text());intent['site_sha256']=digest((oi/'site.json').read_bytes());(oi/'intent.json').write_bytes(encoded(intent));s['lease']['metadata']['annotations']['gsj.io/operation-intent-sha256']=digest((oi/'intent.json').read_bytes())
    elif damage=='mode_changed':site['tls']['profile']='files'
    elif damage=='other_field':site['public_url']='https://foreign.example.test'
    elif damage=='key_permissions':(m['tls']/'ca.key').chmod(0o644)
    elif damage=='directory_permissions':m['tls'].chmod(0o755)
    elif damage=='certificate_permissions':(m['tls']/'ca.crt').chmod(0o666)
    elif damage=='ca_key_mismatch':(m['tls']/'ca.key').write_bytes((m['tls']/'tls.key').read_bytes())
    elif damage=='leaf_hostname':
        # Keep original and derived sites mutually consistent so the actual
        # certificate hostname predicate, rather than site equality, refuses.
        site['public_url']='https://other.example.test';oi=m['original_intent'];old=json.loads((oi/'site.json').read_text());old['public_url']=site['public_url'];(oi/'site.json').write_bytes(encoded(old));intent=json.loads((oi/'intent.json').read_text());intent['site_sha256']=digest((oi/'site.json').read_bytes());(oi/'intent.json').write_bytes(encoded(intent));s['lease']['metadata']['annotations']['gsj.io/operation-intent-sha256']=digest((oi/'intent.json').read_bytes())
    elif damage=='secret_namespace':s['tls_secret']['metadata']['namespace']='foreign'
    else:s['tls_secret']['metadata']['uid']=''
    (m['work']/'site.json').write_bytes(encoded(site));m['cluster'].write_bytes(encoded(s))
    result=m['run'](m['body']);assert result.returncode!=0
    calls=json.loads(m['cluster'].read_text())['calls'];assert all(a[0] in ('get','helm') or '--dry-run=client' in a for a in calls)
    assert not any(a[0] in ('patch','scale','replace','exec','delete') for a in calls)
    assert 'BEGIN PRIVATE KEY' not in result.stdout+result.stderr


def test_proof_pod_retry_preserves_raw_quantity_intent_and_same_uid(pods):
    m=pods;document=json.loads((m['work']/'pod.json').read_text())
    document['spec']['containers'][0]['resources']={'limits':{'cpu':'1000m','memory':'1024Mi'},'requests':{'cpu':'100m','memory':'512Mi'}}
    (m['work']/'pod.json').write_bytes(encoded(document))
    body=m['prefix']+'startup_owned_pod gsj-proof "$GSJ_WORK/pod.json"'
    first=m['run'](body);assert first.returncode==0,first.stderr
    intent=m['saved']/'pods/gsj-proof.json';before=intent.read_bytes()
    second=m['run'](body);assert second.returncode==0,second.stderr
    assert intent.read_bytes()==before
    assert json.loads(before)['spec']['containers'][0]['resources']['limits']=={'cpu':'1000m','memory':'1024Mi'}
    state=json.loads(m['cluster'].read_text())
    assert state['object']['spec']['containers'][0]['resources']['limits']=={'cpu':'1','memory':'1Gi'}
    assert (m['saved']/'pods/gsj-proof.uid').read_text().strip()==state['object']['metadata']['uid']=='owned-uid'
    assert sum(a[0]=='create' for a in state['calls'])==1


# --- The misattribution pass: a fingerprint that could not be read is not "credentials changed" ----

def test_a_fingerprint_over_a_partial_snapshot_is_a_failure_not_a_digest(shell):
    """backup_credential_fingerprint runs inside $(...), where bash does not
    inherit set -e: a kubectl that failed part-way left a partial snapshot,
    the function still printed a digest of it, and the caller read
    "credentials changed". A snapshot that could not be taken must be a
    failure, never a digest."""
    body = '''backup_resources() { printf '{"items":[]}' > "$GSJ_WORK/cluster-private.json"; return 1; }
if out=$(backup_credential_fingerprint); then echo "DIGEST:$out"; else echo "FAILED:${out:-empty}"; fi
'''
    result = shell['run'](body)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'FAILED:empty', result.stdout


def test_every_fingerprint_read_in_the_recovery_helper_captures_its_failure():
    """The three comparisons in startup-recovery.sh must read the fingerprint
    into a variable and stop with the fingerprint's own words when the read
    fails; a bare `[[ $(backup_credential_fingerprint) == … ]]` compares an
    empty string and blames the credentials."""
    import re
    text = HELPER.read_text()
    uses = [line for line in text.splitlines() if 'backup_credential_fingerprint' in line]
    assert len(uses) >= 3
    for line in uses:
        assert re.search(r'=\$\(backup_credential_fingerprint\) \|\| fail ', line), line
        assert '[[ $(backup_credential_fingerprint)' not in line, line


def test_a_proof_that_ends_with_the_lock_code_names_the_lock_not_a_failed_inventory(shell):
    body = '''assert_owner() { :; }; startup_proof_progress() { :; }
mkdir -p "$STATE_DIR/startup-source-$OPERATION"
startup_proof_run "$GSJ_WORK/result.json" bash -c 'echo receipt-words >&2; exit 78'
'''
    result = shell['run'](body)
    assert result.returncode == 1
    assert 'inventory proof failed' not in result.stderr
    assert 'holds the lock' in result.stderr and '78' in result.stderr
    body2 = '''assert_owner() { :; }; startup_proof_progress() { :; }
mkdir -p "$STATE_DIR/startup-source-$OPERATION"
startup_proof_run "$GSJ_WORK/result.json" bash -c 'echo receipt-words >&2; exit 3'
'''
    result = shell['run'](body2)
    assert result.returncode == 1
    assert 'did not complete (exit 3)' in result.stderr and 'receipt-words' not in result.stderr
    receipt = shell['state'] / f'startup-source-{OP}' / 'proof-private.log'
    assert receipt.is_file() and 'receipt-words' in receipt.read_text()
