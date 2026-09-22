"""Exact-field recovery of a stopped first-startup Helm apply.

These tests execute the actual Bash helpers against a stateful synthetic API,
including UID/RV and lost replies.
"""
import copy
import json
import os
from pathlib import Path
import shlex
import sys

import pytest

from tests.test_installer_startup_recovery import shell, encoded, digest, OP, signed_bundle, signing_key, IDENTITY


def put(path, value):
    path.write_bytes(encoded(value))


@pytest.fixture
def partial(shell):
    m = shell
    cluster = m['tmp'] / 'partial-api.json'
    source = []
    metadata = lambda name: {'name': name, 'namespace': 'source-ns', 'uid': name + '-uid', 'resourceVersion': '7',
                            'generation': 1, 'labels': {'app.kubernetes.io/instance': 'gsj'},
                            'annotations': {'meta.helm.sh/release-name': 'gsj', 'meta.helm.sh/release-namespace': 'source-ns'}}
    for role in ('web', 'forgejo', 'chroma'):
        pod = {'metadata': {'labels': {'role': role}}, 'spec': {'automountServiceAccountToken': False,
            'containers': [{'name': role, 'image': role + '@sha256:' + '1' * 64}],
            'initContainers': [], 'volumes': []}}
        if role == 'web':
            pod['spec']['initContainers'] = [
                {'name': 'wait-deps', 'image': 'web@sha256:' + '1' * 64,
                 'command': ['python', '/scripts/wait-deps.py'],
                 'env': [{'name': 'GSJ_DEPLOYMENT_GENERATION', 'value': 'source:1'}, {'name': 'WAIT_MARKER', 'value': 'gsj-provisioned'}]},
                {'name': 'corpus-initialize', 'image': 'web@sha256:' + '1' * 64, 'command': ['python', '-m', 'gsj_deploy.initialize']},
            ]
        source.append({'apiVersion': 'apps/v1', 'kind': 'Deployment', 'metadata': metadata('gsj-' + role),
                       'spec': {'replicas': 1, 'selector': {'matchLabels': {'role': role}}, 'template': pod}})
    source.append({'apiVersion': 'batch/v1', 'kind': 'Job', 'metadata': metadata('gsj-provision'),
                   'spec': {'template': {'metadata': {'labels': {}}, 'spec': {'containers': [{'name': 'provision', 'image': 'web@sha256:' + '1' * 64}]}}},
                   'status': {'succeeded': 1, 'conditions': [{'type': 'Complete', 'status': 'True'}]}})
    source.append({'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': metadata('gsj-scripts'), 'data': {'wait-deps.py': 'exact barrier', 'initializer.json': '{}'}})
    failed = copy.deepcopy(source)
    failed[0]['spec']['template']['spec']['containers'][0]['image'] = 'web@sha256:' + '2' * 64
    for c in failed[0]['spec']['template']['spec']['initContainers']:
        c['image'] = 'web@sha256:' + '2' * 64
    failed[0]['spec']['template']['spec']['initContainers'][0]['env'][0]['value'] = 'target:2'
    failed[-1]['data']['initializer.json'] = '{"repair_generation":1}'
    next_objects = copy.deepcopy(failed)
    next_objects[0]['spec']['template']['spec']['initContainers'][0]['env'][0]['value'] = 'target:3'
    live = copy.deepcopy(failed)
    live[0] = copy.deepcopy(source[0]); live[0]['spec']['replicas'] = 0; live[0]['metadata']['generation'] = 2
    live[0]['metadata']['managedFields'] = [{'manager': 'kubectl-patch', 'operation': 'Update', 'fieldsV1': {'f:spec': {'f:replicas': {}}}}]
    for obj in live[1:3]: obj['metadata']['generation'] = 3
    data = {'objects': live, 'calls': [], 'pods': [], 'marker': {'data': {'generation': 'source:1'}}, 'next': next_objects}
    put(cluster, data)
    put(m['state'] / 'operation.json', {'operation': OP, 'backup_round': 0})
    saved = m['state'] / ('startup-source-' + OP); saved.mkdir()
    put(saved / 'actual.json', source)
    put(saved / 'control.json', {'namespace_uid': 'namespace-uid', 'generation': 'source:1', 'resources': [{'kind': o['kind'], 'name': o['metadata']['name'], 'uid': o['metadata']['uid']} for o in source]})
    put(m['work'] / 'failed-resources.json', failed)
    put(m['work'] / 'next-resources.json', next_objects)
    put(m['state'] / ('quiescence-' + OP + '.json.closure.json'), {'controllers': [{'uid': 'gsj-' + role + '-uid', 'generation': 2, 'replicas': 0} for role in ('web', 'forgejo', 'chroma')]})
    directory = m['work'] / 'startup-continuation'; directory.mkdir()
    fake = m['tmp'] / 'partial-api.py'
    fake.write_text('''import copy,json,os,sys
from pathlib import Path
p=Path(os.environ['PARTIAL_API']);s=json.loads(p.read_text());a=sys.argv[1:];s['calls'].append(a);out=None;rc=0
try:
 if a[0]=='get':
  kind={'deployment':'Deployment','deploy':'Deployment','jobs':'Job','configmap':'ConfigMap','pods':'Pod'}.get(a[1],a[1])
  if a[1]=='pods':out={'items':s['pods']}
  elif a[1]=='jobs' or (a[1]=='deploy' and '-l' in a):out={'items':[o for o in s['objects'] if o['kind']==kind]}
  elif a[2] in ['gsj-installed','gsj-ready-state']:out=s.get('ready')
  elif a[2]=='gsj-provisioned':out=s['marker']
  else:out=next(o for o in s['objects'] if o['kind']==kind and o['metadata']['name']==a[2])
 elif a[0]=='apply':
  want=json.loads(Path(a[a.index('-f')+1]).read_text());old=next(o for o in s['objects'] if o['kind']=='Deployment' and o['metadata']['name']==want['metadata']['name'])
  assert '--server-side' in a and '--field-manager=helm' in a and not any('force' in v for v in a)
  assert 'replicas' not in want['spec'];assert want['metadata']['uid']==old['metadata']['uid'];assert want['metadata']['resourceVersion']==old['metadata']['resourceVersion']
  assert old['spec']['replicas']==0
  old['spec']['template']=want['spec']['template'];old['metadata']['generation']+=1;old['metadata']['resourceVersion']=str(int(old['metadata']['resourceVersion'])+1)
  s['staged_while_zero']=True
  if s.get('lost_apply'):rc=1
 elif a[0]=='patch':
  assert '--subresource=scale' in a and '--field-manager=gsj-startup-scale' in a
  ops=json.loads(Path(a[a.index('--patch-file')+1]).read_text());old=next(o for o in s['objects'] if o['kind']=='Deployment' and o['metadata']['name']==a[2])
  if s.get('scale_churn'):
   churn=s['scale_churn'];s['scale_attempts']=s.get('scale_attempts',0)+1
   if churn=='always-status' or s['scale_attempts']==1:
    old['metadata']['resourceVersion']=str(int(old['metadata']['resourceVersion'])+1)
    old['status']={'observedGeneration':old['metadata']['generation']}
    if churn=='uid':old['metadata']['uid']='replacement'
    elif churn=='generation':old['metadata']['generation']+=1
    elif churn=='spec':old['spec']['template']['spec']['containers'][0]['image']='foreign'
    elif churn=='label':old['metadata']['labels']['foreign']='changed'
    elif churn=='annotation':old['metadata']['annotations']['foreign']='changed'
    elif churn=='deleting':old['metadata']['deletionTimestamp']='2026-09-13T19:32:36Z'
    raise ValueError('resource version test refused')
  assert ops[:2]==[{'op':'test','path':'/metadata/uid','value':old['metadata']['uid']},{'op':'test','path':'/metadata/resourceVersion','value':old['metadata']['resourceVersion']}]
  if s.get('reject_scale'):raise ValueError('concurrent API change')
  value=ops[2]['value'];assert ops[2]['op']=='add' and ops[2]['path']=='/spec/replicas'
  # Faithful public Scale shape: zero is omitted by ScaleSpec's JSON encoder.
  scale_spec={'replicas':old['spec']['replicas']} if old['spec']['replicas'] else {}
  scale_spec['replicas']=value
  s['scale_before_omitted']=not old['spec']['replicas']
  if value==1:assert old['spec']['template']['spec']['containers'][0]['image'].endswith('2'*64)
  old['spec']['replicas']=value;old['metadata']['generation']+=1;old['metadata']['resourceVersion']=str(int(old['metadata']['resourceVersion'])+1)
  if s.get('lost_scale'):rc=1
 else:raise ValueError(a)
except (AssertionError,ValueError,StopIteration):rc=41
p.write_text(json.dumps(s))
if out is not None:print(json.dumps(out))
sys.exit(rc)
''')
    m['env']['PARTIAL_API'] = str(cluster)
    prefix = f'''k() {{ {shlex.quote(sys.executable)} {shlex.quote(str(fake))} "$@"; }}
assert_owner() {{ :; }}
RELEASE_ID=target
helm_application_projection "$GSJ_WORK/failed-resources.json" > "$GSJ_WORK/failed.json"
helm_application_projection "$GSJ_WORK/next-resources.json" > "$GSJ_WORK/next.json"
'''
    return {**m, 'cluster': cluster, 'source': source, 'failed': failed, 'prefix': prefix, 'directory': directory}


def test_guarded_scale_uses_only_scale_subresource_and_original_uid_resource_version(partial):
    m = partial; put(m['work'] / 'web.json', m['source'][0])
    result = m['run'](m['prefix'] + 'startup_scale_web "$GSJ_WORK/web.json" 0')
    assert result.returncode == 0, result.stderr
    api = json.loads(m['cluster'].read_text())
    calls = [c for c in api['calls'] if c[0] == 'patch']
    assert len(calls) == 1 and '--subresource=scale' in calls[0]
    patch = json.loads((m['work'] / 'startup-scale.json').read_text())
    assert patch == [{'op': 'test', 'path': '/metadata/uid', 'value': 'gsj-web-uid'},
                     {'op': 'test', 'path': '/metadata/resourceVersion', 'value': '7'},
                     {'op': 'add', 'path': '/spec/replicas', 'value': 0}]


@pytest.mark.parametrize('fault', ['uid', 'resourceVersion', 'name', 'deleting', 'replicas'])
def test_scale_identity_or_api_race_refuses_without_state_change(partial, fault):
    m = partial; web = copy.deepcopy(m['source'][0])
    replicas = '2' if fault == 'replicas' else '0'
    if fault in ('uid', 'resourceVersion'): web['metadata'][fault] = 'foreign'
    if fault == 'name': web['metadata']['name'] = 'unrelated'
    if fault == 'deleting': web['metadata']['deletionTimestamp'] = '2026-09-13T00:00:00Z'
    put(m['work'] / 'web.json', web)
    before = json.loads(m['cluster'].read_text())['objects']
    result = m['run'](m['prefix'] + f'startup_scale_web "$GSJ_WORK/web.json" {replicas}')
    assert result.returncode != 0
    assert json.loads(m['cluster'].read_text())['objects'] == before


@pytest.mark.parametrize('churn', ['status', 'always-status', 'uid', 'generation', 'spec', 'label', 'annotation', 'deleting'])
def test_scale_retries_only_status_rv_changes_with_at_most_three_requests(partial, churn):
    m = partial; api = json.loads(m['cluster'].read_text())
    api['scale_churn'] = churn
    put(m['cluster'], api)
    put(m['work'] / 'web.json', api['objects'][0])
    result = m['run'](m['prefix'] + 'startup_scale_web "$GSJ_WORK/web.json" 0')
    api = json.loads(m['cluster'].read_text())
    patches = [c for c in api['calls'] if c[0] == 'patch']
    if churn == 'status':
        assert result.returncode == 0, result.stderr
        assert len(patches) == 2
        assert json.loads((m['work'] / 'startup-scale.json').read_text())[1]['value'] == '8'
    elif churn == 'always-status':
        assert result.returncode != 0 and 'three guarded attempts' in result.stderr
        assert len(patches) == 3
    else:
        assert result.returncode != 0 and 'no status-only retry' in result.stderr
        assert len(patches) == 1
    assert api['objects'][0]['spec']['replicas'] == 0


def test_only_observed_stopped_partial_apply_is_admitted(partial):
    m = partial
    result = m['run'](m['prefix'] + 'startup_helm_live_partial "$GSJ_WORK/startup-continuation" "$GSJ_WORK/failed.json"')
    assert result.returncode == 0, result.stderr
    assert all(c[0] == 'get' for c in json.loads(m['cluster'].read_text())['calls'])


@pytest.mark.parametrize('fault', ['web-image', 'web-running', 'web-generation', 'web-owner', 'web-uid', 'web-env', 'script',
                                  'forge-image', 'forge-generation', 'job-uid', 'job-active', 'job-image', 'extra-controller', 'extra-job',
                                  'helm-owner', 'ready', 'corpus-started', 'application-started'])
def test_partial_drift_refuses_before_any_mutation(partial, fault):
    m = partial; api = json.loads(m['cluster'].read_text()); web = api['objects'][0]
    if fault == 'web-image': web['spec']['template']['spec']['containers'][0]['image'] = 'foreign'
    elif fault == 'web-running': web['spec']['replicas'] = 1
    elif fault == 'web-generation': web['metadata']['generation'] += 2
    elif fault == 'web-owner': web['metadata']['managedFields'][0]['manager'] = 'foreign-manager'
    elif fault == 'web-uid': web['metadata']['uid'] = 'replacement'
    elif fault == 'web-env': web['spec']['template']['spec']['containers'][0]['env'] = [{'name': 'FOREIGN', 'value': 'true'}]
    elif fault == 'script': api['objects'][-1]['data']['initializer.json'] = 'foreign'
    elif fault == 'forge-image': api['objects'][1]['spec']['template']['spec']['containers'][0]['image'] = 'foreign'
    elif fault == 'forge-generation': api['objects'][1]['metadata']['generation'] += 2
    elif fault == 'job-uid': api['objects'][3]['metadata']['uid'] = 'new-job'
    elif fault == 'job-active': api['objects'][3]['status']['active'] = 1
    elif fault == 'job-image': api['objects'][3]['spec']['template']['spec']['containers'][0]['image'] = 'foreign'
    elif fault == 'extra-controller':
        extra = copy.deepcopy(web); extra['metadata'].update(name='foreign-web', uid='foreign-web'); api['objects'].append(extra)
    elif fault == 'extra-job':
        extra = copy.deepcopy(api['objects'][3]); extra['metadata'].update(name='foreign-job', uid='foreign-job'); api['objects'].append(extra)
    elif fault == 'helm-owner': web['metadata']['annotations']['meta.helm.sh/release-name'] = 'foreign'
    elif fault == 'ready': api['ready'] = {'kind': 'ConfigMap'}
    elif fault == 'corpus-started': api['pods'] = [{'status': {'initContainerStatuses': [{'name': 'corpus-initialize', 'state': {'running': {}}}]}}]
    else: api['pods'] = [{'status': {'containerStatuses': [{'name': 'gsj-web', 'state': {'running': {}}}]}}]
    put(m['cluster'], api)
    result = m['run'](m['prefix'] + 'startup_helm_live_partial "$GSJ_WORK/startup-continuation" "$GSJ_WORK/failed.json"')
    assert result.returncode != 0, fault
    assert "unbound variable" not in result.stderr and "jq:" not in result.stderr, result.stderr
    assert all(c[0] == 'get' for c in json.loads(m['cluster'].read_text())['calls'])


def stage_setup(m):
    directory = m['state'] / ('startup-helm-' + OP); directory.mkdir()
    put(directory / 'intent.json', {'failed_attempt': 'b' * 24, 'failed_revision': 2})
    next_dir = m['state'] / 'helm-applications' / OP / ('c' * 24); next_dir.mkdir(parents=True)
    put(next_dir / 'values.json', {})
    put(m['work'] / 'values.pending.json', {})
    (m['payload'] / 'chart.tgz').write_bytes(b'synthetic target chart')
    put(m['state'] / 'operation.json', {'operation': OP, 'helm_application': 'c' * 24})
    return m['prefix'] + '''
cp "$GSJ_WORK/failed.json" "$STATE_DIR/startup-helm-$OPERATION/failed-projection.json"
cp "$GSJ_WORK/next.json" "$STATE_DIR/helm-applications/$OPERATION/cccccccccccccccccccccccc/expected.json"
jq -n --arg values "$(sha_file "$STATE_DIR/helm-applications/$OPERATION/cccccccccccccccccccccccc/values.json")" --arg expected "$(sha_file "$GSJ_WORK/next.json")" --arg chart "$(sha_file "$GSJ_PAYLOAD/chart.tgz")" '{format:"gsj.helm-application/1",operation:"aaaaaaaaaaaaaaaaaaaaaaaa",attempt:"cccccccccccccccccccccccc",target:"target",namespace:"source-ns",namespace_uid:"namespace-uid",release:"gsj",chart_sha256:$chart,revision:3,generation:"target:3",prior_job_uid:"gsj-provision-uid",values_sha256:$values,expected_sha256:$expected}' > "$STATE_DIR/helm-applications/$OPERATION/cccccccccccccccccccccccc/intent.json"
startup_helm_render() { cp "$GSJ_WORK/next-resources.json" "$4"; }
startup_helm_stage
'''


def test_stages_target_at_zero_before_scale_and_preserves_prior_evidence(partial):
    m = partial; original = (m['state'] / ('startup-source-' + OP) / 'actual.json').read_bytes()
    result = m['run'](stage_setup(m))
    assert result.returncode == 0, result.stderr
    api = json.loads(m['cluster'].read_text())
    assert api['staged_while_zero'] is True and api['objects'][0]['spec']['replicas'] == 1
    assert api['scale_before_omitted'] is True
    assert api['objects'][0]['spec']['template']['spec']['initContainers'][0]['env'][0]['value'] == 'target:3'
    assert [c[0] for c in api['calls'] if c[0] in ('apply', 'patch')] == ['apply', 'patch']
    assert (m['state'] / ('startup-source-' + OP) / 'actual.json').read_bytes() == original


@pytest.mark.parametrize('fault', ['no-gate', 'wrong-generation', 'wrong-marker', 'initializer-first', 'already-provisioned', 'wrong-next-revision'])
def test_stage_refuses_missing_revision_barrier_before_any_mutation(partial, fault):
    m = partial; body = stage_setup(m)
    next_objects = json.loads((m['work'] / 'next-resources.json').read_text()); gate = next_objects[0]['spec']['template']['spec']['initContainers'][0]
    if fault == 'no-gate': gate['command'] = ['python', 'different.py']
    elif fault == 'wrong-generation': gate['env'][0]['value'] = 'target:2'
    elif fault == 'wrong-marker': gate['env'][1]['value'] = 'foreign-marker'
    elif fault == 'initializer-first': next_objects[0]['spec']['template']['spec']['initContainers'].reverse()
    elif fault == 'already-provisioned':
        api = json.loads(m['cluster'].read_text()); api['marker']['data']['generation'] = 'target:3'; put(m['cluster'], api)
    else: body = body.replace('revision:3,generation:', 'revision:4,generation:')
    put(m['work'] / 'next-resources.json', next_objects)
    result = m['run'](body)
    assert result.returncode != 0
    assert not [c for c in json.loads(m['cluster'].read_text())['calls'] if c[0] in ('apply', 'patch')]


@pytest.mark.parametrize('loss', ['lost_apply', 'lost_scale'])
def test_lost_stage_response_reconciles_exact_target_without_starting_old_image(partial, loss):
    m = partial; body = stage_setup(m)
    api = json.loads(m['cluster'].read_text()); api[loss] = True; put(m['cluster'], api)
    first = m['run'](body); assert first.returncode != 0
    api = json.loads(m['cluster'].read_text()); api[loss] = False; put(m['cluster'], api)
    second = m['run'](body); assert second.returncode == 0, second.stderr
    api = json.loads(m['cluster'].read_text())
    assert api['objects'][0]['spec']['replicas'] == 1
    assert len([c for c in api['calls'] if c[0] == 'apply']) == 1
    assert len([c for c in api['calls'] if c[0] == 'patch']) == 1


def test_stored_failed_generation_is_not_normalized_away(shell):
    m = shell
    def release(generation):
        return {'manifest': json.dumps({'kind': 'Deployment', 'metadata': {'name': 'gsj-web'},
                'spec': {'template': {'spec': {'initContainers': [{'name': 'wait-deps', 'env': [{'name': 'GSJ_DEPLOYMENT_GENERATION', 'value': generation}]}]}}}}), 'hooks': []}
    put(m['work'] / 'signed.json', release('target:1'))
    put(m['work'] / 'stored.json', release('target:2'))
    put(m['work'] / 'wrong.json', release('target:999'))
    result = m['run']('''RELEASE_ID=target
k() { [[ $1 == create && "$*" == *--dry-run=client* ]] || exit 41; while [[ $1 != -f ]]; do shift; done; cat "$2"; }
startup_helm_stored_payload "$GSJ_WORK/signed.json" 2 "$GSJ_WORK/expected.json" true
startup_helm_stored_payload "$GSJ_WORK/stored.json" 2 "$GSJ_WORK/actual.json"
cmp "$GSJ_WORK/expected.json" "$GSJ_WORK/actual.json"
startup_helm_stored_payload "$GSJ_WORK/wrong.json" 2 "$GSJ_WORK/wrong-actual.json"
if cmp -s "$GSJ_WORK/expected.json" "$GSJ_WORK/wrong-actual.json"; then exit 42; fi
''')
    assert result.returncode == 0, result.stderr
    assert 'target:999' in (m['work'] / 'wrong-actual.json').read_text()


@pytest.mark.parametrize('fault', ['value', 'uid', 'type', 'missing', 'deleting'])
def test_preserved_credentials_cannot_be_replaced_or_rotated(partial, fault):
    m = partial; secret = {'kind': 'Secret', 'metadata': {'name': 'gsj-agent-token', 'uid': 'bot-uid'},
                           'type': 'Opaque', 'data': {'token': 'c3ludGhldGljLW9ubHk='}}
    put(m['directory'] / 'resources-private.json', {'kind': 'List', 'items': [secret]})
    api = json.loads(m['cluster'].read_text()); current = copy.deepcopy(secret)
    if fault == 'value': current['data']['token'] = 'cm90YXRlZA=='
    elif fault == 'uid': current['metadata']['uid'] = 'replacement'
    elif fault == 'type': current['type'] = 'another-type'
    elif fault == 'deleting': current['metadata']['deletionTimestamp'] = '2026-09-13T00:00:00Z'
    if fault != 'missing': api['objects'].append(current)
    put(m['cluster'], api)
    result = m['run'](m['prefix'] + 'startup_helm_credentials_match "$GSJ_WORK/startup-continuation"')
    assert result.returncode != 0
    assert all(c[0] == 'get' for c in json.loads(m['cluster'].read_text())['calls'])


@pytest.fixture
def wrapper(shell):
    m = shell; target = m['tmp'] / 'target-payload'; target.mkdir()
    put(m['payload'] / 'release.json', {'identity': 'program', 'supported_sources': ['target']})
    put(target / 'release.json', {'identity': 'target', 'version': '0.1.0'})
    put(target / 'site.schema.json', {})
    (target / 'validate.jq').write_text('.')
    (target / 'compile.jq').write_text('.')
    (target / 'chart.tgz').write_bytes(b'synthetic target chart')
    put(m['work'] / 'site.json', {})
    put(m['state'] / 'site.pending.json', {})
    source = m['state'] / ('startup-source-' + OP); source.mkdir(); put(source / 'source.json', {'source': 'completed'})
    put(source / 'control.json', {'namespace_uid': 'namespace-uid'})
    put(source / 'actual.json', [{'kind': 'Job', 'metadata': {'uid': 'gsj-provision-uid'}}])
    put(m['state'] / 'operation.json', {'operation': OP, 'kind': 'install', 'status': 'applying',
                                      'target': 'target', 'startup_source': {'release_identity': 'source'}, 'helm_application': 'b' * 24})
    intent = m['state'] / 'helm-applications' / OP / ('b' * 24); intent.mkdir(parents=True); put(intent / 'intent.json', {'revision': 2})
    (m['tmp'] / 'target-installer.sh').write_text('synthetic signed target fixture')
    put(m['tmp'] / 'backup.enc.json', {'source': 'original'})
    m['env']['TARGET_PAYLOAD'] = str(target)
    m['env']['TEST_BASE'] = str(m['tmp'])
    prefix = '''RELEASE_ID=program; SITE="$GSJ_WORK/site.json"; CONTINUE_HELM_INSTALLER="$TEST_BASE/target-installer.sh"
SOURCE_INSTALLER=''; BACKUP_ROUND=''; NEXT_STATUS=''; STOP_AFTER_PREPARE=false
current='{"metadata":{"uid":"lease-uid","resourceVersion":"8"},"spec":{"holderIdentity":"aaaaaaaaaaaaaaaaaaaaaaaa","renewTime":"2000-01-01T00:00:00Z"}}'
action() { printf '%s\n' "$*" >> "$STATE_DIR/actions"; }
authenticate_predecessor() { [[ ${FAULT:-} != signature ]] || fail 'signature invalid'; [[ $2 == target ]] || fail 'wrong target authentication'; PREDECESSOR_PAYLOAD="$TARGET_PAYLOAD"; action authenticated-target; }
startup_helm_source_evidence() { [[ ${FAULT:-} != source ]] || fail 'source proof invalid'; printf '{"source":true}' > "$GSJ_WORK/installed.json"; printf '[]' > "$1/credentials-current-private.json"; action source-proof; }
compatibility() { [[ $1 == selected && $RELEASE_ID == target ]] || fail 'wrong source selection'; action compatible; }
backup_archive() { printf '%s' "$TEST_BASE/backup.enc"; }
startup_helm_failed_target() { [[ ${FAULT:-} != history ]] || fail 'failed target history invalid'; printf '[]' > "$1/failed-projection.json"; printf '{}' > "$1/failed-secret-private.json"; action failed-target; }
startup_helm_credentials_match() { [[ ${FAULT:-} != credentials ]] || fail 'credentials changed'; printf '[]' > "$1/credentials-current-private.json"; action credential-recheck; }
startup_helm_live_partial() { [[ ${FAULT:-} != live ]] || fail 'live target invalid'; printf '[]' > "$1/live.json"; action live-proof; }
k() { if [[ $1 == replace ]]; then cat > "$STATE_DIR/replaced-lease.json"; action lease-renewed; elif [[ $1 == get && $2 == secret ]]; then [[ -z $NEXT_STATUS ]] || printf '{"metadata":{"labels":{"status":"%s"}}}' "$NEXT_STATUS"; else fail 'unexpected Kubernetes call'; fi; }
start_renewal() { action start-renewal; }; assert_owner() { :; }
helm_application_prepare() {
 action prepare; mkdir -p "$STATE_DIR/helm-applications/$OPERATION/cccccccccccccccccccccccc"
 cp "$GSJ_WORK/values.pending.json" "$STATE_DIR/helm-applications/$OPERATION/cccccccccccccccccccccccc/values.json"
 printf '[]' > "$STATE_DIR/helm-applications/$OPERATION/cccccccccccccccccccccccc/expected.json"
 jq -n --arg chart "$(sha_file "$GSJ_PAYLOAD/chart.tgz")" --arg values "$(sha_file "$GSJ_WORK/values.pending.json")" --arg expected "$(sha_file "$STATE_DIR/helm-applications/$OPERATION/cccccccccccccccccccccccc/expected.json")" '{format:"gsj.helm-application/1",operation:"aaaaaaaaaaaaaaaaaaaaaaaa",attempt:"cccccccccccccccccccccccc",target:"target",namespace:"source-ns",namespace_uid:"namespace-uid",release:"gsj",chart_sha256:$chart,revision:3,generation:"target:3",prior_job_uid:"gsj-provision-uid",values_sha256:$values,expected_sha256:$expected}' > "$STATE_DIR/helm-applications/$OPERATION/cccccccccccccccccccccccc/intent.json"
 jq '.helm_application="cccccccccccccccccccccccc"' "$STATE_DIR/operation.json" | atomic "$STATE_DIR/operation.json"
}
helm_apply() { [[ $STARTUP_HELM_CONTINUATION == true && $RELEASE_ID == target ]] || fail 'wrong execution identity'; action helm-exact-target; $STOP_AFTER_PREPARE && fail 'synthetic interruption'; return 0; }
helm_application_validate() { action validate-exact-target; }
wait_application() { action wait-target; }; record_ready() { action ready-target; }; verify_application() { action verify-target; }; record_installed() { action installed-target; }
'''
    return {**m, 'prefix': prefix}


def test_corrected_program_continues_exact_target_with_historical_backup_and_no_new_round(wrapper):
    m = wrapper; before_backup = (m['tmp'] / 'backup.enc.json').read_bytes()
    result = m['run'](m['prefix'] + 'startup_helm_continue "$current"')
    assert result.returncode == 0, result.stderr
    op = json.loads((m['state'] / 'operation.json').read_text())
    assert op['target'] == 'target' and op['helm_application'] == 'c' * 24 and 'repair_generation' not in op
    intent = json.loads((m['state'] / ('startup-helm-' + OP) / 'intent.json').read_text())
    assert intent['program'] == 'program' and intent['target'] == 'target' and intent['failed_revision'] == 2
    actions = (m['state'] / 'actions').read_text().splitlines()
    assert actions.index('failed-target') < actions.index('lease-renewed') < actions.index('prepare') < actions.index('helm-exact-target')
    assert actions[-4:] == ['wait-target', 'ready-target', 'verify-target', 'installed-target']
    assert (m['tmp'] / 'backup.enc.json').read_bytes() == before_backup
    assert not list(m['state'].glob('backup-round-*'))


@pytest.mark.parametrize('fault', ['signature', 'source', 'history', 'live', 'kind', 'phase', 'site', 'transition'])
def test_continuation_refusals_precede_lease_renewal(wrapper, fault):
    m = wrapper
    if fault in ('kind', 'phase'):
        op = json.loads((m['state'] / 'operation.json').read_text()); op['kind' if fault == 'kind' else 'status'] = 'backup' if fault == 'kind' else 'verifying'; put(m['state'] / 'operation.json', op)
    elif fault == 'site': put(m['work'] / 'site.json', {'changed': True})
    elif fault == 'transition': put(m['payload'] / 'release.json', {'identity': 'program', 'supported_sources': []})
    result = m['run'](m['prefix'] + f'FAULT={fault}\nstartup_helm_continue "$current"')
    assert result.returncode != 0
    assert 'unbound variable' not in result.stderr and 'jq:' not in result.stderr, result.stderr
    assert not (m['state'] / 'replaced-lease.json').exists()
    assert not (m['state'] / ('startup-helm-' + OP) / 'intent.json').exists()


def test_interrupted_prepared_successor_reuses_same_attempt_and_keeps_original_intent(wrapper):
    m = wrapper
    first = m['run'](m['prefix'] + 'STOP_AFTER_PREPARE=true\nstartup_helm_continue "$current"')
    assert first.returncode != 0 and 'synthetic interruption' in first.stderr
    evidence = m['state'] / ('startup-helm-' + OP) / 'intent.json'; original = evidence.read_bytes()
    import shutil
    shutil.rmtree(m['work'] / 'startup-continuation')  # a new installer gets a new private temporary workdir
    second = m['run'](m['prefix'] + 'startup_helm_continue "$current"')
    assert second.returncode == 0, second.stderr
    assert evidence.read_bytes() == original
    assert (m['state'] / 'actions').read_text().splitlines().count('prepare') == 1


def test_pending_successor_helm_is_not_reapplied_blindly(wrapper):
    m = wrapper
    first = m['run'](m['prefix'] + 'STOP_AFTER_PREPARE=true\nstartup_helm_continue "$current"')
    assert first.returncode != 0
    import shutil
    shutil.rmtree(m['work'] / 'startup-continuation')
    (m['state'] / 'replaced-lease.json').unlink()
    second = m['run'](m['prefix'] + 'NEXT_STATUS=pending-upgrade\nstartup_helm_continue "$current"')
    assert second.returncode != 0 and 'pending or failed' in second.stderr
    assert not (m['state'] / 'replaced-lease.json').exists()
    assert (m['state'] / 'actions').read_text().splitlines().count('prepare') == 1


@pytest.mark.parametrize('fault', [None, 'uid', 'helm-owner', 'spec', 'unrecorded'])
def test_auxiliary_resources_keep_original_uid_owner_and_exact_target_spec(partial, fault):
    m = partial
    resource = {'apiVersion': 'v1', 'kind': 'Service', 'metadata': {'name': 'gsj-web-service', 'namespace': 'source-ns'},
                'spec': {'type': 'ClusterIP', 'selector': {'role': 'web'}, 'ports': [{'port': 8780, 'targetPort': 8780}]}}
    actual = copy.deepcopy(resource)
    actual['metadata'].update(uid='service-uid', annotations={'meta.helm.sh/release-name': 'gsj', 'meta.helm.sh/release-namespace': 'source-ns'})
    put(m['directory'] / 'failed-payload-private.json', [{'kind': 'manifest', 'objects': [resource]}])
    put(m['directory'] / 'resources-private.json', {'items': [] if fault == 'unrecorded' else [copy.deepcopy(actual)]})
    if fault == 'uid': actual['metadata']['uid'] = 'replaced-service'
    elif fault == 'helm-owner': actual['metadata']['annotations']['meta.helm.sh/release-name'] = 'foreign'
    elif fault == 'spec': actual['spec']['selector']['role'] = 'foreign'
    api = json.loads(m['cluster'].read_text()); api['objects'].append(actual); put(m['cluster'], api)
    result = m['run'](m['prefix'] + 'startup_helm_auxiliary_matches "$GSJ_WORK/startup-continuation"')
    assert (result.returncode == 0) == (fault is None), result.stderr
    assert all(c[0] == 'get' for c in json.loads(m['cluster'].read_text())['calls'])


def test_credentials_changed_under_lease_stop_before_any_new_target_intent(wrapper):
    m = wrapper
    result = m['run'](m['prefix'] + 'FAULT=credentials\nstartup_helm_continue "$current"')
    assert result.returncode != 0 and 'credentials changed' in result.stderr
    assert (m['state'] / 'replaced-lease.json').exists()
    assert not (m['state'] / ('startup-helm-' + OP) / 'intent.json').exists()
    assert 'prepare' not in (m['state'] / 'actions').read_text().splitlines()


@pytest.mark.parametrize('arguments', ['install --continue-helm-installer /target',
                                    'repair --continue-helm-installer /target --source-installer /source',
                                    'repair --continue-helm-installer /target --backup-round 1',
                                    'repair --continue-from-program /previous',
                                    'install --continue-from-program /previous'])
def test_cli_refuses_incompatible_continuation_modes_before_bootstrap(shell, arguments):
    m = shell
    result = m['run']('bootstrap() { touch "$STATE_DIR/bootstrap-called"; }\nmain ' + arguments + ' --non-interactive')
    assert result.returncode != 0 and '--continue-' in result.stderr
    assert not (m['state'] / 'bootstrap-called').exists()


def test_cli_passes_exact_named_continuation_to_repair(shell):
    m = shell; (m['payload'] / 'helpers').mkdir()
    for name in ('startup-recovery.sh', 'verification-cleanup.sh'): (m['payload'] / 'helpers' / name).write_text('')
    result = m['run']('''bootstrap() { :; }; install_exit_traps() { :; }; configure_interaction() { :; }; load_site() { :; }
inspect_cluster() { printf '{}'; }; preflight() { :; }
repair_operation() { jq -n --arg target "$CONTINUE_HELM_INSTALLER" --arg previous "$CONTINUE_FROM_PROGRAM" --arg op "$RESUME_ID" '{target:$target,previous:$previous,operation:$op}' > "$STATE_DIR/selected.json"; }
main repair --operation aaaaaaaaaaaaaaaaaaaaaaaa --continue-helm-installer '/protected/signed target/gsj-install.sh' --continue-from-program '/protected/prior program/gsj-install.sh' --non-interactive
''')
    assert result.returncode == 0, result.stderr
    assert json.loads((m['state'] / 'selected.json').read_text()) == {'target': '/protected/signed target/gsj-install.sh', 'previous': '/protected/prior program/gsj-install.sh', 'operation': OP}


@pytest.mark.parametrize('tamper', [False, True])
def test_program_replacement_authenticates_prior_installer_without_executing_it(shell, signing_key, tamper):
    m = shell; prior = signed_bundle(m, signing_key)
    put(m['payload'] / 'release.json', {'identity': 'corrected', 'supported_sources': [IDENTITY]})
    directory = m['state'] / ('startup-helm-' + OP); directory.mkdir()
    put(directory / 'intent.json', {'program': IDENTITY})
    if tamper: (prior / 'gsj-install.sh').write_bytes((prior / 'gsj-install.sh').read_bytes() + b'changed')
    result = m['run'](f'''CONTINUE_FROM_PROGRAM={shlex.quote(str(prior / 'gsj-install.sh'))}
startup_helm_program_authorize "$STATE_DIR/startup-helm-$OPERATION" "$GSJ_WORK" corrected
''')
    assert (result.returncode == 0) is not tamper, result.stderr
    assert not (m['tmp'] / 'MUST-NOT-EXECUTE').exists()
    assert not (directory / 'program-transition.json').exists()


@pytest.fixture
def program_replacement(wrapper):
    import shutil
    m = wrapper
    first = m['run'](m['prefix'] + 'STOP_AFTER_PREPARE=true\nstartup_helm_continue "$current"')
    assert first.returncode != 0 and 'synthetic interruption' in first.stderr
    directory = m['state'] / ('startup-helm-' + OP)
    original_intent = (directory / 'intent.json').read_bytes()
    shutil.rmtree(m['work'] / 'startup-continuation'); (m['state'] / 'replaced-lease.json').unlink()
    prior = m['tmp'] / 'prior-program'; prior.mkdir()
    for file, value in [('gsj-install.sh', 'exact signed prior program'), ('installer-descriptor.json', '{}'), ('installer-descriptor.sig', 'synthetic signature')]:
        (prior / file).write_text(value)
    put(m['payload'] / 'release.json', {'identity': 'corrected', 'supported_sources': ['target', 'program']})
    control = m['state'] / ('startup-source-' + OP) / 'control.json'
    put(control, {'namespace_uid': 'namespace-uid', 'resources': [{'kind': 'Deployment', 'name': 'gsj-web', 'uid': 'gsj-web-uid'}]})
    put(m['state'] / ('quiescence-' + OP + '.json.closure.json'), {'controllers': [{'uid': 'gsj-web-uid', 'generation': 2}]})
    web = {'kind': 'Deployment', 'metadata': {'name': 'gsj-web', 'uid': 'gsj-web-uid', 'generation': 3},
           'spec': {'replicas': 0, 'selector': {'matchLabels': {'role': 'web'}}, 'template': {'metadata': {'labels': {'role': 'web'}}, 'spec': {
               'containers': [{'name': 'web', 'image': 'target-web'}],
               'initContainers': [{'name': 'wait-deps', 'command': ['python', '/scripts/wait-deps.py'],
                                   'env': [{'name': 'GSJ_DEPLOYMENT_GENERATION', 'value': 'target:3'}]}]}}}}
    put(m['work'] / 'program-live.json', [web])
    result = m['run']('''helm_application_projection "$GSJ_WORK/program-live.json" | jq 'map(.replicas=1)' > "$STATE_DIR/helm-applications/$OPERATION/cccccccccccccccccccccccc/expected.json"
jq --arg expected "$(sha_file "$STATE_DIR/helm-applications/$OPERATION/cccccccccccccccccccccccc/expected.json")" '.expected_sha256=$expected' "$STATE_DIR/helm-applications/$OPERATION/cccccccccccccccccccccccc/intent.json" | atomic "$STATE_DIR/helm-applications/$OPERATION/cccccccccccccccccccccccc/intent.json"
''')
    assert result.returncode == 0, result.stderr
    prefix = m['prefix'].replace('RELEASE_ID=program;', 'RELEASE_ID=corrected;') + '''
CONTINUE_FROM_PROGRAM="$TEST_BASE/prior-program/gsj-install.sh"
current=$(jq '.spec.acquireTime="2026-09-13T14:55:15.000000Z"' <<< "$current")
authenticate_predecessor() {
 [[ ${FAULT:-} != signature ]] || fail 'signature invalid'
 if [[ $2 == program ]]; then
   mkdir -p "$3"
   local file
   for file in gsj-install.sh installer-descriptor.json installer-descriptor.sig; do cp "$(dirname "$1")/$file" "$3/$file"; done
   PREDECESSOR_PAYLOAD="$TEST_BASE/prior-payload"; action authenticated-prior-program
 elif [[ $2 == target ]]; then PREDECESSOR_PAYLOAD="$TARGET_PAYLOAD"; action authenticated-target
 else fail 'wrong prior program identity'; fi
}
startup_helm_live_partial() {
 [[ ${FAULT:-} != live ]] || fail 'live target invalid'
 cp "$GSJ_WORK/program-live.json" "$1/live.json"
 helm_application_projection "$1/live.json" > "$1/live-projection.json"
 action live-proof
}
'''
    return {**m, 'prefix': prefix, 'directory': directory, 'original_intent': original_intent, 'prior': prior}


def test_new_program_appends_exact_transition_and_retries_without_replacing_evidence(program_replacement):
    import shutil
    m = program_replacement; backup = (m['tmp'] / 'backup.enc.json').read_bytes()
    result = m['run'](m['prefix'] + 'startup_helm_continue "$current"')
    assert result.returncode == 0, result.stderr
    receipt = m['directory'] / 'program-transition.json'; original = receipt.read_bytes(); data = json.loads(original)
    assert data['from_program'] == 'program' and data['to_program'] == 'corrected'
    assert data['binding']['target'] == 'target' and data['binding']['successor']['attempt'] == 'c' * 24
    assert data['binding']['continuation_sha256'] == digest(m['original_intent'])
    assert data['staged_web'] == {'uid': 'gsj-web-uid', 'generation': 3, 'replicas': 0}
    assert (m['directory'] / 'intent.json').read_bytes() == m['original_intent']
    shutil.rmtree(m['work'] / 'startup-continuation')
    result = m['run'](m['prefix'] + 'CONTINUE_FROM_PROGRAM=""\nstartup_helm_continue "$current"')
    assert result.returncode == 0, result.stderr
    assert receipt.read_bytes() == original and (m['directory'] / 'intent.json').read_bytes() == m['original_intent']
    assert (m['state'] / 'actions').read_text().splitlines().count('prepare') == 1
    assert (m['tmp'] / 'backup.enc.json').read_bytes() == backup


def test_interrupted_prior_program_publication_resumes_create_only(program_replacement):
    import shutil
    m = program_replacement
    first = m['run'](m['prefix'] + '''
startup_helm_program_publish() {
 mkdir -m 700 "$1/program-predecessor"
 startup_intent_file "$2/prior-program/gsj-install.sh" "$1/program-predecessor/gsj-install.sh"
 fail 'interrupted prior program publication'
}
startup_helm_continue "$current"
''')
    assert first.returncode != 0 and 'interrupted prior program publication' in first.stderr
    original = (m['directory'] / 'program-predecessor' / 'gsj-install.sh').read_bytes()
    assert not (m['directory'] / 'program-transition.json').exists()
    shutil.rmtree(m['work'] / 'startup-continuation')
    second = m['run'](m['prefix'] + 'startup_helm_continue "$current"')
    assert second.returncode == 0, second.stderr
    assert (m['directory'] / 'program-predecessor' / 'gsj-install.sh').read_bytes() == original
    assert (m['directory'] / 'intent.json').read_bytes() == m['original_intent']
    assert (m['directory'] / 'program-transition.json').is_file()


@pytest.mark.parametrize('fault', ['missing-selection', 'undeclared-program', 'wrong-signature', 'target-config', 'source-proof',
                                  'backup', 'successor-values', 'successor-intent', 'old-template', 'running', 'generation',
                                  'uid', 'lease-uid', 'lease-acquire-time', 'successor-pending', 'successor-deployed',
                                  'receipt-symlink', 'predecessor-symlink', 'predecessor-bytes'])
def test_program_replacement_refusals_precede_lease_renewal_and_preserve_original(program_replacement, fault):
    m = program_replacement; extra = ''
    if fault == 'missing-selection': extra = 'CONTINUE_FROM_PROGRAM=""\n'
    elif fault == 'undeclared-program': put(m['payload'] / 'release.json', {'identity': 'corrected', 'supported_sources': ['target']})
    elif fault == 'wrong-signature': extra = 'FAULT=signature\n'
    elif fault == 'target-config': put(m['work'] / 'site.json', {'changed': True})
    elif fault == 'source-proof': put(m['state'] / ('startup-source-' + OP) / 'source.json', {'changed': True})
    elif fault == 'backup': put(m['tmp'] / 'backup.enc.json', {'changed': True})
    elif fault == 'successor-values': put(m['state'] / 'helm-applications' / OP / ('c' * 24) / 'values.json', {'changed': True})
    elif fault == 'successor-intent':
        path = m['state'] / 'helm-applications' / OP / ('c' * 24) / 'intent.json'; data = json.loads(path.read_text()); data['attempt'] = 'd' * 24; put(path, data)
    elif fault in ('old-template', 'running', 'generation', 'uid'):
        path = m['work'] / 'program-live.json'; data = json.loads(path.read_text())
        if fault == 'old-template': data[0]['spec']['template']['spec']['containers'][0]['image'] = 'source-web'
        elif fault == 'running': data[0]['spec']['replicas'] = 1
        elif fault == 'generation': data[0]['metadata']['generation'] += 1
        else: data[0]['metadata']['uid'] = 'replacement'
        put(path, data)
    elif fault == 'lease-uid': extra = 'current=$(jq \'del(.metadata.uid)\' <<< "$current")\n'
    elif fault == 'lease-acquire-time': extra = 'current=$(jq \'del(.spec.acquireTime)\' <<< "$current")\n'
    elif fault.startswith('successor-'): extra = 'NEXT_STATUS=' + fault.split('-', 1)[1] + '\n'
    elif fault == 'predecessor-symlink': (m['directory'] / 'program-predecessor').symlink_to(m['prior'], target_is_directory=True)
    elif fault == 'predecessor-bytes':
        path = m['directory'] / 'program-predecessor'; path.mkdir(); (path / 'gsj-install.sh').write_bytes(b'foreign partial evidence')
    else: (m['directory'] / 'program-transition.json').symlink_to(m['tmp'] / 'foreign')
    result = m['run'](m['prefix'] + extra + 'startup_helm_continue "$current"')
    assert result.returncode != 0, fault
    assert 'unbound variable' not in result.stderr and 'jq:' not in result.stderr, result.stderr
    assert not (m['state'] / 'replaced-lease.json').exists()
    assert (m['directory'] / 'intent.json').read_bytes() == m['original_intent']
    assert not (m['directory'] / 'program-transition.json').is_file()


@pytest.mark.parametrize('fault', ['old-program', 'third-program', 'lease', 'prior-program-bytes', 'receipt', 'after-lease-live'])
def test_published_program_transition_cannot_be_reinterpreted(program_replacement, fault):
    import shutil
    m = program_replacement
    if fault == 'after-lease-live':
        body = m['prefix'] + '''
start_renewal() { action start-renewal; jq '.[0].spec.replicas=1' "$GSJ_WORK/program-live.json" | atomic "$GSJ_WORK/program-live.json"; }
startup_helm_continue "$current"
'''
        result = m['run'](body)
        assert result.returncode != 0 and (m['state'] / 'replaced-lease.json').exists()
        assert not (m['directory'] / 'program-transition.json').exists()
        return
    first = m['run'](m['prefix'] + 'startup_helm_continue "$current"')
    assert first.returncode == 0, first.stderr
    receipt = (m['directory'] / 'program-transition.json').read_bytes()
    shutil.rmtree(m['work'] / 'startup-continuation'); (m['state'] / 'replaced-lease.json').unlink()
    extra = ''
    if fault == 'old-program': extra = 'RELEASE_ID=program\n'
    elif fault == 'third-program': extra = 'RELEASE_ID=third\n'
    elif fault == 'lease': extra = 'current=$(jq \'.metadata.uid="replacement"\' <<< "$current")\n'
    elif fault == 'prior-program-bytes': (m['prior'] / 'gsj-install.sh').write_text('different signed bytes')
    else:
        data = json.loads(receipt); data['binding']['successor']['intent_sha256'] = 'f' * 64; put(m['directory'] / 'program-transition.json', data)
    result = m['run'](m['prefix'] + extra + 'startup_helm_continue "$current"')
    assert result.returncode != 0, fault
    assert not (m['state'] / 'replaced-lease.json').exists()
    assert (m['directory'] / 'intent.json').read_bytes() == m['original_intent']


@pytest.mark.parametrize('field', ['operation', 'attempt', 'target', 'namespace', 'namespace_uid', 'release',
                                  'chart_sha256', 'values_sha256', 'expected_sha256', 'generation', 'prior_job_uid'])
def test_successor_intent_drift_refuses_before_staging(partial, field):
    m = partial; body = stage_setup(m)
    injection = 'jq \'.' + field + '="foreign"\' "$STATE_DIR/helm-applications/$OPERATION/cccccccccccccccccccccccc/intent.json" | atomic "$STATE_DIR/helm-applications/$OPERATION/cccccccccccccccccccccccc/intent.json"\nstartup_helm_stage'
    body = body.replace('\nstartup_helm_stage\n', '\n' + injection + '\n')
    result = m['run'](body)
    assert result.returncode != 0 and 'successor Helm' in result.stderr
    assert not [c for c in json.loads(m['cluster'].read_text())['calls'] if c[0] in ('apply', 'patch')]


@pytest.mark.parametrize('path', ['directory', 'intent'])
def test_continuation_reserved_path_symlink_refuses_before_lease(wrapper, path):
    m = wrapper; directory = m['state'] / ('startup-helm-' + OP)
    foreign = m['tmp'] / 'foreign'; foreign.mkdir()
    if path == 'directory': directory.symlink_to(foreign, target_is_directory=True)
    else:
        directory.mkdir(); put(foreign / 'intent.json', {}); (directory / 'intent.json').symlink_to(foreign / 'intent.json')
    result = m['run'](m['prefix'] + 'startup_helm_continue "$current"')
    assert result.returncode != 0 and 'ordinary' in result.stderr
    assert not (m['state'] / 'replaced-lease.json').exists()


def test_completed_successor_cannot_skip_historical_receipt_binding(wrapper):
    m = wrapper
    first = m['run'](m['prefix'] + 'STOP_AFTER_PREPARE=true\nstartup_helm_continue "$current"')
    assert first.returncode != 0
    import shutil
    shutil.rmtree(m['work'] / 'startup-continuation')
    (m['state'] / 'replaced-lease.json').unlink()
    put(m['tmp'] / 'backup.enc.json', {'source': 'changed'})
    second = m['run'](m['prefix'] + 'NEXT_STATUS=deployed\nstartup_helm_continue "$current"')
    assert second.returncode != 0 and 'source evidence changed' in second.stderr
    assert not (m['state'] / 'replaced-lease.json').exists()
    assert 'installed-target' not in (m['state'] / 'actions').read_text().splitlines()
