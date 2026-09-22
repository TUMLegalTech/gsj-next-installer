"""A ready previous release must never complete an interrupted target install.

Real Helm renders the shipped chart; a synthetic Kubernetes API supplies API
defaults, history/Job identities and deliberate drift. No cluster is accessed.
"""
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from tests.test_installer import INSTALLER, _release, _site
from tests import pinned_web

pytestmark = pinned_web.needs_web


@pytest.fixture(scope='module')
def chart(tmp_path_factory):
    # The shipped chart is the PINNED product's (web-pin.json), never a working tree.
    target = tmp_path_factory.mktemp('helm-application-chart')
    subprocess.run(['helm', 'package', str(pinned_web.chart()), '--destination', str(target)], check=True, capture_output=True)
    return next(target.glob('*.tgz'))


@pytest.fixture
def application(tmp_path, chart):
    payload = tmp_path / 'payload'; payload.mkdir()
    work = tmp_path / 'work'; work.mkdir()
    state = tmp_path / 'state'; state.mkdir()
    shutil.copyfile(chart, payload / 'chart.tgz')
    (payload / 'release.json').write_text(json.dumps(_release()))
    site = _site(); site['target'].update(namespace='synthetic-namespace', release='synthetic-release')
    (tmp_path / 'site.json').write_text(json.dumps(site))
    shutil.copyfile(tmp_path / 'site.json', state / 'site.pending.json')
    result = subprocess.run(['jq', '--slurpfile', 'release', str(payload / 'release.json'), '-f', str(INSTALLER / 'compile.jq'), str(tmp_path / 'site.json')], check=True, capture_output=True)
    (work / 'values.pending.json').write_bytes(result.stdout)
    (state / 'operation.json').write_text(json.dumps({'operation': 'a' * 24, 'kind': 'install', 'target': 'synthetic-release', 'status': 'owned'}))
    api = tmp_path / 'api.json'
    old_history = {'kind': 'Secret', 'type': 'helm.sh/release.v1', 'metadata': {'name': 'sh.helm.release.v1.synthetic-release.v3', 'uid': 'history-3', 'labels': {'owner': 'helm', 'name': 'synthetic-release', 'version': '3', 'status': 'deployed'}}}
    api.write_text(json.dumps({'calls': [], 'history': [old_history], 'objects': {'Job/synthetic-release-provision': {'kind': 'Job', 'metadata': {'name': 'synthetic-release-provision', 'uid': 'old-provision'}}}}))
    fake = tmp_path / 'fake.py'
    fake.write_text('''import json,os,pathlib,sys,yaml
p=pathlib.Path(os.environ['API']); s=json.loads(p.read_text()); a=sys.argv[1:]; s['calls'].append(a); code=0; result=None
if a[:1]==['create'] and '--dry-run=client' in a:
 result={'kind':'List','items':list(yaml.safe_load_all(pathlib.Path(a[a.index('-f')+1]).read_text()))}
elif a[:2]==['get','namespace']: result={'metadata':{'uid':s.get('namespace_uid','namespace-uid')}}
elif a[:2]==['get','secrets']: result={'items':s['history']}
elif a[:1]==['get']:
 kind={'job':'Job','secret':'Secret','deploy':'Deployment','lease':'Lease'}.get(a[1],a[1]); key=kind+'/'+a[2]
 result=s['objects'].get(key)
 if result is None and '--ignore-not-found' not in a: code=1
elif a[:1]==['replace']:
 result=json.load(sys.stdin); key=result['kind']+'/'+result['metadata']['name']; old=s['objects'][key]
 if result['metadata']['resourceVersion']!=old['metadata']['resourceVersion']: code=1
 else: result['metadata']['resourceVersion']=str(int(old['metadata']['resourceVersion'])+1); s['objects'][key]=result
else: code=23
p.write_text(json.dumps(s))
if result is not None: print(json.dumps(result))
sys.exit(code)
''')
    functions = tmp_path / 'functions.sh'
    functions.write_text((INSTALLER / 'runtime.sh').read_text().split('# ENTRY POINT', 1)[0].replace('@CLIENT_TABLE@', ''))
    prefix = '''source "$FUNCTIONS"
GSJ_PAYLOAD="$BASE/payload"; GSJ_WORK="$BASE/work"; STATE_DIR="$BASE/state"; SITE="$BASE/site.json"
CONTEXT=synthetic-context; NAMESPACE=synthetic-namespace; RELEASE=synthetic-release; RELEASE_ID=synthetic-release
OPERATION=aaaaaaaaaaaaaaaaaaaaaaaa; COMMAND=install; RENEWER=''
k() { "$PYTHON" -B "$FAKE" "$@"; }
h() { if [[ $1 == get && $2 == values ]]; then cat "${STORED_VALUES:-$GSJ_WORK/values.pending.json}"; else "$HELM" --namespace "$NAMESPACE" "$@"; fi; }
assert_owner() { :; }; start_renewal() { :; }
'''
    env = {**os.environ, 'BASE': str(tmp_path), 'FUNCTIONS': str(functions), 'PYTHON': sys.executable,
           'FAKE': str(fake), 'API': str(api), 'HELM': shutil.which('helm')}
    def run(body):
        return subprocess.run(['bash', '-c', prefix + body], env=env, capture_output=True, text=True, timeout=20)
    def target():
        s = json.loads(api.read_text())
        rendered = json.loads((work / 'helm-target-generation.json').read_text())['items']
        for item in rendered:
            if item['kind'] not in ('Job', 'Deployment', 'ConfigMap'): continue
            item = copy.deepcopy(item); item['metadata'].update(uid='target-' + item['metadata']['name'], generation=2)
            item['metadata'].setdefault('annotations', {}).update({'meta.helm.sh/release-name': 'synthetic-release', 'meta.helm.sh/release-namespace': 'synthetic-namespace'})
            if item['kind'] in ('Deployment', 'Job'):
                for c in item['spec']['template']['spec'].get('containers', []) + item['spec']['template']['spec'].get('initContainers', []):
                    for e in c.get('env', []):
                        if e.get('value') == '': e.pop('value')
                    c.setdefault('resources', {})['requests'] = {'cpu': '1000m'}
            item['status'] = {'succeeded': 1, 'conditions': [{'type': 'Complete', 'status': 'True'}]} if item['kind'] == 'Job' else {'observedGeneration': 2, 'updatedReplicas': 1, 'availableReplicas': 1, 'readyReplicas': 1}
            s['objects'][item['kind'] + '/' + item['metadata']['name']] = item
        h = copy.deepcopy(s['history'][0]); h['metadata'].update(name='sh.helm.release.v1.synthetic-release.v4', uid='history-4'); h['metadata']['labels']['version'] = '4'
        s['objects']['Secret/' + h['metadata']['name']] = h
        s['history'].append(h)
        s['objects']['Lease/synthetic-release-operation'] = {'apiVersion': 'coordination.k8s.io/v1', 'kind': 'Lease', 'metadata': {'name': 'synthetic-release-operation', 'resourceVersion': '1'}, 'spec': {'holderIdentity': 'a' * 24, 'renewTime': '2000-01-01T00:00:00.000000Z'}}
        api.write_text(json.dumps(s)); return s
    return run, target, api, work, state, payload


def test_real_chart_prepare_binds_old_job_and_actual_next_revision_before_launch(application):
    run, target, api, work, state, _ = application
    result = run('helm_application_prepare')
    assert result.returncode == 0, result.stderr
    operation = json.loads((state / 'operation.json').read_text())
    intent = json.loads((state / 'helm-applications' / ('a' * 24) / operation['helm_application'] / 'intent.json').read_text())
    assert intent['prior_job_uid'] == 'old-provision'
    assert intent['revision'] == 4 and intent['template_revision'] == 1
    assert intent['generation'] == 'synthetic-release:4'
    assert operation['status'] == 'applying'
    assert 'synthetic-release:1' in (work / 'helm-target.yaml').read_text()
    assert all(c[0] == 'get' or '--dry-run=client' in c for c in json.loads(api.read_text())['calls'])
    target()
    result = run('helm_application_validate; wait_application')
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize('fault', ['old-job', 'job-incomplete', 'job-generation', 'deployment-generation', 'image', 'init-image',
                                  'scripts', 'namespace', 'pending-helm', 'ownership', 'values', 'expected', 'missing-intent',
                                  'later-history', 'stored-values', 'service-links-enabled', 'service-links-omitted',
                                  'service-links-null'])
def test_ready_source_and_runtime_drift_cannot_advance_applying_resume(application, fault):
    run, target, api, work, state, payload = application
    assert run('helm_application_prepare').returncode == 0
    s = target(); job = s['objects']['Job/synthetic-release-provision']; web = s['objects']['Deployment/synthetic-release-web']
    if fault == 'old-job': job['metadata']['uid'] = 'old-provision'
    if fault == 'job-incomplete': job['status'] = {'active': 1}
    if fault == 'job-generation':
        next(e for e in job['spec']['template']['spec']['containers'][0]['env'] if e['name'] == 'GSJ_DEPLOYMENT_GENERATION')['value'] = 'synthetic-release:3'
    if fault == 'deployment-generation':
        next(e for e in web['spec']['template']['spec']['initContainers'][0]['env'] if e['name'] == 'GSJ_DEPLOYMENT_GENERATION')['value'] = 'synthetic-release:3'
    if fault == 'image': web['spec']['template']['spec']['containers'][0]['image'] = 'registry.invalid/old@sha256:' + 'f' * 64
    if fault == 'init-image': web['spec']['template']['spec']['initContainers'][1]['image'] = 'registry.invalid/old-corpus@sha256:' + 'f' * 64
    if fault.startswith('service-links-'):
        assert web['spec']['template']['spec']['enableServiceLinks'] is False
        if fault == 'service-links-omitted': web['spec']['template']['spec'].pop('enableServiceLinks')
        else: web['spec']['template']['spec']['enableServiceLinks'] = True if fault == 'service-links-enabled' else None
    if fault == 'scripts': s['objects']['ConfigMap/synthetic-release-scripts']['data']['initializer.json'] = '{}'
    if fault == 'namespace': s['namespace_uid'] = 'replaced-namespace'
    if fault == 'pending-helm': s['objects']['Secret/sh.helm.release.v1.synthetic-release.v4']['metadata']['labels']['status'] = 'pending-upgrade'
    if fault == 'later-history':
        later = copy.deepcopy(s['history'][-1]); later['metadata']['labels']['version'] = '5'; s['history'].append(later)
    if fault == 'ownership': web['metadata']['annotations']['meta.helm.sh/release-name'] = 'foreign'
    if fault == 'values': (work / 'values.pending.json').write_text('{}')
    operation = json.loads((state / 'operation.json').read_text())
    if fault == 'expected': (state / 'helm-applications' / ('a' * 24) / operation['helm_application'] / 'expected.json').write_text('[]')
    if fault == 'missing-intent': operation.pop('helm_application'); (state / 'operation.json').write_text(json.dumps(operation))
    api.write_text(json.dumps(s))
    extra = ''
    if fault == 'stored-values':
        (work / 'foreign-values.json').write_text('{}')
        extra = 'STORED_VALUES="$GSJ_WORK/foreign-values.json"\n'
    result = run(extra + '''RESUME_ID="$OPERATION"; COMMAND=resume
record_ready() { touch "$STATE_DIR/incorrect-ready"; }
verify_application() { touch "$STATE_DIR/incorrect-verify"; }
record_installed() { touch "$STATE_DIR/incorrect-installed"; }
resume_operation''')
    assert result.returncode != 0
    assert not list(state.glob('incorrect-*'))
    assert json.loads((state / 'operation.json').read_text())['status'] == 'applying'


def test_real_chart_restore_repair_binds_the_failed_job_and_next_revision(application):
    # restore_application_repair re-runs helm_application_prepare over a failed
    # revision: the same signed chart and values, the failed hook Job's UID as
    # the prior Job, and the next history revision as the only generation change.
    run, _, api, _, state, _ = application
    record = json.loads((state / 'operation.json').read_text()); record['kind'] = 'restore'
    (state / 'operation.json').write_text(json.dumps(record))
    assert run('helm_application_prepare').returncode == 0
    first = json.loads((state / 'operation.json').read_text())['helm_application']
    s = json.loads(api.read_text())
    failed = copy.deepcopy(s['history'][0]); failed['metadata'].update(name='sh.helm.release.v1.synthetic-release.v4', uid='failed-history')
    failed['metadata']['labels'].update(version='4', status='failed'); s['history'].append(failed)
    s['objects']['Job/synthetic-release-provision']['metadata']['uid'] = 'failed-provision'
    api.write_text(json.dumps(s))
    result = run('helm_application_prepare')
    assert result.returncode == 0, result.stderr
    second = json.loads((state / 'operation.json').read_text())['helm_application']
    root = state / 'helm-applications' / ('a' * 24)
    old, new = (json.loads((root / attempt / 'intent.json').read_text()) for attempt in (first, second))
    assert second != first and (old['revision'], new['revision']) == (4, 5)
    assert new['prior_job_uid'] == 'failed-provision' and new['generation'] == 'synthetic-release:5'
    assert (new['chart_sha256'], new['values_sha256']) == (old['chart_sha256'], old['values_sha256'])
    old_expected = (root / first / 'expected.json').read_text(); new_expected = (root / second / 'expected.json').read_text()
    assert old_expected != new_expected
    assert json.loads(old_expected.replace('synthetic-release:4', 'synthetic-release:5')) == json.loads(new_expected)


def test_pending_history_refuses_new_helm_binding(application):
    run, _, api, _, state, _ = application
    s = json.loads(api.read_text()); s['history'][0]['metadata']['labels']['status'] = 'pending-upgrade'; api.write_text(json.dumps(s))
    result = run('helm_application_prepare')
    assert result.returncode != 0
    assert json.loads((state / 'operation.json').read_text())['status'] == 'owned'
    assert not (state / 'helm-applications').exists()


@pytest.mark.parametrize('declared,expected', [('absent', True), (None, True), (True, True), (False, False)])
def test_service_links_projection_preserves_false_and_normalizes_legacy_defaults(application, declared, expected):
    run, _, _, work, _, _ = application
    resource = {'kind': 'Deployment', 'metadata': {'name': 'legacy-or-current'},
                'spec': {'replicas': 1, 'selector': {}, 'template': {'metadata': {}, 'spec': {'containers': []}}}}
    if declared != 'absent': resource['spec']['template']['spec']['enableServiceLinks'] = declared
    (work / 'service-links.json').write_text(json.dumps(resource))
    result = run('helm_application_projection "$GSJ_WORK/service-links.json"')
    assert result.returncode == 0, result.stderr
    actual = json.loads(result.stdout)[0]['pod']['spec']['enableServiceLinks']
    assert actual is expected
    if declared in ('absent', None):
        # An older chart's omitted/null field and the API's explicit default
        # describe the same target; false must never be defaulted to true.
        resource['spec']['template']['spec']['enableServiceLinks'] = True
        (work / 'service-links.json').write_text(json.dumps(resource))
        defaulted = run('helm_application_projection "$GSJ_WORK/service-links.json"')
        assert defaulted.returncode == 0, defaulted.stderr
        assert json.loads(defaulted.stdout) == json.loads(result.stdout)
