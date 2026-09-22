"""Corrected-program restore continuation keeps the authenticated old target."""
import base64
import gzip
import hashlib
import json
from pathlib import Path
import shlex
import shutil

import pytest

from tests.test_installer import runtime, _runtime, _restore_fixture, INSTALLER


def put(path, value):
    path.write_text(json.dumps(value))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _stopped_restore(runtime, tmp_path, ancestry=((1, 'deployed'),)):
    def history(documents, target, work):
        for version, status in ancestry:
            documents['cluster-private.json']['items'].append({
                'apiVersion': 'v1', 'kind': 'Secret', 'type': 'helm.sh/release.v1',
                'metadata': {'name': f'sh.helm.release.v1.synthetic-release.v{version}', 'uid': f'source-history-{version}',
                             'labels': {'owner': 'helm', 'name': 'synthetic-release', 'status': status, 'version': str(version)}},
                'data': {'release': 'c3ludGhldGljLW9wYXF1ZS1oaXN0b3J5'}})
        # The chart owns its scripts ConfigMap; a backup carries it by release label.
        documents['cluster-private.json']['items'].append({
            'apiVersion': 'v1', 'kind': 'ConfigMap',
            'metadata': {'name': 'synthetic-release-scripts', 'labels': {'app.kubernetes.io/instance': 'synthetic-release'}},
            'data': {'provision.sh': 'synthetic source provisioning script'}})
    invoke, _ = _restore_fixture(runtime, tmp_path, transform=history)
    run, state, work = runtime
    first = invoke(before_restore="helm_apply() { exit 79; }")
    assert first.returncode == 79, first.stderr
    operation = json.loads((work / 'operation.json').read_text())['operation']
    saved = work / ('restore-' + operation)
    cluster = json.loads(state.read_text()); cluster['lease']['spec']['renewTime'] = '2000-01-01T00:00:00.000000Z'
    cluster['calls'] = []
    bindings = {}
    for role, suffix in [('forgejo', 'forgejo'), ('gsj', 'data'), ('chroma', 'chroma')]:
        name = 'synthetic-release-' + suffix; pv = 'target-pv-' + suffix
        claim = cluster['resources']['PersistentVolumeClaim/' + name]
        claim['spec']['volumeName'] = pv; claim['status'] = {'phase': 'Bound'}
        cluster['resources']['PersistentVolume/' + pv] = {'kind': 'PersistentVolume',
            'metadata': {'name': pv, 'uid': 'backend-' + suffix},
            'spec': {'claimRef': {'uid': claim['metadata']['uid'], 'namespace': 'synthetic-namespace', 'name': name}}}
        bindings[role] = {'name': name, 'uid': claim['metadata']['uid'], 'pv_name': pv, 'pv_uid': 'backend-' + suffix,
                          'root': '/volumes/' + role}
    put(state, cluster); put(saved / 'bindings.json', bindings)
    checkpoint = json.loads((work / 'restoration.json').read_text())
    proof = {'archive_sha256': '1' * 64, 'manifest_sha256': '2' * 64, 'entries': 12}
    settings = {'format': 'gsj.restore-files/1', 'operation': operation, 'release_identity': 'synthetic-release',
                'namespace_uid': checkpoint['target_namespace_uid'], 'archive_sha256': proof['archive_sha256'],
                'encrypted_archive_sha256': checkpoint['archive_sha256'], 'volumes': bindings}
    put(saved / 'archive-proof.json', proof); put(saved / 'files-settings.json', settings)
    put(saved / 'files-result.json', {'format': 'gsj.restore-files-result/1', 'status': 'complete', 'restored': True,
        'operation': operation, 'release_identity': settings['release_identity'], 'namespace_uid': settings['namespace_uid'],
        'archive_sha256': settings['archive_sha256'], 'encrypted_archive_sha256': settings['encrypted_archive_sha256'],
        'settings_file_sha256': sha(saved / 'files-settings.json'), 'manifest_sha256': proof['manifest_sha256'], 'entries': 12})
    corrected = tmp_path / 'corrected'; corrected.mkdir()
    put(corrected / 'release.json', {'identity': 'corrected-program', 'version': 'v9.9.9', 'supported_sources': ['synthetic-release']})
    prior = tmp_path / 'prior-program'; prior.mkdir()
    for name in ['gsj-install.sh', 'installer-descriptor.json', 'installer-descriptor.sig']:
        (prior / name).write_text('synthetic authenticated ' + name)
    body = f'''source {shlex.quote(str(INSTALLER / 'startup-recovery.sh'))}
RELEASE_ID=corrected-program; GSJ_PAYLOAD={shlex.quote(str(corrected))}; SOURCE_INSTALLER={shlex.quote(str(prior / 'gsj-install.sh'))}
authenticate_predecessor() {{
 [[ $2 == synthetic-release && ${{AUTH_FAIL:-false}} != true ]] || fail 'synthetic prior authentication refused'
 mkdir -p "$3"; local f
 for f in gsj-install.sh installer-descriptor.json installer-descriptor.sig; do cp "$(dirname "$1")/$f" "$3/$f"; done
 PREDECESSOR_PAYLOAD="$TEST_PAYLOAD"
}}
helm_apply() {{ [[ $RELEASE_ID == synthetic-release && $GSJ_PAYLOAD == "$TEST_PAYLOAD" ]] || fail 'wrong application selected'; printf '%s' "$RELEASE_ID" > "$STATE_DIR/actual-target"; exit 80; }}
'''
    return {'invoke': invoke, 'run': run, 'state': state, 'work': work, 'saved': saved, 'operation': operation,
            'body': body, 'corrected': corrected, 'prior': prior, 'payload': tmp_path / 'restore-payload',
            'original_operation': (work / 'operation.json').read_bytes(), 'original_checkpoint': (work / 'restoration.json').read_bytes()}


@pytest.fixture
def stopped_restore(runtime, tmp_path):
    return _stopped_restore(runtime, tmp_path)


def test_corrected_restore_program_preserves_source_backup_and_exact_restored_history(stopped_restore):
    m = stopped_restore; before = json.loads(m['state'].read_text())['resources']
    result = m['invoke']('restore-repair', m['operation'], before_restore=m['body'])
    assert result.returncode == 80, result.stderr
    receipt = json.loads((m['saved'] / 'program-transition.json').read_text())
    assert receipt['program'] == 'corrected-program' and receipt['target'] == receipt['previous_program'] == 'synthetic-release'
    assert receipt['status'] == 'files-restored-before-helm' and receipt['target_namespace_uid'] == 'target-namespace-uid'
    assert receipt['source_namespace_uid'] == 'source-namespace-uid'
    assert receipt['storage']['gsj']['pv_uid'] == 'backend-data'
    assert any(r['name'] == 'sh.helm.release.v1.synthetic-release.v1' for r in receipt['restored_resources'])
    assert json.loads(m['state'].read_text())['resources'] == before
    assert (m['work'] / 'operation.json').read_bytes() == m['original_operation']
    assert (m['work'] / 'restoration.json').read_bytes() == m['original_checkpoint']
    assert (m['saved'] / 'program-original-restoration.json').read_bytes() == m['original_checkpoint']
    assert (m['work'] / 'actual-target').read_text() == 'synthetic-release'


def test_same_corrected_restore_program_reuses_create_only_receipt(stopped_restore):
    m = stopped_restore
    first = m['invoke']('restore-repair', m['operation'], before_restore=m['body']); assert first.returncode == 80, first.stderr
    receipt = (m['saved'] / 'program-transition.json').read_bytes()
    cluster = json.loads(m['state'].read_text()); cluster['lease']['spec']['renewTime'] = '2000-01-01T00:00:00.000000Z'; cluster['calls'] = []; put(m['state'], cluster)
    shutil.rmtree(m['work'] / 'restore-program')
    second = m['invoke']('restore-repair', m['operation'], before_restore=m['body'] + '\nSOURCE_INSTALLER=""\n')
    assert second.returncode == 80, second.stderr
    assert (m['saved'] / 'program-transition.json').read_bytes() == receipt
    assert (m['work'] / 'operation.json').read_bytes() == m['original_operation']


def test_corrected_restore_program_admits_the_trust_bundle_secret_inputs_rewrote(stopped_restore):
    # secret_inputs applies the tools host's system bundle plus trust.ca_file
    # before every Helm apply; only its UID and restore metadata are evidence.
    m = stopped_restore; cluster = json.loads(m['state'].read_text())
    trust = cluster['resources']['ConfigMap/synthetic-release-trust']
    trust['data']['bundle.pem'] = 'another tools host system bundle\nsynthetic-ca-bundle\n'
    trust['metadata']['annotations']['kubectl.kubernetes.io/last-applied-configuration'] = '{}'
    put(m['state'], cluster)
    result = m['invoke']('restore-repair', m['operation'], before_restore=m['body'])
    assert result.returncode == 80, result.stderr
    receipt = json.loads((m['saved'] / 'program-transition.json').read_text())
    assert any(r['kind'] == 'ConfigMap' and r['name'] == 'synthetic-release-trust' for r in receipt['restored_resources'])


def _takeover_then(m, change):
    # The corrected program took over (receipt), then `change` happened before its reconnect.
    first = m['invoke']('restore-repair', m['operation'], before_restore=m['body']); assert first.returncode == 80, first.stderr
    cluster = json.loads(m['state'].read_text()); cluster['lease']['spec']['renewTime'] = '2000-01-01T00:00:00.000000Z'
    change(cluster); cluster['calls'] = []; put(m['state'], cluster)
    shutil.rmtree(m['work'] / 'restore-program')
    return cluster, m['invoke']('restore-repair', m['operation'], before_restore=m['body'] + '\nSOURCE_INSTALLER=""\n')


def test_corrected_restore_program_ignores_an_attempt_directory_without_its_pointer(stopped_restore):
    # helm_application_prepare stopped after its attempt directory and before
    # the pointer commit: no Helm process started, so restore-repair continues.
    m = stopped_restore
    def orphan(cluster):
        directory = m['work'] / 'helm-applications' / m['operation'] / ('5' * 24); directory.mkdir(parents=True)
        shutil.copyfile(m['work'] / 'values.pending.json', directory / 'values.json')
    _, second = _takeover_then(m, orphan)
    assert second.returncode == 80, second.stderr
    assert (m['work'] / 'actual-target').read_text() == 'synthetic-release'
    assert (m['work'] / 'operation.json').read_bytes() == m['original_operation']


def test_a_target_helm_record_after_the_transition_names_the_fresh_restore(stopped_restore):
    m = stopped_restore
    def record(cluster):
        cluster['resources']['Secret/sh.helm.release.v1.synthetic-release.v2'] = {'kind': 'Secret', 'type': 'helm.sh/release.v1',
            'metadata': {'name': 'sh.helm.release.v1.synthetic-release.v2', 'uid': 'foreign-history',
                         'labels': {'owner': 'helm', 'name': 'synthetic-release', 'status': 'failed', 'version': '2'}}}
    cluster, second = _takeover_then(m, record)
    assert second.returncode not in (0, 80), second.stderr
    assert 'after the restore-program transition' in second.stderr and FRESH in second.stderr, second.stderr
    after = json.loads(m['state'].read_text())
    assert after['lease'] == cluster['lease'] and not any(call[0] in MUTATIONS for call in after['calls'])


@pytest.mark.parametrize('fault', ['signature', 'undeclared', 'no-source', 'site', 'checkpoint', 'phase', 'helm-symlink',
    'file-result', 'file-namespace', 'pvc-uid', 'pv-uid', 'secret-data', 'secret-uid', 'trust-uid', 'trust-label', 'source-history',
    'extra-history', 'controller', 'pod', 'namespace', 'lease', 'live-lease', 'intent', 'archive', 'receipt-symlink'])
def test_corrected_restore_refuses_drift_before_lease_or_other_mutations(stopped_restore, fault):
    m = stopped_restore; extra = ''; cluster = json.loads(m['state'].read_text())
    if fault == 'signature': extra = 'AUTH_FAIL=true\n'
    elif fault == 'undeclared': put(m['corrected'] / 'release.json', {'identity': 'corrected-program', 'supported_sources': []})
    elif fault == 'no-source': extra = 'SOURCE_INSTALLER=""\n'
    elif fault == 'site':
        path = m['work'] / 'target-site.json'; value = json.loads(path.read_text()); value['limits']['upload_mb'] += 1; put(path, value)
    elif fault == 'checkpoint':
        path = m['work'] / 'restoration.json'; value = json.loads(path.read_text()); value['status'] = 'restoring-files'; put(path, value)
    elif fault == 'phase':
        path = m['work'] / 'operation.json'; value = json.loads(path.read_text()); value['status'] = 'applying'; put(path, value)
    elif fault == 'helm-symlink':
        elsewhere = m['work'] / 'elsewhere'; elsewhere.mkdir()
        (m['work'] / 'helm-applications').mkdir(); (m['work'] / 'helm-applications' / m['operation']).symlink_to(elsewhere)
    elif fault == 'file-result':
        path = m['saved'] / 'files-result.json'; value = json.loads(path.read_text()); value['entries'] += 1; put(path, value)
    elif fault == 'file-namespace':
        path = m['saved'] / 'files-settings.json'; value = json.loads(path.read_text()); value['namespace_uid'] = 'foreign'; put(path, value)
    elif fault in ('pvc-uid', 'pv-uid', 'secret-uid', 'secret-data', 'trust-uid', 'source-history'):
        key = {'pvc-uid': 'PersistentVolumeClaim/synthetic-release-data', 'pv-uid': 'PersistentVolume/target-pv-data',
               'secret-uid': 'Secret/synthetic-release-operator', 'secret-data': 'Secret/synthetic-release-admin-token',
               'trust-uid': 'ConfigMap/synthetic-release-trust', 'source-history': 'Secret/sh.helm.release.v1.synthetic-release.v1'}[fault]
        if fault.endswith('-uid'): cluster['resources'][key]['metadata']['uid'] = 'replacement'
        else: cluster['resources'][key]['data']['unrelated'] = 'changed'
    elif fault == 'trust-label': del cluster['resources']['ConfigMap/synthetic-release-trust']['metadata']['labels']['gsj.io/restore-operation']
    elif fault == 'extra-history':
        cluster['resources']['Secret/sh.helm.release.v1.synthetic-release.v2'] = {'kind': 'Secret', 'metadata': {'name': 'sh.helm.release.v1.synthetic-release.v2', 'uid': 'new-history'}}
    elif fault == 'controller':
        cluster['resources']['Deployment/foreign'] = {'kind': 'Deployment', 'metadata': {'name': 'foreign', 'labels': {'app.kubernetes.io/instance': 'synthetic-release'}}, 'spec': {}}
    elif fault == 'pod':
        cluster['resources']['Pod/foreign'] = {'kind': 'Pod', 'metadata': {'name': 'foreign'}, 'spec': {'volumes': [{'persistentVolumeClaim': {'claimName': 'synthetic-release-data'}}]}}
    elif fault == 'namespace': cluster['namespace_uid'] = 'replacement'
    elif fault == 'lease': cluster['lease']['metadata']['annotations']['gsj.io/operation-intent-sha256'] = 'foreign'
    elif fault == 'live-lease': cluster['lease']['spec']['renewTime'] = '2099-01-01T00:00:00.000000Z'
    elif fault == 'intent':
        path = m['work'] / 'operation-intents' / m['operation'] / 'intent.json'; value = json.loads(path.read_text()); value['archive']['sha256'] = 'f' * 64; put(path, value)
    elif fault == 'archive':
        path = Path(json.loads((m['work'] / 'restoration.json').read_text())['archive']); path.write_bytes(path.read_bytes() + b'changed')
    else: (m['saved'] / 'program-transition.json').symlink_to(m['work'] / 'foreign')
    cluster['calls'] = []; put(m['state'], cluster)
    result = m['invoke']('restore-repair', m['operation'], before_restore=m['body'] + '\n' + extra)
    assert result.returncode not in (0, 80), (fault, result.stdout, result.stderr)
    assert 'unbound variable' not in result.stderr and 'jq:' not in result.stderr, result.stderr
    after = json.loads(m['state'].read_text())
    assert after['resources'] == cluster['resources']
    assert not any(call[0] in ('replace', 'create', 'apply', 'delete', 'exec') for call in after['calls']), (fault, after['calls'])
    assert not (m['saved'] / 'program-transition.json').is_file()


# A restore whose application Helm revision failed: restored source ancestry
# v1, this operation's failed attempt v2 with its partial controllers, and the
# failed hook Job. Built once per program and restored at the same path per test.
OLD = '2000-01-01T00:00:00.000000Z'
ATTEMPT, SECOND, ORPHAN, EARLIER = '1' * 24, '2' * 24, '3' * 24, '4' * 24
FAILED = {'attempt': ATTEMPT, 'revision': 2, 'release_secret_uid': 'failed-history', 'status': 'failed'}
FRESH = 'another Kubernetes context whose namespace synthetic-namespace is empty'
MUTATIONS = ('create', 'replace', 'apply', 'delete', 'exec', 'patch', 'scale')
CHART = {'metadata': {'name': 'gsj', 'version': '0.1.0'}, 'templates': [{'name': 'templates/gsj.yaml', 'data': 'c3ludGhldGlj'}]}
REPAIR = '''
CONFIG="$TEST_WORK/target-site.json"
trap 'printf "\\nRECOVERY_HINT=%s\\n" "${RECOVERY_HINT:-}" >&2' EXIT
helm_apply() { [[ $RELEASE_ID == synthetic-release && $GSJ_PAYLOAD == "$TEST_PAYLOAD" ]] || fail 'wrong application selected'; printf '%s' "$RELEASE_ID" > "$STATE_DIR/actual-target"; exit 80; }
wait_application() { printf '%s' "$RELEASE_ID" > "$STATE_DIR/actual-target"; exit 81; }
helm() { [[ $1 == install && ${KUBECONFIG:-} == /dev/null ]] || return 9; cat "$STATE_DIR/signed-release.json"; }
'''


def _release(version, status, modtime='stored'):
    return {'name': 'synthetic-release', 'namespace': 'synthetic-namespace', 'version': version, 'info': {'status': status},
            'chart': {**CHART, 'modtime': modtime}, 'config': {'synthetic': 'values'}}


def _history(version, status, uid):
    stored = base64.b64encode(gzip.compress(json.dumps(_release(version, status)).encode()))
    return {'kind': 'Secret', 'type': 'helm.sh/release.v1', 'data': {'release': base64.b64encode(stored).decode()},
            'metadata': {'name': f'sh.helm.release.v1.synthetic-release.v{version}', 'uid': uid,
                         'labels': {'owner': 'helm', 'name': 'synthetic-release', 'status': status, 'version': str(version)}}}


def _attempt(m, attempt, revision):
    directory = m['work'] / 'helm-applications' / m['operation'] / attempt; directory.mkdir(parents=True)
    shutil.copyfile(m['work'] / 'values.pending.json', directory / 'values.json'); (directory / 'expected.json').write_text('[]')
    put(directory / 'intent.json', {'format': 'gsj.helm-application/1', 'operation': m['operation'], 'attempt': attempt,
        'target': 'synthetic-release', 'namespace': 'synthetic-namespace', 'namespace_uid': 'target-namespace-uid',
        'release': 'synthetic-release', 'chart_sha256': sha(m['payload'] / 'chart.tgz'), 'values_sha256': sha(directory / 'values.json'),
        'expected_sha256': sha(directory / 'expected.json'), 'prior_job_uid': '', 'revision': revision,
        'generation': f'synthetic-release:{revision}', 'template_revision': 1})
    return directory


def _failed_helm_state(m, revision=2):
    work, saved, operation = m['work'], m['saved'], m['operation']
    (m['payload'] / 'chart.tgz').write_bytes(b'synthetic signed chart')
    checkpoint = json.loads((work / 'restoration.json').read_text())
    put(work / f'capacity-{operation}-before.json', {'format': 'gsj.capacity/1', 'status': 'passed',
        'purpose': 'restored-files-before-startup', 'operation': operation, 'namespace_uid': checkpoint['target_namespace_uid'],
        'restoration': {'operation': operation, 'archive_sha256': checkpoint['archive_sha256'],
                        'files_result_sha256': sha(saved / 'files-result.json'), 'bindings_sha256': sha(saved / 'bindings.json')}})
    _attempt(m, ATTEMPT, revision)
    record = json.loads((work / 'operation.json').read_text()); record.update(status='applying', helm_application=ATTEMPT)
    put(work / 'operation.json', record)
    put(work / 'signed-release.json', _release(1, 'pending-install', modtime='rendered'))
    cluster = json.loads(m['state'].read_text()); resources = cluster['resources']
    resources[f'Secret/sh.helm.release.v1.synthetic-release.v{revision}'] = _history(revision, 'failed', 'failed-history')
    annotations = {'meta.helm.sh/release-name': 'synthetic-release', 'meta.helm.sh/release-namespace': 'synthetic-namespace'}
    for role, claims in (('web', ['data', 'forgejo']), ('forgejo', ['forgejo']), ('chroma', ['chroma'])):
        name = 'synthetic-release-' + role
        labels = {'app.kubernetes.io/instance': 'synthetic-release', 'app.kubernetes.io/component': 'gsj' if role == 'web' else role}
        volumes = [{'name': c, 'persistentVolumeClaim': {'claimName': 'synthetic-release-' + c}} for c in claims]
        resources['Deployment/' + name] = {'kind': 'Deployment', 'metadata': {'name': name, 'uid': 'deploy-' + role,
            'labels': labels, 'annotations': annotations}, 'spec': {'template': {'spec': {'volumes': volumes}}}}
        resources[f'ReplicaSet/{name}-1'] = {'kind': 'ReplicaSet', 'metadata': {'name': name + '-1', 'uid': 'rs-' + role,
            'labels': labels, 'ownerReferences': [{'kind': 'Deployment', 'name': name, 'uid': 'deploy-' + role}]},
            'spec': {'template': {'spec': {'volumes': volumes}}}}
        status = {'phase': 'Running', 'containerStatuses': [{'name': role, 'state': {'running': {}}}]}
        if role == 'web':
            waiting = {'waiting': {'reason': 'PodInitializing'}}
            status = {'phase': 'Pending', 'initContainerStatuses': [{'name': 'wait-deps', 'state': {'running': {}}}] +
                      [{'name': c, 'state': waiting} for c in ('corpus-copy', 'corpus-initialize')],
                      'containerStatuses': [{'name': c, 'state': waiting} for c in ('gsj-web', 'agent-runner', 'gsj-mcp')]}
        resources[f'Pod/{name}-1-a'] = {'kind': 'Pod', 'metadata': {'name': name + '-1-a', 'uid': 'pod-' + role, 'labels': labels,
            'ownerReferences': [{'kind': 'ReplicaSet', 'uid': 'rs-' + role}]}, 'spec': {'volumes': volumes}, 'status': status}
    forgejo = [{'name': 'forgejo', 'persistentVolumeClaim': {'claimName': 'synthetic-release-forgejo'}}]
    job = {'app.kubernetes.io/instance': 'synthetic-release'}
    resources['Job/synthetic-release-provision'] = {'kind': 'Job', 'metadata': {'name': 'synthetic-release-provision',
        'uid': 'failed-provision', 'labels': job}, 'spec': {'template': {'spec': {'volumes': forgejo}}},
        'status': {'failed': 3, 'conditions': [{'type': 'Failed', 'status': 'True'}]}}
    resources['Pod/synthetic-release-provision-a'] = {'kind': 'Pod', 'metadata': {'name': 'synthetic-release-provision-a',
        'uid': 'pod-provision', 'labels': {**job, 'job-name': 'synthetic-release-provision'},
        'ownerReferences': [{'kind': 'Job', 'uid': 'failed-provision'}]}, 'spec': {'volumes': forgejo},
        'status': {'phase': 'Failed', 'containerStatuses': [{'name': 'provision', 'state': {'terminated': {'exitCode': 1}}}]}}
    cluster['lease']['spec']['renewTime'] = OLD; cluster['calls'] = []
    put(m['state'], cluster)


@pytest.fixture(scope='module')
def failed_helm_templates(tmp_path_factory):
    templates = {}
    def template(program):
        if program not in templates:
            base = tmp_path_factory.mktemp('failed-helm-' + program)
            # 'pruned' is the source program over restored v1 (superseded) and v2 (deployed).
            ancestry = ((1, 'superseded'), (2, 'deployed')) if program == 'pruned' else ((1, 'deployed'),)
            m = _stopped_restore(_runtime(base), base, ancestry)
            if program == 'corrected':
                # The corrected program took over before startup; its receipt exists.
                first = m['invoke']('restore-repair', m['operation'], before_restore=m['body'])
                assert first.returncode == 80, first.stderr
                shutil.rmtree(m['work'] / 'restore-program')
            _failed_helm_state(m, len(ancestry) + 1)
            snapshot = base.parent / (base.name + '-snapshot')
            shutil.copytree(base, snapshot, symlinks=True)
            templates[program] = (base, snapshot, m)
        return templates[program]
    return template


@pytest.fixture
def failed_helm(failed_helm_templates):
    def restore(program='corrected'):
        base, snapshot, m = failed_helm_templates(program)
        shutil.rmtree(base); shutil.copytree(snapshot, base, symlinks=True)
        return m
    return restore


def _run(m, command='repair', program='corrected', extra='', entry='repair_operation'):
    # main() selects the restore's program for resume/repair before preflight.
    body = m['body'] + '\nSOURCE_INSTALLER=""\n' if program == 'corrected' else ''
    return m['invoke'](command, m['operation'], before_restore=body + REPAIR + extra + f'\nrestore_program_select; {entry}; exit 0\n')


def _hint(result):
    return [line for line in result.stderr.splitlines() if line.startswith('RECOVERY_HINT=')][-1][len('RECOVERY_HINT='):]


def _local(m):
    return {name: (m['work'] / name).read_bytes() for name in ('operation.json', 'restoration.json', 'site.pending.json', 'values.pending.json')}


@pytest.mark.parametrize('program', ['corrected', 'source'])
def test_failed_restore_revision_repair_reapplies_the_same_signed_target(failed_helm, program):
    m = failed_helm(program); before = json.loads(m['state'].read_text()); local = _local(m)
    result = _run(m, program=program)
    assert result.returncode == 80, result.stderr
    assert (m['work'] / 'actual-target').read_text() == 'synthetic-release'
    record = json.loads((m['work'] / 'operation.json').read_text())
    assert record.pop('helm_application_history') == [FAILED]
    assert record == json.loads(local['operation.json'])
    after = json.loads(m['state'].read_text())
    assert after['resources'] == before['resources']
    # The Lease renewal is the only cluster write; claims, Secrets and Helm stay.
    assert [call[0] for call in after['calls'] if call[0] in MUTATIONS] == ['replace']
    lease = after['lease']['spec']
    assert lease['holderIdentity'] == m['operation'] and lease['acquireTime'] == before['lease']['spec']['acquireTime']
    assert lease['renewTime'] != OLD
    assert all((m['work'] / name).read_bytes() == local[name] for name in ('restoration.json', 'site.pending.json', 'values.pending.json'))
    assert not list(m['work'].glob('repair-transition-*')) and not list(m['work'].glob('quiescence-*'))
    assert 'Re-applying restore target synthetic-release after failed Helm revision 2' in result.stderr
    assert 'may already have run on the restored claims' in result.stderr


@pytest.mark.parametrize('case', ['unwritten', 'unwritten-controllers', 'unwritten-after-failure', 'recorded', 'orphan',
                                  'deployed', 'pending', 'superseded', 'no-pointer', 'history-symlink'])
def test_restore_repair_classifies_its_pointer_revision(failed_helm, case):
    m = failed_helm(); cluster = json.loads(m['state'].read_text()); resources = cluster['resources']
    record = json.loads((m['work'] / 'operation.json').read_text())
    v2 = resources['Secret/sh.helm.release.v1.synthetic-release.v2']
    if case.startswith('unwritten'): del resources['Secret/sh.helm.release.v1.synthetic-release.v2']
    if case == 'unwritten':
        for key in [k for k, v in resources.items() if v['kind'] in ('Deployment', 'ReplicaSet', 'Job', 'Pod')]: del resources[key]
    if case == 'unwritten-after-failure':
        # A crash after the next pointer committed, before Helm wrote revision 3.
        resources['Secret/sh.helm.release.v1.synthetic-release.v2'] = v2
        _attempt(m, SECOND, 3); record.update(helm_application=SECOND, helm_application_history=[FAILED])
    if case == 'recorded': record['helm_application_history'] = [FAILED]
    if case == 'orphan': _attempt(m, ORPHAN, 3)
    if case in ('deployed', 'pending', 'superseded'): v2['metadata']['labels']['status'] = {'pending': 'pending-upgrade'}.get(case, case)
    if case == 'no-pointer': record.pop('helm_application')
    if case == 'history-symlink':
        target = _attempt(m, EARLIER, 1); moved = target.parent.parent / 'elsewhere'; target.rename(moved); target.symlink_to(moved)
        record['helm_application_history'] = [{'attempt': EARLIER, 'revision': 1, 'release_secret_uid': 'earlier', 'status': 'failed'}]
    put(m['work'] / 'operation.json', record); put(m['state'], cluster); local = _local(m)
    result = _run(m)
    assert 'unbound variable' not in result.stderr and 'jq:' not in result.stderr, result.stderr
    if case in ('unwritten', 'unwritten-after-failure', 'recorded', 'orphan'):
        assert result.returncode == 80, result.stderr
        assert json.loads((m['work'] / 'operation.json').read_text()).get('helm_application_history') == (None if case == 'unwritten' else [FAILED])
        return
    assert result.returncode not in (0, 80), result.stderr
    assert _local(m) == local
    assert not any(call[0] in MUTATIONS for call in json.loads(m['state'].read_text())['calls'])
    if case == 'deployed': assert f"completed; use resume --operation {m['operation']} with this installer" in result.stderr
    else: assert FRESH in result.stderr, result.stderr
    if case == 'pending': assert 'is pending' in result.stderr


DRIFT = {
    'site': 'restore program configuration differs from the retained operation',
    'live-lease': 'still live', 'backup-round': 'cannot select a backup round', 'continue-helm': 'startup Helm continuation',
    'takeover': 'can take over a restore only before application startup',
    'source-program': 'continued by its recorded program corrected-program',
    **{fault: FRESH for fault in ('attempt-values', 'chart', 'receipt-storage', 'receipt-checkpoint', 'pvc-uid', 'secret-data',
        'marker-data', 'trust-uid', 'restore-pod', 'initializer-ran', 'application-running', 'extra-deployment',
        'foreign-statefulset', 'bare-pod', 'foreign-replicaset', 'failed-chart', 'failed-config', 'capacity-missing',
        'capacity-insufficient', 'namespace', 'lease-intent', 'ancestry-data', 'ancestry-pruned', 'foreign-history',
        'intent-symlink', 'resource-symlink', 'helm-symlink')},
}


@pytest.mark.parametrize('fault', list(DRIFT))
def test_restore_repair_refuses_drift_before_the_lease_or_any_write(failed_helm, fault):
    m = failed_helm(); work, saved, operation = m['work'], m['saved'], m['operation']
    cluster = json.loads(m['state'].read_text()); r = cluster['resources']; extra = ''; program = 'corrected'
    web = r['Pod/synthetic-release-web-1-a']['status']; claim = [{'name': 'data', 'persistentVolumeClaim': {'claimName': 'synthetic-release-data'}}]
    def edit(path, change):
        value = json.loads(path.read_text()); change(value); put(path, value)
    def move(path):
        moved = path.with_name(path.name + '-real'); path.rename(moved); path.symlink_to(moved)
    if fault == 'site': edit(work / 'target-site.json', lambda v: v['limits'].update(upload_mb=v['limits']['upload_mb'] + 1))
    elif fault == 'attempt-values': (work / 'helm-applications' / operation / ATTEMPT / 'values.json').write_text('{}')
    elif fault == 'chart': (m['payload'] / 'chart.tgz').write_bytes(b'another chart')
    elif fault == 'receipt-storage': edit(saved / 'program-transition.json', lambda v: v['storage']['gsj'].update(pv_uid='replacement'))
    elif fault == 'receipt-checkpoint': edit(saved / 'program-original-restoration.json', lambda v: v.update(status='restoring-files'))
    elif fault == 'pvc-uid': r['PersistentVolumeClaim/synthetic-release-data']['metadata']['uid'] = 'replacement'
    elif fault == 'secret-data': r['Secret/synthetic-release-admin-token']['data']['token'] = 'Y2hhbmdlZA=='
    elif fault == 'marker-data': r['ConfigMap/synthetic-release-provisioned']['data']['generation'] = 'synthetic-release:2'
    elif fault == 'trust-uid': r['ConfigMap/synthetic-release-trust']['metadata']['uid'] = 'replacement'
    elif fault == 'restore-pod':
        pod = json.loads((work / 'restoration.json').read_text())['pod']; r['Pod/' + pod] = {'kind': 'Pod', 'metadata': {'name': pod}, 'spec': {}}
    elif fault == 'initializer-ran': web['initContainerStatuses'][2]['state'] = {'terminated': {'exitCode': 1}}
    elif fault == 'application-running': web['containerStatuses'][0]['state'] = {'running': {}}
    elif fault == 'extra-deployment':
        extra_web = json.loads(json.dumps(r['Deployment/synthetic-release-web'])); extra_web['metadata'].update(name='synthetic-release-extra', uid='extra')
        r['Deployment/synthetic-release-extra'] = extra_web
    elif fault == 'foreign-statefulset':
        r['StatefulSet/foreign'] = {'kind': 'StatefulSet', 'metadata': {'name': 'foreign', 'uid': 'foreign'}, 'spec': {'template': {'spec': {'volumes': claim}}}}
    elif fault == 'bare-pod': r['Pod/foreign'] = {'kind': 'Pod', 'metadata': {'name': 'foreign', 'uid': 'foreign'}, 'spec': {'volumes': claim}}
    elif fault == 'foreign-replicaset':
        r['ReplicaSet/synthetic-release-web-2'] = {'kind': 'ReplicaSet', 'metadata': {'name': 'synthetic-release-web-2', 'uid': 'rs-foreign',
            'labels': {'app.kubernetes.io/instance': 'synthetic-release'}, 'ownerReferences': [{'kind': 'Deployment', 'uid': 'foreign'}]}, 'spec': {}}
    elif fault == 'failed-chart': edit(work / 'signed-release.json', lambda v: v['chart']['templates'].append({'name': 'templates/extra.yaml'}))
    elif fault == 'failed-config': edit(work / 'signed-release.json', lambda v: v['config'].update(synthetic='other'))
    elif fault == 'capacity-missing': (work / f'capacity-{operation}-before.json').unlink()
    elif fault == 'capacity-insufficient': edit(work / f'capacity-{operation}-before.json', lambda v: v.update(status='insufficient'))
    elif fault == 'namespace': cluster['namespace_uid'] = 'replacement'
    elif fault == 'lease-intent': cluster['lease']['metadata']['annotations']['gsj.io/operation-intent-sha256'] = 'foreign'
    elif fault == 'ancestry-data': r['Secret/sh.helm.release.v1.synthetic-release.v1']['data']['release'] = 'Y2hhbmdlZA=='
    elif fault == 'ancestry-pruned': del r['Secret/sh.helm.release.v1.synthetic-release.v1']
    elif fault == 'foreign-history': r['Secret/sh.helm.release.v1.synthetic-release.v6'] = _history(6, 'failed', 'foreign-history')
    elif fault == 'intent-symlink': move(work / 'operation-intents' / operation)
    elif fault == 'resource-symlink': move(saved / 'Secret')
    elif fault == 'helm-symlink': move(work / 'helm-applications' / operation)
    elif fault == 'live-lease': cluster['lease']['spec']['renewTime'] = '2099-01-01T00:00:00.000000Z'
    elif fault == 'backup-round': extra = 'BACKUP_ROUND=1'
    elif fault == 'continue-helm': extra = 'CONTINUE_HELM_INSTALLER=/synthetic/older/gsj-install.sh'
    elif fault == 'takeover':
        # A corrected program without a receipt may take over only before startup.
        (saved / 'program-transition.json').unlink(); extra = 'SOURCE_INSTALLER=' + shlex.quote(str(m['prior'] / 'gsj-install.sh'))
    else: program = 'source'
    put(m['state'], cluster); local = _local(m)
    result = _run(m, program=program, extra=extra)
    assert result.returncode not in (0, 80), (fault, result.stderr)
    assert DRIFT[fault] in result.stderr, (fault, result.stderr)
    assert 'unbound variable' not in result.stderr and 'jq:' not in result.stderr, result.stderr
    after = json.loads(m['state'].read_text())
    assert after['resources'] == cluster['resources'] and after['lease'] == cluster['lease']
    assert not any(call[0] in MUTATIONS for call in after['calls']), (fault, after['calls'])
    assert _local(m) == local


@pytest.mark.parametrize('fault', ['job-active', 'image-pull'])
def test_restore_repair_fast_fails_name_their_own_recovery(failed_helm, fault):
    m = failed_helm(); cluster = json.loads(m['state'].read_text()); r = cluster['resources']
    if fault == 'job-active': r['Job/synthetic-release-provision']['status'] = {'active': 1}
    else: r['Pod/synthetic-release-forgejo-1-a']['status']['containerStatuses'][0]['state'] = {'waiting': {'reason': 'ImagePullBackOff'}}
    put(m['state'], cluster); local = _local(m)
    result = _run(m)
    assert result.returncode not in (0, 80), result.stderr
    if fault == 'job-active': assert 'provisioning Job is still active; wait until it completes or fails' in result.stderr
    else:
        assert 'image pull is failing for synthetic-release-forgejo-1-a/forgejo (ImagePullBackOff)' in result.stderr
        assert 'repair never changes restored pull credentials' in result.stderr
    assert f"then rerun repair --operation {m['operation']}" in result.stderr and FRESH not in result.stderr
    after = json.loads(m['state'].read_text())
    assert after['lease'] == cluster['lease'] and not any(call[0] in MUTATIONS for call in after['calls'])
    assert _local(m) == local


@pytest.mark.parametrize('program,phase,command', [
    ('corrected', 'initializing', 'resume'), ('corrected', 'restore-files-verified', 'resume'),
    ('source', 'applying', 'resume'), ('source', 'initializing', 'resume'), ('source', 'applying', 'repair')])
def test_a_restore_program_transition_owns_resume_and_repair(failed_helm, program, phase, command):
    # Deliberate: once the receipt exists the source release no longer resumes.
    m = failed_helm()
    record = json.loads((m['work'] / 'operation.json').read_text()); record['status'] = phase
    if phase == 'restore-files-verified': record.pop('helm_application')
    put(m['work'] / 'operation.json', record)
    result = _run(m, command=command, program=program, entry=f'{command}_operation')
    calls = json.loads(m['state'].read_text())['calls']
    if (program, phase) == ('corrected', 'initializing'):
        assert result.returncode == 81, result.stderr
        assert (m['work'] / 'actual-target').read_text() == 'synthetic-release'
        return
    assert result.returncode not in (0, 80, 81), result.stderr
    if program == 'corrected': assert f"restore-repair --operation {m['operation']} until application startup" in result.stderr
    else: assert 'continued by its recorded program corrected-program' in result.stderr
    assert not any(call[0] in MUTATIONS for call in calls)


def test_a_continued_restore_resumes_after_tls_repair(failed_helm):
    # tls-repair's only local effect: the managed CA's new bytes (the site's CA
    # files; one file in a real site), the old bytes and its receipt. The
    # restore-program receipt binds the site, not these bytes.
    m = failed_helm(); work = m['work']
    record = json.loads((work / 'operation.json').read_text()); record['status'] = 'verifying'; put(work / 'operation.json', record)
    ca = work / 'tls' / 'ca.crt'; before = sha(ca)
    (work / 'tls' / f'ca.before-{before}.crt').write_bytes(ca.read_bytes())
    for path in (ca, work / 'ca-crt', work / 'verify-crt'):
        assert path.is_file(); path.write_bytes(b'synthetic reissued managed CA\n')
    put(work / 'tls-repair.json', {'operation': m['operation'], 'before_ca_sha256': before, 'after_ca_sha256': sha(ca)})
    receipt = (m['saved'] / 'program-transition.json').read_bytes()
    result = _run(m, command='resume', program='corrected', entry='resume_operation')
    assert result.returncode == 81, result.stderr
    assert (work / 'actual-target').read_text() == 'synthetic-release'
    assert (m['saved'] / 'program-transition.json').read_bytes() == receipt


@pytest.mark.parametrize('case', ['failed', 'unwritten', 'pending', 'install'])
def test_resume_of_a_failed_restore_revision_names_its_recovery(failed_helm, case):
    m = failed_helm('source'); cluster = json.loads(m['state'].read_text()); v2 = 'Secret/sh.helm.release.v1.synthetic-release.v2'
    if case == 'unwritten': del cluster['resources'][v2]
    if case == 'pending': cluster['resources'][v2]['metadata']['labels']['status'] = 'pending-upgrade'
    if case == 'install':
        record = json.loads((m['work'] / 'operation.json').read_text()); record['kind'] = 'install'; put(m['work'] / 'operation.json', record)
    put(m['state'], cluster)
    result = _run(m, command='resume', program='source', entry='resume_operation')
    assert result.returncode not in (0, 80, 81), result.stderr
    repair = f"repair --operation {m['operation']} --config {m['work'] / 'target-site.json'} --non-interactive"
    message, hint = {'failed': ('revision 2 failed; fix its cause, then use repair --operation', repair + ' after fixing the cause'),
                     'unwritten': ('revision 2 was never written; use repair --operation', repair),
                     'pending': ('revision 2 is pending', 'restore of its verified archive with the exact source installer'),
                     'install': ('the target Helm revision has not completed', '')}[case]
    assert message in result.stderr, result.stderr
    assert _hint(result).startswith(hint) if hint else _hint(result) == ''


@pytest.mark.parametrize('kind', ['restore', 'install', 'upgrade'])
def test_helm_apply_names_repair_only_for_a_restore_and_keeps_its_measured_capacity(runtime, kind):
    run, _, work = runtime
    operation = 'd' * 24
    put(work / 'operation.json', {'operation': operation, 'kind': kind, 'target': 'synthetic-release', 'status': 'applying'})
    result = run(f'''OPERATION={operation}; CONFIG=/synthetic/site.json
trap 'printf "\\nRECOVERY_HINT=%s\\n" "${{RECOVERY_HINT:-}}" >&2' EXIT
assert_owner() {{ :; }}; sleep() {{ :; }}; h() {{ return 3; }}
restore_capacity_qualify() {{ echo restore-capacity >> "$GSJ_WORK/actions"; }}
read_installed() {{ echo read-installed >> "$GSJ_WORK/actions"; : > "$GSJ_WORK/installed.json"; }}
capacity_qualify() {{ echo capacity >> "$GSJ_WORK/actions"; }}
stage_operation_config() {{ echo staged >> "$GSJ_WORK/actions"; }}
helm_application_prepare() {{ echo prepared >> "$GSJ_WORK/actions"; }}
helm_apply''')
    assert result.returncode == 1 and 'Helm provisioning failed' in result.stderr, result.stderr
    actions = (work / 'actions').read_text().split()
    if kind == 'restore':
        assert actions == ['staged', 'prepared']
        assert _hint(result) == f'repair --operation {operation} --config /synthetic/site.json --non-interactive after fixing the cause'
    else:
        assert actions == ['read-installed', 'staged', 'prepared'] and _hint(result) == ''


@pytest.mark.parametrize('kind', ['restore', 'install', 'upgrade'])
@pytest.mark.parametrize('helm_major,takes_over', [(4, True), (3, False)])
def test_helm_apply_takes_over_fields_a_restore_created_with_kubectl(runtime, kind, helm_major, takes_over):
    # A restore re-creates the archived chart objects with kubectl create; the
    # next upgrade that changes one of their fields must take it over, not refuse.
    #
    # That take-over is `--force-conflicts`, and it is a HELM 4 concern only.
    # Helm 4 applies server-side and refuses a field another manager owns
    # (measured: the upgrade fails with a conflict without the flag, succeeds
    # with it). Helm 3 applies client-side, where the conflict does not arise
    # and the flag does not exist -- passing it there is `unknown flag`. So the
    # dialect is chosen from the installed helm's own major, and this asserts
    # BOTH halves: the flag present on 4, absent on 3.
    run, _, work = runtime
    operation = 'd' * 24
    put(work / 'operation.json', {'operation': operation, 'kind': kind, 'target': 'synthetic-release', 'status': 'applying'})
    result = run(f'''OPERATION={operation}; CONFIG=/synthetic/site.json; GSJ_PAYLOAD=/synthetic/payload
assert_owner() {{ :; }}; sleep() {{ :; }}; h() {{ printf '%s\\n' "$@" > "$GSJ_WORK/helm-args"; return 3; }}
restore_capacity_qualify() {{ :; }}; read_installed() {{ : > "$GSJ_WORK/installed.json"; }}
capacity_qualify() {{ :; }}; stage_operation_config() {{ :; }}; helm_application_prepare() {{ :; }}
client_version() {{ printf '{helm_major}.2.2'; }}; helm_dialect
helm_apply''')
    assert 'Helm provisioning failed' in result.stderr, result.stderr
    args = (work / 'helm-args').read_text().splitlines()
    assert args[:2] == ['upgrade', '--install']
    assert ('--force-conflicts' in args) is takes_over, args
    # the Helm 4-only wait spelling must never reappear on either major
    assert not any(a.startswith('--wait=') for a in args), args


@pytest.mark.parametrize('program', ['corrected', 'source'])
@pytest.mark.parametrize('name', ['trust', 'scripts'])
def test_restore_repair_compares_the_rewritten_trust_and_chart_scripts_by_identity_only(failed_helm, program, name):
    # secret_inputs rewrites the trust bundle and the failed revision's chart
    # applied its scripts: their bytes may differ, their restored identity may not.
    key = 'ConfigMap/synthetic-release-' + name
    m = failed_helm(program); cluster = json.loads(m['state'].read_text())
    cluster['resources'][key]['data'] = {'rewritten': 'by secret_inputs or the failed revision'}; put(m['state'], cluster)
    admitted = _run(m, program=program)
    assert admitted.returncode == 80, admitted.stderr
    m = failed_helm(program); cluster = json.loads(m['state'].read_text())
    cluster['resources'][key]['metadata']['uid'] = 'replacement'; put(m['state'], cluster)
    refused = _run(m, program=program)
    assert refused.returncode not in (0, 80) and FRESH in refused.stderr, refused.stderr
    assert not any(call[0] in MUTATIONS for call in json.loads(m['state'].read_text())['calls'])


@pytest.mark.parametrize('change,admitted', [(None, True), ('prune-v1', True), ('prune-v2', False), ('v1-data', False)])
def test_restore_repair_admits_only_the_history_helm_prunes(failed_helm, change, admitted):
    # Restored v1 superseded and v2 deployed, the failed attempt at v3. Helm
    # prunes the oldest revisions but never the last deployed one.
    m = failed_helm('pruned'); cluster = json.loads(m['state'].read_text()); r = cluster['resources']
    if change == 'prune-v1': del r['Secret/sh.helm.release.v1.synthetic-release.v1']
    if change == 'prune-v2': del r['Secret/sh.helm.release.v1.synthetic-release.v2']
    if change == 'v1-data': r['Secret/sh.helm.release.v1.synthetic-release.v1']['data']['release'] = 'Y2hhbmdlZA=='
    put(m['state'], cluster)
    result = _run(m, program='source')
    if admitted:
        assert result.returncode == 80, result.stderr
        assert json.loads((m['work'] / 'operation.json').read_text())['helm_application_history'] == [{**FAILED, 'revision': 3}]
        return
    assert result.returncode not in (0, 80) and FRESH in result.stderr, result.stderr
    assert not any(call[0] in MUTATIONS for call in json.loads(m['state'].read_text())['calls'])


def test_an_unreadable_restored_object_is_retryable_not_drift(failed_helm):
    # A failed API read is not evidence of drift: repair names itself again.
    m = failed_helm(); cluster = json.loads(m['state'].read_text())
    cluster['fail_get'] = 'ConfigMap/synthetic-release-provisioned'; put(m['state'], cluster); local = _local(m)
    result = _run(m)
    assert result.returncode not in (0, 80), result.stderr
    assert f"restore evidence could not be read; rerun repair --operation {m['operation']}" in result.stderr
    assert FRESH not in result.stderr and _hint(result).startswith(f"repair --operation {m['operation']}")
    after = json.loads(m['state'].read_text())
    assert after['lease'] == cluster['lease'] and not any(call[0] in MUTATIONS for call in after['calls'])
    assert _local(m) == local


@pytest.mark.parametrize('program,message', [('corrected', 'restore program evidence directory is unavailable'), ('source', FRESH)])
def test_restore_repair_refuses_a_symlinked_restore_evidence_directory(failed_helm, program, message):
    m = failed_helm(program); saved = m['saved']
    moved = saved.with_name(saved.name + '-real'); saved.rename(moved); saved.symlink_to(moved)
    local = _local(m)
    result = _run(m, program=program)
    assert result.returncode not in (0, 80) and message in result.stderr, result.stderr
    assert not any(call[0] in MUTATIONS for call in json.loads(m['state'].read_text())['calls'])
    assert _local(m) == local


def test_a_symlinked_operation_record_is_refused_before_program_selection(failed_helm):
    m = failed_helm(); record = m['work'] / 'operation.json'
    value = json.loads(record.read_text()); value['status'] = 'initializing'; put(record, value)
    real = m['work'] / 'operation-real.json'; record.rename(real); record.symlink_to(real)
    result = _run(m, command='resume', program='source', entry='resume_operation')
    assert result.returncode not in (0, 80, 81), result.stderr
    assert 'operation metadata is not ordinary state' in result.stderr
    assert not any(call[0] in MUTATIONS for call in json.loads(m['state'].read_text())['calls'])


def test_another_program_names_the_source_installer_for_resume_without_a_transition(failed_helm):
    m = failed_helm('source')
    result = _run(m, command='resume', program='corrected', entry='resume_operation')
    assert result.returncode not in (0, 80, 81), result.stderr
    assert 'resume must use the exact source installer of this restore' in result.stderr
    assert not any(call[0] in MUTATIONS for call in json.loads(m['state'].read_text())['calls'])


# A restore's terminal stop names a fresh restore in another context that a
# command can run: restore admits only the archive's
# exact source release, so every one keeps that installer. A consent code names
# its site setting; a blocked embedding model names an earlier archive.
SOURCE = 'its verified archive with the exact source installer'
ALLOW_UPDATE = SOURCE + ', from a recovery site that sets corpus.allow_update=true,'
EARLIER_ARCHIVE = "an earlier verified archive of this deployment with that archive's exact source installer"
INSTALL_REPAIR = 'repair --operation {op} --config /secure/site.json --non-interactive'
INSTALL_REPAIR_TO = 'repair --operation {op} --to VERSION with a corrected signed release'
# stop: (restore's fresh restore, restore reason, unchanged install/upgrade hint)
TERMINAL_STOPS = {
    'initializer_stop terminal-budget-exhausted': (SOURCE, '(gsj-corpus:terminal-budget-exhausted)', INSTALL_REPAIR),
    'initializer_stop deadline-exceeded': (SOURCE, '(gsj-corpus:deadline-exceeded)', INSTALL_REPAIR),
    'initializer_stop checkpoint-identity-mismatch': (SOURCE, '(gsj-corpus:checkpoint-identity-mismatch)', INSTALL_REPAIR),
    'initializer_stop corpus:source-verification-failed': (SOURCE, '(gsj-corpus:source-verification-failed)', INSTALL_REPAIR),
    'verification_bot_terminal': (SOURCE, 'bot contract-hook check failed on every bounded attempt',
                                  'repair --operation {op} (with --to VERSION for a corrected signed release)'),
    'initializer_stop copy:source-verification-failed': (SOURCE, '(gsj-copy:source-verification-failed)',
                                                         'repair --operation {op} --to VERSION with a verified signed release'),
    'initializer_stop manifest-mismatch': (SOURCE, '(gsj-corpus:manifest-mismatch)', INSTALL_REPAIR_TO),
    'initializer_stop copy:manifest-mismatch': (SOURCE, '(gsj-copy:manifest-mismatch)', INSTALL_REPAIR_TO),
    'initializer_stop core-mismatch': (SOURCE, '(gsj-corpus:core-mismatch)', INSTALL_REPAIR_TO),
    'initializer_stop invalid-settings': (SOURCE, '(gsj-corpus:invalid-settings)', INSTALL_REPAIR_TO),
    'initializer_stop corpus-update-required': (
        ALLOW_UPDATE, 'corpus.allow_update is false; the verified archive is its pre-update backup',
        INSTALL_REPAIR + ' after setting corpus.allow_update=true'),
    'initializer_stop model-change-blocked': (
        EARLIER_ARCHIVE, "This archive's decision index does not match its source release's embedding model",
        'the previous release installer or restore its verified backup'),
}


def test_every_terminal_initializer_code_has_a_restore_recovery():
    from tests.test_installer import TERMINAL_CODES
    codes = {stop.split(' ', 1)[1].split(':')[-1] for stop in TERMINAL_STOPS if stop.startswith('initializer_stop ')}
    assert codes == set(TERMINAL_CODES)


@pytest.mark.parametrize('kind', ['restore', 'install', 'upgrade'])
@pytest.mark.parametrize('stop', list(TERMINAL_STOPS))
def test_a_terminal_stop_names_its_recovery(runtime, kind, stop):
    # repair refuses a restore once its Helm revision completed; resume repeats the stop.
    run, _, work = runtime; operation = 'a' * 24
    fresh, reason, hint = TERMINAL_STOPS[stop]
    put(work / 'operation.json', {'operation': operation, 'kind': kind, 'target': 'synthetic-release', 'status': 'initializing'})
    result = run(f'''GSJ_WORK="$TEST_WORK/throwaway"; mkdir -p "$GSJ_WORK"
OPERATION={operation}; CONFIG=/secure/site.json; LEASE_ACQUIRED=true
install_exit_traps
{stop}
''')
    assert result.returncode != 0
    if kind == 'restore':
        assert reason in result.stderr and 'stay retained for inspection' in result.stderr, result.stderr
        assert 'repair --operation' not in result.stderr and 'Use resume' not in result.stderr, result.stderr
        # The message and RECOVERY_HINT name the same fresh restore, never a corrected release.
        assert f'; keep operation {operation} retained and restore {fresh} in {FRESH}\n' in result.stderr, result.stderr
        assert f'Use restore of {fresh} in {FRESH}; keep operation {operation} retained.' in result.stderr, result.stderr
        assert 'corrected' not in result.stderr, result.stderr
        if fresh != SOURCE:
            assert f'restore {SOURCE} in' not in result.stderr and f'restore of {SOURCE} in' not in result.stderr
    else:
        assert f'Use {hint.format(op=operation)}.' in result.stderr, result.stderr
        assert FRESH not in result.stderr and 'stay retained for inspection' not in result.stderr, result.stderr


@pytest.mark.parametrize('kind', ['restore', 'upgrade'])
@pytest.mark.parametrize('code', ['chroma-unavailable', 'copy:writer-busy', 'internal-error'])
def test_a_transient_initializer_code_is_retried_by_the_pod_for_every_operation(runtime, kind, code):
    # Not terminal: the Pod retries it, so a restore names no fresh restore for it.
    run, _, work = runtime
    put(work / 'operation.json', {'operation': 'a' * 24, 'kind': kind, 'target': 'synthetic-release', 'status': 'initializing'})
    result = run(f"OPERATION={'a' * 24}; CONFIG=/secure/site.json\ninitializer_stop {code}\n")
    assert result.returncode == 0, result.stderr
    assert 'the Pod retries it' in result.stderr, result.stderr
    assert FRESH not in result.stderr and 'restore of' not in result.stderr and 'stay retained' not in result.stderr


@pytest.mark.parametrize('program,damage,message', [
    ('corrected', 'pvc-receipt', 'restored claim synthetic-release-data has no readable create receipt'),
    ('source', 'pvc-receipt', 'restored claim synthetic-release-data has no readable create receipt'),
    ('corrected', 'checkpoint-pod', 'the restore checkpoint names no maintenance Pod'),
    ('source', 'checkpoint-pod', 'the restore checkpoint names no maintenance Pod'),
    ('source', 'checkpoint-claims', 'the restore checkpoint names no restored claims')])
def test_damaged_local_restore_evidence_names_the_fresh_restore(failed_helm, program, damage, message):
    # Rerunning repair cannot bring back local evidence: it refuses, it is not retried.
    m = failed_helm(program); work, saved = m['work'], m['saved']
    if damage == 'pvc-receipt': (saved / 'PersistentVolumeClaim' / 'synthetic-release-data' / 'receipt.json').unlink()
    else:
        checkpoint = json.loads((work / 'restoration.json').read_text())
        if damage == 'checkpoint-pod': del checkpoint['pod']
        else: del checkpoint['references']['PersistentVolumeClaim']
        put(work / 'restoration.json', checkpoint)
    cluster = json.loads(m['state'].read_text()); local = _local(m)
    result = _run(m, program=program)
    assert result.returncode not in (0, 80), result.stderr
    assert message in result.stderr and FRESH in result.stderr, result.stderr
    assert 'could not be read' not in result.stderr and 'jq:' not in result.stderr, result.stderr
    after = json.loads(m['state'].read_text())
    assert after['lease'] == cluster['lease'] and not any(call[0] in MUTATIONS for call in after['calls'])
    assert _local(m) == local


def _patch_cluster_on_renewal(m, resources):
    # start_renewal runs right after the Lease renewal: the change lands between
    # the first and the second evidence pass.
    put(m['work'] / 'renewal-patch.json', resources)
    return ('start_renewal() { jq --slurpfile p "$TEST_WORK/renewal-patch.json" \'.resources+=$p[0]\' "$TEST_KUBECTL_STATE" '
            '> "$TEST_WORK/renewed.json" && mv "$TEST_WORK/renewed.json" "$TEST_KUBECTL_STATE"; }')


@pytest.mark.parametrize('change', ['admin-token', 'foreign-history'])
def test_restore_repair_reproves_the_evidence_after_renewing_the_lease(failed_helm, change):
    m = failed_helm(); resources = json.loads(m['state'].read_text())['resources']; local = _local(m)
    (m['work'] / 'actual-target').unlink(missing_ok=True)  # left by the template's takeover run
    if change == 'admin-token':
        token = json.loads(json.dumps(resources['Secret/synthetic-release-admin-token'])); token['data']['token'] = 'Y2hhbmdlZA=='
        patch = {'Secret/synthetic-release-admin-token': token}
    else: patch = {'Secret/sh.helm.release.v1.synthetic-release.v6': _history(6, 'failed', 'foreign-history')}
    result = _run(m, extra=_patch_cluster_on_renewal(m, patch))
    assert result.returncode not in (0, 80), result.stderr
    assert FRESH in result.stderr and 'unbound variable' not in result.stderr, result.stderr
    assert 'helm_application_history' not in json.loads((m['work'] / 'operation.json').read_text())
    assert _local(m) == local and not (m['work'] / 'actual-target').exists()
    after = json.loads(m['state'].read_text())
    assert after['lease']['spec']['holderIdentity'] == m['operation']
    assert [call[0] for call in after['calls'] if call[0] in MUTATIONS] == ['replace']  # the renewal alone


def test_an_unreadable_renewed_lease_names_repair_again(failed_helm):
    m = failed_helm(); local = _local(m)
    (m['work'] / 'actual-target').unlink(missing_ok=True)  # left by the template's takeover run
    result = _run(m, extra='start_renewal() { lease_read() { return 23; }; }')
    assert result.returncode not in (0, 80), result.stderr
    assert f"the renewed operation Lease could not be read; rerun repair --operation {m['operation']}" in result.stderr
    assert FRESH not in result.stderr and _hint(result).startswith(f"repair --operation {m['operation']}")
    assert _local(m) == local and not (m['work'] / 'actual-target').exists()


@pytest.mark.parametrize('case', ['takeover-initializing', 'takeover-verifying', 'takeover-complete', 'complete', 'another-program'])
def test_restore_repair_refusals_name_the_command_that_continues(failed_helm, case):
    # Routed by phase first: no failed-revision wording once the revision
    # completed, and the command named is the one that owns the operation.
    program = 'source' if case == 'complete' else 'corrected'
    m = failed_helm(program); operation = m['operation']; extra = ''
    if case != 'complete': (m['saved'] / 'program-transition.json').unlink()
    if case.startswith('takeover'): extra = 'SOURCE_INSTALLER=' + shlex.quote(str(m['prior'] / 'gsj-install.sh'))
    record = json.loads((m['work'] / 'operation.json').read_text())
    record['status'] = {'takeover-initializing': 'initializing', 'takeover-verifying': 'verifying',
                        'takeover-complete': 'complete', 'complete': 'complete'}.get(case, record['status'])
    put(m['work'] / 'operation.json', record); cluster = json.loads(m['state'].read_text()); local = _local(m)
    result = _run(m, program=program, extra=extra)
    assert result.returncode not in (0, 80), result.stderr
    expected = {'takeover-initializing': f'completed; use resume --operation {operation} with its exact source installer',
                'takeover-verifying': f'completed; use resume --operation {operation} with its exact source installer',
                'takeover-complete': f'the restore is complete; use resume --operation {operation} with its exact source installer',
                'complete': f'the restore is complete; use resume --operation {operation} with this installer',
                'another-program': 'repair must use the exact source installer of this restore'}[case]
    assert expected in result.stderr, result.stderr
    assert 'failed application Helm revision' not in result.stderr and '--source-installer' not in result.stderr, result.stderr
    after = json.loads(m['state'].read_text())
    assert after['lease'] == cluster['lease'] and not any(call[0] in MUTATIONS for call in after['calls'])
    assert _local(m) == local


def test_a_program_receipt_names_the_restored_resources_repair_proves(failed_helm):
    # The corrected program's receipt lists the resources it proved at takeover.
    # A directory the source program saved outside that list is not its
    # evidence; each listed resource still needs its saved directory.
    m = failed_helm(); saved = m['saved']
    listed = {(r['kind'], r['name']) for r in json.loads((saved / 'program-transition.json').read_text())['restored_resources']}
    assert ('ConfigMap', 'synthetic-release-provisioned') in listed
    shutil.copytree(saved / 'ConfigMap' / 'synthetic-release-provisioned', saved / 'ConfigMap' / 'synthetic-release-unlisted')
    admitted = _run(m)
    assert admitted.returncode == 80, admitted.stderr
    m = failed_helm(); shutil.rmtree(m['saved'] / 'ConfigMap' / 'synthetic-release-provisioned'); local = _local(m)
    refused = _run(m)
    assert refused.returncode not in (0, 80), refused.stderr
    assert 'restored resource evidence is not ordinary state' in refused.stderr and FRESH in refused.stderr, refused.stderr
    assert not any(call[0] in MUTATIONS for call in json.loads(m['state'].read_text())['calls'])
    assert _local(m) == local
