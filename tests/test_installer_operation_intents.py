"""Real Bash, immutable local intents, and a persistent synthetic Lease API."""
import json

import pytest

from tests.test_installer import _release, runtime


def setup(runtime):
    run, state, work = runtime
    payload = work / 'payload'; payload.mkdir()
    (payload / 'release.json').write_text(json.dumps(_release()))
    def invoke(body, **env):
        return run('GSJ_PAYLOAD="$TEST_PAYLOAD"\n' + body, TEST_PAYLOAD=str(payload), **env)
    return invoke, state, work, payload


def interrupted(runtime, gap='promotion'):
    invoke, state, work, payload = setup(runtime)
    if gap == 'promotion':
        body = 'recover_operation_intent() { exit 79; }; acquire'
    else:
        body = '''k() {
 kubectl --context "$CONTEXT" --namespace "$NAMESPACE" "$@"
 if [[ $1 == create ]]; then exit 79; fi
}
acquire'''
    result = invoke(body)
    assert result.returncode == 79, result.stderr
    cluster = json.loads(state.read_text())
    operation = cluster['lease']['spec']['holderIdentity']
    directory = work / 'operation-intents' / operation
    assert directory.is_dir() and (directory / 'intent.json').is_file()
    assert not (work / 'operation.json').exists()
    return invoke, state, work, payload, operation, directory


@pytest.mark.parametrize('gap', ['promotion', 'lease-response'])
def test_lost_response_preserves_exact_recoverable_intent(runtime, gap):
    invoke, state, work, _, operation, directory = interrupted(runtime, gap)
    before = json.loads(state.read_text())['lease']
    result = invoke('recover_operation_intent "$ID"', ID=operation)
    assert result.returncode == 0, result.stderr
    assert not (work / 'operation.json').exists()
    assert json.loads(state.read_text())['lease'] == before
    assert (work / 'recovered-site.json').read_bytes() == (directory / 'site.json').read_bytes()
    assert json.loads((work / 'recovered-operation.json').read_text())['operation'] == operation
    result = invoke('''OPERATION="$ID"; LEASE_ACQUIRED=true
LEASE_RESOURCE_VERSION=$(lease_read | jq -r .metadata.resourceVersion)
recover_operation_intent "$ID" promote''', ID=operation)
    assert result.returncode == 0, result.stderr
    assert json.loads((work / 'operation.json').read_text())['operation'] == operation
    assert (work / 'site.pending.json').read_bytes() == (directory / 'site.json').read_bytes()


@pytest.mark.parametrize('fault', ['namespace', 'release', 'site', 'values', 'manifest', 'intent', 'holder',
                                  'annotation', 'acquire-time', 'active-other', 'later-phase', 'stale', 'cas', 'not-acquired'])
def test_recovery_refuses_drift_without_canonical_writes(runtime, fault):
    invoke, state, work, payload, operation, directory = interrupted(runtime)
    cluster = json.loads(state.read_text())
    prefix = ''
    if fault == 'namespace': cluster['namespace_uid'] = 'replacement-namespace'
    if fault == 'release': prefix = 'RELEASE=different; '
    if fault == 'site': (work / 'site.json').write_text('{}')
    if fault == 'values': (work / 'values.pending.json').write_text('{"changed":true}')
    if fault == 'manifest': (payload / 'release.json').write_text('{}')
    if fault == 'intent': (directory / 'values.json').write_text('{"changed":true}')
    if fault == 'holder': cluster['lease']['spec']['holderIdentity'] = 'f' * 24
    if fault == 'annotation': cluster['lease']['metadata']['annotations'] = {}
    if fault == 'acquire-time': cluster['lease']['spec']['acquireTime'] = '2000-01-01T00:00:00.000000Z'
    if fault == 'stale': cluster['lease']['spec']['renewTime'] = '2000-01-01T00:00:00.000000Z'
    if fault in ('active-other', 'later-phase'):
        record = {'operation': operation if fault == 'later-phase' else 'f' * 24,
                  'target': 'synthetic-release', 'kind': 'install', 'status': 'initializing'}
        (work / 'operation.json').write_text(json.dumps(record))
    state.write_text(json.dumps(cluster))
    before = {name: (work / name).read_bytes() if (work / name).exists() else None
              for name in ('operation.json', 'site.pending.json', 'values.pending.json')}
    script = '''OPERATION="$ID"; LEASE_ACQUIRED=true
LEASE_RESOURCE_VERSION=$(lease_read | jq -r .metadata.resourceVersion)
'''
    if fault == 'cas': script += 'LEASE_RESOURCE_VERSION=999\n'
    if fault == 'not-acquired': script += 'LEASE_ACQUIRED=false\n'
    result = invoke(script + prefix + 'recover_operation_intent "$ID" promote', ID=operation)
    assert result.returncode != 0
    assert json.loads(state.read_text())['lease'] == cluster['lease']
    assert {name: (work / name).read_bytes() if (work / name).exists() else None for name in before} == before


@pytest.mark.parametrize('prior', ['complete', 'backup-complete', 'abandoned', 'owned'])
def test_promotion_only_reconciles_allowed_canonical_prefixes(runtime, prior):
    # 'abandoned' is the state `abandon` leaves behind, and a real install run
    # found the guard refusing it: the verb freed the Lease and the canonical
    # record went on blocking every retry ("another active operation or later
    # phase owns canonical state"), so a recovery verb left nothing recoverable.
    # Like 'complete'/'backup-complete' it carries a FOREIGN operation id here,
    # which is the real case - the abandoned record named the superseded release
    # while the retry carried a new one.
    invoke, state, work, _, operation, _ = interrupted(runtime)
    (work / 'operation.json').write_text(json.dumps({'operation': operation if prior == 'owned' else 'f' * 24,
                                                   'target': 'synthetic-release', 'kind': 'install', 'status': prior}))
    result = invoke('''OPERATION="$ID"; LEASE_ACQUIRED=true
LEASE_RESOURCE_VERSION=$(lease_read | jq -r .metadata.resourceVersion)
recover_operation_intent "$ID" promote''', ID=operation)
    assert result.returncode == 0, result.stderr
    assert json.loads((work / 'operation.json').read_text())['operation'] == operation


def test_competing_intents_never_write_canonical_or_replace_each_other(runtime):
    invoke, state, work, _ = setup(runtime)
    result = invoke('''OPERATION=aaaaaaaaaaaaaaaaaaaaaaaa; create_operation_intent '{}' '2026-01-01T00:00:00.000000Z'
OPERATION=bbbbbbbbbbbbbbbbbbbbbbbb; create_operation_intent '{}' '2026-01-01T00:00:00.000000Z' ''')
    assert result.returncode == 0, result.stderr
    intents = work / 'operation-intents'
    assert {p.name for p in intents.iterdir()} == {'a' * 24, 'b' * 24}
    before = {str(p.relative_to(intents)): p.read_bytes() for p in intents.rglob('*') if p.is_file()}
    result = invoke("OPERATION=aaaaaaaaaaaaaaaaaaaaaaaa; create_operation_intent '{}' '2026-01-01T00:00:00.000000Z'")
    assert result.returncode != 0
    assert before == {str(p.relative_to(intents)): p.read_bytes() for p in intents.rglob('*') if p.is_file()}
    assert not (work / 'operation.json').exists()
    assert json.loads(state.read_text())['lease'] is None


def test_restore_intent_preserves_archive_identity_without_credentials(runtime):
    invoke, _, work, _ = setup(runtime)
    archive = work / 'snapshot.enc'
    for suffix in ('', '.resources.enc', '.json'): (work / (archive.name + suffix)).write_bytes(b'synthetic encrypted archive')
    result = invoke('COMMAND=restore; ARCHIVE="$INPUT_ARCHIVE"; acquire', INPUT_ARCHIVE=str(archive))
    assert result.returncode == 0, result.stderr
    operation = json.loads((work / 'operation.json').read_text())['operation']
    intent = json.loads((work / 'operation-intents' / operation / 'intent.json').read_text())
    assert intent['record']['kind'] == 'restore' and intent['archive']['path'] == str(archive)
    assert set(intent['archive']) == {'path', 'sha256', 'resources_sha256', 'metadata_sha256'}
    assert 'synthetic encrypted archive' not in json.dumps(intent)
