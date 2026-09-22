"""Explicit hostPID fault injection, for the hand-run qualification against a
disposable cluster; never a deployment command."""
import hashlib
import json
from pathlib import Path
import re
import secrets
import subprocess
import tempfile
import time

from release import require, save

UUID = r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'
# Every runtime container of the application Pod, with its release image role.
TARGETS = {'agent-runner': 'runner', 'gsj-mcp': 'mcp', 'gsj-web': 'web'}


def helper_projection(pod):
    spec = pod['spec']
    require(len(spec.get('containers', [])) == 1 and not spec.get('initContainers')
            and not spec.get('ephemeralContainers'), 'helper must contain exactly one ordinary container')
    container = spec['containers'][0]
    return {'nodeName': spec.get('nodeName'), 'hostPID': spec.get('hostPID', False),
            'hostNetwork': spec.get('hostNetwork', False), 'hostIPC': spec.get('hostIPC', False),
            'shareProcessNamespace': spec.get('shareProcessNamespace', False),
            'automountServiceAccountToken': spec.get('automountServiceAccountToken'),
            'restartPolicy': spec.get('restartPolicy'), 'terminationGracePeriodSeconds': spec.get('terminationGracePeriodSeconds'),
            'imagePullSecrets': spec.get('imagePullSecrets', []), 'securityContext': spec.get('securityContext', {}),
            'volumes': spec.get('volumes', []),
            'container': {**{key: container.get(key) for key in ('name', 'image', 'imagePullPolicy', 'command', 'resources', 'securityContext')},
                          **{key: container.get(key, []) for key in ('args', 'env', 'envFrom', 'volumeMounts', 'ports')},
                          **{key: container.get(key) for key in ('lifecycle', 'livenessProbe', 'readinessProbe', 'startupProbe')},
                          'stdin': container.get('stdin', False), 'tty': container.get('tty', False)}}


def validate_receipt(receipt, images, pod_uid):
    require(receipt.get('schema') == 'gsj.hardfault/1' and receipt.get('status') == 'passed'
            and receipt.get('admission_dry_run') == 'passed'
            and receipt.get('helper_cleanup') == receipt.get('policy_cleanup') == 'exact-uid-observed-absent',
            'actual hardfault admission/death/cleanup evidence is incomplete')
    namespace = receipt.get('namespace', '')
    require(isinstance(namespace, str) and namespace.startswith('gsj-qualification-')
            and isinstance(receipt.get('namespace_uid'), str) and re.fullmatch(UUID, receipt['namespace_uid'])
            and isinstance(pod_uid, str) and re.fullmatch(UUID, pod_uid) and receipt.get('pod_uid') == pod_uid
            and isinstance(receipt.get('node'), str) and receipt['node'], 'hardfault namespace/Pod/node binding differs')
    plan = receipt.get('target_plan', {})
    require(plan.get('schema') == 'gsj.hardfault-process/1' and plan.get('pod_uid') == pod_uid, 'hardfault target Pod differs')
    targets = plan.get('targets', [])
    require(len(targets) == len(TARGETS) and {x.get('name') for x in targets} == set(TARGETS)
            and len({x.get('container_id') for x in targets}) == len(TARGETS),
            'hardfault requires every exact distinct target container')
    for target in targets:
        role = TARGETS[target['name']]
        require(re.fullmatch(r'[a-f0-9]{64}', target.get('container_id', ''))
                and target.get('image') == images[role]['repository'] + '@' + images[role]['digest']
                and type(target.get('restart_count')) is int and target['restart_count'] >= 0,
                'hardfault target image/runtime identity differs')
    actual = receipt.get('process', {})
    require(actual.get('schema') == 'gsj.hardfault-process-result/1' and actual.get('status') == 'passed'
            and actual.get('pod_uid') == pod_uid and actual.get('ancestor_namespace') is True, 'hardfault ancestor process proof missing')
    deaths = actual.get('targets', [])
    require(len(deaths) == len(TARGETS) and {x.get('name') for x in deaths} == set(TARGETS), 'hardfault death target count differs')
    for death in deaths:
        expected = next(t for t in targets if t['name'] == death['name'])
        nspid = death.get('namespace_pids', [])
        require(death.get('pod_uid') == pod_uid and death.get('container_id') == expected['container_id']
                and type(death.get('pid')) is int and death['pid'] > 1
                and len(nspid) >= 2 and nspid[0] == death['pid'] and nspid[-1] == 1
                and type(death.get('start_ticks')) is int and death['start_ticks'] > 0
                and death.get('signal_sent') == 'SIGKILL' and death.get('pidfd_exit_observed') is True,
                'hardfault exact process death was not proven')
    created = receipt.get('created', [])
    require(len(created) == 2 and {x.get('kind') for x in created} == {'Pod', 'NetworkPolicy'}
            and all(re.fullmatch(UUID, x.get('uid', '')) for x in created), 'hardfault owned helper identities are incomplete')
    helper = next(x for x in created if x['kind'] == 'Pod')
    policy = next(x for x in created if x['kind'] == 'NetworkPolicy')
    require(re.fullmatch(r'gsj-hardfault-[a-f0-9]{20}', helper.get('name', '')) and policy.get('name') == helper['name'],
            'hardfault helper names do not bind one operation')
    admitted = receipt.get('admitted_helper', {})
    require(admitted.get('uid') == helper['uid'] and admitted.get('namespace_uid') == receipt['namespace_uid']
            and admitted.get('name') == helper['name'], 'hardfault admitted helper identity differs')
    projection = admitted.get('projection', {})
    _, expected_helper = helper_resources(namespace, receipt['namespace_uid'], receipt['node'],
        images['web']['repository'] + '@' + images['web']['digest'], projection.get('imagePullSecrets', []), helper['name'].removeprefix('gsj-hardfault-'))
    require(projection == helper_projection(expected_helper), 'hardfault admitted privilege/image boundary differs')
    require(receipt.get('process_helper_sha256') == hashlib.sha256(Path(__file__).with_name('hardfault_process.py').read_bytes()).hexdigest(),
            'hardfault process helper differs from the qualified source')
    return True


def target_plan(pod, images):
    containers = {v['name']: v for v in pod['spec']['containers']}
    states = {v['name']: v for v in pod.get('status', {}).get('containerStatuses', [])}
    targets = []
    for name, role in TARGETS.items():
        expected = images[role]['repository'] + '@' + images[role]['digest']
        # registry.base relocates an image to <base>/<last path segment>@<same digest>.
        # The release pins the CONTENT; where it was pulled from is the site's business.
        relocated = '/' + images[role]['repository'].rsplit('/', 1)[-1] + '@' + images[role]['digest']
        actual = containers.get(name, {}).get('image') or ''
        require(actual == expected or actual.endswith(relocated), 'source image differs from exact target release')
        current = states.get(name, {})
        require(current.get('state', {}).get('running') and current.get('ready') is True,
                'fault requires every exact running ready container')
        match = re.fullmatch(r'containerd://([a-f0-9]{64})', current.get('containerID', ''))
        require(match is not None, 'fault requires an exact containerd runtime ID')
        targets.append({'name': name, 'container_id': match.group(1), 'image': expected,
                        'restart_count': current['restartCount']})
    require(len({t['container_id'] for t in targets}) == len(TARGETS), 'fault target runtime IDs are duplicated')
    return {'schema': 'gsj.hardfault-process/1', 'pod_uid': pod['metadata']['uid'], 'targets': targets}


def helper_resources(namespace, namespace_uid, node, image, pull_secrets, nonce):
    name = 'gsj-hardfault-' + nonce
    labels = {'gsj.io/hardfault': nonce, 'app.kubernetes.io/managed-by': 'gsj-ci-hardfault'}
    metadata = {'name': name, 'namespace': namespace, 'labels': labels,
                'annotations': {'gsj.io/namespace-uid': namespace_uid}}
    policy = {'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy', 'metadata': metadata,
              'spec': {'podSelector': {'matchLabels': {'gsj.io/hardfault': nonce}},
                       'policyTypes': ['Ingress', 'Egress'], 'ingress': [], 'egress': []}}
    pod = {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': metadata,
           'spec': {'nodeName': node, 'hostPID': True, 'hostNetwork': False,
                    'automountServiceAccountToken': False, 'restartPolicy': 'Never',
                    'terminationGracePeriodSeconds': 1, 'imagePullSecrets': pull_secrets,
                    'securityContext': {'runAsUser': 0, 'runAsGroup': 0, 'seccompProfile': {'type': 'RuntimeDefault'}},
                    'containers': [{'name': 'injector', 'image': image, 'imagePullPolicy': 'IfNotPresent',
                                    'command': ['python', '-B', '-c', 'import time; time.sleep(180)'],
                                    'resources': {'requests': {'cpu': '10m', 'memory': '32Mi'},
                                                  'limits': {'cpu': '100m', 'memory': '64Mi'}},
                                    'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True,
                                                        'capabilities': {'drop': ['ALL'], 'add': ['KILL']}}}]}}
    return policy, pod


def inject(*, context, namespace, namespace_uid, release, pod, images, report_path, timeout=90):
    """Kill the original exact containers; return proof. Caller verifies restart/application state."""
    require(namespace.startswith('gsj-qualification-') and namespace != 'gsj', 'explicit disposable qualification namespace required')
    require(re.fullmatch(UUID, namespace_uid), 'exact disposable namespace UID required')
    require(pod['metadata']['namespace'] == namespace and pod['metadata'].get('labels', {}).get('app.kubernetes.io/instance') == release,
            'application Pod does not belong to the explicit qualification release')
    require(not pod['metadata'].get('deletionTimestamp'), 'target Pod is terminating')
    plan = target_plan(pod, images)
    node = pod['spec']['nodeName']; name = pod['metadata']['name']
    report_path = Path(report_path)
    require(not report_path.exists(), 'fault receipt already exists; do not replay silently')
    report = {'schema': 'gsj.hardfault/1', 'status': 'preparing', 'namespace': namespace,
              'namespace_uid': namespace_uid, 'pod_name': name, 'pod_uid': plan['pod_uid'], 'node': node,
              'target_plan': plan, 'helper_cleanup': 'not-created', 'policy_cleanup': 'not-created'}
    report_path.parent.mkdir(parents=True, exist_ok=True)
    save(report_path, report)
    owned = []
    stage = 'target-preflight'

    def k(*args, data=None):
        result = subprocess.run(['kubectl', '--context', context, '--namespace', namespace, *args],
                                input=data, capture_output=True, text=True, timeout=timeout)
        if result.returncode:
            raise RuntimeError('hardfault Kubernetes operation failed')
        return result.stdout

    def check_target():
        actual_ns = json.loads(k('get', 'namespace', namespace, '-o', 'json'))
        require(actual_ns['metadata']['uid'] == namespace_uid, 'qualification namespace UID changed')
        current = json.loads(k('get', 'pod', name, '-o', 'json'))
        require(current['metadata']['uid'] == plan['pod_uid'] and current['spec']['nodeName'] == node
                and not current['metadata'].get('deletionTimestamp'), 'fault target Pod/node identity changed')
        require(target_plan(current, images) == plan, 'fault target containers changed before injection')

    try:
        check_target()
        nonce = secrets.token_hex(10)
        policy, helper = helper_resources(namespace, namespace_uid, node,
                                          images['web']['repository'] + '@' + images['web']['digest'],
                                          pod['spec'].get('imagePullSecrets', []), nonce)
        # Admission support is measured without creating or weakening PSA/RBAC.
        for item in (policy, helper):
            stage = 'admission-' + item['kind']
            k('create', '--dry-run=server', '-f', '-', '-o', 'json', data=json.dumps(item))
        report['admission_dry_run'] = 'passed'; save(report_path, report)
        for item in (policy, helper):
            stage = 'create-' + item['kind']
            created = json.loads(k('create', '-f', '-', '-o', 'json', data=json.dumps(item)))
            owned.append((item['kind'], created['metadata']['name'], created['metadata']['uid']))
            report['created'] = [dict(kind=a, name=b, uid=c) for a, b, c in owned]; save(report_path, report)
        stage = 'helper-readiness'
        k('wait', '--for=condition=Ready', 'pod/' + helper['metadata']['name'], '--timeout=' + str(timeout) + 's')
        actual = json.loads(k('get', 'pod', helper['metadata']['name'], '-o', 'json'))
        stage = 'admitted-helper-identity'
        require(actual['metadata']['uid'] == owned[-1][2] and not actual['metadata'].get('deletionTimestamp')
                and helper_projection(actual) == helper_projection(helper), 'admitted helper identity or privilege/image boundary changed')
        report['admitted_helper'] = {'uid': actual['metadata']['uid'], 'name': actual['metadata']['name'],
                                    'namespace_uid': namespace_uid, 'projection': helper_projection(actual)}
        stage = 'final-target-preflight'
        check_target()
        script = 'SETTINGS=' + repr(plan) + '\n' + Path(__file__).with_name('hardfault_process.py').read_text()
        report['process_helper_sha256'] = hashlib.sha256(Path(__file__).with_name('hardfault_process.py').read_bytes()).hexdigest()
        save(report_path, report)
        stage = 'pidfd-signal-and-death'
        output = k('exec', '-i', helper['metadata']['name'], '-c', 'injector', '--', 'python', '-B', '-', data=script)
        result = json.loads(output)
        require(result.get('status') == 'passed' and result.get('pod_uid') == plan['pod_uid']
                and {x['container_id'] for x in result['targets']} == {x['container_id'] for x in plan['targets']}
                and all(x.get('signal_sent') == 'SIGKILL' and x.get('pidfd_exit_observed') is True for x in result['targets']),
                'actual target process death was not proven')
        report.update(status='passed', process=result)
    except Exception as error:
        report.update(status='failed', failure_stage=stage, error_type=type(error).__name__)
        raise
    finally:
        cleanup_errors = []
        for kind, owned_name, uid in reversed(owned):
            try:
                group = '/api/v1' if kind == 'Pod' else '/apis/networking.k8s.io/v1'
                plural = 'pods' if kind == 'Pod' else 'networkpolicies'
                options = {'apiVersion': 'v1', 'kind': 'DeleteOptions', 'preconditions': {'uid': uid}, 'gracePeriodSeconds': 0}
                with tempfile.NamedTemporaryFile(mode='w', prefix='gsj-hardfault-delete-', suffix='.json') as file:
                    json.dump(options, file); file.flush()
                    k('delete', '--raw', f'{group}/namespaces/{namespace}/{plural}/{owned_name}', '-f', file.name)
                deadline = time.monotonic() + timeout
                while True:
                    remaining = k('get', kind, owned_name, '--ignore-not-found', '-o', 'json')
                    if not remaining.strip(): break
                    require(json.loads(remaining)['metadata']['uid'] == uid, 'cleanup refuses a replacement object')
                    require(time.monotonic() < deadline, 'owned helper absence was not observed')
                    time.sleep(.2)
                report['helper_cleanup' if kind == 'Pod' else 'policy_cleanup'] = 'exact-uid-observed-absent'
            except Exception as error:
                cleanup_errors.append(type(error).__name__)
        if cleanup_errors:
            report.update(status='failed', cleanup_errors=cleanup_errors)
        save(report_path, report)
    require(report['status'] == 'passed', 'hardfault helper cleanup failed; inspect retained receipt')
    validate_receipt(report, images, plan['pod_uid'])
    return report
