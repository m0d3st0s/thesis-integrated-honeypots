#!/usr/bin/env python3
"""Configure, check, run, and report a node-local honeypot workspace."""
import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from report_time import day_window, reporting_zone

PROJECT = Path(__file__).resolve().parent


def now():
    return datetime.now(timezone.utc).isoformat()


def read(path):
    return json.loads(Path(path).read_text())


def write(path, value):
    path = Path(path)
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    temporary.replace(path)


def call(command, **kwargs):
    return subprocess.run(command, check=True, text=True, **kwargs)


def output(command, **kwargs):
    return call(command, capture_output=True, timeout=60, **kwargs).stdout


def name(value, release=False):
    pattern = r'[a-z0-9][a-z0-9-]{1,18}[a-z0-9]' if release else r'[a-z0-9](?:[a-z0-9-]{0,51}[a-z0-9])?'
    if not re.fullmatch(pattern, value):
        raise ValueError('Invalid ' + ('3–20 character release' if release else 'Kubernetes name') + ': ' + value)
    return value


def root_path(value):
    path = Path(value).expanduser()
    if not path.is_absolute() or '..' in path.parts or len(path.parts) < 4:
        raise ValueError('Use a dedicated absolute storage root: ' + str(path))
    return path.resolve()


def initialize(args):
    zone = getattr(args, 'timezone', 'UTC')
    reporting_zone(zone)
    network = ipaddress.IPv4Network(args.network, strict=True)
    scanner = ipaddress.IPv4Address(args.scanner_ip)
    excludes = {scanner, *(ipaddress.IPv4Address(ip) for ip in args.exclude)}
    if any(ip not in network for ip in excludes):
        raise ValueError('Scanner and exclusions must be inside the authorized network.')
    name(args.namespace)
    name(args.mixed_release, True)
    name(args.conpot_release, True)
    if args.mixed_release == args.conpot_release:
        raise ValueError('Mixed and Conpot releases must have distinct names.')
    if not re.fullmatch(r'[A-Za-z0-9_.:-]+', args.interface):
        raise ValueError('Invalid interface name.')
    if not args.node_hostname.strip():
        raise ValueError('Node hostname label is required.')
    state, logs = root_path(args.state_root), root_path(args.log_root)
    if state == logs or state in logs.parents or logs in state.parents:
        raise ValueError('State and log roots must not overlap.')
    endpoint = urllib.parse.urlsplit(args.honeychart_endpoint)
    if endpoint.scheme not in ('http', 'https') or not endpoint.hostname or endpoint.username or endpoint.password:
        raise ValueError('Use an HTTP(S) HoneyChart endpoint without embedded credentials.')
    kube = args.kubeconfig.expanduser().resolve(strict=True)
    if not kube.is_file():
        raise ValueError('Kubeconfig must be a file.')
    # Clone recipe settings, not the original lab's addresses or controlled-test labels.
    scan = read(PROJECT / 'config/lab-scan.json')
    scan.update(network=str(network), interface=args.interface, scanner_ip=str(scanner),
                exclude_ips=[str(ip) for ip in sorted(excludes)])
    deployment = read(PROJECT / 'config/lab-deployment.json')
    deployment.update(namespace=args.namespace, log_root=str(logs))
    for mapping in deployment['mappings']:
        mapping['release'] = args.conpot_release if mapping['honeypot'] == 'conpot' else args.mixed_release
    pins = (PROJECT / 'image-pins.yaml').read_bytes()
    runtime = dict(schema_version=1, honeychart_endpoint=args.honeychart_endpoint,
                   state_root=str(state), node_hostname=args.node_hostname, image_pins='image-pins.yaml')
    workspace = args.workspace.expanduser().resolve()
    workspace.mkdir(parents=True, exist_ok=False)
    for directory in ('runs', 'reports', 'labels'):
        (workspace / directory).mkdir()
    for filename, data in (('scan.json', scan), ('deployment.json', deployment), ('runtime.json', runtime)):
        write(workspace / filename, data)
    (workspace / 'image-pins.yaml').write_bytes(pins)
    (workspace / 'catalog.json').write_bytes((PROJECT / 'config/service-catalog.json').read_bytes())
    (workspace / 'labels/mixed.txt').write_text('')
    write(workspace / 'labels/conpot.json', dict(schema_version=1, events=[]))
    identity = uuid.uuid4().hex
    write(workspace / 'workspace.json', dict(schema_version=1, identity=identity, kubeconfig=str(kube),
          created_at=now(), project=str(PROJECT), timezone=zone,
          source_layout={'state_root': str(state), 'log_root': str(logs),
                         'namespace': args.namespace, 'mixed_release': args.mixed_release,
                         'conpot_release': args.conpot_release}, limitations=[
              'Run on the storage node; local filesystem access is required for reporting.',
              'Pinned recipes were verified on Linux amd64; other image architectures need validation.',
              'Do not reuse source IDs after replacing a database or resetting a log.']))
    print('Configured:', workspace)
    print('No network scan, storage initialization, or cluster changes performed.')


def load_workspace(path):
    workspace = path.expanduser().resolve(strict=True)
    config = read(workspace / 'workspace.json')
    if config.get('schema_version') != 1 or not re.fullmatch('[a-f0-9]{32}', config.get('identity', '')):
        raise ValueError('Invalid workspace metadata.')
    env = os.environ.copy()
    env['KUBECONFIG'] = config['kubeconfig']
    return workspace, config, env


@contextmanager
def locked(workspace):
    with (workspace / '.operation.lock').open('a') as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError('Another workspace operation is active.') from None
        yield


def doctor(workspace, config, env, *, scan_checks=True):
    """Read-only capability checks; never scans or changes cluster resources."""
    checks = []

    def check(label, action):
        try:
            detail = action()
            checks.append(dict(name=label, status='passed', detail=detail))
        except Exception as exc:
            checks.append(dict(name=label, status='failed', detail=str(exc)))

    def require(condition, message):
        if not condition:
            raise ValueError(message)
        return message

    check('Linux', lambda: require(platform.system() == 'Linux', 'Linux is required; no distribution/version whitelist.'))
    check('Python', lambda: require(sys.version_info >= (3, 10), 'Python 3.10+ is required.'))
    check('recipe storage permissions', lambda: require(os.geteuid() in (0, 1000) or 1000 in os.getgroups(),
            'Recipe storage uses UID/GID 1000 and mode 0750; reporting user needs UID 1000, group 1000, or root access.'))
    check('kubeconfig', lambda: require(Path(config['kubeconfig']).is_file() and os.access(config['kubeconfig'], os.R_OK),
                                        'Explicit kubeconfig must be readable by the current account.'))
    versions = {'kubectl': ['version', '--client', '-o', 'json'], 'helm': ['version', '--short']}
    if scan_checks:
        versions.update(nmap=['--version'], node=['--version'], npm=['--version'])
    for tool, arguments in versions.items():
        def version(tool=tool, arguments=arguments):
            value = output([tool] + arguments, env=env).strip()
            if tool == 'helm' and not value.startswith('v3.'):
                raise ValueError('This workflow expects Helm 3; observed: ' + value)
            return value
        check(tool, version)
    for tool in (('ip', 'sudo', 'bash', 'zip', 'unzip', 'python3') if scan_checks else ('ip', 'bash', 'python3')):
        check(tool + ' available', lambda tool=tool: require(shutil.which(tool) is not None, tool + ' must be on PATH.'))
    runtime, deployment, scan = [read(workspace / f) for f in ('runtime.json', 'deployment.json', 'scan.json')]
    namespace = deployment['namespace']
    check('namespace', lambda: json.loads(output(['kubectl', 'get', 'namespace', namespace, '-o', 'json'], env=env))['metadata']['name'])

    def node_check():
        nodes = json.loads(output(['kubectl', 'get', 'nodes', '-o', 'json'], env=env))['items']
        matches = [node for node in nodes if node['metadata'].get('labels', {}).get('kubernetes.io/hostname') == runtime['node_hostname']]
        require(len(matches) == 1, 'The hostname label must select exactly one node.')
        node = matches[0]
        require(not node['spec'].get('unschedulable'), 'Selected node must be schedulable.')
        require(any(c['type'] == 'Ready' and c['status'] == 'True' for c in node['status']['conditions']), 'Selected node must be Ready.')
        info = node['status']['nodeInfo']
        require(info['operatingSystem'] == 'linux' and info['architecture'] == 'amd64',
                'Current pinned recipes require validated Linux/amd64 images; validate other architectures before use.')
        addresses = json.loads(output(['ip', '-j', '-4', 'addr'], env=env))
        local = {a['local'] for device in addresses for a in device.get('addr_info', [])}
        require(any(a['type'] == 'InternalIP' and a['address'] in local for a in node['status']['addresses']),
                'Run this node-local workflow on its storage node, not a remote kubectl client.')
        return node['metadata']['name']
    check('storage node', node_check)

    def policy_check():
        policies = json.loads(output(['kubectl', 'get', 'networkpolicy', '-n', namespace, '-o', 'json'], env=env))['items']
        require(any(p['spec'].get('podSelector') == {} and 'Egress' in p['spec'].get('policyTypes', [])
                    and not p['spec'].get('egress') for p in policies),
                'Namespace needs an all-pod default-deny egress NetworkPolicy; see docs/user-guide.md.')
        require(not any(p['spec'].get('egress') for p in policies),
                'Additional egress allowances exist; review the namespace policy before using this workflow.')
        return 'Default-deny policy present. This check does not prove enforcement.'
    check('outbound policy configuration', policy_check)
    if scan_checks:
        def nmap_script():
            value = output(['nmap', '--script-help', 'modbus-discover'], env=env)
            require('modbus-discover' in value, 'Nmap must include the modbus-discover script.')
            return 'Modbus discovery script available; no scan performed.'
        check('Nmap Modbus script', nmap_script)
        def interface_check():
            addresses = json.loads(output(['ip', '-j', '-4', 'addr', 'show', 'dev', scan['interface']], env=env))
            return require(any(a.get('local') == scan['scanner_ip'] for d in addresses for a in d.get('addr_info', [])),
                           'Configured scanner IP must exist on the selected interface.')
        check('scan interface', interface_check)
        def honeychart():
            parsed = urllib.parse.urlsplit(runtime['honeychart_endpoint'])
            url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, '/', '', ''))
            with urllib.request.urlopen(url, timeout=10) as response:
                require(response.status == 200, 'HoneyChart root must respond HTTP 200.')
            return 'HTTP 200; chart-generation compatibility is checked during preparation.'
        check('HoneyChart', honeychart)
        check('image pins', lambda: require((workspace / runtime['image_pins']).is_file(), 'Pinned-image file must exist.'))
        for manifest in ('assets/conpot-modbus/manifest.json', 'assets/honeychart/manifest.json'):
            def assets(manifest=manifest):
                path = PROJECT / manifest
                data = read(path)
                for filename, digest in data['files'].items():
                    require(hashlib.sha256((path.parent / filename).read_bytes()).hexdigest() == digest,
                            'Asset checksum mismatch: ' + filename)
                return 'Verified bundled assets.'
            check(manifest, assets)
    return dict(schema_version=1, checked_at=now(), status='passed' if all(c['status'] == 'passed' for c in checks) else 'failed', checks=checks)


def print_checks(report):
    for check in report['checks']:
        print(check['status'].upper() + ': ' + check['name'] + ': ' + str(check['detail']))


def reporting_settings(workspace, config, prepared):
    """Derive sources from successful prepared requests, preserving workspace IDs."""
    runtime, deployment = read(prepared / 'runtime-config.json'), read(prepared / 'deployment-config.json')
    layout = config['source_layout']
    if (runtime['state_root'] != layout['state_root'] or deployment['log_root'] != layout['log_root']
            or deployment['namespace'] != layout['namespace']):
        raise ValueError('Source layout changed; use a new workspace and source identities.')
    for mapping in deployment['mappings']:
        expected = layout['conpot_release'] if mapping['honeypot'] == 'conpot' else layout['mixed_release']
        if mapping['release'] != expected:
            raise ValueError('Release mapping changed; use a new workspace.')
    result = dict(schema_version=2, kubeconfig=config['kubeconfig'], reports_root=str(workspace / 'reports'), timezone=config.get('timezone', 'UTC'))
    identity = config['identity']
    for request_path in sorted((prepared / 'requests').glob('*.request.json')):
        request = read(request_path)
        selected = set(request['honeypots']['names'])
        release = request['name']
        if not selected or selected - {'cowrie', 'dionaea', 'conpot'}:
            raise ValueError('Unsupported selection for reporting.')
        base = dict(deployment=release, namespace=deployment['namespace'])
        if selected & {'cowrie', 'dionaea'}:
            if 'mixed' in result or 'conpot' in selected:
                raise ValueError('Reporting supports one mixed release and one separate Conpot release.')
            logs = Path(deployment['log_root']) / release
            result['mixed'] = dict(base, services=sorted(selected),
                database=str(Path(runtime['state_root']) / release / 'dionaea/dionaea.sqlite'),
                database_id=identity + '-' + release + '-dionaea',
                cowrie_log=str(logs / 'cowrie/cowrie.json'), labels=str(workspace / 'labels/mixed.txt'),
                history_root=str(workspace / 'runs'))
        else:
            if 'conpot' in result:
                raise ValueError('Multiple Conpot releases are not supported by this report configuration.')
            result['conpot'] = dict(base, log=str(Path(deployment['log_root']) / release / 'conpot/conpot.json'),
                log_id=identity + '-' + release + '-conpot', labels=str(workspace / 'labels/conpot.json'))
    if not any(key in result for key in ('mixed', 'conpot')):
        raise ValueError('No reporting sources selected.')
    return result


def run_workspace(args, workspace, config, env):
    with locked(workspace):
        if args.mode == 'install' and (workspace / 'reporting.json').exists():
            raise ValueError('This workspace already has a deployment. Use upgrade; use a new workspace for new source identities.')
        if args.mode == 'upgrade' and not (workspace / 'reporting.json').exists():
            raise ValueError('Upgrade requires a successful install in this workspace; existing lab deployments are not auto-adopted.')
        run = Path(tempfile.mkdtemp(prefix='run-', dir=workspace / 'runs'))
        manifest = dict(schema_version=1, status='checking', mode=args.mode, started_at=now(), stages=[])
        write(run / 'workflow.json', manifest)
        try:
            checks = doctor(workspace, config, env)
            write(run / 'prerequisites.json', checks)
            print_checks(checks)
            if checks['status'] != 'passed':
                raise ValueError('Prerequisite checks failed; see ' + str(run / 'prerequisites.json'))
            if args.mode != 'prepare':
                # Credential refresh before scanning rather than a delayed surprise.
                call(['sudo', '-v'], env=env)
            command = [sys.executable, str(PROJECT / 'run_system.py'),
                       '--scan-config', str(workspace / 'scan.json'), '--catalog', str(workspace / 'catalog.json'),
                       '--deployment-config', str(workspace / 'deployment.json'), '--runtime-config', str(workspace / 'runtime.json'),
                       '--output', str(run / 'system'), '--mode', 'prepare']
            def stage(label, argv):
                record = dict(name=label, command=argv, started_at=now(), status='running')
                manifest['stages'].append(record)
                write(run / 'workflow.json', manifest)
                with (run / (label + '.log')).open('w') as log:
                    # Preserve output while streaming progress to the terminal.
                    process = subprocess.Popen(argv, env=env, stdout=subprocess.PIPE,
                                               stderr=subprocess.STDOUT, text=True)
                    try:
                        for line in process.stdout:
                            log.write(line)
                            log.flush()
                            print(line, end='', flush=True)
                        code = process.wait()
                    except BaseException:
                        process.terminate()
                        try:
                            process.wait(timeout=30)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait()
                        raise
                    finally:
                        process.stdout.close()
                record.update(status='completed' if code == 0 else 'failed', returncode=code, finished_at=now())
                write(run / 'workflow.json', manifest)
                if code:
                    raise ValueError(label + ' failed; inspect ' + str(run / (label + '.log')))
            stage('prepare', command)
            system = read(run / 'system/system-run.json')
            if system['status'] == 'no_targets':
                manifest['status'] = 'no_targets'
                print('No targets; existing deployment and reporting configuration retained.')
            elif args.mode == 'prepare':
                manifest['status'] = 'prepared'
            else:
                prepared = run / 'system/prepared'
                settings = reporting_settings(workspace, config, prepared)
                # Validate before deployment; source files need not exist yet.
                from report_config import load_config
                write(run / 'reporting-proposed.json', settings)
                load_config(run / 'reporting-proposed.json')
                script = 'install_prepared.py' if args.mode == 'install' else 'deploy_prepared.py'
                stage('deployment', [sys.executable, str(PROJECT / script), str(prepared),
                      '--output', str(run / 'deployment')] + (['--install'] if args.mode == 'install' else []))
                manifest['deployment_status'] = 'completed'
                # Publish only after deployment checks pass; retain prior configs as evidence.
                if (workspace / 'reporting.json').exists():
                    shutil.copy2(workspace / 'reporting.json', run / 'reporting-previous.json')
                write(workspace / 'reporting.json', settings)
                write(workspace / 'active-deployment.json', dict(run=str(run), updated_at=now(), reporting=settings))
                manifest['status'] = 'reporting'
                write(run / 'workflow.json', manifest)
                until = now()
                since = args.since or day_window(config.get('timezone', 'UTC'), instant=datetime.fromisoformat(until), previous=False)[0]
                stage('report', [sys.executable, str(PROJECT / 'report_config.py'),
                      '--config', str(workspace / 'reporting.json'), '--output', str(run / 'report'), since, until])
                manifest['status'] = 'completed'
        except BaseException as exc:
            manifest.update(status='failed', error=str(exc) or type(exc).__name__)
            raise
        finally:
            manifest['finished_at'] = now()
            write(run / 'workflow.json', manifest)
            print('Run evidence:', run)
        print('Workflow status:', manifest['status'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    init = sub.add_parser('init', help='Create a new configuration workspace; does not install dependencies.')
    init.add_argument('--workspace', type=Path, required=True)
    for field in ('network', 'interface', 'scanner-ip', 'node-hostname'):
        init.add_argument('--' + field, required=True)
    init.add_argument('--kubeconfig', type=Path, required=True)
    init.add_argument('--timezone', default='UTC', help='Calendar timezone for reports and daily schedule.')
    init.add_argument('--exclude', action='append', default=[])
    init.add_argument('--namespace', default='honeypots')
    init.add_argument('--mixed-release', default='mixed-honeypot')
    init.add_argument('--conpot-release', default='modbus-honeypot')
    init.add_argument('--state-root', required=True)
    init.add_argument('--log-root', required=True)
    init.add_argument('--honeychart-endpoint', default='http://127.0.0.1:8081/custom_build_endpoint')
    for command in ('check', 'run', 'report', 'schedule', 'set-timezone'):
        p = sub.add_parser(command)
        p.add_argument('--workspace', type=Path, required=True)
        if command == 'run':
            p.add_argument('--mode', choices=('prepare', 'install', 'upgrade'), default='prepare')
            p.add_argument('--since', help='Immediate report start (default midnight in the workspace timezone).')
        elif command == 'report':
            p.add_argument('--since')
            p.add_argument('--until')
            p.add_argument('--previous-day', action='store_true')
            p.add_argument('--output', type=Path)
        elif command == 'set-timezone':
            p.add_argument('--timezone', required=True)
        elif command == 'schedule':
            p.add_argument('--output', type=Path, required=True)
            p.add_argument('--time', '--utc-time', dest='utc_time', default='00:10')
            p.add_argument('--install', action='store_true', help='Install validated units and enable timer using sudo.')
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if args.command == 'init':
            initialize(args)
            return 0
        workspace, config, env = load_workspace(args.workspace)
        if args.command == 'set-timezone':
            reporting_zone(args.timezone)
            with locked(workspace):
                active = workspace / 'reporting.json'
                settings = read(active) if active.exists() else None
                backup = Path(tempfile.mkdtemp(prefix='timezone-change-', dir=workspace / 'runs'))
                shutil.copy2(workspace / 'workspace.json', backup / 'workspace.json')
                if settings is not None:
                    shutil.copy2(active, backup / 'reporting.json')
                    settings['timezone'] = args.timezone
                    write(active, settings)
                config['timezone'] = args.timezone
                write(workspace / 'workspace.json', config)
            print('Reporting timezone:', args.timezone)
            print('Backup:', backup)
            print('Regenerate/install the timer using schedule --time; existing timers are not changed here.')
            return 0
        if args.command == 'check':
            checks = doctor(workspace, config, env)
            print_checks(checks)
            return 0 if checks['status'] == 'passed' else 1
        if args.command == 'run':
            if args.since:
                from report_config import parse_time
                if parse_time(args.since) >= datetime.now(timezone.utc):
                    raise ValueError('--since must precede now.')
            run_workspace(args, workspace, config, env)
        else:
            if not (workspace / 'reporting.json').is_file():
                raise ValueError('No active reporting configuration; complete an install first.')
            if args.command == 'report':
                with locked(workspace):
                    command = [sys.executable, str(PROJECT / 'report_config.py'), '--config', str(workspace / 'reporting.json')]
                    if args.previous_day:
                        if args.since or args.until:
                            raise ValueError('Use --previous-day or both --since/--until.')
                        command += ['--previous-day']
                    elif args.since and args.until:
                        command += [args.since, args.until]
                    else:
                        raise ValueError('Supply --previous-day or both --since/--until.')
                    if args.output:
                        command += ['--output', str(args.output)]
                    call(command, env=env)
            elif args.command == 'schedule':
                # Generate using the existing validated generator, then route service
                # through this CLI so scheduled reports share the workspace lock.
                with locked(workspace):
                    zone = read(workspace / 'reporting.json').get('timezone', 'UTC')
                    reporting_zone(zone)
                    if any(arg == '--utc-time' or arg.startswith('--utc-time=') for arg in sys.argv[1:]) and zone != 'UTC':
                        raise ValueError('Use --time for a non-UTC timezone.')
                    unit = 'honeypot-report-' + config['identity'][:12]
                    call([sys.executable, str(PROJECT / 'generate_report_units.py'),
                          '--project', str(PROJECT), '--config', str(workspace / 'reporting.json'),
                          '--output', str(args.output), '--time', args.utc_time, '--name', unit,
                          '--python', sys.executable], env=env)
                    from generate_report_units import quoted
                    path = args.output.expanduser().resolve() / (unit + '.service')
                    text = path.read_text()
                    replacement = 'ExecStart=' + ' '.join(quoted(v) for v in (
                        sys.executable, PROJECT / 'honeypotctl.py', 'report', '--workspace', workspace, '--previous-day'))
                    text = '\n'.join(replacement if line.startswith('ExecStart=') else line for line in text.splitlines()) + '\n'
                    path.write_text(text)
                    call(['systemd-analyze', 'verify', str(path), str(path.with_suffix('.timer'))], env=env, timeout=60)
                    print('Workspace-aware units validated:', path.parent)
                    if args.install:
                        backup = Path(tempfile.mkdtemp(prefix='timer-backup-', dir=workspace / 'runs'))
                        for suffix in ('.service', '.timer'):
                            source = path.with_suffix(suffix)
                            target = Path('/etc/systemd/system') / source.name
                            if target.exists():
                                call(['sudo', 'cp', '-a', str(target), str(backup / target.name)], env=env)
                            call(['sudo', 'install', '-m', '0644', str(source), str(target)], env=env)
                        call(['sudo', 'systemctl', 'daemon-reload'], env=env)
                        call(['sudo', 'systemctl', 'enable', '--now', unit + '.timer'], env=env)
                        print('Timer installed:', unit + '.timer')
                        print('Previous units (if any):', backup)
                    else:
                        print('No units installed. Use schedule --install to install and enable the timer.')
        return 0
    except (Exception, KeyboardInterrupt) as exc:
        print('Stopped: ' + (str(exc) or type(exc).__name__), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
