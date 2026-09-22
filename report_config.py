"""Collect combined reports with explicit source identities and local source paths."""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from report_time import day_window, reporting_zone
from protocol_support import reporting_protocols


def load_config(path):
    path = path.expanduser().resolve()
    config = json.loads(path.read_text())
    if config.get('schema_version') != 2:
        raise ValueError('Expected reporting configuration schema_version 2.')

    def string(mapping, key):
        value = mapping.get(key)
        if not isinstance(value, str) or not value.strip() or '\0' in value or '\n' in value:
            raise ValueError('Missing or invalid setting: ' + key)
        return value

    def resolve(value):
        p = Path(value).expanduser()
        return str((p if p.is_absolute() else path.parent / p).resolve())

    zone = config.get('timezone', 'UTC')
    reporting_zone(zone)
    result = {'schema_version': 2, 'reports_root': resolve(string(config, 'reports_root')), 'timezone': zone}
    for name, paths, ids in (
        ('mixed', ('database', 'cowrie_log', 'labels', 'history_root'), ('database_id',)),
        ('conpot', ('log', 'labels'), ('log_id',)),
    ):
        if name not in config:
            continue
        source = config[name]
        section = {}
        for key in ('deployment', 'namespace'):
            value = string(source, key)
            if not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', value):
                raise ValueError('Invalid Kubernetes name: ' + value)
            section[key] = value
        for key in ids:
            value = string(source, key)
            if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', value):
                raise ValueError('Source identifiers must use letters, digits, dots, underscores or hyphens.')
            section[key] = value
        for key in paths:
            section[key] = resolve(string(source, key))
        if name == 'mixed':
            services = source.get('services', ['cowrie', 'dionaea'])
            if (not isinstance(services, list) or not services
                    or any(hp not in ('cowrie', 'dionaea') for hp in services)
                    or len(set(services)) != len(services)):
                raise ValueError('mixed.services must select cowrie and/or dionaea.')
            section['services'] = services
            if 'protocols' in source:
                section['protocols'] = reporting_protocols(source['protocols'], services)
        result[name] = section
    if not any(name in result for name in ('mixed', 'conpot')):
        raise ValueError('At least one reporting source must be configured.')
    kubeconfig = config.get('kubeconfig')
    if kubeconfig is not None:
        result['kubeconfig'] = resolve(string(config, 'kubeconfig'))
        if not Path(result['kubeconfig']).is_file():
            raise ValueError('Configured kubeconfig is missing.')
    for name in ('mixed', 'conpot'):
        if name in result and not Path(result[name]['labels']).is_file():
            raise ValueError('Label file is missing for ' + name)
    if 'mixed' in result and not Path(result['mixed']['history_root']).is_dir():
        raise ValueError('Configured history root must be an existing directory; it may be empty.')
    return result


def parse_time(value):
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('Timestamps must include a timezone.')
    return parsed.astimezone(timezone.utc)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('since', nargs='?')
    parser.add_argument('until', nargs='?')
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--previous-day', action='store_true')
    args = parser.parse_args()
    if args.previous_day:
        if args.since is not None or args.until is not None:
            parser.error('--previous-day cannot be combined with timestamps.')
        # Resolve calendar boundaries after loading the configured timezone.
    elif args.since is None or args.until is None:
        parser.error('Supply SINCE UNTIL or --previous-day.')
    status_path = None
    status = None
    try:
        os.umask(0o077)
        config = load_config(args.config)
        if args.previous_day:
            args.since, args.until = day_window(config['timezone'])
        if parse_time(args.since) >= parse_time(args.until):
            raise ValueError('SINCE must be earlier than UNTIL.')
        if args.output:
            parent = args.output.expanduser().resolve()
            parent.mkdir(parents=True, exist_ok=False)
        else:
            root = Path(config['reports_root'])
            root.mkdir(parents=True, exist_ok=True)
            parent = Path(tempfile.mkdtemp(prefix='configured-report-', dir=root))
        (parent / 'reporting-config-resolved.json').write_text(json.dumps(config, indent=2) + '\n')
        status_path = parent / 'configured-report-result.json'
        status = {'schema_version': 1, 'status': 'running', 'since': args.since, 'until': args.until,
                  'configuration_source': str(args.config.expanduser().resolve()),
                  'reporting_timezone': config['timezone'],
                  'window_basis': 'previous_local_calendar_day' if args.previous_day else 'explicit_timestamps',
                  'limitations': ['Collectors require filesystem access to configured log and database paths.',
                                  'A cluster kubeconfig alone does not provide remote filesystem access.',
                                  'Absent reporting sections are not selected; at most one mixed and one Conpot release are supported.',
                                  'Source IDs must change when a database is replaced or a Conpot log is reset.']}
        status_path.write_text(json.dumps(status, indent=2) + '\n')
        command = [sys.executable, str(Path(__file__).resolve().parent / 'collect_combined_report.py'),
                   args.since, args.until, '--output', str(parent / 'report')]
        if 'mixed' in config:
            mixed = config['mixed']
            for option, key in (('deployment', 'deployment'), ('namespace', 'namespace'),
                                ('database', 'database'), ('database-id', 'database_id'),
                                ('cowrie-log', 'cowrie_log'), ('labels', 'labels'), ('history-root', 'history_root')):
                command += ['--mixed-' + option, mixed[key]]
            command += ['--mixed-reports-root', config['reports_root'],
                        '--mixed-services', ','.join(mixed['services'])]
            if 'protocols' in mixed:
                command += ['--mixed-protocols', ','.join(mixed['protocols'])]
        else:
            command += ['--skip-mixed']
        if 'conpot' in config:
            conpot = config['conpot']
            for option, key in (('deployment', 'deployment'), ('namespace', 'namespace'),
                                ('log', 'log'), ('log-id', 'log_id'), ('labels', 'labels')):
                command += ['--conpot-' + option, conpot[key]]
        else:
            command += ['--skip-conpot']
        env = os.environ.copy()
        if 'kubeconfig' in config:
            env['KUBECONFIG'] = config['kubeconfig']
        print('Reporting calendar timezone:', config['timezone'], flush=True)
        print('Configured report directory:', parent, flush=True)
        subprocess.run(command, env=env, check=True, timeout=1300)
        manifest = json.loads((parent / 'report/collection-manifest.json').read_text())
        if manifest['status'] != 'completed':
            raise ValueError('Combined report did not complete.')
        status['status'] = 'completed'
        status_path.write_text(json.dumps(status, indent=2) + '\n')
        print((parent / 'report/report.txt').read_text())
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        if status_path is not None:
            status.update(status='failed', error=str(exc))
            status_path.write_text(json.dumps(status, indent=2) + '\n')
        print('Configured report failed: ' + str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
