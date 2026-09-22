#!/usr/bin/env python3
"""Generate, but do not install, systemd units for configured daily reports."""
import argparse
import grp
import json
import os
import pwd
import re
import subprocess
from pathlib import Path
from report_time import reporting_zone


def quoted(value):
    value = str(value)
    # Reject expansion/escape syntax rather than interpreting user-supplied paths.
    if any(ord(c) < 32 or ord(c) == 127 or c in '\\"%$' for c in value):
        raise ValueError('Unsupported systemd character in: ' + repr(value))
    return '"' + value + '"'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project', type=Path, required=True)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--user', default=pwd.getpwuid(os.getuid()).pw_name)
    parser.add_argument('--name', default='thesis-daily-report')
    parser.add_argument('--time', '--utc-time', dest='utc_time', default='00:10', help='HH:MM in reporting configuration timezone; legacy --utc-time is UTC-only.')
    parser.add_argument('--python', type=Path, default=Path('/usr/bin/python3'))
    parser.add_argument('--tool-path', default='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin')
    args = parser.parse_args()
    try:
        account = pwd.getpwnam(args.user)
        group = grp.getgrgid(account.pw_gid).gr_name
        for value in (account.pw_name, group):
            if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]*', value):
                raise ValueError('Unsupported account or group name.')
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,79}', args.name):
            raise ValueError('Invalid unit name.')
        if not re.fullmatch(r'(?:[01][0-9]|2[0-3]):[0-5][0-9]', args.utc_time):
            raise ValueError('Time must be HH:MM.')
        project = args.project.expanduser().resolve(strict=True)
        config = args.config.expanduser().resolve(strict=True)
        python = args.python.expanduser().absolute()
        if not python.is_file() or not os.access(python, os.X_OK):
            raise ValueError('Python executable is missing or not executable.')
        if not (project / 'report_config.py').is_file():
            raise ValueError('report_config.py is missing from the project.')
        settings = json.loads(config.read_text())
        if settings.get('schema_version') != 2:
            raise ValueError('Expected reporting configuration schema version 2.')
        zone = settings.get('timezone', 'UTC')
        reporting_zone(zone)
        import sys
        if any(arg == '--utc-time' or arg.startswith('--utc-time=') for arg in sys.argv[1:]) and zone != 'UTC':
            raise ValueError('Use --time for a non-UTC timezone.')
        if not isinstance(settings.get('kubeconfig'), str) or not settings['kubeconfig'].strip():
            raise ValueError('Scheduled reporting requires an explicit kubeconfig in its configuration.')
        if any(not entry.startswith('/') for entry in args.tool_path.split(':')):
            raise ValueError('Every tool PATH entry must be absolute and nonempty.')
        service = '\n'.join([
            '[Unit]',
            'Description=Generate the previous configured calendar day\'s configured honeypot report',
            'Wants=network-online.target',
            'After=network-online.target',
            '', '[Service]', 'Type=oneshot',
            'User=' + account.pw_name, 'Group=' + group,
            'Environment=' + quoted('HOME=' + account.pw_dir),
            'Environment=' + quoted('PATH=' + args.tool_path),
            'WorkingDirectory=' + str(project),
            'ExecStart=' + ' '.join(quoted(v) for v in (
                python, project / 'report_config.py', '--config', config, '--previous-day')),
            'UMask=0077', 'TimeoutStartSec=25min', '',
        ])
        timer = '\n'.join([
            '[Unit]', 'Description=Schedule configured daily honeypot reporting',
            '', '[Timer]', 'OnCalendar=*-*-* ' + args.utc_time + ':00 ' + zone,
            'Persistent=true', 'Unit=' + args.name + '.service',
            '', '[Install]', 'WantedBy=timers.target', '',
        ])
        output = args.output.expanduser().resolve()
        output.mkdir(parents=True, exist_ok=False)
        service_path = output / (args.name + '.service')
        timer_path = output / (args.name + '.timer')
        service_path.write_text(service)
        timer_path.write_text(timer)
        metadata = {'schema_version': 1, 'status': 'generated', 'user': account.pw_name,
                    'project': str(project), 'reporting_config': str(config),
                    'local_time': args.utc_time, 'timezone': zone, 'limitations': [
                        'Unit validation does not verify account access to logs or Kubernetes.',
                        'Reporting requires local access to configured source files.',
                        'Persistent timers do not generate one report for every missed day.',
                        'Paths containing quotes, backslashes, percent signs, dollar signs or control characters are rejected.']}
        try:
            subprocess.run(['systemd-analyze', 'verify', str(service_path), str(timer_path)],
                           check=True, timeout=60)
            metadata['status'] = 'validated'
        except (OSError, subprocess.SubprocessError) as exc:
            metadata.update(status='validation_failed', error=str(exc))
            raise
        finally:
            (output / 'generation.json').write_text(json.dumps(metadata, indent=2) + '\n')
        print('PASS: generated units passed systemd-analyze verify.')
        print(service)
        print(timer)
        print('Saved:', output)
        print('No system service or timer was installed, started, or enabled.')
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        parser.exit(1, 'Generation stopped: ' + str(exc) + '\n')


if __name__ == '__main__':
    main()
