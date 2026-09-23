#!/usr/bin/env python3
"""Reprocess saved discovery evidence into descriptive device profiles; no network or deployment."""
import argparse
import json
import os
from pathlib import Path

from reconcile_profiles import reconcile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, required=True, help='Completed discovery directory containing scan-manifest.json.')
    parser.add_argument('--output', type=Path, required=True, help='New output directory; existing paths are refused.')
    args = parser.parse_args()
    os.umask(0o077)
    result = reconcile(args.evidence.expanduser())
    lines = ['DEVICE PROFILES', 'Descriptive only; deployment selection still uses confirmed service evidence.', '']
    for device in result['devices']:
        profile = device['device_profile']
        lines.extend([device['ip'],
                      '  OS family: ' + profile['os_family'],
                      '  OS assessment: ' + profile['os_assessment']['status'],
                      '  Roles: ' + (', '.join(profile['roles']) or 'none established within scan scope'),
                      '  Physical device type: undetermined', ''])
    lines.append('Detailed evidence and source hashes: device-profiles.json')
    text = '\n'.join(lines) + '\n'
    data = json.dumps(result, indent=2) + '\n'
    folder = args.output.expanduser()
    folder.mkdir(parents=True, exist_ok=False)
    (folder / 'device-profiles.json').write_text(data)
    (folder / 'device-profiles.txt').write_text(text)
    print(text, end='')
    print('Saved:', folder.resolve())


if __name__ == '__main__':
    main()
