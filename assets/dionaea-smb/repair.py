"""Repair two field-name typos in the inspected Dionaea SMB1 implementation.

Runs in an init container. Reads the image source and writes a separate volume;
never modifies the image source, persistent honeypot state, or database.
Compatible with the inspected image's Python 3.6 runtime.
"""
import argparse
import hashlib
import os
import tempfile
from pathlib import Path

BEFORE = 'fb2ac0b62759bdc00a5ff66b4c3f1bf8478fe7169f4e4ad21774e320b67f7959'
AFTER = '06e2214d76987ac96062695750882e3f0e73971922865809e27ff3528537d692'
SOURCE = '/opt/dionaea/lib/dionaea/python/dionaea/smb/include/smbfields.py'


def repair(data):
    if hashlib.sha256(data).hexdigest() != BEFORE:
        raise ValueError('Unrecognized SMB source; refusing to patch this image.')
    if data.count(b'"OemDomainNam"') != 2:
        raise ValueError('Expected exactly two misspelled field references.')
    fixed = data.replace(b'"OemDomainNam"', b'"OemDomainName"')
    if hashlib.sha256(fixed).hexdigest() != AFTER:
        raise ValueError('Repaired SMB source checksum mismatch.')
    compile(fixed, SOURCE, 'exec')
    return fixed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', default=SOURCE, type=Path)
    parser.add_argument('--output', default='/smb-repaired/smbfields.py', type=Path)
    args = parser.parse_args()
    if args.source.resolve() == args.output.resolve():
        raise ValueError('Source and output must be different files.')
    fixed = repair(args.source.read_bytes())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.smb-repair-', dir=str(args.output.parent))
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(fixed)
        os.chmod(name, 0o444)
        os.replace(name, str(args.output))
    finally:
        if os.path.exists(name):
            os.unlink(name)
    print('PASS: SMB1 field-name repair prepared; SHA-256=' + AFTER)


if __name__ == '__main__':
    main()
