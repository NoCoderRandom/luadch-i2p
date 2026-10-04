#!/usr/bin/python3
"""Inspect the package payload without installing/executing it."""
import argparse
import io
from pathlib import PurePosixPath
import subprocess
import tarfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('package')
    parser.add_argument('--forbid-text', action='append', default=[])
    args = parser.parse_args()
    data = subprocess.check_output(['dpkg-deb', '--fsys-tarfile', args.package])
    count = 0
    errors = []
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            if member.uid != 0 or member.gid != 0:
                errors.append(member.name + ': not root-owned')
            if member.mode & 0o022:
                # Symlink mode is not an access permission on Linux.
                if not member.issym():
                    errors.append(member.name + ': writable program payload')
            if not member.isfile():
                continue
            count += 1
            forbidden = {'.git', '.codex', '.claude', '__pycache__', 'node_modules'}
            if forbidden.intersection(path.parts) or path.name.lower() in {
                    'claude.md', 'agents.md', 'setup.txt', 'user.tbl', 'master.key', 'hub-address'}:
                errors.append(member.name + ': private/generated/assistant file')
            if path.suffix.lower() in {'.private', '.key', '.log', '.pcap', '.pcapng', '.pdb', '.pyc'}:
                errors.append(member.name + ': forbidden artifact type')
            content = archive.extractfile(member).read()
            for text in args.forbid_text:
                variants = (text, text.replace('\\', '\\\\'))
                if any(value.encode(encoding).lower() in content.lower()
                       for value in variants for encoding in ('utf-8', 'utf-16le')):
                    errors.append(member.name + ': forbidden private text')
    if errors:
        raise SystemExit('\n'.join(errors))
    print(f'PASS: {count} payload files; permissions, private-file inventory and supplied privacy strings')


if __name__ == '__main__':
    main()
