#!/usr/bin/env python3
"""Verify an archival asset and optionally restore into a NEW directory."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import tarfile


def verify(archive, report):
    digest = hashlib.sha256()
    with archive.open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(block)
    expected = json.loads(report.read_text())
    if digest.hexdigest() != expected['sha256']:
        raise ValueError('Archive SHA-256 does not match report')
    with tarfile.open(archive, 'r:gz') as tar:
        manifest = json.load(tar.extractfile('SNAPSHOT-MANIFEST.json'))
        entries = {item['path']: item for item in manifest['files']}
        if len(entries) != len(manifest['files']):
            raise ValueError('Duplicate manifest paths')
        seen = set()
        for member in tar:
            if member.name == 'SNAPSHOT-MANIFEST.json':
                continue
            path = PurePosixPath(member.name)
            if not member.isfile() or path.is_absolute() or '..' in path.parts:
                raise ValueError('Unsafe archive member')
            if member.name in seen or member.name not in entries:
                raise ValueError('Unexpected or duplicate member')
            item = entries[member.name]
            digest = hashlib.sha256()
            with tar.extractfile(member) as source:
                for block in iter(lambda: source.read(1024 * 1024), b''):
                    digest.update(block)
            if member.size != item['bytes'] or digest.hexdigest() != item['sha256']:
                raise ValueError('Member verification failed: ' + member.name)
            seen.add(member.name)
        if seen != set(entries):
            raise ValueError('Missing members')
    return len(entries)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    parser.add_argument('--report', type=Path)
    parser.add_argument('--extract-to', type=Path,
                        help='Must not already exist; no existing files are overwritten')
    args = parser.parse_args()
    report = args.report or args.archive.with_name(
        args.archive.name.removesuffix('.tar.gz') + '.report.json')
    count = verify(args.archive, report)
    if args.extract_to:
        args.extract_to.mkdir(parents=True, exist_ok=False)
        with tarfile.open(args.archive, 'r:gz') as tar:
            for member in tar:
                target = args.extract_to / member.name
                target.parent.mkdir(parents=True, exist_ok=True)
                with tar.extractfile(member) as source, target.open('xb') as dest:
                    shutil.copyfileobj(source, dest)
                target.chmod(member.mode & 0o777)
    print(f'PASS: archive hash and all {count:,} member hashes match')
