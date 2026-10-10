"""Check integrity and exact derivation; does not retrain or claim model replay."""
import gzip
import hashlib
import json
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / 'results/bandit_update_20261010'


def main():
    for directory in (DATA, Path(__file__).resolve().parent):
        for line in (directory / 'SHA256SUMS').read_text().splitlines():
            digest, name = line.split('  ', 1)
            path = directory / name
            assert path.resolve().is_relative_to(directory.resolve())
            assert hashlib.sha256(path.read_bytes()).hexdigest() == digest, name
    manifest = json.loads((DATA / 'MANIFEST.json').read_text())
    names = set(json.loads((DATA / 'inputs150/algorithms.json').read_text()))
    assert len(names) == 150 and sum('sqisign' in n for n in names) == 9
    with gzip.open(ROOT / manifest['inputs150']['source'], 'rt') as f:
        original = json.load(f)
    with gzip.open(DATA / 'inputs150/tls_all50.json.gz', 'rt') as f:
        records = json.load(f)
    assert records == [r for r in original if r['algorithm'] in names]
    assert len(records) == 24000
    assert {r['algorithm'] for r in records} == names
    assert all(len(r['samples']) == 50 and {s['run'] for s in r['samples']} == set(range(1, 51)) for r in records)
    count = 0
    for spec in manifest['model_archives']:
        expected = {m['name']: m['published_sha256'] for m in spec['members']}
        with tarfile.open(ROOT / spec['path'], 'r:gz') as archive:
            members = archive.getmembers()
            assert len(members) == len(expected) == 75
            for member in members:
                assert member.isfile() and member.name == 'models/' + Path(member.name).name
                data = archive.extractfile(member).read()
                assert hashlib.sha256(data).hexdigest() == expected[Path(member.name).name]
                json.loads(data)
                count += 1
    print(json.dumps({'tls_candidates': 150, 'tls_conditions': 24000, 'tls_samples': 1200000,
                      'model_files_checked': count, 'model_archives': len(manifest['model_archives'])}))


if __name__ == '__main__':
    main()
