"""Verify final hashes, raw inputs, and every saved test decision."""
import gzip
import hashlib
import json
from pathlib import Path
import sys
import tarfile
import numpy as np

HERE = Path(__file__).resolve().parent
DATA = HERE.parents[1] / 'results/latest'
sys.path.insert(0, str(HERE / 'code'))
from rl_weight_selector import sqisign_bandit_release as release
from rl_weight_selector.scaling_reference_ablation import context


def main():
    for directory in (DATA, HERE):
        for line in (directory / 'SHA256SUMS').read_text().splitlines():
            digest, name = line.split('  ', 1)
            path = directory / name
            assert path.resolve().is_relative_to(directory.resolve())
            assert hashlib.sha256(path.read_bytes()).hexdigest() == digest, name
    names = set(json.loads((DATA / 'inputs/algorithms.json').read_text()))
    assert len(names) == 150 and sum('sqisign' in n for n in names) == 9
    with gzip.open(DATA / 'inputs/tls_all50.json.gz', 'rt') as f:
        raw = json.load(f)
    assert len(raw) == 24000 and {r['algorithm'] for r in raw} == names
    lookup = {}
    for r in raw:
        samples = {s['run']: s['elapsed_ms'] for s in r['samples']}
        assert len(r['samples']) == 50 and set(samples) == set(range(1, 51))
        keep = set(sorted(samples, key=lambda n: (samples[n], n))[:35])
        key = (r['region'], r['certificate_mode'].removeprefix('chain').upper(),
               r['loss_percent'], r['bandwidth_mbps'], r['algorithm'])
        assert key not in lookup
        lookup[key] = [samples[i] for i in range(1, 51) if i in keep]
    path = DATA / 'inputs/prepared.json.gz'
    input_hash = hashlib.sha256(path.read_bytes()).hexdigest()
    _, bundles, outcomes = release.load_input(path)
    by_id = {b['id']: b for b in bundles}
    assert {c['algorithm'] for b in bundles for c in b['episode'].candidates} == names
    for b in bundles:
        e = b['episode']
        for i, c in enumerate(e.candidates):
            np.testing.assert_array_equal(outcomes[b['id']][i], lookup[
                (e.region, e.certificate_mode, e.loss_percent, e.bandwidth_mbps, c['algorithm'])])
    counts = {}
    for mode in ('region', 'condition'):
        directory = DATA / mode
        rows = json.loads((directory / 'test_decisions.json').read_text())
        records = {(r['fold'], r['level'], r['seed'], r['episode_id']): r for r in rows}
        assert len(rows) == len(records) == 7200
        cache = {}; verified = 0; models = 0
        with tarfile.open(directory / 'models.tar.gz', 'r:gz') as tf:
            for member in tf.getmembers():
                assert member.isfile() and member.name == 'models/' + Path(member.name).name
                m = json.load(tf.extractfile(member)); models += 1
                assert m['input_sha256'] == input_hash
                assert m['score_terms'] == 4 and m['verification_cost'] == 'chain-only'
                assert m['context_spec']['reference_mode'] == 'train-max'
                assert not set(m['fit_contexts']) & set(m['test_contexts'])
                for k in ('rtt_ms', 'bandwidth_mbps'):
                    assert m['reference'][k] == max(getattr(by_id[i]['episode'], k) for i in m['fit_contexts'])
                test = [by_id[i] for i in m['test_contexts']]
                bounds = tuple(np.asarray(m['feature_bounds'][k]) for k in ('minimum', 'maximum'))
                key = (m['fold'], m['level'])
                if key not in cache:
                    cache[key] = release.score_choices(test, bounds, m['actions'], 4)
                agent = release.LinUCBAgent(m['actions'], 5, m['alpha'])
                agent.a_inverse = np.asarray(m['a_inverse']); agent.b = np.asarray(m['b'])
                for b in test:
                    r = records[m['fold'], m['level'], m['seed'], b['id']]
                    arm = agent.select(context(b['episode'], m['reference']))[0]
                    index = int(cache[key][b['id']][arm])
                    assert arm == r['action']
                    assert b['episode'].candidates[index]['algorithm'] == r['rl_algorithm']
                    assert abs(outcomes[b['id']][index].mean() - r['rl_tls_ms']) < 1e-8
                    verified += 1
        assert models == 75 and verified == 7200
        metrics = json.loads((directory / 'metrics.json').read_text())
        assert abs(np.mean([r['rl_tls_ms'] for r in rows]) - metrics['mean_rl_tls_ms']) < 1e-8
        counts[mode] = {'models': models, 'verified_decisions': verified}
        print(mode, counts[mode], flush=True)
    print(json.dumps({'tls_candidates': 150, 'tls_samples': 1200000, 'checks': counts}))


if __name__ == '__main__':
    main()
