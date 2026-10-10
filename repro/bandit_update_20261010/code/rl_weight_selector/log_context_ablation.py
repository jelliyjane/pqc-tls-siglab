"""Isolated log-vs-linear context ablation using the frozen release protocol.

Keeps 300 ms / 1000 Mbps references, probability loss, interaction, four
chain-only costs, folds, seeds, reward, and validation alpha selection fixed.
Does not replace the release feature transform or existing artifacts.
"""
import argparse
import hashlib
import json
from pathlib import Path
import statistics

import numpy as np
from rl_weight_selector import sqisign_bandit_release as release


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--transform', choices=['log', 'linear'], required=True)
    parser.add_argument('--split', choices=['condition', 'region'], required=True)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    original_context = release.loss_context
    original_spec = release.context_spec
    original_evaluate = release.evaluate
    rows = []

    def context(episode, loss_reference_percent=100.):
        expected = original_context(episode, loss_reference_percent)
        if args.transform == 'log':
            return expected
        r, b = episode.rtt_ms / 300., episode.bandwidth_mbps / 1000.
        actual = np.asarray([1., r, b, r*b, expected[-1]])
        assert actual.shape == expected.shape and np.all(np.isfinite(actual))
        return actual

    def spec(version):
        result = original_spec(version)
        if args.transform == 'linear':
            result['version'] = 'loss5-probability-linear-unclipped'
            result['features'] = ['bias', 'scaled_rtt', 'scaled_bandwidth',
                                  'scaled_rtt_x_scaled_bandwidth', 'loss_probability']
            result['transform'] = 'value/reference'
        return result

    def evaluate(*positional, **keywords):
        result = original_evaluate(*positional, **keywords)
        rows.extend(result)
        return result

    release.loss_context = context
    release.context_spec = spec
    release.evaluate = evaluate
    release.run(args.input, args.output_dir, args.split,
                'loss5-probability-unclipped', 4, 'chain-only')
    metrics = json.loads((args.output_dir / 'metrics.json').read_text())
    assert len(rows) == metrics['test_decisions'] == 7200
    summary = {
        'transform': args.transform, 'split': args.split,
        'mean_handshake_ms': statistics.fmean(r['rl_tls_ms'] for r in rows),
        'per_seed_ms': {str(s): statistics.fmean(r['rl_tls_ms'] for r in rows if r['seed'] == s)
                        for s in sorted({r['seed'] for r in rows})},
        'per_region_ms': {g: statistics.fmean(r['rl_tls_ms'] for r in rows if r['region'] == g)
                          for g in sorted({r['region'] for r in rows})},
        'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'numpy_version': np.__version__,
        'note': 'Development ablation; validation selects alpha separately for each transform. No deployment changes.'
    }
    release.save_json(args.output_dir / 'ablation_summary.json', summary)
    release.save_json(args.output_dir / 'paired_outcomes.json', [
        {k: r[k] for k in ('episode_id', 'seed', 'fold', 'rl_algorithm', 'rl_tls_ms')}
        for r in rows])
    print(json.dumps(summary), flush=True)


if __name__ == '__main__':
    main()
