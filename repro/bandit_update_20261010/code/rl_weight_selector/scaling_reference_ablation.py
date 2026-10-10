"""Compare fixed vs training-only maximum references, keeping log1p features.

Validation transforms are fitted on inner training contexts only. Final test
transforms are fitted on outer training contexts only. All other settings use
the frozen four-cost, probability-loss, chain-only release protocol.
"""
import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import statistics
import time

import numpy as np
from rl_weight_selector import sqisign_bandit_release as release


def fit_reference(training, mode):
    if mode == 'fixed':
        return {'rtt_ms': 300., 'bandwidth_mbps': 1000.}
    if mode != 'train-max':
        raise ValueError(mode)
    result = {key: max(float(getattr(b['episode'], key)) for b in training)
              for key in ('rtt_ms', 'bandwidth_mbps')}
    if not all(math.isfinite(v) and v > 0 for v in result.values()):
        raise ValueError('Training maxima must be positive and finite')
    return result


def context(episode, reference):
    r = math.log1p(episode.rtt_ms) / math.log1p(reference['rtt_ms'])
    b = math.log1p(episode.bandwidth_mbps) / math.log1p(reference['bandwidth_mbps'])
    x = np.asarray([1., r, b, r*b, episode.loss_percent / 100.])
    assert np.all(np.isfinite(x))
    return x


def transform(bundles, reference):
    # Separate dictionaries prevent inner/outer transforms from overwriting
    # each other when the same source context participates in both stages.
    return [{**b, 'x': context(b['episode'], reference)} for b in bundles]


def run(args):
    start = time.monotonic()
    out = args.output_dir
    out.mkdir(parents=True, exist_ok=False)
    (out / 'models').mkdir()
    input_hash = hashlib.sha256(args.input.read_bytes()).hexdigest()
    data, bundles, outcomes = release.load_input(args.input)
    assignment = release.assignments(bundles)
    actions = release.score_actions(4)
    spec = {'reference_mode': args.reference, 'transform': 'log1p(value)/log1p(reference)',
            'features': ['bias', 'log_rtt', 'log_bandwidth', 'log_rtt_x_log_bandwidth', 'loss_probability'],
            'clip': False, 'loss_reference_percent': 100.,
            'reference_fit': 'inner training for validation; outer training for test',
            'score_terms': 4, 'verification_cost': 'chain-only'}
    release.save_json(out / 'context_spec.json', spec)
    release.save_json(out / 'split_manifest.json',
        [{'group': g, 'test_fold': f} for g, f in sorted(assignment.items())]
        if args.split == 'condition' else
        [{'fold': i, 'test_region': r, 'validation_region': release.REGIONS[(i+1)%5]}
         for i, r in enumerate(release.REGIONS)])
    results, searches, audits = [], [], []
    verified = 0
    for fold in range(5):
        for level in release.BASELINES:
            cohort = [b for b in bundles if b['episode'].level == level]
            tuning0, validation0, fitting0, testing0 = release.split(cohort, fold, args.split, assignment)
            assert len(fitting0) == 384 and len(testing0) == 96
            assert {b['id'] for b in tuning0}.isdisjoint(b['id'] for b in validation0)
            assert {b['id'] for b in fitting0}.isdisjoint(b['id'] for b in testing0)
            inner_ref = fit_reference(tuning0, args.reference)
            outer_ref = fit_reference(fitting0, args.reference)
            tuning, validation = transform(tuning0, inner_ref), transform(validation0, inner_ref)
            fitting, testing = transform(fitting0, outer_ref), transform(testing0, outer_ref)
            if args.reference == 'train-max':
                for subset in (tuning, fitting):
                    assert all(0 <= b['x'][1] <= 1 and 0 <= b['x'][2] <= 1 for b in subset)
                    assert max(b['x'][1] for b in subset) == max(b['x'][2] for b in subset) == 1.
            print(args.reference, args.split, fold, level, round(time.monotonic()-start, 1), flush=True)
            tb = release.score_bounds(tuning, 4)
            tc = release.score_choices(tuning+validation, tb, actions, 4)
            current = []
            for alpha in release.ALPHAS:
                for seed in release.SEEDS:
                    agent = release.train(tuning, {b['id']: outcomes[b['id']] for b in tuning},
                                          tc, alpha, seed, actions=actions)
                    row = dict(fold=fold, level=level, alpha=alpha, seed=seed,
                               validation_tls_ms=release.policy_mean(agent, validation, outcomes, tc))
                    current.append(row)
                    searches.append(row)
            best = min(release.ALPHAS, key=lambda a: statistics.fmean(
                r['validation_tls_ms'] for r in current if r['alpha'] == a))
            bounds = release.score_bounds(fitting, 4)
            choices = release.score_choices(fitting+testing, bounds, actions, 4)
            audits.append(dict(fold=fold, level=level, selected_alpha=best,
                tuning_reference=inner_ref, fitting_reference=outer_ref,
                tuning_ids=[b['id'] for b in tuning], validation_ids=[b['id'] for b in validation],
                fitting_ids=[b['id'] for b in fitting], testing_ids=[b['id'] for b in testing],
                test_above_reference=sum(int(b['x'][1] > 1 or b['x'][2] > 1) for b in testing)))
            for seed in release.SEEDS:
                agent = release.train(fitting, {b['id']: outcomes[b['id']] for b in fitting},
                                      choices, best, seed, actions=actions)
                rows = release.evaluate(agent, testing, outcomes, choices, seed, fold, actions=actions)
                checkpoint = {**agent.to_json(), 'context_spec': spec, 'reference': outer_ref,
                    'feature_bounds': {'minimum': bounds[0].tolist(), 'maximum': bounds[1].tolist()},
                    'score_features': release.FEATURES[:4], 'score_terms': 4,
                    'verification_cost': 'chain-only', 'feedback_mode': 'selected-action',
                    'fold': fold, 'level': level, 'seed': seed, 'split_type': args.split,
                    'input_sha256': input_hash, 'fit_contexts': [b['id'] for b in fitting],
                    'test_contexts': [b['id'] for b in testing]}
                path = out / 'models' / f'fold{fold}_{level}_seed{seed}.json'
                release.save_json(path, checkpoint)
                restored = json.loads(path.read_text())
                replay = release.LinUCBAgent(restored['actions'], 5, restored['alpha'])
                replay.a_inverse = np.asarray(restored['a_inverse'])
                replay.b = np.asarray(restored['b'])
                for b, row in zip(testing, rows):
                    x = context(b['episode'], restored['reference'])
                    assert np.array_equal(x, b['x'])
                    arm = replay.select(x)[0]
                    index = int(choices[b['id']][arm])
                    assert arm == row['action']
                    assert b['episode'].candidates[index]['algorithm'] == row['rl_algorithm']
                    assert abs(outcomes[b['id']][index].mean()-row['rl_tls_ms']) < 1e-9
                    verified += 1
                results.extend(rows)
    assert len(results) == verified == 7200
    assert max(Counter((r['episode_id'], r['seed']) for r in results).values()) == 1
    assert hashlib.sha256(args.input.read_bytes()).hexdigest() == input_hash
    metrics = dict(reference_mode=args.reference, split_type=args.split, context_spec=spec,
        mean_rl_tls_ms=statistics.fmean(r['rl_tls_ms'] for r in results),
        mean_oracle_tls_ms=statistics.fmean(r['oracle_tls_ms_evaluator_only'] for r in results),
        mean_mldsa_tls_ms=statistics.fmean(r['mldsa_tls_ms'] for r in results),
        per_seed_ms={str(s): statistics.fmean(r['rl_tls_ms'] for r in results if r['seed'] == s)
                     for s in release.SEEDS},
        per_region_ms={g: statistics.fmean(r['rl_tls_ms'] for r in results if r['region'] == g)
                       for g in release.REGIONS},
        input_sha256=input_hash, seeds=list(release.SEEDS), alphas=list(release.ALPHAS),
        ridge=1., actions=len(actions), score_terms=4, verification_cost='chain-only',
        reward='-observed_tls_ms/1000', feedback_mode='selected-action',
        models=75, test_decisions=len(results), verified_checkpoint_decisions=verified,
        numpy_version=np.__version__, elapsed_seconds=time.monotonic()-start,
        limitations=data['limitations'],
        source_hashes={str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in
                      [Path(__file__), Path(release.__file__),
                       Path(release.__file__).with_name('tail5_region_holdout.py'),
                       Path(release.__file__).with_name('partial_feedback_linucb.py')]})
    release.save_json(out / 'test_decisions.json', results)
    release.save_json(out / 'validation_search.json', searches)
    release.save_json(out / 'scaling_audit.json', audits)
    release.save_json(out / 'metrics.json', metrics)
    print(json.dumps({k: metrics[k] for k in ('reference_mode', 'split_type', 'mean_rl_tls_ms',
                                             'per_seed_ms', 'elapsed_seconds')}), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference', choices=['fixed', 'train-max'], required=True)
    parser.add_argument('--split', choices=['condition', 'region'], required=True)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    run(parser.parse_args())
