"""Five-term scoring ablation: sign, transmission, rounds, verify, binary tail.

Uses the existing immutable X25519 snapshot, splits, reward, seeds and alpha grid.
Does not modify measurement workers, old models, or deterministic selector code.
"""
from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import random
import statistics
import time
from dataclasses import replace
from pathlib import Path

import numpy as np

from contextual_signature_selector.selector import NetworkContext, SelectorConstants, score_row
from rl_weight_selector.partial_feedback_linucb import LinUCBAgent
from rl_weight_selector.region_holdout_unified_evp import REGIONS, all_run_outcomes, write_csv
from rl_weight_selector.retrain_ica12 import (
    ROOT, ALPHAS, SEEDS, BASELINES, prepare, cost_rows, load_evp_averages,
)

FEATURES = ('sign_ms', 'transmission_ms', 'extra_round_ms', 'verify_chain_ms', 'i_tail')
WEIGHTS = ('weight_sign', 'weight_transmission', 'weight_round', 'weight_verify', 'weight_tail')


def action_grid5(step=0.1):
    """Five-dimensional simplex at a step that divides one exactly."""
    units = round(1.0 / step)
    if step <= 0 or not np.isclose(units * step, 1.0):
        raise ValueError('action step must divide 1 exactly')
    return [tuple(v / units for v in (*prefix, units-sum(prefix)))
            for prefix in itertools.product(range(units+1), repeat=4) if sum(prefix) <= units]


ACTIONS = action_grid5()


def save_json(path, data):
    with path.open('x') as f:
        json.dump(data, f, ensure_ascii=False, allow_nan=False, separators=(',', ':'))
        f.write('\n')


class CachedLinUCB(LinUCBAgent):
    """Same scores/update as LinUCB; recompute only changed arms per context."""
    def __init__(self, actions, dimension, alpha):
        super().__init__(actions, dimension, alpha)
        self._score_cache = {}

    def scores(self, context):
        key = tuple(context)
        if key not in self._score_cache:
            scores, means, uncertainty = super().scores(context)
            self._score_cache[key] = (self.counts.copy(), scores, means, uncertainty)
        counts, scores, means, uncertainty = self._score_cache[key]
        dirty = np.flatnonzero(counts != self.counts)
        if len(dirty):
            inverse = self.a_inverse[dirty]
            theta = np.einsum('aij,aj->ai', inverse, self.b[dirty])
            means[dirty] = theta @ context
            projected = np.einsum('aij,j->ai', inverse, context)
            uncertainty[dirty] = np.sqrt(np.maximum(0., np.einsum('ai,i->a', projected, context)))
            scores[dirty] = means[dirty] + self.alpha * uncertainty[dirty]
            counts[dirty] = self.counts[dirty]
        return scores, means, uncertainty

    def update_many(self, action_indices, context, reward):
        """Apply the same observed reward to behaviorally equivalent arms."""
        indices = np.asarray(action_indices, dtype=int)
        inverse = self.a_inverse[indices]
        projected = np.einsum('aij,j->ai', inverse, context)
        denominator = 1.0 + np.einsum('ai,i->a', projected, context)
        self.a_inverse[indices] = inverse - (
            projected[:, :, None] * projected[:, None, :]
            / denominator[:, None, None]
        )
        self.b[indices] += reward * context
        self.counts[indices] += 1
        self.total_updates += len(indices)


def features5(scored, rtt):
    # Neither legacy I_tail*sign nor legacy overlap is used in the new score.
    return (float(scored['sign_ms']), float(scored['serialization_ms']),
            float(scored['extra_rounds']) * rtt, float(scored['verify_chain_ms']),
            float(scored['i_tail']))


def prepare5(snapshot, pure_path, composite_path, sign, verify):
    bundles, _, _, exclusions = prepare(snapshot, pure_path, composite_path, sign, verify)
    pure, composite = cost_rows(pure_path, composite_path, sign, verify)
    provenance = []
    for b in bundles:
        ep = b['episode']
        candidates = []
        for candidate in ep.candidates:
            alg = candidate['algorithm']
            if ep.classical_algorithm == 'pure':
                r = pure[alg, ep.certificate_mode]
                profile = {'actual_chain_der_size_bytes':r['chain_bytes'],
                           'signature_size_bytes':r['signature_bytes'], 'sent_cert_count':r['sent_cert_count'],
                           'actual_sign_ms':r['sign_ms'], 'actual_verify_ms':r['verify_ms']}
            else:
                profile = composite[ep.region, alg, ep.certificate_mode]
            profile = {**profile, 'algorithm':alg, 'pqc_algorithm':candidate['pqc_algorithm'],
                       'classical_algorithm':ep.classical_algorithm, 'level':ep.level,
                       'certificate_mode':ep.certificate_mode}
            scored = score_row(profile, NetworkContext(ep.rtt_ms, ep.bandwidth_mbps, 16384, ep.rtt_ms), SelectorConstants())
            feature = features5(scored, ep.rtt_ms)
            assert all(np.isfinite(v) and v >= 0 for v in feature)
            assert feature[-1] in (0.,1.)
            candidates.append({'algorithm':alg, 'pqc_algorithm':candidate['pqc_algorithm'], 'features':feature})
            provenance.append({'episode_id':b['id'], 'algorithm':alg,
                'sign_ms':scored['sign_ms'], 'verify_one_ms':scored['verify_one_ms'],
                'sent_cert_count':scored['sent_cert_count'], 'chain_bytes':scored['chain_bytes'],
                'signature_bytes':scored['signature_bytes'], 'server_flight_bytes':scored['server_flight_bytes'],
                'extra_rounds':scored['extra_rounds'], 'i_tail':scored['i_tail'],
                'features':feature, 'legacy_overlap_not_used':scored['overlap_ms'],
                'legacy_tail_delay_not_used':scored['tail_delay_ms']})
        b['episode'] = replace(ep, candidates=tuple(candidates))
    return bundles, provenance, exclusions


def fit_bounds(bundles):
    values = np.array([c['features'] for b in bundles for c in b['episode'].candidates])
    low, high = values.min(axis=0), values.max(axis=0)
    # I_tail remains an unscaled 0/1 indicator, even if training has one state.
    low[-1], high[-1] = 0., 1.
    return low, high


def normalize(features, bounds):
    low, high = bounds
    features = np.asarray(features, dtype=float)
    result = np.clip(np.divide(features-low, high-low, out=np.zeros_like(features), where=high>low), 0., 1.)
    result[..., -1] = features[..., -1]
    return result


def action_choices(bundles, bounds, actions=ACTIONS):
    result = {}
    for b in bundles:
        cs = b['episode'].candidates
        costs = normalize([c['features'] for c in cs], bounds)
        # Keep the original exact tie break (weighted cost, cost sum, name).
        result[b['id']] = np.array([min(range(len(cs)), key=lambda i:(
            float(np.dot(w, costs[i])), float(costs[i].sum()), cs[i]['algorithm'])) for w in actions])
    return result


def train(bundles, outcomes, choices, alpha, seed, actions=ACTIONS, feedback_mode='selected-action'):
    assert set(outcomes) == {b['id'] for b in bundles}
    agent = CachedLinUCB(actions, 4, alpha)
    order = list(range(35))
    random.Random(seed*17).shuffle(order)
    for index in order:
        episodes = list(bundles)
        random.Random(seed+index*1009).shuffle(episodes)
        for b in episodes:
            action = agent.select(b['x'])[0]
            selected = int(choices[b['id']][action])
            reward = -float(outcomes[b['id']][selected,index])/1000.
            if feedback_mode == 'same-certificate':
                # These arms would make the exact same certificate choice in
                # this context, so the one observed TLS value is valid for all
                # of them without revealing any unselected certificate.
                equivalent = np.flatnonzero(choices[b['id']] == selected)
                agent.update_many(equivalent, b['x'], reward)
            else:
                agent.update(action, b['x'], reward)
    observations = 35*len(bundles)
    if feedback_mode == 'selected-action':
        assert agent.total_updates == observations
    else:
        assert agent.total_updates >= observations
    return agent


def policy_mean(agent, bundles, outcomes, choices):
    return statistics.fmean(float(outcomes[b['id']][choices[b['id']][agent.select(b['x'])[0]]].mean()) for b in bundles)


def evaluate(agent, bundles, outcomes, choices, seed, fold, actions=ACTIONS):
    rows = []
    before = agent.total_updates
    for b in bundles:
        ep = b['episode']; action = agent.select(b['x'])[0]
        selected = int(choices[b['id']][action]); means = outcomes[b['id']].mean(axis=1)
        baseline = [c['pqc_algorithm'] for c in ep.candidates].index(BASELINES[ep.level])
        selected_ms, baseline_ms, oracle = float(means[selected]), float(means[baseline]), float(means.min())
        rows.append({'fold':fold,'held_out_region':ep.region,'episode_id':b['id'],'seed':seed,
            'level':ep.level,'suite':ep.classical_algorithm,'certificate_mode':ep.certificate_mode,
            'loss_percent':ep.loss_percent,'bandwidth_mbps':ep.bandwidth_mbps,'region':ep.region,
            'rtt_ms':ep.rtt_ms,'rtt_mismatch':b['rtt_mismatch'],'candidate_count':len(ep.candidates),
            'action':action, **dict(zip(WEIGHTS,actions[action])),
            'rl_algorithm':ep.candidates[selected]['algorithm'],'rl_tls_ms':selected_ms,
            'mldsa_algorithm':ep.candidates[baseline]['algorithm'],'mldsa_tls_ms':baseline_ms,
            'oracle_tls_ms_evaluator_only':oracle,'regret_ms_evaluator_only':selected_ms-oracle,
            'reduction_vs_mldsa_pct':100*(baseline_ms-selected_ms)/baseline_ms})
    assert agent.total_updates == before
    return rows


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--snapshot',type=Path,required=True)
    p.add_argument('--server-sign-profile-dir',type=Path,required=True)
    p.add_argument('--client-verify-profile-dir',type=Path,required=True)
    p.add_argument('--output-dir',type=Path,required=True)
    p.add_argument('--comparison-dir',type=Path,required=True)
    p.add_argument('--action-step',type=float,default=.1)
    p.add_argument('--feedback-mode',choices=('selected-action','same-certificate'),default='selected-action')
    args=p.parse_args()
    actions=action_grid5(args.action_step)
    start=time.monotonic()
    snapshot=json.loads(args.snapshot.read_text())
    snapshot_hash=hashlib.sha256(args.snapshot.read_bytes()).hexdigest()
    old=json.loads((args.comparison_dir/'metrics.json').read_text())
    assert snapshot_hash == old['snapshot_sha256'], 'Comparator must use exactly the same input snapshot'
    sign,sign_meta=load_evp_averages(args.server_sign_profile_dir,'server_sign')
    verify,verify_meta=load_evp_averages(args.client_verify_profile_dir,'seoul_client_verify')
    assert [sign_meta,verify_meta] == old['evp_profile_metadata']
    pure=ROOT/'outputs/analysis/contextual_signature_selector/itail_full_matrix/itail_all_rows_seoul.csv'
    composite=ROOT/'outputs/analysis/composite_chain_length_overhead/composite_chain_detail.csv'
    bundles,provenance,exclusions=prepare5(snapshot,pure,composite,sign,verify)
    outcomes=all_run_outcomes(snapshot,bundles)
    args.output_dir.mkdir(parents=True,exist_ok=False)
    (args.output_dir/'models').mkdir()
    save_json(args.output_dir/'cost_provenance.json',provenance)
    save_json(args.output_dir/'decision_contexts.json',[{'id':b['id'],'key':b['key'],'x':b['x'].tolist(),
        'rtt_values':b['rtt_values'],'rtt_mismatch':b['rtt_mismatch'],
        'candidates':list(b['episode'].candidates)} for b in bundles])
    print(f'Prepared {len(bundles)} contexts, {len(actions)} actions; same snapshot as legacy3',flush=True)
    test_rows=[];validation_rows=[];fold_rows=[]
    for fold,test_region in enumerate(REGIONS):
        validation_region=REGIONS[(fold+1)%5]
        for level in BASELINES:
            print(f'Fold {fold+1}/5 {test_region} {level}: tuning; elapsed {time.monotonic()-start:.1f}s',flush=True)
            bs=[b for b in bundles if b['episode'].level==level]
            tuning=[b for b in bs if b['episode'].region not in {test_region,validation_region}]
            validation=[b for b in bs if b['episode'].region==validation_region]
            fitting=[b for b in bs if b['episode'].region!=test_region]
            testing=[b for b in bs if b['episode'].region==test_region]
            assert {b['id'] for b in fitting}.isdisjoint(b['id'] for b in testing)
            tuning_bounds=fit_bounds(tuning)
            tuning_choices=action_choices(tuning+validation,tuning_bounds,actions)
            tuning_outcomes={b['id']:outcomes[b['id']] for b in tuning}
            for alpha in ALPHAS:
                for seed in SEEDS:
                    agent=train(tuning,tuning_outcomes,tuning_choices,alpha,seed,actions,args.feedback_mode)
                    validation_rows.append({'fold':fold,'level':level,'test_region':test_region,
                        'validation_region':validation_region,'alpha':alpha,'seed':seed,
                        'validation_tls_ms':policy_mean(agent,validation,outcomes,tuning_choices)})
            best=min(ALPHAS,key=lambda a:statistics.fmean(r['validation_tls_ms'] for r in validation_rows
                if r['fold']==fold and r['level']==level and r['alpha']==a))
            bounds=fit_bounds(fitting); choices=action_choices(fitting+testing,bounds,actions)
            fit_outcomes={b['id']:outcomes[b['id']] for b in fitting}
            for seed in SEEDS:
                agent=train(fitting,fit_outcomes,choices,best,seed,actions,args.feedback_mode)
                test_rows.extend(evaluate(agent,testing,outcomes,choices,seed,fold,actions))
                save_json(args.output_dir/'models'/f'fold{fold}_{test_region}_{level}_seed{seed}.json',{
                    **agent.to_json(),'score_variant':'tail5','score_features':FEATURES,
                    'fold':fold,'held_out_region':test_region,'level':level,'seed':seed,
                    'feedback_mode':args.feedback_mode,'observation_sessions':35*len(fitting),
                    'feature_bounds':{'minimum':bounds[0].tolist(),'maximum':bounds[1].tolist()},
                    'normalization':'train minmax clip for first four; raw binary I_tail',
                    'snapshot_sha256':snapshot_hash,'frozen_evaluation_policy':'UCB_argmax_no_updates_matches_previous_protocol'})
            fold_rows.append({'fold':fold,'level':level,'fit_regions':';'.join(r for r in REGIONS if r!=test_region),
                'test_region':test_region,'validation_region_during_tuning':validation_region,
                'selected_alpha':best,'fit_contexts':len(fitting),'test_contexts':len(testing)})
            print(f'Fold {fold+1}/5 {test_region} {level}: complete alpha={best}; elapsed {time.monotonic()-start:.1f}s',flush=True)
    write_csv(args.output_dir/'test_decisions.csv',test_rows)
    write_csv(args.output_dir/'validation_search.csv',validation_rows)
    write_csv(args.output_dir/'fold_summary.csv',fold_rows)
    rl=statistics.fmean(r['rl_tls_ms'] for r in test_rows)
    oracle=statistics.fmean(r['oracle_tls_ms_evaluator_only'] for r in test_rows)
    fixed=statistics.fmean(r['mldsa_tls_ms'] for r in test_rows)
    metrics={'model':'disjoint LinUCB weight selector','score_variant':'tail5','score_features':FEATURES,
        'score_formula':'sum(w_j*N_j(f_j), j=1..4) + w5*I_tail; no overlap subtraction, no tail*sign addition',
        'actions':len(actions),'action_step':args.action_step,'context_input':'RTT,BW only, unchanged',
        'feedback_mode':args.feedback_mode,
        'snapshot_path':str(args.snapshot),'snapshot_sha256':snapshot_hash,'comparison_dir':str(args.comparison_dir),
        'split':old['split'],'run_split':old['run_split'],'seeds':list(SEEDS),'alphas':list(ALPHAS),
        'included_icas':snapshot['included_icas'],'included_ica_loss_pairs':snapshot['included_ica_loss_pairs'],
        'included_bandwidths_mbps':snapshot['included_bandwidths_mbps'],'source_algorithm_conditions':len(snapshot['conditions']),
        'source_raw_samples':len(snapshot['conditions'])*50,'excluded_HAWK_conditions':len(exclusions),'eligible_algorithms':141,
        'decision_contexts':len(bundles),'test_decisions':len(test_rows),'rtt_mismatch_contexts':sum(b['rtt_mismatch'] for b in bundles),
        'mean_rl_tls_ms':rl,'mean_oracle_tls_ms':oracle,'mean_regret_ms':rl-oracle,
        'mean_mldsa_tls_ms':fixed,'reduction_vs_mldsa_pct':100*(fixed-rl)/fixed,
        'evp_profile_metadata':[sign_meta,verify_meta],'elapsed_seconds':time.monotonic()-start,
        'source_hashes':{str(f):hashlib.sha256(f.read_bytes()).hexdigest() for f in (
            Path(__file__),pure,composite,ROOT/'rl_weight_selector/retrain_ica12.py',
            ROOT/'rl_weight_selector/partial_feedback_linucb.py',ROOT/'rl_weight_selector/region_holdout_unified_evp.py',
            ROOT/'contextual_signature_selector/selector.py')},
        'limitations':old['important_limitations']+[
            f'{len(actions)} arms versus 66; exploration budget differs by action representation',
            'Same-certificate sharing propagates one observed TLS value only to arms that select that exact certificate',
            'This comparison changes the entire cost decomposition, not just I_tail',
            'Chain verification remains an EVP single-verify times certificate-count proxy',
            'I_tail is the existing size/buffer heuristic, not a new per-session observation',
            'Full 50-run offline trimming is preprocessing, not available online future feedback']}
    save_json(args.output_dir/'metrics.json',metrics)
    print(json.dumps({'rl_ms':rl,'oracle_ms':oracle,'gap_ms':rl-oracle,'elapsed_seconds':metrics['elapsed_seconds']}),flush=True)


if __name__=='__main__':main()
