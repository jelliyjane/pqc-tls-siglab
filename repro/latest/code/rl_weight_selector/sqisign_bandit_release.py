"""Portable four/five-term Bandit replay on prepared, provenance-checked inputs.

Reuses the existing agent, action grid, normalization and selected-feedback update.
No network access or live experiment/model mutation. Each output must be new.
"""
import argparse
import csv
from collections import Counter
from dataclasses import asdict
import gzip
import hashlib
import json
import math
from pathlib import Path
import random
import statistics
import time
import numpy as np

from rl_weight_selector.bw147_interim_linucb import InterimEpisode
from rl_weight_selector.partial_feedback_linucb import LinUCBAgent
from rl_weight_selector.retrain_ica12 import ALPHAS, SEEDS, BASELINES
from rl_weight_selector.region_holdout_unified_evp import REGIONS, write_csv
from rl_weight_selector.tail5_region_holdout import (
    ACTIONS, FEATURES, fit_bounds, action_choices, train, policy_mean, evaluate, save_json,
)

CONTEXT_VERSIONS = ('legacy4', 'loss5-unclipped', 'loss5-probability-unclipped')
LEGACY_FEATURES = ['bias', 'log_rtt', 'log_bandwidth', 'log_rtt_x_log_bandwidth']


def score_actions(terms):
    if terms == 5:
        return ACTIONS
    if terms == 4:
        # Same 0.1 simplex grid, with the removed tail coordinate omitted.
        return [w[:4] for w in ACTIONS if w[4] == 0.]
    raise ValueError('Expected four or five score terms')


def score_bounds(bundles, terms):
    if terms == 5:
        return fit_bounds(bundles)
    if terms != 4:
        raise ValueError('Expected four or five score terms')
    features=np.array([c['features'][:4] for b in bundles for c in b['episode'].candidates])
    return features.min(axis=0),features.max(axis=0)


def score_choices(bundles, bounds, actions, terms):
    if terms == 5:
        return action_choices(bundles,bounds,actions)
    if terms != 4:
        raise ValueError('Expected four or five score terms')
    low,high=bounds
    result={}
    for b in bundles:
        candidates=b['episode'].candidates
        raw=np.array([c['features'][:4] for c in candidates])
        costs=np.clip(np.divide(raw-low,high-low,out=np.zeros_like(raw),where=high>low),0.,1.)
        # Tail must not affect either the score or the cost-sum tie break.
        result[b['id']]=np.array([min(range(len(candidates)),key=lambda i:(
            float(np.dot(w,costs[i])),float(costs[i].sum()),candidates[i]['algorithm'])) for w in actions])
    return result


def context_spec(version):
    if version not in CONTEXT_VERSIONS:
        raise ValueError(f'Unknown context version: {version}')
    probability = version == 'loss5-probability-unclipped'
    return dict(version=version,
        features=LEGACY_FEATURES + ([] if version == 'legacy4' else
                                  ['loss_probability' if probability else 'loss_percent']),
        rtt_reference_ms=300., bandwidth_reference_mbps=1000.,
        transform='log1p(value)/log1p(reference)',
        clip=version == 'legacy4', loss_reference_percent=100. if probability else 1.,
        loss_source='configured experiment loss, not an online loss estimator',
        cost_normalization='unchanged training-only minmax with clipping; binary tail unchanged')


def loss_context(episode, loss_reference_percent=1.):
    """Five features; divide percentage-point loss by the explicit reference.

    Reference 1 preserves percentage points; reference 100 gives probability.
    """
    if not math.isfinite(loss_reference_percent) or loss_reference_percent <= 0:
        raise ValueError('Loss reference must be finite and positive')
    rtt, bw, loss = map(float, (episode.rtt_ms, episode.bandwidth_mbps, episode.loss_percent))
    if not all(math.isfinite(v) for v in (rtt, bw, loss)) or rtt < 0 or bw <= 0 or not 0 <= loss <= 100:
        raise ValueError('Expected finite RTT >= 0, BW > 0, and loss percent in [0,100]')
    r = math.log1p(rtt) / math.log1p(300.)
    b = math.log1p(bw) / math.log1p(1000.)
    return np.asarray([1., r, b, r*b, loss/loss_reference_percent], dtype=float)


def group(b):
    e=b['episode']
    return (e.region,e.certificate_mode,e.loss_percent,e.bandwidth_mbps)


def assignments(bundles):
    result={}
    for ri,region in enumerate(REGIONS):
        groups=sorted({group(b) for b in bundles if b['episode'].region==region})
        assert len(groups)==32
        random.Random(20260927+ri).shuffle(groups)
        for i,g in enumerate(groups):result[g]=(i+2*ri)%5
    assert Counter(result.values())=={i:32 for i in range(5)}
    return result


def split(bundles, fold, mode, assignment):
    if mode=='region':
        test=REGIONS[fold];val=REGIONS[(fold+1)%5]
        return ([b for b in bundles if b['episode'].region not in (test,val)],
                [b for b in bundles if b['episode'].region==val],
                [b for b in bundles if b['episode'].region!=test],
                [b for b in bundles if b['episode'].region==test])
    test_groups={g for g,f in assignment.items() if f==fold}
    fit_groups=set(assignment)-test_groups;val_groups=set()
    for ri,region in enumerate(REGIONS):
        pool=sorted(g for g in fit_groups if g[0]==region)
        random.Random(20261000+10*fold+ri).shuffle(pool)
        val_groups.update(pool[:5])
    return ([b for b in bundles if group(b) in fit_groups-val_groups],
            [b for b in bundles if group(b) in val_groups],
            [b for b in bundles if group(b) in fit_groups],
            [b for b in bundles if group(b) in test_groups])


def load_input(path):
    with gzip.open(path,'rt') as f:data=json.load(f)
    bundles=[];outcomes={}
    for row in data['contexts']:
        e=InterimEpisode(**row['episode'])
        b={k:row[k] for k in ('id','rtt_values','rtt_mismatch')}
        b.update(episode=e,x=np.asarray(row['x']))
        matrix=np.asarray(row['retained_tls_ms'])
        assert matrix.shape==(len(e.candidates),35) and np.all(np.isfinite(matrix)) and np.all(matrix>0)
        bundles.append(b);outcomes[b['id']]=matrix
    assert len(bundles)==len(outcomes)==1440
    return data,bundles,outcomes


def add_certificate_verify(bundles, input_dir):
    """Add one measured EVP CV verification; preserve the frozen input on disk.

    This campaign sends leaf + intermediates, not the trusted root. Chain
    verification remains a proxy using that same per-signature EVP timing.
    """
    provenance=json.loads((input_dir/'provenance.json').read_text())
    counts={};times={};hashes={}
    for name in ('pure_costs.csv','composite_costs.csv','seoul_client_verify.csv'):
        path=input_dir/name
        hashes[name]=hashlib.sha256(path.read_bytes()).hexdigest()
        assert hashes[name]==provenance['inputs_sha256'][name], name
        with path.open() as f:
            for row in csv.DictReader(f):
                if name=='seoul_client_verify.csv':
                    times[row['algorithm']]=float(row['verify_mean_ms'])
                else:
                    key=(row['algorithm'],row['certificate_mode'])
                    n=int(row['sent_cert_count'])
                    assert n==int(row['certificate_mode'].removesuffix('ICA'))+1
                    assert counts.setdefault(key,n)==n
    audit=[]
    for bundle in bundles:
        e=bundle['episode']
        for candidate in e.candidates:
            name=candidate['algorithm'];n=counts[name,e.certificate_mode];v=times[name]
            assert math.isfinite(v) and v>=0
            features=list(candidate['features'])
            old=features[3]
            assert math.isclose(old,n*v,rel_tol=1e-12,abs_tol=1e-12)
            features[3]=(n+1)*v
            candidate['features']=features
            audit.append(dict(episode_id=bundle['id'],algorithm=name,sent_cert_count=n,
                per_signature_verify_ms=v,old_verify_chain_ms=old,new_verify_total_ms=features[3]))
    return audit,hashes


def run(path,out,mode,context_version='legacy4',score_terms=5,verification_cost='chain-only'):
    start=time.monotonic();data,bundles,outcomes=load_input(path)
    input_sha256=hashlib.sha256(path.read_bytes()).hexdigest()
    spec=context_spec(context_version)
    actions=score_actions(score_terms)
    score_features=FEATURES[:score_terms]
    verification_hashes={};verification_audit=[]
    if verification_cost=='chain-plus-cv':
        if score_terms!=4:
            raise ValueError('CertificateVerify correction is supported for the four-term model')
        verification_audit,verification_hashes=add_certificate_verify(bundles,path.parent)
        score_features=(*FEATURES[:3],'verify_total_ms')
        data['limitations']=[v for v in data['limitations'] if not v.startswith('Chain verification is')]
        data['limitations'].append('Verification cost is (sent certificate count + 1) times the measured CertificateVerify EVP verification time. Root excluded; same per-signature timing approximates all chain signatures, not a whole-chain measurement.')
    elif verification_cost!='chain-only':
        raise ValueError('Unknown verification cost version')
    if score_terms == 4:
        spec['cost_normalization']='training-only minmax with clipping for all four costs; no tail'
    if context_version != 'legacy4':
        for bundle in bundles:
            bundle['x']=loss_context(bundle['episode'],spec['loss_reference_percent'])
    dimension=len(spec['features'])
    assert all(b['x'].shape==(dimension,) for b in bundles)
    out.mkdir(parents=True,exist_ok=False);(out/'models').mkdir()
    if verification_audit:
        write_csv(out/'verification_cost_audit.csv',verification_audit)
    save_json(out/'context_spec.json',spec)
    save_json(out/'decision_contexts.json',[dict(id=b['id'],x=b['x'].tolist(),
        rtt_ms=b['episode'].rtt_ms,bandwidth_mbps=b['episode'].bandwidth_mbps,
        loss_percent=b['episode'].loss_percent) for b in bundles])
    assignment=assignments(bundles)
    save_json(out/'split_manifest.json',[dict(group=g,test_fold=f) for g,f in sorted(assignment.items())]
              if mode=='condition' else [dict(fold=i,test_region=r,validation_region=REGIONS[(i+1)%5]) for i,r in enumerate(REGIONS)])
    tests=[];searches=[];folds=[];verified=0
    for fold in range(5):
        for level in BASELINES:
            bs=[b for b in bundles if b['episode'].level==level]
            tuning,validation,fitting,testing=split(bs,fold,mode,assignment)
            assert len(fitting)==384 and len(testing)==96
            assert {b['id'] for b in fitting}.isdisjoint(b['id'] for b in testing)
            assert {b['id'] for b in tuning}.isdisjoint(b['id'] for b in validation)
            print(mode,fold,level,'tuning',round(time.monotonic()-start,1),flush=True)
            tb=score_bounds(tuning,score_terms);tc=score_choices(tuning+validation,tb,actions,score_terms)
            for alpha in ALPHAS:
                for seed in SEEDS:
                    agent=train(tuning,{b['id']:outcomes[b['id']] for b in tuning},tc,alpha,seed,actions=actions)
                    searches.append(dict(fold=fold,level=level,alpha=alpha,seed=seed,
                        validation_tls_ms=policy_mean(agent,validation,outcomes,tc)))
            best=min(ALPHAS,key=lambda a:statistics.fmean(r['validation_tls_ms'] for r in searches
                     if r['fold']==fold and r['level']==level and r['alpha']==a))
            bounds=score_bounds(fitting,score_terms);choices=score_choices(fitting+testing,bounds,actions,score_terms)
            for seed in SEEDS:
                agent=train(fitting,{b['id']:outcomes[b['id']] for b in fitting},choices,best,seed,actions=actions)
                result=evaluate(agent,testing,outcomes,choices,seed,fold,actions=actions)
                for r in result:
                    r['split_type']=mode
                    if mode=='condition':r.pop('held_out_region')
                checkpoint={**agent.to_json(),'score_features':score_features,'score_terms':score_terms,'feedback_mode':'selected-action',
                    'verification_cost':verification_cost,'verification_profile_sha256':verification_hashes,
                    'context_features':spec['features'],'context_spec':spec,'context_dimension':dimension,
                    'fold':fold,'level':level,'seed':seed,'split_type':mode,
                    'feature_bounds':dict(minimum=bounds[0].tolist(),maximum=bounds[1].tolist()),
                    'input_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
                    'fit_contexts':[b['id'] for b in fitting],'test_contexts':[b['id'] for b in testing]}
                model=out/'models'/f'fold{fold}_{level}_seed{seed}.json'
                save_json(model,checkpoint)
                restored=json.loads(model.read_text())
                replay=LinUCBAgent(restored['actions'],dimension,restored['alpha'])
                replay.a_inverse=np.asarray(restored['a_inverse']);replay.b=np.asarray(restored['b'])
                # Recompute action/candidate from the saved checkpoint, not in-memory agent.
                for b,r in zip(testing,result):
                    action=replay.select(b['x'])[0];index=int(choices[b['id']][action])
                    assert action==r['action'] and b['episode'].candidates[index]['algorithm']==r['rl_algorithm']
                    assert abs(outcomes[b['id']][index].mean()-r['rl_tls_ms'])<1e-9
                    verified+=1
                tests.extend(result)
            folds.append(dict(fold=fold,level=level,selected_alpha=best,fit_contexts=len(fitting),
                              test_contexts=len(testing),tune_contexts=len(tuning),validation_contexts=len(validation)))
    assert len(tests)==verified==7200
    assert max(Counter((r['episode_id'],r['seed']) for r in tests).values())==1
    for filename,rows in [('test_decisions.csv',tests),('validation_search.csv',searches),('fold_summary.csv',folds)]:
        write_csv(out/filename,rows)
    metrics=dict(model=f'{score_terms}-term disjoint LinUCB weight selector',pareto_filter=False,split_type=mode,
        verification_cost=verification_cost,verification_profile_sha256=verification_hashes,
        split_seed=20260927 if mode=='condition' else None,actions=len(actions),action_step=.1,
        score_features=score_features,score_terms=score_terms,feedback_mode='selected-action',reward='-observed_tls_ms/1000',
        context_features=spec['features'],context_spec=spec,context_dimension=dimension,
        seeds=list(SEEDS),alphas=list(ALPHAS),ridge=1.,raw_catalog_algorithms=156,eligible_algorithms=150,
        excluded_HAWK_algorithms=6,source_conditions=24960,source_raw_samples=1248000,
        retained_runs_per_condition=35,models=75,test_decisions=len(tests),
        mean_rl_tls_ms=statistics.fmean(r['rl_tls_ms'] for r in tests),
        mean_oracle_tls_ms=statistics.fmean(r['oracle_tls_ms_evaluator_only'] for r in tests),
        mean_mldsa_tls_ms=statistics.fmean(r['mldsa_tls_ms'] for r in tests),
        sqisign_selected_decisions=sum('sqisign' in r['rl_algorithm'] for r in tests),
        verified_checkpoint_decisions=verified,elapsed_seconds=time.monotonic()-start,
        input_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        limitations=data['limitations'],input_source_snapshot_sha256=data['source_snapshot_sha256'])
    metrics['mean_regret_ms']=metrics['mean_rl_tls_ms']-metrics['mean_oracle_tls_ms']
    assert hashlib.sha256(path.read_bytes()).hexdigest()==input_sha256
    metrics['source_hashes']={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in (
        Path(__file__),Path(__file__).with_name('tail5_region_holdout.py'),
        Path(__file__).with_name('partial_feedback_linucb.py'))}
    save_json(out/'metrics.json',metrics)
    print(json.dumps(metrics),flush=True)


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--input',type=Path,required=True)
    p.add_argument('--output-dir',type=Path,required=True);p.add_argument('--split',choices=['region','condition'],required=True)
    p.add_argument('--context',choices=CONTEXT_VERSIONS,default='legacy4')
    p.add_argument('--score-terms',choices=[4,5],type=int,default=5)
    p.add_argument('--verification-cost',choices=['chain-only','chain-plus-cv'],default='chain-only')
    a=p.parse_args();run(a.input,a.output_dir,a.split,a.context,a.score_terms,a.verification_cost)
