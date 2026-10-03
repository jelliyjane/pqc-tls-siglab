"""Portable five-term Bandit-only replay on prepared, provenance-checked inputs.

Reuses the existing agent, action grid, normalization and selected-feedback update.
No network access or live experiment/model mutation. Each output must be new.
"""
import argparse
from collections import Counter
from dataclasses import asdict
import gzip
import hashlib
import json
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


def run(path,out,mode):
    start=time.monotonic();data,bundles,outcomes=load_input(path)
    out.mkdir(parents=True,exist_ok=False);(out/'models').mkdir()
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
            tb=fit_bounds(tuning);tc=action_choices(tuning+validation,tb)
            for alpha in ALPHAS:
                for seed in SEEDS:
                    agent=train(tuning,{b['id']:outcomes[b['id']] for b in tuning},tc,alpha,seed)
                    searches.append(dict(fold=fold,level=level,alpha=alpha,seed=seed,
                        validation_tls_ms=policy_mean(agent,validation,outcomes,tc)))
            best=min(ALPHAS,key=lambda a:statistics.fmean(r['validation_tls_ms'] for r in searches
                     if r['fold']==fold and r['level']==level and r['alpha']==a))
            bounds=fit_bounds(fitting);choices=action_choices(fitting+testing,bounds)
            for seed in SEEDS:
                agent=train(fitting,{b['id']:outcomes[b['id']] for b in fitting},choices,best,seed)
                result=evaluate(agent,testing,outcomes,choices,seed,fold)
                for r in result:
                    r['split_type']=mode
                    if mode=='condition':r.pop('held_out_region')
                checkpoint={**agent.to_json(),'score_features':FEATURES,'feedback_mode':'selected-action',
                    'fold':fold,'level':level,'seed':seed,'split_type':mode,
                    'feature_bounds':dict(minimum=bounds[0].tolist(),maximum=bounds[1].tolist()),
                    'input_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
                    'fit_contexts':[b['id'] for b in fitting],'test_contexts':[b['id'] for b in testing]}
                model=out/'models'/f'fold{fold}_{level}_seed{seed}.json'
                save_json(model,checkpoint)
                restored=json.loads(model.read_text())
                replay=LinUCBAgent(restored['actions'],4,restored['alpha'])
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
    metrics=dict(model='five-term disjoint LinUCB weight selector',pareto_filter=False,split_type=mode,
        split_seed=20260927 if mode=='condition' else None,actions=len(ACTIONS),action_step=.1,
        score_features=FEATURES,feedback_mode='selected-action',reward='-observed_tls_ms/1000',
        context_features=['bias','log_rtt','log_bandwidth','log_rtt_x_log_bandwidth'],
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
    save_json(out/'metrics.json',metrics)
    print(json.dumps(metrics),flush=True)


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--input',type=Path,required=True)
    p.add_argument('--output-dir',type=Path,required=True);p.add_argument('--split',choices=['region','condition'],required=True)
    a=p.parse_args();run(a.input,a.output_dir,a.split)
