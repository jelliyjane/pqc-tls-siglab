"""Verify release hashes, raw-to-replay values and saved model decisions."""
import csv
import gzip
import hashlib
import json
from pathlib import Path
import sys
import tarfile
import numpy as np

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
DATA=ROOT/'results/bandit_sqisign_20261003'
sys.path.insert(0,str(HERE/'code'))
from rl_weight_selector.sqisign_bandit_release import load_input, assignments, split
from rl_weight_selector.partial_feedback_linucb import LinUCBAgent
from rl_weight_selector.tail5_region_holdout import normalize


def main():
    for directory in (HERE,DATA):
        for line in (directory/'SHA256SUMS').read_text().splitlines():
            digest,name=line.split('  ',1);p=directory/name
            assert p.resolve().is_relative_to(directory.resolve())
            assert hashlib.sha256(p.read_bytes()).hexdigest()==digest,name
    metadata,bundles,outcomes=load_input(DATA/'inputs/prepared.json.gz')
    with gzip.open(DATA/'inputs/tls_all50.json.gz','rt') as f:raw=json.load(f)
    assert len(raw)==24960
    lookup={}
    for r in raw:
        key=(r['region'],r['certificate_mode'].removeprefix('chain').upper(),r['loss_percent'],r['bandwidth_mbps'],r['algorithm'])
        assert key not in lookup
        values={int(s['run']):float(s['elapsed_ms']) for s in r['samples']}
        assert len(r['samples'])==len(values)==50 and set(values)==set(range(1,51))
        keep=set(sorted(values,key=lambda run:(values[run],run))[:35])
        lookup[key]=[values[i] for i in range(1,51) if i in keep]
    for b in bundles:
        e=b['episode']
        for i,c in enumerate(e.candidates):
            key=(e.region,e.certificate_mode,e.loss_percent,e.bandwidth_mbps,c['algorithm'])
            np.testing.assert_array_equal(outcomes[b['id']][i],lookup[key])
    assert len({c['algorithm'] for b in bundles for c in b['episode'].candidates})==150
    assert len({c['algorithm'] for b in bundles for c in b['episode'].candidates if 'sqisign' in c['algorithm']})==9
    assignment=assignments(bundles);by_id={b['id']:b for b in bundles}
    result={}
    for mode in ('region','condition'):
        folder=DATA/mode
        with (folder/'test_decisions.csv').open() as f:rows=list(csv.DictReader(f))
        records={(int(r['fold']),r['level'],int(r['seed']),r['episode_id']):r for r in rows}
        assert len(rows)==len(records)==7200
        verified=0;models=0
        with tarfile.open(folder/'models.tar.gz','r:gz') as archive:
            for item in archive.getmembers():
                assert item.isfile() and item.name.startswith('models/') and item.name.endswith('.json')
                model=json.load(archive.extractfile(item));models+=1
                bs=[b for b in bundles if b['episode'].level==model['level']]
                _,_,fit,test=split(bs,model['fold'],mode,assignment)
                assert model['fit_contexts']==[b['id'] for b in fit]
                assert model['test_contexts']==[b['id'] for b in test]
                assert model['total_updates']==35*len(fit)
                agent=LinUCBAgent(model['actions'],4,model['alpha'])
                agent.a_inverse=np.asarray(model['a_inverse']);agent.b=np.asarray(model['b'])
                bounds=tuple(np.asarray(model['feature_bounds'][k]) for k in ('minimum','maximum'))
                for b in test:
                    r=records[model['fold'],model['level'],model['seed'],b['id']]
                    action=agent.select(b['x'])[0]
                    cs=b['episode'].candidates;costs=normalize([c['features'] for c in cs],bounds)
                    chosen=min(range(len(cs)),key=lambda i:(float(np.dot(model['actions'][action],costs[i])),float(costs[i].sum()),cs[i]['algorithm']))
                    assert int(r['action'])==action and r['rl_algorithm']==cs[chosen]['algorithm']
                    assert abs(float(r['rl_tls_ms'])-outcomes[b['id']][chosen].mean())<1e-8
                    assert abs(float(r['oracle_tls_ms_evaluator_only'])-outcomes[b['id']].mean(axis=1).min())<1e-8
                    verified+=1
        assert models==75 and verified==7200
        metrics=json.loads((folder/'metrics.json').read_text())
        assert abs(metrics['mean_rl_tls_ms']-np.mean([float(r['rl_tls_ms']) for r in rows]))<1e-8
        result[mode]=dict(models=models,verified_decisions=verified,sqisign_selected=metrics['sqisign_selected_decisions'])
    print(json.dumps(dict(raw_conditions=len(raw),raw_samples=len(raw)*50,checks=result),indent=2))


if __name__=='__main__':main()
