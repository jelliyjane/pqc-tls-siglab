"""Selected-scope LinUCB replay with immutable legacy or unified EVP costs.

Never updates live models, source measurements, or experiment scheduling.
Training only receives the selected outcome from the train/fit partition.
Validation chooses alpha and fixed comparators; test is evaluation-only.
"""
from __future__ import annotations
import argparse
import csv
from collections import Counter, defaultdict
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import random
import statistics
import numpy as np

from contextual_signature_selector.selector import NetworkContext, SelectorConstants, score_row
from rl_weight_selector.bandit import action_grid
from rl_weight_selector.partial_feedback_linucb import LinUCBAgent, context_vector
from rl_weight_selector.bw147_interim_linucb import InterimEpisode
from rl_weight_selector.screen_composite_vs_deterministic import Bounds, normalize, raw_features

ROOT = Path(__file__).resolve().parents[1]
BASELINES = {'L1': 'mldsa44', 'L3': 'mldsa65', 'L5': 'mldsa87'}
SEEDS = (42, 43, 44, 45, 46)
ALPHAS = (.01, .05, .1, .25)
ACTIONS = action_grid(.1)
COHORT_FIELDS = ('level', 'suite', 'certificate_mode', 'loss_percent', 'bandwidth_mbps', 'region')


def save_json(path, data):
    with path.open('x') as f:
        json.dump(data, f, ensure_ascii=False, indent=2, allow_nan=False);f.write('\n')


def rows(path):
    with path.open(newline='') as f:return list(csv.DictReader(f))


def file_sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_evp_averages(profile_dir, expected_role, expected_count=147):
    manifests=sorted(profile_dir.glob('manifest.*.json'))
    if len(manifests)!=1:raise ValueError(f'Expected one finalized manifest in {profile_dir}, found {len(manifests)}')
    manifest_path=manifests[0];manifest=json.loads(manifest_path.read_text())
    if manifest.get('profile_role')!=expected_role:raise ValueError(f'Expected role {expected_role}: {manifest_path}')
    if (manifest.get('target_count'),manifest.get('success_count'),manifest.get('failed_count'),manifest.get('missing_count'))!=(expected_count,expected_count,0,0):
        raise ValueError(f'EVP profile is not complete: {manifest_path}')
    averages_path=profile_dir/manifest['averages_file']
    if file_sha256(averages_path)!=manifest['averages_sha256']:raise ValueError(f'Averages hash mismatch: {averages_path}')
    data={r['algorithm']:r for r in rows(averages_path)}
    if len(data)!=expected_count:raise ValueError(f'Expected {expected_count} unique EVP rows: {averages_path}')
    for algorithm,row in data.items():
        if int(row['samples'])!=50:raise ValueError(f'Expected 50 EVP samples for {algorithm}')
        for field in ('sign_mean_ms','verify_mean_ms','signature_bytes_mean'):
            if not np.isfinite(float(row[field])) or float(row[field])<=0:raise ValueError(f'Invalid {field} for {algorithm}')
    return data,{'profile_dir':str(profile_dir),'manifest':str(manifest_path),'averages':str(averages_path),
                 'profile_role':expected_role,'manifest_sha256':file_sha256(manifest_path),
                 'averages_sha256':file_sha256(averages_path),'protocol':manifest.get('protocol')}


def write_csv(path, data):
    if not data:return
    with path.open('x', newline='') as f:
        w=csv.DictWriter(f, fieldnames=list(data[0]));w.writeheader();w.writerows(data)


def cohort(record):
    # Historical comparator convention only; preserve original L2 in source metadata.
    return 'L1' if record['pqc_algorithm']=='mldsa44' else record['security_level']


def cost_rows(pure_path, composite_path, sign_costs=None, verify_costs=None):
    pure={(r['algorithm'],r['certificate_mode']):r for r in rows(pure_path) if r['family']=='pure'}
    composite={(r['region'].lower(),r['algorithm'],r['certificate_mode']):r for r in rows(composite_path)}
    if (sign_costs is None)!=(verify_costs is None):raise ValueError('Both server-sign and client-verify profiles are required')
    if sign_costs is not None:
        if set(sign_costs)!=set(verify_costs):raise ValueError('Server-sign and client-verify algorithm sets differ')
        for key,row in list(pure.items()):
            algorithm=key[0]
            if algorithm not in sign_costs:raise ValueError(f'Missing unified EVP cost: {algorithm}')
            pure[key]={**row,'sign_ms':sign_costs[algorithm]['sign_mean_ms'],
                       'verify_ms':verify_costs[algorithm]['verify_mean_ms'],
                       'signature_bytes':sign_costs[algorithm]['signature_bytes_mean'],
                       '_server_sign_origin':'unified_EVP_server_sign',
                       '_client_verify_origin':'unified_EVP_seoul_client_verify'}
        for key,row in list(composite.items()):
            algorithm=key[1]
            if algorithm not in sign_costs:raise ValueError(f'Missing unified EVP cost: {algorithm}')
            composite[key]={**row,'actual_sign_ms':sign_costs[algorithm]['sign_mean_ms'],
                            'actual_verify_ms':verify_costs[algorithm]['verify_mean_ms'],
                            'signature_size_bytes':sign_costs[algorithm]['signature_bytes_mean'],
                            'cost_measurement_backend':'unified_EVP_in_process',
                            '_server_sign_origin':'unified_EVP_server_sign',
                            '_client_verify_origin':'unified_EVP_seoul_client_verify'}
    return pure,composite


def prepare(snapshot, pure_path, composite_path, sign_costs=None, verify_costs=None):
    scope_pairs={(int(pair['ica']),int(pair['loss_percent']))
                 for pair in snapshot.get('included_ica_loss_pairs', [])}
    if not scope_pairs:
        scope_pairs={(int(ica),loss) for ica in snapshot.get('included_icas', []) for loss in (0,1)}
    if not scope_pairs:raise ValueError('Input snapshot has no explicit ICA/loss scope')
    bandwidths=snapshot.get('included_bandwidths_mbps', [1,5,50])
    if len(bandwidths)!=len(set(bandwidths)) or not bandwidths:
        raise ValueError('Invalid bandwidth scope')
    declared=snapshot.get('expected_algorithms')
    if declared is not None:
        if not isinstance(declared,list) or len(declared)!=len(set(declared)) or not declared:
            raise ValueError('Expected an explicit unique algorithm list')
        if {r['algorithm'] for r in snapshot['conditions']}!=set(declared):
            raise ValueError('Snapshot algorithms do not match the declared candidate set')
    expected_conditions=len(scope_pairs)*5*len(bandwidths)*(len(declared) if declared is not None else 147)
    if len(snapshot['conditions'])!=expected_conditions:
        raise ValueError(f'Expected {expected_conditions} conditions for selected scope')
    pure, composite=cost_rows(pure_path,composite_path,sign_costs,verify_costs)
    groups=defaultdict(list);outcomes={};provenance=[];exclusions=[]
    for record in snapshot['conditions']:
        pair=(int(record['certificate_mode'].removeprefix('chain').removesuffix('ica')),int(record['loss_percent']))
        if pair not in scope_pairs:raise ValueError('Out-of-scope ICA/loss record')
        if record['bandwidth_mbps'] not in bandwidths:raise ValueError('Out-of-scope bandwidth')
        if 'hawk' in record['algorithm']:
            exclusions.append({'algorithm':record['algorithm'],'reason':'existing_HAWK_exclusion_policy'});continue
        if record['status']!='ready':raise ValueError('Incomplete requested matrix: '+str(record))
        level=cohort(record)
        if level not in BASELINES:raise ValueError('Unmapped security cohort')
        family=record['classical_algorithm']
        key=(level,family,record['certificate_mode'],record['loss_percent'],record['bandwidth_mbps'],record['region'])
        groups[key].append(record)
    bundles=[]
    for key, records in sorted(groups.items()):
        level,family,mode,loss,bw,region=key
        records.sort(key=lambda r:r['algorithm'])
        rtts={r['rtt_ms'] for r in records}
        rtt=statistics.median(r['rtt_ms'] for r in records)
        mode_short=mode.removeprefix('chain').upper()
        network=NetworkContext(rtt,bw,16384,rtt);candidates=[]
        for record in records:
            if family=='pure':
                r=pure[(record['algorithm'],mode_short)]
                profile={'actual_chain_der_size_bytes':r['chain_bytes'], 'signature_size_bytes':r['signature_bytes'],
                         'sent_cert_count':r['sent_cert_count'],'actual_sign_ms':r['sign_ms'],'actual_verify_ms':r['verify_ms'],
                         '_server_sign_origin':r.get('_server_sign_origin','legacy_Seoul_Pure'),
                         '_client_verify_origin':r.get('_client_verify_origin','legacy_Seoul_Pure')}
                origin='unified_EVP_in_process' if sign_costs is not None else 'legacy_Seoul_Pure_profile_reused_across_regions'
            else:
                profile=composite[(region,record['algorithm'],mode_short)]
                origin=profile['cost_measurement_backend']
            for field in ('actual_chain_der_size_bytes','signature_size_bytes','sent_cert_count','actual_sign_ms','actual_verify_ms'):
                if not np.isfinite(float(profile[field])) or float(profile[field])<=0:raise ValueError('Invalid cost '+field)
            profile={**profile,'algorithm':record['algorithm'],'pqc_algorithm':record['pqc_algorithm'],
                     'classical_algorithm':family,'level':level,'certificate_mode':mode_short}
            scored=score_row(profile,network,SelectorConstants())
            candidates.append({'algorithm':record['algorithm'],'pqc_algorithm':record['pqc_algorithm'],
                               'features':raw_features(scored,rtt),
                               'deterministic_estimated_tls_ms':float(scored['estimated_tls_ms'])})
            provenance.append({'episode_key':list(key),'algorithm':record['algorithm'],
                               'original_security_level':record['security_level'],'cost_origin':origin,
                               'server_sign_origin':profile.get('_server_sign_origin',origin),
                               'client_verify_origin':profile.get('_client_verify_origin',origin),
                               'sign_ms':scored['sign_ms'],'verify_one_ms':scored['verify_one_ms'],
                               'signature_bytes':scored['signature_bytes'],'chain_bytes':scored['chain_bytes'],
                               'features':list(candidates[-1]['features'])})
        ep=InterimEpisode(region,mode_short,loss,level,family,
                          tuple(r['pqc_algorithm'] for r in records),rtt,bw,tuple(candidates))
        eid='|'.join(map(str,key)); parts={}
        for part in ('train','validation','fit','test'):
            parts[part]=np.array([[float(v['elapsed_ms']) for v in r['partitions'][part] if v['retained']] for r in records])
        outcomes[eid]=parts
        deterministic_index=min(range(len(candidates)),key=lambda i:(candidates[i]['deterministic_estimated_tls_ms'],candidates[i]['algorithm']))
        bundles.append({'id':eid,'key':key,'episode':ep,'x':context_vector(ep),'deterministic_index':deterministic_index,
                        'rtt_values':sorted(rtts),'rtt_mismatch':len(rtts)>1})
    # All eligible conditions must appear exactly once, not just a small full-family subset.
    eligible_conditions=expected_conditions-len(exclusions)
    assert sum(len(b['episode'].candidates) for b in bundles)==eligible_conditions
    return bundles,outcomes,provenance,exclusions


def configure_actions(bundles):
    features=np.array([c['features'] for b in bundles for c in b['episode'].candidates])
    bounds=Bounds(tuple(features.min(axis=0)),tuple(features.max(axis=0)))
    for b in bundles:
        candidates=b['episode'].candidates
        costs=np.array([normalize(c['features'],bounds) for c in candidates])
        b['choices']=np.array([min(range(len(candidates)),key=lambda i:(float(np.dot(w,costs[i])),float(costs[i].sum()),candidates[i]['algorithm'])) for w in ACTIONS])
    return bounds


class SelectedFeedback:
    """Only this partition is held by the training environment; no test values."""
    def __init__(self, outcomes, partition):
        if partition not in ('train','fit'):raise ValueError('Training cannot request evaluation partitions')
        self._samples={eid:parts[partition] for eid,parts in outcomes.items()}
        self.calls=0

    def reveal(self,eid,candidate_index,sample_index):
        self.calls+=1
        return -float(self._samples[eid][candidate_index,sample_index])/1000


def train(bundles,outcomes,partition,alpha,seed):
    feedback=SelectedFeedback(outcomes,partition)
    sample_count={'train':21,'fit':28}[partition]
    agent=LinUCBAgent(ACTIONS,4,alpha)
    order=list(range(sample_count));random.Random(seed*17).shuffle(order)
    for sample_index in order:
        episodes=list(bundles);random.Random(seed+sample_index*1009).shuffle(episodes)
        for b in episodes:
            action=agent.select(b['x'])[0]
            reward=feedback.reveal(b['id'],int(b['choices'][action]),sample_index)
            agent.update(action,b['x'],reward)
    assert agent.total_updates==feedback.calls==len(bundles)*sample_count
    return agent


def policy_mean(agent,bundles,outcomes,partition):
    return statistics.fmean(float(outcomes[b['id']][partition][b['choices'][agent.select(b['x'])[0]]].mean()) for b in bundles)


def frozen_comparators(bundles,outcomes):
    by_suite=defaultdict(list)
    for b in bundles:by_suite[b['episode'].classical_algorithm].append(b)
    fixed={}
    for suite,items in by_suite.items():
        inventories=[set(c['pqc_algorithm'] for c in b['episode'].candidates) for b in items]
        assert all(s==inventories[0] for s in inventories)
        def mean(pqc):
            return statistics.fmean(float(outcomes[b['id']]['validation'][next(i for i,c in enumerate(b['episode'].candidates) if c['pqc_algorithm']==pqc)].mean()) for b in items)
        fixed[suite]=min(inventories[0],key=lambda pqc:(mean(pqc),pqc))
    weight=min(range(len(ACTIONS)),key=lambda a:(statistics.fmean(float(outcomes[b['id']]['validation'][b['choices'][a]].mean()) for b in bundles),a))
    return fixed,weight


def evaluate(agent,bundles,outcomes,seed,fixed,fixed_weight):
    result=[]
    for b in bundles:
        ep=b['episode'];action=agent.select(b['x'])[0];ci=int(b['choices'][action]);test=outcomes[b['id']]['test']
        means=test.mean(axis=1); names=[c['pqc_algorithm'] for c in ep.candidates]
        baseline=names.index(BASELINES[ep.level]);fixed_i=names.index(fixed[ep.classical_algorithm]);det_i=int(b['deterministic_index'])
        greedy=int(b['choices'][int(agent.scores(b['x'])[1].argmax())])
        row={'episode_id':b['id'],'seed':seed,'level':ep.level,'suite':ep.classical_algorithm,
             'certificate_mode':ep.certificate_mode,'loss_percent':ep.loss_percent,'bandwidth_mbps':ep.bandwidth_mbps,
             'region':ep.region,'rtt_ms':ep.rtt_ms,'rtt_mismatch':b['rtt_mismatch'],'candidate_count':len(ep.candidates),'action':action,
             'weight_sign':ACTIONS[action][0],'weight_transmission':ACTIONS[action][1],'weight_penalty':ACTIONS[action][2],
             'rl_algorithm':ep.candidates[ci]['algorithm'],'rl_tls_ms':float(means[ci]),
             'mldsa_algorithm':ep.candidates[baseline]['algorithm'],'mldsa_tls_ms':float(means[baseline]),
             'fixed_algorithm':ep.candidates[fixed_i]['algorithm'],'fixed_tls_ms':float(means[fixed_i]),
             'deterministic_algorithm':ep.candidates[det_i]['algorithm'],'deterministic_tls_ms':float(means[det_i]),
             'fixed_weight_tls_ms':float(means[b['choices'][fixed_weight]]),
             'greedy_tls_ms':float(means[greedy]),'oracle_tls_ms_evaluator_only':float(means.min()),
             'rl_untrimmed_test_ms':None}
        # Untrimmed diagnostics are computed separately from the preserved snapshot.
        row.pop('rl_untrimmed_test_ms')
        row['reduction_vs_mldsa_pct']=100*(row['mldsa_tls_ms']-row['rl_tls_ms'])/row['mldsa_tls_ms']
        result.append(row)
    return result


def aggregate(rows, fields):
    groups=defaultdict(list)
    for r in rows:groups[tuple(r[f] for f in fields)].append(r)
    result=[]
    for key,items in sorted(groups.items()):
        means={k:statistics.fmean(r[k] for r in items) for k in ('rl_tls_ms','mldsa_tls_ms','fixed_tls_ms','deterministic_tls_ms','fixed_weight_tls_ms','greedy_tls_ms','oracle_tls_ms_evaluator_only')}
        row={**dict(zip(fields,key)),'episodes':len({r['episode_id'] for r in items}),**means}
        for label,base in (('mldsa','mldsa_tls_ms'),('best_fixed','fixed_tls_ms'),('deterministic','deterministic_tls_ms'),('fixed_weight','fixed_weight_tls_ms')):
            row['reduction_vs_'+label+'_pct']=100*(means[base]-means['rl_tls_ms'])/means[base]
        row['saved_vs_mldsa_ms']=means['mldsa_tls_ms']-means['rl_tls_ms']
        per_seed=[]
        for seed in SEEDS:
            sr=[r for r in items if r['seed']==seed];m=statistics.fmean(r['mldsa_tls_ms'] for r in sr);v=statistics.fmean(r['rl_tls_ms'] for r in sr)
            per_seed.append(100*(m-v)/m)
        row['seed_reduction_min_pct']=min(per_seed);row['seed_reduction_max_pct']=max(per_seed)
        result.append(row)
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--snapshot',type=Path,required=True);p.add_argument('--output-dir',type=Path,required=True)
    p.add_argument('--allow-legacy-costs',action='store_true')
    p.add_argument('--server-sign-profile-dir',type=Path)
    p.add_argument('--client-verify-profile-dir',type=Path)
    p.add_argument('--pure-cost-profile',type=Path)
    p.add_argument('--composite-cost-profile',type=Path)
    args=p.parse_args()
    fresh=bool(args.server_sign_profile_dir or args.client_verify_profile_dir)
    if fresh and (not args.server_sign_profile_dir or not args.client_verify_profile_dir):p.error('Both fresh EVP profile directories are required')
    if fresh and args.allow_legacy_costs:p.error('Choose fresh EVP profiles or legacy costs, not both')
    if not fresh and not args.allow_legacy_costs:p.error('Provide both fresh EVP profiles or explicitly allow legacy costs')
    snapshot=json.loads(args.snapshot.read_text())
    scope_pairs=[(int(pair['ica']),int(pair['loss_percent']))
                 for pair in snapshot.get('included_ica_loss_pairs', [])]
    if not scope_pairs:
        scope_pairs=[(int(ica),loss) for ica in snapshot.get('included_icas', []) for loss in (0,1)]
    pure=args.pure_cost_profile or ROOT/'outputs/analysis/contextual_signature_selector/itail_full_matrix/itail_all_rows_seoul.csv'
    comp=args.composite_cost_profile or ROOT/'outputs/analysis/composite_chain_length_overhead/composite_chain_detail.csv'
    profile_metadata=[];sign_costs=verify_costs=None
    if fresh:
        expected_count=len(snapshot['expected_algorithms']) if 'expected_algorithms' in snapshot else 147
        sign_costs,sign_meta=load_evp_averages(args.server_sign_profile_dir,'server_sign',expected_count)
        verify_costs,verify_meta=load_evp_averages(args.client_verify_profile_dir,'seoul_client_verify',expected_count)
        profile_metadata=[sign_meta,verify_meta]
    bundles,outcomes,provenance,exclusions=prepare(snapshot,pure,comp,sign_costs,verify_costs)
    args.output_dir.mkdir(parents=True,exist_ok=False)
    modeldir=args.output_dir/'models';modeldir.mkdir()
    all_decisions=[];validation=[];models=[];contexts=[]
    for level in BASELINES:
        bs=[b for b in bundles if b['episode'].level==level];bounds=configure_actions(bs)
        for alpha in ALPHAS:
            for seed in SEEDS:
                agent=train(bs,outcomes,'train',alpha,seed)
                validation.append({'level':level,'alpha':alpha,'seed':seed,'validation_tls_ms':policy_mean(agent,bs,outcomes,'validation')})
        best=min(ALPHAS,key=lambda a:statistics.fmean(r['validation_tls_ms'] for r in validation if r['level']==level and r['alpha']==a))
        fixed,fw=frozen_comparators(bs,outcomes)
        print(level,'episodes',len(bs),'selected alpha',best,'fixed comparators',fixed,flush=True)
        for seed in SEEDS:
            agent=train(bs,outcomes,'fit',best,seed)
            checkpoint={**agent.to_json(),'seed':seed,'level':level,'feature_bounds':asdict(bounds),
                        'fixed_comparators_validation_only':fixed,'fixed_weight_validation_only':ACTIONS[fw],
                        'frozen_evaluation_policy':'UCB_argmax_no_updates_matches_previous_protocol',
                        'snapshot_sha256':hashlib.sha256(args.snapshot.read_bytes()).hexdigest()}
            save_json(modeldir/f'{level}_seed{seed}.json',checkpoint)
            models.append({'level':level,'seed':seed,'alpha':best,'updates':agent.total_updates})
            all_decisions.extend(evaluate(agent,bs,outcomes,seed,fixed,fw))
        contexts.extend({'id':b['id'],'context':asdict(b['episode']),'choices':b['choices'].tolist(),
                         'rtt_values':b['rtt_values'],'rtt_mismatch':b['rtt_mismatch']} for b in bs)
    # Persist the exact cost inputs, bounds, frozen candidate lists, and action map.
    save_json(args.output_dir/'cost_provenance.json',provenance)
    save_json(args.output_dir/'decision_contexts.json',contexts)
    write_csv(args.output_dir/'test_decisions.csv',all_decisions)
    write_csv(args.output_dir/'validation_search.csv',validation)
    write_csv(args.output_dir/'summary_by_level_suite.csv',aggregate(all_decisions,('level','suite')))
    write_csv(args.output_dir/'summary_by_ica_loss.csv',aggregate(all_decisions,('level','suite','certificate_mode','loss_percent')))
    write_csv(args.output_dir/'summary_by_region.csv',aggregate(all_decisions,('level','suite','region')))
    write_csv(args.output_dir/'sensitivity_matched_rtt_only.csv',aggregate([r for r in all_decisions if not r['rtt_mismatch']],('level','suite')))
    condition_summary=aggregate(all_decisions,COHORT_FIELDS)
    write_csv(args.output_dir/'summary_by_condition.csv',condition_summary)
    source_files=[args.snapshot,pure,comp,Path(__file__),ROOT/'rl_weight_selector/partial_feedback_linucb.py',ROOT/'contextual_signature_selector/selector.py',ROOT/'rl_weight_selector/screen_composite_vs_deterministic.py']
    if fresh:
        source_files.extend(Path(m[k]) for m in profile_metadata for k in ('manifest','averages'))
    limitations=['RTT is configured summary value, not per-run observation; per-context median used when metadata differ','Frozen UCB evaluation; greedy diagnostic also saved',
                 'Repeated-run holdout at familiar contexts, not unseen-network test','Top30% trimming changes latency estimand',
                 'L1 comparison cohort includes ML-DSA-44 (catalog L2)','Same weight reward model hides suite/ICA/loss; those affect candidate costs or outcome only']
    if fresh:
        limitations.extend(['Server sign profile is measured on the Frankfurt server hardware and used as the server cost reference',
                            'Client verify profile measures CertificateVerify on Seoul client1; it is not a measured full certificate-chain verification time'])
    else:
        limitations[:0]=['Legacy composite cost contains command overhead','Pure cost is Seoul-only reused across regions']
    source_algorithm_conditions=len(snapshot['conditions'])
    eligible_algorithm_conditions=source_algorithm_conditions-len(exclusions)
    metrics={'status':'fresh_unified_evp_costs' if fresh else 'provisional_legacy_costs','snapshot_time':snapshot['created_at'],
             'included_icas':sorted({ica for ica,_ in scope_pairs}),
             'included_ica_loss_pairs':[{'ica':ica,'loss_percent':loss} for ica,loss in scope_pairs],
             'excluded_ica_loss_pairs':snapshot.get('excluded_ica_loss_pairs',[]),
             'source_algorithm_conditions':source_algorithm_conditions,'source_raw_samples':source_algorithm_conditions*50,
             'excluded_HAWK_conditions':len(exclusions),'eligible_algorithm_conditions':eligible_algorithm_conditions,
             'eligible_algorithms':len({r['algorithm'] for r in snapshot['conditions'] if 'hawk' not in r['algorithm']}),
             'decision_contexts':len(bundles),'seeds':list(SEEDS),
             'rtt_mismatch_contexts':sum(b['rtt_mismatch'] for b in bundles),
             'models':models,'run_split':{'train':'1-30','validation':'31-40','fit':'1-40','test':'41-50'},
             'upper_trim_fraction_per_partition':.3,'reward':'-selected_tls_ms/1000',
             'weights':'66 nonnegative 3D vectors summing to 1, step 0.1',
             'test_seed_aggregation':'mean TLS across seeds, then relative reduction; seeds not independent network samples',
             'all_requested_scope_conditions_trained':True,'fresh_cost_remeasurement':fresh,
             'evp_profile_metadata':profile_metadata,'deterministic_baseline':'contextual_signature_selector.selector.score_row with the same cost inputs',
             'limitations':limitations,
             'source_hashes':{str(f):hashlib.sha256(f.read_bytes()).hexdigest() for f in source_files},
             'summary':aggregate(all_decisions,('level','suite'))}
    save_json(args.output_dir/'metrics.json',metrics)
    scope_text=', '.join(f'{ica}ICA/loss {loss}%' for ica,loss in scope_pairs)
    report=['# 선택 범위 RL 재학습 결과','',
            ('통일 EVP 비용 재측정 결과를 반영.' if fresh else
             '기존 비용 프로파일 사용. 통일 비용 재측정 결과가 아님.'),
            '',f'- 학습 범위: {scope_text}.',
            f'- 원자료: {source_algorithm_conditions:,}조건 × 50회. HAWK {len(exclusions):,}조건 제외 후 141개 인증서, {eligible_algorithm_conditions:,}조건.',
            f'- L1(ML-DSA-44 포함)·L3·L5별 모델. Pure와 두 Composite 유형의 총 {len(bundles):,}개 선택 상황을 학습.',
            '- 표는 학습 완료 후 동결한 같은 모델의 테스트 결과를 조건별로 필터링한 것.',
            '- seed 42–46 다섯 번. seed 평균 TLS로 감소율 계산. seed를 새 네트워크 측정으로 세지 않음.',
            '- 학습 1–30, 검증 31–40, 재학습 1–40, 테스트 41–50. 각 구간 느린 30% 제외.',
            '- ML-DSA 감소율 = 100 × (ML-DSA 평균 TLS − RL 평균 TLS) / ML-DSA 평균 TLS.',
            '- 최선 고정 알고리즘은 레벨·Pure/Composite 유형별 검증 데이터만으로 선정.',
            '- 고정 weight는 레벨별 검증 데이터로 선정. 테스트를 보고 대조군을 바꾸지 않음.',
            ('- sign은 프랑크푸르트 서버, verify는 서울 client1의 동일 EVP 기준 50회 평균. 크기·체인 구조는 실제 인증서 프로파일 사용.' if fresh else
             '- Pure 비용은 서울 프로파일을 타 지역에도 적용한 잠정 입력. Composite는 명령 실행 오버헤드 포함.'),
            f"- {len(bundles):,}개 선택 상황 중 {sum(b['rtt_mismatch'] for b in bundles):,}개는 후보별 RTT 메타데이터 불일치. 중앙값 입력 및 별도 표시; 해당 상황 제외 평가 요약도 저장.",
            '','## 전체 요약','',
            '| 비교군 | 유형 | ML-DSA(ms) | Deterministic(ms) | RL(ms) | ML-DSA 대비 감소율 | Deterministic 대비 감소율 | 최선 고정 대비 감소율 |',
            '|---|---|---:|---:|---:|---:|---:|---:|']
    for r in metrics['summary']:
        report.append(f"| {r['level']} | {r['suite']} | {r['mldsa_tls_ms']:.3f} | {r['deterministic_tls_ms']:.3f} | {r['rl_tls_ms']:.3f} | {r['reduction_vs_mldsa_pct']:.2f}% | {r['reduction_vs_deterministic_pct']:.2f}% | {r['reduction_vs_best_fixed_pct']:.2f}% |")
    for level in BASELINES:
        suites=sorted({r['suite'] for r in condition_summary if r['level']==level})
        for loss in sorted({r['loss_percent'] for r in condition_summary if r['level']==level}):
            for suite in suites:
                scoped=[r for r in condition_summary
                        if r['level']==level and r['suite']==suite and r['loss_percent']==loss]
                if not scoped:continue
                columns=sorted({(int(r['certificate_mode'].removesuffix('ICA')),int(r['bandwidth_mbps']))
                                for r in scoped})
                report.extend(['',f'## {level} / {suite} / loss {loss}%','',
                    '각 칸: ML-DSA 대비 TLS 감소율. 음수는 RL이 더 느림. 지역 간 거리는 실제 RTT로 해석해야 함.','',
                    '| 서버 지역 | '+' | '.join(f'{ica}ICA·{bw}Mbps' for ica,bw in columns)+' |',
                    '|---|'+'---:|'*len(columns)])
                for region in ('seoul','tokyo','singapore','usa','frankfurt'):
                    cells=[]
                    for ica,bw in columns:
                        r=next(r for r in scoped if (r['region'],r['certificate_mode'],r['bandwidth_mbps'])==(region,f'{ica}ICA',bw))
                        cells.append(f"{r['reduction_vs_mldsa_pct']:.2f}%")
                    report.append('| '+region+' | '+' | '.join(cells)+' |')
    with (args.output_dir/'report.md').open('x') as f:f.write('\n'.join(report)+'\n')
    print(json.dumps(metrics['summary'],ensure_ascii=False),flush=True)


if __name__=='__main__':main()
