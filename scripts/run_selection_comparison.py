#!/usr/bin/env python3
"""Matched native OpenSSL-order vs final-model Python-sidecar selection timing."""
import argparse
from collections import Counter
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import tempfile
import time


def stats(values):
    v=sorted(x/1000 for x in values)
    def p(q):
        k=(len(v)-1)*q; lo=int(k)
        return v[lo]+(v[min(lo+1,len(v)-1)]-v[lo])*(k-lo)
    return dict(n=len(v),mean_us=statistics.fmean(v),p50_us=p(.5),p95_us=p(.95),p99_us=p(.99),max_us=v[-1])


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,required=True)
    p.add_argument('--instrumented-openssl',type=Path,required=True)
    p.add_argument('--openssl-prefix',type=Path,required=True)
    p.add_argument('--oqs-lib',type=Path,required=True)
    p.add_argument('--sign-hook',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--iterations',type=int,default=500)
    p.add_argument('--runs',type=int,default=3)
    a=p.parse_args()
    if a.iterations<1 or a.runs<1: p.error('positive iteration/run counts required')
    a.output.mkdir(parents=True,exist_ok=False)
    root=Path(__file__).resolve().parents[1]
    lib=a.openssl_prefix/'lib64'
    if not lib.is_dir(): lib=a.openssl_prefix/'lib'
    env=os.environ.copy()
    env.update(LD_LIBRARY_PATH=f'{a.instrumented_openssl}:{lib}:{a.oqs_lib}',
               OPENSSL_MODULES=str(lib/'ossl-modules'),OPENBLAS_NUM_THREADS='1',OMP_NUM_THREADS='1')
    openssl=str(a.openssl_prefix/'bin/openssl')
    result=dict(schema='cats.selection-comparison.v1',measured_at_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
        host=dict(kernel=platform.release(),cpu_count=os.cpu_count(),python=platform.python_version(),
                  cpu=next(x.split(':',1)[1].strip() for x in Path('/proc/cpuinfo').read_text().splitlines() if x.startswith('model name'))),
        conditions=dict(candidates=['mldsa44','falcon512'],server_policy='both preapproved; OpenSSL default security level',
                        model='condition/models/fold0_L1_seed42.json',model_arms=286,context_features=5,cost_terms=4,
                        tls='1.3',group='X25519',network='IPv4 loopback',concurrency=1,certificate_count=1,
                        client_sigalgs='mldsa44:falcon512',server_preference=True,iterations=a.iterations,runs=a.runs,
                        warmup_per_process=100,clock_baseline_subtracted=False,
                        cats_runtime='C collector + persistent Unix socket + Python/NumPy final-model adapter',
                        bw_fallback_mbps=1000),runs=[],groups={})
    sources=['src/bench_selection_compare.c','src/cats_context.c','src/cats_context.h','src/cats_sign_timer.c',
             'scripts/run_selection_comparison.py','scripts/selection_benchmark_sidecar.py','scripts/instrument_selection_openssl.py',
             'repro/latest/code/rl_weight_selector/partial_feedback_linucb.py','results/latest/condition/models.tar.gz']
    result['source_sha256']={name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in sources}
    result['binary_sha256']={name:hashlib.sha256(path.read_bytes()).hexdigest() for name,path in
        [('bench',a.binary),('libssl.so.3',a.instrumented_openssl/'libssl.so.3'),('sign_hook',a.sign_hook)]}
    result['instrumented_statem_sha256']=hashlib.sha256((a.instrumented_openssl/'ssl/statem/statem_srvr.c').read_bytes()).hexdigest()
    collected={}
    with tempfile.TemporaryDirectory(prefix='cats-order-') as tmp:
        task=Path(tmp); env['SELECT_CERT_DIR']=str(task)
        for file,key in [('mldsa44','ML-DSA-44'),('falcon512','falcon512')]:
            subprocess.run([openssl,'req','-x509','-newkey',key,'-noenc','-days','1','-subj',f'/CN={file}',
                            '-provider','default','-provider','oqsprovider','-keyout',str(task/f'{file}.key'),
                            '-out',str(task/f'{file}.crt')],env=env,check=True,capture_output=True)
        result['certificate_sha256']={name:hashlib.sha256((task/f'{name}.crt').read_bytes()).hexdigest()
                                      for name in ['mldsa44','falcon512']}
        socket=task/'model.sock'
        with (a.output/'sidecar.log').open('w+') as log:
            sidecar=subprocess.Popen([sys.executable,str(root/'scripts/selection_benchmark_sidecar.py'),
                                     '--socket',str(socket)],env=env,stdout=log,stderr=log)
            try:
                deadline=time.monotonic()+30
                while not socket.exists():
                    if sidecar.poll() is not None: raise RuntimeError('sidecar failed; see sidecar.log')
                    if time.monotonic()>deadline: raise TimeoutError('sidecar readiness')
                    time.sleep(.02)
                env['LD_PRELOAD']=str(a.sign_hook)
                # Alternate baseline/CATS order between runs to reduce drift bias.
                for run in range(a.runs):
                    for order in ['mldsa-first','falcon-first']:
                        for mode in (['stock','cats'] if run%2==0 else ['cats','stock']):
                            r=subprocess.run([str(a.binary),mode,order,str(a.iterations),str(socket)],
                                             env=env,capture_output=True,text=True,timeout=180)
                            if r.returncode: raise RuntimeError(r.stderr+r.stdout[:2000])
                            rows=[json.loads(line) for line in r.stdout.splitlines()]
                            samples=[x for x in rows if x['kind']=='selection']
                            assert len(samples)==a.iterations
                            assert all(x['total_ns']==x['shared_ns']+x['decision_ns'] for x in samples)
                            assert all(x['total_ns']>=x['acquisition_ns']+x['policy_ipc_ns']+x['install_ns'] for x in samples)
                            if mode=='stock': assert all(x['selected']==int(order=='falcon-first') for x in samples)
                            name=f'{mode}-{order}-run{run}'
                            with gzip.open(a.output/f'{name}.jsonl.gz','xt') as f: f.write(r.stdout)
                            collected.setdefault((mode,order),[]).extend(samples)
                            report=dict(name=name,metadata=rows[0],total=stats([x['total_ns'] for x in samples]),
                                        clock=stats([x['ns'] for x in rows if x['kind']=='clock']))
                            result['runs'].append(report)
                            print(name,report['total'],flush=True)
            finally:
                sidecar.terminate(); sidecar.wait(timeout=10)
    for (mode,order),samples in collected.items():
        fields=['shared_ns','decision_ns','total_ns','acquisition_ns','policy_ipc_ns','model_ns','install_ns']
        result['groups'][f'{mode}-{order}']=dict(
            timing={k:stats([r[k] for r in samples]) for k in fields},
            selected=dict(Counter(['mldsa44','falcon512'][r['selected']] for r in samples)),
            bw_history=sum(r['bw_history'] for r in samples),loss_history=sum(r['loss_history'] for r in samples))
    result['comparison']={}
    for order in ['mldsa-first','falcon-first']:
        stock=result['groups'][f'stock-{order}']['timing']['total_ns']['mean_us']
        cats=result['groups'][f'cats-{order}']['timing']['total_ns']['mean_us']
        result['comparison'][order]=dict(stock_mean_us=stock,cats_mean_us=cats,extra_mean_us=cats-stock,ratio=cats/stock)
    (a.output/'summary.json').write_text(json.dumps(result,indent=2)+'\n')


if __name__=='__main__': main()
