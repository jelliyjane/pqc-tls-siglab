#!/usr/bin/env python3
"""Run real TLS connections and save raw timing samples, separate from replay results."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import time


def stats(values):
    a = sorted(v / 1000 for v in values)  # ns to microseconds
    def percentile(p):
        pos = (len(a) - 1) * p
        lo = int(pos)
        return a[lo] + (a[min(lo + 1, len(a) - 1)] - a[lo]) * (pos - lo)
    return dict(n=len(a), mean_us=statistics.fmean(a), p50_us=percentile(.5),
                p95_us=percentile(.95), p99_us=percentile(.99), max_us=a[-1])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--build', type=Path, required=True)
    p.add_argument('--openssl-prefix', type=Path, required=True)
    p.add_argument('--iterations', type=int, default=1000)
    p.add_argument('--runs', type=int, default=3)
    p.add_argument('--profiles', type=int, default=150)
    args = p.parse_args()
    if args.iterations < 1 or args.runs < 1:
        p.error('iterations and runs must be positive')
    args.output.mkdir(parents=True, exist_ok=False)
    env = os.environ.copy()
    lib = args.openssl_prefix / 'lib64'
    if not lib.is_dir():
        lib = args.openssl_prefix / 'lib'
    env['LD_LIBRARY_PATH'] = str(lib)
    env['LD_PRELOAD'] = str(args.build / 'libcats_sign_timer.so')
    root = Path(__file__).resolve().parents[1]
    sources = list((root / 'src').glob('cats_*.[ch]')) + [root / 'src/bench_cats_context.c', Path(__file__)]
    result = dict(schema='cats.context-acquisition-benchmark.v1',
                  measured_at_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                  system=platform.system(), kernel=platform.release(), machine=platform.machine(),
                  cpu_count=os.cpu_count(),
                  cpu_description=next((x.split(':', 1)[1].strip() for x in
                      Path('/proc/cpuinfo').read_text().splitlines() if x.startswith('model name')), ''),
                  compiler=subprocess.check_output(['cc', '--version'], text=True).splitlines()[0],
                  source_sha256={str(f.relative_to(root)): hashlib.sha256(f.read_bytes()).hexdigest() for f in sources},
                  binary_sha256={n: hashlib.sha256((args.build / n).read_bytes()).hexdigest()
                      for n in ['bench_cats_context', 'libcats_sign_timer.so']},
                  conditions=dict(network='IPv4 loopback', tls='1.3', key_exchange='X25519',
                      concurrency=1, profile_slots=args.profiles, service_response_bytes=65536,
                      sampler_interval_ms=1000, log_inside_timed_section=False,
                      clock_baseline_subtracted=False),
                  limitations=[
                      'Acquisition overhead, not total signature-selection overhead or end-to-end TLS improvement.',
                      'Only ECDSA P-256 and ML-DSA-44 are executed; 150 denotes cached profile slots, not tested algorithms.',
                      'Single-host loopback, one live service connection; no cross-region or high-concurrency claim.',
                      'BW is a host-wide historical delivery-rate proxy, not measured available bandwidth on the new path.',
                      'Loss is a recent aggregate TCP retransmission ratio, not measured packet-loss probability on the new path.',
                      'Synthetic application response is benchmark workload; collection itself sends no data.',
                      'Crypto execution time is reported separately and is NOT acquisition overhead.',
                  ], algorithms={})
    for algorithm in ['ECDSA', 'ML-DSA-44']:
        samples, micro, clock, runs = [], [], [], []
        for run in range(args.runs):
            command = [str(args.build / 'bench_cats_context'), algorithm,
                       str(args.iterations), str(args.profiles)]
            proc = subprocess.run(command, env=env, text=True, capture_output=True, timeout=300)
            if proc.returncode:
                raise RuntimeError(f'{algorithm} run {run}: {proc.stderr}')
            rows = [json.loads(line) for line in proc.stdout.splitlines()]
            handshakes = [r for r in rows if r['kind'] == 'handshake']
            assert len(handshakes) == args.iterations
            assert all(r['sign_calls'] == 1 and r['window_bytes'] > 0 for r in handshakes)
            assert any(r['kind'] == 'no_probe_check' and r['data_segments_added'] == 0 for r in rows)
            with gzip.open(args.output / f'{algorithm}-run{run}.jsonl.gz', 'xt') as f:
                f.write(proc.stdout)
            samples.extend(handshakes)
            micro.extend(r['ns'] for r in rows if r['kind'] == 'micro')
            clock.extend(r['ns'] for r in rows if r['kind'] == 'clock_pair')
            runs.append(dict(run=run, metadata=rows[0],
                             acquisition=stats([r['acquisition_ns'] for r in handshakes]),
                             sampler=next(r for r in rows if r['kind']=='sampler')))
            print(algorithm, run, runs[-1]['acquisition'], flush=True)
        fields=['acquisition_ns','track_ns','untrack_ns','ewma_ns','sign_ns']
        result['algorithms'][algorithm] = dict(runs=runs,
            timing={k:stats([r[k] for r in samples]) for k in fields},
            per_connection_bookkeeping=stats([sum(r[k] for k in fields[:-1]) for r in samples]),
            steady_state_collection=stats(micro), clock_pair=stats(clock),
            history_usage=dict(bw=sum(r['bw_history'] for r in samples),
                               loss=sum(r['loss_history'] for r in samples)),
            measured_handshakes=len(samples))
    with (args.output / 'summary.json').open('x') as f:
        json.dump(result, f, indent=2)
        f.write('\n')


if __name__ == '__main__':
    main()
