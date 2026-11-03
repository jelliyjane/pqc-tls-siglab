#!/usr/bin/env python3
"""Benchmark-only runtime adapter for the saved final LinUCB model.

Uses the release's actual LinUCBAgent.select, without replay's precomputed choices.
One persistent Unix stream per benchmark process. Not the old DECIDE protocol.
"""
import argparse
import json
import math
from pathlib import Path
import socket
import sys
import tarfile
import time
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'repro/latest/code'))
from rl_weight_selector.partial_feedback_linucb import LinUCBAgent


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--socket', type=Path, required=True)
    a = p.parse_args()
    with tarfile.open(ROOT / 'results/latest/condition/models.tar.gz') as archive:
        model = json.load(archive.extractfile('models/fold0_L1_seed42.json'))
    assert model['score_terms'] == 4 and len(model['a_inverse'][0]) == 5
    agent = LinUCBAgent(model['actions'], 5, model['alpha'])
    agent.a_inverse, agent.b = np.asarray(model['a_inverse']), np.asarray(model['b'])
    low = np.asarray(model['feature_bounds']['minimum'])
    high = np.asarray(model['feature_bounds']['maximum'])
    reference = model['reference']

    def decide(row):
        rtt, bw, loss, window, sign0, sign1, flight0, flight1, allowed = row
        if not (rtt >= 0 and bw > 0 and 0 <= loss <= 1 and window > 0):
            raise ValueError('Invalid live context')
        r = math.log1p(rtt) / math.log1p(reference['rtt_ms'])
        b = math.log1p(bw) / math.log1p(reference['bandwidth_mbps'])
        x = np.asarray([1., r, b, r*b, loss])
        arm = agent.select(x)[0]
        # One sent self-signed certificate per candidate, matched by the client
        # trust store. Verification estimates from the published pure profiles.
        raw = np.asarray([[sign0, 8*flight0/(1000*bw), max(0, math.ceil(flight0/window)-1)*rtt, .13782916],
                          [sign1, 8*flight1/(1000*bw), max(0, math.ceil(flight1/window)-1)*rtt, .69939332]])
        costs = np.clip(np.divide(raw-low, high-low, out=np.zeros_like(raw), where=high>low), 0., 1.)
        names = ['mldsa44', 'falcon512']
        selected = min((i for i in range(2) if int(allowed) & (1 << i)),
                       key=lambda i: (float(np.dot(agent.actions[arm], costs[i])), float(costs[i].sum()), names[i]))
        return selected, arm

    # Check the actual release selector against an independent matrix expression.
    rng = np.random.default_rng(42)
    for x in rng.random((100, 5)):
        theta = np.stack([m @ b for m,b in zip(agent.a_inverse, agent.b)])
        scores = theta @ x + agent.alpha*np.sqrt(np.maximum(0., np.array([x @ m @ x for m in agent.a_inverse])))
        assert agent.select(x)[0] == int(np.argmax(scores))
    for _ in range(200):
        decide([.3,1000.,0.,65536.,.71714122,1.00602308,6400,2800,3])
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(str(a.socket)); server.listen(8)
        print('READY final model: 286 arms, 5 context features, 4 costs', flush=True)
        while True:
            connection, _ = server.accept()
            with connection, connection.makefile('r') as incoming:
                for line in incoming:
                    start = time.perf_counter_ns()
                    row = list(map(float, line.split()))
                    selected, arm = decide(row)
                    elapsed = time.perf_counter_ns()-start
                    connection.sendall(f'{selected} {arm} {elapsed}\n'.encode())


if __name__ == '__main__':
    main()
