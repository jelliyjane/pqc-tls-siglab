#!/usr/bin/env python3
"""Validate Pareto handoff identifiers, cost joins, and source hashes."""
import csv
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def main():
    mapping = json.loads((HERE / 'algorithm_mapping.json').read_text())['algorithms']
    assert len(mapping) == 147
    assert len({r['algorithm'] for r in mapping}) == 147
    assert sum(r['suite'] == 'pure' for r in mapping) == 49
    assert sum(r['suite'] == 'composite' for r in mapping) == 98
    assert sum(r['provider_build'] == 'standard' for r in mapping) == 135
    assert sum(r['provider_build'] == 'shake98' for r in mapping) == 12
    for r in mapping:
        assert int(r['tls_code_point_hex'], 16) == r['tls_code_point_decimal']
    for scope in ['standard', 'shake98']:
        rows = [r for r in mapping if r['provider_build'] == scope]
        assert len({r['tls_code_point_decimal'] for r in rows}) == len(rows)
    for name in ['server_sign_frankfurt_evp_v2.csv', 'client_verify_seoul_evp_v2.csv']:
        with (ROOT / 'results/pc_tls_20260929' / name).open(newline='') as f:
            rows = list(csv.DictReader(f))
        assert {r['algorithm'] for r in rows} == {r['algorithm'] for r in mapping}
    provenance = json.loads((HERE / 'build_provenance.json').read_text())
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    assert digest(HERE / 'provider-shake98.patch') == provenance['rebuild_sources']['provider_shake98']['patch_sha256']
    old = json.loads((ROOT / 'results/pc_tls_20260929/provenance.json').read_text())
    protocol = old['cost_protocols']['server_sign_frankfurt']
    assert digest(HERE / 'evp_sig_bench.c') == protocol['benchmark_source_sha256']
    for binary, key in [('standard', 'provider_binary_sha256'), ('shake98', 'shake_provider_binary_sha256'), ('libcrypto', 'libcrypto_sha256')]:
        assert provenance['runtime_binary_sha256'][binary] == protocol[key]
    print('PASS: 147 candidates, 49/98 split, 135/12 provider scopes, exact cost joins, and historical hashes')


if __name__ == '__main__':
    main()
