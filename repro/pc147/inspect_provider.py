#!/usr/bin/env python3
"""Read provider TLS capabilities and optionally check a campaign mapping.

Run once per provider build, in separate processes. No TLS connections,
key generation, signatures, or model updates are performed.
"""
import argparse
import ctypes as C
import json
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--libcrypto', required=True, type=Path)
    parser.add_argument('--provider-dir', required=True, type=Path)
    parser.add_argument('--provider-build', required=True, choices=['standard', 'shake98'])
    mapping_input = parser.add_mutually_exclusive_group()
    mapping_input.add_argument('--mapping', type=Path)
    mapping_input.add_argument('--mapping-stdin', action='store_true')
    args = parser.parse_args()
    lib = C.CDLL(str(args.libcrypto.resolve()), mode=C.RTLD_GLOBAL)

    class Param(C.Structure):
        _fields_ = [('key', C.c_char_p), ('data_type', C.c_uint),
                    ('data', C.c_void_p), ('data_size', C.c_size_t),
                    ('return_size', C.c_size_t)]

    callback_type = C.CFUNCTYPE(C.c_int, C.POINTER(Param), C.c_void_p)
    lib.OSSL_LIB_CTX_new.restype = C.c_void_p
    lib.OSSL_PROVIDER_set_default_search_path.argtypes = [C.c_void_p, C.c_char_p]
    lib.OSSL_PROVIDER_load.argtypes = [C.c_void_p, C.c_char_p]
    lib.OSSL_PROVIDER_load.restype = C.c_void_p
    lib.OSSL_PROVIDER_get_capabilities.argtypes = [C.c_void_p, C.c_char_p, callback_type, C.c_void_p]
    lib.EVP_SIGNATURE_fetch.argtypes = [C.c_void_p, C.c_char_p, C.c_char_p]
    lib.EVP_SIGNATURE_fetch.restype = C.c_void_p
    lib.EVP_SIGNATURE_get0_name.argtypes = [C.c_void_p]
    lib.EVP_SIGNATURE_get0_name.restype = C.c_char_p
    lib.EVP_SIGNATURE_get0_provider.argtypes = [C.c_void_p]
    lib.EVP_SIGNATURE_get0_provider.restype = C.c_void_p
    lib.OSSL_PROVIDER_get0_name.argtypes = [C.c_void_p]
    lib.OSSL_PROVIDER_get0_name.restype = C.c_char_p
    lib.EVP_SIGNATURE_free.argtypes = [C.c_void_p]
    ctx = lib.OSSL_LIB_CTX_new()
    if not ctx or not lib.OSSL_PROVIDER_set_default_search_path(ctx, str(args.provider_dir.resolve()).encode()):
        raise RuntimeError('Could not configure the OpenSSL library context')
    rows = []
    for name in ['default', 'oqsprovider']:
        provider = lib.OSSL_PROVIDER_load(ctx, name.encode())
        if not provider:
            raise RuntimeError('Cannot load ' + name + '; check provider path and LD_LIBRARY_PATH')

        @callback_type
        def receive(params, unused):
            row = {'provider': name}
            i = 0
            while params[i].key:
                p = params[i]
                if p.data_type in (1, 2):
                    value = int.from_bytes(C.string_at(p.data, p.data_size), sys.byteorder,
                                           signed=p.data_type == 1)
                elif p.data_type == 4:
                    value = C.string_at(p.data).decode()
                else:
                    value = None
                row[p.key.decode()] = value
                i += 1
            rows.append(row)
            return 1

        if lib.OSSL_PROVIDER_get_capabilities(provider, b'TLS-SIGALG', receive, None) != 1:
            raise RuntimeError(name + ' does not expose TLS-SIGALG capabilities')
    result = {'provider_build': args.provider_build, 'capabilities': rows}
    if args.mapping or args.mapping_stdin:
        mapping = json.loads(sys.stdin.read() if args.mapping_stdin else args.mapping.read_text())
        candidates = [r for r in mapping['algorithms']
                      if r['provider_build'] == args.provider_build]
        caps = {(r['provider'], r['tls-sigalg-name']): r for r in rows}
        errors = []
        for r in candidates:
            sig = lib.EVP_SIGNATURE_fetch(ctx, r['openssl_algorithm_argument'].encode(), None)
            if not sig:
                errors.append(r['algorithm'] + ': EVP signature unavailable')
                continue
            fetched_name = lib.EVP_SIGNATURE_get0_name(sig).decode()
            provider_name = lib.OSSL_PROVIDER_get0_name(lib.EVP_SIGNATURE_get0_provider(sig)).decode()
            lib.EVP_SIGNATURE_free(sig)
            cap = caps.get((provider_name, fetched_name))
            if (fetched_name != r['evp_signature_name'] or provider_name != r['signature_provider']
                    or not cap or cap['tls-sigalg-code-point'] != r['tls_code_point_decimal']):
                errors.append(r['algorithm'] + ': name, provider, or code point differs')
        result.update(checked_candidates=len(candidates), errors=errors)
    print(json.dumps(result, indent=2))
    return 1 if result.get('errors') else 0


if __name__ == '__main__':
    raise SystemExit(main())
