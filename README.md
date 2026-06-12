# PQC TLS Testbed

Experimental TLS 1.3 testbed for PQC signature algorithms in OpenSSL 3.5,
liboqs, and oqs-provider.

## Layout

- `scripts/build_aws.sh`: builds OpenSSL, liboqs, and oqs-provider.
- `scripts/env.sh`: runtime environment variables.
- `scripts/test_tls_sigalg.sh`: localhost TLS 1.3 handshake test for one signature algorithm.
- `src/tls_maxcert_client.c`: client with larger certificate-list limit for oversized certs.
- `patches/`: optional patch exports from local liboqs and oqs-provider worktrees.

## Recommended Git Setup

Use three repositories:

1. A fork of `open-quantum-safe/liboqs` with added algorithms.
2. A fork of `open-quantum-safe/oqs-provider` with provider/TLS support.
3. This wrapper repository for AWS build and benchmark scripts.

Do not commit build outputs, generated certificates, logs, or installed libraries.

## Build

```bash
git clone <this-repo>
cd pqc-tls-testbed
export LIBOQS_REPO=https://github.com/<user>/<liboqs-fork>.git
export LIBOQS_REF=<branch>
export OQSPROVIDER_REPO=https://github.com/<user>/<oqs-provider-fork>.git
export OQSPROVIDER_REF=<branch>
./scripts/build_aws.sh
source ./scripts/env.sh
```

## TLS Test

```bash
./scripts/test_tls_sigalg.sh faest128s
./scripts/test_tls_sigalg.sh slhdsasha2128s
./scripts/test_tls_sigalg.sh qruov5q7l10v1490m190 --large-cert
```

## Notes

- QR-UOV level 5 exceeds OpenSSL's default certificate-list limit, so use
  `--large-cert`.
- The local SLH-DSA provider experiment uses private OIDs to avoid OpenSSL 3.5
  native SLH-DSA OID conflicts.
