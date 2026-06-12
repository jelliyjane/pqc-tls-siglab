# PQC TLS SigLab

Experimental TLS 1.3 testbed for PQC signature algorithms in OpenSSL 3.5,
liboqs, and oqs-provider.

This repository is the AWS/reproduction wrapper. The actual algorithm/provider
changes live in two forked repositories.

## Handoff For Next Session

If another Codex session continues this work, start here.

User context:

- Research area: TLS 1.3, PQC signatures, hybrid/adaptive certificate selection.
- Goal: run AWS-based benchmarks for PQC signature certificates and TLS 1.3
  handshakes.
- Current focus: certificate DER size and localhost TLS handshake time by
  algorithm/security level.

Repository set:

- liboqs fork:
  `https://github.com/jelliyjane/liboqs-pqc-tls-siglab.git`
- liboqs branch:
  `pqc-tls-siglab`
- oqs-provider fork:
  `https://github.com/jelliyjane/oqs-provider-pqc-tls-siglab.git`
- oqs-provider branch:
  `pqc-tls-siglab`
- wrapper repo:
  `https://github.com/jelliyjane/pqc-tls-siglab.git`
- wrapper branch:
  `main`

Important local commits at handoff:

- liboqs: `e084ea6 Add experimental PQC signature algorithms`
- oqs-provider: `3fd2152 Add experimental PQC TLS signature provider support`
- wrapper: `647202e Add PQC TLS AWS testbed wrapper`

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

## Fresh AWS Build

```bash
git clone https://github.com/jelliyjane/pqc-tls-siglab.git
cd pqc-tls-siglab

export LIBOQS_REPO=https://github.com/jelliyjane/liboqs-pqc-tls-siglab.git
export LIBOQS_REF=pqc-tls-siglab
export OQSPROVIDER_REPO=https://github.com/jelliyjane/oqs-provider-pqc-tls-siglab.git
export OQSPROVIDER_REF=pqc-tls-siglab

./scripts/build_aws.sh
source ./scripts/env.sh
```

The build script installs into:

- `install/openssl`
- `install/liboqs`
- `install/oqs-provider`

## TLS Test

```bash
./scripts/test_tls_sigalg.sh faest128s
./scripts/test_tls_sigalg.sh slhdsasha2128s
./scripts/test_tls_sigalg.sh qruov5q7l10v1490m190 --large-cert
```

Useful signature names:

- FAEST: `faest128s`, `faest128f`, `faest192s`, `faest192f`,
  `faest256s`, `faest256f`
- HAWK: `hawk512`, `hawk1024`
- QR-UOV Round2:
  `qruov1q7l10v740m100`, `qruov3q7l10v1100m140`,
  `qruov5q7l10v1490m190`
- ML-DSA: `mldsa44`, `mldsa65`, `mldsa87`
- Falcon: `falcon512`, `falcon1024`
- SLH-DSA SHA2:
  `slhdsasha2128s`, `slhdsasha2128f`, `slhdsasha2192s`,
  `slhdsasha2192f`, `slhdsasha2256s`, `slhdsasha2256f`
- SDitH: `sdithhypercubecat1gf256`

For a quick availability check:

```bash
openssl list -signature-algorithms \
  -provider-path "$OQSPROV_MODULES" \
  -provider oqsprovider \
  -provider default

openssl list -tls-signature-algorithms \
  -provider-path "$OQSPROV_MODULES" \
  -provider oqsprovider \
  -provider default
```

## Notes

- QR-UOV level 5 exceeds OpenSSL's default certificate-list limit, so use
  `--large-cert`.
- The local SLH-DSA provider experiment uses private OIDs to avoid OpenSSL 3.5
  native SLH-DSA OID conflicts.
- `oqs-provider` may have local build directories such as `build-35/`; do not
  commit them.
- The timing scripts are simple localhost smoke tests. For paper-quality data,
  repeat measurements, pin CPU settings, record machine type, and separate
  certificate size from network effects.

## Previously Observed Local Results

These were one-shot localhost measurements on the original development machine.
Use them only as sanity checks, not final benchmark data.

| Algorithm | Certificate DER | TLS handshake |
|---|---:|---:|
| Falcon512 | 1,788B | 10ms |
| HAWK512 | 1,819B | 30ms |
| ML-DSA44 | 3,981B | 10ms |
| FAEST128s | 4,773B | 110ms |
| FAEST128f | 6,191B | 70ms |
| SLH-DSA-SHA2-128s | 8,130B | 260ms |
| SLH-DSA-SHA2-128f | 17,362B | 30ms |
| QR-UOV level1 | 21,212B | 50ms |
| ML-DSA65 | 5,510B | 10ms |
| FAEST192s | 11,544B | 310ms |
| FAEST192f | 15,232B | 150ms |
| SLH-DSA-SHA2-192s | 16,515B | 440ms |
| SLH-DSA-SHA2-192f | 35,955B | 30ms |
| QR-UOV level3 | 55,878B | 80ms |
| Falcon1024 | 3,304B | 10ms |
| HAWK1024 | 3,901B | 30ms |
| ML-DSA87 | 7,468B | 10ms |
| FAEST256s | 20,980B | 490ms |
| FAEST256f | 26,832B | 230ms |
| SLH-DSA-SHA2-256s | 30,099B | 400ms |
| SLH-DSA-SHA2-256f | 50,163B | 60ms |
| QR-UOV level5 | 136,313B | 90ms with large-cert client |
