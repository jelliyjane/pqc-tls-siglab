# Reproducibility Status

Last reviewed: 2026-07-14

## Current Status

The repository now pins OpenSSL, liboqs, and oqs-provider revisions and
documents a clean Ubuntu installation in `INSTALL.md`.

A new user can reproduce the cryptographic build and localhost TLS smoke tests
from this repository alone.

The complete paper benchmark is not yet a one-command public artifact. The
multi-region AWS topology, 1ICA certificate generation, network-condition
runner, result builder, and analysis pipeline still need to be sanitized and
added without credentials or user-specific paths.

## Publicly Reproducible Now

1. Pinned OpenSSL 3.5.7 build.
2. Pinned custom liboqs build.
3. Pinned custom oqs-provider build.
4. Provider activation and algorithm availability checks.
5. Self-signed PQC leaf certificate generation.
6. Forced-signature TLS 1.3 localhost smoke tests.
7. Large-certificate client with a 512 KB certificate-list limit.

## Not Yet Publicly Reproducible

1. The exact current pure-PQC experiment manifest.
2. Deterministic root, ICA, and leaf generation for every algorithm.
3. The Seoul client and USA, Tokyo, and Singapore server orchestration.
4. Port-specific `tc` bandwidth and loss configuration and cleanup.
5. One hundred runs with a one-second pause and fastest-70 aggregation.
6. Independent and combined network-condition experiments.
7. Composite signature experiments.
8. Raw CSV, summary CSV, workbook, ranking, and board-cost analysis generation.

## Required Before Paper Artifact Release

1. Replace all addresses, SSH keys, ports, and interfaces with configuration
   variables and a safe example file.
2. Add the exact algorithm manifests used by each experiment.
3. Add 1ICA certificate generation and verification scripts.
4. Add smoke tests that stop the pipeline on any unsupported certificate.
5. Add independent and matrix benchmark runners with guaranteed `tc` cleanup.
6. Add resumable raw and summary result generation.
7. Add a reduced end-to-end test with expected output.
8. Record OS, kernel, CPU, instance type, region, RTT, component revisions,
   certificate mode, run count, pause, and trimming method in every result.

## Security Rule

Do not commit PEM private keys, AWS credentials, generated private keys,
user-specific absolute paths, or private host configuration. Public experiment
scripts must read those values from environment variables or a local ignored
configuration file.
