# Installation Guide

This guide installs the pinned PQC TLS SigLab cryptographic stack on a clean
Ubuntu host and verifies that the custom OpenSSL provider is working.

Use wrapper tag `repro-self-contained-v1`. Do not replace the pinned liboqs
commit `fa33db143fb12a2e1e306b51ab3c8c98432a46c4` with an older revision; this
is the self-contained revision that includes HAWK, QR-UOV Round 2, and SDitH.

## Supported Baseline

The documented baseline is:

1. Ubuntu 22.04 or Ubuntu 24.04, x86_64.
2. At least 2 vCPUs and 8 GB RAM.
3. At least 30 GB of free disk space.
4. Outbound HTTPS access to GitHub.
5. `sudo` access for package installation.

The build script pins these source revisions:

| Component | Revision |
|---|---|
| OpenSSL | `openssl-3.5.7` |
| liboqs fork | `fa33db143fb12a2e1e306b51ab3c8c98432a46c4` |
| oqs-provider fork | `29f791a772b8c72506efba414ef616bc48cac9ab` |

## 1. Install Operating-System Packages

```bash
sudo apt-get update
sudo apt-get install -y \
  build-essential \
  git \
  cmake \
  ninja-build \
  perl \
  pkg-config \
  python3 \
  python3-pip \
  python3-venv \
  libssl-dev \
  zlib1g-dev \
  unzip \
  iproute2 \
  openssh-client \
  openssh-server \
  screen \
  tcpdump
```

`iproute2` supplies `tc`, which is required for the bandwidth and packet-loss
experiments. `screen` is optional for local tests but useful for detached AWS
benchmark sessions.

## 2. Clone The Wrapper

```bash
git clone https://github.com/jelliyjane/pqc-tls-siglab.git
cd pqc-tls-siglab
git checkout repro-self-contained-v1
```

Do not run the experiment as root. Use a normal user with `sudo` permission
only for package installation and `tc` configuration.

## 3. Build The Pinned Stack

The pinned liboqs revision vendors the HAWK, QR-UOV Round 2, and SDitH
reference implementations with their upstream license files. Do not create or
configure a separate `pq-sig-refs` directory; the build uses only sources from
the cloned liboqs repository. The build script explicitly enables FAEST, HAWK,
QR-UOV Round 2, and SDitH because those experimental families are disabled by
default in liboqs.

```bash
export PQC_TLS_TESTBED="$PWD"
export JOBS="$(nproc)"
./scripts/build_aws.sh
```

On a memory-constrained machine, reduce parallelism:

```bash
export JOBS=2
./scripts/build_aws.sh
```

The build is installed below the repository:

```text
install/openssl
install/liboqs
install/oqs-provider
```

The source worktrees and build trees are stored below `src-work/`.

## 4. Load The Runtime Environment

```bash
source ./scripts/env.sh
```

The script sets:

1. `OPENSSL_ROOT`
2. `LIBOQS_ROOT`
3. `OQSPROV_ROOT`
4. `OQSPROV_MODULES`
5. `OPENSSL_MODULES`
6. `PATH`
7. `LD_LIBRARY_PATH`

Confirm that the custom binary is active:

```bash
"$OPENSSL_ROOT/bin/openssl" version -a
```

The version must report OpenSSL 3.5.7 from the repository-local installation,
not `/usr/bin/openssl`.

Confirm that the experiment timing option is installed:

```bash
"$OPENSSL_ROOT/bin/openssl" s_client -help 2>&1 | grep handshake_time
```

`-handshake_time` reports `TLS_HANDSHAKE_TIME_MS` from immediately before
OpenSSL calls `BIO_connect` to immediately after OpenSSL writes the outgoing
client TLS `Finished` handshake message. This corresponds to TCP SYN start
through client Finished transmission. DNS lookup, provider startup,
application I/O, `close_notify`, and process shutdown are excluded.

This boundary was checked against a packet capture over 10 TLS 1.3 handshakes.
The internal timer differed from packet timestamps by 0.020 ms on average and
0.022 ms at maximum. Do not replace this value with whole-process wall-clock
timing.

## 5. Verify The Provider

```bash
"$OPENSSL_ROOT/bin/openssl" list -providers \
  -provider-path "$OQSPROV_MODULES" \
  -provider oqsprovider \
  -provider default
```

Both `default` and `oqsprovider` must be active.

Check representative added signature algorithms:

```bash
"$OPENSSL_ROOT/bin/openssl" list -tls-signature-algorithms \
  -provider-path "$OQSPROV_MODULES" \
  -provider oqsprovider \
  -provider default \
  | grep -E 'hawk512|mayo1|snova2454|mqom2cat1gf16fastr5|sdiththresholdcat5gf256'
```

If an expected name is missing, do not start a long benchmark. Record the
three component revisions and inspect the provider build first.

## 6. Run Local TLS Smoke Tests

```bash
./scripts/test_tls_sigalg.sh falcon512
./scripts/test_tls_sigalg.sh hawk512
./scripts/test_tls_sigalg.sh mayo1
./scripts/test_tls_sigalg.sh snova2454
./scripts/test_tls_sigalg.sh mqom2cat1gf16fastr5
```

Use the large-certificate client when the certificate exceeds OpenSSL's
default certificate-list limit:

```bash
./scripts/test_tls_sigalg.sh qruov5q7l10v1490m190 --large-cert
```

Each command must print an algorithm name, certificate DER size, and TLS
handshake time without an OpenSSL provider or certificate error.

## 7. Re-entering An Existing Installation

After reconnecting over SSH:

```bash
cd ~/pqc-tls-siglab
export PQC_TLS_TESTBED="$PWD"
source ./scripts/env.sh
```

No rebuild is required unless a pinned component revision or build option has
changed.

## 8. Optional Overrides

The defaults are pinned for reproducibility. Developers can override them
before building:

```bash
export OPENSSL_REPO=https://github.com/openssl/openssl.git
export OPENSSL_REF=openssl-3.5.7
export LIBOQS_REPO=https://github.com/jelliyjane/liboqs-pqc-tls-siglab.git
export LIBOQS_REF=fa33db143fb12a2e1e306b51ab3c8c98432a46c4
export OQSPROVIDER_REPO=https://github.com/jelliyjane/oqs-provider-pqc-tls-siglab.git
export OQSPROVIDER_REF=29f791a772b8c72506efba414ef616bc48cac9ab
./scripts/build_aws.sh
```

Results produced with overridden revisions must record the actual commit
hashes and must not be mixed with the pinned baseline results.

## 9. Common Failures

### The system OpenSSL is used

Run `source ./scripts/env.sh` and invoke
`"$OPENSSL_ROOT/bin/openssl"` explicitly.

### `oqsprovider` cannot be loaded

Confirm that `OQSPROV_MODULES` contains `oqsprovider.so` and that
`LD_LIBRARY_PATH` contains the installed liboqs and OpenSSL library paths.

### A large certificate produces `excessive message size`

Use `--large-cert`. The bundled C client raises the certificate-list limit to
512 KB.

### The build is killed

Reduce `JOBS` to 1 or 2 and confirm that the host has sufficient RAM and disk
space.

### A long AWS test is about to start

Run every algorithm as a smoke test first. Verify the network interface names,
TLS port, security-group rules, `tc` cleanup command, certificate chain, and
trust root before collecting timing data.

## 10. Reproduction Scope

This installation guide reproduces the pinned cryptographic build and local
TLS smoke workflow. The current status of the complete multi-region paper
experiment is tracked in `REPRODUCIBILITY_STATUS.md`.

Never commit PEM private keys, AWS credentials, generated private keys, or
user-specific absolute paths.
