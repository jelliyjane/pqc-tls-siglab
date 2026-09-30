# Optional build and remeasurement

For the Pareto-filter task, start with [README.md](README.md). This document is only for inspecting or rebuilding the cryptographic environment.

## Source code and versions

| Component | Recorded runtime | Public rebuild source |
| --- | --- | --- |
| OpenSSL | 3.5.7 | `openssl-3.5.7`, plus the existing handshake timing patch |
| liboqs | Installed header reports 0.15.0 | [self-contained liboqs fork](https://github.com/jelliyjane/liboqs-pqc-tls-siglab/tree/fa33db143fb12a2e1e306b51ab3c8c98432a46c4), commit `fa33db143fb12a2e1e306b51ab3c8c98432a46c4` |
| Standard oqs-provider | 0.12.0-dev | [custom provider fork](https://github.com/jelliyjane/oqs-provider-pqc-tls-siglab/tree/da0d3156af41915792cb99ce7a64b1a7633ce8f6), commit `da0d3156af41915792cb99ce7a64b1a7633ce8f6` |
| Additional SHAKE provider | 0.12.0-dev | Same provider commit plus `provider-shake98.patch` |

The repository's [baseline build script](../../scripts/build_aws.sh) records the
OpenSSL configuration and CMake flags, including explicit enablement of FAEST,
HAWK, QR-UOV Round 2, and SDitH. [env.sh](../../scripts/env.sh) supplies the private
SLH-DSA OID overrides used by the testbed. Keep these overrides when reproducing
the experiment identifiers; OIDs are not TLS code points.

### Historical provenance limitation

The installed binary hashes are verified, but the exact historical liboqs source
commit cannot be established from the surviving checkout and cache. The old
cache disables four experimental families that the installed header enables;
the current checkout HEAD is therefore not reliable evidence of the installed
binary's source. The public self-contained liboqs commit above is a rebuild
baseline, **not a recovered historical commit**. The standard provider's old
checkout is also not presented as the installed binary's exact source.

The SHAKE source patch is recovered from its separate build workspace. Applying
it to the pinned provider commit has been checked, and its selected code points
are checked against the runtime mapping. A new clean Linux compilation and
bit-identical or timing-equivalent reproduction of the full stack have not been
performed for this release. Do not claim an identical measurement environment
solely because these sources build successfully.

## Build and check on a clean Ubuntu machine

Use a fresh clone of **main**, not the older `repro-self-contained-v1` tag, to get
these handoff files. Follow [INSTALL.md](../../docs/INSTALL.md) for prerequisites.
From the repository root:

```bash
export PQC_TLS_TESTBED="$PWD"
bash scripts/build_aws.sh
source scripts/env.sh
bash scripts/build_pc147_shake_provider.sh
python3 repro/pc147/check_handoff.py
```

The additional build is placed in
`src-work/build-oqs-provider-shake98-repro/lib`; it is not installed over the
standard provider. The script refuses to overwrite an existing reproduction
source/build directory. Generated provider C sources are supplied in the patch,
so no generator run is required to build that snapshot.

Check the standard build separately (the Linux layout below uses `lib64`):

```bash
python3 repro/pc147/inspect_provider.py \
  --libcrypto "$OPENSSL_ROOT/lib64/libcrypto.so.3" \
  --provider-dir "$OQSPROV_MODULES" \
  --provider-build standard \
  --mapping repro/pc147/algorithm_mapping.json
```

The additional build script runs the corresponding check for the SHAKE scope.
Both checks must report an empty `errors` list before using the identifiers for
new measurements. They check name, provider, and code point availability, not
cryptographic correctness, full TLS interoperability, or performance equivalence.

## Existing costs or optional remeasurement

For the same offline cost assumptions, use `sign_mean_ms` from the published
Frankfurt profile and `verify_mean_ms` from the Seoul client profile. These are
CertificateVerify costs, not full certificate-chain verification costs.

If a separate desktop profile is needed, the supplied `evp_sig_bench.c` accepts
a locally generated test key, provider directory, provider name, warmup count,
iteration count, and delay in milliseconds. The historical settings were
`5 50 1000`. Compile with the existing OpenSSL headers and libcrypto using
`-O2 -Wall -Wextra -Werror`, as recorded by the original cost runner. Never put
private keys in this repository. New desktop measurements are a different
hardware profile and must not replace or be labeled as the original server data.
