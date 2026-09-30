# 147-candidate experiment handoff

Use this directory with the [published PC results](../../results/pc_tls_20260929/README.md).
It supplies the candidate identifiers, Bandit action definitions, custom provider
patch, and build information needed to interpret those results.

## What is included

- [algorithm_mapping.json](algorithm_mapping.json): all 49 pure PQC and 98
  composite candidates, their OpenSSL arguments, fetched EVP signature names,
  provider names, TLS SignatureScheme names, and hexadecimal/decimal code points.
- [bandit_arms.json](bandit_arms.json): zero-based arm IDs and their weight vectors
  from the saved models. It contains the September 27 five-term model's 126 arms
  and the older three-term model's 66 arms, under separate variant names.
- [build_provenance.json](build_provenance.json): runtime versions, binary hashes,
  public source pins, runtime OID overrides, and the limits of the recovered
  historical build information.
- [provider-shake98.patch](provider-shake98.patch): the generator changes and
  generated C changes from the actual isolated SHAKE provider source, relative to
  provider commit `da0d3156af41915792cb99ce7a64b1a7633ce8f6`. Provider licensing is
  included in [PROVIDER_LICENSE.txt](PROVIDER_LICENSE.txt).
- [evp_sig_bench.c](evp_sig_bench.c): the cost benchmark source, byte-for-byte
  matching the source hash in the original EVP v2 protocol.
- [inspect_provider.py](inspect_provider.py): a read-only runtime capability and
  identifier check for a recipient's build. It does not run TLS measurements.
- [check_handoff.py](check_handoff.py): local consistency and historical-hash checks.

## Identifier mapping

Join result CSVs to the mapping using the exact `algorithm` string. Do not use
row order as an identifier. `openssl_algorithm_argument` is the experiment's
OpenSSL-facing name; `evp_signature_name` is the name returned by
`EVP_SIGNATURE_fetch`. For example, `mldsa44` resolves to `ML-DSA-44` in OpenSSL's
`default` provider. The provider field must not be assumed to be `oqsprovider`
for every candidate.

The mapping was queried on 2026-09-30 with `OSSL_PROVIDER_get_capabilities` and
`EVP_SIGNATURE_fetch`, without private-key access. The standard provider, SHAKE
provider, and libcrypto binary hashes match the September 12 EVP v2 records.
This establishes runtime identity for the cost profiles; it is not a fresh
packet-capture verification of every earlier TLS measurement.

The experiment used **two provider scopes**:

| `provider_build` | Candidates selected in the campaign |
| --- | --- |
| `standard` | 49 pure PQC plus the original 86 composite candidates |
| `shake98` | The 12 additional composite SLH-DSA-SHAKE candidates |

The SHAKE build can fetch all 147 names, but inserting SHAKE variants into the
generator changes some other composite assignments. Nine selected code points
are reused across the two historical scopes for different algorithms. The exact
pairs are listed in `cross_build_codepoint_reuse` in the mapping.

**Use `(provider_build, tls_code_point_decimal)` as the lookup key, not the code
point alone.** Match the provider build on both client and server. Do not load
both builds into one process or use the old standard-scope assignments with a
SHAKE-only server. These include experimental assignments; the mapping is not a
claim that all candidates or code points are standardized.

`source_security_level` preserves the original labels. `policy_level` records the
existing selector convention of grouping ML-DSA-44 and its composites into L1.
That grouping is a policy cohort, not a redefinition of the algorithm's security
category. The two fields are intentionally separate.

## Bandit arm IDs are not algorithm IDs

The saved Bandit selects a **weight vector**. The cost rule then selects an
eligible algorithm for the current context. Consequently, there is no fixed
`arm_id -> algorithm -> code_point` mapping. `bandit_arm_id` is explicitly null
in each candidate row rather than an invented index.

For the five-term model, the weight order is:

1. `sign_ms`
2. `transmission_ms`
3. `extra_round_ms`
4. `verify_chain_ms`
5. `i_tail`

The 126 action vectors were checked against all 75 saved models in the
`tail5_step02_x25519_20260927/unified_evp` run. Their IDs are the original
zero-based positions in `actions`. The older model uses three terms, in the
order `sign`, `size_over_bandwidth`, `critical_path`, and has 66 actions.
Never interchange IDs between model variants.

For a Pareto-filter comparison, use algorithm strings as candidate IDs and keep
the selected model's existing weight-arm IDs unchanged. After applying the
client-supported set and policy constraints, an arm's selected candidate can
change with context. Trained model parameters are not included or modified here.

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
these handoff files. Follow [INSTALL.md](../../INSTALL.md) for prerequisites.
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
