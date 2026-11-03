# CTI restrictions at certificate selection

This prototype accepts a **local OASIS STIX 2.1 bundle** and separate,
operator-owned mapping rules. It compiles them to a bounded runtime allowlist,
which `tls_context_selector_server.c` reads inside its certificate callback.
It does not change the cost model, training checkpoints, or recorded experiments.

## Standard vs local policy

- Standard: [STIX 2.1, OASIS Standard](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html),
  especially sections 3.6 (versioning), 4.19 (Vulnerability) and 8 (Bundle).
- Supported input profile: `vulnerability` SDOs with `spec_version: "2.1"`,
  `id`, `name`, `created`, `modified`, and `created_by_ref`. This consumer
  requires the optional creator field for its publisher allowlist. UTC STIX
  timestamps with 3–6 fractional digits are supported. Other object types may
  accompany vulnerabilities but do not trigger restrictions in this version.
- Local policy: which vulnerability IDs affect which exact OpenSSL candidate
  names, which creator IDs the operator accepts, the base allowlist, and policy
  expiration. **These are CATS rules, not STIX-standard algorithm verdicts.**
- A vulnerability's presence is not proof that a cryptographic algorithm is
  broken. The operator must review affected implementation versions and scope
  before mapping it to a candidate. Descriptions are never executed or parsed
  into automatic security judgments; no ML model decides whether CTI is true.
- `created_by_ref` is attribution, not authentication. Use authenticated CTI
  ingestion in the server's existing security management system. This compiler
  does not fetch TAXII feeds, authenticate publishers, validate signatures, or
  claim full STIX schema validation. Input files and runtime output must be
  writable only by the trusted operator/service account. The SHA-256 revision
  is an audit identifier, **not** a signature or authenticity check.

The existing experimental `pqc_cti/policy.py` custom evidence schema remains
unchanged. This new production-facing prototype bridge uses explicit operator
mapping rather than silently treating that old schema as STIX.

## Operation

1. Supply a complete STIX bundle and operator rules. Example shapes are in
   `config/cti/example.synthetic.stix.json` and `config/cti/example.rules.json`.
   These are **synthetic fixtures, not real vulnerability reports**. The example
   rules intentionally expired in 2000: set a reviewed UTC `valid_until` before
   using a COPY for testing. Do not deploy the synthetic publisher as trusted.
2. Set `allowed_algorithms` to the exact names in the server's candidate manifest.
   A name not listed is denied. Names are case-sensitive and not normalized.
   List affected hybrid names explicitly along with pure algorithms; no prefix
   or substring guessing is performed. Every rule contains a `stix_id` and
   nonempty `deny_algorithms`, which must be a subset of the base allowlist.
3. Compile, running from the repository root, with Python 3.10+ (stdlib only):

   ```sh
   python3 scripts/compile_cti_policy.py \
     --bundle /absolute/path/trusted-bundle.json \
     --rules /absolute/path/operator-rules.json \
     --output /absolute/path/cats-policy.txt
   ```

   The parent directory must already exist. Run the compiler and prototype as
   the same service account (new snapshots are mode 0600). The compiler prints
   a JSON audit record containing the input revision, matched rules, excluded
   algorithms, and unmapped vulnerability IDs. Capture this in service logs.
4. Start the existing server command with:

   ```sh
   export CATS_CTI_POLICY=/absolute/path/cats-policy.txt
   ```

   The normal build scripts need no new linker flags: the bounded runtime
   reader is header-only. Unset `CATS_CTI_POLICY` preserves historical behavior;
   an explicitly empty value is a configuration error, not a way to disable it.
5. Recompile after input changes, or run the compiler under the operator's
   service manager with `--watch 1` to poll once a second. This option reads only
   local files. Update those files atomically. The output is also replaced
   atomically, so each callback sees one complete revision. The next selection
   after publication uses it without restarting the TLS server.

`valid_until` is an **operator policy freshness deadline**, not a STIX
Vulnerability field. The watcher never extends it automatically. Missing mapped
objects, untrusted creators, conflicting versions, malformed data, or expired
rules cause the compiler to publish an expired deny-all snapshot and report an
error. If it cannot write the output, it exits nonzero; the service manager must
alert on this failure. The existing snapshot can then remain usable until its
deadline. Choose an appropriately short deadline for the deployment.

Unmapped vulnerabilities are reported but do not imply restrictions. A missing
mapped vulnerability is an error rather than an implicit unblock: supply complete
bundles, not TAXII deltas. Within a bundle, the latest `modified` version is used;
`created` and creator cannot change, conflicting versions are rejected, and no
version may follow a revoked version. A trusted `revoked: true` removes that
object's deny contribution; other deny rules still apply. This compiler is
stateless across input bundles: cross-update rollback/revocation history must be
enforced by the upstream trusted CTI store. It is not a general CTI database.

## Enforcement boundaries

- The callback intersects the runtime allowlist with the client signature
  algorithms **before** context acquisition, sidecar requests, or scoring.
- Local scoring, sidecar failure fallback, and sidecar results all use that same
  candidate mask. A sidecar cannot select a denied algorithm.
- A missing, unreadable, malformed, truncated, or expired runtime snapshot fails
  certificate selection. An empty intersection also fails; no denied candidate
  is substituted. No last-known-good permissive fallback is used.
- CTI-enabled mode disables session tickets and session caching, because this
  prototype enforces restrictions in full-handshake certificate selection, which
  TLS resumption could otherwise bypass. Existing established connections are
  not terminated; resumption-aware policy enforcement is outside this change.
- This is candidate selection policy, not a replacement for OpenSSL security
  levels, certificate/path validation, or a scan of every issuer algorithm in a
  heterogeneous certificate chain. Provision appropriately reviewed candidate
  certificates/chains. TLS message formats are unchanged.
- The original CTI-only release protects the selector's candidate boundary
  independently of its scoring backend. The subsequent learned-model release
  is documented in [adaptive-runtime.md](adaptive-runtime.md).

## Verification

```sh
python3 scripts/test_cti_policy.py --openssl-prefix /path/to/openssl
```

The test compiles the real server, generates temporary self-signed Ed25519/ECDSA
certificates, and connects only to loopback. It verifies selection changes in the
same server process, no-compatible-candidate rejection, deny-all, missing/bad/
expired policies, trusted CTI revocation, disabled ticket issuance, blocked
sidecar outputs and safe fallback. Separate tests cover parsing, exact hybrid
mapping, version conflicts, trust filtering, atomic publication and the watcher.
`python3 scripts/test_cti_policy.py` runs compiler/parser tests without TLS when
OpenSSL development files are unavailable.

Initial local verification on 2026-10-18 used OpenSSL 3.6.2 on macOS.
The existing context unit test cannot compile on macOS because it uses
`pthread_condattr_setclock`; it was subsequently run successfully on AWS Linux.

## AWS deployment verified on 2026-10-18

- Host: the existing Seoul server, `ubuntu@3.34.48.95`.
- Release: `/home/ubuntu/cats-cti-20261018-6anbBT` (persistent, separate from
  the existing testbed source and executable).
- OpenSSL: the testbed's existing 3.5.7 installation at
  `/home/ubuntu/jelliyjane-repos/pqc-tls-siglab/install/openssl`.
- Build: `bash scripts/build_cti_release.sh OPENSSL_PREFIX`. This enables
  `CATS_CONTEXT_ACQUISITION` and builds the signing-time interposer.
- Results: all 19 CTI tests passed with native ML-DSA-44/ECDSA certificates
  against the deployed binary, including hot reload, fail-closed behavior and
  sidecar filtering. Successful handshakes also checked valid context acquisition.
  The context unit test, 128-live-socket/concurrent-reader test, and TCP window
  test passed. TLS tests used loopback on the EC2 host, not an inter-region path.
- Server executable SHA-256:
  `26ab1777333e2d9f96c5fd2a01fdfbc158f10f87478010089a3acde9c6ffd848`.
- Evidence: `verification.log` in that release (local copy in
  `docs/verification/cti-aws-seoul-20261018.log`).

Start this release after compiling reviewed CTI and rules as described above:

```sh
cd /home/ubuntu/jelliyjane-repos/pqc-tls-siglab
. scripts/env.sh
export CATS_CTI_POLICY=/absolute/path/reviewed-policy.txt
bash /home/ubuntu/cats-cti-20261018-6anbBT/scripts/run_cti_server.sh \
  PORT MANIFEST_TSV PROVIDER_MODULE_PATH X25519 MAX_CONNECTIONS
```

The launcher requires a policy and loads the signing timer. It does not configure
CTI feeds or enable a service automatically. All verification used explicitly
synthetic CTI and temporary certificates; none was installed as an active security
policy. Test processes were stopped. Existing testbed files, certificates,
benchmarks, checkpoints, `scripts/env.sh`, and network shaping were unchanged;
`enX0` retained its original `fq_codel` configuration. The latest trained model
checkpoint was not part of this initial release; its subsequent AWS integration
and cross-host verification are recorded in [adaptive-runtime.md](adaptive-runtime.md).
