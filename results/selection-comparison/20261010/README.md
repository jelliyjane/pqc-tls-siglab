# OpenSSL order-based selection vs CATS — 2026-10-10

This is a **matched runtime microbenchmark**, not the offline replay and not a
measurement of total TLS handshake latency. It uses the actual OpenSSL selection
path and the saved final LinUCB model, connected by a new benchmark-only adapter.
The older selector server's deterministic fallback is not used as CATS.

## Results

All values are microseconds (µs). Each row pools three runs of 500 measured
handshakes after 100 warmups per process. Modes alternate run order. There are
6,000 measured handshakes and 1,200 excluded warmups overall.

| Server preference | Method | Selected credential | Mean | Median | p95 | p99 |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| ML-DSA first | OpenSSL native order | ML-DSA-44 | 6.965 | 5.213 | 6.930 | 18.246 |
| ML-DSA first | CATS + Python sidecar | Falcon-512 | 1,044.756 | 827.808 | 1,735.300 | 1,917.676 |
| Falcon first | OpenSSL native order | Falcon-512 | 786.590 | 595.833 | 1,511.932 | 1,816.345 |
| Falcon first | CATS + Python sidecar | Falcon-512 | 1,034.826 | 830.284 | 1,737.693 | 1,936.659 |

For the **same selected credential (Falcon-512)**, the difference of mean
selection times is **248.236 µs (0.248 ms)**, or 31.56% of the baseline selection
time. These are independently sampled means, not a paired per-connection delta.
The ML-DSA-first comparison also changes the selected algorithm and its native
usability-check cost; its 1,037.790-µs difference must not be described as pure
model inference overhead. No handshake-latency improvement follows from this test.

### CATS breakdown, Falcon-first case

| Section | Mean µs |
| --- | ---: |
| OpenSSL shared signature-list preparation | 1.851 |
| Context collection (two cached profiles) | 3.825 |
| Candidate-mask construction + model round trip | 233.512 |
| └ Python request parsing + context transform + LinUCB + candidate scoring (included above) | 172.462 |
| Apply the selected in-memory certificate/key | 35.758 |
| Remaining native selection/checks and instrumentation between sections | 759.879 |
| Total | 1,034.826 |

The Python row is nested, not an additional cost. The remainder is calculated
from the measured total minus the other non-nested sections; it is not a separate
timer. The prototype uses a persistent Unix socket to a Python/NumPy process.
Its communication, process scheduling and serialization are **included**. It is
not an optimized in-process C implementation of LinUCB.

## Exact start and stop points

The same timing-only patch is used for both modes in a disposable OpenSSL 3.5.7
build. No installed OpenSSL library is overwritten. In `ssl/statem/statem_srvr.c`:

1. **Shared-list span:** start immediately before the call to
   `tls1_set_server_sigalgs(s)`, stop immediately after its success check. This
   includes preparing shared signature schemes and the configured ordering.
2. **Decision span:** start immediately before the certificate-callback block
   in `tls_post_process_client_hello`, stop immediately after successful
   `tls_choose_sigalg(s, 1)`. By that point the native code has set
   `s->s3.tmp.cert` and `s->s3.tmp.sigalg`.
3. **Reported selection time = span 1 + span 2**, not elapsed time across the gap.
   Unrelated ClientHello processing between these spans is excluded identically.

For native order selection there is no custom certificate callback. For CATS,
the callback collects context, filters to the two shared/preapproved candidates,
calls the final model, scores candidates and applies the chosen certificate/key.
Both modes then execute the native `tls_choose_sigalg` usability check.

Timing uses `clock_gettime(CLOCK_MONOTONIC)`; samples are saved in nanoseconds.
Timer and hook overhead are included and not subtracted. Raw files also include
10,000 clock-pair measurements per process. Logging is outside timed spans.

### Included and excluded

- Included: compatibility-list preparation, native algorithm/certificate
  usability checks, and CATS collection/model/IPC/credential-application work.
- Native usability checks are not merely array comparisons. OpenSSL 3.5.7's
  `check_cert_usable` calls `EVP_PKEY_digestsign_supports_digest`, which calls
  `EVP_DigestSignInit_ex`. Provider initialization during those checks is included.
  The expensive Falcon path is not isolated further in this benchmark, so no
  individual provider routine is claimed to explain its entire cost.
- Excluded: TCP connection establishment, ClientHello reception/parsing, actual
  CertificateVerify signing and client verification, network waiting, model/file
  loading, socket registration/final sampling and signing-time EWMA updates.
- A signing hook confirms one actual `EVP_DigestSign` call per handshake, but its
  duration is outside the reported selection spans.

## Matched conditions and limits

- Same server/loopback client, TLS 1.3, X25519, no resumption, TCP_NODELAY on both
  sides, one connection at a time; same certificate/key files in every mode/run.
- One self-signed certificate per algorithm, explicitly trusted by the test
  client. This is not a four-ICA or public-Web deployment test.
- Client advertises `mldsa44:falcon512`. Server preference is enabled and tested
  in both orders. Both credentials are preapproved; there is no dynamic external
  security-policy lookup. ML-DSA-44 is C2 and Falcon-512 C1, both admissible for
  this L1/minimum-C1 inventory.
- OpenSSL 3.5.7 plus the host's oqsprovider/liboqs build (Falcon is provider-backed;
  ML-DSA is native). This is not a provider-independent OpenSSL constant.
- Linux 7.0.0-1006-aws, one Intel Xeon E5-2686 v4 vCPU. Python 3.14 with NumPy
  2.3.5; BLAS/OpenMP thread count is one. Scheduler noise is retained in the data.
- Final saved `condition/models/fold0_L1_seed42.json`: 286 arms, five context
  features and four normalized costs. The adapter directly imports the release's
  `LinUCBAgent.select`; it does not substitute a fixed weight vector or use
  precomputed per-context choices. The model is frozen, not retrained or updated.
- RTT/window come from the current TCP socket. Loss is the recent aggregate
  retransmission proxy. BW uses the 1,000-Mbps fallback (no usable BW history).
  Signing-time estimates are updated after each CATS handshake; verification
  estimates start from published pure profiles. No network-estimation accuracy
  claim is made.
- Costs use the actual test certificate DER size plus signature upper bound and
  a 200-byte framing estimate; this is not wire-exact flight-size validation.
- **Two real candidate credentials**, not 150. The earlier acquisition-only
  benchmark copied 150 cached profiles and did not execute a selection model.
  Its 4.49–4.59 µs must not be substituted for this complete selection result.

## Verification and artifacts

Every measured handshake authenticates successfully. Assertions confirm four
timing hooks, one actual signature, both candidates offered, stock selection
matching its configured order and CATS selection matching the returned model
choice. Before serving, the adapter checks the release's arm selection against
an independent matrix expression for 100 deterministic random contexts.

`summary.json` contains pooled/per-run timings, source and binary hashes,
certificate hashes, selected-algorithm counts and estimate provenance. Twelve
`*.jsonl.gz` files preserve all samples. Local audit confirmed all source hashes,
6,000 sample rows, stage sums and pooled means. No private keys are saved here.

## Reproduction

Requires a disposable **configured and built** copy of the matching OpenSSL
3.5.7 source tree, the compatible provider/liboqs installation, and Python with
NumPy 2.3.5. Do not patch the installed source tree. From this repository root:

```bash
python3 scripts/instrument_selection_openssl.py /path/to/disposable-openssl
make -C /path/to/disposable-openssl -j2 libssl.so.3
cc -O2 -g -std=c11 -Wall -Wextra -Werror -pthread -rdynamic \
  -I/path/to/disposable-openssl/include \
  src/bench_selection_compare.c src/cats_context.c \
  -L/path/to/disposable-openssl -Wl,-rpath,/path/to/disposable-openssl \
  -lssl -lcrypto -ldl -lm -o /path/to/bench_selection_compare
python3 scripts/run_selection_comparison.py \
  --binary /path/to/bench_selection_compare \
  --instrumented-openssl /path/to/disposable-openssl \
  --openssl-prefix /path/to/installed-openssl \
  --oqs-lib /path/to/liboqs/lib \
  --sign-hook /path/to/libcats_sign_timer.so \
  --output /path/to/new-output-directory --iterations 500 --runs 3
```

The signing hook is built by `scripts/build_context_acquisition.sh`. The adapter
is benchmark-only and does not replace the legacy selector's sidecar protocol.
