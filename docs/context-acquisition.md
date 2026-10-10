# Runtime context acquisition

This Linux prototype obtains context during real TLS 1.3 connections. It is
separate from the offline Bandit replay in `results/latest`. Adding this collector
does not retrain that model or establish the accuracy of its network estimates.

Measured results: [2026-10-10 real-TLS acquisition benchmark](../results/context-acquisition/20261010/README.md).

## Implemented sources

| Value | Implementation | Scope / missing data |
| --- | --- | --- |
| RTT | One `getsockopt(TCP_INFO)` on the accepted server socket; `tcpi_rtt / 1000` | Current kernel estimate in ms, not a new probe or a direct timestamp of SYN-ACK/ACK. Missing RTT is flagged. |
| W | `min(tcpi_snd_cwnd * tcpi_snd_mss, tcpi_snd_wnd)` in bytes | `snd_wnd` is already scaled. Zero is a closed window, not missing telemetry. Neither `rcv_space` nor a fixed window is substituted. |
| Loss | Sum of recent `total_retrans` deltas divided by `data_segs_out` deltas, across registered server sockets | Server-wide retransmission-ratio proxy, not the new client's measured loss probability. Data transmission counts include retransmissions, exclude pure ACKs. Baseline after accept excludes SYN retransmissions. |
| BW | EWMA of eligible `tcpi_delivery_rate` samples in 168 UTC weekday/hour slots, converted from bytes/s to Mbps | Historical, server-wide delivery-rate proxy, not path-specific available bandwidth. No claim that all clients share a bottleneck. |
| T_sig | Time around the actual non-NULL-output `EVP_DigestSign` call, then per-algorithm EWMA | Excludes size queries, DigestSign initialization, certificate serialization and network waiting. Uses profile initialization. The old message-callback `sign_phase_ms` remains explicitly distinct. |
| T_verify, S_TLS, n_cert | Existing profiles / candidate configuration | Not newly measured on the client; copying cached profile values is not live verification measurement. |

The collector makes **no send/write/connect calls**. The background sampler reads
registered application sockets; it does not create measurement connections.
`cats_collect` performs one TCP_INFO read and bounded cached lookups. Call it after
ClientHello, e.g. from the OpenSSL certificate callback. Returned flags distinguish
historical estimates from configured defaults and unavailable transport fields.

## Storage and update rules

- Only active sockets retain counter cursors. Call `cats_track` immediately after
  accept and `cats_untrack` **before** closing or reusing the descriptor.
- A worker samples every 1,000 ms; unregister also collects a final delta, so
  short connections are not omitted. The embedding application must register all
  sockets it wants represented, not merely the most recent client. This prototype
  does not collect other processes' or other hosts' connections.
- Loss uses 60 ten-second buckets (roughly ten minutes). Expired buckets are
  ignored. Counter deltas are attributed to observation time, giving bucket and
  sampling-interval granularity rather than exact per-packet timestamps. A gap
  of an entire retention window resets the cursor instead of reviving old data.
- BW samples require newly acknowledged bytes, a positive delivery rate and
  `delivery_rate_app_limited == 0`. No fresh ACK or application-limited samples
  do not update BW. Small handshakes may never yield an eligible BW sample.
- Each BW slot expires after 14 days. No history, expired history, or a clock
  rollback uses the configured fallback. Default BW=1,000 Mbps and Loss=0 are
  explicit **engineering defaults, not measurements**. Callers can change them.
- EWMA alpha=0.2 is configurable, not an experimentally selected optimum.
- `cats_bw_save/load` checkpoints only 168 aggregate slots using an atomic rename.
  No IPs, client identifiers, keys or per-connection histories are persisted.
  Schedule checkpoints outside selection; the example selector saves at clean
  exit. A crash before checkpoint can lose recent history. Signing EWMAs and
  loss buckets are in-memory and reset on restart.
- One context holds at most 4,096 active sockets and 512 algorithm profiles.
  Registration fails explicitly at capacity. The registry lock protects descriptor
  lifetime during sampling; the cache lock is not held across the whole scan.
  Connection registration/close can still wait for a scan. High-concurrency
  performance must be measured separately from the single-connection results.
- Stop/start calls are serialized; destroy the context only after all application
  threads have stopped calling its APIs. A manually supplied cursor belongs to
  one connection lifetime; do not reuse it for another socket.

## Build and tests

Requires Linux TCP headers with `tcpi_snd_wnd`, `tcpi_data_segs_out`,
`tcpi_bytes_acked`, `tcpi_delivery_rate` and shared OpenSSL 3.5.
No installed OpenSSL source or system network configuration is modified.

```bash
OPENSSL_PREFIX=/path/to/openssl bash scripts/build_context_acquisition.sh
python3 scripts/test_context_selector_live.py \
  --build "$PWD/build/context-acquisition" --openssl-prefix /path/to/openssl
python3 scripts/run_context_benchmark.py \
  --build "$PWD/build/context-acquisition" --openssl-prefix /path/to/openssl \
  --iterations 1000 --runs 3 --profiles 150 --output /path/to/new-result-directory
```

The deterministic unit test covers delta aggregation, unsigned counter wrap,
duplicate samples, no-new-ACK and application-limited filtering, expiration,
EWMA, missing data, BW persistence and concurrent worker lifecycle calls. The live
TCP test uses 128 registered connections and four simultaneous readers. The TLS
integration test uses ECDSA P-256 and ML-DSA-44, verifies certificates, checks the
signing hook and checks that a subsequent malformed ClientHello cannot reuse old
context measurements. These tests do **not** validate all 150 signature variants.

## Selector integration

`build_context_acquisition.sh` builds the existing selector with
`CATS_CONTEXT_ACQUISITION`; the original build without that define keeps its prior
behavior. Example (test certificates and manifest must already exist):

```bash
LD_LIBRARY_PATH=/path/to/openssl/lib64 \
LD_PRELOAD="$PWD/build/context-acquisition/libcats_sign_timer.so" \
TLS_REQUIRE_OQSPROVIDER=0 TLS_SELECTOR_REQUIRE_CLIENT_SIGALG_MATCH=1 \
TLS_SELECTOR_LISTEN_HOST=127.0.0.1 \
CATS_BW_HISTORY=/path/to/bw.cache \
TLS_SELECTOR_BANDWIDTH_MBPS=100 CATS_DEFAULT_LOSS=0 CATS_EWMA_ALPHA=0.2 \
build/context-acquisition/tls_context_selector_server \
  44333 /path/to/manifest.tsv /path/to/openssl/lib64/ossl-modules X25519 10
```

Use `lib` instead of `lib64` where appropriate. Set `TLS_REQUIRE_OQSPROVIDER=1`
when provider-only algorithms are needed. The collector returns loss as a
probability; the existing DECIDE2 protocol still receives percent, with an
explicit conversion. Updated T_sig values are read into the local candidate
profiles before local scoring. The existing RL sidecar protocol does **not**
transmit those updated per-candidate signing profiles; that separate integration
is not claimed here. The legacy fallback score is not the final four-term Bandit
evaluation, and this change does not replace it or enable new online training.

The signing timer uses Linux symbol interposition only around synchronous
handshakes on the current thread. It has been checked with shared OpenSSL 3.5.7
for ECDSA and ML-DSA-44. Static linkage, ASYNC jobs and migration of a handshake
across threads require another integration. Missing hooks fail startup; missing
signing samples are never replaced by the broader message-callback phase time.

## Interpreting timings

- `acquisition_ns`: TCP query + historical lookup + copy of 150 cached signing
  profiles during a real TLS certificate callback. Timer instrumentation is
  included; no clock overhead is subtracted.
- `track_ns`, `untrack_ns`: active-socket registration and final statistics update.
- `ewma_ns`: signing-profile EWMA update, **not the signing operation**.
- `sign_ns`: actual EVP signing operation; excluded from collection overhead.
- `sampler`: background batch time and count, separate from foreground calls.
- `per_connection_bookkeeping`: sum of the four measured foreground sections
  (collect, track, untrack, EWMA). This subtotal excludes background work, logging
  and the signing hook's own clock/wrapper overhead; it is not total system overhead.
- `micro`: repeated collection on an established socket, not a replacement for
  the actual per-handshake callback measurement.

The benchmark deliberately transfers a 64-KiB synthetic application response;
that is test workload, not measurement traffic generated by acquisition. Its
no-probe check verifies zero extra server data segments across 10,000 collection
calls. All printed/logged output is outside timed regions. Raw samples, source
and binary hashes, hardware metadata, warmup counts and percentiles are saved.

Results are acquisition microbenchmarks on one Linux host with IPv4 loopback and
one active TLS service connection. They must not be used as whole-selector
overhead, multi-region service performance, BW/Loss accuracy or a blanket
no-overhead claim. Host scheduling and instrumentation affect tails.

## Primary implementation references

- [Linux TCP_INFO fields](https://github.com/torvalds/linux/blob/master/include/uapi/linux/tcp.h)
- [Linux data-segment counter on original and retransmitted sends](https://github.com/torvalds/linux/blob/master/net/ipv4/tcp_output.c)
- [OpenSSL 3.5.7 CertificateVerify signing path](https://github.com/openssl/openssl/blob/openssl-3.5.7/ssl/statem/statem_lib.c)
