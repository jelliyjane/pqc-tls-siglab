# Runtime context acquisition measurements — 2026-10-10

Real TLS 1.3 connections on one Linux host, not offline replay. The certificate
callback reads TCP information, looks up cached BW/Loss estimates and copies
150 signing-profile entries. Only **ECDSA P-256 and ML-DSA-44** execute signatures;
150 is the number of cached profiles, not the number of algorithms tested here.

## Selection-time acquisition

Times in microseconds (µs), pooled over three runs per algorithm:

| TLS signing algorithm | Measured connections | Mean | Median | p95 | p99 | Maximum |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| ECDSA P-256 | 3,000 | 4.592 | 4.022 | 5.154 | 8.464 | 322.061 |
| ML-DSA-44 | 3,000 | 4.489 | 4.107 | 5.307 | 9.700 | 220.082 |

These are **context acquisition times**, not full signature-selection overhead
or a measured reduction in handshake latency. Clock instrumentation is included;
no baseline is subtracted. Scheduling on the shared virtual machine affects tails.

## Work outside selection

| Mean time (µs) | ECDSA P-256 | ML-DSA-44 |
| --- | ---: | ---: |
| Register an accepted socket | 2.992 | 3.002 |
| Collect final counters and unregister | 7.536 | 7.817 |
| Update the signing-time EWMA | 1.140 | 0.958 |
| Sum of acquisition and the above three sections | 16.259 | 16.266 |

The subtotal is not total system overhead: background sampling, logging and the
signing timer's wrapper/clock overhead are excluded. Actual cryptographic signing
time is reported separately in `summary.json` and is **not** charged as collection
overhead. Background sampling ran once per second; its mean batch duration was
7.787 µs (ECDSA) and 7.995 µs (ML-DSA), with one active socket per batch. This does
not establish sampling cost at thousands of simultaneous connections.

## Conditions and estimate provenance

- Linux 7.0.0-1006-aws, one vCPU, Intel Xeon E5-2686 v4 @ 2.30 GHz;
  shared OpenSSL 3.5.7 and GCC 15.2.0, optimized build.
- IPv4 loopback, TLS 1.3, X25519, certificate verification enabled, no session
  resumption. One service connection at a time.
- Three runs of 1,000 measured connections per algorithm, after 100 warmups per
  run: 6,000 measured connections and 600 excluded warmups overall.
- A 64-KiB synthetic application response supplies normal workload for the
  sampler. The collector itself sends no probe traffic.
- **BW used the configured 1,000-Mbps fallback in every measured connection.**
  The short workload produced no eligible non-application-limited BW history.
  Thus these timings do not validate historical BW accuracy or its populated-cache
  performance. Filtering, EWMA and persistence are covered by deterministic tests.
- Loss used recent aggregate counters in all measured connections. This is a
  server-wide retransmission proxy, not an independently measured loss probability
  for the new client's path. No packet loss was induced.
- Each run also made 10,000 repeated collection calls on an established socket;
  the server's data-segment counter did not increase during those calls.

## Verification

The following passed on the same Linux host:

- Deterministic unit tests: aggregation, duplicate/ACK filtering, expiry, counter
  rollover, EWMA, persistence, concurrent sampler lifecycle and missing telemetry.
- Live TCP test: 128 sockets, periodic sampling and four concurrent reader threads
  performing 40,000 queries. This is a correctness test, not a scaling benchmark.
- Existing selector integration: two authenticated TLS handshakes each for ECDSA
  and ML-DSA-44, one actual signing sample per handshake, reuse of the updated
  signing estimate, malformed-ClientHello reset and BW checkpoint creation.
- AddressSanitizer + UndefinedBehaviorSanitizer with leak detection: deterministic
  and live TCP tests passed. Sanitized binaries were not used for timing.
- Saved source hashes match the benchmark sources; raw sample counts and mean
  acquisition times match `summary.json`.

The selector integration does not add online Bandit training or transmit updated
per-candidate signing profiles through the existing RL sidecar protocol.

## Files and reproduction

`summary.json` contains conditions, source/binary hashes, per-run and pooled
statistics. The six `*.jsonl.gz` files contain raw samples, warmup metadata,
sampler totals, clock measurements and no-probe checks.

See [implementation and commands](../../../docs/context-acquisition.md).
Existing final TLS/Bandit evaluation results in `results/latest` are unchanged.
