# PC TLS benchmark results

Completed PC campaign summaries and EVP v2 cost measurements, exported on
2026-09-30. This release supports offline comparison and Pareto-filter experiments
using existing measurements. It does not report new experiments or model results.

## Files

| CSV | Rows | Purpose |
| --- | ---: | --- |
| [x25519_bw1_5_50_summary.csv](x25519_bw1_5_50_summary.csv) | 17,640 | Forced X25519, BW 1, 5, 50 Mbps |
| [x25519_bw100_summary.csv](x25519_bw100_summary.csv) | 5,880 | Forced X25519, BW 100 Mbps |
| [openssl_default_bw1_5_50_summary.csv](openssl_default_bw1_5_50_summary.csv) | 16,920 | Default OpenSSL ClientHello, BW 1, 5, 50 Mbps |
| [server_sign_frankfurt_evp_v2.csv](server_sign_frankfurt_evp_v2.csv) | 147 | Use `sign_mean_ms` for the server signing cost |
| [client_verify_seoul_evp_v2.csv](client_verify_seoul_evp_v2.csv) | 147 | Use `verify_mean_ms` for the PC client verification cost |

The three TLS files contain 40,440 condition summaries representing 1,683,600
successful measurements. Per-run TLS data are not included in this release.
Both cost files retain signing and verification columns from the original
measurements; use the columns indicated above for the respective deployment roles.

## TLS conditions and aggregation

- Server regions: Seoul, Tokyo, Singapore, USA (Virginia), Frankfurt.
- Certificate configurations: `chain1ica` through `chain4ica`. The number denotes
  intermediate CAs, not the total number of certificates sent.
- Configured packet loss: 0% and 1%.
- Forced-X25519 campaigns: 147 candidates, comprising 49 pure PQC and 98 composite
  candidates. Each condition uses 50 measurements, averages all 50, and has a
  one-second inter-run delay. BW 1/5/50 represents 882,000 measurements; BW 100
  represents 294,000.
- Default-ClientHello campaign: 141 candidates, excluding six HAWK-based candidates.
  The runner omitted `-groups`; `key_exchange_group` retains the recorded group.
  At 0% loss, it averages the fastest 7 of 10 measurements, with a 0.5-second
  inter-run delay. At 1% loss, it averages the fastest 35 of 50 measurements, with
  a one-second delay. This campaign represents 507,600 measurements.
- `tls_handshake_time_ms` uses the original timing method:
  `tcp_connect_start_to_tls_finished_openssl_internal`. It includes TCP connection
  establishment and is not a measurement of TLS processing alone.

Do not pool these campaigns as if their key exchange and aggregation methods were
identical. In particular, an all-sample mean and a fastest-70% mean are different
statistics. The old unshaped reference experiment is not included or relabeled as
100 Mbps. Board measurements are also excluded.

## Columns and joining

Within each TLS file, use `(region, certificate_mode, bw_mbps, lossrate, algorithm)`
as the unique condition key. Join cost profiles on the exact, case-sensitive
`algorithm` string, not CSV row number.

- `suite`: `pure` or `composite`. Composite denotes an existing RSA or ECDSA
  signature combined with a PQC signature, not a choice between two certificates.
- `configured_key_exchange`: campaign policy, distinct from an observed group.
- `key_exchange_group`: original summary value where available. The BW 1/5/50
  forced-X25519 source summaries did not contain this column, so it is not invented.
  Early BW100 raw records had missing group reporting; a summary group value must
  not be interpreted as proof that every underlying raw row recorded the group.
- `rtt_ms`: original recorded campaign RTT metadata, not a new per-handshake RTT
  measurement made by this export.
- `bw_mbps`: configured bandwidth in Mbps. `lossrate` is a percentage string.
- `sample_count`, `kept_count`: collected and retained sample counts.
- `tls_handshake_time_ms`, `min_ms`, `max_ms`: original summary values in milliseconds.
- `security_level`: original source label, preserved without relabeling. Some
  source records use `L2`; these are not silently changed to the paper's grouped
  level labels. Apply an explicitly documented policy mapping if needed.

The candidate names in these files are the recorded experiment identifiers.
This release does **not** provide an audited mapping to Bandit arm IDs or TLS
SignatureScheme code points. Do not infer either from row order.

## EVP v2 cost protocol

Each profile contains 147 algorithms, with 50 recorded iterations after five
warmup iterations and a 1,000 ms delay. There is no trimming. The input is a
130-byte TLS 1.3 server CertificateVerify message using a fixed SHA-256 transcript
digest.

The timed operations include `EVP_DigestSignInit_ex` plus `EVP_DigestSign`, or
`EVP_DigestVerifyInit_ex` plus `EVP_DigestVerify`. Process startup, provider loading,
key import, buffer allocation, context reset, CSV output, and sleep are excluded.
Times and standard deviations are in milliseconds; `signature_bytes_mean` is in
bytes. The recorded runtime used OpenSSL 3.5.7 and oqs-provider 0.12.0-dev, with a
separate provider build for the 12 composite SLH-DSA-SHAKE candidates.

These are CertificateVerify costs, **not whole-chain verification costs**. The
Seoul profile was measured on the PC client host, not on a recipient's desktop.
They are suitable for reproducing the existing cost assumptions, not for claiming
identical costs on different hardware. The older v1 diagnostic profile is excluded.
Selected hardware and protocol metadata are in [provenance.json](provenance.json).

## Using the results for a Pareto experiment

1. Use the recorded algorithm strings to join the server signing and client
   verification costs to the TLS summaries.
2. Fix the campaign, region, bandwidth, loss, and chain configuration before
   comparing measured TLS latency across algorithms.
3. Restrict candidates to the chosen security policy and client-supported set
   before constructing a Pareto frontier. Keep those experimental assumptions
   separate from the original observations.

This release does not include certificate/public-key size profiles, full-chain
verification profiles, client-support traces, a trained policy, or per-run TLS
data. If the proposed filter uses certificate bytes as an objective, these CSVs
alone are insufficient: `signature_bytes_mean` is not certificate or chain size.
Likewise, summaries alone cannot reproduce tail distributions or per-run learning.

## Export checks and provenance

All 40,440 summary rows were checked against their canonical raw files for sample
counts, successful status, duplicate run IDs, and the appropriate mean (within
0.0011 ms of the rounded stored summary). The raw sample total was 1,683,600.
All 294 raw cost-file hashes were checked against the stored EVP averages.

The export retains measured value strings and source labels. It removes client
IP addresses and server ports, adds region, suite, and configured-key-exchange
labels, and combines the canonical scope summaries into one CSV per campaign.
It does not fill missing measurements, retrain a model, or change source files.
Attempt journals, preserved retries, and quarantined duplicates are not pooled
with completed canonical results.

[provenance.json](provenance.json) records relative source filenames and SHA-256
hashes for audit; these source files remain in the original experiment archive
and are not all included here. `raw_sha256` in the cost CSVs refers to the original
per-algorithm raw file. [SHA256SUMS](SHA256SUMS) covers the published data files.
