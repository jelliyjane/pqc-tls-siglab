# Frozen learned weights in the AWS selector

The native C scorer now accepts the approved 2026-10-17 no-chain/cap-2 model.
This is inference only: no retraining, online coefficient update, or automatic
fallback to baseline. Historical artifacts and earlier releases are unchanged.

## Data and arithmetic

- Source checkpoints: `selection_no_chain_feature_ablation_20261017/no_chain/`
  `all_all_L1.npz`, `all_all_L3.npz`, `all_all_L5.npz`, initialization seed 731.
- `experiments/export_live_model_20261018.py` in the parent workspace verifies
  source hashes against `models_locked_before_test.json` before export. It keeps
  seven scaler slots `[0,1,2,3,4,5,7]` and the original `(20,4)` coefficient array.
- Inputs are RTT ms, BW Mbps, loss fraction (not percent), window bytes, signing
  ms, chain verification ms, and total server flight bytes. Log1p except loss;
  training mean/standard deviation; inactive features zero; clipping to [-3,3].
- Features are `[1, four connection values, three profile values, 4x3 products]`.
  Four weights are `2*sigmoid(phi^T theta)`. Costs are signing, transmission,
  additional rounds, and **chain-only** verification, in that order.
- Model mode excludes the legacy shared RTT, tail-signing and overlap terms.
  The score is not a calibrated prediction of elapsed handshake time.
- CTI and client compatibility filter candidates BEFORE model evaluation.
  Ties use unweighted cost sum, then exact algorithm name.

## Runtime

The model is loaded once at startup per level present in the candidate manifest.
`CATS_MODEL_DIR` enables inference. Missing/invalid files, unknown manifest levels,
an empty directory setting, or concurrent `TLS_RL_SOCKET` configuration abort
startup. Unset `CATS_MODEL_DIR` preserves the old scorer for explicit legacy runs.
Model files are trusted local deployment artifacts; hash strings are provenance,
not authentication. A model change requires a server restart; CTI updates do not.

The adaptive launcher requires CTI and enables the model by default:

```sh
cd /home/ubuntu/jelliyjane-repos/pqc-tls-siglab
. scripts/env.sh
export CATS_CTI_POLICY=/absolute/path/reviewed-policy.txt
bash /home/ubuntu/cats-adaptive-20261018-cL10ot/scripts/run_adaptive_server.sh \
  PORT MANIFEST_TSV PROVIDER_MODULE_PATH X25519 MAX_CONNECTIONS
```

`CATS_MODEL_TRACE=1` optionally records every eligible candidate's inputs, weights,
costs, score, and source checkpoint hash for audit. Logging is off by default.
The legacy log field `estimated_tls_ms` contains a selection score in model mode;
use the `adaptive-no-chain-cap2` arm and `MODEL_CANDIDATE score` to identify it.

## Verification on 2026-10-18

- C inference compared with 6,120 saved historical candidate/context scores plus
  600 random boundary/extrapolation vectors across L1/L3/L5: all 6,720 passed.
  Both macOS and AWS Linux were checked. Bad inputs/models were rejected; zero
  coefficients reproduce four unit weights.
- AWS OpenSSL 3.5.7: existing 19 CTI tests and three context/window tests passed.
- A distinct Seoul EC2 client connected to the Seoul server using five fresh
  functional-test certificate configurations. CTI allowed counts were
  5,4,3,2,1,0,5; the server was not restarted. All 18 successes matched the
  expected leaf fingerprint, and two forbidden selections were rejected.
- The live L1 model selected ML-DSA, MAYO, Falcon, UOV, FAEST, then rejected all,
  and returned to ML-DSA after restoring permissions. All 60 eligible-candidate
  scores/weights were independently recomputed from the checkpoint parameters;
  maximum score difference was 2.842170943040401e-14 ms. Signing EWMA updates
  and actual socket context remained active.
- L3 and L5 were numerically validated and deployed, but this cross-host
  five-candidate functional run used L1 only. It is not a performance-benefit
  evaluation, a security equivalence assertion, or validation of all chain types.
- The model retains its historical chain-only verification definition. It must
  not be described as the manuscript's `(n_cert+1)*T_verify` variant.
- Synthetic CTI and one-day self-signed test certificates were used. No real
  CTI feed, persistent test service, or security-group/network shaping change.

Evidence in the parent workspace:
`outputs/analysis/adaptive_deployment_20261018/` (export provenance, vectors,
build/tests) and `outputs/analysis/adaptive_cti_seoul_live_20261018/`
(plan, policies, server/client logs, independently verified result).
