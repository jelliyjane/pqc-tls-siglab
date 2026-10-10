CertificateVerify-inclusive verification-cost replay

Change: c_verify = (n_cert + 1) * T_verify, rather than n_cert * T_verify.
n_cert counts the transmitted leaf and intermediate certificates; root excluded.
The additional operation is TLS CertificateVerify signature verification.
The same measured per-signature EVP time remains a proxy for chain signatures;
this is not a measurement of complete certificate-path validation.

Frozen input: outputs/analysis/bandit_sqisign_20261003/inputs/prepared.json.gz
Baseline: outputs/analysis/bandit_cost4_loss_probability_20261008
The frozen input, original results, and live/runtime selector are not modified.
Profile CSV hashes are checked against the original input provenance.

Unchanged: four costs (no tail), 286 weight actions, 5-dimensional loss-probability
context, seeds 42-46, validation-selected alpha in {0.01,0.05,0.1,0.25},
training-only cost normalization, fastest 35 of 50 measured TLS runs per condition.
Offline transmission-window approximation remains 16,384 bytes, as in the baseline.
No new network measurements or online deployment are performed.

Evaluations: five-fold grouped condition holdout (80% fitting, 20% testing), and
leave-one-region-out. Each includes 75 saved models and 7,200 held-out decisions.
These reused holdouts are development evaluations, not untouched final tests.
The epsilon threshold is excess latency <= epsilon * RTT, not epsilon * oracle TLS.

Reproduce from workspace root, with a NumPy-enabled Python (run used NumPy 2.3.5):
python -m rl_weight_selector.sqisign_bandit_release --input outputs/analysis/bandit_sqisign_20261003/inputs/prepared.json.gz --output-dir NEW_ROOT/condition --split condition --context loss5-probability-unclipped --score-terms 4 --verification-cost chain-plus-cv
python -m rl_weight_selector.sqisign_bandit_release --input outputs/analysis/bandit_sqisign_20261003/inputs/prepared.json.gz --output-dir NEW_ROOT/region --split region --context loss5-probability-unclipped --score-terms 4 --verification-cost chain-plus-cv
python -m rl_weight_selector.report_loss_context --root NEW_ROOT --baseline outputs/analysis/bandit_cost4_loss_probability_20261008 --input outputs/analysis/bandit_sqisign_20261003/inputs/prepared.json.gz

All output directories must be new. Comparison report generation independently
reconstructs costs, training bounds, checkpoint choices, and measured outcomes.
