# Latest Bandit replay code snapshot

This additive release preserves the October 8–9 cost/context experiments and
their saved models. It does not replace the October 3 five-cost release and
does not change any deployed service. The code is the current export snapshot;
historical source hashes are retained in the result metadata. Do not interpret
this as a byte-identical snapshot of every earlier training run.

Python 3.12+ and NumPy are required. From the repository root:

```bash
export PYTHONPATH="$PWD/repro/bandit_update_20261010/code"
python -m rl_weight_selector.sqisign_bandit_release \
  --input results/bandit_sqisign_20261003/inputs/prepared.json.gz \
  --output-dir outputs/replay-cost4-condition \
  --split condition --context loss5-probability-unclipped \
  --score-terms 4 --verification-cost chain-only

python -m rl_weight_selector.log_context_ablation \
  --input results/bandit_sqisign_20261003/inputs/prepared.json.gz \
  --output-dir outputs/replay-linear-condition \
  --split condition --transform linear

python -m rl_weight_selector.scaling_reference_ablation \
  --input results/bandit_sqisign_20261003/inputs/prepared.json.gz \
  --output-dir outputs/replay-train-max-condition \
  --split condition --reference train-max
```

Use a new output directory for each run. For region holdout use `--split region`.
The other comparison switches are `--score-terms 5`,
`--context loss5-unclipped`, `--verification-cost chain-plus-cv`,
`--transform log`, and `--reference fixed`. They describe separate experiments,
not interchangeable settings of one published result. Use prepared inputs, not
the all-50 summary CSV, to reproduce the fastest-35/50 replay protocol.

The export only removes absolute workspace paths and replaces hard-coded
workspace roots with module-relative roots; it does not intentionally change
numeric model parameters. Source and published hashes are in
[`MANIFEST.json`](../../results/bandit_update_20261010/MANIFEST.json).

Verify package integrity and the 150-candidate TLS view:

```bash
python repro/bandit_update_20261010/check_release.py
```
