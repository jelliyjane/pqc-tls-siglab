#!/usr/bin/env python3
"""80:20 whole-region holdout for the selected-scope unified-EVP LinUCB model.

Each fold fits on four complete regions and evaluates on one region that is never
shown during fitting. All 50 raw runs stay with their region/context; raw rows are
never randomly split across train and test.
"""
from __future__ import annotations

import argparse
import csv
import copy
import json
import math
import random
import statistics
import hashlib
from dataclasses import asdict
from collections import defaultdict
from pathlib import Path

import numpy as np

from rl_weight_selector.partial_feedback_linucb import LinUCBAgent
from rl_weight_selector.retrain_ica12 import (
    ACTIONS,
    ALPHAS,
    BASELINES,
    SEEDS,
    ROOT,
    Bounds,
    load_evp_averages,
    normalize,
    prepare,
)


REGIONS = ("seoul", "tokyo", "singapore", "usa", "frankfurt")


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    if not rows:
        raise ValueError(f"No rows for {path}")
    with path.open("x", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def retained_all_runs(record: dict[str, object]) -> list[float]:
    """Return the fastest 70% of runs 1..50, preserving retained run order."""
    values: dict[int, float] = {}
    partitions = record["partitions"]
    for partition in ("fit", "test"):
        for sample in partitions[partition]:
            run = int(sample["run"])
            value = float(sample["elapsed_ms"])
            if run in values and values[run] != value:
                raise ValueError(f"Conflicting run {run} for {record['algorithm']}")
            values[run] = value
    if set(values) != set(range(1, 51)):
        raise ValueError(f"Expected runs 1..50 for {record['algorithm']}")
    keep = math.floor(50 * 0.7)
    retained = set(sorted(values, key=lambda run: (values[run], run))[:keep])
    return [values[run] for run in range(1, 51) if run in retained]


def all_run_outcomes(snapshot: dict[str, object], bundles: list[dict[str, object]]) -> dict[str, np.ndarray]:
    records: dict[tuple[object, ...], dict[str, dict[str, object]]] = defaultdict(dict)
    for record in snapshot["conditions"]:
        if "hawk" in str(record["algorithm"]):
            continue
        level = "L1" if record["pqc_algorithm"] == "mldsa44" else record["security_level"]
        key = (
            level,
            record["classical_algorithm"],
            record["certificate_mode"],
            record["loss_percent"],
            record["bandwidth_mbps"],
            record["region"],
        )
        records[key][str(record["algorithm"])] = record

    outcomes: dict[str, np.ndarray] = {}
    for bundle in bundles:
        by_algorithm = records[tuple(bundle["key"])]
        candidate_algorithms = [str(candidate["algorithm"]) for candidate in bundle["episode"].candidates]
        matrix = np.array([retained_all_runs(by_algorithm[name]) for name in candidate_algorithms])
        if matrix.shape[1] != 35:
            raise AssertionError(matrix.shape)
        outcomes[str(bundle["id"])] = matrix
    return outcomes


def fit_bounds(bundles: list[dict[str, object]]) -> Bounds:
    features = np.array(
        [candidate["features"] for bundle in bundles for candidate in bundle["episode"].candidates]
    )
    return Bounds(tuple(features.min(axis=0)), tuple(features.max(axis=0)))


def action_choices(bundles: list[dict[str, object]], bounds: Bounds) -> dict[str, np.ndarray]:
    result: dict[str, np.ndarray] = {}
    for bundle in bundles:
        candidates = bundle["episode"].candidates
        costs = np.array([normalize(candidate["features"], bounds) for candidate in candidates])
        result[str(bundle["id"])] = np.array(
            [
                min(
                    range(len(candidates)),
                    key=lambda index: (
                        float(np.dot(weight, costs[index])),
                        float(costs[index].sum()),
                        candidates[index]["algorithm"],
                    ),
                )
                for weight in ACTIONS
            ]
        )
    return result


def train(
    bundles: list[dict[str, object]],
    outcomes: dict[str, np.ndarray],
    choices: dict[str, np.ndarray],
    alpha: float,
    seed: int,
) -> LinUCBAgent:
    agent = LinUCBAgent(ACTIONS, 4, alpha)
    sample_order = list(range(35))
    random.Random(seed * 17).shuffle(sample_order)
    for sample_index in sample_order:
        episode_order = list(bundles)
        random.Random(seed + sample_index * 1009).shuffle(episode_order)
        for bundle in episode_order:
            action = agent.select(bundle["x"])[0]
            candidate = int(choices[str(bundle["id"])][action])
            reward = -float(outcomes[str(bundle["id"])][candidate, sample_index]) / 1000.0
            agent.update(action, bundle["x"], reward)
    return agent


def policy_mean(
    agent: LinUCBAgent,
    bundles: list[dict[str, object]],
    outcomes: dict[str, np.ndarray],
    choices: dict[str, np.ndarray],
) -> float:
    selected = []
    for bundle in bundles:
        action = agent.select(bundle["x"])[0]
        candidate = int(choices[str(bundle["id"])][action])
        selected.append(float(outcomes[str(bundle["id"])][candidate].mean()))
    return statistics.fmean(selected)


def evaluate(
    agent: LinUCBAgent,
    bundles: list[dict[str, object]],
    outcomes: dict[str, np.ndarray],
    choices: dict[str, np.ndarray],
    seed: int,
    fold: int,
) -> list[dict[str, object]]:
    rows = []
    for bundle in bundles:
        episode = bundle["episode"]
        action = agent.select(bundle["x"])[0]
        candidate = int(choices[str(bundle["id"])][action])
        means = outcomes[str(bundle["id"])].mean(axis=1)
        names = [item["pqc_algorithm"] for item in episode.candidates]
        baseline = names.index(BASELINES[episode.level])
        oracle = float(means.min())
        selected = float(means[candidate])
        rows.append(
            {
                "fold": fold,
                "held_out_region": episode.region,
                "episode_id": bundle["id"],
                "seed": seed,
                "level": episode.level,
                "suite": episode.classical_algorithm,
                "certificate_mode": episode.certificate_mode,
                "loss_percent": episode.loss_percent,
                "bandwidth_mbps": episode.bandwidth_mbps,
                "region": episode.region,
                "rtt_ms": episode.rtt_ms,
                "rtt_mismatch": bundle["rtt_mismatch"],
                "candidate_count": len(episode.candidates),
                "action": action,
                "weight_sign": ACTIONS[action][0],
                "weight_transmission": ACTIONS[action][1],
                "weight_penalty": ACTIONS[action][2],
                "rl_algorithm": episode.candidates[candidate]["algorithm"],
                "rl_tls_ms": selected,
                "mldsa_algorithm": episode.candidates[baseline]["algorithm"],
                "mldsa_tls_ms": float(means[baseline]),
                "oracle_tls_ms_evaluator_only": oracle,
                "regret_ms_evaluator_only": selected - oracle,
                "reduction_vs_mldsa_pct": 100.0 * (float(means[baseline]) - selected) / float(means[baseline]),
            }
        )
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--server-sign-profile-dir", type=Path, required=True)
    parser.add_argument("--client-verify-profile-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=False)
    (args.output_dir / "models").mkdir()

    snapshot = json.loads(args.snapshot.read_text(encoding="utf-8"))
    sign_costs, sign_meta = load_evp_averages(args.server_sign_profile_dir, "server_sign")
    verify_costs, verify_meta = load_evp_averages(args.client_verify_profile_dir, "seoul_client_verify")
    pure = ROOT / "outputs/analysis/contextual_signature_selector/itail_full_matrix/itail_all_rows_seoul.csv"
    composite = ROOT / "outputs/analysis/composite_chain_length_overhead/composite_chain_detail.csv"
    bundles, _, provenance, exclusions = prepare(snapshot, pure, composite, sign_costs, verify_costs)
    outcomes = all_run_outcomes(snapshot, bundles)
    snapshot_hash = hashlib.sha256(args.snapshot.read_bytes()).hexdigest()
    (args.output_dir / "cost_provenance.json").write_text(json.dumps(provenance, ensure_ascii=False))
    contexts = [{"id": b["id"], "key": b["key"], "x": b["x"].tolist(),
                 "rtt_values": b["rtt_values"], "rtt_mismatch": b["rtt_mismatch"],
                 "candidates": list(b["episode"].candidates)} for b in bundles]
    (args.output_dir / "decision_contexts.json").write_text(json.dumps(contexts, ensure_ascii=False))
    print(f"Prepared {len(bundles)} contexts from {len(snapshot['conditions'])} conditions", flush=True)

    validation_rows: list[dict[str, object]] = []
    test_rows: list[dict[str, object]] = []
    fold_rows: list[dict[str, object]] = []

    for fold, test_region in enumerate(REGIONS):
        validation_region = REGIONS[(fold + 1) % len(REGIONS)]
        for level in BASELINES:
            level_bundles = [bundle for bundle in bundles if bundle["episode"].level == level]
            training = [
                bundle
                for bundle in level_bundles
                if bundle["episode"].region not in {test_region, validation_region}
            ]
            validation = [bundle for bundle in level_bundles if bundle["episode"].region == validation_region]
            fitting = [bundle for bundle in level_bundles if bundle["episode"].region != test_region]
            testing = [bundle for bundle in level_bundles if bundle["episode"].region == test_region]
            assert {b["id"] for b in fitting}.isdisjoint(b["id"] for b in testing)
            print(f"Fold {fold+1}/5 {test_region} {level}: tuning", flush=True)

            tuning_bounds = fit_bounds(training)
            tuning_choices = action_choices(training + validation, tuning_bounds)
            for alpha in ALPHAS:
                for seed in SEEDS:
                    agent = train(training, {b["id"]: outcomes[b["id"]] for b in training}, tuning_choices, alpha, seed)
                    validation_rows.append(
                        {
                            "fold": fold,
                            "level": level,
                            "test_region": test_region,
                            "validation_region": validation_region,
                            "alpha": alpha,
                            "seed": seed,
                            "validation_tls_ms": policy_mean(
                                agent, validation, outcomes, tuning_choices
                            ),
                        }
                    )
            best_alpha = min(
                ALPHAS,
                key=lambda alpha: statistics.fmean(
                    float(row["validation_tls_ms"])
                    for row in validation_rows
                    if row["fold"] == fold and row["level"] == level and row["alpha"] == alpha
                ),
            )

            fit_bounds_value = fit_bounds(fitting)
            fit_choices = action_choices(fitting + testing, fit_bounds_value)
            for seed in SEEDS:
                agent = train(fitting, {b["id"]: outcomes[b["id"]] for b in fitting}, fit_choices, best_alpha, seed)
                test_rows.extend(evaluate(agent, testing, outcomes, fit_choices, seed, fold))
                model_path = args.output_dir / "models" / f"fold{fold}_{test_region}_{level}_seed{seed}.json"
                model_path.write_text(
                    json.dumps(
                        {
                            **agent.to_json(),
                            "fold": fold,
                            "held_out_region": test_region,
                            "level": level,
                            "seed": seed,
                            "alpha": best_alpha,
                            "feature_bounds": asdict(fit_bounds_value),
                            "snapshot_sha256": snapshot_hash,
                            "frozen_evaluation_policy": "UCB_argmax_no_updates_matches_previous_protocol",
                            "split": "four complete fit regions / one complete unseen test region",
                        },
                        ensure_ascii=False,
                        indent=2,
                    )
                    + "\n",
                    encoding="utf-8",
                )
            fold_rows.append(
                {
                    "fold": fold,
                    "level": level,
                    "fit_regions": ";".join(region for region in REGIONS if region != test_region),
                    "test_region": test_region,
                    "validation_region_during_tuning": validation_region,
                    "selected_alpha": best_alpha,
                    "fit_contexts": len(fitting),
                    "test_contexts": len(testing),
                }
            )
            print(f"Fold {fold+1}/5 {test_region} {level}: complete, alpha={best_alpha}", flush=True)

    write_csv(args.output_dir / "validation_search.csv", validation_rows)
    write_csv(args.output_dir / "fold_summary.csv", fold_rows)
    write_csv(args.output_dir / "test_decisions.csv", test_rows)

    mean_rl = statistics.fmean(float(row["rl_tls_ms"]) for row in test_rows)
    mean_oracle = statistics.fmean(float(row["oracle_tls_ms_evaluator_only"]) for row in test_rows)
    mean_mldsa = statistics.fmean(float(row["mldsa_tls_ms"]) for row in test_rows)
    metrics = {
        "model": "LinUCB with five-fold whole-region holdout",
        "split": "per fold: four complete regions fit (80%), one complete unseen region test (20%)",
        "run_split": {
            "train": "3 whole regions × retained 35/50 runs",
            "validation": "1 whole region × retained 35/50 runs",
            "fit": "4 whole regions (80%) × retained 35/50 runs",
            "test": "1 unseen whole region (20%) × retained 35/50 runs",
        },
        "upper_trim_fraction_per_context": 0.3,
        "included_icas": snapshot["included_icas"],
        "included_bandwidths_mbps": snapshot.get("included_bandwidths_mbps", [1, 5, 50]),
        "included_ica_loss_pairs": snapshot["included_ica_loss_pairs"],
        "source_algorithm_conditions": len(snapshot["conditions"]),
        "source_raw_samples": len(snapshot["conditions"]) * 50,
        "excluded_HAWK_conditions": len(exclusions),
        "eligible_algorithms": 141,
        "decision_contexts": len(bundles),
        "test_decisions": len(test_rows),
        "seeds": list(SEEDS),
        "mean_rl_tls_ms": mean_rl,
        "mean_oracle_tls_ms": mean_oracle,
        "mean_regret_ms": mean_rl - mean_oracle,
        "mean_mldsa_tls_ms": mean_mldsa,
        "reduction_vs_mldsa_pct": 100.0 * (mean_mldsa - mean_rl) / mean_mldsa,
        "agent_feedback": "only the selected candidate TLS value",
        "oracle_usage": "evaluation only",
        "evp_profile_metadata": [sign_meta, verify_meta],
        "snapshot_sha256": snapshot_hash,
        "rtt_mismatch_contexts": sum(b["rtt_mismatch"] for b in bundles),
        "source_hashes": {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in (
            Path(__file__), pure, composite,
            ROOT / "rl_weight_selector/retrain_ica12.py",
            ROOT / "rl_weight_selector/partial_feedback_linucb.py",
            ROOT / "rl_weight_selector/screen_composite_vs_deterministic.py",
            ROOT / "contextual_signature_selector/selector.py",
        )},
        "important_limitations": [
            "A held-out region changes the full server path, not RTT alone",
            "All included BW values are observed in fitting; this tests unseen region, not unseen BW values",
            "The offline policy input is RTT and BW; loss is not an independent policy feature",
            "Five seeds are model initializations, not independent network measurements",
        ],
    }
    (args.output_dir / "metrics.json").write_text(
        json.dumps(metrics, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(metrics, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
