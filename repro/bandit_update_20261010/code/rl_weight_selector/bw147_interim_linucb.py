#!/usr/bin/env python3
"""Interim partial-feedback LinUCB replay for the growing BW147 matrix.

Only composite algorithm contexts with 50 unique successful runs are admitted.
RTT and known bandwidth are the only context features.  Packet loss remains an
unobserved source of reward variation, and certificate-chain effects enter only
through each candidate's cost features.  For every temporal partition, the
slowest 30 percent of measurements are removed before a selected arm's batch
feedback is revealed to the learner.
"""

from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import json
import math
import random
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

import numpy as np

from contextual_signature_selector.replay_certificate_inventories import (
    FAMILY_CANDIDATES,
    inventory_products,
)
from contextual_signature_selector.selector import NetworkContext, SelectorConstants, score_row
from rl_weight_selector.bandit import action_grid
from rl_weight_selector.partial_feedback_linucb import LinUCBAgent, context_vector
from rl_weight_selector.screen_composite_vs_deterministic import Bounds, fit_bounds, normalize, raw_features


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INVENTORY = ROOT / "outputs/regional_exact/bw147_all_chains_plan/inventory.json"
DEFAULT_PROFILE = ROOT / "outputs/analysis/composite_chain_length_overhead/composite_chain_detail.csv"
DEFAULT_OLD_MODEL = ROOT / "outputs/analysis/rl_weight_selector_partial_feedback/model_after_fit.json"
DEFAULT_OUTPUT = ROOT / "outputs/analysis/rl_weight_selector_bw147_interim"
PARTITION_RUNS = {
    "train": range(1, 31),
    "validation": range(31, 41),
    "fit": range(1, 41),
    "test": range(41, 51),
}
REGION_NAMES = {
    "seoul": "Seoul",
    "tokyo": "Tokyo",
    "usa": "USA",
    "singapore": "Singapore",
    "frankfurt": "Frankfurt",
}


@dataclass(frozen=True)
class InterimEpisode:
    region: str
    certificate_mode: str
    loss_percent: float
    level: str
    classical_algorithm: str
    inventory: tuple[str, ...]
    rtt_ms: float
    bandwidth_mbps: float
    candidates: tuple[dict[str, object], ...]


def condition_name(experiment: str, bandwidth: str, loss: str) -> str:
    loss_value = loss.rstrip("%")
    if experiment == "matrix":
        return f"bw_{bandwidth}mbps_loss_{loss_value}pct"
    if experiment == "bw_only":
        return f"bw_{bandwidth}mbps"
    return f"bw_{bandwidth}_loss_{loss_value}"


def mode_name(value: str) -> str:
    value = value.lower()
    if not value.startswith("chain") or not value.endswith("ica"):
        raise ValueError(f"unsupported certificate mode: {value}")
    return value.removeprefix("chain").upper()


def upper_trimmed_samples(
    run_values: Iterable[tuple[int, float]], fraction: float = 0.3
) -> list[float]:
    values = [(int(run), float(value)) for run, value in run_values]
    if not values:
        raise ValueError("cannot trim an empty sample")
    keep = max(1, math.floor(len(values) * (1.0 - fraction)))
    retained_runs = {
        run for run, _ in sorted(values, key=lambda item: (item[1], item[0]))[:keep]
    }
    return [value for run, value in sorted(values) if run in retained_runs]


def load_profile(path: Path) -> dict[tuple[str, str, str], dict[str, str]]:
    lookup: dict[tuple[str, str, str], dict[str, str]] = {}
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            lookup[(row["region"].lower(), row["certificate_mode"].upper(), row["algorithm"])] = row
    if not lookup:
        raise ValueError(f"empty profile: {path}")
    return lookup


def complete_groups(
    inventory_path: Path,
    profile_path: Path,
) -> tuple[dict[tuple[str, str, float, float, str, str], dict[str, dict[str, object]]], dict[str, object]]:
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    profile = load_profile(profile_path)
    grouped: dict[tuple[str, str, float, float, str, str], dict[str, dict[str, object]]] = defaultdict(dict)
    digest = hashlib.sha256()
    admitted_algorithm_contexts = 0
    admitted_raw_samples = 0
    skipped_incomplete = 0
    skipped_partial_candidate_sets = 0
    duplicate_rows_ignored = 0
    source_files: list[str] = []

    for stage in inventory["stages"]:
        root = Path(stage["output_root"])
        if not root.exists():
            continue
        mode = mode_name(str(stage["certificate_mode"]))
        for raw_path in sorted(root.glob("*/composite*/*_raw.csv")):
            region_key = raw_path.relative_to(root).parts[0].lower()
            if region_key not in REGION_NAMES:
                continue
            region = REGION_NAMES[region_key]
            summary_paths = list(raw_path.parent.glob("*_summary.csv"))
            if len(summary_paths) != 1:
                continue
            summary_path = summary_paths[0]
            source_files.extend((str(raw_path), str(summary_path)))
            summary_lookup: dict[tuple[str, str, str], dict[str, str]] = {}
            with summary_path.open(newline="", encoding="utf-8") as handle:
                for row in csv.DictReader(handle):
                    condition = condition_name(row["experiment"], row["bw_mbps"], row["lossrate"])
                    summary_lookup[(row["experiment"], condition, row["algorithm"])] = row

            samples: dict[tuple[str, str, str], dict[int, float]] = defaultdict(dict)
            with raw_path.open(newline="", encoding="utf-8") as handle:
                for row in csv.DictReader(handle):
                    if row.get("status") != "OK":
                        continue
                    sample_key = (row["experiment"], row["condition"], row["algorithm"])
                    run = int(row["run"])
                    if run in samples[sample_key]:
                        duplicate_rows_ignored += 1
                        continue
                    samples[sample_key][run] = float(row["elapsed_ms"])

            for sample_key, run_values in sorted(samples.items()):
                experiment, condition, algorithm = sample_key
                summary = summary_lookup.get(sample_key)
                if summary is None or set(run_values) != set(range(1, 51)):
                    skipped_incomplete += 1
                    continue
                profile_row = profile.get((region.lower(), mode, algorithm))
                if profile_row is None or profile_row["level"] not in FAMILY_CANDIDATES:
                    continue
                partition_samples = {
                    part: upper_trimmed_samples((run, run_values[run]) for run in runs)
                    for part, runs in PARTITION_RUNS.items()
                }
                means = {
                    part: statistics.fmean(values)
                    for part, values in partition_samples.items()
                }
                loss_percent = float(summary["lossrate"].rstrip("%"))
                bandwidth_mbps = float(summary["bw_mbps"])
                context_key = (
                    region,
                    mode,
                    loss_percent,
                    bandwidth_mbps,
                    profile_row["level"],
                    profile_row["classical_algorithm"],
                )
                grouped[context_key][profile_row["pqc_algorithm"]] = {
                    "algorithm": algorithm,
                    "profile": profile_row,
                    "means": means,
                    "partition_samples": partition_samples,
                }
                admitted_algorithm_contexts += 1
                admitted_raw_samples += 50
                for run, value in sorted(run_values.items()):
                    digest.update(
                        f"{region}|{mode}|{loss_percent}|{bandwidth_mbps}|{algorithm}|{run}|{value:.12f}\n".encode()
                    )

    expected_candidates: dict[tuple[str, str, str, str], set[str]] = defaultdict(set)
    for (region, mode, _), row in profile.items():
        if row["level"] in FAMILY_CANDIDATES:
            expected_candidates[(region, mode, row["level"], row["classical_algorithm"])].add(
                row["pqc_algorithm"]
            )
    for context_key in list(grouped):
        region, mode, _, _, level, classical = context_key
        expected = expected_candidates[(region.lower(), mode, level, classical)]
        if set(grouped[context_key]) != expected:
            skipped_partial_candidate_sets += 1
            del grouped[context_key]

    admitted_algorithm_contexts = sum(len(candidates) for candidates in grouped.values())
    admitted_raw_samples = admitted_algorithm_contexts * 50
    digest = hashlib.sha256()
    for context_key, candidates in sorted(grouped.items()):
        for pqc_algorithm, item in sorted(candidates.items()):
            digest.update(f"{context_key}|{pqc_algorithm}|".encode())
            for part, values in sorted(item["partition_samples"].items()):  # type: ignore[union-attr]
                digest.update(f"{part}|{','.join(f'{float(value):.12f}' for value in values)}\n".encode())

    snapshot = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "inventory_path": str(inventory_path),
        "profile_path": str(profile_path),
        "source_files": sorted(set(source_files)),
        "admitted_algorithm_contexts": admitted_algorithm_contexts,
        "admitted_raw_samples": admitted_raw_samples,
        "skipped_incomplete_algorithm_contexts": skipped_incomplete,
        "skipped_partial_candidate_sets": skipped_partial_candidate_sets,
        "duplicate_raw_rows_ignored": duplicate_rows_ignored,
        "dataset_snapshot_sha256": digest.hexdigest(),
    }
    return grouped, snapshot


def build_episodes(
    grouped: dict[tuple[str, str, float, float, str, str], dict[str, dict[str, object]]],
    window_size_bytes: int,
) -> list[InterimEpisode]:
    constants = SelectorConstants()
    episodes: list[InterimEpisode] = []
    for (region, mode, loss, bandwidth, level, classical), available in sorted(grouped.items()):
        for inventory in inventory_products(level):
            if not all(pqc in available for pqc in inventory):
                continue
            chosen = [available[pqc] for pqc in inventory]
            rtt_ms = statistics.median(float(item["profile"]["rtt_ms"]) for item in chosen)  # type: ignore[index]
            network = NetworkContext(rtt_ms, bandwidth, window_size_bytes, rtt_ms)
            candidates: list[dict[str, object]] = []
            for item in chosen:
                profile_row = item["profile"]
                scored = score_row(profile_row, network, constants)  # type: ignore[arg-type]
                candidates.append(
                    {
                        "algorithm": item["algorithm"],
                        "pqc_algorithm": profile_row["pqc_algorithm"],  # type: ignore[index]
                        "features": raw_features(scored, rtt_ms),
                        **item["means"],  # type: ignore[arg-type]
                        **{
                            f"{part}_samples": values
                            for part, values in item["partition_samples"].items()  # type: ignore[union-attr]
                        },
                    }
                )
            episodes.append(
                InterimEpisode(
                    region=region,
                    certificate_mode=mode,
                    loss_percent=loss,
                    level=level,
                    classical_algorithm=classical,
                    inventory=inventory,
                    rtt_ms=rtt_ms,
                    bandwidth_mbps=bandwidth,
                    candidates=tuple(candidates),
                )
            )
    if not episodes:
        raise ValueError("no complete inventory episodes could be built")
    return episodes


def select_candidate(episode: InterimEpisode, weights: tuple[float, float, float], bounds: Bounds) -> dict[str, object]:
    ranked = []
    for candidate in episode.candidates:
        costs = normalize(candidate["features"], bounds)  # type: ignore[arg-type]
        score = sum(weight * cost for weight, cost in zip(weights, costs))
        ranked.append((score, sum(costs), str(candidate["algorithm"]), candidate))
    return min(ranked)[3]


def ordered(episodes: list[InterimEpisode], seed: int) -> list[InterimEpisode]:
    output = list(episodes)
    random.Random(seed).shuffle(output)
    return output


def train_agent(
    agent: LinUCBAgent,
    episodes: list[InterimEpisode],
    bounds: Bounds,
    outcome_field: str,
    seed: int,
) -> list[dict[str, object]]:
    curve: list[dict[str, object]] = []
    selected_values: list[float] = []
    sample_count = len(episodes[0].candidates[0][f"{outcome_field}_samples"])  # type: ignore[arg-type]
    updates = 0
    sample_order = list(range(sample_count))
    random.Random(seed * 17).shuffle(sample_order)
    for sample_index in sample_order:
        for episode in ordered(episodes, seed + sample_index * 1009):
            x = context_vector(episode)  # type: ignore[arg-type]
            action_index, expected_reward, uncertainty = agent.select(x)
            weights = agent.actions[action_index]
            selected = select_candidate(episode, weights, bounds)
            selected_ms = float(selected[f"{outcome_field}_samples"][sample_index])  # type: ignore[index]
            agent.update(action_index, x, -selected_ms / 1000.0)
            selected_values.append(selected_ms)
            updates += 1
            if updates % 10000 == 0:
                curve.append(
                    {
                        "updates": updates,
                        "mean_selected_tls_ms": statistics.fmean(selected_values),
                        "last_action_index": action_index,
                        "last_expected_reward": expected_reward,
                        "last_uncertainty": uncertainty,
                    }
                )
    curve.append(
        {
            "updates": updates,
            "mean_selected_tls_ms": statistics.fmean(selected_values),
            "last_action_index": action_index,
            "last_expected_reward": expected_reward,
            "last_uncertainty": uncertainty,
        }
    )
    return curve


def policy_action(agent: LinUCBAgent, episode: InterimEpisode) -> int:
    return agent.select(context_vector(episode))[0]  # type: ignore[arg-type]


def old_policy_action(model: dict[str, object], episode: InterimEpisode) -> int:
    x = context_vector(episode)  # type: ignore[arg-type]
    inverse = np.asarray(model["a_inverse"], dtype=float)
    b = np.asarray(model["b"], dtype=float)
    theta = np.einsum("aij,aj->ai", inverse, b)
    means = theta @ x
    projected = np.einsum("aij,j->ai", inverse, x)
    uncertainty = np.sqrt(np.maximum(0.0, np.einsum("ai,i->a", projected, x)))
    scores = means + float(model["alpha"]) * uncertainty
    return int(np.argmax(scores))


def evaluate(
    episodes: list[InterimEpisode],
    bounds: Bounds,
    actions: list[tuple[float, float, float]],
    policy,
    policy_name: str,
    outcome_field: str = "test",
    keep_rows: bool = False,
) -> tuple[dict[str, object], list[dict[str, object]]]:
    selected_values: list[float] = []
    oracle_values: list[float] = []
    action_usage: Counter[int] = Counter()
    rows: list[dict[str, object]] = []
    for episode in episodes:
        action_index = int(policy(episode))
        weights = actions[action_index]
        selected = select_candidate(episode, weights, bounds)
        oracle = min(episode.candidates, key=lambda item: (float(item[outcome_field]), str(item["algorithm"])))
        selected_ms = float(selected[outcome_field])
        oracle_ms = float(oracle[outcome_field])
        selected_values.append(selected_ms)
        oracle_values.append(oracle_ms)
        action_usage[action_index] += 1
        if keep_rows:
            rows.append(
                {
                    "policy": policy_name,
                    "region": episode.region,
                    "certificate_mode": episode.certificate_mode,
                    "loss_percent_hidden_from_state": episode.loss_percent,
                    "security_level": episode.level,
                    "classical_algorithm": episode.classical_algorithm,
                    "rtt_ms": episode.rtt_ms,
                    "bandwidth_mbps": episode.bandwidth_mbps,
                    "inventory": ";".join(episode.inventory),
                    "action_index": action_index,
                    "weight_sign": weights[0],
                    "weight_size_over_bw": weights[1],
                    "weight_critical_path": weights[2],
                    "selected_algorithm": selected["algorithm"],
                    "selected_tls_ms": selected_ms,
                    "oracle_algorithm_evaluator_only": oracle["algorithm"],
                    "oracle_tls_ms_evaluator_only": oracle_ms,
                    "regret_ms_evaluator_only": selected_ms - oracle_ms,
                }
            )
    regrets = [selected - oracle for selected, oracle in zip(selected_values, oracle_values)]
    metrics = {
        "policy": policy_name,
        "decision_count": len(episodes),
        "mean_selected_tls_ms": statistics.fmean(selected_values),
        "mean_oracle_tls_ms_evaluator_only": statistics.fmean(oracle_values),
        "mean_regret_ms_evaluator_only": statistics.fmean(regrets),
        "median_regret_ms_evaluator_only": statistics.median(regrets),
        "oracle_match_rate_evaluator_only": sum(abs(value) <= 1e-12 for value in regrets) / len(regrets),
        "distinct_weight_actions": len(action_usage),
        "most_used_actions": [
            {"action_index": index, "weights": list(actions[index]), "count": count}
            for index, count in action_usage.most_common(10)
        ],
    }
    return metrics, rows


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


G1_EPSILONS = (0.01, 0.10, 0.20, 0.30, 0.40, 0.50)


def g1_epsilon_sweep(
    decisions: list[dict[str, object]],
    epsilons: tuple[float, ...] = G1_EPSILONS,
) -> tuple[list[dict[str, object]], dict[str, object]]:
    """Evaluate G1 membership using regret <= epsilon * RTT."""
    regions = sorted({str(row["region"]) for row in decisions})
    rows: list[dict[str, object]] = []
    summary: dict[str, object] = {
        "criterion": "selected_tls_ms - oracle_tls_ms <= epsilon * rtt_ms",
        "used_for_training": False,
        "epsilons": {},
    }
    for epsilon in epsilons:
        region_rates: list[float] = []
        epsilon_summary: dict[str, object] = {"by_region": {}}
        total_ok = 0
        total = 0
        for region in regions:
            region_rows = [row for row in decisions if str(row["region"]) == region]
            ok = sum(
                float(row["regret_ms_evaluator_only"])
                <= epsilon * float(row["rtt_ms"]) + 1e-12
                for row in region_rows
            )
            count = len(region_rows)
            rate = ok / count if count else 0.0
            region_rates.append(rate)
            total_ok += ok
            total += count
            rows.append(
                {
                    "epsilon": epsilon,
                    "region": region,
                    "ok": ok,
                    "total": count,
                    "pct": 100.0 * rate,
                }
            )
            epsilon_summary["by_region"][region] = rate
        macro_rate = statistics.fmean(region_rates)
        micro_rate = total_ok / total if total else 0.0
        rows.append(
            {
                "epsilon": epsilon,
                "region": "Average",
                "ok": "",
                "total": "",
                "pct": 100.0 * macro_rate,
            }
        )
        epsilon_summary["macro_average"] = macro_rate
        epsilon_summary["micro_average"] = micro_rate
        summary["epsilons"][str(epsilon)] = epsilon_summary
    return rows, summary


def write_g1_markdown(path: Path, rows: list[dict[str, object]]) -> None:
    by_epsilon: dict[float, dict[str, float]] = defaultdict(dict)
    for row in rows:
        by_epsilon[float(row["epsilon"])][str(row["region"])] = float(row["pct"])
    region_order = ["Seoul", "Tokyo", "Frankfurt", "Singapore", "USA", "Average"]
    lines = [
        "| ε | Seoul | Tokyo | Frankfurt | Singapore | USA | Average |",
        "|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for epsilon in sorted(by_epsilon):
        values = by_epsilon[epsilon]
        lines.append(
            "| " + f"{epsilon:.2f}" + " | "
            + " | ".join(f"{values[region]:.2f}%" for region in region_order)
            + " |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run(args: argparse.Namespace) -> dict[str, object]:
    grouped, snapshot = complete_groups(args.inventory, args.profile)
    episodes = build_episodes(grouped, args.window_size_bytes)
    bounds = fit_bounds(episodes)  # type: ignore[arg-type]
    actions = action_grid(args.action_step)
    dimension = len(context_vector(episodes[0]))  # type: ignore[arg-type]
    validation_rows: list[dict[str, object]] = []

    for alpha in args.alphas:
        candidate = LinUCBAgent(actions, dimension, alpha)
        train_agent(candidate, episodes, bounds, "train", args.seed)
        validation_metrics, _ = evaluate(
            episodes,
            bounds,
            actions,
            lambda episode, model=candidate: policy_action(model, episode),
            f"validation_alpha_{alpha}",
            outcome_field="validation",
        )
        validation_rows.append({"alpha": alpha, **validation_metrics})
    selected_alpha = min(validation_rows, key=lambda row: float(row["mean_selected_tls_ms"]))["alpha"]

    fitted = LinUCBAgent(actions, dimension, float(selected_alpha))
    learning_curve = train_agent(fitted, episodes, bounds, "fit", args.seed)
    frozen = copy.deepcopy(fitted)
    new_metrics, decisions = evaluate(
        episodes,
        bounds,
        actions,
        lambda episode: policy_action(frozen, episode),
        "updated_bw147_linucb",
        keep_rows=True,
    )
    new_g1_rows, new_g1_metrics = g1_epsilon_sweep(decisions)

    equal_index = min(
        range(len(actions)),
        key=lambda index: sum((value - 1.0 / 3.0) ** 2 for value in actions[index]),
    )
    equal_metrics, equal_decisions = evaluate(
        episodes,
        bounds,
        actions,
        lambda _: equal_index,
        "equal_weight_reference",
        keep_rows=True,
    )
    equal_g1_rows, equal_g1_metrics = g1_epsilon_sweep(equal_decisions)

    old_metrics = None
    old_g1_rows: list[dict[str, object]] = []
    old_g1_metrics = None
    if args.old_model.exists():
        old_model = json.loads(args.old_model.read_text(encoding="utf-8"))
        old_actions = [tuple(float(value) for value in action) for action in old_model["actions"]]
        if old_actions == actions:
            old_metrics, old_decisions = evaluate(
                episodes,
                bounds,
                actions,
                lambda episode: old_policy_action(old_model, episode),
                "previous_1000mbps_linucb",
                keep_rows=True,
            )
            old_g1_rows, old_g1_metrics = g1_epsilon_sweep(old_decisions)

    summary: dict[str, object] = {
        "model": "partial-feedback disjoint LinUCB over three-dimensional weight arms",
        "interim": True,
        "deterministic_baseline_used": False,
        "context_features": ["continuous_log_rtt", "continuous_log_bandwidth", "interaction"],
        "loss_used_as_context": False,
        "certificate_mode_used_as_context": False,
        "candidate_costs": ["sign", "size_over_bandwidth", "critical_path_including_ICA_and_I_tail"],
        "feedback_visible_to_agent": ["selected_algorithm", "one_retained_selected_tls_sample_per_update"],
        "counterfactual_candidate_tls_visible_to_agent": False,
        "candidate_profile": "Composite98 one-certificate-per-family inventories",
        "run_split": {"train": "1-30", "validation": "31-40", "fit": "1-40", "test": "41-50"},
        "trim_upper_fraction_within_each_partition": 0.3,
        "partition_kept_samples_per_algorithm_context": {"train": 21, "validation": 7, "fit": 28, "test": 7},
        "episode_count": len(episodes),
        "network_context_count": len(
            {
                (episode.region, episode.certificate_mode, episode.loss_percent, episode.bandwidth_mbps)
                for episode in episodes
            }
        ),
        "regions": sorted({episode.region for episode in episodes}),
        "certificate_modes": sorted({episode.certificate_mode for episode in episodes}),
        "bandwidths_mbps": sorted({episode.bandwidth_mbps for episode in episodes}),
        "loss_values_present_but_hidden_from_state": sorted({episode.loss_percent for episode in episodes}),
        "action_step": args.action_step,
        "action_count": len(actions),
        "selected_alpha": selected_alpha,
        "updated_policy_test": new_metrics,
        "updated_policy_g1_evaluator_only": new_g1_metrics,
        "previous_policy_same_test": old_metrics,
        "previous_policy_g1_evaluator_only": old_g1_metrics,
        "equal_weight_same_test": equal_metrics,
        "equal_weight_g1_evaluator_only": equal_g1_metrics,
        "snapshot": snapshot,
        "limitations": [
            "This is an interim snapshot; incomplete 50-run algorithm contexts are excluded.",
            "The temporal split tests new repetitions of measured RTT/BW contexts, not an unseen RTT/BW value.",
            "Controlled measurements are reused across hypothetical server certificate inventories.",
            "Loss affects observed TLS rewards but is intentionally hidden from the model state.",
        ],
    }
    if old_metrics is not None:
        old_mean = float(old_metrics["mean_selected_tls_ms"])
        new_mean = float(new_metrics["mean_selected_tls_ms"])
        summary["updated_vs_previous_same_test"] = {
            "improvement_ms": old_mean - new_mean,
            "improvement_percent": 100.0 * (old_mean - new_mean) / old_mean,
            "regret_reduction_ms": float(old_metrics["mean_regret_ms_evaluator_only"])
            - float(new_metrics["mean_regret_ms_evaluator_only"]),
        }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(args.output_dir / "validation_search.csv", validation_rows)
    write_csv(args.output_dir / "learning_curve.csv", learning_curve)
    write_csv(args.output_dir / "test_decisions.csv", decisions)
    write_csv(args.output_dir / "updated_policy_g1_epsilon_sweep_by_region.csv", new_g1_rows)
    write_g1_markdown(args.output_dir / "updated_policy_g1_epsilon_sweep_table.md", new_g1_rows)
    write_csv(args.output_dir / "equal_weight_g1_epsilon_sweep_by_region.csv", equal_g1_rows)
    if old_g1_rows:
        write_csv(args.output_dir / "previous_policy_g1_epsilon_sweep_by_region.csv", old_g1_rows)
    (args.output_dir / "model_after_fit.json").write_text(
        json.dumps(fitted.to_json(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (args.output_dir / "snapshot.json").write_text(
        json.dumps(snapshot, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (args.output_dir / "metrics.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY)
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--old-model", type=Path, default=DEFAULT_OLD_MODEL)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--window-size-bytes", type=int, default=16384)
    parser.add_argument("--action-step", type=float, default=0.1)
    parser.add_argument("--alphas", type=lambda value: [float(item) for item in value.split(",")], default=[0.01, 0.05, 0.1, 0.25])
    parser.add_argument("--seed", type=int, default=42)
    return parser.parse_args()


def main() -> int:
    result = run(parse_args())
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
