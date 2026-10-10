#!/usr/bin/env python3
"""Screen a learned weight policy against the existing deterministic selector.

This is an offline, leakage-resistant screening experiment.  Each fold keeps an
entire server region out for testing, uses another complete region for model
selection, and trains on the remaining three regions.  The existing
``score_row`` implementation is used unchanged as the deterministic baseline.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from contextual_signature_selector.replay_certificate_inventories import (
    FAMILY_CANDIDATES,
    inventory_products,
)
from contextual_signature_selector.selector import NetworkContext, SelectorConstants, score_row
from rl_weight_selector.bandit import action_grid


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PROFILE = ROOT / "outputs/analysis/composite_chain_length_overhead/composite_chain_detail.csv"
DEFAULT_OUT = ROOT / "outputs/analysis/rl_weight_selector_composite_screening"


@dataclass(frozen=True)
class Episode:
    region: str
    certificate_mode: str
    level: str
    classical_algorithm: str
    inventory: tuple[str, ...]
    rtt_ms: float
    bandwidth_mbps: float
    candidates: tuple[dict[str, object], ...]
    deterministic_algorithm: str
    deterministic_tls_ms: float


@dataclass(frozen=True)
class Bounds:
    minimum: tuple[float, float, float]
    maximum: tuple[float, float, float]


def read_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    if not rows:
        raise ValueError(f"empty profile: {path}")
    return rows


def raw_features(scored: dict[str, object], rtt_ms: float) -> tuple[float, float, float]:
    """Return sign, serialization, and non-serialization critical-path penalty."""
    sign_ms = float(scored["sign_ms"])
    serialization_ms = float(scored["serialization_ms"])
    extra_round_ms = int(scored["extra_rounds"]) * rtt_ms
    critical_path_ms = (
        extra_round_ms
        + float(scored["tail_delay_ms"])
        + float(scored["verify_chain_ms"])
        - float(scored["overlap_ms"])
    )
    return sign_ms, serialization_ms, critical_path_ms


def build_episodes(
    rows: list[dict[str, str]], bandwidth_mbps: float, window_size_bytes: int
) -> list[Episode]:
    by_context: dict[tuple[str, str, str, str], dict[str, dict[str, str]]] = defaultdict(dict)
    for row in rows:
        if row["level"] not in FAMILY_CANDIDATES:
            continue
        key = (row["region"], row["certificate_mode"], row["level"], row["classical_algorithm"])
        by_context[key][row["pqc_algorithm"]] = row

    constants = SelectorConstants()
    episodes: list[Episode] = []
    for (region, mode, level, classical), available in sorted(by_context.items()):
        for inventory in inventory_products(level):
            if not all(algorithm in available for algorithm in inventory):
                continue
            inventory_rows = [available[algorithm] for algorithm in inventory]
            rtt_ms = statistics.median(float(row["rtt_ms"]) for row in inventory_rows)
            context = NetworkContext(rtt_ms, bandwidth_mbps, window_size_bytes, rtt_ms)
            candidates: list[dict[str, object]] = []
            for row in inventory_rows:
                scored = score_row(row, context, constants)
                candidates.append(
                    {
                        "algorithm": row["algorithm"],
                        "pqc_algorithm": row["pqc_algorithm"],
                        "tls_ms": float(row["tls_handshake_time_ms"]),
                        "estimated_tls_ms": float(scored["estimated_tls_ms"]),
                        "features": raw_features(scored, rtt_ms),
                    }
                )
            deterministic = min(
                candidates,
                key=lambda item: (float(item["estimated_tls_ms"]), str(item["algorithm"])),
            )
            episodes.append(
                Episode(
                    region=region,
                    certificate_mode=mode,
                    level=level,
                    classical_algorithm=classical,
                    inventory=inventory,
                    rtt_ms=rtt_ms,
                    bandwidth_mbps=bandwidth_mbps,
                    candidates=tuple(candidates),
                    deterministic_algorithm=str(deterministic["algorithm"]),
                    deterministic_tls_ms=float(deterministic["tls_ms"]),
                )
            )
    if not episodes:
        raise ValueError("no complete inventory episodes could be constructed")
    return episodes


def fit_bounds(episodes: Iterable[Episode]) -> Bounds:
    values = [[], [], []]
    for episode in episodes:
        for candidate in episode.candidates:
            for index, value in enumerate(candidate["features"]):  # type: ignore[union-attr]
                values[index].append(float(value))
    if any(not part for part in values):
        raise ValueError("cannot fit feature bounds")
    return Bounds(
        tuple(min(part) for part in values),
        tuple(max(part) for part in values),
    )


def normalize(features: tuple[float, float, float], bounds: Bounds) -> tuple[float, float, float]:
    output = []
    for value, minimum, maximum in zip(features, bounds.minimum, bounds.maximum):
        if maximum <= minimum:
            output.append(0.0)
        else:
            output.append(max(0.0, min(1.0, (value - minimum) / (maximum - minimum))))
    return tuple(output)  # type: ignore[return-value]


def fit_state_range(episodes: Iterable[Episode]) -> tuple[float, float, float]:
    episodes = list(episodes)
    rtts = [episode.rtt_ms for episode in episodes]
    bandwidth_log_max = max(math.log1p(episode.bandwidth_mbps) for episode in episodes)
    return min(rtts), max(rtts), bandwidth_log_max


def state_key(episode: Episode, state_range: tuple[float, float, float], bins: int) -> str:
    rtt_min, rtt_max, bandwidth_log_max = state_range
    rtt_n = 0.0 if rtt_max <= rtt_min else (episode.rtt_ms - rtt_min) / (rtt_max - rtt_min)
    bw_n = math.log1p(episode.bandwidth_mbps) / bandwidth_log_max if bandwidth_log_max else 0.0
    rtt_index = min(bins - 1, max(0, int(max(0.0, min(1.0, rtt_n)) * bins)))
    bw_index = min(bins - 1, max(0, int(max(0.0, min(1.0, bw_n)) * bins)))
    return f"r{rtt_index}_b{bw_index}"


def parse_state(key: str) -> tuple[int, int]:
    left, right = key.split("_")
    return int(left[1:]), int(right[1:])


def nearest_state(key: str, table: dict[str, list[float]]) -> str:
    if key in table:
        return key
    target = parse_state(key)
    return min(
        table,
        key=lambda candidate: (
            sum((a - b) ** 2 for a, b in zip(target, parse_state(candidate))),
            candidate,
        ),
    )


def choose(
    episode: Episode, weights: tuple[float, float, float], bounds: Bounds
) -> dict[str, object]:
    ranked = []
    for candidate in episode.candidates:
        costs = normalize(candidate["features"], bounds)  # type: ignore[arg-type]
        score = sum(weight * cost for weight, cost in zip(weights, costs))
        ranked.append((score, sum(costs), str(candidate["algorithm"]), candidate, costs))
    _, _, _, selected, costs = min(ranked)
    return {**selected, "normalized_features": costs}


def relative_reward(episode: Episode, selected: dict[str, object]) -> float:
    return (episode.deterministic_tls_ms - float(selected["tls_ms"])) / episode.deterministic_tls_ms


def train(
    episodes: list[Episode], bins: int, action_step: float
) -> dict[str, object]:
    actions = action_grid(action_step)
    bounds = fit_bounds(episodes)
    state_range = fit_state_range(episodes)
    sums: dict[str, list[float]] = {}
    counts: dict[str, list[int]] = {}
    for episode in episodes:
        key = state_key(episode, state_range, bins)
        state_sums = sums.setdefault(key, [0.0] * len(actions))
        state_counts = counts.setdefault(key, [0] * len(actions))
        for index, weights in enumerate(actions):
            selected = choose(episode, weights, bounds)
            state_sums[index] += relative_reward(episode, selected)
            state_counts[index] += 1
    q_table = {
        key: [total / count if count else 0.0 for total, count in zip(values, counts[key])]
        for key, values in sums.items()
    }
    return {
        "bins": bins,
        "action_step": action_step,
        "actions": actions,
        "bounds": bounds,
        "state_range": state_range,
        "q_table": q_table,
        "q_counts": counts,
    }


def learned_weights(model: dict[str, object], episode: Episode) -> tuple[str, tuple[float, float, float]]:
    target = state_key(episode, model["state_range"], int(model["bins"]))  # type: ignore[arg-type]
    table = model["q_table"]  # type: ignore[assignment]
    used = nearest_state(target, table)  # type: ignore[arg-type]
    values = table[used]  # type: ignore[index]
    best = max(range(len(values)), key=lambda index: (values[index], -index))
    return used, tuple(model["actions"][best])  # type: ignore[index,return-value]


def evaluate(model: dict[str, object], episodes: list[Episode], fold: int, split: str) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    bounds = model["bounds"]
    for episode in episodes:
        used_state, weights = learned_weights(model, episode)
        selected = choose(episode, weights, bounds)  # type: ignore[arg-type]
        rl_ms = float(selected["tls_ms"])
        improvement_ms = episode.deterministic_tls_ms - rl_ms
        improvement_fraction = improvement_ms / episode.deterministic_tls_ms
        oracle = min(episode.candidates, key=lambda item: (float(item["tls_ms"]), str(item["algorithm"])))
        rows.append(
            {
                "fold": fold,
                "split": split,
                "region": episode.region,
                "certificate_mode": episode.certificate_mode,
                "security_level": episode.level,
                "classical_algorithm": episode.classical_algorithm,
                "inventory": ";".join(episode.inventory),
                "rtt_ms": episode.rtt_ms,
                "bandwidth_mbps": episode.bandwidth_mbps,
                "q_state": used_state,
                "weight_sign": weights[0],
                "weight_size_over_bw": weights[1],
                "weight_critical_path": weights[2],
                "deterministic_algorithm": episode.deterministic_algorithm,
                "rl_algorithm": selected["algorithm"],
                "oracle_algorithm": oracle["algorithm"],
                "deterministic_tls_ms": episode.deterministic_tls_ms,
                "rl_tls_ms": rl_ms,
                "oracle_tls_ms": float(oracle["tls_ms"]),
                "improvement_ms": improvement_ms,
                "improvement_percent": 100.0 * improvement_fraction,
                "relative_reward": improvement_fraction,
                "regret_vs_oracle_ms": rl_ms - float(oracle["tls_ms"]),
            }
        )
    return rows


def mean_reward(rows: list[dict[str, object]]) -> float:
    return statistics.fmean(float(row["relative_reward"]) for row in rows)


def select_hyperparameters(
    train_episodes: list[Episode], validation_episodes: list[Episode]
) -> tuple[int, float, list[dict[str, object]]]:
    searches: list[dict[str, object]] = []
    for bins in (1, 2, 3, 5):
        for action_step in (0.2, 0.1):
            model = train(train_episodes, bins, action_step)
            rows = evaluate(model, validation_episodes, -1, "validation")
            reward = mean_reward(rows)
            regret = statistics.fmean(float(row["regret_vs_oracle_ms"]) for row in rows)
            searches.append(
                {
                    "bins": bins,
                    "action_step": action_step,
                    "validation_mean_improvement_percent": 100.0 * reward,
                    "validation_mean_regret_ms": regret,
                }
            )
    best = max(
        searches,
        key=lambda row: (
            float(row["validation_mean_improvement_percent"]),
            -float(row["validation_mean_regret_ms"]),
            -int(row["bins"]),
            -float(row["action_step"]),
        ),
    )
    return int(best["bins"]), float(best["action_step"]), searches


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    position = fraction * (len(ordered) - 1)
    low = math.floor(position)
    high = math.ceil(position)
    if low == high:
        return ordered[low]
    return ordered[low] + (ordered[high] - ordered[low]) * (position - low)


def summarize(rows: list[dict[str, object]], episode_count: int) -> dict[str, object]:
    improvements_ms = [float(row["improvement_ms"]) for row in rows]
    improvements_pct = [float(row["improvement_percent"]) for row in rows]
    deterministic_mean = statistics.fmean(float(row["deterministic_tls_ms"]) for row in rows)
    rl_mean = statistics.fmean(float(row["rl_tls_ms"]) for row in rows)
    tolerance = 1e-9
    changed = [row for row in rows if row["deterministic_algorithm"] != row["rl_algorithm"]]
    return {
        "method": "5-fold region holdout; each fold train=3 regions, validation=1, test=1",
        "candidate_profile": "Composite98, five certificate modes, one-per-family inventories",
        "profile_episode_count": episode_count,
        "test_episode_count": len(rows),
        "mean_deterministic_tls_ms": deterministic_mean,
        "mean_rl_tls_ms": rl_mean,
        "aggregate_improvement_percent": 100.0 * (deterministic_mean - rl_mean) / deterministic_mean,
        "mean_improvement_ms": statistics.fmean(improvements_ms),
        "median_improvement_ms": statistics.median(improvements_ms),
        "mean_improvement_percent": statistics.fmean(improvements_pct),
        "median_improvement_percent": statistics.median(improvements_pct),
        "p05_improvement_percent": percentile(improvements_pct, 0.05),
        "p95_improvement_percent": percentile(improvements_pct, 0.95),
        "rl_win_count": sum(value > tolerance for value in improvements_ms),
        "tie_count": sum(abs(value) <= tolerance for value in improvements_ms),
        "rl_loss_count": sum(value < -tolerance for value in improvements_ms),
        "selection_changed_count": len(changed),
        "changed_selection_mean_improvement_ms": (
            statistics.fmean(float(row["improvement_ms"]) for row in changed) if changed else 0.0
        ),
        "changed_selection_mean_improvement_percent": (
            statistics.fmean(float(row["improvement_percent"]) for row in changed) if changed else 0.0
        ),
        "mean_regret_vs_oracle_ms": statistics.fmean(float(row["regret_vs_oracle_ms"]) for row in rows),
        "note": "screening result uses aggregate measured TLS means; raw-handshake confidence intervals are a later confirmation step",
    }


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def run(args: argparse.Namespace) -> dict[str, object]:
    episodes = build_episodes(read_rows(args.profile), args.bandwidth_mbps, args.window_size_bytes)
    regions = sorted({episode.region for episode in episodes})
    if len(regions) != 5:
        raise ValueError(f"expected five complete regions, got {regions}")

    test_rows: list[dict[str, object]] = []
    search_rows: list[dict[str, object]] = []
    fold_rows: list[dict[str, object]] = []
    for fold, test_region in enumerate(regions):
        validation_region = regions[(fold + 1) % len(regions)]
        train_regions = [region for region in regions if region not in {test_region, validation_region}]
        training = [episode for episode in episodes if episode.region in train_regions]
        validation = [episode for episode in episodes if episode.region == validation_region]
        testing = [episode for episode in episodes if episode.region == test_region]
        bins, action_step, searches = select_hyperparameters(training, validation)
        for row in searches:
            search_rows.append(
                {
                    "fold": fold,
                    "test_region": test_region,
                    "validation_region": validation_region,
                    **row,
                }
            )
        model = train(training + validation, bins, action_step)
        evaluated = evaluate(model, testing, fold, "test")
        test_rows.extend(evaluated)
        fold_rows.append(
            {
                "fold": fold,
                "train_regions": ";".join(train_regions),
                "validation_region": validation_region,
                "test_region": test_region,
                "bins": bins,
                "action_step": action_step,
                "train_episode_count": len(training),
                "validation_episode_count": len(validation),
                "test_episode_count": len(testing),
                "test_mean_improvement_percent": 100.0 * mean_reward(evaluated),
                "test_mean_improvement_ms": statistics.fmean(float(row["improvement_ms"]) for row in evaluated),
                "test_win_count": sum(float(row["improvement_ms"]) > 1e-9 for row in evaluated),
                "test_tie_count": sum(abs(float(row["improvement_ms"])) <= 1e-9 for row in evaluated),
                "test_loss_count": sum(float(row["improvement_ms"]) < -1e-9 for row in evaluated),
            }
        )

    summary = summarize(test_rows, len(episodes))
    summary["regions"] = regions
    summary["bandwidth_mbps"] = args.bandwidth_mbps
    summary["window_size_bytes"] = args.window_size_bytes
    summary["deterministic_baseline"] = "contextual_signature_selector.selector.score_row (unchanged)"
    summary["reward"] = "(deterministic_tls_ms - rl_tls_ms) / deterministic_tls_ms"
    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(args.output_dir / "test_evaluation.csv", test_rows)
    write_csv(args.output_dir / "fold_summary.csv", fold_rows)
    write_csv(args.output_dir / "validation_search.csv", search_rows)
    (args.output_dir / "metrics.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--bandwidth-mbps", type=float, default=1000.0)
    parser.add_argument("--window-size-bytes", type=int, default=16384)
    return parser.parse_args()


def main() -> int:
    summary = run(parse_args())
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
