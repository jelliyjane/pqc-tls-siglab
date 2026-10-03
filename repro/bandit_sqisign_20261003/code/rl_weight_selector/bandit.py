#!/usr/bin/env python3
"""Train and run a tabular contextual-bandit TLS candidate selector.

The learner uses RTT and known bandwidth as context.  Its action is a
three-element weight vector over transmission, extra-RTT-round, and crypto costs.
The selected candidate is the one with the smallest weighted normalized cost.
Reward is the measured TLS-time improvement over a fixed-weight selector.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "outputs" / "analysis" / "rl_weight_selector"
DEFAULT_CERT_PROFILE = ROOT / "outputs" / "historical_results" / "pqc_chain1ica_certificate_sizes.csv"
DEFAULT_CRYPTO_PROFILE = ROOT / "contextual_tls_profile" / "results" / "cost_profile_liboqs.csv"
DEFAULT_REGIONS = ("usa", "tokyo", "singapore")


@dataclass(frozen=True)
class CandidateProfile:
    algorithm: str
    security_level: str
    payload_bytes: int
    crypto_ms: float
    sign_ms: float = 0.0
    verify_ms: float = 0.0


@dataclass
class Measurement:
    mean_ms: float
    count: int


@dataclass
class ExperimentContext:
    source_region: str
    server_location: str
    experiment: str
    condition: str
    level: str
    rtt_ms: float
    bandwidth_mbps: float | None
    loss_percent: float
    measurements: dict[str, Measurement] = field(default_factory=dict)

    @property
    def identifier(self) -> str:
        return "|".join((self.source_region, self.experiment, self.condition, self.level))


@dataclass(frozen=True)
class ContextNormalizer:
    rtt_min: float
    rtt_max: float
    bandwidth_log_max: float

    def normalize(self, context: ExperimentContext | tuple[float, float | None]) -> tuple[float, float]:
        if isinstance(context, ExperimentContext):
            rtt, bandwidth = context.rtt_ms, context.bandwidth_mbps
        else:
            rtt, bandwidth = context
        rtt_n = minmax(rtt, self.rtt_min, self.rtt_max)
        bandwidth_n = 1.0 if bandwidth is None else math.log1p(max(0.0, bandwidth)) / self.bandwidth_log_max
        return clamp(rtt_n), clamp(bandwidth_n)


@dataclass(frozen=True)
class CostBounds:
    transmission_min: float
    transmission_max: float
    rtt_round_min: float
    rtt_round_max: float
    crypto_min: float
    crypto_max: float


def clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def minmax(value: float, minimum: float, maximum: float) -> float:
    if maximum <= minimum:
        return 0.0
    return (value - minimum) / (maximum - minimum)


def parse_float(value: str | None) -> float:
    if value is None:
        raise ValueError("missing numeric value")
    return float(value.rstrip("%"))


def parse_bandwidth(value: str) -> float | None:
    cleaned = value.strip().lower()
    if cleaned in {"", "unlimited", "none", "inf", "infinite"}:
        return None
    return float(cleaned)


def condition_name(experiment: str, bandwidth: str, loss: str) -> str:
    loss_value = loss.rstrip("%")
    if experiment == "matrix":
        return f"bw_{bandwidth}mbps_loss_{loss_value}pct"
    if experiment == "bw_only":
        return f"bw_{bandwidth}mbps"
    if experiment == "loss_only":
        return f"loss_{loss_value}pct"
    return f"bw_{bandwidth}_loss_{loss_value}"


def default_data_pairs(root: Path = ROOT) -> list[tuple[str, Path, Path]]:
    pairs: list[tuple[str, Path, Path]] = []
    for region in DEFAULT_REGIONS:
        base = root / "outputs" / "regional_exact" / region
        for suffix in ("", "_matrix"):
            summary = base / f"tls_results_{region}_chain1ica{suffix}_summary.csv"
            raw = base / f"tls_results_{region}_chain1ica{suffix}_raw.csv"
            if summary.exists():
                pairs.append((region, summary, raw))
    return pairs


def load_profiles(cert_path: Path, crypto_path: Path) -> dict[str, CandidateProfile]:
    cert_sizes: dict[str, tuple[int, str]] = {}
    with cert_path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            cert_sizes[row["algorithm"]] = (int(row["chain_total_der_bytes"]), row["security_level"])

    crypto: dict[str, tuple[float, int, float, float]] = {}
    with crypto_path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            if row.get("supported", "true").lower() != "true":
                continue
            sign_ms = float(row["sign_time_ms"])
            verify_ms = float(row["verify_time_ms"])
            crypto[row["algorithm"]] = (
                sign_ms + verify_ms,
                int(float(row["signature_size_bytes"])),
                sign_ms,
                verify_ms,
            )

    profiles: dict[str, CandidateProfile] = {}
    for algorithm, (chain_bytes, security_level) in cert_sizes.items():
        if algorithm not in crypto:
            continue
        crypto_ms, signature_bytes, sign_ms, verify_ms = crypto[algorithm]
        profiles[algorithm] = CandidateProfile(
            algorithm=algorithm,
            security_level=security_level,
            payload_bytes=chain_bytes + signature_bytes,
            crypto_ms=crypto_ms,
            sign_ms=sign_ms,
            verify_ms=verify_ms,
        )
    if not profiles:
        raise ValueError("no candidate profiles matched certificate and crypto profiles")
    return profiles


def load_context_pair(
    source_region: str,
    summary_path: Path,
    raw_path: Path,
    raw_partition: str = "all",
    split_modulus: int = 5,
    trim_upper_fraction: float = 0.3,
) -> list[ExperimentContext]:
    contexts: dict[tuple[str, str, str], ExperimentContext] = {}
    algorithm_lookup: dict[tuple[str, str, str], tuple[str, str, str]] = {}

    with summary_path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            experiment = row["experiment"]
            condition = condition_name(experiment, row["bw_mbps"], row["lossrate"])
            level = row["security_level"]
            key = (experiment, condition, level)
            context = contexts.setdefault(
                key,
                ExperimentContext(
                    source_region=source_region,
                    server_location=row["server_location"],
                    experiment=experiment,
                    condition=condition,
                    level=level,
                    rtt_ms=parse_float(row["rtt_ms"]),
                    bandwidth_mbps=parse_bandwidth(row["bw_mbps"]),
                    loss_percent=parse_float(row["lossrate"]),
                ),
            )
            algorithm = row["algorithm"]
            context.measurements[algorithm] = Measurement(
                mean_ms=float(row["tls_handshake_time_ms"]),
                count=int(row.get("kept_count") or row.get("sample_count") or 1),
            )
            algorithm_lookup[(experiment, condition, algorithm)] = key

    if raw_path.exists():
        samples: dict[tuple[str, str, str], list[float]] = {}
        with raw_path.open(newline="", encoding="utf-8") as handle:
            for row in csv.DictReader(handle):
                if row.get("status", "OK") != "OK":
                    continue
                run_number = int(row.get("run") or 0)
                is_test = run_number % split_modulus == 0
                if raw_partition == "train" and is_test:
                    continue
                if raw_partition == "test" and not is_test:
                    continue
                raw_key = (row["experiment"], row["condition"], row["algorithm"])
                if raw_key not in algorithm_lookup:
                    continue
                samples.setdefault(raw_key, []).append(float(row["elapsed_ms"]))
        for raw_key, values in samples.items():
            values.sort()
            keep_count = max(1, math.floor(len(values) * (1.0 - trim_upper_fraction)))
            kept = values[:keep_count]
            context_key = algorithm_lookup[raw_key]
            contexts[context_key].measurements[raw_key[2]] = Measurement(sum(kept) / len(kept), len(kept))

    return list(contexts.values())


def load_dataset(
    pairs: Iterable[tuple[str, Path, Path]],
    raw_partition: str = "all",
    split_modulus: int = 5,
    trim_upper_fraction: float = 0.3,
) -> list[ExperimentContext]:
    contexts: list[ExperimentContext] = []
    for source_region, summary, raw in pairs:
        contexts.extend(
            load_context_pair(source_region, summary, raw, raw_partition, split_modulus, trim_upper_fraction)
        )
    if not contexts:
        raise ValueError("no experiment contexts loaded")
    return contexts


def fit_context_normalizer(contexts: list[ExperimentContext]) -> ContextNormalizer:
    rtts = [c.rtt_ms for c in contexts]
    finite_bandwidths = [c.bandwidth_mbps for c in contexts if c.bandwidth_mbps is not None]
    bandwidth_max = max(finite_bandwidths, default=1.0)
    return ContextNormalizer(min(rtts), max(rtts), math.log1p(bandwidth_max))


def raw_costs(profile: CandidateProfile, rtt_ms: float, bandwidth_mbps: float | None) -> tuple[float, float, float]:
    transmission_ms = 0.0
    if bandwidth_mbps is not None:
        transmission_ms = profile.payload_bytes * 8.0 / (bandwidth_mbps * 1_000_000.0) * 1000.0
    # Candidate-specific RTT cost without using packet loss. A larger server
    # flight can require additional send-window rounds before TLS completes.
    flight_window_bytes = 16384
    extra_rounds = max(0, math.ceil(profile.payload_bytes / flight_window_bytes) - 1)
    rtt_round_ms = extra_rounds * rtt_ms
    return transmission_ms, rtt_round_ms, profile.crypto_ms


def fit_cost_bounds(contexts: list[ExperimentContext], profiles: dict[str, CandidateProfile]) -> CostBounds:
    values = [[], [], []]
    for context in contexts:
        for algorithm in context.measurements:
            profile = profiles.get(algorithm)
            if profile is None:
                continue
            costs = raw_costs(profile, context.rtt_ms, context.bandwidth_mbps)
            for index, value in enumerate(costs):
                values[index].append(value)
    if any(not part for part in values):
        raise ValueError("cannot fit cost normalization bounds")
    return CostBounds(
        min(values[0]), max(values[0]), min(values[1]), max(values[1]), min(values[2]), max(values[2])
    )


def normalized_costs(profile: CandidateProfile, context: ExperimentContext | tuple[float, float | None], bounds: CostBounds) -> tuple[float, float, float]:
    if isinstance(context, ExperimentContext):
        rtt, bandwidth = context.rtt_ms, context.bandwidth_mbps
    else:
        rtt, bandwidth = context
    transmission, rtt_round, crypto = raw_costs(profile, rtt, bandwidth)
    return (
        clamp(minmax(transmission, bounds.transmission_min, bounds.transmission_max)),
        clamp(minmax(rtt_round, bounds.rtt_round_min, bounds.rtt_round_max)),
        clamp(minmax(crypto, bounds.crypto_min, bounds.crypto_max)),
    )


def action_grid(step: float) -> list[tuple[float, float, float]]:
    divisions = round(1.0 / step)
    if step <= 0 or not math.isclose(divisions * step, 1.0, abs_tol=1e-9):
        raise ValueError("action step must divide 1 exactly, for example 0.1 or 0.05")
    actions = []
    for first in range(divisions + 1):
        for second in range(divisions - first + 1):
            third = divisions - first - second
            actions.append((first / divisions, second / divisions, third / divisions))
    return actions


def state_key(normalized: tuple[float, float], bins: int) -> str:
    indices = [min(bins - 1, max(0, int(value * bins))) for value in normalized]
    return f"r{indices[0]}_b{indices[1]}"


def state_indices(key: str) -> tuple[int, int]:
    parts = key.split("_")
    return tuple(int(part[1:]) for part in parts)  # type: ignore[return-value]


def select_candidate(
    algorithms: Iterable[str],
    profiles: dict[str, CandidateProfile],
    context: ExperimentContext | tuple[float, float | None],
    bounds: CostBounds,
    weights: tuple[float, float, float],
) -> tuple[str, tuple[float, float, float], float]:
    ranked = []
    for algorithm in algorithms:
        profile = profiles.get(algorithm)
        if profile is None:
            continue
        costs = normalized_costs(profile, context, bounds)
        score = sum(weight * cost for weight, cost in zip(weights, costs))
        ranked.append((score, sum(costs), algorithm, costs))
    if not ranked:
        raise ValueError("no measured candidates have a matching profile")
    score, _, algorithm, costs = min(ranked)
    return algorithm, costs, score


def nearest_q_state(target: str, q_table: dict[str, list[float]]) -> str:
    if target in q_table:
        return target
    wanted = state_indices(target)
    return min(
        q_table,
        key=lambda key: (sum((a - b) ** 2 for a, b in zip(wanted, state_indices(key))), key),
    )


def train_model(
    contexts: list[ExperimentContext],
    profiles: dict[str, CandidateProfile],
    bins: int,
    action_step: float,
    static_weights: tuple[float, float, float],
) -> dict[str, object]:
    normalizer = fit_context_normalizer(contexts)
    bounds = fit_cost_bounds(contexts, profiles)
    actions = action_grid(action_step)
    q_table: dict[str, list[float]] = {}
    q_counts: dict[str, list[int]] = {}

    for context in contexts:
        algorithms = [algorithm for algorithm in context.measurements if algorithm in profiles]
        if not algorithms:
            continue
        static_algorithm, _, _ = select_candidate(algorithms, profiles, context, bounds, static_weights)
        static_measurement = context.measurements[static_algorithm]
        key = state_key(normalizer.normalize(context), bins)
        q_values = q_table.setdefault(key, [0.0] * len(actions))
        counts = q_counts.setdefault(key, [0] * len(actions))
        for index, action in enumerate(actions):
            selected, _, _ = select_candidate(algorithms, profiles, context, bounds, action)
            selected_measurement = context.measurements[selected]
            reward = static_measurement.mean_ms - selected_measurement.mean_ms
            observations = min(static_measurement.count, selected_measurement.count)
            new_count = counts[index] + observations
            q_values[index] += (observations / new_count) * (reward - q_values[index])
            counts[index] = new_count

    if not q_table:
        raise ValueError("training produced an empty Q table")
    return {
        "version": 1,
        "description": "tabular contextual bandit; CPU and loss excluded",
        "state_features": ["normalized_rtt", "normalized_bandwidth"],
        "action_features": ["transmission_weight", "rtt_round_weight", "crypto_weight"],
        "bins": bins,
        "action_step": action_step,
        "actions": [list(action) for action in actions],
        "static_weights": list(static_weights),
        "context_normalizer": asdict(normalizer),
        "cost_bounds": asdict(bounds),
        "q_table": q_table,
        "q_counts": q_counts,
        "profiles": {algorithm: asdict(profile) for algorithm, profile in profiles.items()},
        "training_contexts": len(contexts),
        "training_observations": sum(m.count for c in contexts for m in c.measurements.values()),
    }


def model_parts(model: dict[str, object]) -> tuple[ContextNormalizer, CostBounds, dict[str, CandidateProfile]]:
    normalizer = ContextNormalizer(**model["context_normalizer"])  # type: ignore[arg-type]
    bounds = CostBounds(**model["cost_bounds"])  # type: ignore[arg-type]
    profiles = {
        algorithm: CandidateProfile(**values)
        for algorithm, values in model["profiles"].items()  # type: ignore[union-attr]
    }
    return normalizer, bounds, profiles


def learned_action(model: dict[str, object], context: ExperimentContext | tuple[float, float | None]) -> tuple[str, tuple[float, float, float], float]:
    normalizer, _, _ = model_parts(model)
    target = state_key(normalizer.normalize(context), int(model["bins"]))
    q_table = model["q_table"]  # type: ignore[assignment]
    used = nearest_q_state(target, q_table)  # type: ignore[arg-type]
    values = q_table[used]  # type: ignore[index]
    best_index = max(range(len(values)), key=lambda index: (values[index], -index))
    action = tuple(model["actions"][best_index])  # type: ignore[index]
    return used, action, float(values[best_index])  # type: ignore[return-value]


def evaluate(model: dict[str, object], contexts: list[ExperimentContext]) -> tuple[list[dict[str, object]], dict[str, object]]:
    _, bounds, profiles = model_parts(model)
    static_weights = tuple(model["static_weights"])  # type: ignore[arg-type]
    rows: list[dict[str, object]] = []
    for context in contexts:
        algorithms = [algorithm for algorithm in context.measurements if algorithm in profiles]
        if not algorithms:
            continue
        used_state, weights, expected_reward = learned_action(model, context)
        rl_algorithm, costs, score = select_candidate(algorithms, profiles, context, bounds, weights)
        static_algorithm, _, _ = select_candidate(algorithms, profiles, context, bounds, static_weights)  # type: ignore[arg-type]
        oracle_algorithm = min(algorithms, key=lambda algorithm: (context.measurements[algorithm].mean_ms, algorithm))
        rl_ms = context.measurements[rl_algorithm].mean_ms
        static_ms = context.measurements[static_algorithm].mean_ms
        oracle_ms = context.measurements[oracle_algorithm].mean_ms
        rows.append({
            "context_id": context.identifier,
            "region": context.server_location,
            "experiment": context.experiment,
            "condition": context.condition,
            "security_level": context.level,
            "rtt_ms": context.rtt_ms,
            "bandwidth_mbps": "unlimited" if context.bandwidth_mbps is None else context.bandwidth_mbps,
            "loss_percent": context.loss_percent,
            "q_state": used_state,
            "weight_transmission": weights[0],
            "weight_rtt_round": weights[1],
            "weight_crypto": weights[2],
            "selected_algorithm": rl_algorithm,
            "static_algorithm": static_algorithm,
            "oracle_algorithm": oracle_algorithm,
            "selected_tls_ms": rl_ms,
            "static_tls_ms": static_ms,
            "oracle_tls_ms": oracle_ms,
            "improvement_vs_static_ms": static_ms - rl_ms,
            "regret_vs_oracle_ms": rl_ms - oracle_ms,
            "expected_training_reward_ms": expected_reward,
            "selected_transmission_cost_norm": costs[0],
            "selected_rtt_round_cost_norm": costs[1],
            "selected_crypto_cost_norm": costs[2],
            "selected_weighted_score": score,
        })
    if not rows:
        raise ValueError("evaluation produced no rows")
    metrics: dict[str, object] = {
        "contexts": len(rows),
        "mean_rl_tls_ms": sum(float(row["selected_tls_ms"]) for row in rows) / len(rows),
        "mean_static_tls_ms": sum(float(row["static_tls_ms"]) for row in rows) / len(rows),
        "mean_oracle_tls_ms": sum(float(row["oracle_tls_ms"]) for row in rows) / len(rows),
        "mean_improvement_vs_static_ms": sum(float(row["improvement_vs_static_ms"]) for row in rows) / len(rows),
        "mean_regret_vs_oracle_ms": sum(float(row["regret_vs_oracle_ms"]) for row in rows) / len(rows),
        "rl_better_than_static_contexts": sum(float(row["improvement_vs_static_ms"]) > 0 for row in rows),
        "rl_equal_to_static_contexts": sum(math.isclose(float(row["improvement_vs_static_ms"]), 0.0, abs_tol=1e-9) for row in rows),
        "rl_oracle_match_contexts": sum(row["selected_algorithm"] == row["oracle_algorithm"] for row in rows),
    }
    return rows, metrics


def classification_metrics(rows: list[dict[str, object]]) -> tuple[dict[str, object], list[dict[str, object]], list[dict[str, object]]]:
    """Return multiclass metrics, per-class metrics, and sparse confusion rows."""
    confusion: Counter[tuple[str, str]] = Counter(
        (str(row["oracle_algorithm"]), str(row["selected_algorithm"])) for row in rows
    )
    true_counts: Counter[str] = Counter(str(row["oracle_algorithm"]) for row in rows)
    predicted_counts: Counter[str] = Counter(str(row["selected_algorithm"]) for row in rows)
    labels = sorted(set(true_counts) | set(predicted_counts))
    per_class: list[dict[str, object]] = []
    for label in labels:
        true_positive = confusion[(label, label)]
        precision = true_positive / predicted_counts[label] if predicted_counts[label] else 0.0
        recall = true_positive / true_counts[label] if true_counts[label] else 0.0
        f1 = 2.0 * precision * recall / (precision + recall) if precision + recall else 0.0
        per_class.append({
            "algorithm": label,
            "support": true_counts[label],
            "predicted_count": predicted_counts[label],
            "precision": precision,
            "recall": recall,
            "f1": f1,
        })
    total = len(rows)
    correct = sum(confusion[(label, label)] for label in labels)
    true_classes = [item for item in per_class if int(item["support"]) > 0]
    metrics = {
        "top1_accuracy": correct / total if total else 0.0,
        "micro_f1": correct / total if total else 0.0,
        "macro_f1": sum(float(item["f1"]) for item in per_class) / len(per_class) if per_class else 0.0,
        "weighted_f1": sum(float(item["f1"]) * int(item["support"]) for item in per_class) / total if total else 0.0,
        "balanced_accuracy": sum(float(item["recall"]) for item in true_classes) / len(true_classes) if true_classes else 0.0,
        "tie_aware_accuracy_5ms": sum(float(row["regret_vs_oracle_ms"]) <= 5.0 for row in rows) / total if total else 0.0,
        "tie_aware_accuracy_20ms": sum(float(row["regret_vs_oracle_ms"]) <= 20.0 for row in rows) / total if total else 0.0,
        "class_count": len(labels),
        "true_class_count": len(true_counts),
    }
    confusion_rows = [
        {"actual_algorithm": actual, "predicted_algorithm": predicted, "count": count}
        for (actual, predicted), count in sorted(confusion.items())
    ]
    return metrics, per_class, confusion_rows


def context_group_key(context: ExperimentContext) -> str:
    bandwidth = "unlimited" if context.bandwidth_mbps is None else f"{context.bandwidth_mbps:g}"
    # Loss is deliberately excluded from both model state and split identity.
    # All loss conditions for the same RTT/BW path stay in the same split.
    return f"{context.source_region}|{context.rtt_ms:g}|{bandwidth}"


def grouped_context_split(
    contexts: list[ExperimentContext], seed: int, train_fraction: float = 0.6, validation_fraction: float = 0.2
) -> tuple[list[ExperimentContext], list[ExperimentContext], list[ExperimentContext]]:
    """Split whole network contexts so no RTT/BW/loss group crosses a boundary."""
    grouped: dict[str, list[ExperimentContext]] = defaultdict(list)
    for context in contexts:
        grouped[context_group_key(context)].append(context)
    keys = sorted(
        grouped,
        key=lambda key: hashlib.sha256(f"{seed}|{key}".encode("utf-8")).hexdigest(),
    )
    if len(keys) < 3:
        raise ValueError("at least three distinct context groups are required")
    train_end = max(1, min(len(keys) - 2, round(len(keys) * train_fraction)))
    validation_end = max(train_end + 1, min(len(keys) - 1, train_end + round(len(keys) * validation_fraction)))
    train_keys = set(keys[:train_end])
    validation_keys = set(keys[train_end:validation_end])
    test_keys = set(keys[validation_end:])
    return (
        [context for key in train_keys for context in grouped[key]],
        [context for key in validation_keys for context in grouped[key]],
        [context for key in test_keys for context in grouped[key]],
    )


def parse_number_list(text: str, converter: type[int] | type[float]) -> list[int] | list[float]:
    values = [converter(part.strip()) for part in text.split(",") if part.strip()]
    if not values:
        raise argparse.ArgumentTypeError("list cannot be empty")
    return values


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def parse_weights(text: str) -> tuple[float, float, float]:
    values = tuple(float(value.strip()) for value in text.split(","))
    if len(values) != 3 or any(value < 0 for value in values) or not math.isclose(sum(values), 1.0, abs_tol=1e-9):
        raise argparse.ArgumentTypeError("weights must be three nonnegative comma-separated values summing to 1")
    return values  # type: ignore[return-value]


def train_command(args: argparse.Namespace) -> int:
    pairs = default_data_pairs(args.root)
    contexts = load_dataset(pairs, trim_upper_fraction=args.trim_upper_fraction)
    profiles = load_profiles(args.cert_profile, args.crypto_profile)
    train_contexts, validation_contexts, test_contexts = grouped_context_split(contexts, args.seed)
    bins_grid = parse_number_list(args.bins_grid, int)
    action_steps = parse_number_list(args.action_steps, float)
    search_rows: list[dict[str, object]] = []
    best_choice: tuple[float, float, int, float] | None = None
    for bins in bins_grid:
        for action_step in action_steps:
            candidate_model = train_model(train_contexts, profiles, int(bins), float(action_step), args.static_weights)
            validation_rows, validation_reward_metrics = evaluate(candidate_model, validation_contexts)
            validation_classification, _, _ = classification_metrics(validation_rows)
            search_row = {
                "bins": bins,
                "action_step": action_step,
                "validation_accuracy": validation_classification["top1_accuracy"],
                "validation_macro_f1": validation_classification["macro_f1"],
                "validation_weighted_f1": validation_classification["weighted_f1"],
                "validation_mean_improvement_ms": validation_reward_metrics["mean_improvement_vs_static_ms"],
                "validation_mean_regret_ms": validation_reward_metrics["mean_regret_vs_oracle_ms"],
            }
            search_rows.append(search_row)
            choice = (
                float(validation_classification["macro_f1"]),
                float(validation_classification["top1_accuracy"]),
                int(bins),
                float(action_step),
            )
            if best_choice is None or choice[:2] > best_choice[:2]:
                best_choice = choice
    assert best_choice is not None
    selected_bins, selected_action_step = best_choice[2], best_choice[3]
    evaluation_model = train_model(
        train_contexts + validation_contexts,
        profiles,
        selected_bins,
        selected_action_step,
        args.static_weights,
    )
    rows, metrics = evaluate(evaluation_model, test_contexts)
    classification, per_class, confusion_rows = classification_metrics(rows)
    metrics.update(classification)

    model = train_model(contexts, profiles, selected_bins, selected_action_step, args.static_weights)
    model["data_files"] = [str(summary) for _, summary, _ in pairs]
    model["validation"] = "grouped train/validation/test by region+RTT+bandwidth; loss excluded"
    model["trim_upper_fraction"] = args.trim_upper_fraction
    model["split_seed"] = args.seed
    metrics["validation"] = model["validation"]
    metrics["selected_bins"] = selected_bins
    metrics["selected_action_step"] = selected_action_step
    metrics["train_contexts"] = len(train_contexts)
    metrics["validation_contexts"] = len(validation_contexts)
    metrics["test_contexts"] = len(test_contexts)
    metrics["test_context_groups"] = len({context_group_key(c) for c in test_contexts})
    metrics["final_training_contexts"] = len(contexts)
    metrics["final_training_observations"] = model["training_observations"]

    args.output_dir.mkdir(parents=True, exist_ok=True)
    model_path = args.output_dir / "bandit_model.json"
    evaluation_path = args.output_dir / "holdout_evaluation.csv"
    metrics_path = args.output_dir / "holdout_metrics.json"
    per_class_path = args.output_dir / "classification_per_algorithm.csv"
    confusion_path = args.output_dir / "confusion_matrix_sparse.csv"
    search_path = args.output_dir / "validation_search.csv"
    model_path.write_text(json.dumps(model, ensure_ascii=False, indent=2), encoding="utf-8")
    write_csv(evaluation_path, rows)
    write_csv(per_class_path, per_class)
    write_csv(confusion_path, confusion_rows)
    write_csv(search_path, search_rows)
    metrics_path.write_text(json.dumps(metrics, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"model": str(model_path), "evaluation": str(evaluation_path), "metrics": metrics}, ensure_ascii=False, indent=2))
    return 0


def select_command(args: argparse.Namespace) -> int:
    model = json.loads(args.model.read_text(encoding="utf-8"))
    _, bounds, profiles = model_parts(model)
    context = (args.rtt_ms, parse_bandwidth(args.bandwidth_mbps))
    algorithms = sorted(profiles)
    algorithms = [algorithm for algorithm in algorithms if profiles[algorithm].security_level == args.security_level]
    if args.candidates:
        requested = {part.strip() for part in args.candidates.split(",") if part.strip()}
        algorithms = [algorithm for algorithm in algorithms if algorithm in requested]
    used_state, weights, expected_reward = learned_action(model, context)
    algorithm, costs, score = select_candidate(algorithms, profiles, context, bounds, weights)
    result = {
        "normalized_state_used": used_state,
        "learned_weights": weights,
        "selected_candidate": algorithm,
        "expected_reward_vs_static_ms": expected_reward,
        "normalized_costs": {"transmission": costs[0], "rtt_round": costs[1], "crypto": costs[2]},
        "weighted_score": score,
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    train = subparsers.add_parser("train", help="train and evaluate the offline bandit")
    train.add_argument("--root", type=Path, default=ROOT)
    train.add_argument("--cert-profile", type=Path, default=DEFAULT_CERT_PROFILE)
    train.add_argument("--crypto-profile", type=Path, default=DEFAULT_CRYPTO_PROFILE)
    train.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    train.add_argument("--seed", type=int, default=42)
    train.add_argument("--bins-grid", default="3,5,7", help="validation candidates for state bins")
    train.add_argument("--action-steps", default="0.2,0.1", help="validation candidates for weight-grid step")
    train.add_argument("--trim-upper-fraction", type=float, default=0.3, help="discard the slowest fraction per algorithm, matching the experiment summaries")
    train.add_argument("--static-weights", type=parse_weights, default=(1 / 3, 1 / 3, 1 / 3))
    train.set_defaults(func=train_command)

    select = subparsers.add_parser("select", help="select a candidate with a trained model")
    select.add_argument("--model", type=Path, default=DEFAULT_OUTPUT / "bandit_model.json")
    select.add_argument("--rtt-ms", type=float, required=True)
    select.add_argument("--bandwidth-mbps", required=True, help="numeric Mbps or unlimited")
    select.add_argument("--security-level", choices=["L1", "L2", "L3", "L5"], required=True)
    select.add_argument("--candidates", default=None, help="optional comma-separated candidate allowlist")
    select.set_defaults(func=select_command)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
