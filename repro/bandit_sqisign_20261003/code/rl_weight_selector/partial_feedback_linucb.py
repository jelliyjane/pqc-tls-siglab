#!/usr/bin/env python3
"""Train a weight selector from partial TLS feedback with online LinUCB replay.

The agent sees the current continuous RTT/bandwidth context and certificate
metadata, chooses one weight-vector arm, and observes only the TLS latency of
the certificate selected by that arm.  Counterfactual candidate latencies stay
inside the evaluator and are used only for oracle-regret reporting.
"""

from __future__ import annotations

import argparse
import copy
import csv
import json
import math
import random
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

import numpy as np

from contextual_signature_selector.replay_certificate_inventories import FAMILY_CANDIDATES, inventory_products
from contextual_signature_selector.selector import NetworkContext, SelectorConstants, score_row
from pqc_cti.policy import filter_candidates, load_feed
from rl_weight_selector.bandit import action_grid
from rl_weight_selector.screen_composite_temporal import MODES, REGIONS, base_raw_path, shake_raw_path
from rl_weight_selector.screen_composite_vs_deterministic import (
    DEFAULT_PROFILE,
    Bounds,
    choose,
    fit_bounds,
    raw_features,
    read_rows,
    write_csv,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = ROOT / "outputs/analysis/rl_weight_selector_partial_feedback"
REWARD_SCALE_MS = 1000.0


@dataclass(frozen=True)
class BanditEpisode:
    region: str
    certificate_mode: str
    level: str
    classical_algorithm: str
    inventory: tuple[str, ...]
    rtt_ms: float
    bandwidth_mbps: float
    candidates: tuple[dict[str, object], ...]


def build_bandit_episodes(
    rows: list[dict[str, str]],
    bandwidth_mbps: float,
    window_size_bytes: int,
    cti_feed: dict[str, object] | None = None,
    cti_at: str | None = None,
) -> list[BanditEpisode]:
    by_context: dict[tuple[str, str, str, str], dict[str, dict[str, str]]] = defaultdict(dict)
    for row in rows:
        if row["level"] not in FAMILY_CANDIDATES:
            continue
        key = (row["region"], row["certificate_mode"], row["level"], row["classical_algorithm"])
        by_context[key][row["pqc_algorithm"]] = row

    constants = SelectorConstants()
    episodes: list[BanditEpisode] = []
    for (region, mode, level, classical), available in sorted(by_context.items()):
        for inventory in inventory_products(level):
            if not all(algorithm in available for algorithm in inventory):
                continue
            inventory_rows = [available[algorithm] for algorithm in inventory]
            rtt_ms = statistics.median(float(row["rtt_ms"]) for row in inventory_rows)
            context = NetworkContext(rtt_ms, bandwidth_mbps, window_size_bytes, rtt_ms)
            candidates = []
            for row in inventory_rows:
                scored = score_row(row, context, constants)
                candidates.append(
                    {
                        "algorithm": row["algorithm"],
                        "pqc_algorithm": row["pqc_algorithm"],
                        "classical_algorithm": row["classical_algorithm"],
                        "features": raw_features(scored, rtt_ms),
                    }
                )
            if cti_feed is not None:
                filtered = filter_candidates(candidates, cti_feed, at=cti_at)
                candidates = [dict(candidate) for candidate in filtered.eligible]
                if not candidates:
                    continue
            episodes.append(
                BanditEpisode(
                    region=region,
                    certificate_mode=mode,
                    level=level,
                    classical_algorithm=classical,
                    inventory=inventory,
                    rtt_ms=rtt_ms,
                    bandwidth_mbps=bandwidth_mbps,
                    candidates=tuple(candidates),
                )
            )
    if not episodes:
        raise ValueError("no complete inventory episodes could be constructed")
    return episodes


def raw_mode(profile_mode: str) -> str:
    mode = profile_mode.lower()
    return mode if mode == "root_direct" else f"chain{mode}"


def episode_id(episode: BanditEpisode) -> str:
    return "|".join(
        (
            episode.region.lower(),
            raw_mode(episode.certificate_mode),
            episode.level,
            episode.classical_algorithm,
            ";".join(episode.inventory),
        )
    )


def load_raw_samples() -> dict[tuple[int, str, str, str], float]:
    samples: dict[tuple[int, str, str, str], float] = {}
    for region in REGIONS:
        for mode in MODES:
            for path in (base_raw_path(region, mode), shake_raw_path(region, mode)):
                if not path.exists():
                    raise FileNotFoundError(path)
                with path.open(newline="", encoding="utf-8") as handle:
                    for row in csv.DictReader(handle):
                        if row.get("status") != "OK" or row.get("condition") != "loss_0pct":
                            continue
                        key = (int(row["run"]), region, mode, row["algorithm"])
                        value = float(row["elapsed_ms"])
                        previous = samples.setdefault(key, value)
                        if not math.isclose(previous, value, abs_tol=1e-12):
                            raise ValueError(f"conflicting raw sample: {key}")
    expected = 50 * len(REGIONS) * len(MODES) * 98
    if len(samples) != expected:
        raise ValueError(f"expected {expected} unique raw samples, got {len(samples)}")
    return samples


def context_vector(episode: BanditEpisode) -> np.ndarray:
    """Continuous context; fixed scales do not inspect any TLS outcome."""
    rtt = min(1.0, max(0.0, math.log1p(episode.rtt_ms) / math.log1p(300.0)))
    bandwidth = min(1.0, max(0.0, math.log1p(episode.bandwidth_mbps) / math.log1p(1000.0)))
    return np.asarray((1.0, rtt, bandwidth, rtt * bandwidth), dtype=float)


class LinUCBAgent:
    def __init__(
        self,
        actions: list[tuple[float, float, float]],
        dimension: int,
        alpha: float,
        ridge: float = 1.0,
    ) -> None:
        self.actions = actions
        self.dimension = dimension
        self.alpha = alpha
        self.ridge = ridge
        count = len(actions)
        identity = np.eye(dimension, dtype=float) / ridge
        self.a_inverse = np.repeat(identity[np.newaxis, :, :], count, axis=0)
        self.b = np.zeros((count, dimension), dtype=float)
        self.counts = np.zeros(count, dtype=np.int64)
        self.total_updates = 0

    def scores(self, context: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        theta = np.einsum("aij,aj->ai", self.a_inverse, self.b)
        means = theta @ context
        projected = np.einsum("aij,j->ai", self.a_inverse, context)
        uncertainty = np.sqrt(np.maximum(0.0, np.einsum("ai,i->a", projected, context)))
        return means + self.alpha * uncertainty, means, uncertainty

    def select(self, context: np.ndarray) -> tuple[int, float, float]:
        scores, means, uncertainty = self.scores(context)
        index = int(np.argmax(scores))
        return index, float(means[index]), float(uncertainty[index])

    def update(self, action_index: int, context: np.ndarray, reward: float) -> None:
        """Sherman-Morrison update for exactly the selected arm."""
        inverse = self.a_inverse[action_index]
        projected = inverse @ context
        denominator = 1.0 + float(context @ projected)
        self.a_inverse[action_index] = inverse - np.outer(projected, projected) / denominator
        self.b[action_index] += reward * context
        self.counts[action_index] += 1
        self.total_updates += 1

    def to_json(self) -> dict[str, object]:
        return {
            "model": "disjoint LinUCB weight selector",
            "context_features": ["bias", "log_rtt", "log_bandwidth", "log_rtt_x_log_bandwidth"],
            "alpha": self.alpha,
            "ridge": self.ridge,
            "reward": "-observed_tls_ms / 1000",
            "actions": [list(action) for action in self.actions],
            "counts": self.counts.tolist(),
            "a_inverse": self.a_inverse.tolist(),
            "b": self.b.tolist(),
            "total_updates": self.total_updates,
        }


@dataclass(frozen=True)
class Feedback:
    selected_algorithm: str
    selected_tls_ms: float
    reward: float


def reveal_selected_feedback(
    run: int,
    episode: BanditEpisode,
    selected_algorithm: str,
    samples: dict[tuple[int, str, str, str], float],
) -> Feedback:
    """The only outcome returned to the learning agent."""
    key = (run, episode.region.lower(), raw_mode(episode.certificate_mode), selected_algorithm)
    tls_ms = samples[key]
    return Feedback(selected_algorithm, tls_ms, -tls_ms / REWARD_SCALE_MS)


def oracle_for_evaluator(
    run: int,
    episode: BanditEpisode,
    samples: dict[tuple[int, str, str, str], float],
) -> tuple[str, float]:
    """Hidden counterfactual lookup; never passed into ``LinUCBAgent.update``."""
    results = []
    for candidate in episode.candidates:
        algorithm = str(candidate["algorithm"])
        key = (run, episode.region.lower(), raw_mode(episode.certificate_mode), algorithm)
        results.append((samples[key], algorithm))
    tls_ms, algorithm = min(results)
    return algorithm, tls_ms


def ordered_episodes(episodes: list[BanditEpisode], run: int, seed: int) -> list[BanditEpisode]:
    ordered = list(episodes)
    random.Random(seed * 1009 + run).shuffle(ordered)
    return ordered


def replay_runs(
    agent: LinUCBAgent,
    episodes: list[BanditEpisode],
    samples: dict[tuple[int, str, str, str], float],
    bounds: Bounds,
    first_run: int,
    last_run: int,
    seed: int,
    phase: str,
    keep_decisions: bool,
    update_agent: bool = True,
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    decisions: list[dict[str, object]] = []
    run_summaries: list[dict[str, object]] = []
    for run in range(first_run, last_run + 1):
        selected_values: list[float] = []
        oracle_values: list[float] = []
        matches = 0
        action_counts: Counter[int] = Counter()
        for episode in ordered_episodes(episodes, run, seed):
            x = context_vector(episode)
            action_index, expected_reward, uncertainty = agent.select(x)
            weights = agent.actions[action_index]
            selected = choose(episode, weights, bounds)
            selected_algorithm = str(selected["algorithm"])

            # Only this feedback object reaches the agent.
            feedback = reveal_selected_feedback(run, episode, selected_algorithm, samples)
            if update_agent:
                agent.update(action_index, x, feedback.reward)

            # The evaluator separately opens hidden candidate outcomes.
            oracle_algorithm, oracle_ms = oracle_for_evaluator(run, episode, samples)
            regret_ms = feedback.selected_tls_ms - oracle_ms
            selected_values.append(feedback.selected_tls_ms)
            oracle_values.append(oracle_ms)
            matches += selected_algorithm == oracle_algorithm
            action_counts[action_index] += 1
            if keep_decisions:
                decisions.append(
                    {
                        "phase": phase,
                        "run": run,
                        "episode_id": episode_id(episode),
                        "region": episode.region,
                        "certificate_mode": episode.certificate_mode,
                        "security_level": episode.level,
                        "classical_algorithm": episode.classical_algorithm,
                        "inventory": ";".join(episode.inventory),
                        "rtt_ms": episode.rtt_ms,
                        "bandwidth_mbps": episode.bandwidth_mbps,
                        "action_index": action_index,
                        "weight_sign": weights[0],
                        "weight_size_over_bw": weights[1],
                        "weight_critical_path": weights[2],
                        "expected_reward_before_observation": expected_reward,
                        "uncertainty_before_observation": uncertainty,
                        "selected_algorithm": selected_algorithm,
                        "observed_tls_ms": feedback.selected_tls_ms,
                        "observed_reward": feedback.reward,
                        "agent_updated_after_observation": int(update_agent),
                        "oracle_algorithm_evaluator_only": oracle_algorithm,
                        "oracle_tls_ms_evaluator_only": oracle_ms,
                        "regret_ms_evaluator_only": regret_ms,
                    }
                )
        run_summaries.append(
            {
                "phase": phase,
                "run": run,
                "decisions": len(selected_values),
                "mean_selected_tls_ms": statistics.fmean(selected_values),
                "mean_oracle_tls_ms_evaluator_only": statistics.fmean(oracle_values),
                "mean_regret_ms_evaluator_only": statistics.fmean(
                    selected - oracle for selected, oracle in zip(selected_values, oracle_values)
                ),
                "cumulative_regret_ms_evaluator_only": sum(
                    selected - oracle for selected, oracle in zip(selected_values, oracle_values)
                ),
                "oracle_match_rate_evaluator_only": matches / len(selected_values),
                "distinct_weight_actions": len(action_counts),
                "agent_total_updates_after_run": agent.total_updates,
            }
        )
    return decisions, run_summaries


def validate_alpha(
    alpha: float,
    actions: list[tuple[float, float, float]],
    episodes: list[BanditEpisode],
    samples: dict[tuple[int, str, str, str], float],
    bounds: Bounds,
    seed: int,
) -> dict[str, object]:
    dimension = len(context_vector(episodes[0]))
    agent = LinUCBAgent(actions, dimension, alpha)
    replay_runs(agent, episodes, samples, bounds, 1, 30, seed, "train", False)
    _, validation = replay_runs(agent, episodes, samples, bounds, 31, 40, seed, "validation", False)
    return {
        "alpha": alpha,
        "validation_mean_selected_tls_ms": statistics.fmean(
            float(row["mean_selected_tls_ms"]) for row in validation
        ),
        "validation_mean_regret_ms_evaluator_only": statistics.fmean(
            float(row["mean_regret_ms_evaluator_only"]) for row in validation
        ),
        "validation_oracle_match_rate_evaluator_only": statistics.fmean(
            float(row["oracle_match_rate_evaluator_only"]) for row in validation
        ),
        "updates": agent.total_updates,
    }


def run(args: argparse.Namespace) -> dict[str, object]:
    cti_feed = load_feed(args.cti_feed) if args.cti_feed else None
    episodes = build_bandit_episodes(
        read_rows(args.profile),
        args.bandwidth_mbps,
        args.window_size_bytes,
        cti_feed=cti_feed,
        cti_at=args.cti_at,
    )
    samples = load_raw_samples()
    bounds = fit_bounds(episodes)
    actions = action_grid(args.action_step)
    alpha_candidates = [float(value) for value in args.alphas.split(",") if value.strip()]
    validation = [
        validate_alpha(alpha, actions, episodes, samples, bounds, args.seed)
        for alpha in alpha_candidates
    ]
    selected_alpha = min(validation, key=lambda row: float(row["validation_mean_selected_tls_ms"]))["alpha"]

    dimension = len(context_vector(episodes[0]))
    fitted_agent = LinUCBAgent(actions, dimension, float(selected_alpha))
    _, fitting_curve = replay_runs(fitted_agent, episodes, samples, bounds, 1, 40, args.seed, "fit", False)
    frozen_agent = copy.deepcopy(fitted_agent)
    online_agent = copy.deepcopy(fitted_agent)
    frozen_decisions, frozen_curve = replay_runs(
        frozen_agent, episodes, samples, bounds, 41, 50, args.seed, "frozen_test", True, update_agent=False
    )
    decisions, test_curve = replay_runs(
        online_agent, episodes, samples, bounds, 41, 50, args.seed, "online_test", True, update_agent=True
    )
    learning_curve = fitting_curve + test_curve

    selected_values = [float(row["observed_tls_ms"]) for row in decisions]
    oracle_values = [float(row["oracle_tls_ms_evaluator_only"]) for row in decisions]
    regrets = [float(row["regret_ms_evaluator_only"]) for row in decisions]
    action_usage = Counter(int(row["action_index"]) for row in decisions)
    metrics: dict[str, object] = {
        "model": "partial-feedback disjoint LinUCB over three-dimensional weight arms",
        "deterministic_baseline_used": False,
        "feedback_visible_to_agent": ["selected_algorithm", "selected_tls_ms"],
        "counterfactual_candidate_tls_visible_to_agent": False,
        "context_features": ["continuous_log_rtt", "continuous_log_bandwidth", "interaction"],
        "candidate_selection_costs": ["sign", "size_over_bandwidth", "critical_path"],
        "cti": {
            "enabled": cti_feed is not None,
            "feed": str(args.cti_feed) if args.cti_feed else None,
            "feed_id": cti_feed.get("feed_id") if cti_feed else None,
            "feed_version": cti_feed.get("feed_version") if cti_feed else None,
            "synthetic": bool(cti_feed.get("synthetic", False)) if cti_feed else False,
            "evaluated_at": args.cti_at,
        },
        "action_step": args.action_step,
        "action_count": len(actions),
        "selected_alpha": selected_alpha,
        "raw_sample_count": len(samples),
        "inventory_episode_count_per_run": len(episodes),
        "fit_runs": "1-40",
        "test_runs": "41-50; excluded from fitting and hyperparameter selection",
        "test_decision_count": len(decisions),
        "agent_total_updates": online_agent.total_updates,
        "expected_total_updates": 50 * len(episodes),
        "test_mean_selected_tls_ms": statistics.fmean(selected_values),
        "test_mean_oracle_tls_ms_evaluator_only": statistics.fmean(oracle_values),
        "test_mean_regret_ms_evaluator_only": statistics.fmean(regrets),
        "test_cumulative_regret_ms_evaluator_only": sum(regrets),
        "test_oracle_match_rate_evaluator_only": sum(
            row["selected_algorithm"] == row["oracle_algorithm_evaluator_only"] for row in decisions
        ) / len(decisions),
        "test_distinct_weight_actions": len(action_usage),
        "test_most_used_actions": [
            {
                "action_index": index,
                "weights": list(actions[index]),
                "count": count,
            }
            for index, count in action_usage.most_common(10)
        ],
        "important_limitations": [
            "Composite98 replay has five measured RTT values but only one bandwidth value (1000 Mbps)",
            "raw run numbers approximate time; algorithms were not measured simultaneously",
            "the same controlled measurement can appear in multiple hypothetical inventory episodes",
            "oracle values are evaluator-only and never update the agent",
        ],
    }
    frozen_selected = [float(row["observed_tls_ms"]) for row in frozen_decisions]
    frozen_oracle = [float(row["oracle_tls_ms_evaluator_only"]) for row in frozen_decisions]
    frozen_regrets = [float(row["regret_ms_evaluator_only"]) for row in frozen_decisions]
    metrics["frozen_holdout"] = {
        "agent_updates_during_test": 0,
        "agent_total_updates_after_test": frozen_agent.total_updates,
        "decision_count": len(frozen_decisions),
        "mean_selected_tls_ms": statistics.fmean(frozen_selected),
        "mean_oracle_tls_ms_evaluator_only": statistics.fmean(frozen_oracle),
        "mean_regret_ms_evaluator_only": statistics.fmean(frozen_regrets),
        "cumulative_regret_ms_evaluator_only": sum(frozen_regrets),
        "oracle_match_rate_evaluator_only": sum(
            row["selected_algorithm"] == row["oracle_algorithm_evaluator_only"] for row in frozen_decisions
        ) / len(frozen_decisions),
        "distinct_weight_actions": len({int(row["action_index"]) for row in frozen_decisions}),
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(args.output_dir / "validation_search.csv", validation)
    write_csv(args.output_dir / "learning_curve.csv", learning_curve)
    write_csv(args.output_dir / "test_decisions.csv", decisions)
    write_csv(args.output_dir / "frozen_holdout_decisions.csv", frozen_decisions)
    write_csv(args.output_dir / "frozen_holdout_curve.csv", frozen_curve)
    (args.output_dir / "model_after_fit.json").write_text(
        json.dumps(fitted_agent.to_json(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (args.output_dir / "model.json").write_text(
        json.dumps(online_agent.to_json(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (args.output_dir / "metrics.json").write_text(
        json.dumps(metrics, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return metrics


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--bandwidth-mbps", type=float, default=1000.0)
    parser.add_argument("--window-size-bytes", type=int, default=16384)
    parser.add_argument("--action-step", type=float, default=0.1)
    parser.add_argument("--alphas", default="0.01,0.05,0.1,0.25")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--cti-feed", type=Path, default=None)
    parser.add_argument("--cti-at", default=None)
    return parser.parse_args()


def main() -> int:
    metrics = run(parse_args())
    print(json.dumps(metrics, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
