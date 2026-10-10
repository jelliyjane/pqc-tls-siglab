#!/usr/bin/env python3
"""Temporal 60/20/20 screening of RL weights versus the HTML deterministic policy."""

from __future__ import annotations

import argparse
import csv
import json
import statistics
from collections import defaultdict
from dataclasses import replace
from pathlib import Path

from rl_weight_selector.screen_composite_vs_deterministic import (
    DEFAULT_PROFILE,
    Episode,
    build_episodes,
    evaluate,
    read_rows,
    select_hyperparameters,
    summarize,
    train,
    write_csv,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = ROOT / "outputs/analysis/rl_weight_selector_composite_temporal"
REGIONS = ("usa", "seoul", "tokyo", "singapore", "frankfurt")
MODES = ("root_direct", "chain1ica", "chain2ica", "chain3ica", "chain4ica")


def base_raw_path(region: str, mode: str) -> Path:
    base = ROOT / "outputs/regional_exact"
    if region == "frankfurt":
        if mode == "chain1ica":
            return base / "frankfurt_chain1ica_default/composite86/tls_results_frankfurt_composite86_chain1ica_raw.csv"
        if mode in {"root_direct", "chain2ica"}:
            return base / f"frankfurt_default_cert_modes/composite86/{mode}/tls_results_frankfurt_composite86_{mode}_raw.csv"
        return base / f"composite_default_cert_modes/frankfurt/{mode}/tls_results_frankfurt_composite_{mode}_raw.csv"
    if mode == "chain1ica":
        return base / f"composite/{region}/tls_results_{region}_composite_chain1ica_raw.csv"
    if region == "seoul" and mode == "root_direct":
        return base / "composite/seoul_root_direct/tls_results_seoul_composite_root_direct_raw.csv"
    return base / f"composite_default_cert_modes/{region}/{mode}/tls_results_{region}_composite_{mode}_raw.csv"


def shake_raw_path(region: str, mode: str) -> Path:
    return (
        ROOT
        / f"outputs/regional_exact/composite_shake12_cert_modes/{region}/{mode}/tls_results_{region}_composite_{mode}_raw.csv"
    )


def trimmed_mean(values: list[float], trim_upper_fraction: float = 0.3) -> float:
    if not values:
        raise ValueError("cannot aggregate an empty sample set")
    ordered = sorted(values)
    keep = max(1, int(len(ordered) * (1.0 - trim_upper_fraction)))
    return statistics.fmean(ordered[:keep])


def load_temporal_means(
    start_run: int, end_run: int, trim_upper_fraction: float
) -> tuple[dict[tuple[str, str, str], float], int]:
    samples: dict[tuple[str, str, str], list[float]] = defaultdict(list)
    raw_count = 0
    for region in REGIONS:
        for mode in MODES:
            for path in (base_raw_path(region, mode), shake_raw_path(region, mode)):
                if not path.exists():
                    raise FileNotFoundError(path)
                with path.open(newline="", encoding="utf-8") as handle:
                    for row in csv.DictReader(handle):
                        if row.get("status") != "OK" or row.get("condition") != "loss_0pct":
                            continue
                        run = int(row["run"])
                        if start_run <= run <= end_run:
                            samples[(region, mode, row["algorithm"])].append(float(row["elapsed_ms"]))
                            raw_count += 1
    expected_samples = end_run - start_run + 1
    incomplete = {key: len(values) for key, values in samples.items() if len(values) != expected_samples}
    if incomplete:
        preview = list(sorted(incomplete.items()))[:5]
        raise ValueError(f"incomplete temporal partitions: {preview}")
    means = {key: trimmed_mean(values, trim_upper_fraction) for key, values in samples.items()}
    expected_keys = len(REGIONS) * len(MODES) * 98
    if len(means) != expected_keys:
        raise ValueError(f"expected {expected_keys} algorithm contexts, got {len(means)}")
    return means, raw_count


def apply_means(episodes: list[Episode], means: dict[tuple[str, str, str], float]) -> list[Episode]:
    output: list[Episode] = []
    for episode in episodes:
        region = episode.region.lower()
        mode_label = episode.certificate_mode.lower()
        mode = mode_label if mode_label == "root_direct" else f"chain{mode_label}"
        candidates = []
        for candidate in episode.candidates:
            algorithm = str(candidate["algorithm"])
            key = (region, mode, algorithm)
            if key not in means:
                raise KeyError(f"missing temporal mean: {key}")
            candidates.append({**candidate, "tls_ms": means[key]})
        deterministic = next(
            candidate for candidate in candidates if candidate["algorithm"] == episode.deterministic_algorithm
        )
        output.append(
            replace(
                episode,
                candidates=tuple(candidates),
                deterministic_tls_ms=float(deterministic["tls_ms"]),
            )
        )
    return output


def run(args: argparse.Namespace) -> dict[str, object]:
    base_episodes = build_episodes(read_rows(args.profile), args.bandwidth_mbps, args.window_size_bytes)
    train_means, train_raw = load_temporal_means(1, 30, args.trim_upper_fraction)
    validation_means, validation_raw = load_temporal_means(31, 40, args.trim_upper_fraction)
    fit_means, fit_raw = load_temporal_means(1, 40, args.trim_upper_fraction)
    test_means, test_raw = load_temporal_means(41, 50, args.trim_upper_fraction)
    training = apply_means(base_episodes, train_means)
    validation = apply_means(base_episodes, validation_means)
    fitting = apply_means(base_episodes, fit_means)
    testing = apply_means(base_episodes, test_means)

    bins, action_step, searches = select_hyperparameters(training, validation)
    model = train(fitting, bins, action_step)
    rows = evaluate(model, testing, 0, "test")
    summary = summarize(rows, len(base_episodes))
    summary.update(
        {
            "method": "temporal 60/20/20 split within every region/mode/algorithm context",
            "run_split": {"train": "1-30", "validation": "31-40", "final_fit": "1-40", "test": "41-50"},
            "raw_rows": {"train": train_raw, "validation": validation_raw, "final_fit": fit_raw, "test": test_raw},
            "trim_upper_fraction_within_each_partition": args.trim_upper_fraction,
            "selected_bins": bins,
            "selected_action_step": action_step,
            "bandwidth_mbps": args.bandwidth_mbps,
            "window_size_bytes": args.window_size_bytes,
            "deterministic_baseline": "contextual_signature_selector.selector.score_row (unchanged)",
            "reward": "(deterministic_tls_ms - rl_tls_ms) / deterministic_tls_ms",
            "loss_filter": "only loss_0pct",
            "note": "final metrics use only raw runs 41-50; each partition independently removes its slowest 30%",
        }
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(args.output_dir / "test_evaluation.csv", rows)
    write_csv(args.output_dir / "validation_search.csv", searches)
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
    parser.add_argument("--trim-upper-fraction", type=float, default=0.3)
    return parser.parse_args()


def main() -> int:
    summary = run(parse_args())
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
