#!/usr/bin/env python3
"""Replay four-family server certificate inventories on measured TLS results.

The replay does not invent TLS latency.  Static and contextual choices are made
from the same four-certificate inventory, then their latency is looked up in the
existing measured profile.
"""

from __future__ import annotations

import argparse
import csv
import itertools
import json
import statistics
from collections import defaultdict
from pathlib import Path

from contextual_signature_selector.selector import (
    NetworkContext,
    SelectorConstants,
    score_row,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PROFILE = ROOT / "outputs/analysis/composite_chain_length_overhead/composite_chain_detail.csv"
DEFAULT_CLIENT_ORDER = ROOT / "outputs/analysis/contextual_signature_selector/default_clienthello/default_signature_algorithms_order.csv"
DEFAULT_OUT = ROOT / "outputs/analysis/contextual_signature_selector/inventory_replay_client_order"

# One certificate is drawn from each family.  Algorithms are kept at the same
# security level, and the classical component is kept identical within a set.
FAMILY_CANDIDATES = {
    "L1": {
        "lattice": ("falcon512", "hawk512"),
        "multivariate": ("mayo1", "snova2454"),
        "mpc_symmetric": ("faest128f", "faest128s"),
        "hash_based": ("slhdsasha2128f", "slhdsasha2128s"),
    },
    "L3": {
        "lattice": ("mldsa65",),
        "multivariate": ("mayo3", "snova2455"),
        "mpc_symmetric": ("faest192f", "faest192s"),
        "hash_based": ("slhdsasha2192f", "slhdsasha2192s"),
    },
    "L5": {
        "lattice": ("falcon1024", "hawk1024", "mldsa87"),
        "multivariate": ("mayo5", "snova2965"),
        "mpc_symmetric": ("faest256f", "faest256s"),
        "hash_based": ("slhdsasha2256f", "slhdsasha2256s"),
    },
}


def read_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def inventory_products(level: str) -> list[tuple[str, ...]]:
    families = FAMILY_CANDIDATES[level]
    return list(itertools.product(*(families[name] for name in families)))


def global_static_sign_means(rows: list[dict[str, str]]) -> dict[str, float]:
    """Return the context-free crypto-speed priority used by Static.

    Static intentionally ignores region, RTT, bandwidth, and ICA.  Averaging
    the measured signing cost only removes duplicate profile rows without
    leaking context-specific TLS latency into the fixed baseline.
    """
    values: dict[str, list[float]] = defaultdict(list)
    for row in rows:
        if row["level"] not in FAMILY_CANDIDATES:
            continue
        values[row["algorithm"]].append(float(row["actual_sign_ms"]))
    return {algorithm: statistics.fmean(samples) for algorithm, samples in values.items()}


def read_client_order(path: Path) -> dict[str, int]:
    with path.open(newline="") as f:
        rows = list(csv.DictReader(f))
    return {row["algorithm"]: int(row["position"]) for row in rows}


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def replay(
    rows: list[dict[str, str]],
    bandwidth_mbps: float,
    window_size_bytes: int,
    client_order: dict[str, int] | None = None,
    static_policy: str = "client-order",
) -> list[dict[str, object]]:
    static_sign_mean = global_static_sign_means(rows)
    by_context: dict[tuple[str, str, str, str], dict[str, dict[str, str]]] = defaultdict(dict)
    for row in rows:
        if row["level"] not in FAMILY_CANDIDATES:
            continue
        key = (row["region"], row["certificate_mode"], row["level"], row["classical_algorithm"])
        by_context[key][row["pqc_algorithm"]] = row

    constants = SelectorConstants()
    results: list[dict[str, object]] = []
    for (region, mode, level, classical), available in sorted(by_context.items()):
        for inventory in inventory_products(level):
            if not all(algorithm in available for algorithm in inventory):
                continue
            inventory_rows = [available[algorithm] for algorithm in inventory]
            rtt_ms = statistics.median(float(row["rtt_ms"]) for row in inventory_rows)
            context = NetworkContext(
                rtt_ms=rtt_ms,
                bandwidth_mbps=bandwidth_mbps,
                window_size_bytes=window_size_bytes,
                base_ms=rtt_ms,
            )
            scored = [(score_row(row, context, constants), row) for row in inventory_rows]
            deterministic_score, deterministic_row = min(
                scored,
                key=lambda pair: (float(pair[0]["estimated_tls_ms"]), pair[1]["algorithm"]),
            )
            if static_policy == "client-order":
                if client_order is None or not all(row["algorithm"] in client_order for row in inventory_rows):
                    continue
                static_row = min(
                    inventory_rows,
                    key=lambda row: (client_order[row["algorithm"]], row["algorithm"]),
                )
                static_priority = client_order[static_row["algorithm"]]
            elif static_policy == "sign-time":
                static_row = min(
                    inventory_rows,
                    key=lambda row: (static_sign_mean[row["algorithm"]], row["algorithm"]),
                )
                static_priority = static_sign_mean[static_row["algorithm"]]
            else:
                raise ValueError(f"unknown static policy: {static_policy}")
            static_ms = float(static_row["tls_handshake_time_ms"])
            deterministic_ms = float(deterministic_row["tls_handshake_time_ms"])
            improvement_ms = static_ms - deterministic_ms
            improvement_percent = 100.0 * improvement_ms / static_ms
            full_inventory = [row["algorithm"] for row in inventory_rows]
            results.append(
                {
                    "region": region,
                    "certificate_mode": mode,
                    "security_level": level,
                    "classical_algorithm": classical,
                    "rtt_ms": round(rtt_ms, 6),
                    "bandwidth_mbps": bandwidth_mbps,
                    "window_size_bytes": window_size_bytes,
                    "inventory": ";".join(full_inventory),
                    "falcon_available": int(any("falcon" in name for name in inventory)),
                    "static_policy": static_policy,
                    "static_algorithm": static_row["algorithm"],
                    "static_priority": round(float(static_priority), 6),
                    "deterministic_algorithm": deterministic_row["algorithm"],
                    "selection_changed": int(static_row["algorithm"] != deterministic_row["algorithm"]),
                    "static_tls_ms": round(static_ms, 6),
                    "deterministic_tls_ms": round(deterministic_ms, 6),
                    "improvement_ms": round(improvement_ms, 6),
                    "improvement_percent": round(improvement_percent, 6),
                    "deterministic_estimated_tls_ms": round(float(deterministic_score["estimated_tls_ms"]), 6),
                }
            )
    return results


def summarize(rows: list[dict[str, object]]) -> tuple[list[dict[str, object]], dict[str, object]]:
    grouped: dict[tuple[str, str, str], list[dict[str, object]]] = defaultdict(list)
    for row in rows:
        grouped[(str(row["region"]), str(row["certificate_mode"]), str(row["security_level"]))].append(row)

    summary_rows: list[dict[str, object]] = []
    for (region, mode, level), group in sorted(grouped.items()):
        percentages = [float(row["improvement_percent"]) for row in group]
        milliseconds = [float(row["improvement_ms"]) for row in group]
        summary_rows.append(
            {
                "region": region,
                "certificate_mode": mode,
                "security_level": level,
                "inventory_count": len(group),
                "mean_improvement_percent": round(statistics.fmean(percentages), 6),
                "median_improvement_percent": round(statistics.median(percentages), 6),
                "mean_improvement_ms": round(statistics.fmean(milliseconds), 6),
                "selection_changed_count": sum(int(row["selection_changed"]) for row in group),
                "positive_improvement_count": sum(float(row["improvement_ms"]) > 0 for row in group),
                "zero_improvement_count": sum(float(row["improvement_ms"]) == 0 for row in group),
                "negative_improvement_count": sum(float(row["improvement_ms"]) < 0 for row in group),
            }
        )

    all_percentages = [float(row["improvement_percent"]) for row in rows]
    all_ms = [float(row["improvement_ms"]) for row in rows]
    overall = {
        "replay_rows": len(rows),
        "original_contexts": len(
            {
                (row["region"], row["certificate_mode"], row["security_level"], row["classical_algorithm"])
                for row in rows
            }
        ),
        "mean_improvement_percent": statistics.fmean(all_percentages) if rows else 0.0,
        "median_improvement_percent": statistics.median(all_percentages) if rows else 0.0,
        "mean_improvement_ms": statistics.fmean(all_ms) if rows else 0.0,
        "selection_changed_count": sum(int(row["selection_changed"]) for row in rows),
        "positive_improvement_count": sum(float(row["improvement_ms"]) > 0 for row in rows),
        "zero_improvement_count": sum(float(row["improvement_ms"]) == 0 for row in rows),
        "negative_improvement_count": sum(float(row["improvement_ms"]) < 0 for row in rows),
    }
    return summary_rows, overall


def summarize_server_ica(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    grouped: dict[tuple[str, str], list[dict[str, object]]] = defaultdict(list)
    for row in rows:
        grouped[(str(row["region"]), str(row["certificate_mode"]))].append(row)
    output: list[dict[str, object]] = []
    for (region, mode), group in sorted(grouped.items()):
        percentages = [float(row["improvement_percent"]) for row in group]
        milliseconds = [float(row["improvement_ms"]) for row in group]
        output.append(
            {
                "server_region": region,
                "certificate_mode": mode,
                "inventory_count": len(group),
                "mean_improvement_percent": round(statistics.fmean(percentages), 6),
                "median_improvement_percent": round(statistics.median(percentages), 6),
                "mean_improvement_ms": round(statistics.fmean(milliseconds), 6),
                "selection_changed_count": sum(int(row["selection_changed"]) for row in group),
                "positive_improvement_count": sum(float(row["improvement_ms"]) > 0 for row in group),
                "zero_improvement_count": sum(float(row["improvement_ms"]) == 0 for row in group),
                "negative_improvement_count": sum(float(row["improvement_ms"]) < 0 for row in group),
            }
        )
    return output


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--client-order", type=Path, default=DEFAULT_CLIENT_ORDER)
    parser.add_argument("--static-policy", choices=["client-order", "sign-time"], default="client-order")
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--bandwidth-mbps", type=float, default=1000.0)
    parser.add_argument("--window-size-bytes", type=int, default=16384)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    rows = read_rows(args.profile)
    client_order = read_client_order(args.client_order) if args.static_policy == "client-order" else None
    details = replay(rows, args.bandwidth_mbps, args.window_size_bytes, client_order, args.static_policy)
    summaries, overall = summarize(details)
    overall["static_policy"] = args.static_policy
    if args.static_policy == "client-order":
        overall["client_order_file"] = str(args.client_order)
    server_ica = summarize_server_ica(details)
    write_csv(args.out_dir / "inventory_replay_detail.csv", details)
    write_csv(args.out_dir / "inventory_replay_by_region_ica.csv", summaries)
    write_csv(args.out_dir / "inventory_replay_by_server_ica.csv", server_ica)
    (args.out_dir / "inventory_replay_overall.json").write_text(
        json.dumps(overall, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(overall, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
