#!/usr/bin/env python3
"""Prototype context-aware TLS signature/certificate selector.

This prototype consumes the offline candidate profile already produced by the
TLS experiments and scores every remaining candidate under a supplied network
context. It is intentionally simple and transparent so the calculation can be
shown in meetings before wiring it into a live TLS server.
"""

from __future__ import annotations

import argparse
import csv
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PROFILE = ROOT / "outputs/analysis/composite_chain_length_overhead/composite_chain_detail.csv"
DEFAULT_OUT = ROOT / "outputs/analysis/contextual_signature_selector"


@dataclass(frozen=True)
class NetworkContext:
    rtt_ms: float
    bandwidth_mbps: float
    window_size_bytes: int
    base_ms: float


@dataclass(frozen=True)
class SelectorConstants:
    server_hello_keyshare_bytes: int = 160
    encrypted_extensions_bytes: int = 80
    finished_bytes: int = 64
    record_overhead_bytes: int = 22
    tls_plaintext_fragment_bytes: int = 16384
    bio_buffer_bytes: int = 4096
    handshake_header_bytes: int = 4
    certificate_context_length_bytes: int = 1
    certificate_list_length_bytes: int = 3
    certificate_entry_overhead_bytes: int = 5


def as_float(value: str, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def as_int(value: str, default: int = 0) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def load_client_algorithms(path: Path | None) -> set[str] | None:
    if path is None:
        return None
    algorithms: set[str] = set()
    with path.open(newline="") as f:
        sample = f.read(2048)
        f.seek(0)
        if "," in sample:
            reader = csv.DictReader(f)
            for row in reader:
                value = row.get("algorithm") or row.get("signature_algorithm") or row.get("name")
                if value:
                    algorithms.add(value.strip())
        else:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    algorithms.add(line)
    return algorithms


def level_allowed(level: str, minimum: str | None) -> bool:
    if minimum is None:
        return True
    order = {"L1": 1, "L2": 2, "L3": 3, "L4": 4, "L5": 5}
    return order.get(level, 0) >= order.get(minimum, 0)


def record_overhead(server_flight_without_records: int, per_record_overhead: int) -> int:
    if server_flight_without_records <= 0:
        return 0
    # TLS plaintext fragments are at most 16 KiB, so estimate one record
    # overhead per fragment. This is a scoring approximation, not wire replay.
    return math.ceil(server_flight_without_records / 16384) * per_record_overhead


def certificate_tail_state(chain_bytes: int, sent_cert_count: int, const: SelectorConstants) -> tuple[int, int, int, int]:
    """Return I_tail, tail bytes, Certificate start offset, and message bytes.

    ServerHello(+KeyShare) is explicitly treated as a flush boundary because
    TLS switches to encrypted handshake records after ServerHello. Within the
    encrypted flight, EncryptedExtensions precedes Certificate, so its bytes
    and all TLS handshake/Certificate framing move the Certificate start offset.
    """
    fragment = max(1, const.tls_plaintext_fragment_bytes)
    bio_buffer = max(1, const.bio_buffer_bytes)
    encrypted_extensions_message_bytes = const.handshake_header_bytes + const.encrypted_extensions_bytes
    certificate_start_offset = encrypted_extensions_message_bytes % fragment
    certificate_message_bytes = (
        const.handshake_header_bytes
        + const.certificate_context_length_bytes
        + const.certificate_list_length_bytes
        + max(0, chain_bytes)
        + max(1, sent_cert_count) * const.certificate_entry_overhead_bytes
    )
    certificate_end = certificate_start_offset + certificate_message_bytes
    if certificate_end <= fragment:
        return 0, 0, certificate_start_offset, certificate_message_bytes
    tail_bytes = certificate_end % fragment
    if tail_bytes == 0:
        return 0, 0, certificate_start_offset, certificate_message_bytes
    return (1 if tail_bytes < bio_buffer else 0), tail_bytes, certificate_start_offset, certificate_message_bytes


def score_row(row: dict[str, str], ctx: NetworkContext, const: SelectorConstants) -> dict[str, str | float | int]:
    chain_bytes = as_int(row["actual_chain_der_size_bytes"])
    signature_bytes = as_int(row["signature_size_bytes"])
    sent_cert_count = max(1, as_int(row["sent_cert_count"], 1))
    sign_ms = as_float(row["actual_sign_ms"])
    verify_one_ms = as_float(row["actual_verify_ms"])
    verify_chain_ms = verify_one_ms * sent_cert_count

    flight_without_records = (
        const.server_hello_keyshare_bytes
        + const.encrypted_extensions_bytes
        + chain_bytes
        + signature_bytes
        + const.finished_bytes
    )
    overhead = record_overhead(flight_without_records, const.record_overhead_bytes)
    server_flight_bytes = flight_without_records + overhead

    window_size = max(1, ctx.window_size_bytes)
    extra_rounds = max(0, math.ceil(server_flight_bytes / window_size) - 1)
    serialization_ms = (server_flight_bytes * 8.0) / (ctx.bandwidth_mbps * 1_000_000.0) * 1000.0
    network_penalty_ms = extra_rounds * ctx.rtt_ms + serialization_ms
    i_tail, certificate_tail_bytes, certificate_start_offset, certificate_message_bytes = certificate_tail_state(
        chain_bytes, sent_cert_count, const
    )
    tail_delay_ms = sign_ms if i_tail else 0.0

    # If the Certificate tail is buffered until CertificateVerify, client-side
    # verification cannot start early, so do not hide verification with overlap.
    # Otherwise, if the flight fits in the current window, approximate overlap.
    overlap_ms = min(sign_ms, verify_chain_ms) if extra_rounds == 0 and not i_tail else 0.0
    estimated_tls_ms = ctx.base_ms + sign_ms + network_penalty_ms + tail_delay_ms + verify_chain_ms - overlap_ms

    out: dict[str, str | float | int] = {
        "algorithm": row["algorithm"],
        "level": row["level"],
        "pqc_algorithm": row["pqc_algorithm"],
        "classical_algorithm": row["classical_algorithm"],
        "certificate_mode": row["certificate_mode"],
        "sent_cert_count": sent_cert_count,
        "chain_bytes": chain_bytes,
        "signature_bytes": signature_bytes,
        "server_hello_keyshare_bytes": const.server_hello_keyshare_bytes,
        "server_hello_flush_boundary": 1,
        "certificate_start_offset": certificate_start_offset,
        "certificate_message_bytes": certificate_message_bytes,
        "server_flight_bytes": server_flight_bytes,
        "window_size_bytes": ctx.window_size_bytes,
        "extra_rounds": extra_rounds,
        "i_tail": i_tail,
        "certificate_tail_bytes": certificate_tail_bytes,
        "tail_delay_ms": tail_delay_ms,
        "serialization_ms": serialization_ms,
        "network_penalty_ms": network_penalty_ms,
        "sign_ms": sign_ms,
        "verify_one_ms": verify_one_ms,
        "verify_chain_ms": verify_chain_ms,
        "overlap_ms": overlap_ms,
        "estimated_tls_ms": estimated_tls_ms,
        "measured_tls_ms": as_float(row.get("tls_handshake_time_ms", "")),
    }
    return out


def iter_candidates(
    profile_path: Path,
    region: str | None,
    certificate_mode: str | None,
    minimum_level: str | None,
    client_algorithms: set[str] | None,
) -> Iterable[dict[str, str]]:
    with profile_path.open(newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if region and row["region"].lower() != region.lower():
                continue
            if certificate_mode and row["certificate_mode"].lower() != certificate_mode.lower():
                continue
            if not level_allowed(row["level"], minimum_level):
                continue
            if client_algorithms is not None and row["algorithm"] not in client_algorithms:
                continue
            yield row


def write_csv(path: Path, rows: list[dict[str, str | float | int]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "rank",
        "algorithm",
        "level",
        "pqc_algorithm",
        "classical_algorithm",
        "certificate_mode",
        "sent_cert_count",
        "chain_bytes",
        "signature_bytes",
        "server_hello_keyshare_bytes",
        "server_hello_flush_boundary",
        "certificate_start_offset",
        "certificate_message_bytes",
        "server_flight_bytes",
        "window_size_bytes",
        "extra_rounds",
        "i_tail",
        "certificate_tail_bytes",
        "tail_delay_ms",
        "serialization_ms",
        "network_penalty_ms",
        "sign_ms",
        "verify_one_ms",
        "verify_chain_ms",
        "overlap_ms",
        "estimated_tls_ms",
        "measured_tls_ms",
    ]
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for index, row in enumerate(rows, start=1):
            row = {"rank": index, **row}
            writer.writerow(row)


def write_summary(path: Path, args: argparse.Namespace, rows: list[dict[str, str | float | int]]) -> None:
    best = rows[0] if rows else None
    lines = [
        "# Contextual Signature Selector Prototype Result",
        "",
        f"- profile: `{args.profile}`",
        f"- region filter: `{args.region or 'all'}`",
        f"- certificate mode filter: `{args.certificate_mode or 'all'}`",
        f"- minimum level: `{args.minimum_level or 'none'}`",
        f"- RTT: `{args.rtt_ms}` ms",
        f"- bandwidth: `{args.bandwidth_mbps}` Mbps",
        f"- window size: `{args.window_size_bytes}` bytes",
        f"- candidates scored: `{len(rows)}`",
        "",
    ]
    if best:
        lines.extend(
            [
                "## Selected Candidate",
                "",
                f"- algorithm: `{best['algorithm']}`",
                f"- level: `{best['level']}`",
                f"- certificate mode: `{best['certificate_mode']}`",
                f"- estimated TLS: `{float(best['estimated_tls_ms']):.3f}` ms",
                f"- server flight bytes: `{best['server_flight_bytes']}`",
                f"- extra rounds: `{best['extra_rounds']}`",
                f"- I_tail: `{best['i_tail']}`",
                f"- ServerHello(+KeyShare) flush boundary: `{best['server_hello_flush_boundary']}`",
                f"- Certificate start offset: `{best['certificate_start_offset']}` bytes",
                f"- Certificate message bytes: `{best['certificate_message_bytes']}` bytes",
                f"- certificate tail bytes: `{best['certificate_tail_bytes']}`",
                f"- tail delay: `{float(best['tail_delay_ms']):.3f}` ms",
                f"- network penalty: `{float(best['network_penalty_ms']):.3f}` ms",
                f"- sign: `{float(best['sign_ms']):.3f}` ms",
                f"- verify chain: `{float(best['verify_chain_ms']):.3f}` ms",
                f"- overlap: `{float(best['overlap_ms']):.3f}` ms",
                "",
            ]
        )
    lines.extend(
        [
            "## Model",
            "",
            "- `A = C_client ∩ A_cert ∩ A_provider ∩ A_policy`",
            "- `c = { RTT, bandwidth, window_size }`",
            "- `extra_rounds = ceil(server_flight_bytes / window_size) - 1`",
            "- `I_tail = 1` when Certificate crosses a TLS record boundary and the final Certificate fragment is smaller than the BIO buffer",
            "- `tail_delay = I_tail × sign`",
            "- `serialization_time = server_flight_bytes / bandwidth`",
            "- `network_penalty = extra_rounds × RTT + serialization_time`",
            "- `estimated_tls = base + sign + network_penalty + tail_delay + verify_chain - overlap`",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Prototype context-aware TLS signature selector")
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--region", default="Seoul")
    parser.add_argument("--certificate-mode", default="1ICA")
    parser.add_argument("--minimum-level", choices=["L1", "L2", "L3", "L4", "L5"], default=None)
    parser.add_argument("--client-algorithms", type=Path, default=None)
    parser.add_argument("--rtt-ms", type=float, required=True)
    parser.add_argument("--bandwidth-mbps", type=float, required=True)
    parser.add_argument("--window-size-bytes", type=int, default=16384)
    parser.add_argument("--base-ms", type=float, default=None)
    parser.add_argument("--base-rtt-factor", type=float, default=1.0)
    parser.add_argument("--server-hello-keyshare-bytes", type=int, default=160)
    parser.add_argument("--encrypted-extensions-bytes", type=int, default=80)
    parser.add_argument("--finished-bytes", type=int, default=64)
    parser.add_argument("--record-overhead-bytes", type=int, default=22)
    parser.add_argument("--tls-plaintext-fragment-bytes", type=int, default=16384)
    parser.add_argument("--bio-buffer-bytes", type=int, default=4096)
    parser.add_argument("--top", type=int, default=20)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    client_algorithms = load_client_algorithms(args.client_algorithms)
    ctx = NetworkContext(
        rtt_ms=args.rtt_ms,
        bandwidth_mbps=args.bandwidth_mbps,
        window_size_bytes=args.window_size_bytes,
        base_ms=args.base_ms if args.base_ms is not None else args.rtt_ms * args.base_rtt_factor,
    )
    const = SelectorConstants(
        server_hello_keyshare_bytes=args.server_hello_keyshare_bytes,
        encrypted_extensions_bytes=args.encrypted_extensions_bytes,
        finished_bytes=args.finished_bytes,
        record_overhead_bytes=args.record_overhead_bytes,
        tls_plaintext_fragment_bytes=args.tls_plaintext_fragment_bytes,
        bio_buffer_bytes=args.bio_buffer_bytes,
    )
    candidates = list(
        iter_candidates(
            args.profile,
            args.region,
            args.certificate_mode,
            args.minimum_level,
            client_algorithms,
        )
    )
    scored = [score_row(row, ctx, const) for row in candidates]
    scored.sort(key=lambda r: (float(r["estimated_tls_ms"]), str(r["algorithm"])))

    level_suffix = args.minimum_level or "alllevels"
    suffix = f"{args.region or 'all'}_{args.certificate_mode or 'all'}_{level_suffix}".replace(" ", "_").lower()
    csv_path = args.out_dir / f"selector_scores_{suffix}.csv"
    md_path = args.out_dir / f"selector_summary_{suffix}.md"
    write_csv(csv_path, scored)
    write_summary(md_path, args, scored)

    if not scored:
        print(f"No candidates matched. Wrote empty scores to {csv_path}")
        return 1

    best = scored[0]
    print(f"best={best['algorithm']} estimated_tls_ms={float(best['estimated_tls_ms']):.3f}")
    print(f"scores={csv_path}")
    print(f"summary={md_path}")
    print(f"top={min(args.top, len(scored))}")
    for index, row in enumerate(scored[: args.top], start=1):
        print(
            f"{index:02d} {row['algorithm']} {row['level']} {row['certificate_mode']} "
            f"est={float(row['estimated_tls_ms']):.3f}ms "
            f"flight={row['server_flight_bytes']}B rounds={row['extra_rounds']} "
            f"I_tail={row['i_tail']} tail={row['certificate_tail_bytes']}B "
            f"sign={float(row['sign_ms']):.3f} verify_chain={float(row['verify_chain_ms']):.3f}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
