#!/usr/bin/env python3
"""Auditable CTI-to-PQC policy rules.

The module deliberately does not ask a model to decide whether an algorithm is
safe.  It converts structured evidence into allow/caution/block using fixed,
testable rules, then masks candidates before either TLS selector runs.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping


STATUS_RANK = {"allow": 0, "caution": 1, "block": 2}

SOURCE_STRENGTH = {
    "unknown": 0,
    "unverified": 1,
    "research_group": 2,
    "vendor": 2,
    "peer_reviewed": 3,
    "national_cert": 3,
    "standards_authority": 4,
}

EVIDENCE_STRENGTH = {
    "unverified": 0,
    "single_report": 1,
    "peer_reviewed_analysis": 2,
    "independently_reproduced": 3,
    "multiple_independent_reproductions": 4,
    "official_decision": 4,
}

HIGH_IMPACT = {
    "below_required_security_level",
    "existential_forgery",
    "key_recovery",
}

ATTACK_MATURITY = {"theoretical", "reduced_margin", "practical"}
IMPACTS = {"none", "security_margin_reduced", *HIGH_IMPACT}
DISPOSITIONS = {"none", "under_review", "deprecated", "withdrawn", "disallowed"}

SCHEME_RULES: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("mldsa", "ml_dsa", ("lattice",)),
    ("falcon", "falcon", ("lattice",)),
    ("hawk", "hawk", ("lattice",)),
    ("mayo", "mayo", ("multivariate",)),
    ("snova", "snova", ("multivariate",)),
    ("qruov", "qr_uov", ("multivariate",)),
    ("ov", "uov", ("multivariate",)),
    ("slhdsa", "slh_dsa", ("hash_based",)),
    ("faest", "faest", ("mpc_in_the_head", "symmetric")),
    ("mqom", "mqom", ("mpc_in_the_head", "multivariate")),
    ("sdith", "sdith", ("mpc_in_the_head", "code_based")),
    ("rsa", "rsa", ("integer_factorization",)),
    ("p256", "ecdsa", ("elliptic_curve_discrete_log",)),
    ("p384", "ecdsa", ("elliptic_curve_discrete_log",)),
    ("p521", "ecdsa", ("elliptic_curve_discrete_log",)),
)


class CTIPolicyError(ValueError):
    """Raised when a CTI feed does not follow the expected policy schema."""


@dataclass(frozen=True)
class AlgorithmIdentity:
    algorithm: str
    scheme: str
    assumptions: tuple[str, ...]


@dataclass(frozen=True)
class CandidateAssessment:
    algorithm: str
    status: str
    matched_event_ids: tuple[str, ...]
    reasons: tuple[str, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "algorithm": self.algorithm,
            "status": self.status,
            "matched_event_ids": list(self.matched_event_ids),
            "reasons": list(self.reasons),
        }


@dataclass(frozen=True)
class FilterResult:
    eligible: tuple[Mapping[str, Any], ...]
    assessments: tuple[CandidateAssessment, ...]
    selection_tier: str

    def report(self) -> dict[str, Any]:
        counts = {status: 0 for status in STATUS_RANK}
        for assessment in self.assessments:
            counts[assessment.status] += 1
        return {
            "selection_tier": self.selection_tier,
            "candidate_count_before_cti": len(self.assessments),
            "candidate_count_after_cti": len(self.eligible),
            "status_counts": counts,
            "assessments": [item.to_json() for item in self.assessments],
        }


def normalize_name(value: str) -> str:
    return "".join(character for character in value.lower() if character.isalnum())


def classify_algorithm(algorithm: str) -> AlgorithmIdentity:
    normalized = normalize_name(algorithm)
    for prefix, scheme, assumptions in SCHEME_RULES:
        if normalized.startswith(prefix):
            return AlgorithmIdentity(algorithm, scheme, assumptions)
    return AlgorithmIdentity(algorithm, normalized, ())


def parse_time(value: str | datetime | None) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def load_feed(path: Path) -> dict[str, Any]:
    feed = json.loads(path.read_text(encoding="utf-8"))
    if feed.get("schema") != "pqc-cti-feed.v1":
        raise CTIPolicyError("CTI feed schema must be pqc-cti-feed.v1")
    if not isinstance(feed.get("events"), list):
        raise CTIPolicyError("CTI feed events must be a list")
    for event in feed["events"]:
        if not isinstance(event, Mapping):
            raise CTIPolicyError("every CTI event must be an object")
        validate_event(event)
    return feed


def event_is_active(event: Mapping[str, Any], at: datetime) -> bool:
    if event.get("active", True) is False:
        return False
    valid_from = parse_time(event.get("valid_from") or event.get("published_at"))
    expires_at = parse_time(event.get("expires_at"))
    return (valid_from is None or valid_from <= at) and (expires_at is None or at < expires_at)


def classify_event(event: Mapping[str, Any]) -> tuple[str, str]:
    """Map one structured item to a status using explicit policy thresholds."""
    validate_event(event)
    source = event.get("source") or {}
    source_type = source.get("type", "unknown") if isinstance(source, Mapping) else "unknown"
    source_strength = SOURCE_STRENGTH.get(str(source_type), 0)
    evidence = str(event.get("evidence", "unverified"))
    evidence_strength = EVIDENCE_STRENGTH.get(evidence, 0)
    maturity = str(event.get("attack_maturity", "theoretical"))
    impact = str(event.get("impact", "none"))
    disposition = str(event.get("disposition", "none"))

    if (
        disposition in {"withdrawn", "disallowed"}
        and source_strength >= 4
        and evidence == "official_decision"
    ):
        return "block", "authoritative withdrawal or disallow decision"

    if (
        impact in HIGH_IMPACT
        and maturity == "practical"
        and evidence_strength >= 3
        and source_strength >= 2
    ):
        return "block", "practical high-impact attack with independently verified evidence"

    if (
        impact == "below_required_security_level"
        and evidence_strength >= 3
        and source_strength >= 2
    ):
        return "block", "verified security level is below the required policy level"

    if (
        disposition in {"under_review", "deprecated"}
        and source_strength >= 3
        and evidence == "official_decision"
    ):
        return "caution", "credible authority placed the algorithm under review or deprecation"

    if (
        (maturity in {"reduced_margin", "practical"} or impact != "none")
        and evidence_strength >= 1
        and source_strength >= 2
    ):
        return "caution", "credible but not block-level evidence requires review"

    return "allow", "evidence does not meet the caution or block threshold"


def validate_event(event: Mapping[str, Any]) -> None:
    event_id = event.get("id")
    if not isinstance(event_id, str) or not event_id.strip():
        raise CTIPolicyError("every CTI event needs a non-empty id")
    source = event.get("source")
    if not isinstance(source, Mapping) or source.get("type") not in SOURCE_STRENGTH:
        raise CTIPolicyError(f"event {event_id} has an unsupported source type")
    if event.get("evidence") not in EVIDENCE_STRENGTH:
        raise CTIPolicyError(f"event {event_id} has an unsupported evidence level")
    if event.get("attack_maturity") not in ATTACK_MATURITY:
        raise CTIPolicyError(f"event {event_id} has an unsupported attack maturity")
    if event.get("impact") not in IMPACTS:
        raise CTIPolicyError(f"event {event_id} has an unsupported impact")
    if event.get("disposition", "none") not in DISPOSITIONS:
        raise CTIPolicyError(f"event {event_id} has an unsupported disposition")
    if event.get("confidence") is not None:
        try:
            confidence = float(event["confidence"])
        except (TypeError, ValueError) as error:
            raise CTIPolicyError(f"event {event_id} confidence must be numeric") from error
        if not 0.0 <= confidence <= 100.0:
            raise CTIPolicyError(f"event {event_id} confidence must be between 0 and 100")
    target = event.get("target")
    if not isinstance(target, Mapping) or target.get("scope") not in {"algorithm", "scheme", "assumption", "all"}:
        raise CTIPolicyError(f"event {event_id} has an unsupported target")
    values = target.get("values")
    if values is None:
        values = [target.get("value")]
    if not isinstance(values, list) or not values or any(not isinstance(value, str) or not value for value in values):
        raise CTIPolicyError(f"event {event_id} target needs a non-empty value or values")
    for field in ("published_at", "valid_from", "expires_at"):
        try:
            parse_time(event.get(field))
        except (TypeError, ValueError) as error:
            raise CTIPolicyError(f"event {event_id} has an invalid {field}") from error


def candidate_identities(candidate: Mapping[str, Any]) -> tuple[AlgorithmIdentity, ...]:
    names: list[str] = []
    for field in ("pqc_algorithm", "classical_algorithm"):
        value = candidate.get(field)
        if value:
            names.append(str(value))
    if not names and candidate.get("algorithm"):
        names.append(str(candidate["algorithm"]))
    return tuple(classify_algorithm(name) for name in dict.fromkeys(names))


def event_matches_candidate(event: Mapping[str, Any], candidate: Mapping[str, Any]) -> bool:
    target = event.get("target") or {}
    if not isinstance(target, Mapping):
        raise CTIPolicyError(f"event {event.get('id', '<unknown>')} target must be an object")
    scope = str(target.get("scope", "algorithm"))
    raw_values = target.get("values")
    if raw_values is None:
        raw_values = [target.get("value")]
    if not isinstance(raw_values, list) or any(value is None for value in raw_values):
        raise CTIPolicyError(f"event {event.get('id', '<unknown>')} target needs value or values")
    values = {normalize_name(str(value)) for value in raw_values}
    identities = candidate_identities(candidate)

    if scope == "all":
        return True
    if scope == "algorithm":
        names = {normalize_name(str(candidate.get("algorithm", "")))}
        names.update(normalize_name(identity.algorithm) for identity in identities)
        return bool(values & names)
    if scope == "scheme":
        return bool(values & {normalize_name(identity.scheme) for identity in identities})
    if scope == "assumption":
        assumptions = {
            normalize_name(assumption)
            for identity in identities
            for assumption in identity.assumptions
        }
        return bool(values & assumptions)
    raise CTIPolicyError(f"unsupported CTI target scope: {scope}")


def assess_candidate(
    candidate: Mapping[str, Any],
    feed: Mapping[str, Any],
    at: str | datetime | None = None,
) -> CandidateAssessment:
    now = parse_time(at) or datetime.now(timezone.utc)
    matches: list[tuple[str, str, str]] = []
    for event in feed.get("events", []):
        if not isinstance(event, Mapping):
            raise CTIPolicyError("every CTI event must be an object")
        if not event_is_active(event, now) or not event_matches_candidate(event, candidate):
            continue
        status, reason = classify_event(event)
        matches.append((str(event.get("id", "missing-id")), status, reason))

    if matches:
        final_status = max((status for _, status, _ in matches), key=STATUS_RANK.__getitem__)
    else:
        final_status = "allow"
    return CandidateAssessment(
        algorithm=str(candidate.get("algorithm", candidate.get("pqc_algorithm", "unknown"))),
        status=final_status,
        matched_event_ids=tuple(event_id for event_id, _, _ in matches),
        reasons=tuple(f"{event_id}: {reason}" for event_id, _, reason in matches),
    )


def filter_candidates(
    candidates: Iterable[Mapping[str, Any]],
    feed: Mapping[str, Any],
    at: str | datetime | None = None,
    allow_caution_fallback: bool = True,
) -> FilterResult:
    rows = tuple(candidates)
    assessments = tuple(assess_candidate(row, feed, at) for row in rows)
    allowed = tuple(row for row, result in zip(rows, assessments) if result.status == "allow")
    caution = tuple(row for row, result in zip(rows, assessments) if result.status == "caution")

    if allowed:
        return FilterResult(allowed, assessments, "allow")
    if caution and allow_caution_fallback:
        return FilterResult(caution, assessments, "caution-fallback")
    return FilterResult((), assessments, "none")
