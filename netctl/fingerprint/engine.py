from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable

from .models import AssetFingerprint, FingerprintEvidence


_TIER_RANK = {"weak": 0, "medium": 1, "strong": 2}


def _tier(weight: int) -> str:
    if weight >= 80:
        return "strong"
    if weight >= 30:
        return "medium"
    return "weak"


def _evidence_order(item: FingerprintEvidence) -> tuple[object, ...]:
    return (
        -_TIER_RANK[_tier(item.weight)],
        -item.weight,
        item.candidate_type,
        item.provider,
        item.signal,
        item.summary,
    )


def classify_evidence(
    evidence: Iterable[FingerprintEvidence],
) -> AssetFingerprint:
    """Classify typed evidence with deterministic tier precedence and score gates."""
    by_signal: dict[tuple[str, str, str], FingerprintEvidence] = {}
    for item in evidence:
        key = (item.provider, item.signal, item.candidate_type)
        current = by_signal.get(key)
        if current is None or (
            -item.weight,
            len(item.summary),
            item.summary,
        ) < (
            -current.weight,
            len(current.summary),
            current.summary,
        ):
            by_signal[key] = item
    normalized = tuple(sorted(by_signal.values(), key=_evidence_order))
    if not normalized:
        return AssetFingerprint("unknown", 0, (), ())

    scores: dict[str, int] = defaultdict(int)
    candidate_tiers: dict[str, int] = {}
    for item in normalized:
        scores[item.candidate_type] += item.weight
        candidate_tiers[item.candidate_type] = max(
            candidate_tiers.get(item.candidate_type, -1),
            _TIER_RANK[_tier(item.weight)],
        )

    ranked = sorted(
        scores,
        key=lambda candidate: (
            -candidate_tiers[candidate],
            -min(100, scores[candidate]),
            candidate,
        ),
    )
    top_type = ranked[0]
    top_tier = candidate_tiers[top_type]
    top_score = min(100, scores[top_type])
    same_tier_scores = [
        min(100, scores[candidate])
        for candidate in ranked[1:]
        if candidate_tiers[candidate] == top_tier
    ]
    second_score = max(same_tier_scores, default=0)
    decided = top_score >= 60 and top_score - second_score >= 15
    alternatives = () if decided else tuple(
        {"device_type": candidate, "score": min(100, scores[candidate])}
        for candidate in ranked
    )
    return AssetFingerprint(
        top_type if decided else "unknown",
        top_score,
        normalized,
        alternatives,
    )
