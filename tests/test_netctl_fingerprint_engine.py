from __future__ import annotations

from dataclasses import replace

import pytest


def _evidence(
    provider: str,
    signal: str,
    candidate_type: str,
    weight: int,
):
    from netctl.fingerprint.models import FingerprintEvidence

    return FingerprintEvidence(
        provider=provider,
        signal=signal,
        candidate_type=candidate_type,
        weight=weight,
        summary=f"{provider} {signal}",
    )


def test_medium_camera_signals_combine_into_a_high_confidence_result() -> None:
    """Removing cross-provider score aggregation would lose a supported camera."""
    from netctl.fingerprint.engine import classify_evidence

    result = classify_evidence(
        (
            _evidence("oui", "hikvision", "camera", 50),
            _evidence("nmap_service", "rtsp", "camera", 60),
        )
    )

    assert result.device_type == "camera"
    assert result.confidence == 100
    assert result.alternatives == ()
    assert result.version == "fingerprint-v2"


def test_strong_identity_beats_any_number_of_weak_hostname_hints() -> None:
    """Summing weak names must never overturn one authoritative switch identity."""
    from netctl.fingerprint.engine import classify_evidence

    result = classify_evidence(
        (
            _evidence("snmp", "known_switch", "network", 100),
            *tuple(
                _evidence("hostname", f"phone-{index}", "phone", 15)
                for index in range(10)
            ),
        )
    )

    assert result.device_type == "network"
    assert result.confidence == 100


def test_two_competing_strong_types_remain_unknown_with_ranked_alternatives() -> None:
    """A close strong conflict must not be hidden behind a deterministic tie-break."""
    from netctl.fingerprint.engine import classify_evidence

    result = classify_evidence(
        (
            _evidence("snmp", "known_switch", "network", 100),
            _evidence("lldp", "telephone", "phone", 90),
        )
    )

    assert result.device_type == "unknown"
    assert result.confidence == 100
    assert result.alternatives == (
        {"device_type": "network", "score": 100},
        {"device_type": "phone", "score": 90},
    )


@pytest.mark.parametrize(
    ("second_score", "expected_type"),
    [(45, "pc"), (46, "unknown")],
)
def test_selection_requires_both_the_score_floor_and_fifteen_point_lead(
    second_score: int, expected_type: str
) -> None:
    """Changing either comparison at the exact lead boundary breaks the contract."""
    from netctl.fingerprint.engine import classify_evidence

    result = classify_evidence(
        (
            _evidence("nmap_os", "windows", "pc", 40),
            _evidence("hostname", "pc-prefix", "pc", 20),
            _evidence("nmap_os", "general-purpose", "server", second_score),
        )
    )

    assert result.device_type == expected_type
    assert result.confidence == 60


def test_classification_is_deterministic_and_duplicate_evidence_is_idempotent() -> None:
    """Collector ordering and duplicate rows must not change persisted JSON or scores."""
    from netctl.fingerprint.engine import classify_evidence

    first = _evidence("nmap_os", "windows", "pc", 40)
    second = _evidence("hostname", "pc-prefix", "pc", 20)

    assert classify_evidence(
        (first, second, replace(first, summary="alternate rendering of same signal"))
    ) == classify_evidence(
        (second, first)
    )


def test_evidence_rejects_types_outside_the_fixed_public_vocabulary() -> None:
    """Provider drift must not silently create a ninth public device type."""
    with pytest.raises(ValueError, match="unsupported fingerprint candidate type"):
        _evidence("test", "unsupported", "tablet", 80)
