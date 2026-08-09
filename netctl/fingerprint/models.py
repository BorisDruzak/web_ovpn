from __future__ import annotations

from dataclasses import dataclass


FINGERPRINT_VERSION = "fingerprint-v2"
SUPPORTED_DEVICE_TYPES = frozenset(
    {"pc", "phone", "server", "network", "camera", "printer", "noise", "unknown"}
)


@dataclass(frozen=True, slots=True)
class FingerprintEvidence:
    provider: str
    signal: str
    candidate_type: str
    weight: int
    summary: str

    def __post_init__(self) -> None:
        if self.candidate_type not in SUPPORTED_DEVICE_TYPES - {"unknown"}:
            raise ValueError("unsupported fingerprint candidate type")
        if type(self.weight) is not int or not 1 <= self.weight <= 100:
            raise ValueError("fingerprint evidence weight must be between 1 and 100")
        if not all(
            isinstance(value, str) and value.strip()
            for value in (self.provider, self.signal, self.summary)
        ):
            raise ValueError("fingerprint evidence text must be non-empty")


@dataclass(frozen=True, slots=True)
class AssetFingerprint:
    device_type: str
    confidence: int
    evidence: tuple[FingerprintEvidence, ...]
    alternatives: tuple[dict[str, object], ...]
    version: str = FINGERPRINT_VERSION

    def __post_init__(self) -> None:
        if self.device_type not in SUPPORTED_DEVICE_TYPES:
            raise ValueError("unsupported fingerprint device type")
        if type(self.confidence) is not int or not 0 <= self.confidence <= 100:
            raise ValueError("fingerprint confidence must be between 0 and 100")
        if self.version != FINGERPRINT_VERSION:
            raise ValueError("unsupported fingerprint version")
