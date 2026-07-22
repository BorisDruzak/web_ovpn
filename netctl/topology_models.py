from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class LinkEndpoint:
    source_id: int
    port_key: str


@dataclass(frozen=True)
class LinkEvidence:
    endpoint_a: LinkEndpoint
    endpoint_b: LinkEndpoint
    evidence_type: str
    confidence: int
    observed_at: str
    intent_link_stable_id: str
    details: dict[str, Any]
