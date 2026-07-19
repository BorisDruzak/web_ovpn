from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .outcomes import SnmpOutcome


@dataclass(frozen=True)
class SnmpVarBind:
    oid: tuple[int, ...]
    value_type: str
    value: int | str | bytes


@dataclass(frozen=True)
class CapabilityResult:
    capability: str
    outcome: SnmpOutcome
    rows: tuple[SnmpVarBind, ...] = ()
    error_code: str = ""
    error_message: str = ""
    details: dict[str, Any] = field(default_factory=dict)
