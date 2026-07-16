from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ControlError(Exception):
    code: str
    message: str
    exit_code: int = 1
    details: dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        return self.message

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "status": "error",
            "error": {
                "code": self.code,
                "message": self.message,
            },
        }

        if self.details:
            payload["error"]["details"] = self.details

        return payload
