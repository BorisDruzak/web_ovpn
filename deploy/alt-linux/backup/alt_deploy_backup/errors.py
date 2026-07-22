from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class BackupError(Exception):
    code: str
    message: str
    exit_code: int = 1
    details: dict[str, object] = field(default_factory=dict)

    def __str__(self) -> str:
        return self.message

    def to_dict(self) -> dict[str, object]:
        error: dict[str, object] = {
            "code": self.code,
            "message": self.message,
        }
        if self.details:
            error["details"] = dict(self.details)
        return {"status": "error", "error": error}
