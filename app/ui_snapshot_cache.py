from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
import threading
import time
from typing import Any, Callable


@dataclass
class SnapshotResult:
    data: dict[str, Any]
    generated_at: datetime
    stale: bool
    errors: list[str]


@dataclass
class _Entry:
    result: SnapshotResult | None = None
    expires_at: float = 0.0
    refreshing: bool = False


class SnapshotCache:
    """A process-local, single-flight cache for sanitized read snapshots."""

    def __init__(self) -> None:
        self._condition = threading.Condition(threading.RLock())
        self._entries: dict[str, _Entry] = {}

    @staticmethod
    def _copy(result: SnapshotResult, *, stale: bool | None = None, errors: list[str] | None = None) -> SnapshotResult:
        return SnapshotResult(
            data=deepcopy(result.data),
            generated_at=result.generated_at,
            stale=result.stale if stale is None else stale,
            errors=list(result.errors if errors is None else errors),
        )

    def get(self, key: str, ttl_seconds: float, loader: Callable[[], dict[str, Any]]) -> SnapshotResult:
        with self._condition:
            entry = self._entries.setdefault(key, _Entry())
            now = time.monotonic()
            if entry.result is not None and now < entry.expires_at:
                return self._copy(entry.result)
            if entry.refreshing:
                if entry.result is not None:
                    return self._copy(entry.result, stale=True)
                while entry.refreshing:
                    self._condition.wait()
                if entry.result is not None:
                    return self._copy(entry.result)
                return SnapshotResult({}, datetime.now(timezone.utc), True, ["unavailable"])
            entry.refreshing = True

        try:
            loaded = loader()
            result = SnapshotResult(deepcopy(loaded), datetime.now(timezone.utc), False, [])
        except Exception:
            result = None

        with self._condition:
            entry = self._entries[key]
            entry.refreshing = False
            if result is not None:
                entry.result = result
                entry.expires_at = time.monotonic() + ttl_seconds
                response = self._copy(result)
            elif entry.result is not None:
                response = self._copy(entry.result, stale=True, errors=["unavailable"])
            else:
                response = SnapshotResult({}, datetime.now(timezone.utc), True, ["unavailable"])
            self._condition.notify_all()
            return response
