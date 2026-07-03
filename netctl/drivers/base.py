from __future__ import annotations

from typing import Any


class NetworkDriver:
    def __init__(self, source: dict[str, Any], secrets: dict[str, str]) -> None:
        self.source = source
        self.secrets = secrets

    def test(self) -> dict[str, Any]:
        raise NotImplementedError

    def collect(self, include_connections: bool = False) -> dict[str, Any]:
        raise NotImplementedError
