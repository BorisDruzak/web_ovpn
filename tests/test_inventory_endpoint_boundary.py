from __future__ import annotations

from pathlib import Path
from uuid import UUID

import pytest


def test_inventory_endpoint_code_has_no_agent_transport_or_direct_http() -> None:
    inventory_root = Path(__file__).resolve().parents[1] / "app" / "inventory"
    source = "\n".join(path.read_text(encoding="utf-8") for path in inventory_root.glob("*.py"))

    assert "websocket" not in source.lower()
    assert "httpx." not in source
    assert "requests." not in source
    assert "endpoint_server" not in source
    assert "pc_agent" not in source


def test_service_client_redacts_permission_failure_as_scope_denied() -> None:
    from app.endpoint_platform_client import (
        EndpointPlatformServiceClient,
        EndpointPlatformServiceScopeDenied,
    )

    with pytest.raises(EndpointPlatformServiceScopeDenied) as denied:
        EndpointPlatformServiceClient._call(lambda: (_ for _ in ()).throw(PermissionError()))

    assert str(denied.value) == "endpoint_platform_scope_denied"


def test_adapter_reads_all_known_profiles_without_fabricating_missing_profile() -> None:
    from app.endpoint_context_adapter import EndpointContextAdapter

    device_id = UUID("11111111-1111-1111-1111-111111111111")

    class Client:
        def close(self) -> None:
            return None

        def get_latest_context(self, actual_device_id: UUID, profile: str):
            assert actual_device_id == device_id
            if profile == "baseline_v1":
                return {
                    "id": "snapshot-1",
                    "profile": profile,
                    "collected_at": "2026-09-18T10:00:00Z",
                    "semantic_hash": "hash-1",
                    "warnings": [],
                    "sections": {"system": {"platform": "windows"}},
                }
            return None

    profiles = EndpointContextAdapter(Client()).read_profiles(device_id)  # type: ignore[arg-type]

    assert profiles["baseline_v1"]["semantic_hash"] == "hash-1"
    assert profiles["health_v1"] is None
    assert profiles["network_v1"] is None
