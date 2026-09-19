from __future__ import annotations

from pathlib import Path
from uuid import UUID

import pytest


def test_inventory_endpoint_code_has_no_agent_transport_or_direct_http() -> None:
    app_root = Path(__file__).resolve().parents[1] / "app"
    sources = [
        *(app_root / "inventory").glob("*.py"),
        app_root / "endpoint_platform_client.py",
        app_root / "endpoint_context_adapter.py",
    ]
    source = "\n".join(path.read_text(encoding="utf-8") for path in sources)

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
                    "sections": {
                        "system": {
                            "platform": "windows",
                            "distribution": "Windows 11",
                            "architecture": "x86_64",
                            "unexpected": "must not escape",
                        },
                        "hardware": {
                            "manufacturer": "Contoso",
                            "model": "Workstation",
                            "cpu_model": "CPU",
                            "memory_bytes": 16,
                            "serial_number": "must not escape",
                        },
                        "storage": [{"stable_key": "disk-1", "model": "SSD", "size_bytes": 1, "raw": "must not escape"}],
                        "interfaces": [{"stable_key": "mac-001122334455", "name": "eth0", "link_type": "ethernet", "mac": "must not escape"}],
                        "software": [{"name": "endpoint-agent", "version": "1", "source": "system", "token": "must not escape"}],
                        "diagnostic": {"log_excerpt": "must not escape"},
                    },
                }
            if profile == "inventory_v1":
                return {
                    "id": "inventory-1",
                    "profile": profile,
                    "collected_at": "2026-09-18T10:05:00Z",
                    "semantic_hash": "hash-inventory",
                    "warnings": [],
                    "sections": {
                        "system": {
                            "hostname": "workstation-1",
                            "platform": "windows",
                            "os_name": "Windows 11 Pro",
                            "os_version": "24H2",
                            "os_build": "26100",
                            "architecture": "x86_64",
                            "raw": "must not escape",
                        },
                        "hardware": {
                            "manufacturer": "Contoso",
                            "model": "Workstation",
                            "serial_number": "ABC123",
                            "product_uuid": "product-uuid",
                            "cpu_model": "CPU",
                            "raw": "must not escape",
                        },
                        "memory": {
                            "total_bytes": 16,
                            "memory_type": "DDR5",
                            "module_count": 1,
                            "modules": [{"slot": "DIMM0", "capacity_bytes": 16, "raw": "must not escape"}],
                        },
                        "storage": {"physical_devices": [{"stable_key": "disk-1", "model": "SSD", "size_bytes": 1, "media_type": "SSD", "bus_type": "NVME", "raw": "must not escape"}]},
                        "interfaces": [{"stable_key": "mac-001122334455", "name": "eth0", "mac": "001122334455", "link_type": "ethernet", "raw": "must not escape"}],
                    },
                }
            if profile == "session_v1":
                return {
                    "id": "session-1",
                    "profile": profile,
                    "collected_at": "2026-09-18T10:06:00Z",
                    "semantic_hash": "hash-session",
                    "warnings": [],
                    "sections": {
                        "current_user_login": "operator",
                        "interactive_session_present": True,
                        "collected_at": "2026-09-18T10:06:00Z",
                        "token": "must not escape",
                    },
                }
            return None

    profiles = EndpointContextAdapter(Client()).read_profiles(device_id)  # type: ignore[arg-type]

    assert profiles["baseline_v1"]["semantic_hash"] == "hash-1"
    assert profiles["baseline_v1"]["sections"] == {
        "system": {"platform": "windows", "distribution": "Windows 11", "architecture": "x86_64"},
        "hardware": {"manufacturer": "Contoso", "model": "Workstation", "cpu_model": "CPU", "memory_bytes": 16},
        "storage": [{"stable_key": "disk-1", "model": "SSD", "size_bytes": 1}],
        "interfaces": [{"stable_key": "mac-001122334455", "name": "eth0", "link_type": "ethernet"}],
        "software": [{"name": "endpoint-agent", "version": "1", "source": "system"}],
    }
    assert profiles["health_v1"] is None
    assert profiles["network_v1"] is None
    assert profiles["inventory_v1"]["sections"] == {
        "system": {"hostname": "workstation-1", "platform": "windows", "os_name": "Windows 11 Pro", "os_version": "24H2", "os_build": "26100", "architecture": "x86_64"},
        "hardware": {"manufacturer": "Contoso", "model": "Workstation", "serial_number": "ABC123", "product_uuid": "product-uuid", "cpu_model": "CPU"},
        "memory": {"total_bytes": 16, "memory_type": "DDR5", "module_count": 1, "modules": [{"slot": "DIMM0", "capacity_bytes": 16}]},
        "storage": {"physical_devices": [{"stable_key": "disk-1", "model": "SSD", "size_bytes": 1, "media_type": "SSD", "bus_type": "NVME"}]},
        "interfaces": [{"stable_key": "mac-001122334455", "name": "eth0", "mac": "001122334455", "link_type": "ethernet"}],
    }
    assert profiles["session_v1"]["sections"] == {
        "current_user_login": "operator",
        "interactive_session_present": True,
        "collected_at": "2026-09-18T10:06:00Z",
    }
