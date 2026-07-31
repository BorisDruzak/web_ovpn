"""Safe projection adapter between web_ovpn and Endpoint Platform SDK data."""

from __future__ import annotations

from typing import Any, Literal
from uuid import UUID

from .config import get_settings
from .endpoint_platform_client import EndpointPlatformServiceClient, get_endpoint_platform_client


SafeProfile = Literal["baseline_v1", "health_v1", "network_v1"]
SAFE_PROFILES = frozenset(("baseline_v1", "health_v1", "network_v1"))


def _dump(value: Any) -> dict[str, Any]:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    if not isinstance(value, dict):
        raise ValueError("safe SDK model was expected")
    return value


def _pick(value: Any, fields: tuple[str, ...]) -> dict[str, Any]:
    source = _dump(value)
    return {field: source.get(field) for field in fields}


def _project_device(value: Any) -> dict[str, Any]:
    return _pick(value, ("id", "device_identifier", "display_name", "retired_at"))


def _project_snapshot(value: Any) -> dict[str, Any]:
    return _pick(value, ("id", "profile", "collected_at", "semantic_hash", "warnings", "sections"))


def _project_collection(value: Any) -> dict[str, Any]:
    return _pick(
        value,
        ("id", "device_id", "profile", "status", "requested_at", "result_received_at", "completed_at", "failure_code"),
    )


def _project_network_identity(value: Any) -> dict[str, Any]:
    source = _dump(value)
    profiles = source.get("profiles")
    return {
        "id": source.get("id"),
        "display_name": source.get("display_name"),
        "last_seen_at": source.get("last_seen_at"),
        "baseline_collected_at": source.get("baseline_collected_at"),
        "profiles": [
            _pick(profile, ("profile", "collected_at"))
            for profile in profiles
            if isinstance(profile, dict)
        ]
        if isinstance(profiles, list)
        else [],
        "baseline_mac_keys": list(source.get("baseline_mac_keys") or []),
    }


class EndpointContextAdapter:
    """Offer only projections intentionally suitable for the panel API."""

    def __init__(self, client: EndpointPlatformServiceClient) -> None:
        self._client = client

    def close(self) -> None:
        self._client.close()

    def list_devices(self) -> list[dict[str, Any]]:
        return [_project_device(device) for device in self._client.list_devices()]

    def list_agent_network_identities(self) -> list[dict[str, Any]]:
        return [
            _project_network_identity(identity)
            for identity in self._client.list_agent_network_identities()
        ]

    def get_device(self, device_id: UUID) -> dict[str, Any]:
        device = _project_device(self._client.get_device(device_id))
        profiles: list[dict[str, Any]] = []
        snapshots: list[dict[str, Any]] = []
        for profile in SAFE_PROFILES:
            snapshot = self._client.get_latest_context(device_id, profile)
            if snapshot is not None:
                snapshots.append(_project_snapshot(snapshot))
                profiles.append({"profile": profile, "status": "available", "last_collected_at": snapshots[-1]["collected_at"]})
        return {"device": device, "profiles": profiles, "snapshots": snapshots}

    def request_collection(self, device_id: UUID, profile: SafeProfile, idempotency_key: str) -> dict[str, Any]:
        if profile not in SAFE_PROFILES:
            raise ValueError("unsupported context profile")
        return _project_collection(self._client.request_collection(device_id, profile, idempotency_key))

    def get_collection(self, collection_id: UUID) -> dict[str, Any]:
        details = _dump(self._client.get_collection(collection_id))
        snapshot = details.get("snapshot")
        return {
            "collection": _project_collection(details.get("collection")),
            "snapshot": _project_snapshot(snapshot) if snapshot is not None else None,
        }

    def compare_context(
        self, device_id: UUID, from_snapshot_id: UUID, to_snapshot_id: UUID
    ) -> dict[str, Any]:
        comparison = _dump(self._client.compare_context(device_id, from_snapshot_id, to_snapshot_id))
        return {"comparison": _pick(comparison.get("comparison"), ("schema_version", "profile", "from_hash", "to_hash", "changes"))}


def get_endpoint_context_adapter() -> EndpointContextAdapter:
    return EndpointContextAdapter(get_endpoint_platform_client(get_settings()))
