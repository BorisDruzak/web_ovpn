"""Narrow local boundary around the published Endpoint Platform SDK.

This module deliberately does not implement HTTP itself.  It only constructs
the typed, TLS-verifying SDK client from root-managed configuration and turns
all local/upstream failures into a redacted availability signal for the UI.
"""

from __future__ import annotations

from typing import Any

from .config import Settings


class EndpointPlatformServiceError(RuntimeError):
    """Base error that is safe to map into a public degraded response."""


class EndpointPlatformServiceUnavailable(EndpointPlatformServiceError):
    def __init__(self) -> None:
        super().__init__("endpoint_platform_unavailable")


class EndpointPlatformServiceDisabled(EndpointPlatformServiceError):
    def __init__(self) -> None:
        super().__init__("endpoint_platform_disabled")


class EndpointPlatformServiceClient:
    """Expose only the safe SDK methods consumed by the adapter layer."""

    def __init__(self, settings: Settings) -> None:
        if not settings.endpoint_platform_enabled:
            raise EndpointPlatformServiceDisabled()
        if (
            not settings.endpoint_platform_token_file.is_absolute()
            or not settings.endpoint_platform_ca_file.is_absolute()
        ):
            raise EndpointPlatformServiceUnavailable()
        try:
            from endpoint_platform_client import EndpointPlatformClient

            self._client = EndpointPlatformClient(
                settings.endpoint_platform_base_url,
                token_file=settings.endpoint_platform_token_file,
                ca_file=settings.endpoint_platform_ca_file,
                timeout_seconds=settings.endpoint_platform_timeout_seconds,
            )
        except Exception:
            # Configuration, import, TLS setup and token failures must not
            # disclose paths, tokens, or implementation details to callers.
            raise EndpointPlatformServiceUnavailable() from None

    def close(self) -> None:
        try:
            self._client.close()
        except Exception:
            return None

    def list_devices(self) -> Any:
        return self._call(self._client.list_devices)

    def list_agent_network_identities(self) -> Any:
        return self._call(self._client.list_agent_network_identities)

    def get_device(self, device_id: object) -> Any:
        return self._call(self._client.get_device, device_id)

    def get_latest_context(self, device_id: object, profile: str) -> Any:
        return self._call(self._client.get_latest_context, device_id, profile)

    def request_collection(self, device_id: object, profile: str, idempotency_key: str) -> Any:
        return self._call(self._client.request_collection, device_id, profile, idempotency_key)

    def get_collection(self, collection_id: object) -> Any:
        return self._call(self._client.get_collection, collection_id)

    def compare_context(self, device_id: object, from_snapshot_id: object, to_snapshot_id: object) -> Any:
        return self._call(
            self._client.compare_context, device_id, from_snapshot_id, to_snapshot_id
        )

    @staticmethod
    def _call(method: Any, *args: object) -> Any:
        try:
            return method(*args)
        except EndpointPlatformServiceError:
            raise
        except Exception:
            # SDK errors intentionally redact upstream bodies.  Do not retain
            # or serialize exception text at this boundary.
            raise EndpointPlatformServiceUnavailable() from None


def get_endpoint_platform_client(settings: Settings) -> EndpointPlatformServiceClient:
    return EndpointPlatformServiceClient(settings)
