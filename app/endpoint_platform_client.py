"""Narrow local boundary around the published Endpoint Platform SDK.

This module deliberately does not implement HTTP itself.  It only constructs
the typed, TLS-verifying SDK client from root-managed configuration and turns
all local/upstream failures into a redacted availability signal for the UI.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from .config import Settings


def endpoint_console_origin(settings: Settings) -> str | None:
    if not settings.endpoint_platform_enabled:
        return None
    try:
        url = urlsplit(settings.endpoint_platform_base_url.strip())
        port = url.port
        if (url.scheme != "https" or not url.hostname or url.username is not None
                or url.path not in {"", "/"} or url.query or url.fragment
                or "\\" in url.netloc or any(char.isspace() for char in url.netloc)
                or port == 0):
            return None
        return f"https://{url.netloc}"
    except ValueError:
        return None


class EndpointPlatformServiceError(RuntimeError):
    """Base error that is safe to map into a public degraded response."""


class EndpointPlatformServiceUnavailable(EndpointPlatformServiceError):
    def __init__(self) -> None:
        super().__init__("endpoint_platform_unavailable")


class EndpointPlatformServiceDisabled(EndpointPlatformServiceError):
    def __init__(self) -> None:
        super().__init__("endpoint_platform_disabled")


class EndpointPlatformServiceScopeDenied(EndpointPlatformServiceError):
    def __init__(self) -> None:
        super().__init__("endpoint_platform_scope_denied")


class EndpointPlatformInstallationUnavailable(EndpointPlatformServiceError):
    def __init__(self) -> None:
        super().__init__("endpoint_installation_unavailable")


class EndpointPlatformInstallationConflict(EndpointPlatformServiceError):
    def __init__(self) -> None:
        super().__init__("endpoint_installation_conflict")


class EndpointPlatformServiceClient:
    """Expose only the safe SDK methods consumed by the adapter layer."""

    def __init__(self, settings: Settings, *, installation: bool = False) -> None:
        token_file = (
            settings.endpoint_platform_installation_token_file if installation else settings.endpoint_platform_token_file
        )
        if not settings.endpoint_platform_enabled or token_file is None:
            raise EndpointPlatformServiceDisabled()
        if not token_file.is_absolute() or not settings.endpoint_platform_ca_file.is_absolute():
            raise EndpointPlatformServiceUnavailable()
        try:
            if installation and token_file.resolve() == settings.endpoint_platform_token_file.resolve():
                raise EndpointPlatformServiceUnavailable()
            from endpoint_platform_client import EndpointPlatformClient

            self._client = EndpointPlatformClient(
                settings.endpoint_platform_base_url,
                token_file=token_file,
                ca_file=settings.endpoint_platform_ca_file,
                timeout_seconds=(
                    min(3.0, settings.endpoint_platform_timeout_seconds)
                    if installation else settings.endpoint_platform_timeout_seconds
                ),
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

    def issue_inventory_installation(self, installation_id: str, hardware_fingerprint: str, platform: str) -> Any:
        return self._call(
            lambda: self._client.issue_inventory_installation(installation_id, hardware_fingerprint, platform),
            installation=True,
        )

    def lookup_inventory_installation(self, installation_id: str) -> Any:
        return self._call(lambda: self._client.lookup_inventory_installation(installation_id), installation=True)

    @staticmethod
    def _call(method: Any, *args: object, installation: bool = False) -> Any:
        try:
            return method(*args)
        except EndpointPlatformServiceError:
            raise
        except Exception as exc:
            # SDK errors intentionally redact upstream bodies.  Do not retain
            # or serialize exception text at this boundary.
            if EndpointPlatformServiceClient._is_scope_denied(exc):
                raise EndpointPlatformServiceScopeDenied() from None
            if installation:
                if getattr(exc, "status_code", None) == 409:
                    raise EndpointPlatformInstallationConflict() from None
                if getattr(exc, "status_code", None) == 404:
                    raise EndpointPlatformInstallationUnavailable() from None
            raise EndpointPlatformServiceUnavailable() from None

    @staticmethod
    def _is_scope_denied(exc: Exception) -> bool:
        if isinstance(exc, PermissionError):
            return True
        for field in ("status_code", "status"):
            if getattr(exc, field, None) in {401, 403}:
                return True
        return any(
            marker in type(exc).__name__.lower()
            for marker in ("forbidden", "unauthorized", "permission", "authorization")
        )


def get_endpoint_platform_client(settings: Settings) -> EndpointPlatformServiceClient:
    return EndpointPlatformServiceClient(settings)


def get_endpoint_installation_client(settings: Settings) -> EndpointPlatformServiceClient:
    return EndpointPlatformServiceClient(settings, installation=True)
