from __future__ import annotations

from pathlib import Path

import pytest


def test_endpoint_platform_settings_use_root_managed_secret_paths(monkeypatch, tmp_path):
    monkeypatch.setenv("ENDPOINT_PLATFORM_ENABLED", "1")
    monkeypatch.setenv("ENDPOINT_PLATFORM_TOKEN_FILE", str(tmp_path / "service.token"))
    monkeypatch.setenv("ENDPOINT_PLATFORM_CA_FILE", str(tmp_path / "endpoint-ca.pem"))

    from app.config import get_settings, reset_settings_cache

    reset_settings_cache()
    settings = get_settings()

    assert settings.endpoint_platform_enabled is True
    assert settings.endpoint_platform_token_file == tmp_path / "service.token"
    assert settings.endpoint_platform_ca_file == tmp_path / "endpoint-ca.pem"
    assert settings.endpoint_platform_smoke_device_id is None
    reset_settings_cache()


def test_endpoint_platform_settings_default_to_disabled_and_use_positive_timeout_fallback(monkeypatch):
    from app.config import get_settings, reset_settings_cache

    monkeypatch.delenv("ENDPOINT_PLATFORM_ENABLED", raising=False)
    monkeypatch.setenv("ENDPOINT_PLATFORM_TIMEOUT_SECONDS", "0")
    reset_settings_cache()

    settings = get_settings()

    assert settings.endpoint_platform_enabled is False
    assert settings.endpoint_platform_timeout_seconds == 5.0
    reset_settings_cache()


@pytest.mark.parametrize("relative_setting", ("ENDPOINT_PLATFORM_TOKEN_FILE", "ENDPOINT_PLATFORM_CA_FILE"))
def test_service_client_rejects_relative_token_or_ca_path(monkeypatch, tmp_path, relative_setting):
    from app.config import get_settings, reset_settings_cache
    from app.endpoint_platform_client import EndpointPlatformServiceUnavailable, get_endpoint_platform_client

    monkeypatch.setenv("ENDPOINT_PLATFORM_ENABLED", "1")
    monkeypatch.setenv("ENDPOINT_PLATFORM_TOKEN_FILE", str(tmp_path / "service.token"))
    monkeypatch.setenv("ENDPOINT_PLATFORM_CA_FILE", str(tmp_path / "endpoint-ca.pem"))
    monkeypatch.setenv(relative_setting, "relative-path")
    reset_settings_cache()

    with pytest.raises(EndpointPlatformServiceUnavailable):
        get_endpoint_platform_client(get_settings())

    reset_settings_cache()


def test_endpoint_platform_settings_parse_only_valid_smoke_device_uuid(monkeypatch):
    from app.config import get_settings, reset_settings_cache

    smoke_device_id = "11111111-1111-1111-1111-111111111111"
    monkeypatch.setenv("ENDPOINT_PLATFORM_SMOKE_DEVICE_ID", smoke_device_id)
    reset_settings_cache()
    assert str(get_settings().endpoint_platform_smoke_device_id) == smoke_device_id

    monkeypatch.setenv("ENDPOINT_PLATFORM_SMOKE_DEVICE_ID", "not-a-uuid")
    reset_settings_cache()
    assert get_settings().endpoint_platform_smoke_device_id is None

    monkeypatch.setenv("ENDPOINT_PLATFORM_SMOKE_DEVICE_ID", "")
    reset_settings_cache()
    assert get_settings().endpoint_platform_smoke_device_id is None
    reset_settings_cache()


def test_service_client_degrades_when_sdk_or_local_configuration_is_unavailable(monkeypatch, tmp_path):
    from app.config import get_settings, reset_settings_cache
    from app.endpoint_platform_client import EndpointPlatformServiceUnavailable, get_endpoint_platform_client

    monkeypatch.setenv("ENDPOINT_PLATFORM_ENABLED", "1")
    monkeypatch.setenv("ENDPOINT_PLATFORM_TOKEN_FILE", str(tmp_path / "missing.token"))
    monkeypatch.setenv("ENDPOINT_PLATFORM_CA_FILE", str(tmp_path / "missing-ca.pem"))
    reset_settings_cache()

    with pytest.raises(EndpointPlatformServiceUnavailable) as exc:
        get_endpoint_platform_client(get_settings())

    assert "missing.token" not in str(exc.value)
    assert "endpoint_platform_unavailable" in str(exc.value)
    reset_settings_cache()


def test_inventory_assignment_client_uses_separate_scope_token(monkeypatch, tmp_path):
    from dataclasses import replace
    from types import SimpleNamespace
    import sys

    from app.config import get_settings
    from app.endpoint_platform_client import (
        EndpointPlatformInstallationConflict, EndpointPlatformServiceDisabled,
        EndpointPlatformServiceUnavailable, get_endpoint_installation_client, get_endpoint_platform_client,
    )

    normal = tmp_path / "context.token"
    directed = tmp_path / "install.token"
    ca = tmp_path / "endpoint.pem"
    paths = []

    class SDK:
        def __init__(self, origin, *, token_file, ca_file, timeout_seconds):
            paths.append((token_file, ca_file))

        def issue_inventory_installation(self, installation_id, fingerprint, platform):
            return installation_id, fingerprint, platform

        def lookup_inventory_installation(self, installation_id):
            error = RuntimeError(installation_id)
            error.status_code = 409
            raise error

    monkeypatch.setitem(sys.modules, "endpoint_platform_client", SimpleNamespace(EndpointPlatformClient=SDK))
    settings = replace(get_settings(), endpoint_platform_enabled=True, endpoint_platform_token_file=normal,
                       endpoint_platform_ca_file=ca, endpoint_platform_installation_token_file=directed)
    client = get_endpoint_installation_client(settings)
    get_endpoint_platform_client(settings)
    assert paths == [(directed, ca), (normal, ca)]
    assert client.issue_inventory_installation("fixture-id", "fixture-fingerprint", "linux")[-1] == "linux"
    with pytest.raises(EndpointPlatformInstallationConflict) as failure:
        client.lookup_inventory_installation("fixture-private-id")
    assert "fixture-private-id" not in str(failure.value)
    with pytest.raises(EndpointPlatformServiceUnavailable):
        get_endpoint_installation_client(replace(settings, endpoint_platform_installation_token_file=normal))
    with pytest.raises(EndpointPlatformServiceDisabled):
        get_endpoint_installation_client(replace(settings, endpoint_platform_installation_token_file=None))
