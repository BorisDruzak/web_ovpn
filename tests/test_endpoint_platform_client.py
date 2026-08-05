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
