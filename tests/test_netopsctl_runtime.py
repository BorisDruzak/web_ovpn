from __future__ import annotations

import pytest


def test_production_writes_need_explicit_enablement_and_verified_checkpoint() -> None:
    from netopsctl.runtime import production_writes_allowed

    assert production_writes_allowed({}) is False
    assert production_writes_allowed({"NETOPSCTL_PRODUCTION_WRITES_ENABLED": "true"}) is False
    assert production_writes_allowed({"NETOPSCTL_AUDIT_CHECKPOINT_HEALTHY": "true"}) is False
    assert production_writes_allowed({
        "NETOPSCTL_PRODUCTION_WRITES_ENABLED": "true",
        "NETOPSCTL_AUDIT_CHECKPOINT_HEALTHY": "true",
    }) is True


def test_runtime_requires_dedicated_routeros_secret_file(tmp_path) -> None:
    from netopsctl.runtime import load_routeros_config

    with pytest.raises(ValueError, match="secret file"):
        load_routeros_config({"NETOPSCTL_ROUTEROS_HOST": "192.0.2.1"})
    secret = tmp_path / "routeros-password"
    secret.write_text("not-a-real-password\n", encoding="utf-8")
    config = load_routeros_config({
        "NETOPSCTL_ROUTEROS_HOST": "192.0.2.1",
        "NETOPSCTL_ROUTEROS_USERNAME": "netopsctl",
        "NETOPSCTL_ROUTEROS_PASSWORD_FILE": str(secret),
    })
    assert (config.host, config.port, config.tls, config.password) == ("192.0.2.1", 8729, True, "not-a-real-password")
