from __future__ import annotations

from pathlib import Path

import pytest


def test_private_signing_credentials_are_named_regular_32_byte_files(tmp_path: Path, monkeypatch) -> None:
    import netopsctl.credentials as credentials
    from netopsctl.credentials import read_ed25519_private_key

    # Windows does not expose POSIX credential modes; systemd production still
    # executes the real mode check on Linux.
    monkeypatch.setattr(credentials.stat, "S_IMODE", lambda _mode: 0o440)

    with pytest.raises(ValueError, match="invalid audit signing credential"):
        read_ed25519_private_key("netopsctl-audit-signing-key", role="audit signing", credentials_directory=tmp_path)

    key_path = tmp_path / "netopsctl-audit-signing-key"
    key_path.write_bytes(b"a" * 31)
    key_path.chmod(0o600)
    with pytest.raises(ValueError, match="invalid audit signing credential"):
        read_ed25519_private_key("netopsctl-audit-signing-key", role="audit signing", credentials_directory=tmp_path)

    key_path.write_bytes(b"a" * 32)
    key_path.chmod(0o600)
    assert read_ed25519_private_key(
        "netopsctl-audit-signing-key", role="audit signing", credentials_directory=tmp_path
    ) == b"a" * 32


def test_control_plane_units_load_named_signing_credentials() -> None:
    root = Path(__file__).resolve().parents[1]
    broker = (root / "deploy" / "netopsctl.service").read_text(encoding="utf-8")
    web = (root / "deploy" / "openvpn-web.service").read_text(encoding="utf-8")
    reconciler = (root / "deploy" / "netopsctl-reconcile.service").read_text(encoding="utf-8")

    assert "LoadCredential=netopsctl-audit-signing-key:" in broker
    assert "LoadCredential=netopsctl-active-probe-ssh-key:/etc/netopsctl/credentials/active_probe_ssh_ed25519" in broker
    assert "LoadCredential=web-netopsctl-signing-key:" in web
    assert "LoadCredential=netopsctl-reconcile-signing-key:" in reconciler
    assert "NETOPSCTL_AUDIT_SIGNING_KEY_FILE" not in broker
    assert "NETWORK_CONTROL_SIGNING_KEY_PATH" not in web
    assert "NETOPSCTL_RECONCILE_SIGNING_KEY_FILE" not in reconciler


def test_broker_installer_requires_the_active_connectivity_probe_credential() -> None:
    root = Path(__file__).resolve().parents[1]
    installer = (root / "deploy" / "netopsctl").read_text(encoding="utf-8")

    assert "require_credential_source /etc/netopsctl/credentials/active_probe_ssh_ed25519" in installer


def test_broker_credential_directory_permits_only_peer_public_key_reads() -> None:
    root = Path(__file__).resolve().parents[1]
    installer = (root / "deploy" / "netopsctl").read_text(encoding="utf-8")

    assert "install -d -o root -g netopsctl -m 0750 /etc/netopsctl/credentials" in installer
    assert "install -d -o root -g root -m 0700 /etc/openvpn-web/credentials" in installer
