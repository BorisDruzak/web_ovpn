from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_netopsctl_reconciler_uses_a_separate_unprivileged_timer_principal() -> None:
    service = (ROOT / "deploy" / "netopsctl-reconcile.service").read_text(encoding="utf-8")
    timer = (ROOT / "deploy" / "netopsctl-reconcile.timer").read_text(encoding="utf-8")
    installer = (ROOT / "deploy" / "netopsctl").read_text(encoding="utf-8")

    assert "User=netopsctl-reconcile" in service
    assert "After=netctl-reconcile.service netopsctl.socket" in service
    assert "python -m netopsctl.reconcile_runner" in service
    assert "OnUnitActiveSec=5m" in timer
    assert "SocketGroup=netopsctl" in (ROOT / "deploy" / "netopsctl.socket").read_text(encoding="utf-8")
    assert "useradd --system --gid netopsctl --home-dir /var/lib/netopsctl-reconcile" in installer
    assert "usermod -aG netopsctl openvpn-web" in installer
    assert "systemctl enable --now netopsctl-reconcile.timer" not in installer
    assert "SupplementaryGroups=netopsctl" in (ROOT / "deploy" / "openvpn-web.service").read_text(encoding="utf-8")
