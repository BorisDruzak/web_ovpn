from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_reconcile_service_is_local_netctl_job_without_device_or_sudo_commands():
    service = (ROOT / "deploy" / "netctl-reconcile.service").read_text(encoding="utf-8")

    assert "User=netctl" in service
    assert "Group=netctl" in service
    assert "ExecStart=/usr/local/sbin/netctl --json topology reconcile" in service
    assert "ExecStart=/usr/local/sbin/netctl --json attachments reconcile" in service
    assert "sudo" not in service
    assert "ssh" not in service
    assert "snmp" not in service
    assert " collect " not in "\n".join(
        line for line in service.splitlines() if line.startswith("ExecStart=")
    )


def test_reconcile_timer_runs_every_five_minutes_and_persists():
    timer = (ROOT / "deploy" / "netctl-reconcile.timer").read_text(encoding="utf-8")

    assert "OnBootSec=4min" in timer
    assert "OnUnitActiveSec=5min" in timer
    assert "AccuracySec=30s" in timer
    assert "Persistent=true" in timer
    assert "Unit=netctl-reconcile.service" in timer


def test_installer_wires_reconcile_timer_without_restarting_vpn_units():
    installer = (ROOT / "deploy" / "install-openvpn-web.sh").read_text(encoding="utf-8")

    assert 'install -m 0644 "$SRC/deploy/netctl-reconcile.service" /etc/systemd/system/netctl-reconcile.service' in installer
    assert 'install -m 0644 "$SRC/deploy/netctl-reconcile.timer" /etc/systemd/system/netctl-reconcile.timer' in installer
    assert "systemctl enable --now netctl-reconcile.timer" in installer
    assert "restart wg-quick@wg0.service" not in installer
    assert "restart openvpn-server@server.service" not in installer
