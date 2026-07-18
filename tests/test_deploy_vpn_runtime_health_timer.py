from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_runtime_health_service_is_strict_and_root_owned():
    text = (ROOT / "deploy" / "vpn-runtime-health.service").read_text(encoding="utf-8")

    assert "User=root" in text
    assert "ExecStart=/usr/local/sbin/vpnctl --json runtime-health --strict" in text


def test_runtime_health_timer_runs_every_minute():
    text = (ROOT / "deploy" / "vpn-runtime-health.timer").read_text(encoding="utf-8")

    assert "OnBootSec=1min" in text
    assert "OnUnitActiveSec=1min" in text
    assert "Persistent=true" in text


def test_installer_wires_policy_and_timer_without_restarting_vpn_tunnels():
    text = (ROOT / "deploy" / "install-openvpn-web.sh").read_text(encoding="utf-8")

    assert 'install -m 0755 "$SRC/deploy/vpn-policy.sh" /usr/local/sbin/vpn-policy.sh' in text
    assert 'install -m 0644 "$SRC/deploy/vpn-policy.service" /etc/systemd/system/vpn-policy.service' in text
    assert 'install -m 0644 "$SRC/deploy/vpn-runtime-health.service" /etc/systemd/system/vpn-runtime-health.service' in text
    assert 'install -m 0644 "$SRC/deploy/vpn-runtime-health.timer" /etc/systemd/system/vpn-runtime-health.timer' in text
    assert "systemctl enable vpn-policy.service" in text
    assert "systemctl enable --now vpn-runtime-health.timer" in text
    assert "restart wg-quick@wg0.service" not in text
    assert "restart openvpn-server@server.service" not in text


def test_reconcile_timer_is_root_scoped_and_does_not_manage_wg_service():
    service = (ROOT / "deploy" / "vpn-policy-reconcile.service").read_text(encoding="utf-8")
    timer = (ROOT / "deploy" / "vpn-policy-reconcile.timer").read_text(encoding="utf-8")

    assert "User=root" in service
    assert "ExecStart=/usr/bin/flock --exclusive /run/lock/vpn-policy.lock /usr/local/sbin/vpn-policy.sh reconcile" in service
    assert "wg-quick" not in service
    assert "OnBootSec=1min" in timer
    assert "OnUnitActiveSec=1min" in timer
    assert "Persistent=true" in timer


def test_policy_units_share_a_blocking_exclusive_lifecycle_lock():
    policy = (ROOT / "deploy" / "vpn-policy.service").read_text(encoding="utf-8")
    reconcile = (ROOT / "deploy" / "vpn-policy-reconcile.service").read_text(encoding="utf-8")

    lock = "/usr/bin/flock --exclusive /run/lock/vpn-policy.lock"
    assert f"ExecStart={lock} /usr/local/sbin/vpn-policy.sh start" in policy
    assert f"ExecStop={lock} /usr/local/sbin/vpn-policy.sh stop" in policy
    assert f"ExecStart={lock} /usr/local/sbin/vpn-policy.sh reconcile" in reconcile
    assert "--nonblock" not in policy
    assert "--nonblock" not in reconcile
    exec_lines = "\n".join(line for line in (policy + reconcile).splitlines() if line.startswith("Exec"))
    assert "wg-quick" not in exec_lines
    assert "openvpn" not in exec_lines


def test_installer_enables_reconcile_timer_without_tunnel_restart():
    text = (ROOT / "deploy" / "install-openvpn-web.sh").read_text(encoding="utf-8")

    assert 'install -m 0644 "$SRC/deploy/vpn-policy-reconcile.service" /etc/systemd/system/vpn-policy-reconcile.service' in text
    assert 'install -m 0644 "$SRC/deploy/vpn-policy-reconcile.timer" /etc/systemd/system/vpn-policy-reconcile.timer' in text
    assert "systemctl enable --now vpn-policy-reconcile.timer" in text
    assert "restart wg-quick@wg0.service" not in text
    assert "restart openvpn-server@server.service" not in text
