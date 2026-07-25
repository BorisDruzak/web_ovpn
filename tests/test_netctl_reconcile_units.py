from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_reconcile_service_preserves_local_hardening_without_device_commands() -> None:
    service = (ROOT / "deploy" / "netctl-reconcile.service").read_text(encoding="utf-8")

    assert "User=netctl" in service
    assert "Group=netctl" in service
    assert "NoNewPrivileges=true" in service
    assert "PrivateTmp=true" in service
    assert "ProtectHome=true" in service
    assert "sudo" not in service
    assert "ssh" not in service
    assert "snmp" not in service


def test_reconcile_timer_runs_every_five_minutes_and_persists():
    timer = (ROOT / "deploy" / "netctl-reconcile.timer").read_text(encoding="utf-8")

    assert "OnBootSec=4min" in timer
    assert "OnUnitActiveSec=5min" in timer
    assert "AccuracySec=30s" in timer
    assert "Persistent=true" in timer
    assert "Unit=netctl-reconcile.service" in timer
