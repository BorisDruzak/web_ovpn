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


def test_reconcile_timer_runs_after_the_collection_window_and_persists():
    timer = (ROOT / "deploy" / "netctl-reconcile.timer").read_text(encoding="utf-8")

    assert "OnBootSec=5min" in timer
    assert "OnCalendar=*:2/5" in timer
    assert "OnUnitActiveSec" not in timer
    assert "AccuracySec=30s" in timer
    assert "Persistent=true" in timer
    assert "Unit=netctl-reconcile.service" in timer


def test_availability_timer_runs_after_collection_and_reconcile_windows():
    timer = (ROOT / "deploy" / "netctl-availability.timer").read_text(encoding="utf-8")

    assert "OnBootSec=6min" in timer
    assert "OnCalendar=*:3/5" in timer
    assert "OnUnitActiveSec" not in timer
    assert "AccuracySec=30s" in timer
    assert "Persistent=true" in timer
