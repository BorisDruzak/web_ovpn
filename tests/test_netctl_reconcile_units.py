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


def test_reconciliation_runs_on_boot_and_after_collection_failure():
    timer = (ROOT / "deploy" / "netctl-reconcile.timer").read_text(encoding="utf-8")
    collect = (ROOT / "deploy" / "netctl-collect.service").read_text(encoding="utf-8")
    reconcile = (ROOT / "deploy" / "netctl-reconcile.service").read_text(encoding="utf-8")

    assert "OnBootSec=5min" in timer
    assert "OnCalendar=" not in timer
    assert "OnUnitActiveSec" not in timer
    assert "AccuracySec=30s" in timer
    assert "Unit=netctl-reconcile.service" in timer
    assert "OnFailure=netctl-reconcile.service" in collect
    assert "After=netctl-collect.service" in reconcile


def test_availability_fallback_runs_on_boot_or_under_the_reconciliation_lock():
    timer = (ROOT / "deploy" / "netctl-availability.timer").read_text(encoding="utf-8")
    recovery = (ROOT / "deploy" / "netctl-reconcile.service").read_text(encoding="utf-8")

    assert "OnBootSec=6min" in timer
    assert "OnCalendar=" not in timer
    service = (ROOT / "deploy" / "netctl-availability.service").read_text(encoding="utf-8")
    assert "After=netctl-collect.service netctl-reconcile.service" in service
    assert "OnUnitActiveSec" not in timer
    assert "AccuracySec=30s" in timer
    assert "ExecStart=/usr/local/sbin/netctl --json reconcile --availability" in recovery
    assert "AmbientCapabilities=CAP_NET_RAW" in recovery
