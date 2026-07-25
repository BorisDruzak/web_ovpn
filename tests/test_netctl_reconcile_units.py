from pathlib import Path

from test_deploy_netctl import _run_installer, _systemctl


ROOT = Path(__file__).resolve().parents[1]


def test_reconcile_service_is_a_hardened_single_netctl_recovery_job(tmp_path: Path) -> None:
    result, bin_dir, _calls_path, environment = _run_installer(tmp_path)

    assert result.returncode == 0, result.stderr
    assert _systemctl(
        bin_dir, environment, "show", "--property=ExecStart", "--value", "netctl-reconcile.service"
    ) == "/usr/local/sbin/netctl --json reconcile"
    for property_name, expected in (
        ("User", "netctl"),
        ("Group", "netctl"),
        ("NoNewPrivileges", "true"),
        ("PrivateTmp", "true"),
        ("ProtectHome", "true"),
    ):
        assert _systemctl(
            bin_dir,
            environment,
            "show",
            f"--property={property_name}",
            "--value",
            "netctl-reconcile.service",
        ) == expected


def test_reconcile_timer_runs_every_five_minutes_and_persists():
    timer = (ROOT / "deploy" / "netctl-reconcile.timer").read_text(encoding="utf-8")

    assert "OnBootSec=4min" in timer
    assert "OnUnitActiveSec=5min" in timer
    assert "AccuracySec=30s" in timer
    assert "Persistent=true" in timer
    assert "Unit=netctl-reconcile.service" in timer
