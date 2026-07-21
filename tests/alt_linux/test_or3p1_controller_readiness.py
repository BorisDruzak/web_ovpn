from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from alt_deploy import controller_readiness
from alt_deploy.controller_permissions import ControllerPermissionAuditor
from alt_deploy.vault import VaultHealthChecker
from support.cli import run_json_cli
from support.controller_sandbox import make_controller_sandbox


EXPECTED_CHECKS = {
    "active_jobs_empty",
    "controller_permissions",
    "vault",
    "runtime_entrypoints",
    "api_files",
    "static_assets",
    "systemd_units_loaded",
    "systemd_units_enabled",
    "systemd_units_active",
    "registration_api_health",
    "static_http_health",
    "ansible_preflight_syntax",
    "ansible_provision_syntax",
}


class FakeResponse:
    status = 200

    def __init__(self, body: bytes) -> None:
        self.body = body

    def read(self, amount: int = -1) -> bytes:
        return self.body if amount < 0 else self.body[:amount]

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *args: object) -> None:
        return None


def test_controller_readiness_returns_exact_healthy_contract(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    root = sandbox.root / "readiness"

    runtime_paths = {
        name: root / "bin" / name
        for name in ("workstationctl", "provision_worker", "job_stage_helper")
    }
    api_paths = {
        name: root / "api" / f"{name}.py"
        for name in ("register_api", "process_pending")
    }
    static_paths = {
        name: root / "static" / name
        for name in (
            "autoinstall",
            "vm_profile",
            "pkg_groups",
            "install_scripts",
            "bootstrap",
            "authorized_keys",
        )
    }

    for path in runtime_paths.values():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        path.chmod(0o755)
    for path in (*api_paths.values(), *static_paths.values()):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("fixture\n", encoding="utf-8")

    monkeypatch.setattr(controller_readiness, "RUNTIME_ENTRYPOINTS", runtime_paths)
    monkeypatch.setattr(controller_readiness, "API_FILES", api_paths)
    monkeypatch.setattr(controller_readiness, "STATIC_FILES", static_paths)
    monkeypatch.setattr(
        ControllerPermissionAuditor,
        "check",
        lambda self: {"status": "ok"},
    )
    monkeypatch.setattr(
        VaultHealthChecker,
        "check",
        lambda self: {"status": "ok"},
    )

    def fake_run(command, *, timeout=30, env=None):
        command = [str(item) for item in command]
        if command[:2] == ["systemctl", "show"]:
            unit = command[2]
            load_state, active_state, unit_file_state = (
                controller_readiness.EXPECTED_UNIT_STATE[unit]
            )
            stdout = (
                f"LoadState={load_state}\n"
                f"ActiveState={active_state}\n"
                f"UnitFileState={unit_file_state}\n"
            )
        else:
            stdout = "ok\n"
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

    monkeypatch.setattr(controller_readiness, "run_command", fake_run)
    monkeypatch.setattr(
        controller_readiness,
        "urlopen",
        lambda url, timeout=5: FakeResponse(
            b'{"status":"ok"}' if "8088" in str(url) else b"x"
        ),
    )

    result = run_json_cli(
        ["controller", "readiness"],
        settings=sandbox.settings,
    )

    assert result.exit_code == 0
    readiness = result.payload["controller_readiness"]
    assert readiness["ready"] is True
    assert set(readiness["checks"]) == EXPECTED_CHECKS
    assert all(readiness["checks"].values())
    assert readiness["failed_checks"] == []
