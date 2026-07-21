from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from alt_deploy import controller_readiness
from alt_deploy.controller_permissions import ControllerPermissionAuditor
from alt_deploy.controller_readiness import ControllerReadinessChecker
from alt_deploy.errors import ControlError
from alt_deploy.vault import VaultHealthChecker
from support.cli import run_json_cli
from support.controller_sandbox import make_controller_sandbox


CHECK_NAMES = (
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
)


@pytest.mark.parametrize("failed_check", CHECK_NAMES)
def test_controller_readiness_reports_each_failed_boundary_exactly(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    failed_check: str,
) -> None:
    sandbox = make_controller_sandbox(tmp_path)

    monkeypatch.setattr(
        ControllerReadinessChecker,
        "active_jobs_empty",
        lambda self: failed_check != "active_jobs_empty",
    )
    monkeypatch.setattr(
        ControllerReadinessChecker,
        "permissions_ok",
        lambda self: failed_check != "controller_permissions",
    )
    monkeypatch.setattr(
        ControllerReadinessChecker,
        "vault_ok",
        lambda self: failed_check != "vault",
    )
    monkeypatch.setattr(
        ControllerReadinessChecker,
        "static_assets_ok",
        lambda self: failed_check != "static_assets",
    )
    monkeypatch.setattr(
        ControllerReadinessChecker,
        "registration_health_ok",
        staticmethod(
            lambda: failed_check != "registration_api_health"
        ),
    )
    monkeypatch.setattr(
        ControllerReadinessChecker,
        "static_http_ok",
        staticmethod(lambda: failed_check != "static_http_health"),
    )
    monkeypatch.setattr(
        ControllerReadinessChecker,
        "systemd_checks",
        lambda self: {
            "systemd_units_loaded": failed_check != "systemd_units_loaded",
            "systemd_units_enabled": failed_check != "systemd_units_enabled",
            "systemd_units_active": failed_check != "systemd_units_active",
        },
    )
    monkeypatch.setattr(
        ControllerReadinessChecker,
        "ansible_syntax_ok",
        lambda self, name: not (
            failed_check == "ansible_preflight_syntax"
            and name == "01-preflight.yml"
        )
        and not (
            failed_check == "ansible_provision_syntax"
            and name == "02-provision-account.yml"
        ),
    )

    runtime = Path("/fixture/runtime")
    api = Path("/fixture/api")
    monkeypatch.setattr(
        controller_readiness,
        "RUNTIME_ENTRYPOINTS",
        {"runtime": runtime},
    )
    monkeypatch.setattr(
        controller_readiness,
        "API_FILES",
        {"api": api},
    )
    monkeypatch.setattr(
        controller_readiness,
        "regular_nonempty",
        lambda path, executable=False: not (
            failed_check == "runtime_entrypoints" and path == runtime
        )
        and not (failed_check == "api_files" and path == api),
    )

    result = run_json_cli(
        ["controller", "readiness"],
        settings=sandbox.settings,
    )

    assert result.exit_code == 11
    assert result.payload["error"]["code"] == "controller_not_ready"
    details = result.payload["error"]["details"]
    assert details["ready"] is False
    assert details["failed_checks"] == [failed_check]
    assert details["checks"][failed_check] is False
    assert set(details["checks"]) == set(CHECK_NAMES)


def test_controller_readiness_redacts_source_error_text(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    marker = "opaque-diagnostic-marker"

    monkeypatch.setattr(
        ControllerPermissionAuditor,
        "check",
        lambda self: (_ for _ in ()).throw(
            ControlError(
                code="controller_permissions_unhealthy",
                message=marker,
                exit_code=8,
            )
        ),
    )
    monkeypatch.setattr(
        VaultHealthChecker,
        "check",
        lambda self: {"status": "ok"},
    )
    monkeypatch.setattr(
        ControllerReadinessChecker,
        "active_jobs_empty",
        lambda self: True,
    )
    monkeypatch.setattr(
        ControllerReadinessChecker,
        "static_assets_ok",
        lambda self: True,
    )
    monkeypatch.setattr(
        ControllerReadinessChecker,
        "systemd_checks",
        lambda self: {
            "systemd_units_loaded": True,
            "systemd_units_enabled": True,
            "systemd_units_active": True,
        },
    )
    monkeypatch.setattr(
        ControllerReadinessChecker,
        "registration_health_ok",
        staticmethod(lambda: True),
    )
    monkeypatch.setattr(
        ControllerReadinessChecker,
        "static_http_ok",
        staticmethod(lambda: True),
    )
    monkeypatch.setattr(
        ControllerReadinessChecker,
        "ansible_syntax_ok",
        lambda self, name: True,
    )
    monkeypatch.setattr(
        controller_readiness,
        "regular_nonempty",
        lambda path, executable=False: True,
    )

    result = run_json_cli(
        ["controller", "readiness"],
        settings=sandbox.settings,
    )

    assert result.exit_code == 11
    assert result.payload["error"]["details"]["failed_checks"] == [
        "controller_permissions"
    ]
    assert marker not in json.dumps(result.payload)


class LocalResponse:
    status = 200

    def __init__(self, body: bytes) -> None:
        self.body = body

    def read(self, amount: int = -1) -> bytes:
        return self.body if amount < 0 else self.body[:amount]

    def __enter__(self) -> "LocalResponse":
        return self

    def __exit__(self, *args: object) -> None:
        return None


def test_controller_readiness_uses_only_fixed_local_operations(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    commands: list[list[str]] = []
    urls: list[str] = []

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
    monkeypatch.setattr(
        controller_readiness,
        "regular_nonempty",
        lambda path, executable=False: True,
    )

    def fake_run(command, *, timeout=30, env=None, cwd=None):
        command = [str(item) for item in command]
        commands.append(command)
        if command[:2] == ["systemctl", "show"]:
            expected = controller_readiness.EXPECTED_UNIT_STATE[command[2]]
            stdout = (
                f"LoadState={expected[0]}\n"
                f"ActiveState={expected[1]}\n"
                f"UnitFileState={expected[2]}\n"
            )
        else:
            stdout = "ok\n"
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

    def fake_urlopen(url, timeout=5):
        url_text = str(url)
        urls.append(url_text)
        return LocalResponse(
            b'{"status":"ok"}' if "8088" in url_text else b"x"
        )

    monkeypatch.setattr(controller_readiness, "run_command", fake_run)
    monkeypatch.setattr(controller_readiness, "urlopen", fake_urlopen)

    result = run_json_cli(
        ["controller", "readiness"],
        settings=sandbox.settings,
    )

    assert result.exit_code == 0
    assert commands
    assert urls
    assert all(url.startswith("http://127.0.0.1:") for url in urls)

    flattened = "\n".join(" ".join(command) for command in commands)
    assert "systemd-run" not in flattened
    assert "alt-provision-worker" not in flattened
    assert "192.168." not in flattened
    assert " -i " not in f" {flattened} "
    assert not any(
        command and command[0] in {"ssh", "ssh-keyscan", "ssh-keygen"}
        for command in commands
    )
    assert all(
        command[:2] == ["systemctl", "show"]
        or command[:2] == ["bash", "-n"]
        or "--syntax-check" in command
        for command in commands
    )
