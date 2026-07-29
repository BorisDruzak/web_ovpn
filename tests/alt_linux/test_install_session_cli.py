from __future__ import annotations

import io
import json
import sys
from datetime import datetime as real_datetime
from pathlib import Path
from types import SimpleNamespace

import pytest


pytest.importorskip("fcntl", reason="CLI imports POSIX controller locking")


REPO_ROOT = Path(__file__).resolve().parents[2]
CONTROL_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "control"
FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "install"
if str(CONTROL_ROOT) not in sys.path:
    sys.path.insert(0, str(CONTROL_ROOT))

from alt_deploy import cli as cli_module
from alt_deploy.cli import build_parser, main
from alt_deploy.config import Settings
from alt_deploy.install_session_repository import InstallSessionRepository
from alt_deploy.install_session_service import InstallSessionService


def test_cli_show_redacts_private_session_fields(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("ALT_DEPLOY_INSTALL_SESSIONS", str(tmp_path / "sessions"))
    monkeypatch.setenv("ALT_DEPLOY_INSTALL_SESSIONS_LOCK", str(tmp_path / "sessions.lock"))
    monkeypatch.setenv(
        "ALT_DEPLOY_INSTALL_PROFILE_ROOT",
        str(REPO_ROOT / "deploy" / "alt-linux" / "autoinstall" / "profiles"),
    )
    settings = Settings.from_env()
    repository = InstallSessionRepository(settings)
    payload = json.loads((FIXTURE_ROOT / "inventory-disk-100g.json").read_text(encoding="utf-8"))
    created = InstallSessionService(
        settings,
        repository=repository,
        clock=lambda: "2026-07-27T12:00:00+00:00",
        session_id_factory=lambda: "install-20260727T120000Z-a1b2c3d4",
    ).create(
        payload, source_ip="192.168.100.10", create_nonce="A" * 43
    )

    output = io.StringIO()
    assert main(
        ["--json", "install-sessions", "show", created.session_id],
        settings=settings,
        stdout=output,
    ) == 0
    document = json.loads(output.getvalue())
    assert document["session"]["session_id"] == created.session_id
    assert "source_ip" not in document["session"]
    assert "agent_boot_id" not in document["session"]


@pytest.mark.parametrize(
    "missing",
    [
        "--plan-sha256",
        "--inventory-sha256",
        "--disk-fingerprint",
        "--confirm-target",
        "--reason",
    ],
)
def test_authorize_execution_requires_every_exact_binding_argument(
    missing: str,
) -> None:
    arguments = [
        "install-sessions",
        "authorize-execution",
        "install-20260729T120000Z-a1b2c3d4",
        "--plan-sha256",
        "a" * 64,
        "--inventory-sha256",
        "b" * 64,
        "--disk-fingerprint",
        "sha256:" + "c" * 64,
        "--confirm-target",
        "/dev/vda",
        "--reason",
        "Authorize exact target",
    ]
    index = arguments.index(missing)
    del arguments[index : index + 2]

    with pytest.raises(SystemExit) as raised:
        build_parser().parse_args(arguments)

    assert raised.value.code == 2


def test_execution_commands_reject_abbreviated_option_names() -> None:
    with pytest.raises(SystemExit) as raised:
        build_parser().parse_args(
            [
                "install-sessions",
                "authorize-execution",
                "install-20260729T120000Z-a1b2c3d4",
                "--plan-sha",
                "a" * 64,
                "--inventory-sha256",
                "b" * 64,
                "--disk-fingerprint",
                "sha256:" + "c" * 64,
                "--confirm-target",
                "/dev/vda",
                "--reason",
                "Authorize exact target",
            ]
        )

    assert raised.value.code == 2


def test_execution_commands_require_root_before_calling_the_service(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        cli_module.os, "geteuid", lambda: 1000, raising=False
    )
    monkeypatch.setenv(
        "ALT_DEPLOY_INSTALL_SESSIONS", str(tmp_path / "sessions")
    )
    output = io.StringIO()

    result = main(
        [
            "--json",
            "install-sessions",
            "cancel-execution",
            "install-20260729T120000Z-a1b2c3d4",
            "--reason",
            "Operator cancellation",
        ],
        settings=Settings.from_env(),
        stdout=output,
    )

    assert result == 4
    assert json.loads(output.getvalue())["error"]["code"] == (
        "execution_root_required"
    )


def test_execution_commands_call_task2_service_and_redact_output(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        cli_module.os, "geteuid", lambda: 0, raising=False
    )
    monkeypatch.setenv(
        "ALT_DEPLOY_INSTALL_SESSIONS", str(tmp_path / "sessions")
    )
    calls: list[tuple[str, object]] = []

    class FakeExecutionService:
        def __init__(self, settings: Settings, **kwargs: object) -> None:
            calls.append(("init", settings))

        def authorize(
            self, session_id: str, **kwargs: object
        ) -> SimpleNamespace:
            calls.append(("authorize", (session_id, kwargs)))
            return SimpleNamespace(
                status={
                    "session_id": session_id,
                    "execution": {
                        "state": "authorized",
                        "reason": kwargs["reason"],
                        "plan_sha256": kwargs["plan_sha256"],
                        "disk_fingerprint": kwargs[
                            "disk_fingerprint_value"
                        ],
                        "rendered_secret": "$y$j9T$must-not-appear",
                    },
                }
            )

        def cancel(
            self, session_id: str, *, reason: object
        ) -> dict[str, object]:
            calls.append(("cancel", (session_id, reason)))
            return {
                "session_id": session_id,
                "execution": {
                    "state": "cancelled",
                    "cancel_reason": reason,
                    "bearer": "must-not-appear",
                },
            }

    monkeypatch.setattr(
        cli_module, "ExecutionAuthorizationService", FakeExecutionService
    )
    monkeypatch.setattr(
        cli_module,
        "load_execution_release_archives",
        lambda _settings: {},
    )
    settings = Settings.from_env()
    authorize_output = io.StringIO()
    cancel_output = io.StringIO()
    session_id = "install-20260729T120000Z-a1b2c3d4"
    plan_sha256 = "a" * 64
    inventory_sha256 = "b" * 64
    disk_fingerprint = "sha256:" + "c" * 64

    assert main(
        [
            "--json",
            "install-sessions",
            "authorize-execution",
            session_id,
            "--plan-sha256",
            plan_sha256,
            "--inventory-sha256",
            inventory_sha256,
            "--disk-fingerprint",
            disk_fingerprint,
            "--confirm-target",
            "/dev/vda",
            "--reason",
            "Authorize exact target",
        ],
        settings=settings,
        stdout=authorize_output,
    ) == 0
    assert main(
        [
            "--json",
            "install-sessions",
            "cancel-execution",
            session_id,
            "--reason",
            "Operator cancellation",
        ],
        settings=settings,
        stdout=cancel_output,
    ) == 0

    assert calls[1] == (
        "authorize",
        (
            session_id,
            {
                "plan_sha256": plan_sha256,
                "inventory_sha256": inventory_sha256,
                "disk_fingerprint_value": disk_fingerprint,
                "confirm_target": "/dev/vda",
                "reason": "Authorize exact target",
            },
        ),
    )
    assert calls[3] == (
        "cancel",
        (session_id, "Operator cancellation"),
    )
    authorize_document = json.loads(authorize_output.getvalue())
    cancel_document = json.loads(cancel_output.getvalue())
    assert authorize_document == {
        "status": "ok",
        "session": {
            "session_id": session_id,
            "execution_state": "authorized",
        },
    }
    assert cancel_document == {
        "status": "ok",
        "session": {
            "session_id": session_id,
            "execution_state": "cancelled",
        },
    }
    combined = authorize_output.getvalue() + cancel_output.getvalue()
    assert plan_sha256 not in combined
    assert inventory_sha256 not in combined
    assert disk_fingerprint not in combined
    assert "Authorize exact target" not in combined
    assert "Operator cancellation" not in combined
    assert "$y$" not in combined
    assert "must-not-appear" not in combined


def test_authorize_execution_reaches_real_service_with_held_release(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from test_install_execution import (
        _approved_session,
        _publish_held_release_contract,
        _renderer_secrets,
    )

    settings, repository, session_id, approved, plan_sha256 = (
        _approved_session(tmp_path, monkeypatch)
    )
    release_root = tmp_path / "held-release-cli"
    _publish_held_release_contract(release_root)
    object.__setattr__(
        settings, "install_execution_release_root", release_root
    )
    plan = json.loads(
        repository.read_revision_file(session_id, "plan.json")
    )

    class FixedDateTime:
        @classmethod
        def now(cls, timezone: object) -> real_datetime:
            return real_datetime.fromisoformat(
                "2026-07-29T12:02:00+00:00"
            )

    monkeypatch.setattr(
        cli_module.os, "geteuid", lambda: 0, raising=False
    )
    monkeypatch.setattr(cli_module, "datetime", FixedDateTime)
    monkeypatch.setattr(
        cli_module.ExecutionAuthorizationService,
        "_vault_secrets",
        lambda _service: _renderer_secrets(),
    )
    output = io.StringIO()

    result = main(
        [
            "--json",
            "install-sessions",
            "authorize-execution",
            session_id,
            "--plan-sha256",
            plan_sha256,
            "--inventory-sha256",
            str(approved["inventory_sha256"]),
            "--disk-fingerprint",
            str(plan["target_disk"]["fingerprint"]),
            "--confirm-target",
            "/dev/vda",
            "--reason",
            "Authorize held-release integration",
        ],
        settings=settings,
        stdout=output,
    )

    assert result == 0
    assert json.loads(output.getvalue())["session"] == {
        "session_id": session_id,
        "execution_state": "authorized",
    }
    assert repository.load_status(session_id)["execution"]["state"] == (
        "authorized"
    )


def test_cli_show_and_list_omit_execution_internals_and_secret_values(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv(
        "ALT_DEPLOY_INSTALL_SESSIONS", str(tmp_path / "sessions")
    )
    monkeypatch.setenv(
        "ALT_DEPLOY_INSTALL_SESSIONS_LOCK",
        str(tmp_path / "sessions.lock"),
    )
    monkeypatch.setenv(
        "ALT_DEPLOY_INSTALL_PROFILE_ROOT",
        str(
            REPO_ROOT
            / "deploy"
            / "alt-linux"
            / "autoinstall"
            / "profiles"
        ),
    )
    settings = Settings.from_env()
    repository = InstallSessionRepository(settings)
    payload = json.loads(
        (FIXTURE_ROOT / "inventory-disk-100g.json").read_text(
            encoding="utf-8"
        )
    )
    created = InstallSessionService(
        settings,
        repository=repository,
        clock=lambda: "2026-07-27T12:00:00+00:00",
        session_id_factory=lambda: "install-20260727T120000Z-a1b2c3d4",
    ).create(
        payload,
        source_ip="192.168.100.10",
        create_nonce="A" * 43,
    )
    status_path = (
        settings.install_sessions_dir / created.session_id / "status.json"
    )
    status = json.loads(status_path.read_text(encoding="utf-8"))
    status["execution"] = {
        "state": "authorized",
        "manifest_sha256": "d" * 64,
        "reason": "private operator reason",
        "rendered_secret": "$y$j9T$must-not-appear",
        "bearer": "must-not-appear",
    }
    status_path.write_text(json.dumps(status), encoding="utf-8")
    show_output = io.StringIO()
    list_output = io.StringIO()

    assert main(
        ["--json", "install-sessions", "show", created.session_id],
        settings=settings,
        stdout=show_output,
    ) == 0
    assert main(
        ["--json", "install-sessions", "list"],
        settings=settings,
        stdout=list_output,
    ) == 0

    assert "execution" not in json.loads(show_output.getvalue())["session"]
    assert "execution" not in json.loads(list_output.getvalue())["sessions"][0]
    combined = show_output.getvalue() + list_output.getvalue()
    assert "$y$" not in combined
    assert "must-not-appear" not in combined
    assert "private operator reason" not in combined
