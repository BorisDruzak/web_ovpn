from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path
from types import ModuleType

import pytest


MACHINE_UUID = "53b03180-5d78-11f0-bd95-f027db877a00"

PROCESS_PENDING_PATH = (
    Path(__file__).resolve().parents[2]
    / "deploy"
    / "alt-linux"
    / "api"
    / "process_pending.py"
)


def load_process_pending() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "process_pending_under_test",
        PROCESS_PENDING_PATH,
    )

    assert spec is not None
    assert spec.loader is not None

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    return module


def prepare_module(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    module = load_process_pending()

    pending_dir = tmp_path / "pending"
    ready_dir = tmp_path / "ready"
    failed_dir = tmp_path / "failed"

    for directory in (
        pending_dir,
        ready_dir,
        failed_dir,
    ):
        directory.mkdir(parents=True)

    known_hosts = tmp_path / "known_hosts"
    known_hosts.touch()

    private_key = tmp_path / "id_ed25519"
    private_key.write_text(
        "private key fixture",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        module,
        "PENDING_DIR",
        pending_dir,
    )
    monkeypatch.setattr(
        module,
        "READY_DIR",
        ready_dir,
    )
    monkeypatch.setattr(
        module,
        "FAILED_DIR",
        failed_dir,
    )
    monkeypatch.setattr(
        module,
        "KNOWN_HOSTS",
        known_hosts,
    )
    monkeypatch.setattr(
        module,
        "PRIVATE_KEY",
        private_key,
    )
    monkeypatch.setattr(
        module,
        "WORKSTATIONCTL",
        "/usr/local/sbin/workstationctl",
        raising=False,
    )
    monkeypatch.setattr(
        module,
        "wait_for_ssh",
        lambda ip: True,
    )

    return (
        module,
        pending_dir,
        ready_dir,
        failed_dir,
    )


def write_pending_record(
    pending_dir: Path,
) -> Path:
    path = pending_dir / f"{MACHINE_UUID}.json"

    path.write_text(
        json.dumps(
            {
                "machine_key": MACHINE_UUID,
                "uuid": MACHINE_UUID,
                "hostname": "alt-auto-test",
                "ip": "192.168.101.56",
                "mac": "c0:9b:f4:62:54:e5",
                "registered_at": (
                    "2026-07-16T07:38:55+00:00"
                ),
                "status": "pending",
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    return path


def test_successful_registration_runs_automatic_preflight(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        module,
        pending_dir,
        ready_dir,
        _,
    ) = prepare_module(tmp_path, monkeypatch)

    pending_record = write_pending_record(
        pending_dir
    )

    def fake_run(
        command: list[str],
        *,
        timeout: int = 60,
    ) -> subprocess.CompletedProcess[str]:
        if command[0] == module.SSH_KEYGEN:
            return subprocess.CompletedProcess(
                command,
                0,
                "",
                "",
            )

        if command[0] == module.SSH_KEYSCAN:
            return subprocess.CompletedProcess(
                command,
                0,
                (
                    "192.168.101.56 "
                    "ssh-ed25519 AAAATEST\n"
                ),
                "",
            )

        if command[0] == module.ANSIBLE:
            return subprocess.CompletedProcess(
                command,
                0,
                (
                    "192.168.101.56 | SUCCESS => "
                    '{"ping":"pong"}\n'
                ),
                "",
            )

        if command[0] == module.WORKSTATIONCTL:
            return subprocess.CompletedProcess(
                command,
                0,
                json.dumps(
                    {
                        "status": "ok",
                        "machine_uuid": MACHINE_UUID,
                        "preflight": {
                            "status": "ok",
                            "checks": {
                                "uuid": True,
                            },
                        },
                    }
                ),
                "",
            )

        raise AssertionError(
            f"Unexpected command: {command}"
        )

    monkeypatch.setattr(
        module,
        "run_command",
        fake_run,
    )

    module.process_record(pending_record)

    ready_record = (
        ready_dir / f"{MACHINE_UUID}.json"
    )

    assert ready_record.is_file()

    record = json.loads(
        ready_record.read_text(encoding="utf-8")
    )

    assert record["status"] == "awaiting_assignment"
    assert record["preflight"]["status"] == "ok"
    assert record["preflight"]["checks"]["uuid"] is True


def test_failed_automatic_preflight_moves_record_to_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        module,
        pending_dir,
        _,
        failed_dir,
    ) = prepare_module(tmp_path, monkeypatch)

    pending_record = write_pending_record(
        pending_dir
    )

    def fake_run(
        command: list[str],
        *,
        timeout: int = 60,
    ) -> subprocess.CompletedProcess[str]:
        if command[0] == module.SSH_KEYGEN:
            return subprocess.CompletedProcess(
                command,
                0,
                "",
                "",
            )

        if command[0] == module.SSH_KEYSCAN:
            return subprocess.CompletedProcess(
                command,
                0,
                (
                    "192.168.101.56 "
                    "ssh-ed25519 AAAATEST\n"
                ),
                "",
            )

        if command[0] == module.ANSIBLE:
            return subprocess.CompletedProcess(
                command,
                0,
                (
                    "192.168.101.56 | SUCCESS => "
                    '{"ping":"pong"}\n'
                ),
                "",
            )

        if command[0] == module.WORKSTATIONCTL:
            return subprocess.CompletedProcess(
                command,
                5,
                json.dumps(
                    {
                        "status": "error",
                        "error": {
                            "code": "preflight_failed",
                        },
                    }
                ),
                "preflight failed",
            )

        raise AssertionError(
            f"Unexpected command: {command}"
        )

    monkeypatch.setattr(
        module,
        "run_command",
        fake_run,
    )

    module.process_record(pending_record)

    failed_record = (
        failed_dir / f"{MACHINE_UUID}.json"
    )

    assert failed_record.is_file()

    record = json.loads(
        failed_record.read_text(encoding="utf-8")
    )

    assert record["status"] == "failed"
    assert "Automatic preflight failed" in record["error"]
