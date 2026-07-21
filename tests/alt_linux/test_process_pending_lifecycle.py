from __future__ import annotations

import importlib.util
import json
import subprocess
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType

import pytest

from alt_deploy.config import Settings
from support.lifecycle_fixtures import (
    TEST_MACHINE_UUID,
    commit_candidate_without_cleanup,
    registration_payload,
    write_registration,
)

PROCESS_PENDING_PATH = (
    Path(__file__).resolve().parents[2]
    / "deploy"
    / "alt-linux"
    / "api"
    / "process_pending.py"
)


def load_process_pending() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "process_pending_lifecycle_under_test",
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
) -> tuple[ModuleType, Settings, Path, Path, Path]:
    module = load_process_pending()
    registration = tmp_path / "registration"
    state = tmp_path / "state"
    settings = Settings(
        registration_root=registration,
        state_root=state,
        jobs_dir=state / "jobs",
        assignments_dir=state / "assignments",
        lock_file=state / "workstationctl.lock",
        ansible_project_dir=tmp_path / "ansible",
        known_hosts_file=tmp_path / "known_hosts",
        private_key_file=tmp_path / "id_ed25519",
        ansible_playbook_path=Path("/usr/bin/ansible-playbook"),
        systemd_run_path=Path("/usr/bin/systemd-run"),
        worker_path=Path("/usr/local/libexec/alt-provision-worker"),
        job_stage_helper_path=tmp_path / "alt-job-stage",
        workstationctl_path=Path("/usr/local/sbin/workstationctl"),
    )
    pending = registration / "pending"
    ready = registration / "ready"
    failed = registration / "failed"
    for directory in (pending, ready, failed):
        directory.mkdir(parents=True)
    settings.known_hosts_file.touch()
    settings.private_key_file.write_text(
        "test-private-key",
        encoding="utf-8",
    )
    monkeypatch.setattr(module, "SETTINGS", settings, raising=False)
    monkeypatch.setattr(module, "PENDING_DIR", pending)
    monkeypatch.setattr(module, "READY_DIR", ready)
    monkeypatch.setattr(module, "FAILED_DIR", failed)
    monkeypatch.setattr(module, "KNOWN_HOSTS", settings.known_hosts_file)
    monkeypatch.setattr(module, "PRIVATE_KEY", settings.private_key_file)
    monkeypatch.setattr(
        module,
        "WORKSTATIONCTL",
        "/usr/local/sbin/workstationctl",
        raising=False,
    )
    monkeypatch.setattr(module, "wait_for_ssh", lambda ip: True)
    return module, settings, pending, ready, failed


def write_pending(settings: Settings, registration_id: str) -> Path:
    return write_registration(
        settings,
        "pending",
        registration_payload(
            registration_id=registration_id,
            status="pending",
        ),
    )


def successful_run_command(module: ModuleType):
    def run(
        command: list[str],
        *,
        timeout: int = 60,
    ) -> subprocess.CompletedProcess[str]:
        if command[0] == module.SSH_KEYGEN:
            return subprocess.CompletedProcess(command, 0, "", "")
        if command[0] == module.SSH_KEYSCAN:
            return subprocess.CompletedProcess(
                command,
                0,
                "192.0.2.56 ssh-ed25519 AAAATEST\n",
                "",
            )
        if command[0] == module.ANSIBLE:
            return subprocess.CompletedProcess(
                command,
                0,
                '192.0.2.56 | SUCCESS => {"ping":"pong"}\n',
                "",
            )
        if command[0] == module.WORKSTATIONCTL:
            return subprocess.CompletedProcess(
                command,
                0,
                json.dumps(
                    {
                        "status": "ok",
                        "machine_uuid": TEST_MACHINE_UUID,
                        "preflight": {
                            "status": "ok",
                            "checks": {"uuid": True},
                        },
                    }
                ),
                "",
            )
        raise AssertionError(f"Unexpected command: {command}")

    return run


def failed_preflight_run_command(module: ModuleType):
    success = successful_run_command(module)

    def run(
        command: list[str],
        *,
        timeout: int = 60,
    ) -> subprocess.CompletedProcess[str]:
        if command[0] == module.WORKSTATIONCTL:
            return subprocess.CompletedProcess(
                command,
                5,
                json.dumps(
                    {
                        "status": "error",
                        "error": {"code": "preflight_failed"},
                    }
                ),
                "preflight failed",
            )
        return success(command, timeout=timeout)

    return run


def test_committed_generation_cannot_finalize_ready(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, settings, _, ready, failed = prepare_module(
        tmp_path,
        monkeypatch,
    )
    pending = write_pending(
        settings,
        "reg-11111111111111111111111111111111",
    )
    commit_candidate_without_cleanup(settings, pending, "pending")
    monkeypatch.setattr(
        module,
        "run_command",
        successful_run_command(module),
    )

    module.process_record(pending)

    assert not (ready / pending.name).exists()
    assert not (failed / pending.name).exists()


def test_committed_generation_cannot_finalize_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, settings, _, ready, failed = prepare_module(
        tmp_path,
        monkeypatch,
    )
    pending = write_pending(
        settings,
        "reg-11111111111111111111111111111111",
    )
    commit_candidate_without_cleanup(settings, pending, "pending")
    monkeypatch.setattr(
        module,
        "run_command",
        failed_preflight_run_command(module),
    )

    module.process_record(pending)

    assert not (ready / pending.name).exists()
    assert not (failed / pending.name).exists()


def test_new_generation_replacing_source_is_untouched(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, settings, pending_dir, ready, failed = prepare_module(
        tmp_path,
        monkeypatch,
    )
    pending = write_pending(
        settings,
        "reg-11111111111111111111111111111111",
    )
    base_run = successful_run_command(module)

    def replacing_run(
        command: list[str],
        *,
        timeout: int = 60,
    ) -> subprocess.CompletedProcess[str]:
        if command[0] == module.WORKSTATIONCTL:
            write_pending(
                settings,
                "reg-22222222222222222222222222222222",
            )
        return base_run(command, timeout=timeout)

    monkeypatch.setattr(module, "run_command", replacing_run)

    module.process_record(pending)

    current = json.loads(
        (pending_dir / pending.name).read_text(encoding="utf-8")
    )
    assert current["registration_id"] == (
        "reg-22222222222222222222222222222222"
    )
    assert not (ready / pending.name).exists()
    assert not (failed / pending.name).exists()


def test_long_running_work_occurs_outside_global_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, settings, _, ready, _ = prepare_module(
        tmp_path,
        monkeypatch,
    )
    pending = write_pending(
        settings,
        "reg-11111111111111111111111111111111",
    )
    lock_held = False
    original_save = module.save_record

    @contextmanager
    def tracked_lock(path: Path):
        nonlocal lock_held
        assert lock_held is False
        lock_held = True
        try:
            yield
        finally:
            lock_held = False

    base_run = successful_run_command(module)

    def checked_run(
        command: list[str],
        *,
        timeout: int = 60,
    ) -> subprocess.CompletedProcess[str]:
        assert lock_held is False
        return base_run(command, timeout=timeout)

    def checked_save(path: Path, record: dict, destination: Path):
        assert lock_held is True
        return original_save(path, record, destination)

    monkeypatch.setattr(module, "exclusive_lock", tracked_lock)
    monkeypatch.setattr(module, "run_command", checked_run)
    monkeypatch.setattr(module, "save_record", checked_save)

    module.process_record(pending)

    assert (ready / pending.name).is_file()
    assert lock_held is False
