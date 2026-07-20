from __future__ import annotations

import errno
import grp
import io
import json
import os
import pwd
import stat
from pathlib import Path

import pytest

from alt_deploy.assignments import AssignmentRepository
from alt_deploy.cli import main
from alt_deploy.config import Settings
from alt_deploy.controller_permissions import ControllerPermissionAuditor
from alt_deploy.jobs import JobRepository
from support.outcomes import get_outcome
from support.payloads import (
    SECOND_TEST_MACHINE_UUID,
    assignment_payload,
    provision_request,
)


EXPECTED_PATH_KEYS = {
    "state_root",
    "jobs_dir",
    "assignments_dir",
    "registration_root",
    "ssh_dir",
    "vault_file",
    "vault_password_file",
}


def _configure_settings(
    monkeypatch,
    *,
    registration_root: Path,
    state_root: Path,
    ansible_project: Path,
    ssh_dir: Path,
) -> Settings:
    monkeypatch.setenv(
        "ALT_DEPLOY_REGISTRATION_ROOT",
        str(registration_root),
    )
    monkeypatch.setenv(
        "ALT_DEPLOY_STATE_ROOT",
        str(state_root),
    )
    monkeypatch.setenv(
        "ALT_DEPLOY_ANSIBLE_PROJECT",
        str(ansible_project),
    )
    monkeypatch.setenv(
        "ALT_DEPLOY_KNOWN_HOSTS",
        str(ssh_dir / "known_hosts_autoinstall"),
    )
    monkeypatch.setenv(
        "ALT_DEPLOY_SERVICE_USER",
        pwd.getpwuid(os.geteuid()).pw_name,
    )
    monkeypatch.setenv(
        "ALT_DEPLOY_SERVICE_GROUP",
        grp.getgrgid(os.getegid()).gr_name,
    )
    return Settings.from_env()


def _prepare_regular_state(
    monkeypatch,
    tmp_path: Path,
    *,
    directory_mode: int,
    secret_mode: int,
) -> tuple[Settings, dict[str, Path]]:
    registration_root = tmp_path / "registration"
    state_root = tmp_path / "state"
    ansible_project = tmp_path / "ansible"
    ssh_dir = tmp_path / ".ssh"

    paths = {
        "state_root": state_root,
        "jobs_dir": state_root / "jobs",
        "assignments_dir": state_root / "assignments",
        "registration_root": registration_root,
        "ssh_dir": ssh_dir,
        "vault_file": ansible_project / "group_vars" / "vault.yml",
        "vault_password_file": tmp_path / ".ansible-vault-pass",
    }

    for key in (
        "registration_root",
        "state_root",
        "jobs_dir",
        "assignments_dir",
        "ssh_dir",
    ):
        paths[key].mkdir(parents=True, exist_ok=True)
        paths[key].chmod(directory_mode)

    paths["vault_file"].parent.mkdir(parents=True, exist_ok=True)
    paths["vault_file"].write_text(
        "fixture ciphertext\n",
        encoding="utf-8",
    )
    paths["vault_file"].chmod(secret_mode)

    paths["vault_password_file"].write_text(
        "fixture password\n",
        encoding="utf-8",
    )
    paths["vault_password_file"].chmod(secret_mode)

    settings = _configure_settings(
        monkeypatch,
        registration_root=registration_root,
        state_root=state_root,
        ansible_project=ansible_project,
        ssh_dir=ssh_dir,
    )
    return settings, paths


def test_controller_permissions_reports_healthy_private_state(
    monkeypatch,
    tmp_path: Path,
) -> None:
    settings, _ = _prepare_regular_state(
        monkeypatch,
        tmp_path,
        directory_mode=0o700,
        secret_mode=0o600,
    )

    stdout = io.StringIO()
    rc = main(
        ["--json", "controller", "permissions"],
        settings=settings,
        stdout=stdout,
        stderr=io.StringIO(),
    )

    assert rc == 0
    payload = json.loads(stdout.getvalue())
    assert payload["status"] == "ok"

    audit = payload["controller_permissions"]
    assert audit["status"] == "ok"
    assert set(audit["paths"]) == EXPECTED_PATH_KEYS

    for result in audit["paths"].values():
        assert result["exists"] is True
        assert result["owner_ok"] is True
        assert result["group_ok"] is True
        assert result["mode_ok"] is True

    serialized = stdout.getvalue()
    assert "fixture ciphertext" not in serialized
    assert "fixture password" not in serialized


def test_controller_permissions_repair_fixes_known_modes(
    monkeypatch,
    tmp_path: Path,
) -> None:
    settings, paths = _prepare_regular_state(
        monkeypatch,
        tmp_path,
        directory_mode=0o755,
        secret_mode=0o644,
    )
    monkeypatch.setattr(os, "geteuid", lambda: 0)

    stdout = io.StringIO()
    rc = main(
        ["--json", "controller", "permissions", "repair"],
        settings=settings,
        stdout=stdout,
        stderr=io.StringIO(),
    )

    assert rc == 0
    payload = json.loads(stdout.getvalue())
    repair = payload["controller_permissions"]
    assert repair["status"] == "ok"
    assert set(repair["changed"]) == EXPECTED_PATH_KEYS

    for key in (
        "state_root",
        "jobs_dir",
        "assignments_dir",
        "registration_root",
        "ssh_dir",
    ):
        assert stat.S_IMODE(paths[key].stat().st_mode) == 0o700

    for key in ("vault_file", "vault_password_file"):
        assert stat.S_IMODE(paths[key].stat().st_mode) == 0o600

    serialized = stdout.getvalue()
    assert "fixture ciphertext" not in serialized
    assert "fixture password" not in serialized


def test_controller_permissions_repair_requires_root(
    monkeypatch,
    tmp_path: Path,
) -> None:
    settings, paths = _prepare_regular_state(
        monkeypatch,
        tmp_path,
        directory_mode=0o755,
        secret_mode=0o644,
    )
    monkeypatch.setattr(os, "geteuid", lambda: 1000)

    stdout = io.StringIO()
    rc = main(
        ["--json", "controller", "permissions", "repair"],
        settings=settings,
        stdout=stdout,
        stderr=io.StringIO(),
    )

    assert rc != 0
    payload = json.loads(stdout.getvalue())
    assert payload["error"]["code"] == "root_required"
    assert stat.S_IMODE(paths["state_root"].stat().st_mode) == 0o755
    assert stat.S_IMODE(paths["vault_file"].stat().st_mode) == 0o644


def test_controller_permissions_repair_blocks_before_mutation(
    monkeypatch,
    tmp_path: Path,
) -> None:
    registration_root = tmp_path / "registration"
    state_root = tmp_path / "state"
    ansible_project = tmp_path / "ansible"
    ssh_target = tmp_path / "ssh-target"
    ssh_link = tmp_path / ".ssh"

    for directory in (
        registration_root,
        state_root,
        state_root / "jobs",
        state_root / "assignments",
        ansible_project / "group_vars",
        ssh_target,
    ):
        directory.mkdir(parents=True, exist_ok=True)

    state_root.chmod(0o755)
    ssh_target.chmod(0o755)
    ssh_link.symlink_to(ssh_target, target_is_directory=True)

    vault_password_file = tmp_path / ".ansible-vault-pass"
    vault_password_file.write_text(
        "fixture password\n",
        encoding="utf-8",
    )
    vault_password_file.chmod(0o644)

    settings = _configure_settings(
        monkeypatch,
        registration_root=registration_root,
        state_root=state_root,
        ansible_project=ansible_project,
        ssh_dir=ssh_link,
    )
    monkeypatch.setattr(os, "geteuid", lambda: 0)

    stdout = io.StringIO()
    rc = main(
        ["--json", "controller", "permissions", "repair"],
        settings=settings,
        stdout=stdout,
        stderr=io.StringIO(),
    )

    assert rc != 0
    payload = json.loads(stdout.getvalue())
    assert payload["error"]["code"] == (
        "controller_permissions_repair_blocked"
    )
    details = payload["error"]["details"]
    assert details["unsafe_paths"] == ["ssh_dir"]
    assert details["missing_paths"] == ["vault_file"]

    assert stat.S_IMODE(state_root.stat().st_mode) == 0o755
    assert stat.S_IMODE(ssh_target.stat().st_mode) == 0o755
    assert not (ansible_project / "group_vars" / "vault.yml").exists()
    assert stat.S_IMODE(vault_password_file.stat().st_mode) == 0o644

    serialized = stdout.getvalue()
    assert "fixture password" not in serialized


EXPECTED_PATH_ORDER = (
    "state_root",
    "jobs_dir",
    "assignments_dir",
    "registration_root",
    "ssh_dir",
    "vault_file",
    "vault_password_file",
)


def _create_permission_sentinels(
    settings: Settings,
) -> dict[Path, bytes]:
    job = JobRepository(settings).create(provision_request())
    AssignmentRepository(settings).write(
        SECOND_TEST_MACHINE_UUID,
        assignment_payload(
            machine_uuid=SECOND_TEST_MACHINE_UUID,
            job_id="job-sentinel",
        ),
    )
    assignment_path = (
        settings.assignments_dir
        / f"{SECOND_TEST_MACHINE_UUID}.json"
    )
    sentinel_paths = (
        job.job_dir / "request.json",
        job.job_dir / "status.json",
        assignment_path,
    )
    return {
        sentinel_path: sentinel_path.read_bytes()
        for sentinel_path in sentinel_paths
    }


def _assert_permission_sentinels_unchanged(
    sentinels: dict[Path, bytes],
) -> None:
    for sentinel_path, expected in sentinels.items():
        assert sentinel_path.read_bytes() == expected


def test_controller_permissions_unhealthy_outcome_is_safe_and_isolated(
    monkeypatch,
    tmp_path: Path,
) -> None:
    outcome = get_outcome("controller-permissions-unhealthy")
    settings, paths = _prepare_regular_state(
        monkeypatch,
        tmp_path,
        directory_mode=0o700,
        secret_mode=0o600,
    )
    sentinels = _create_permission_sentinels(settings)
    paths["state_root"].chmod(0o755)

    stdout = io.StringIO()
    rc = main(
        ["--json", "controller", "permissions"],
        settings=settings,
        stdout=stdout,
        stderr=io.StringIO(),
    )
    payload = json.loads(stdout.getvalue())

    assert rc == outcome.command_exit_code
    assert payload["error"]["code"] == outcome.error_code
    matrix = payload["error"]["details"]["paths"]
    assert set(matrix) == EXPECTED_PATH_KEYS
    assert matrix["state_root"] == {
        "exists": True,
        "owner_ok": True,
        "group_ok": True,
        "mode_ok": False,
        "type_ok": True,
    }
    for name, result in matrix.items():
        if name != "state_root":
            assert all(result.values())

    serialized = stdout.getvalue()
    assert "fixture ciphertext" not in serialized
    assert "fixture password" not in serialized
    _assert_permission_sentinels_unchanged(sentinels)


def test_controller_permissions_owner_group_matrix_is_deterministic(
    monkeypatch,
    tmp_path: Path,
) -> None:
    settings, _ = _prepare_regular_state(
        monkeypatch,
        tmp_path,
        directory_mode=0o700,
        secret_mode=0o600,
    )
    sentinels = _create_permission_sentinels(settings)
    monkeypatch.setattr(
        ControllerPermissionAuditor,
        "_expected_ids",
        lambda self: (os.getuid() + 10000, os.getgid() + 10000),
    )

    stdout = io.StringIO()
    rc = main(
        ["--json", "controller", "permissions"],
        settings=settings,
        stdout=stdout,
        stderr=io.StringIO(),
    )
    matrix = json.loads(stdout.getvalue())["error"]["details"]["paths"]

    assert rc == 8
    for result in matrix.values():
        assert result["exists"] is True
        assert result["owner_ok"] is False
        assert result["group_ok"] is False
        assert result["mode_ok"] is True
        assert result["type_ok"] is True
    _assert_permission_sentinels_unchanged(sentinels)


def test_controller_permissions_missing_and_symlink_matrix_is_safe(
    monkeypatch,
    tmp_path: Path,
) -> None:
    settings, paths = _prepare_regular_state(
        monkeypatch,
        tmp_path,
        directory_mode=0o700,
        secret_mode=0o600,
    )
    sentinels = _create_permission_sentinels(settings)
    paths["vault_file"].unlink()
    paths["ssh_dir"].rmdir()
    ssh_target = tmp_path / "ssh-target-audit"
    ssh_target.mkdir()
    paths["ssh_dir"].symlink_to(ssh_target, target_is_directory=True)

    stdout = io.StringIO()
    rc = main(
        ["--json", "controller", "permissions"],
        settings=settings,
        stdout=stdout,
        stderr=io.StringIO(),
    )
    matrix = json.loads(stdout.getvalue())["error"]["details"]["paths"]

    assert rc == 8
    assert matrix["vault_file"] == {
        "exists": False,
        "owner_ok": False,
        "group_ok": False,
        "mode_ok": False,
        "type_ok": False,
    }
    assert matrix["ssh_dir"]["exists"] is True
    assert matrix["ssh_dir"]["type_ok"] is False
    assert matrix["ssh_dir"]["mode_ok"] is False
    _assert_permission_sentinels_unchanged(sentinels)


def test_controller_permissions_repair_root_required_precedes_mutation(
    monkeypatch,
    tmp_path: Path,
) -> None:
    outcome = get_outcome("controller-permissions-repair-root-required")
    settings, paths = _prepare_regular_state(
        monkeypatch,
        tmp_path,
        directory_mode=0o700,
        secret_mode=0o600,
    )
    sentinels = _create_permission_sentinels(settings)
    paths["state_root"].chmod(0o755)
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    monkeypatch.setattr(
        os,
        "fchown",
        lambda *args: pytest.fail("fchown must not run"),
    )
    monkeypatch.setattr(
        os,
        "fchmod",
        lambda *args: pytest.fail("fchmod must not run"),
    )

    stdout = io.StringIO()
    rc = main(
        ["--json", "controller", "permissions", "repair"],
        settings=settings,
        stdout=stdout,
        stderr=io.StringIO(),
    )
    payload = json.loads(stdout.getvalue())

    assert rc == outcome.command_exit_code
    assert payload["error"]["code"] == outcome.error_code
    assert stat.S_IMODE(paths["state_root"].stat().st_mode) == 0o755
    _assert_permission_sentinels_unchanged(sentinels)


def test_controller_permissions_repair_blocked_precedes_mutation(
    monkeypatch,
    tmp_path: Path,
) -> None:
    outcome = get_outcome("controller-permissions-repair-blocked")
    settings, paths = _prepare_regular_state(
        monkeypatch,
        tmp_path,
        directory_mode=0o700,
        secret_mode=0o600,
    )
    sentinels = _create_permission_sentinels(settings)
    paths["vault_file"].unlink()
    paths["ssh_dir"].rmdir()
    ssh_target = tmp_path / "ssh-target-repair"
    ssh_target.mkdir()
    paths["ssh_dir"].symlink_to(ssh_target, target_is_directory=True)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        os,
        "fchown",
        lambda *args: pytest.fail("fchown must not run"),
    )
    monkeypatch.setattr(
        os,
        "fchmod",
        lambda *args: pytest.fail("fchmod must not run"),
    )

    stdout = io.StringIO()
    rc = main(
        ["--json", "controller", "permissions", "repair"],
        settings=settings,
        stdout=stdout,
        stderr=io.StringIO(),
    )
    payload = json.loads(stdout.getvalue())

    assert rc == outcome.command_exit_code
    assert payload["error"]["code"] == outcome.error_code
    assert payload["error"]["details"] == {
        "missing_paths": ["vault_file"],
        "unsafe_paths": ["ssh_dir"],
    }
    _assert_permission_sentinels_unchanged(sentinels)


def test_controller_permissions_repair_open_race_is_blocked(
    monkeypatch,
    tmp_path: Path,
) -> None:
    settings, paths = _prepare_regular_state(
        monkeypatch,
        tmp_path,
        directory_mode=0o700,
        secret_mode=0o600,
    )
    sentinels = _create_permission_sentinels(settings)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    original_open = ControllerPermissionAuditor._open_policy

    def race_open(policy):
        if policy.path == paths["state_root"]:
            raise FileNotFoundError(errno.ENOENT, "race marker")
        return original_open(policy)

    monkeypatch.setattr(
        ControllerPermissionAuditor,
        "_open_policy",
        staticmethod(race_open),
    )
    monkeypatch.setattr(
        os,
        "fchown",
        lambda *args: pytest.fail("fchown must not run"),
    )
    monkeypatch.setattr(
        os,
        "fchmod",
        lambda *args: pytest.fail("fchmod must not run"),
    )

    stdout = io.StringIO()
    rc = main(
        ["--json", "controller", "permissions", "repair"],
        settings=settings,
        stdout=stdout,
        stderr=io.StringIO(),
    )
    payload = json.loads(stdout.getvalue())

    assert rc == 9
    assert payload["error"]["details"] == {
        "missing_paths": ["state_root"],
        "unsafe_paths": [],
    }
    _assert_permission_sentinels_unchanged(sentinels)


@pytest.mark.parametrize("operation", ["fchown", "fchmod"])
def test_controller_permissions_repair_failure_is_redacted_and_closes_fds(
    monkeypatch,
    tmp_path: Path,
    operation: str,
) -> None:
    outcome = get_outcome("controller-permissions-repair-failed")
    settings, paths = _prepare_regular_state(
        monkeypatch,
        tmp_path,
        directory_mode=0o700,
        secret_mode=0o600,
    )
    sentinels = _create_permission_sentinels(settings)
    monkeypatch.setattr(os, "geteuid", lambda: 0)

    if operation == "fchown":
        monkeypatch.setattr(
            ControllerPermissionAuditor,
            "_expected_ids",
            lambda self: (os.getuid() + 10000, os.getgid() + 10000),
        )
    else:
        paths["state_root"].chmod(0o755)

    opened: list[int] = []
    closed: list[int] = []
    original_open = ControllerPermissionAuditor._open_policy
    original_close = os.close

    def tracking_open(policy):
        descriptor = original_open(policy)
        opened.append(descriptor)
        return descriptor

    def tracking_close(descriptor: int) -> None:
        closed.append(descriptor)
        original_close(descriptor)

    def fail_operation(*args) -> None:
        raise PermissionError("sensitive path marker")

    monkeypatch.setattr(
        ControllerPermissionAuditor,
        "_open_policy",
        staticmethod(tracking_open),
    )
    monkeypatch.setattr(os, "close", tracking_close)
    monkeypatch.setattr(os, operation, fail_operation)

    stdout = io.StringIO()
    rc = main(
        ["--json", "controller", "permissions", "repair"],
        settings=settings,
        stdout=stdout,
        stderr=io.StringIO(),
    )
    payload = json.loads(stdout.getvalue())

    assert rc == outcome.command_exit_code
    assert payload["error"]["code"] == outcome.error_code
    assert payload["error"]["details"] == {
        "system_error": "PermissionError",
    }
    assert "sensitive path marker" not in stdout.getvalue()
    assert opened
    assert set(opened) <= set(closed)
    _assert_permission_sentinels_unchanged(sentinels)


def test_controller_permissions_repair_is_exact_and_idempotent(
    monkeypatch,
    tmp_path: Path,
) -> None:
    outcome = get_outcome("controller-permissions-repaired")
    settings, paths = _prepare_regular_state(
        monkeypatch,
        tmp_path,
        directory_mode=0o700,
        secret_mode=0o600,
    )
    sentinels = _create_permission_sentinels(settings)
    for key in (
        "state_root",
        "jobs_dir",
        "assignments_dir",
        "registration_root",
        "ssh_dir",
    ):
        paths[key].chmod(0o755)
    for key in ("vault_file", "vault_password_file"):
        paths[key].chmod(0o644)
    monkeypatch.setattr(os, "geteuid", lambda: 0)

    first_stdout = io.StringIO()
    first_rc = main(
        ["--json", "controller", "permissions", "repair"],
        settings=settings,
        stdout=first_stdout,
        stderr=io.StringIO(),
    )
    first_payload = json.loads(first_stdout.getvalue())

    assert first_rc == outcome.command_exit_code
    assert first_payload["controller_permissions"]["changed"] == list(
        EXPECTED_PATH_ORDER
    )
    assert ControllerPermissionAuditor(settings).check()["status"] == "ok"

    second_stdout = io.StringIO()
    second_rc = main(
        ["--json", "controller", "permissions", "repair"],
        settings=settings,
        stdout=second_stdout,
        stderr=io.StringIO(),
    )
    second_payload = json.loads(second_stdout.getvalue())

    assert second_rc == 0
    assert second_payload["controller_permissions"]["changed"] == []
    _assert_permission_sentinels_unchanged(sentinels)
