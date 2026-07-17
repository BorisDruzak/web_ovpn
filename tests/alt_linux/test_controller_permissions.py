from __future__ import annotations

import grp
import io
import json
import os
import pwd
import stat
from pathlib import Path

from alt_deploy.cli import main
from alt_deploy.config import Settings


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
