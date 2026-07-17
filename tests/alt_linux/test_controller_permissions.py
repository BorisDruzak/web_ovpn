from __future__ import annotations

import grp
import io
import json
import os
import pwd
from dataclasses import replace
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


def test_controller_permissions_reports_healthy_private_state(
    monkeypatch,
    tmp_path: Path,
) -> None:
    registration_root = tmp_path / "registration"
    state_root = tmp_path / "state"
    ansible_project = tmp_path / "ansible"
    ssh_dir = tmp_path / ".ssh"

    for directory in (
        registration_root,
        state_root,
        state_root / "jobs",
        state_root / "assignments",
        ssh_dir,
        ansible_project / "group_vars",
    ):
        directory.mkdir(parents=True, exist_ok=True)

    for directory in (
        registration_root,
        state_root,
        state_root / "jobs",
        state_root / "assignments",
        ssh_dir,
    ):
        directory.chmod(0o700)

    vault_file = ansible_project / "group_vars" / "vault.yml"
    vault_file.write_text("fixture ciphertext\n", encoding="utf-8")
    vault_file.chmod(0o600)

    vault_password_file = tmp_path / ".ansible-vault-pass"
    vault_password_file.write_text("fixture password\n", encoding="utf-8")
    vault_password_file.chmod(0o600)

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

    settings = replace(
        Settings.from_env(),
        service_user=pwd.getpwuid(os.geteuid()).pw_name,
        service_group=grp.getgrgid(os.getegid()).gr_name,
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
