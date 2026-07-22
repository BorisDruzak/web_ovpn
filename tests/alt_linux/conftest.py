from __future__ import annotations

import os
import sys
import types
from pathlib import Path

import pytest

if os.name == "nt":
    pytest.skip("ALT Linux test suite requires POSIX account modules", allow_module_level=True)

import pwd

CONTROL_ROOT = (
    Path(__file__).resolve().parents[2]
    / "deploy"
    / "alt-linux"
    / "control"
)
BACKUP_ROOT = (
    Path(__file__).resolve().parents[2]
    / "deploy"
    / "alt-linux"
    / "backup"
)
API_ROOT = (
    Path(__file__).resolve().parents[2]
    / "deploy"
    / "alt-linux"
    / "api"
)

sys.path.insert(0, str(CONTROL_ROOT))
sys.path.insert(0, str(BACKUP_ROOT))
sys.path.insert(0, str(API_ROOT))


@pytest.fixture(autouse=True)
def provide_portable_altserver_account(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Provide controller service dependencies on non-ALT test runners."""
    real_getpwnam = pwd.getpwnam

    def getpwnam(username: str) -> object:
        if username == "altserver":
            return types.SimpleNamespace(
                pw_uid=os.getuid(),
                pw_gid=os.getgid(),
            )
        return real_getpwnam(username)

    monkeypatch.setattr(pwd, "getpwnam", getpwnam)

    ansible_vault = tmp_path / "portable-ansible-vault"
    ansible_vault.write_text(
        (
            "#!/bin/sh\n"
            "printf '%s\\n' "
            "\"vault_employee_password_hash: '\\$y\\$portable-test-hash'\"\n"
        ),
        encoding="utf-8",
    )
    ansible_vault.chmod(0o755)
    monkeypatch.setenv(
        "ALT_DEPLOY_ANSIBLE_VAULT",
        str(ansible_vault),
    )
