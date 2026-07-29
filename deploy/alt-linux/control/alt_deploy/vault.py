from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

try:
    import pwd
except ImportError:  # pragma: no cover - Windows has no account database module.
    pwd = None  # type: ignore[assignment]

from .config import Settings
from .errors import ControlError


VAULT_VARIABLE = "vault_employee_password_hash"
EXECUTION_ROOT_VARIABLE = "vault_install_root_password_hash"
EXECUTION_ADMIN_VARIABLE = "vault_install_admin_password_hash"


def extract_execution_password_hashes(decrypted_text: str) -> dict[str, str]:
    """Return the two distinct V2 renderer hashes without logging them."""
    if not isinstance(decrypted_text, str):
        raise ValueError("execution password material is invalid")
    values: dict[str, str] = {}
    names = {
        EXECUTION_ROOT_VARIABLE: "root_yescrypt_hash",
        EXECUTION_ADMIN_VARIABLE: "admin_yescrypt_hash",
    }
    for line in decrypted_text.splitlines():
        name, separator, raw_value = line.partition(":")
        if separator and name.strip() in names:
            value = raw_value.strip()
            if len(value) >= 2 and value[0] in {"'", '"'} and value[-1] == value[0]:
                value = value[1:-1]
            values[names[name.strip()]] = value
    if set(values) != {"root_yescrypt_hash", "admin_yescrypt_hash"}:
        raise ValueError("execution password material is invalid")
    root_hash = values["root_yescrypt_hash"]
    admin_hash = values["admin_yescrypt_hash"]
    if (
        root_hash == admin_hash
        or not root_hash.startswith("$y$")
        or not admin_hash.startswith("$y$")
        or len(root_hash) > 256
        or len(admin_hash) > 256
    ):
        raise ValueError("execution password material is invalid")
    return values


class VaultHealthChecker:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    @property
    def vault_file(self) -> Path:
        return (
            self.settings.ansible_project_dir
            / "group_vars"
            / "vault.yml"
        )

    @property
    def password_file(self) -> Path:
        return (
            self.settings.ansible_project_dir.parent
            / ".ansible-vault-pass"
        )

    @property
    def ansible_vault_path(self) -> Path:
        return Path(
            os.environ.get(
                "ALT_DEPLOY_ANSIBLE_VAULT",
                "/usr/bin/ansible-vault",
            )
        )

    def _service_uid(self) -> int | None:
        if pwd is None:
            return None
        try:
            return pwd.getpwnam(
                self.settings.service_user
            ).pw_uid
        except KeyError:
            return None

    @staticmethod
    def _owned_by(
        path: Path,
        expected_uid: int | None,
    ) -> bool:
        if expected_uid is None:
            return False
        try:
            return path.stat().st_uid == expected_uid
        except OSError:
            return False

    @staticmethod
    def _has_private_mode(path: Path) -> bool:
        try:
            return stat.S_IMODE(path.stat().st_mode) == 0o600
        except OSError:
            return False

    @staticmethod
    def _has_vault_header(path: Path) -> bool:
        try:
            with path.open("r", encoding="utf-8") as stream:
                first_line = stream.readline().strip()
        except (OSError, UnicodeError):
            return False

        return first_line.startswith("$ANSIBLE_VAULT;")

    def _decrypt(self) -> str | None:
        command = [
            str(self.ansible_vault_path),
            "view",
            "--vault-password-file",
            str(self.password_file),
            str(self.vault_file),
        ]

        try:
            completed = subprocess.run(
                command,
                shell=False,
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
                cwd=self.settings.ansible_project_dir,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None

        if completed.returncode != 0:
            return None

        return completed.stdout

    @staticmethod
    def _extract_variable_value(
        decrypted_text: str | None,
    ) -> str | None:
        if decrypted_text is None:
            return None

        prefix = f"{VAULT_VARIABLE}:"

        for line in decrypted_text.splitlines():
            stripped = line.strip()

            if not stripped.startswith(prefix):
                continue

            value = stripped[len(prefix):].strip()

            if (
                len(value) >= 2
                and value[0] in {"'", '"'}
                and value[-1] == value[0]
            ):
                value = value[1:-1]

            return value

        return None

    def _build_checks(self) -> dict[str, bool]:
        expected_uid = self._service_uid()
        vault_exists = self.vault_file.is_file()
        password_exists = self.password_file.is_file()

        checks = {
            "vault_file_exists": vault_exists,
            "password_file_exists": password_exists,
            "vault_file_owner": self._owned_by(
                self.vault_file,
                expected_uid,
            ),
            "password_file_owner": self._owned_by(
                self.password_file,
                expected_uid,
            ),
            "vault_file_mode": self._has_private_mode(
                self.vault_file
            ),
            "password_file_mode": self._has_private_mode(
                self.password_file
            ),
            "vault_header": self._has_vault_header(
                self.vault_file
            ),
        }

        structural_ok = all(checks.values())
        decrypted_text = self._decrypt() if structural_ok else None
        variable_value = self._extract_variable_value(
            decrypted_text
        )

        checks.update(
            {
                "decryptable": decrypted_text is not None,
                "variable_present": variable_value is not None,
                "yescrypt_format": bool(
                    variable_value
                    and variable_value.startswith("$y$")
                ),
            }
        )
        return checks

    def check(self) -> dict[str, object]:
        checks = self._build_checks()

        if not all(checks.values()):
            raise ControlError(
                code="vault_unhealthy",
                message="Ansible Vault health check failed",
                exit_code=7,
                details={"checks": checks},
            )

        return {
            "status": "ok",
            "checks": checks,
        }
