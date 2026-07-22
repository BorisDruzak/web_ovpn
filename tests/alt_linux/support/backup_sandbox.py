from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from alt_deploy_backup.secrets import (
    FingerprintKeyStore,
    SecretIdentityProvider,
)
from alt_deploy_backup.settings import BackupSettings


REPO_ROOT = Path(__file__).resolve().parents[3]
BACKUP_SOURCE_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "backup"


@dataclass(frozen=True)
class BackupSandbox:
    root: Path
    fake_bin: Path
    command_log_path: Path
    settings: BackupSettings

    @classmethod
    def create(cls, tmp_path: Path) -> "BackupSandbox":
        root = tmp_path / "controller-root"
        fake_bin = tmp_path / "fake-bin"
        command_log_path = tmp_path / "commands.jsonl"
        root.mkdir()
        fake_bin.mkdir()
        environment = cls._base_environment(root, fake_bin, command_log_path)
        return cls(
            root=root,
            fake_bin=fake_bin,
            command_log_path=command_log_path,
            settings=BackupSettings.from_env(environment),
        )

    @staticmethod
    def _base_environment(
        root: Path,
        fake_bin: Path,
        command_log_path: Path,
    ) -> dict[str, str]:
        uid = str(os.getuid())
        gid = str(os.getgid())
        environment = os.environ.copy()
        environment.update(
            {
                "PYTHONPATH": str(BACKUP_SOURCE_ROOT),
                "PATH": f"{fake_bin}:{environment['PATH']}",
                "ALT_DEPLOY_BACKUP_TEST_MODE": "1",
                "ALT_DEPLOY_BACKUP_TEST_ROOT": str(root),
                "ALT_DEPLOY_BACKUP_EXPECTED_ROOT_UID": uid,
                "ALT_DEPLOY_BACKUP_EXPECTED_ROOT_GID": gid,
                "ALT_DEPLOY_BACKUP_EXPECTED_SERVICE_UID": uid,
                "ALT_DEPLOY_BACKUP_EXPECTED_SERVICE_GID": gid,
                "ALT_DEPLOY_BACKUP_COMMAND_LOG": str(command_log_path),
                "ALT_DEPLOY_BACKUP_SSH_KEYGEN": str(
                    fake_bin / "ssh-keygen"
                ),
                "ALT_DEPLOY_BACKUP_ANSIBLE_PLAYBOOK": str(
                    fake_bin / "ansible-playbook"
                ),
                "ALT_DEPLOY_BACKUP_SYSTEMCTL": str(
                    fake_bin / "systemctl"
                ),
                "ALT_DEPLOY_BACKUP_SYSTEMD_ANALYZE": str(
                    fake_bin / "systemd-analyze"
                ),
                "ALT_DEPLOY_BACKUP_TAR": str(fake_bin / "tar"),
                "ALT_DEPLOY_BACKUP_ZSTD": str(fake_bin / "zstd"),
            }
        )
        return environment

    def environment(self, **overrides: str) -> dict[str, str]:
        environment = self._base_environment(
            self.root,
            self.fake_bin,
            self.command_log_path,
        )
        environment.update(overrides)
        return environment

    def run_cli(
        self,
        *arguments: str,
        effective_uid: int,
        **overrides: str,
    ) -> subprocess.CompletedProcess[str]:
        environment = self.environment(
            ALT_DEPLOY_BACKUP_EFFECTIVE_UID=str(effective_uid),
            **overrides,
        )
        return subprocess.run(
            [sys.executable, "-m", "alt_deploy_backup.cli", *arguments],
            cwd=REPO_ROOT,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )

    def command_log(self) -> list[list[str]]:
        if not self.command_log_path.exists():
            return []
        return [
            json.loads(line)
            for line in self.command_log_path.read_text(
                encoding="utf-8"
            ).splitlines()
            if line
        ]

    def _write_executable(self, name: str, body: str) -> Path:
        path = self.fake_bin / name
        path.write_text(
            "#!/bin/sh\nset -eu\n" + body,
            encoding="utf-8",
        )
        path.chmod(0o755)
        return path

    def fake_ssh_fingerprint(self, fingerprint: str) -> Path:
        output = shlex.quote(f"256 {fingerprint} fixture (ED25519)")
        return self._write_executable(
            "ssh-keygen",
            (
                "if [ \"${1:-}\" = '-y' ]; then\n"
                "  printf '%s\\n' 'ssh-ed25519 AAAATEST fixture'\n"
                "  exit 0\n"
                "fi\n"
                "if [ \"${1:-}\" = '-lf' ]; then\n"
                "  cat >/dev/null\n"
                f"  printf '%s\\n' {output}\n"
                "  exit 0\n"
                "fi\n"
                "exit 2\n"
            ),
        )

    def seed_secrets(
        self,
        *,
        vault: bytes = b"$ANSIBLE_VAULT;1.1;AES256\nfixture\n",
        vault_password: bytes = b"fixture-password\n",
        ssh_private_key: bytes = b"fixture-private-key\n",
    ) -> None:
        values = {
            self.settings.vault_file: vault,
            self.settings.vault_password_file: vault_password,
            self.settings.ssh_private_key: ssh_private_key,
        }
        for path, raw in values.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            path.chmod(0o600)
        self.fake_ssh_fingerprint("SHA256:fixture-public-fingerprint")

    def fingerprint_store(self) -> FingerprintKeyStore:
        return FingerprintKeyStore(self.settings)

    def secret_provider(self) -> SecretIdentityProvider:
        return SecretIdentityProvider(
            self.settings,
            key_store=self.fingerprint_store(),
        )
