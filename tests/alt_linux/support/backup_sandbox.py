from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from alt_deploy_backup.quiescence import QuiescenceChecker
from alt_deploy_backup.secrets import (
    FingerprintKeyStore,
    SecretIdentityProvider,
)
from alt_deploy_backup.settings import BackupSettings
from alt_deploy_backup.systemd import SystemdManager


REPO_ROOT = Path(__file__).resolve().parents[3]
BACKUP_SOURCE_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "backup"


@dataclass(frozen=True)
class BackupSandbox:
    root: Path
    fake_bin: Path
    command_log_path: Path
    systemd_state_path: Path
    settings: BackupSettings

    @classmethod
    def create(cls, tmp_path: Path) -> "BackupSandbox":
        root = tmp_path / "controller-root"
        fake_bin = tmp_path / "fake-bin"
        command_log_path = tmp_path / "commands.jsonl"
        systemd_state_path = tmp_path / "systemd-state.json"
        root.mkdir()
        fake_bin.mkdir()
        environment = cls._base_environment(root, fake_bin, command_log_path)
        sandbox = cls(
            root=root,
            fake_bin=fake_bin,
            command_log_path=command_log_path,
            systemd_state_path=systemd_state_path,
            settings=BackupSettings.from_env(environment),
        )
        sandbox._seed_systemd_state()
        sandbox._install_fake_systemctl()
        return sandbox

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

    def _seed_systemd_state(self) -> None:
        state = {
            "malformed": False,
            "transients": [],
            "units": {
                "alt-deploy-http.service": {
                    "load": "loaded",
                    "enabled": "enabled",
                    "active": "active",
                    "sub": "running",
                    "failed": False,
                },
                "alt-deploy-register.service": {
                    "load": "loaded",
                    "enabled": "enabled",
                    "active": "active",
                    "sub": "running",
                    "failed": False,
                },
                "alt-deploy-process.path": {
                    "load": "loaded",
                    "enabled": "enabled",
                    "active": "active",
                    "sub": "waiting",
                    "failed": False,
                },
                "alt-deploy-process.service": {
                    "load": "loaded",
                    "enabled": "static",
                    "active": "inactive",
                    "sub": "dead",
                    "failed": False,
                },
            },
        }
        self.systemd_state_path.write_text(
            json.dumps(state, indent=2) + "\n",
            encoding="utf-8",
        )

    def _install_fake_systemctl(self) -> None:
        script = self.fake_bin / "systemctl"
        state_literal = json.dumps(str(self.systemd_state_path))
        log_literal = json.dumps(str(self.command_log_path))
        script.write_text(
            f"#!{sys.executable}\n"
            "from __future__ import annotations\n"
            "import json\n"
            "import sys\n"
            "from pathlib import Path\n"
            f"STATE_PATH = Path({state_literal})\n"
            f"LOG_PATH = Path({log_literal})\n"
            "args = sys.argv[1:]\n"
            "with LOG_PATH.open('a', encoding='utf-8') as stream:\n"
            "    stream.write(json.dumps(args) + '\\n')\n"
            "state = json.loads(STATE_PATH.read_text(encoding='utf-8'))\n"
            "units = state['units']\n"
            "def save():\n"
            "    STATE_PATH.write_text(json.dumps(state, indent=2) + '\\n', encoding='utf-8')\n"
            "def get_unit(name):\n"
            "    return units.get(name, {'load': 'not-found', 'enabled': 'not-found', 'active': 'inactive', 'sub': 'dead', 'failed': False})\n"
            "if not args:\n"
            "    raise SystemExit(2)\n"
            "command = args[0]\n"
            "if command == 'show':\n"
            "    if state.get('malformed'):\n"
            "        print('malformed')\n"
            "        raise SystemExit(0)\n"
            "    item = get_unit(args[1])\n"
            "    print(item['load'])\n"
            "    print(item['active'])\n"
            "    print(item['sub'])\n"
            "    raise SystemExit(0)\n"
            "if command == 'is-enabled':\n"
            "    item = get_unit(args[1])\n"
            "    print(item['enabled'])\n"
            "    raise SystemExit(0 if item['enabled'] in {'enabled', 'enabled-runtime', 'static', 'indirect', 'generated', 'transient', 'alias'} else 1)\n"
            "if command == 'is-failed':\n"
            "    item = get_unit(args[1])\n"
            "    print('failed' if item['failed'] else item['active'])\n"
            "    raise SystemExit(0 if item['failed'] else 1)\n"
            "if command in {'stop', 'start', 'enable', 'disable'}:\n"
            "    name = args[-1]\n"
            "    item = get_unit(name)\n"
            "    if item['load'] == 'not-found':\n"
            "        raise SystemExit(5)\n"
            "    if command == 'stop':\n"
            "        item['active'] = 'inactive'\n"
            "        item['sub'] = 'dead'\n"
            "        item['failed'] = False\n"
            "    elif command == 'start':\n"
            "        item['active'] = 'active'\n"
            "        item['sub'] = 'waiting' if name.endswith('.path') else 'running'\n"
            "        item['failed'] = False\n"
            "    elif command == 'enable':\n"
            "        item['enabled'] = 'enabled-runtime' if '--runtime' in args else 'enabled'\n"
            "    else:\n"
            "        item['enabled'] = 'disabled'\n"
            "    units[name] = item\n"
            "    save()\n"
            "    raise SystemExit(0)\n"
            "if command == 'list-units':\n"
            "    for name in sorted(state.get('transients', [])):\n"
            "        print(f'{name} loaded active running fixture')\n"
            "    raise SystemExit(0)\n"
            "raise SystemExit(2)\n",
            encoding="utf-8",
        )
        script.chmod(0o755)

    def _read_systemd_state(self) -> dict[str, object]:
        return json.loads(
            self.systemd_state_path.read_text(encoding="utf-8")
        )

    def _write_systemd_state(self, state: dict[str, object]) -> None:
        self.systemd_state_path.write_text(
            json.dumps(state, indent=2) + "\n",
            encoding="utf-8",
        )

    def set_unit_state(
        self,
        name: str,
        *,
        enabled: str,
        active: str,
        load: str = "loaded",
    ) -> None:
        state = self._read_systemd_state()
        units = state["units"]
        assert isinstance(units, dict)
        units[name] = {
            "load": load,
            "enabled": enabled,
            "active": active,
            "sub": (
                "failed"
                if active == "failed"
                else "waiting"
                if active == "active" and name.endswith(".path")
                else "running"
                if active == "active"
                else "dead"
            ),
            "failed": active == "failed",
        }
        self._write_systemd_state(state)

    def unit_state(self, name: str) -> tuple[str, str]:
        state = self._read_systemd_state()
        units = state["units"]
        assert isinstance(units, dict)
        item = units[name]
        assert isinstance(item, dict)
        return str(item["enabled"]), str(item["active"])

    def set_systemctl_malformed(self, value: bool) -> None:
        state = self._read_systemd_state()
        state["malformed"] = value
        self._write_systemd_state(state)

    def set_transient_units(self, units: list[str]) -> None:
        state = self._read_systemd_state()
        state["transients"] = list(units)
        self._write_systemd_state(state)

    def systemd_manager(self) -> SystemdManager:
        return SystemdManager(self.settings)

    def quiescence_checker(self) -> QuiescenceChecker:
        return QuiescenceChecker(
            self.settings,
            systemd_manager=self.systemd_manager(),
        )

    def seed_job(self, *, state: str, stage: str) -> str:
        jobs_root = self.settings.controller_state_root / "jobs"
        jobs_root.mkdir(parents=True, exist_ok=True)
        index = len(list(jobs_root.iterdir())) + 1
        job_id = f"job-20260722T000000Z-{index:08x}"
        job_dir = jobs_root / job_id
        job_dir.mkdir(mode=0o700)
        (job_dir / "status.json").write_text(
            json.dumps(
                {
                    "job_id": job_id,
                    "state": state,
                    "stage": stage,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        (job_dir / "status.json").chmod(0o600)
        return job_id

    def seed_pending(self, filename: str) -> Path:
        pending = self.settings.registration_root / "pending"
        pending.mkdir(parents=True, exist_ok=True)
        path = pending / filename
        path.write_text("{}\n", encoding="utf-8")
        path.chmod(0o600)
        return path
