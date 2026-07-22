from __future__ import annotations

import json
import os
import shlex
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
ALT_ROOT = REPO_ROOT / "deploy" / "alt-linux"
LIBRARY_PATH = ALT_ROOT / "install-backup-tool-lib.sh"
PUBLIC_INSTALLER = ALT_ROOT / "install-backup-tool.sh"


@dataclass
class BackupInstallerSandbox:
    root: Path
    fake_bin: Path
    command_log: Path

    @classmethod
    def create(cls, tmp_path: Path) -> "BackupInstallerSandbox":
        sandbox = cls(
            root=tmp_path / "controller-root",
            fake_bin=tmp_path / "fake-bin",
            command_log=tmp_path / "commands.jsonl",
        )
        sandbox.root.mkdir()
        sandbox.fake_bin.mkdir()
        log_parent = sandbox.destination("/var/log")
        log_parent.mkdir(parents=True)
        log_parent.chmod(0o755)
        sandbox._seed_control_plane_sentinels()
        sandbox._install_fakes()
        return sandbox

    def destination(self, absolute_path: str) -> Path:
        return self.root / absolute_path.lstrip("/")

    def _write(self, absolute_path: str, raw: bytes) -> Path:
        path = self.destination(absolute_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        return path

    def _seed_control_plane_sentinels(self) -> None:
        for absolute_path in (
            "/opt/alt-deploy-control/sentinel",
            "/opt/alt-deploy-api/sentinel",
            "/var/lib/alt-deploy/sentinel",
            "/srv/alt-deploy/registration/sentinel",
        ):
            self._write(absolute_path, absolute_path.encode("utf-8"))

    def _fake_script(self, name: str, body: str) -> None:
        path = self.fake_bin / name
        path.write_text(
            "#!/bin/bash\nset -Eeuo pipefail\n"
            "{ printf '%q ' " + shlex.quote(name)
            + " \"$@\"; printf '\\n'; } >> \"${BACKUP_INSTALLER_COMMAND_LOG}\"\n"
            + body,
            encoding="utf-8",
        )
        path.chmod(0o755)

    def _install_fakes(self) -> None:
        self._fake_script(
            "id",
            "[[ ${1:-} == altserver ]] && exit ${BACKUP_INSTALLER_ID_RC:-0}\n"
            "exec /usr/bin/id \"$@\"\n",
        )
        self._fake_script(
            "python3",
            "exec " + shlex.quote(sys.executable) + ' "$@"\n',
        )
        self._fake_script(
            "install",
            "directory_mode=0\nmode=\nargs=()\n"
            "while (( $# )); do\n"
            "  case \"$1\" in\n"
            "    -d) directory_mode=1; shift ;;\n"
            "    -o|-g) shift 2 ;;\n"
            "    -m) mode=$2; shift 2 ;;\n"
            "    --) shift; while (( $# )); do args+=(\"$1\"); shift; done ;;\n"
            "    *) args+=(\"$1\"); shift ;;\n"
            "  esac\n"
            "done\n"
            "if (( directory_mode )); then\n"
            "  for path in \"${args[@]}\"; do\n"
            "    mkdir -p \"$path\"\n"
            "    [[ -n $mode ]] && /bin/chmod \"$mode\" \"$path\"\n"
            "  done\n"
            "  exit 0\n"
            "fi\n"
            "(( ${#args[@]} >= 2 )) || exit 2\n"
            "source=${args[${#args[@]}-2]}\n"
            "destination=${args[${#args[@]}-1]}\n"
            "mkdir -p \"$(dirname \"$destination\")\"\n"
            "/bin/cp \"$source\" \"$destination\"\n"
            "[[ -n $mode ]] && /bin/chmod \"$mode\" \"$destination\"\n",
        )
        self._fake_script("cp", 'exec /bin/cp "$@"\n')
        self._fake_script("chmod", 'exec /bin/chmod "$@"\n')
        self._fake_script("chown", "exit 0\n")
        self._fake_script("stat", 'exec /usr/bin/stat "$@"\n')
        self._fake_script("sha256sum", 'exec /usr/bin/sha256sum "$@"\n')
        for name in (
            "tar",
            "zstd",
            "systemctl",
            "systemd-analyze",
            "ansible-playbook",
            "ssh-keygen",
        ):
            self._fake_script(name, "exit 0\n")

    def environment(self, **overrides: str) -> dict[str, str]:
        environment = os.environ.copy()
        environment.update(
            {
                "PATH": f"{self.fake_bin}:{environment['PATH']}",
                "BACKUP_INSTALLER_COMMAND_LOG": str(self.command_log),
                "ALT_DEPLOY_BACKUP_EXPECTED_ROOT_UID": str(os.getuid()),
                "ALT_DEPLOY_BACKUP_EXPECTED_ROOT_GID": str(os.getgid()),
                "ALT_DEPLOY_BACKUP_EXPECTED_SERVICE_UID": str(os.getuid()),
                "ALT_DEPLOY_BACKUP_EXPECTED_SERVICE_GID": str(os.getgid()),
            }
        )
        environment.update(overrides)
        return environment

    def run_public(
        self,
        *arguments: str,
        **overrides: str,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(PUBLIC_INSTALLER), *arguments],
            text=True,
            capture_output=True,
            check=False,
            cwd=REPO_ROOT,
            env=self.environment(**overrides),
        )

    def run_library(
        self,
        **overrides: str,
    ) -> subprocess.CompletedProcess[str]:
        command = (
            "set -Eeuo pipefail; "
            f"REPO_ROOT={json.dumps(str(REPO_ROOT))}; "
            f"ALT_ROOT={json.dumps(str(ALT_ROOT))}; "
            f"source {json.dumps(str(LIBRARY_PATH))}; "
            f"install_backup_tool_main {json.dumps(str(self.root))}"
        )
        return subprocess.run(
            ["bash", "-c", command],
            text=True,
            capture_output=True,
            check=False,
            cwd=REPO_ROOT,
            env=self.environment(**overrides),
        )

    def commands(self) -> list[list[str]]:
        if not self.command_log.exists():
            return []
        return [
            shlex.split(line)
            for line in self.command_log.read_text(
                encoding="utf-8"
            ).splitlines()
            if line
        ]

    def mutation_commands(self) -> list[list[str]]:
        return [
            command
            for command in self.commands()
            if command and command[0] in {
                "install",
                "cp",
                "chmod",
                "chown",
                "systemctl",
            }
        ]

    def control_plane_snapshot(self) -> dict[str, bytes]:
        roots = (
            self.destination("/opt/alt-deploy-control"),
            self.destination("/opt/alt-deploy-api"),
            self.destination("/var/lib/alt-deploy"),
            self.destination("/srv/alt-deploy"),
        )
        result: dict[str, bytes] = {}
        for root in roots:
            if not root.exists():
                continue
            for path in sorted(root.rglob("*")):
                if path.is_file():
                    result[str(path.relative_to(self.root))] = path.read_bytes()
        return result

    def seed_existing_backup_state(self) -> dict[str, bytes]:
        sentinels = {
            "/var/backups/alt-deploy/backup-20260722T120000Z-11111111/manifest.json": b"bundle-sentinel\n",
            "/var/lib/alt-deploy-backup/fingerprint.key": b"k" * 32,
            "/var/log/alt-deploy-backup.log": b"audit-sentinel\n",
        }
        for absolute_path, raw in sentinels.items():
            path = self._write(absolute_path, raw)
            if absolute_path.endswith("fingerprint.key"):
                path.chmod(0o600)
            if absolute_path.endswith("alt-deploy-backup.log"):
                path.chmod(0o600)
        self.destination("/var/backups/alt-deploy").chmod(0o700)
        self.destination("/var/lib/alt-deploy-backup").chmod(0o700)
        return {
            absolute_path: self.destination(absolute_path).read_bytes()
            for absolute_path in sentinels
        }

    def read_sentinels(
        self,
        sentinels: dict[str, bytes],
    ) -> dict[str, bytes]:
        return {
            absolute_path: self.destination(absolute_path).read_bytes()
            for absolute_path in sentinels
        }

    def assert_private_mode(self, absolute_path: str, mode: int) -> None:
        assert stat.S_IMODE(self.destination(absolute_path).stat().st_mode) == mode
