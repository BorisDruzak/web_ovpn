from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path
from urllib.request import urlopen

from .config import Settings
from .controller_permissions import ControllerPermissionAuditor
from .errors import ControlError
from .jobs import ACTIVE_STATES, JobRepository
from .vault import VaultHealthChecker


RUNTIME_ENTRYPOINTS = {
    "workstationctl": Path("/usr/local/sbin/workstationctl"),
    "provision_worker": Path("/usr/local/libexec/alt-provision-worker"),
    "job_stage_helper": Path("/usr/local/libexec/alt-job-stage"),
}

API_FILES = {
    "register_api": Path("/opt/alt-deploy-api/register_api.py"),
    "process_pending": Path("/opt/alt-deploy-api/process_pending.py"),
}

STATIC_FILES = {
    "autoinstall": Path("/srv/alt-deploy/metadata/autoinstall.scm"),
    "vm_profile": Path("/srv/alt-deploy/metadata/vm-profile.scm"),
    "pkg_groups": Path("/srv/alt-deploy/metadata/pkg-groups.tar"),
    "install_scripts": Path("/srv/alt-deploy/metadata/install-scripts.tar"),
    "bootstrap": Path("/srv/alt-deploy/bootstrap/bootstrap.sh"),
    "authorized_keys": Path("/srv/alt-deploy/bootstrap/ansible_authorized_keys"),
}

EXPECTED_UNIT_STATE = {
    "alt-deploy-http.service": ("loaded", "active", "enabled"),
    "alt-deploy-register.service": ("loaded", "active", "enabled"),
    "alt-deploy-process.path": ("loaded", "active", "enabled"),
    "alt-deploy-process.service": ("loaded", "inactive", "static"),
}

REGISTRATION_HEALTH_URL = "http://127.0.0.1:8088/health"
STATIC_HEALTH_URLS = (
    "http://127.0.0.1:8087/bootstrap/bootstrap.sh",
    "http://127.0.0.1:8087/bootstrap/ansible_authorized_keys",
    "http://127.0.0.1:8087/metadata/autoinstall.scm",
)


def run_command(
    command: list[str],
    *,
    timeout: int = 30,
    env: dict[str, str] | None = None,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
        env=env,
        cwd=cwd,
    )


def regular_nonempty(path: Path, *, executable: bool = False) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size < 1:
        return False
    return not executable or os.access(path, os.X_OK)


def _response_status(response: object) -> int | None:
    status_value = getattr(response, "status", None)
    if isinstance(status_value, int):
        return status_value
    getcode = getattr(response, "getcode", None)
    if callable(getcode):
        code = getcode()
        if isinstance(code, int):
            return code
    return None


class ControllerReadinessChecker:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def active_jobs_empty(self) -> bool:
        try:
            jobs = JobRepository(self.settings).list()
        except (ControlError, OSError, ValueError):
            return False
        return not any(job.state in ACTIVE_STATES for job in jobs)

    def permissions_ok(self) -> bool:
        try:
            ControllerPermissionAuditor(self.settings).check()
        except (ControlError, OSError, ValueError):
            return False
        return True

    def vault_ok(self) -> bool:
        try:
            VaultHealthChecker(self.settings).check()
        except (ControlError, OSError, ValueError):
            return False
        return True

    @staticmethod
    def _run_ok(
        command: list[str],
        *,
        timeout: int = 30,
        env: dict[str, str] | None = None,
        cwd: Path | None = None,
    ) -> bool:
        try:
            completed = run_command(
                command,
                timeout=timeout,
                env=env,
                cwd=cwd,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        return completed.returncode == 0

    def static_assets_ok(self) -> bool:
        if not all(regular_nonempty(path) for path in STATIC_FILES.values()):
            return False
        return self._run_ok(
            ["bash", "-n", str(STATIC_FILES["bootstrap"])],
            timeout=15,
        )

    @staticmethod
    def _parse_systemd_properties(text: str) -> dict[str, str]:
        properties: dict[str, str] = {}
        allowed = {"LoadState", "ActiveState", "UnitFileState"}
        for raw_line in text.splitlines():
            key, separator, value = raw_line.partition("=")
            if separator and key in allowed:
                properties[key] = value.strip()
        return properties

    def systemd_checks(self) -> dict[str, bool]:
        loaded_ok = True
        enabled_ok = True
        active_ok = True

        for unit, expected in EXPECTED_UNIT_STATE.items():
            try:
                completed = run_command(
                    [
                        "systemctl",
                        "show",
                        unit,
                        "--property=LoadState",
                        "--property=ActiveState",
                        "--property=UnitFileState",
                    ],
                    timeout=15,
                )
            except (OSError, subprocess.TimeoutExpired):
                loaded_ok = False
                enabled_ok = False
                active_ok = False
                continue

            properties = self._parse_systemd_properties(
                completed.stdout if completed.returncode == 0 else ""
            )
            expected_load, expected_active, expected_file = expected
            loaded_ok = loaded_ok and properties.get("LoadState") == expected_load
            active_ok = active_ok and properties.get("ActiveState") == expected_active
            enabled_ok = (
                enabled_ok
                and properties.get("UnitFileState") == expected_file
            )

        return {
            "systemd_units_loaded": loaded_ok,
            "systemd_units_enabled": enabled_ok,
            "systemd_units_active": active_ok,
        }

    @staticmethod
    def registration_health_ok() -> bool:
        try:
            with urlopen(REGISTRATION_HEALTH_URL, timeout=5) as response:
                if _response_status(response) != 200:
                    return False
                raw_body = response.read(4096)
            payload = json.loads(raw_body.decode("utf-8"))
        except (OSError, UnicodeError, ValueError, TimeoutError):
            return False
        return isinstance(payload, dict) and payload.get("status") == "ok"

    @staticmethod
    def static_http_ok() -> bool:
        for url in STATIC_HEALTH_URLS:
            try:
                with urlopen(url, timeout=5) as response:
                    if _response_status(response) != 200:
                        return False
                    if not response.read(1):
                        return False
            except (OSError, ValueError, TimeoutError):
                return False
        return True

    def ansible_syntax_ok(self, playbook_name: str) -> bool:
        playbook = self.settings.ansible_project_dir / "playbooks" / playbook_name
        environment = os.environ.copy()
        environment["ANSIBLE_CONFIG"] = str(
            self.settings.ansible_project_dir / "ansible.cfg"
        )
        return self._run_ok(
            [
                str(self.settings.ansible_playbook_path),
                "--syntax-check",
                str(playbook),
            ],
            timeout=120,
            env=environment,
            cwd=self.settings.ansible_project_dir,
        )

    def check(self) -> dict[str, object]:
        checks = {
            "active_jobs_empty": self.active_jobs_empty(),
            "controller_permissions": self.permissions_ok(),
            "vault": self.vault_ok(),
            "runtime_entrypoints": all(
                regular_nonempty(path, executable=True)
                for path in RUNTIME_ENTRYPOINTS.values()
            ),
            "api_files": all(
                regular_nonempty(path)
                for path in API_FILES.values()
            ),
            "static_assets": self.static_assets_ok(),
            **self.systemd_checks(),
            "registration_api_health": self.registration_health_ok(),
            "static_http_health": self.static_http_ok(),
            "ansible_preflight_syntax": self.ansible_syntax_ok(
                "01-preflight.yml"
            ),
            "ansible_provision_syntax": self.ansible_syntax_ok(
                "02-provision-account.yml"
            ),
        }
        result: dict[str, object] = {
            "ready": all(checks.values()),
            "checks": checks,
            "failed_checks": [
                name for name, succeeded in checks.items() if not succeeded
            ],
        }
        if not result["ready"]:
            raise ControlError(
                code="controller_not_ready",
                message="ALT deployment controller is not ready",
                exit_code=11,
                details=result,
            )
        return result
