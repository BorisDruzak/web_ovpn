from __future__ import annotations

import os
import stat
from pathlib import Path

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


def regular_nonempty(path: Path, *, executable: bool = False) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size < 1:
        return False
    return not executable or os.access(path, os.X_OK)


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
