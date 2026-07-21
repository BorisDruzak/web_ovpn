from __future__ import annotations

import stat
from pathlib import Path

from alt_deploy.config import Settings
from alt_deploy.machine_archive_repository import (
    MachineArchiveRepository,
)


def test_archive_root_creation_does_not_mutate_existing_ancestor(
    tmp_path: Path,
) -> None:
    ancestor = tmp_path / "existing-ancestor"
    ancestor.mkdir(mode=0o755)
    state_root = ancestor / "missing-parent" / "state"
    settings = Settings(
        registration_root=tmp_path / "registration",
        state_root=state_root,
        jobs_dir=state_root / "jobs",
        assignments_dir=state_root / "assignments",
        lock_file=state_root / "workstationctl.lock",
        ansible_project_dir=tmp_path / "ansible",
        known_hosts_file=tmp_path / "known_hosts",
        private_key_file=tmp_path / "id_ed25519",
        ansible_playbook_path=Path("/usr/bin/ansible-playbook"),
        systemd_run_path=Path("/usr/bin/systemd-run"),
        worker_path=Path("/usr/local/libexec/alt-provision-worker"),
        job_stage_helper_path=tmp_path / "alt-job-stage",
        workstationctl_path=Path("/usr/local/sbin/workstationctl"),
    )
    before_mode = stat.S_IMODE(ancestor.stat().st_mode)

    archive_id = MachineArchiveRepository(
        settings
    ).allocate_archive_id()

    assert archive_id.startswith("archive-")
    assert stat.S_IMODE(ancestor.stat().st_mode) == before_mode
    assert stat.S_IMODE(state_root.stat().st_mode) == 0o700
    assert stat.S_IMODE(
        settings.machine_archives_dir.stat().st_mode
    ) == 0o700
    assert stat.S_IMODE(
        settings.archive_transactions_dir.stat().st_mode
    ) == 0o700
