from __future__ import annotations

import io
import json
from pathlib import Path

from alt_deploy.assignments import AssignmentRepository
from alt_deploy.cli import main
from alt_deploy.config import Settings
from alt_deploy.jsonio import atomic_write_json
from alt_deploy.registry import MachineRepository


MACHINE_UUID = "53b03180-5d78-11f0-bd95-f027db877a00"


def make_settings(tmp_path: Path) -> Settings:
    registration = tmp_path / "registration"
    state = tmp_path / "state"

    settings = Settings(
        registration_root=registration,
        state_root=state,
        jobs_dir=state / "jobs",
        assignments_dir=state / "assignments",
        lock_file=state / "workstationctl.lock",
        ansible_project_dir=tmp_path / "ansible",
        known_hosts_file=tmp_path / "known_hosts",
        private_key_file=tmp_path / "id_ed25519",
        ansible_playbook_path=Path(
            "/usr/bin/ansible-playbook"
        ),
        systemd_run_path=Path("/usr/bin/systemd-run"),
        worker_path=Path(
            "/usr/local/libexec/alt-provision-worker"
        ),
        job_stage_helper_path=tmp_path / "alt-job-stage",
        workstationctl_path=Path(
            "/usr/local/sbin/workstationctl"
        ),
    )
    settings.job_stage_helper_path.write_text(
        "#!/usr/bin/python3\n",
        encoding="utf-8",
    )
    settings.job_stage_helper_path.chmod(0o755)
    return settings


def write_machine(
    settings: Settings,
    state: str,
    registered_at: str,
) -> None:
    atomic_write_json(
        settings.registration_root
        / state
        / f"{MACHINE_UUID}.json",
        {
            "machine_key": MACHINE_UUID,
            "uuid": MACHINE_UUID,
            "hostname": "alt-auto-test",
            "ip": "192.168.101.56",
            "mac": "c0:9b:f4:62:54:e5",
            "registered_at": registered_at,
            "status": state,
        },
    )


def test_repository_prefers_newest_duplicate_record(
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)

    write_machine(
        settings,
        "ready",
        "2026-07-16T07:00:00+00:00",
    )
    write_machine(
        settings,
        "pending",
        "2026-07-16T08:00:00+00:00",
    )

    machines = MachineRepository(settings).list()

    assert len(machines) == 1
    assert machines[0].registration_state == "pending"


def test_machines_list_emits_json(
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    write_machine(
        settings,
        "ready",
        "2026-07-16T08:00:00+00:00",
    )

    stdout = io.StringIO()
    stderr = io.StringIO()

    rc = main(
        ["--json", "machines", "list"],
        settings=settings,
        stdout=stdout,
        stderr=stderr,
    )

    assert rc == 0

    payload = json.loads(stdout.getvalue())

    assert payload["status"] == "ok"
    assert payload["machines"][0]["uuid"] == MACHINE_UUID
    assert payload["machines"][0]["ip"] == "192.168.101.56"


def test_machines_show_returns_not_found_error(
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    stdout = io.StringIO()

    rc = main(
        [
            "--json",
            "machines",
            "show",
            "00000000-0000-0000-0000-000000000000",
        ],
        settings=settings,
        stdout=stdout,
        stderr=io.StringIO(),
    )

    assert rc == 3

    payload = json.loads(stdout.getvalue())

    assert payload["status"] == "error"
    assert payload["error"]["code"] == "machine_not_found"


def test_machine_with_assignment_reports_assigned_status(
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)

    write_machine(
        settings,
        "ready",
        "2026-07-16T08:00:00+00:00",
    )

    repository = MachineRepository(settings)
    machine = repository.get(MACHINE_UUID)

    repository.persist_preflight(
        machine,
        {
            "status": "ok",
            "checks": {
                "uuid": True,
            },
        },
        succeeded=True,
    )

    AssignmentRepository(settings).write(
        MACHINE_UUID,
        {
            "machine_uuid": MACHINE_UUID,
            "employee_login": "test-user",
            "employee_full_name": "Тестовый Пользователь",
            "final_hostname": "alt-auto-test",
            "profile": "standard",
            "job_id": "job-test",
            "completed_at": "2026-07-17T11:29:05Z",
            "verification": {
                "hostname": True,
            },
        },
    )

    refreshed = repository.get(MACHINE_UUID)

    assert refreshed.assignment is not None
    assert refreshed.to_public_dict()["status"] == "assigned"
