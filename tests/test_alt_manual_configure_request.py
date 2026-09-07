from __future__ import annotations

import json
import sys
import types
import os
from pathlib import Path
from types import SimpleNamespace
import subprocess

import pytest


CONTROL_ROOT = (
    Path(__file__).resolve().parents[1]
    / "deploy"
    / "alt-linux"
    / "control"
)
sys.path.insert(0, str(CONTROL_ROOT))
_ORIGINAL_FCNTL_MODULE = sys.modules.get("fcntl")

if sys.platform == "win32":
    sys.modules["fcntl"] = types.SimpleNamespace(
        LOCK_EX=2,
        LOCK_NB=4,
        LOCK_UN=8,
        flock=lambda *_args: None,
    )
    sys.modules["pwd"] = types.SimpleNamespace(
        getpwnam=lambda _name: SimpleNamespace(pw_uid=0, pw_gid=0),
        getpwuid=lambda _uid: SimpleNamespace(pw_name="altserver"),
    )
    sys.modules["grp"] = types.SimpleNamespace(
        getgrnam=lambda _name: SimpleNamespace(gr_gid=0),
    )

from alt_deploy.configure import ConfigureRequest  # noqa: E402
from alt_deploy.configure import ConfigurePlanner  # noqa: E402
from alt_deploy.cli import build_parser  # noqa: E402
from alt_deploy.errors import ControlError  # noqa: E402

if sys.platform == "win32":
    if _ORIGINAL_FCNTL_MODULE is None:
        sys.modules.pop("fcntl", None)
    else:
        sys.modules["fcntl"] = _ORIGINAL_FCNTL_MODULE


MACHINE_UUID = "53b03180-5d78-11f0-bd95-f027db877a00"


def valid_request() -> dict[str, str]:
    return {
        "machine_uuid": MACHINE_UUID,
        "final_hostname": "alt-a1-pc3",
        "hostname_mode": "verify",
        "profile": "standard-domain",
        "domain": "sosnadmin.local",
        "realm": "SOSNADMIN.LOCAL",
        "workgroup": "SOSNADM",
        "computer_ou": "OU=Workstations,DC=sosnadmin,DC=local",
        "domain_test_user": "pilot.user",
    }


def valid_structured_result() -> dict[str, object]:
    return {
        "schema_version": 1,
        "machine_uuid": MACHINE_UUID,
        "hostname": "alt-a1-pc3",
        "profile": "standard-domain",
        "status": "successful",
        "phase": "finalize",
        "retryable": False,
        "recovered": False,
        "reboot_required": False,
        "error": None,
        "components": {"domain_join": True},
        "verification": {"domain_join": True},
    }


def valid_legacy_result() -> dict[str, object]:
    """Exact public result written by the stage-03 domain_verify role."""
    return {
        "machine_uuid": MACHINE_UUID,
        "hostname": "alt-a1-pc3",
        "profile": "standard-domain",
        "domain": "sosnadmin.local",
        "already_joined": True,
        "reboot_required": False,
        "verification": {
            "ssh": True,
            "sudo": True,
            "dns": True,
            "time": True,
            "domain_join": True,
            "sssd": True,
            "domain_user_lookup": True,
            "packages": True,
            "group_policy": False,
        },
    }


@pytest.fixture
def run_configure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from alt_deploy.config import Settings
    from alt_deploy.vault import VaultHealthChecker

    settings = Settings(
        registration_root=tmp_path / "registration", state_root=tmp_path / "state",
        jobs_dir=tmp_path / "state" / "jobs", assignments_dir=tmp_path / "state" / "assignments",
        lock_file=tmp_path / "state" / "lock", ansible_project_dir=tmp_path / "ansible",
        known_hosts_file=tmp_path / "known_hosts", private_key_file=tmp_path / "id_ed25519",
        ansible_playbook_path=tmp_path / "ansible-playbook", systemd_run_path=tmp_path / "systemd-run",
        worker_path=tmp_path / "worker", job_stage_helper_path=tmp_path / "stage-helper",
        workstationctl_path=tmp_path / "workstationctl",
    )
    for path in (
        settings.known_hosts_file,
        settings.private_key_file,
        settings.ansible_playbook_path,
    ):
        path.write_text("fixture", encoding="utf-8")
    playbook = settings.ansible_project_dir / "playbooks" / "03-configure-domain-workstation.yml"
    playbook.parent.mkdir(parents=True)
    playbook.write_text("---\n- hosts: all\n", encoding="utf-8")
    machine = SimpleNamespace(uuid=MACHINE_UUID, ip="192.168.101.56")
    monkeypatch.setattr(
        VaultHealthChecker,
        "check_ad_join",
        lambda _self: {"status": "ok"},
    )

    def run(result_payload: dict[str, object]) -> dict[str, object]:
        def fake_run(
            command: list[str], **_kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            result_arg = next(
                item for item in command if item.startswith("configure_result_file=")
            )
            result_path = Path(result_arg.split("=", 1)[1])
            result_path.write_text(json.dumps(result_payload), encoding="utf-8")
            return subprocess.CompletedProcess(command, 0)

        monkeypatch.setattr(subprocess, "run", fake_run)
        request = ConfigureRequest.from_mapping(
            valid_request(), expected_uuid=MACHINE_UUID
        )
        return ConfigurePlanner(
            settings, machines=SimpleNamespace(get=lambda _: machine)
        ).start(MACHINE_UUID, request)

    return run


def test_configure_request_normalizes_safe_values() -> None:
    payload = valid_request()
    payload["final_hostname"] = "ALT-A1-PC3"

    request = ConfigureRequest.from_mapping(
        payload,
        expected_uuid=MACHINE_UUID,
    )

    assert request.to_dict() == {
        **valid_request(),
        "final_hostname": "alt-a1-pc3",
        "software_profile": "base",
        "remote_access_profile": "none",
        "assigned_domain_user": None,
    }


def test_legacy_configure_request_receives_safe_profile_defaults() -> None:
    request = ConfigureRequest.from_mapping(valid_request(), expected_uuid=MACHINE_UUID)
    assert request.software_profile == "base"
    assert request.remote_access_profile == "none"
    assert request.assigned_domain_user is None


def test_core_apps_profile_requires_assigned_user() -> None:
    payload = valid_request() | {"software_profile": "core-apps", "remote_access_profile": "none", "assigned_domain_user": "Pilot.User@SOSNADMIN.LOCAL"}
    request = ConfigureRequest.from_mapping(payload, expected_uuid=MACHINE_UUID)
    assert request.software_profile == "core-apps"
    assert request.assigned_domain_user == "pilot.user@sosnadmin.local"


def test_core_apps_profile_rejects_missing_assigned_user() -> None:
    payload = valid_request() | {"software_profile": "core-apps", "remote_access_profile": "none", "assigned_domain_user": None}
    with pytest.raises(ControlError, match="assigned domain user"):
        ConfigureRequest.from_mapping(payload, expected_uuid=MACHINE_UUID)


def test_krfb_profile_requires_assigned_user() -> None:
    payload = valid_request() | {"software_profile": "base", "remote_access_profile": "krfb", "assigned_domain_user": "pilot.user"}
    request = ConfigureRequest.from_mapping(payload, expected_uuid=MACHINE_UUID)
    assert request.remote_access_profile == "krfb"
    assert request.assigned_domain_user == "pilot.user"


def test_krfb_profile_rejects_missing_assigned_user() -> None:
    payload = valid_request() | {
        "software_profile": "base",
        "remote_access_profile": "krfb",
        "assigned_domain_user": None,
    }

    with pytest.raises(ControlError, match="assigned domain user"):
        ConfigureRequest.from_mapping(payload, expected_uuid=MACHINE_UUID)


@pytest.mark.parametrize("change", [
    {"software_profile": "unsupported", "remote_access_profile": "none", "assigned_domain_user": None},
    {"software_profile": "base", "remote_access_profile": "unsupported", "assigned_domain_user": None},
    {"software_profile": "base", "remote_access_profile": "none"},
    {"software_profile": "base", "assigned_domain_user": None},
    {"software_profile": "base", "remote_access_profile": "none", "assigned_domain_user": "bad user"},
])
def test_configure_request_rejects_unsupported_or_partial_profiles(change: dict[str, object]) -> None:
    payload = valid_request()
    payload.update(change)  # type: ignore[arg-type]
    with pytest.raises(ControlError) as exc:
        ConfigureRequest.from_mapping(payload, expected_uuid=MACHINE_UUID)
    assert exc.value.code == "configure_request_invalid"


def test_configure_request_accepts_explicit_confirmed_hostname_change() -> None:
    payload = valid_request()
    payload["hostname_mode"] = "change_confirmed"

    request = ConfigureRequest.from_mapping(payload, expected_uuid=MACHINE_UUID)

    assert request.hostname_mode == "change_confirmed"


def test_configure_request_accepts_domain_test_user_upn() -> None:
    payload = valid_request()
    payload["domain_test_user"] = "alt-test-user@sosnadmin.local"

    request = ConfigureRequest.from_mapping(
        payload,
        expected_uuid=MACHINE_UUID,
    )

    assert request.domain_test_user == "alt-test-user@sosnadmin.local"


@pytest.mark.parametrize(
    ("change", "expected_code"),
    [
        ({"playbook": "other.yml"}, "configure_request_invalid"),
        ({"ad_join_password": "secret"}, "configure_request_invalid"),
        ({"domain": "example.local"}, "configure_request_invalid"),
        ({"realm": "OTHER.LOCAL"}, "configure_request_invalid"),
        ({"workgroup": ""}, "configure_request_invalid"),
        ({"computer_ou": ""}, "configure_request_invalid"),
        ({"domain_test_user": ""}, "configure_request_invalid"),
        ({"machine_uuid": "not-a-uuid"}, "configure_request_invalid"),
        ({"hostname_mode": "change"}, "configure_request_invalid"),
    ],
)
def test_configure_request_rejects_untrusted_input(
    change: dict[str, str],
    expected_code: str,
) -> None:
    payload = valid_request()
    payload.update(change)

    with pytest.raises(ControlError) as exc:
        ConfigureRequest.from_mapping(
            payload,
            expected_uuid=MACHINE_UUID,
        )

    assert exc.value.code == expected_code


@pytest.mark.parametrize(
    "hostname",
    ["alt_ws_001", "alt-a11-pc3", "ubuntu-a1-pc3", "alt-a1-pc0"],
)
def test_configure_request_rejects_hostname_outside_operational_grammar(
    hostname: str,
) -> None:
    payload = valid_request()
    payload["final_hostname"] = hostname

    with pytest.raises(ControlError) as exc:
        ConfigureRequest.from_mapping(payload, expected_uuid=MACHINE_UUID)

    assert exc.value.code == "hostname_invalid"


def test_configure_request_rejects_selected_uuid_mismatch() -> None:
    with pytest.raises(ControlError) as exc:
        ConfigureRequest.from_mapping(
            valid_request(),
            expected_uuid="11111111-2222-3333-4444-555555555555",
        )

    assert exc.value.code == "configure_request_invalid"


def test_configure_preview_uses_registered_ip_without_assignment_check() -> None:
    machine = SimpleNamespace(uuid=MACHINE_UUID, ip="192.168.101.56")
    machines = SimpleNamespace(get=lambda machine_uuid: machine)
    request = ConfigureRequest.from_mapping(
        valid_request(), expected_uuid=MACHINE_UUID
    )

    preview = ConfigurePlanner(
        SimpleNamespace(), machines=machines
    ).preview(MACHINE_UUID, request)

    assert preview == {
        "status": "ok",
        "machine_uuid": MACHINE_UUID,
        "target_ip": "192.168.101.56",
        "playbook": "03-configure-domain-workstation.yml",
        "request": {**valid_request(), "software_profile": "base", "remote_access_profile": "none", "assigned_domain_user": None},
        "actions": [
            "manual_preflight",
            "verify_or_change_hostname",
            "configure_domain_dns",
            "join_or_verify_domain",
            "verify_domain_workstation",
        ],
        "deferred_actions": [],
    }


def test_configure_preview_describes_only_explicit_selected_components() -> None:
    machine = SimpleNamespace(uuid=MACHINE_UUID, ip="192.168.101.56")
    machines = SimpleNamespace(get=lambda machine_uuid: machine)
    request = ConfigureRequest.from_mapping(valid_request() | {"software_profile": "core-apps", "remote_access_profile": "krfb", "assigned_domain_user": "pilot.user"}, expected_uuid=MACHINE_UUID)
    preview = ConfigurePlanner(SimpleNamespace(), machines=machines).preview(MACHINE_UUID, request)
    assert "install_standard_packages" not in preview["actions"]
    assert "install_core_apps" not in preview["actions"]
    assert "configure_krfb" not in preview["actions"]
    assert preview["deferred_actions"] == ["install_core_apps", "configure_krfb"]


def test_cli_accepts_only_configure_preview_and_start_with_vars_file() -> None:
    parser = build_parser()
    preview = parser.parse_args(
        [
            "--json",
            "configure",
            "preview",
            MACHINE_UUID,
            "--vars-file",
            "request.json",
        ]
    )
    start = parser.parse_args(
        [
            "configure",
            "start",
            MACHINE_UUID,
            "--vars-file",
            "request.json",
        ]
    )

    assert preview.command == "configure"
    assert preview.configure_command == "preview"
    assert preview.vars_file == "request.json"
    assert start.configure_command == "start"


@pytest.mark.parametrize(
    "result_payload",
    [
        valid_structured_result(),
        valid_structured_result() | {"status": "degraded"},
        valid_structured_result()
        | {
            "status": "failed",
            "phase": "domain_join",
            "error": {
                "code": "domain_join_failed",
                "class": "DomainJoinError",
                "safe_message": "Domain join failed",
            },
        },
    ],
    ids=["successful", "degraded", "failed"],
)
def test_configure_start_accepts_valid_structured_results(
    run_configure,
    result_payload: dict[str, object],
) -> None:
    result = run_configure(result_payload)

    assert result["schema_version"] == 1
    assert result["verification"] == {"domain_join": True}
    assert isinstance(result["run_id"], str)


@pytest.mark.parametrize(
    "result_payload",
    [
        valid_structured_result() | {"unexpected": True},
        valid_structured_result() | {"machine_uuid": "11111111-2222-3333-4444-555555555555"},
        valid_structured_result()
        | {
            "status": "failed",
            "error": {
                "code": "domain_join_failed\nsecret",
                "class": "DomainJoinError",
                "safe_message": "Domain join failed",
            },
        },
        valid_structured_result() | {"phase": "untrusted_phase"},
    ],
    ids=["unknown_field", "mismatched_machine", "unsafe_error", "unsupported_phase"],
)
def test_configure_start_rejects_untrusted_structured_results(
    run_configure,
    result_payload: dict[str, object],
) -> None:
    with pytest.raises(ControlError) as exc:
        run_configure(result_payload)

    assert exc.value.code == "domain_verification_failed"
    assert set(exc.value.details) == {"run_id"}


@pytest.mark.parametrize(
    ("code", "accepted"),
    [
        ("a", False),
        ("ab", True),
        ("a" + "x" * 64, True),
        ("a" + "x" * 79, True),
        ("a" + "x" * 80, False),
    ],
    ids=["one", "minimum", "sixty_five", "maximum", "eighty_one"],
)
def test_configure_start_enforces_failed_error_code_boundaries(
    run_configure,
    code: str,
    accepted: bool,
) -> None:
    result_payload = valid_structured_result() | {
        "status": "failed",
        "phase": "domain_join",
        "error": {
            "code": code,
            "class": "DomainJoinError",
            "safe_message": "Domain join failed",
        },
    }

    if accepted:
        assert run_configure(result_payload)["error"] == result_payload["error"]
    else:
        with pytest.raises(ControlError) as exc:
            run_configure(result_payload)
        assert exc.value.code == "domain_verification_failed"


@pytest.mark.parametrize(
    ("safe_message", "accepted"),
    [("", False), ("x" * 240, True), ("x" * 241, False)],
    ids=["empty", "maximum", "two_hundred_forty_one"],
)
def test_configure_start_enforces_failed_safe_message_boundaries(
    run_configure,
    safe_message: str,
    accepted: bool,
) -> None:
    result_payload = valid_structured_result() | {
        "status": "failed",
        "phase": "domain_join",
        "error": {
            "code": "domain_join_failed",
            "class": "DomainJoinError",
            "safe_message": safe_message,
        },
    }

    if accepted:
        assert run_configure(result_payload)["error"] == result_payload["error"]
    else:
        with pytest.raises(ControlError) as exc:
            run_configure(result_payload)
        assert exc.value.code == "domain_verification_failed"


@pytest.mark.parametrize(
    "change",
    [
        {"schema_version": 2},
        {"hostname": "wrong-host"},
        {"profile": "wrong-profile"},
        {"status": "pending"},
        {"status": []},
        {"phase": []},
        {"retryable": 1},
        {"recovered": "false"},
        {"reboot_required": 0},
        {"components": []},
        {"verification": []},
        {
            "error": {
                "code": "domain_join_failed",
                "class": "DomainJoinError",
                "safe_message": "Domain join failed",
            }
        },
        {"status": "failed", "error": None},
    ],
)
def test_configure_start_rejects_invalid_structured_contract_values(
    run_configure,
    change: dict[str, object],
) -> None:
    with pytest.raises(ControlError) as exc:
        run_configure(valid_structured_result() | change)

    assert exc.value.code == "domain_verification_failed"


@pytest.mark.parametrize(
    "result_payload",
    [
        {"machine_uuid": MACHINE_UUID, "hostname": "alt-a1-pc3", "profile": "standard-domain"},
        {
            "machine_uuid": MACHINE_UUID,
            "hostname": "alt-a1-pc3",
            "profile": "standard-domain",
            "verification": {},
            "unexpected": True,
        },
        {
            "machine_uuid": MACHINE_UUID,
            "hostname": "wrong-host",
            "profile": "standard-domain",
            "verification": {},
        },
    ],
    ids=["missing_verification", "extra_field", "mismatched_hostname"],
)
def test_configure_start_rejects_invalid_legacy_result(
    run_configure,
    result_payload: dict[str, object],
) -> None:
    with pytest.raises(ControlError) as exc:
        run_configure(result_payload)

    assert exc.value.code == "domain_verification_failed"


def test_configure_start_accepts_exact_stage_03_legacy_result(run_configure) -> None:
    result = run_configure(valid_legacy_result())

    assert result["domain"] == "sosnadmin.local"
    assert result["already_joined"] is True
    assert result["reboot_required"] is False
    assert result["verification"]["group_policy"] is False


@pytest.mark.parametrize(
    ("change", "missing"),
    [
        ({}, "domain"),
        ({"unexpected": True}, None),
        ({"machine_uuid": "11111111-2222-3333-4444-555555555555"}, None),
        ({"hostname": "wrong-host"}, None),
        ({"profile": "wrong-profile"}, None),
        ({"domain": "example.local"}, None),
        ({"already_joined": 1}, None),
        ({"reboot_required": "false"}, None),
        ({"verification": []}, None),
    ],
    ids=[
        "missing_field",
        "extra_field",
        "mismatched_machine_uuid",
        "mismatched_hostname",
        "mismatched_profile",
        "mismatched_domain",
        "already_joined_not_bool",
        "reboot_required_not_bool",
        "verification_not_mapping",
    ],
)
def test_configure_start_rejects_invalid_stage_03_legacy_result(
    run_configure,
    change: dict[str, object],
    missing: str | None,
) -> None:
    result_payload = valid_legacy_result() | change
    if missing is not None:
        result_payload.pop(missing)

    with pytest.raises(ControlError) as exc:
        run_configure(result_payload)

    assert exc.value.code == "domain_verification_failed"
    assert set(exc.value.details) == {"run_id"}


def test_configure_start_uses_fixed_playbook_and_private_run_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from alt_deploy.config import Settings
    from alt_deploy.vault import VaultHealthChecker

    settings = Settings(
        registration_root=tmp_path / "registration", state_root=tmp_path / "state",
        jobs_dir=tmp_path / "state" / "jobs", assignments_dir=tmp_path / "state" / "assignments",
        lock_file=tmp_path / "state" / "lock", ansible_project_dir=tmp_path / "ansible",
        known_hosts_file=tmp_path / "known_hosts", private_key_file=tmp_path / "id_ed25519",
        ansible_playbook_path=tmp_path / "ansible-playbook", systemd_run_path=tmp_path / "systemd-run",
        worker_path=tmp_path / "worker", job_stage_helper_path=tmp_path / "stage-helper",
        workstationctl_path=tmp_path / "workstationctl",
    )
    for path in (settings.known_hosts_file, settings.private_key_file, settings.ansible_playbook_path):
        path.write_text("fixture", encoding="utf-8")
    playbook = settings.ansible_project_dir / "playbooks" / "03-configure-domain-workstation.yml"
    playbook.parent.mkdir(parents=True)
    playbook.write_text("---\n- hosts: all\n", encoding="utf-8")
    machine = SimpleNamespace(uuid=MACHINE_UUID, ip="192.168.101.56")
    captured: list[str] = []

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        captured.extend(command)
        result_arg = next(item for item in command if item.startswith("configure_result_file="))
        result_path = Path(result_arg.split("=", 1)[1])
        result_path.write_text(
            json.dumps(
                valid_legacy_result()
            ),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(VaultHealthChecker, "check_ad_join", lambda _self: {"status": "ok"})
    request = ConfigureRequest.from_mapping(valid_request(), expected_uuid=MACHINE_UUID)
    result = ConfigurePlanner(settings, machines=SimpleNamespace(get=lambda _: machine)).start(MACHINE_UUID, request)

    assert "03-configure-domain-workstation.yml" in " ".join(captured)
    assert "192.168.101.56," in captured
    assert "ansible" in captured
    assert result["verification"]["domain_join"] is True
    if os.name != "nt":
        assert (settings.state_root / "configure-runs").stat().st_mode & 0o777 == 0o700


def test_ad_join_vault_gate_reports_only_boolean_checks() -> None:
    from alt_deploy.vault import VaultHealthChecker

    checker = VaultHealthChecker(SimpleNamespace())
    checker._build_checks = lambda: {"decryptable": True}  # type: ignore[method-assign]
    checker._decrypt = lambda: "vault_ad_join_user: joiner\nvault_ad_join_password: secret\n"  # type: ignore[method-assign]

    assert checker.check_ad_join() == {
        "status": "ok",
        "checks": {"ad_join_user_present": True, "ad_join_password_present": True},
    }


def test_configure_start_maps_known_hostname_marker_without_log_disclosure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from alt_deploy.config import Settings
    from alt_deploy.vault import VaultHealthChecker

    settings = Settings(
        registration_root=tmp_path / "registration", state_root=tmp_path / "state",
        jobs_dir=tmp_path / "state" / "jobs", assignments_dir=tmp_path / "state" / "assignments",
        lock_file=tmp_path / "state" / "lock", ansible_project_dir=tmp_path / "ansible",
        known_hosts_file=tmp_path / "known_hosts", private_key_file=tmp_path / "id_ed25519",
        ansible_playbook_path=tmp_path / "ansible-playbook", systemd_run_path=tmp_path / "systemd-run",
        worker_path=tmp_path / "worker", job_stage_helper_path=tmp_path / "stage-helper",
        workstationctl_path=tmp_path / "workstationctl",
    )
    for path in (settings.known_hosts_file, settings.private_key_file, settings.ansible_playbook_path):
        path.write_text("fixture", encoding="utf-8")
    playbook = settings.ansible_project_dir / "playbooks" / "03-configure-domain-workstation.yml"
    playbook.parent.mkdir(parents=True)
    playbook.write_text("---\n- hosts: all\n", encoding="utf-8")
    machine = SimpleNamespace(uuid=MACHINE_UUID, ip="192.168.101.56")

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        kwargs["stdout"].write("ALT_PREFLIGHT_FAILURE:hostname_mismatch\n")  # type: ignore[index,union-attr]
        return subprocess.CompletedProcess(command, 2)

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(VaultHealthChecker, "check_ad_join", lambda _self: {"status": "ok"})

    with pytest.raises(ControlError) as exc:
        ConfigurePlanner(
            settings, machines=SimpleNamespace(get=lambda _: machine)
        ).start(
            MACHINE_UUID,
            ConfigureRequest.from_mapping(valid_request(), expected_uuid=MACHINE_UUID),
        )

    assert exc.value.code == "hostname_mismatch"
    assert set(exc.value.details) == {"run_id"}


def test_configure_start_maps_long_running_timeout_without_disclosure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from alt_deploy.config import Settings
    from alt_deploy.vault import VaultHealthChecker

    settings = Settings(
        registration_root=tmp_path / "registration", state_root=tmp_path / "state",
        jobs_dir=tmp_path / "state" / "jobs", assignments_dir=tmp_path / "state" / "assignments",
        lock_file=tmp_path / "state" / "lock", ansible_project_dir=tmp_path / "ansible",
        known_hosts_file=tmp_path / "known_hosts", private_key_file=tmp_path / "id_ed25519",
        ansible_playbook_path=tmp_path / "ansible-playbook", systemd_run_path=tmp_path / "systemd-run",
        worker_path=tmp_path / "worker", job_stage_helper_path=tmp_path / "stage-helper",
        workstationctl_path=tmp_path / "workstationctl",
    )
    for path in (settings.known_hosts_file, settings.private_key_file, settings.ansible_playbook_path):
        path.write_text("fixture", encoding="utf-8")
    playbook = settings.ansible_project_dir / "playbooks" / "03-configure-domain-workstation.yml"
    playbook.parent.mkdir(parents=True)
    playbook.write_text("---\n- hosts: all\n", encoding="utf-8")
    machine = SimpleNamespace(uuid=MACHINE_UUID, ip="192.168.101.56")
    timeout_error = subprocess.TimeoutExpired(["ansible-playbook"], 5400)
    timeouts: list[int] = []

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        timeouts.append(kwargs["timeout"])  # type: ignore[arg-type]
        raise timeout_error

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(VaultHealthChecker, "check_ad_join", lambda _self: {"status": "ok"})

    with pytest.raises(ControlError) as exc:
        ConfigurePlanner(
            settings, machines=SimpleNamespace(get=lambda _: machine)
        ).start(
            MACHINE_UUID,
            ConfigureRequest.from_mapping(valid_request(), expected_uuid=MACHINE_UUID),
        )

    assert timeouts == [5400]
    assert exc.value.code == "domain_join_timeout"
    assert exc.value.exit_code == 7
    assert exc.value.message == "Ansible domain configure timed out"
    assert set(exc.value.details) == {"run_id"}
    assert isinstance(exc.value.details["run_id"], str)
    assert exc.value.__cause__ is timeout_error
