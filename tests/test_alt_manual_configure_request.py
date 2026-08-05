from __future__ import annotations

import sys
import types
from pathlib import Path
from types import SimpleNamespace

import pytest


CONTROL_ROOT = (
    Path(__file__).resolve().parents[1]
    / "deploy"
    / "alt-linux"
    / "control"
)
sys.path.insert(0, str(CONTROL_ROOT))

if sys.platform == "win32":
    sys.modules["fcntl"] = types.SimpleNamespace(
        LOCK_EX=2,
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

from alt_deploy.configure import ConfigureRequest
from alt_deploy.configure import ConfigurePlanner
from alt_deploy.errors import ControlError


MACHINE_UUID = "53b03180-5d78-11f0-bd95-f027db877a00"


def valid_request() -> dict[str, str]:
    return {
        "machine_uuid": MACHINE_UUID,
        "final_hostname": "alt-ws-001",
        "profile": "standard-domain",
        "domain": "sosnadmin.local",
        "realm": "SOSNADMIN.LOCAL",
        "workgroup": "SOSNADM",
        "computer_ou": "OU=Workstations,DC=sosnadmin,DC=local",
        "domain_test_user": "pilot.user",
    }


def test_configure_request_normalizes_safe_values() -> None:
    payload = valid_request()
    payload["final_hostname"] = "ALT-WS-001"

    request = ConfigureRequest.from_mapping(
        payload,
        expected_uuid=MACHINE_UUID,
    )

    assert request.to_dict() == {
        **valid_request(),
        "final_hostname": "alt-ws-001",
    }


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
        ({"final_hostname": "alt_ws_001"}, "configure_request_invalid"),
        ({"machine_uuid": "not-a-uuid"}, "configure_request_invalid"),
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
        "request": valid_request(),
        "actions": [
            "manual_preflight",
            "set_final_hostname",
            "configure_domain_dns",
            "join_or_verify_domain",
            "install_standard_packages",
            "verify_domain_workstation",
        ],
    }


def test_cli_accepts_only_configure_preview_and_start_with_vars_file() -> None:
    from alt_deploy.cli import build_parser

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
