from __future__ import annotations

import sys
from pathlib import Path

import pytest


CONTROL_ROOT = (
    Path(__file__).resolve().parents[1]
    / "deploy"
    / "alt-linux"
    / "control"
)
sys.path.insert(0, str(CONTROL_ROOT))

from alt_deploy.configure import ConfigureRequest
from alt_deploy.errors import ControlError


MACHINE_UUID = "53b03180-5d78-11f0-bd95-f027db877a00"


def valid_request() -> dict[str, str]:
    return {
        "machine_uuid": MACHINE_UUID,
        "final_hostname": "alt-ws-001",
        "profile": "standard-domain",
        "domain": "sosnadmin.local",
        "realm": "SOSNADMIN.LOCAL",
        "workgroup": "SOSNADMIN",
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
