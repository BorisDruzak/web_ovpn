from __future__ import annotations

import json
from pathlib import Path

from support.lifecycle_fixtures import (
    TEST_MACHINE_MAC,
    TEST_MACHINE_UUID,
    TEST_REGISTRATION_ID,
)
from support.register_helper_sandbox import HELPER, run_helper


def test_helper_posts_identity_and_accepts_registered(
    tmp_path: Path,
) -> None:
    run = run_helper(tmp_path)

    assert run.result.returncode == 0, run.result.stderr
    assert len(run.curl_calls) == 1
    assert run.curl_calls[0]["url"] == (
        "http://127.0.0.1:18088/register"
    )
    assert json.loads(str(run.curl_calls[0]["body"])) == {
        "hostname": "alt-lifecycle-test",
        "mac": TEST_MACHINE_MAC,
        "uuid": TEST_MACHINE_UUID,
    }
    assert json.loads(run.result.stdout)["status"] == "registered"


def test_helper_accepts_already_registered(
    tmp_path: Path,
) -> None:
    run = run_helper(
        tmp_path,
        http_status=200,
        response={
            "status": "already_registered",
            "machine_key": TEST_MACHINE_UUID,
            "registration_id": TEST_REGISTRATION_ID,
            "registration_state": "ready",
        },
    )

    assert run.result.returncode == 0
    assert json.loads(run.result.stdout)["status"] == (
        "already_registered"
    )


def test_helper_requires_root_before_network(
    tmp_path: Path,
) -> None:
    run = run_helper(tmp_path, uid=1000)

    assert run.result.returncode == 6
    assert "Run as root" in run.result.stderr
    assert run.curl_calls == []


def test_helper_rejects_missing_default_interface(
    tmp_path: Path,
) -> None:
    run = run_helper(tmp_path, interface="")

    assert run.result.returncode != 0
    assert run.curl_calls == []


def test_helper_allows_empty_dmi_uuid(
    tmp_path: Path,
) -> None:
    run = run_helper(
        tmp_path,
        machine_uuid="",
        response={
            "status": "registered",
            "machine_key": TEST_MACHINE_MAC.replace(":", ""),
            "registration_id": TEST_REGISTRATION_ID,
            "ip": "192.168.101.56",
        },
    )

    assert run.result.returncode == 0
    assert json.loads(str(run.curl_calls[0]["body"]))["uuid"] == ""


def test_helper_returns_nonzero_for_lifecycle_conflict(
    tmp_path: Path,
) -> None:
    run = run_helper(
        tmp_path,
        http_status=409,
        response={
            "status": "error",
            "error": {"code": "machine_assigned"},
        },
    )

    assert run.result.returncode != 0
    assert json.loads(run.result.stdout)["error"]["code"] == (
        "machine_assigned"
    )


def test_helper_returns_nonzero_for_malformed_response(
    tmp_path: Path,
) -> None:
    run = run_helper(
        tmp_path,
        http_status=201,
        response="not-json",
    )

    assert run.result.returncode != 0


def test_helper_returns_nonzero_for_network_failure(
    tmp_path: Path,
) -> None:
    run = run_helper(tmp_path, curl_rc=7)

    assert run.result.returncode != 0


def test_helper_is_registration_only() -> None:
    source = HELPER.read_text(encoding="utf-8")

    assert "/var/lib/alt-bootstrap-completed" not in source
    assert "/var/lib/alt-bootstrap-registered" not in source
    for forbidden in (
        "apt-get",
        "useradd",
        "usermod",
        "systemctl",
        "visudo",
        "authorized_keys",
        "sudoers",
    ):
        assert forbidden not in source
