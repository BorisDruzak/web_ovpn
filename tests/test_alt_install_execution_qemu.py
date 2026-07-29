from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
QEMU_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "qemu"
SUPPORT = QEMU_ROOT / "agent_v2_test_api.py"
HARNESS = QEMU_ROOT / "run-agent-v2-execution-acceptance.sh"
PASS_LINE = (
    "PASS: root-authorized install wrote only the disposable target; "
    "authenticated postflight installed"
)


@dataclass(frozen=True)
class WriteEvidence:
    target_write_bytes: int
    sentinel_write_bytes: int


@dataclass(frozen=True)
class AcceptanceEvidence:
    before_authorization: WriteEvidence
    after_install: WriteEvidence
    postflight_state: str


def _support_command(
    *arguments: str,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SUPPORT), *arguments],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def _write_qmp(
    path: Path,
    *,
    target_write_bytes: int,
    sentinel_write_bytes: int,
    nested_sentinel_write_bytes: int = 0,
    target_read_only: bool = False,
    sentinel_read_only: bool = True,
) -> None:
    def statistics(
        device: str,
        writes: int,
        *,
        nested_writes: int = 0,
    ) -> dict[str, object]:
        return {
            "device": device,
            "stats": {
                "rd_bytes": 4096,
                "rd_operations": 1,
                "wr_bytes": writes,
                "wr_operations": 0 if writes == 0 else 1,
                "wr_total_time_ns": 0 if writes == 0 else 100,
            },
            "parent": {
                "node-name": f"{device}-file",
                "stats": {
                    "rd_bytes": 4096,
                    "rd_operations": 1,
                    "wr_bytes": nested_writes or writes,
                    "wr_operations": (
                        0 if (nested_writes or writes) == 0 else 1
                    ),
                    "wr_total_time_ns": (
                        0 if (nested_writes or writes) == 0 else 100
                    ),
                },
            },
        }

    messages = [
        {"QMP": {"version": {"qemu": {"major": 9, "minor": 0, "micro": 0}}}},
        {"return": {}},
        {
            "return": [
                statistics("target", target_write_bytes),
                statistics(
                    "sentinel",
                    sentinel_write_bytes,
                    nested_writes=nested_sentinel_write_bytes,
                ),
            ]
        },
        {
            "return": [
                {
                    "device": "target",
                    "inserted": {
                        "backing_file_depth": 0,
                        "drv": "qcow2",
                        "file": "target.qcow2",
                        "ro": target_read_only,
                    },
                },
                {
                    "device": "sentinel",
                    "inserted": {
                        "backing_file_depth": 0,
                        "drv": "qcow2",
                        "file": "sentinel.qcow2",
                        "ro": sentinel_read_only,
                    },
                },
            ]
        },
    ]
    path.write_text(
        "".join(
            json.dumps(message, sort_keys=True) + "\n"
            for message in messages
        ),
        encoding="utf-8",
    )


def _write_sha(path: Path, digest: str, filename: str) -> None:
    path.write_text(f"{digest}  {filename}\n", encoding="ascii")


def _timeline() -> dict[str, object]:
    return {
        "schema_version": 1,
        "session_id": "install-20260729T120000Z-a1b2c3d4",
        "target_disk": "/dev/vda",
        "operator_uid": 0,
        "waiting_for_authorization_at": "2026-07-29T12:01:00+00:00",
        "preflight_ready_at": "2026-07-29T12:01:30+00:00",
        "root_authorized_at": "2026-07-29T12:02:00+00:00",
        "execution_claimed_at": "2026-07-29T12:02:10+00:00",
        "verified_handoff_at": "2026-07-29T12:02:20+00:00",
        "installer_completed_at": "2026-07-29T12:22:00+00:00",
        "postflight_authenticated_at": "2026-07-29T12:23:00+00:00",
    }


def _postflight() -> dict[str, object]:
    return {
        "schema_version": 1,
        "session_id": "install-20260729T120000Z-a1b2c3d4",
        "authenticated": True,
        "boot_source": "target-without-iso",
        "state": "installed",
        "reported_at": "2026-07-29T12:23:00+00:00",
    }


def _verify_evidence(
    tmp_path: Path,
    *,
    before_target_writes: int = 0,
    before_sentinel_writes: int = 0,
    after_target_writes: int = 8192,
    after_sentinel_writes: int = 0,
    nested_sentinel_writes: int = 0,
    target_before_sha: str = "a" * 64,
    target_after_sha: str = "b" * 64,
    sentinel_before_sha: str = "c" * 64,
    sentinel_after_sha: str = "c" * 64,
    timeline: dict[str, object] | None = None,
    postflight: dict[str, object] | None = None,
) -> tuple[subprocess.CompletedProcess[str], Path]:
    before_qmp = tmp_path / "before-authorization.qmp.jsonl"
    after_qmp = tmp_path / "after-install.qmp.jsonl"
    _write_qmp(
        before_qmp,
        target_write_bytes=before_target_writes,
        sentinel_write_bytes=before_sentinel_writes,
    )
    _write_qmp(
        after_qmp,
        target_write_bytes=after_target_writes,
        sentinel_write_bytes=after_sentinel_writes,
        nested_sentinel_write_bytes=nested_sentinel_writes,
    )
    records = {
        "target_before": (target_before_sha, "target.qcow2"),
        "target_after": (target_after_sha, "target.qcow2"),
        "sentinel_before": (sentinel_before_sha, "sentinel.qcow2"),
        "sentinel_after": (sentinel_after_sha, "sentinel.qcow2"),
    }
    paths: dict[str, Path] = {}
    for name, (digest, filename) in records.items():
        paths[name] = tmp_path / f"{name}.sha256"
        _write_sha(paths[name], digest, filename)
    timeline_path = tmp_path / "authorization-timeline.json"
    timeline_path.write_text(
        json.dumps(timeline or _timeline(), sort_keys=True) + "\n",
        encoding="utf-8",
    )
    postflight_path = tmp_path / "postflight.json"
    postflight_path.write_text(
        json.dumps(postflight or _postflight(), sort_keys=True) + "\n",
        encoding="utf-8",
    )
    output = tmp_path / "acceptance-receipt.json"
    completed = _support_command(
        "finalize-evidence",
        "--before-qmp",
        str(before_qmp),
        "--after-qmp",
        str(after_qmp),
        "--target-before-sha",
        str(paths["target_before"]),
        "--target-after-sha",
        str(paths["target_after"]),
        "--sentinel-before-sha",
        str(paths["sentinel_before"]),
        "--sentinel-after-sha",
        str(paths["sentinel_after"]),
        "--timeline",
        str(timeline_path),
        "--postflight",
        str(postflight_path),
        "--output",
        str(output),
    )
    return completed, output


@pytest.fixture
def evidence(tmp_path: Path) -> AcceptanceEvidence:
    completed, output = _verify_evidence(tmp_path)
    assert completed.returncode == 0, completed.stderr
    receipt = json.loads(output.read_text(encoding="utf-8"))
    return AcceptanceEvidence(
        before_authorization=WriteEvidence(
            **{
                key: receipt["before_authorization"][key]
                for key in ("target_write_bytes", "sentinel_write_bytes")
            }
        ),
        after_install=WriteEvidence(
            **{
                key: receipt["after_install"][key]
                for key in ("target_write_bytes", "sentinel_write_bytes")
            }
        ),
        postflight_state=receipt["postflight_state"],
    )


def test_execution_requires_root_authorization_and_never_writes_sentinel(
    evidence: AcceptanceEvidence,
) -> None:
    assert evidence.before_authorization.target_write_bytes == 0
    assert evidence.before_authorization.sentinel_write_bytes == 0
    assert evidence.after_install.target_write_bytes > 0
    assert evidence.after_install.sentinel_write_bytes == 0
    assert evidence.postflight_state == "installed"


def test_receipt_is_exact_non_secret_generic_ovmf_evidence(
    tmp_path: Path,
) -> None:
    completed, output = _verify_evidence(tmp_path)

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == PASS_LINE + "\n"
    receipt = json.loads(output.read_text(encoding="utf-8"))
    assert set(receipt) == {
        "acceptance_scope",
        "after_install",
        "authorization_timeline",
        "before_authorization",
        "firmware",
        "postflight",
        "postflight_state",
        "result",
        "schema_version",
        "session_id",
        "target_disk",
    }
    assert receipt["schema_version"] == 1
    assert receipt["acceptance_scope"] == "generic-ovmf-disposable"
    assert receipt["firmware"] == "generic-ovmf"
    assert receipt["target_disk"] == "/dev/vda"
    assert receipt["result"] == "pass"
    assert receipt["before_authorization"] == {
        "sentinel_read_only": True,
        "sentinel_sha256": "c" * 64,
        "sentinel_write_bytes": 0,
        "target_read_only": False,
        "target_sha256": "a" * 64,
        "target_write_bytes": 0,
    }
    assert receipt["after_install"] == {
        "sentinel_read_only": True,
        "sentinel_sha256": "c" * 64,
        "sentinel_write_bytes": 0,
        "target_read_only": False,
        "target_sha256": "b" * 64,
        "target_write_bytes": 8192,
    }
    serialized = json.dumps(receipt, sort_keys=True).lower()
    assert "credential" not in serialized
    assert "password" not in serialized
    assert "private" not in serialized
    assert "bearer" not in serialized


@pytest.mark.parametrize(
    ("mutation", "expected_error"),
    [
        ({"before_target_writes": 4096}, "before authorization"),
        ({"before_sentinel_writes": 4096}, "sentinel write"),
        ({"after_target_writes": 0}, "target write"),
        ({"after_sentinel_writes": 4096}, "sentinel write"),
        ({"nested_sentinel_writes": 4096}, "sentinel write"),
        ({"target_after_sha": "a" * 64}, "Target SHA-256 did not change"),
        ({"sentinel_after_sha": "d" * 64}, "Sentinel SHA-256 changed"),
    ],
)
def test_evidence_gate_fails_closed_on_write_boundary_mutation(
    tmp_path: Path,
    mutation: dict[str, object],
    expected_error: str,
) -> None:
    completed, output = _verify_evidence(tmp_path, **mutation)

    assert completed.returncode == 1
    assert expected_error in completed.stderr
    assert PASS_LINE not in completed.stdout
    assert not output.exists()


@pytest.mark.parametrize("mutation", ["not_root", "out_of_order", "postflight"])
def test_evidence_gate_requires_ordered_root_and_authenticated_postflight(
    tmp_path: Path,
    mutation: str,
) -> None:
    timeline = _timeline()
    postflight = _postflight()
    if mutation == "not_root":
        timeline["operator_uid"] = 1000
    elif mutation == "out_of_order":
        timeline["root_authorized_at"] = "2026-07-29T12:24:00+00:00"
    else:
        postflight["authenticated"] = False

    completed, output = _verify_evidence(
        tmp_path, timeline=timeline, postflight=postflight
    )

    assert completed.returncode == 1
    assert PASS_LINE not in completed.stdout
    assert not output.exists()


def _bash() -> Path:
    for candidate in (
        shutil.which("bash"),
        r"C:\Program Files\Git\bin\bash.exe",
    ):
        if candidate and Path(candidate).is_file():
            return Path(candidate)
    pytest.skip("Bash is required for the QEMU harness contract")


def test_prerequisite_check_enumerates_missing_tools_without_acceptance(
    tmp_path: Path,
) -> None:
    completed = subprocess.run(
        [str(_bash()), HARNESS.as_posix(), "--check-prerequisites"],
        cwd=REPO_ROOT,
        env={**os.environ, "PATH": str(tmp_path)},
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 1
    for command in (
        "qemu-system-x86_64",
        "qemu-img",
        "python3",
        "xorriso",
        "cpio",
        "socat",
    ):
        assert f"Missing required command: {command}" in completed.stderr
    assert "prerequisites are available" not in completed.stdout
    assert PASS_LINE not in completed.stdout


@pytest.mark.parametrize(
    "argument",
    [
        "--target",
        "--proxmox-vm",
        "--controller",
    ],
)
def test_harness_rejects_real_target_and_infrastructure_inputs(
    argument: str,
) -> None:
    completed = subprocess.run(
        [str(_bash()), HARNESS.as_posix(), argument, "/dev/sda"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 2
    assert (
        "Usage: run-agent-v2-execution-acceptance.sh"
        in completed.stderr
    )
    assert PASS_LINE not in completed.stdout


def test_harness_reports_only_the_generic_disposable_execution_contract() -> None:
    completed = subprocess.run(
        [str(_bash()), HARNESS.as_posix(), "--describe-safety-contract"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == (
        "target_input=none\n"
        "firmware=generic-ovmf\n"
        "target_device=/dev/vda\n"
        "target_virtual_size=64G\n"
        "target_drive=qcow2,writable\n"
        "sentinel_virtual_size=8M\n"
        "sentinel_drive=qcow2,readonly=on\n"
        "iso_first_boot=required\n"
        "iso_postflight_boot=absent\n"
        "network=tap,harness-created\n"
        "cleanup=qemu,tap,temporary-directory;validated-harness-owned-only\n"
    )


def test_harness_exercises_disposable_target_and_sentinel_cleanup(
    tmp_path: Path,
) -> None:
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    qemu_img_log = tmp_path / "qemu-img.log"
    fake_qemu_img = fake_bin / "qemu-img"
    fake_qemu_img.write_text(
        """#!/bin/bash
set -eu
printf '%s\\n' "$*" >>"$FAKE_QEMU_IMG_LOG"
output="${@: -2:1}"
[[ "${!#}" == 64G || "${!#}" == 8M ]] && output="${@: -2:1}"
: >"$output"
""",
        encoding="utf-8",
        newline="\n",
    )
    fake_qemu_img.chmod(0o755)
    contract_tmp = tmp_path / "contract-tmp"
    contract_tmp.mkdir()
    environment = os.environ.copy()
    environment["PATH"] = (
        f"{fake_bin}{os.pathsep}{environment['PATH']}"
    )
    environment["FAKE_QEMU_IMG_LOG"] = qemu_img_log.as_posix()
    environment["TMPDIR"] = contract_tmp.as_posix()

    completed = subprocess.run(
        [str(_bash()), HARNESS.as_posix(), "--exercise-storage-contract"],
        cwd=REPO_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    contract = dict(
        line.split("=", 1)
        for line in completed.stdout.splitlines()
        if "=" in line
    )
    workdir = contract["workdir"]
    assert contract["target"] == f"{workdir}/target.qcow2"
    assert contract["sentinel"] == f"{workdir}/sentinel.qcow2"
    assert contract["target_drive"] == (
        f"id=target,if=none,format=qcow2,file={workdir}/target.qcow2,"
        "cache=none"
    )
    assert contract["sentinel_drive"] == (
        f"id=sentinel,if=none,format=qcow2,"
        f"file={workdir}/sentinel.qcow2,cache=none,readonly=on"
    )
    assert contract["cleanup"] == "removed"
    assert "/dev/" not in "\n".join(
        line
        for line in completed.stdout.splitlines()
        if not line.startswith("target_device=")
    )
    assert qemu_img_log.read_text(encoding="utf-8").splitlines() == [
        f"create -f qcow2 {workdir}/target.qcow2 64G",
        f"create -f qcow2 {workdir}/sentinel.qcow2 8M",
    ]
    assert not any(contract_tmp.iterdir())
