from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


REPO_ROOT = Path(__file__).resolve().parents[1]
QEMU_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "qemu"
SUPPORT = QEMU_ROOT / "agent_v1_test_api.py"
HARNESS = QEMU_ROOT / "run-agent-v1-dry-run-acceptance.sh"
PASS_LINE = (
    "PASS: signed plan verified; disk preflight passed; no target writes"
)


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
    writes: int = 0,
    nested_writes: int | None = None,
    device: str = "target",
) -> None:
    target = {
        "device": device,
        "stats": {
            "rd_bytes": 4096,
            "rd_operations": 1,
            "wr_bytes": writes,
            "wr_operations": 0 if writes == 0 else 1,
            "wr_total_time_ns": 0 if writes == 0 else 100,
        },
    }
    if nested_writes is not None:
        target["backing"] = {
            "node-name": "backing-node",
            "stats": {
                "rd_bytes": 4096,
                "rd_operations": 1,
                "wr_bytes": nested_writes,
                "wr_operations": 0 if nested_writes == 0 else 1,
                "wr_total_time_ns": 0 if nested_writes == 0 else 100,
            },
        }
    messages = [
        {"QMP": {"version": {"qemu": {"major": 9, "minor": 0, "micro": 0}}}},
        {"return": {}},
        {"return": [target]},
    ]
    path.write_text(
        "".join(
            json.dumps(message, sort_keys=True) + "\n"
            for message in messages
        ),
        encoding="utf-8",
    )


def _write_sha(path: Path, digest: str) -> None:
    path.write_text(f"{digest}  disposable-backing.qcow2\n", encoding="ascii")


def _verify_variant(
    tmp_path: Path,
    *,
    variant: str = "writable",
    after_writes: int = 0,
    after_nested_writes: int | None = None,
    after_device: str = "target",
    after_digest: str = "a" * 64,
) -> subprocess.CompletedProcess[str]:
    before_qmp = tmp_path / f"{variant}.before.qmp.jsonl"
    after_qmp = tmp_path / f"{variant}.after.qmp.jsonl"
    before_sha = tmp_path / f"{variant}.before.sha256"
    after_sha = tmp_path / f"{variant}.after.sha256"
    output = tmp_path / f"{variant}.summary.json"
    _write_qmp(before_qmp)
    _write_qmp(
        after_qmp,
        writes=after_writes,
        nested_writes=after_nested_writes,
        device=after_device,
    )
    _write_sha(before_sha, "a" * 64)
    _write_sha(after_sha, after_digest)
    return _support_command(
        "verify-variant",
        "--variant",
        variant,
        "--before-qmp",
        str(before_qmp),
        "--after-qmp",
        str(after_qmp),
        "--before-sha",
        str(before_sha),
        "--after-sha",
        str(after_sha),
        "--output",
        str(output),
    )


def test_writable_qmp_contract_records_zero_writes_and_equal_backing_sha(
    tmp_path: Path,
) -> None:
    completed = _verify_variant(tmp_path)

    assert completed.returncode == 0, completed.stderr
    summary = json.loads(
        (tmp_path / "writable.summary.json").read_text(encoding="utf-8")
    )
    assert summary == {
        "backing_sha256": "a" * 64,
        "device": "target",
        "qmp_write_counters_after": {
            "wr_bytes": 0,
            "wr_operations": 0,
            "wr_total_time_ns": 0,
        },
        "qmp_write_counters_before": {
            "wr_bytes": 0,
            "wr_operations": 0,
            "wr_total_time_ns": 0,
        },
        "qmp_write_graph_after": {
            "target": {
                "wr_bytes": 0,
                "wr_operations": 0,
                "wr_total_time_ns": 0,
            }
        },
        "qmp_write_graph_before": {
            "target": {
                "wr_bytes": 0,
                "wr_operations": 0,
                "wr_total_time_ns": 0,
            }
        },
        "variant": "writable",
        "zero_target_writes": True,
    }


@pytest.mark.parametrize(
    ("mutation", "expected_error"),
    [
        ({"after_writes": 4096}, "non-zero QMP target write counter"),
        (
            {"after_nested_writes": 4096},
            "non-zero QMP target write counter",
        ),
        ({"after_device": "another-disk"}, "QMP target device is absent"),
        ({"after_digest": "b" * 64}, "Backing SHA-256 changed"),
    ],
)
def test_variant_verifier_fails_closed_on_incomplete_zero_write_evidence(
    tmp_path: Path,
    mutation: dict[str, object],
    expected_error: str,
) -> None:
    completed = _verify_variant(tmp_path, **mutation)

    assert completed.returncode == 1
    assert expected_error in completed.stderr
    assert not (tmp_path / "writable.summary.json").exists()


def test_fixture_prepare_generates_an_ephemeral_matching_ed25519_keypair(
    tmp_path: Path,
) -> None:
    state = tmp_path / "fixture"
    state.mkdir()

    completed = _support_command("prepare", "--state-dir", str(state))

    assert completed.returncode == 0, completed.stderr
    assert "PRIVATE KEY" not in completed.stdout
    private_path = state / "install-plan-ed25519.pem"
    public_path = state / "install-plan-ed25519.pub"
    private_key = serialization.load_pem_private_key(
        private_path.read_bytes(), password=None
    )
    assert isinstance(private_key, Ed25519PrivateKey)
    public_document = json.loads(public_path.read_text(encoding="utf-8"))
    public_raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    assert (
        public_document["public_key_b64"]
        == __import__("base64").b64encode(public_raw).decode("ascii")
    )
    assert list((state / "sessions").glob("install-*")) == []
    if os.name != "nt":
        assert private_path.stat().st_mode & 0o777 == 0o600
        assert public_path.stat().st_mode & 0o777 == 0o644


def test_fixture_approval_gate_rejects_a_non_root_process() -> None:
    specification = importlib.util.spec_from_file_location(
        "agent_v1_test_api", SUPPORT
    )
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)

    with pytest.raises(RuntimeError, match="real root approval is required"):
        module.require_real_root(1000)


def _write_variant_summary(path: Path, variant: str) -> None:
    path.write_text(
        json.dumps(
            {
                "backing_sha256": "a" * 64,
                "device": "target",
                "qmp_write_counters_after": {
                    "wr_bytes": 0,
                    "wr_operations": 0,
                },
                "qmp_write_counters_before": {
                    "wr_bytes": 0,
                    "wr_operations": 0,
                },
                "qmp_write_graph_after": {
                    "target": {
                        "wr_bytes": 0,
                        "wr_operations": 0,
                    }
                },
                "qmp_write_graph_before": {
                    "target": {
                        "wr_bytes": 0,
                        "wr_operations": 0,
                    }
                },
                "variant": variant,
                "zero_target_writes": True,
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def _write_fixture_report(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "public_key_id": "sha256:" + ("c" * 64),
                "sessions": [
                    {
                        "operator_uid": 0,
                        "plan_revision": 1,
                        "reported_stage": "preflight_ready",
                        "root_approved": True,
                        "session_id": "install-20260727T120000Z-a1b2c3d4",
                        "state": "plan_published",
                    },
                    {
                        "operator_uid": 0,
                        "plan_revision": 1,
                        "reported_stage": "preflight_ready",
                        "root_approved": True,
                        "session_id": "install-20260727T120100Z-a1b2c3d5",
                        "state": "plan_published",
                    },
                ],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def test_final_gate_requires_both_variants_and_emits_the_exact_pass_line(
    tmp_path: Path,
) -> None:
    writable = tmp_path / "writable.summary.json"
    readonly = tmp_path / "readonly.summary.json"
    fixture = tmp_path / "fixture-report.json"
    output = tmp_path / "acceptance-summary.json"
    _write_variant_summary(writable, "writable")
    _write_variant_summary(readonly, "readonly")
    _write_fixture_report(fixture)

    completed = _support_command(
        "finalize-evidence",
        "--variant-summary",
        str(writable),
        "--variant-summary",
        str(readonly),
        "--fixture-report",
        str(fixture),
        "--output",
        str(output),
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == PASS_LINE + "\n"
    result = json.loads(output.read_text(encoding="utf-8"))
    assert result["result"] == "pass"
    assert result["variants"] == ["readonly", "writable"]
    assert result["session_count"] == 2


def test_final_gate_refuses_to_pass_without_the_readonly_guard(
    tmp_path: Path,
) -> None:
    writable = tmp_path / "writable.summary.json"
    fixture = tmp_path / "fixture-report.json"
    _write_variant_summary(writable, "writable")
    _write_fixture_report(fixture)

    completed = _support_command(
        "finalize-evidence",
        "--variant-summary",
        str(writable),
        "--fixture-report",
        str(fixture),
        "--output",
        str(tmp_path / "acceptance-summary.json"),
    )

    assert completed.returncode == 1
    assert "writable and readonly evidence are both required" in completed.stderr
    assert PASS_LINE not in completed.stdout


def _bash() -> Path:
    for candidate in (
        shutil.which("bash"),
        r"C:\Program Files\Git\bin\bash.exe",
    ):
        if candidate and Path(candidate).is_file():
            return Path(candidate)
    pytest.skip("Bash is required for the QEMU harness contract")


def test_harness_prerequisite_check_fails_closed_when_qemu_is_absent(
    tmp_path: Path,
) -> None:
    environment = os.environ.copy()
    environment["PATH"] = str(tmp_path)

    completed = subprocess.run(
        [str(_bash()), HARNESS.as_posix(), "--check-prerequisites"],
        cwd=REPO_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 1
    assert "Missing required command: qemu-system-x86_64" in completed.stderr
    assert "Missing required command: qemu-img" in completed.stderr
    assert PASS_LINE not in completed.stdout
