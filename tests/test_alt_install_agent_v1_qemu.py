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
    read_only: bool = False,
    backing_depth: int = 1,
    include_parent: bool = True,
    include_backing: bool = True,
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
    if include_parent:
        target["parent"] = {
            "node-name": "target-file",
            "stats": {
                "rd_bytes": 4096,
                "rd_operations": 1,
                "wr_bytes": 0,
                "wr_operations": 0,
                "wr_total_time_ns": 0,
            },
        }
    if include_backing:
        target["backing"] = {
            "node-name": "backing-format",
            "stats": {
                "rd_bytes": 4096,
                "rd_operations": 1,
                "wr_bytes": nested_writes or 0,
                "wr_operations": 1 if nested_writes else 0,
                "wr_total_time_ns": 100 if nested_writes else 0,
            },
            "parent": {
                "node-name": "backing-file",
                "stats": {
                    "rd_bytes": 4096,
                    "rd_operations": 1,
                    "wr_bytes": 0,
                    "wr_operations": 0,
                    "wr_total_time_ns": 0,
                },
            },
        }
    messages = [
        {"QMP": {"version": {"qemu": {"major": 9, "minor": 0, "micro": 0}}}},
        {"return": {}},
        {"return": [target]},
        {
            "return": [
                {
                    "device": device,
                    "inserted": {
                        "backing_file_depth": backing_depth,
                        "drv": "qcow2",
                        "file": "disposable-target.qcow2",
                        "ro": read_only,
                    },
                }
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
    read_only: bool | None = None,
    backing_depth: int | None = None,
    include_parent: bool = True,
    include_backing: bool | None = None,
) -> subprocess.CompletedProcess[str]:
    before_qmp = tmp_path / f"{variant}.before.qmp.jsonl"
    after_qmp = tmp_path / f"{variant}.after.qmp.jsonl"
    before_sha = tmp_path / f"{variant}.before.sha256"
    after_sha = tmp_path / f"{variant}.after.sha256"
    output = tmp_path / f"{variant}.summary.json"
    expected_read_only = variant == "readonly"
    expected_depth = 0 if expected_read_only else 1
    expected_backing = not expected_read_only
    actual_read_only = (
        expected_read_only if read_only is None else read_only
    )
    actual_depth = (
        expected_depth if backing_depth is None else backing_depth
    )
    actual_backing = (
        expected_backing if include_backing is None else include_backing
    )
    _write_qmp(
        before_qmp,
        read_only=actual_read_only,
        backing_depth=actual_depth,
        include_parent=include_parent,
        include_backing=actual_backing,
    )
    _write_qmp(
        after_qmp,
        writes=after_writes,
        nested_writes=after_nested_writes,
        device=after_device,
        read_only=actual_read_only,
        backing_depth=actual_depth,
        include_parent=include_parent,
        include_backing=actual_backing,
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
            },
            "target.backing": {
                "wr_bytes": 0,
                "wr_operations": 0,
                "wr_total_time_ns": 0,
            },
            "target.backing.parent": {
                "wr_bytes": 0,
                "wr_operations": 0,
                "wr_total_time_ns": 0,
            },
            "target.parent": {
                "wr_bytes": 0,
                "wr_operations": 0,
                "wr_total_time_ns": 0,
            },
        },
        "qmp_write_graph_before": {
            "target": {
                "wr_bytes": 0,
                "wr_operations": 0,
                "wr_total_time_ns": 0,
            },
            "target.backing": {
                "wr_bytes": 0,
                "wr_operations": 0,
                "wr_total_time_ns": 0,
            },
            "target.backing.parent": {
                "wr_bytes": 0,
                "wr_operations": 0,
                "wr_total_time_ns": 0,
            },
            "target.parent": {
                "wr_bytes": 0,
                "wr_operations": 0,
                "wr_total_time_ns": 0,
            },
        },
        "qmp_backing_depth_after": 1,
        "qmp_backing_depth_before": 1,
        "qmp_inserted_read_only_after": False,
        "qmp_inserted_read_only_before": False,
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


def test_readonly_variant_rejects_a_writable_inserted_target(
    tmp_path: Path,
) -> None:
    completed = _verify_variant(
        tmp_path,
        variant="readonly",
        read_only=False,
    )

    assert completed.returncode == 1
    assert "readonly QEMU variant is not read-only" in completed.stderr
    assert not (tmp_path / "readonly.summary.json").exists()


@pytest.mark.parametrize(
    ("mutation", "expected_error"),
    [
        ({"include_parent": False}, "QMP target parent statistics are absent"),
        (
            {"include_backing": False},
            "QMP backing statistics do not match query-block depth",
        ),
    ],
)
def test_writable_variant_rejects_an_incomplete_reported_block_graph(
    tmp_path: Path,
    mutation: dict[str, object],
    expected_error: str,
) -> None:
    completed = _verify_variant(tmp_path, **mutation)

    assert completed.returncode == 1
    assert expected_error in completed.stderr
    assert not (tmp_path / "writable.summary.json").exists()


def test_readonly_variant_accepts_no_backing_at_reported_depth_zero(
    tmp_path: Path,
) -> None:
    completed = _verify_variant(tmp_path, variant="readonly")

    assert completed.returncode == 0, completed.stderr
    summary = json.loads(
        (tmp_path / "readonly.summary.json").read_text(encoding="utf-8")
    )
    assert summary["qmp_inserted_read_only_before"] is True
    assert summary["qmp_inserted_read_only_after"] is True
    assert summary["qmp_backing_depth_before"] == 0
    assert summary["qmp_backing_depth_after"] == 0
    assert set(summary["qmp_write_graph_before"]) == {
        "target",
        "target.parent",
    }


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


def test_fixture_settings_keep_root_owned_approval_artifacts(tmp_path: Path) -> None:
    specification = importlib.util.spec_from_file_location(
        "agent_v1_test_api", SUPPORT
    )
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)

    settings = module._settings(tmp_path)

    assert settings.service_user == "root"
    assert settings.service_group == "root"


def test_harness_allows_the_tcg_boot_budget() -> None:
    harness = HARNESS.read_text(encoding="utf-8")

    assert "for _ in $(seq 1 1200); do" in harness


def test_harness_preserves_boot_failure_diagnostics() -> None:
    harness = HARNESS.read_text(encoding="utf-8")

    assert 'qmp-screendump \\' in harness
    assert '--socket "$qmp_socket"' in harness
    assert '"$variant_evidence/boot-failure.ppm"' in harness
    assert '"$variant_evidence/boot-failure-console.log"' in harness


def _write_variant_summary(
    path: Path,
    variant: str,
    *,
    read_only: bool | None = None,
) -> None:
    expected_read_only = variant == "readonly"
    actual_read_only = (
        expected_read_only if read_only is None else read_only
    )
    backing_depth = 0 if variant == "readonly" else 1
    graph = {
        "target": {
            "wr_bytes": 0,
            "wr_operations": 0,
        },
        "target.parent": {
            "wr_bytes": 0,
            "wr_operations": 0,
        },
    }
    if variant == "writable":
        graph.update(
            {
                "target.backing": {
                    "wr_bytes": 0,
                    "wr_operations": 0,
                },
                "target.backing.parent": {
                    "wr_bytes": 0,
                    "wr_operations": 0,
                },
            }
        )
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
                "qmp_backing_depth_after": backing_depth,
                "qmp_backing_depth_before": backing_depth,
                "qmp_inserted_read_only_after": actual_read_only,
                "qmp_inserted_read_only_before": actual_read_only,
                "qmp_write_graph_after": graph,
                "qmp_write_graph_before": graph,
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


def test_final_gate_rejects_a_writable_summary_relabeled_readonly(
    tmp_path: Path,
) -> None:
    writable = tmp_path / "writable.summary.json"
    relabeled = tmp_path / "readonly.summary.json"
    fixture = tmp_path / "fixture-report.json"
    _write_variant_summary(writable, "writable")
    _write_variant_summary(relabeled, "readonly", read_only=False)
    _write_fixture_report(fixture)

    completed = _support_command(
        "finalize-evidence",
        "--variant-summary",
        str(writable),
        "--variant-summary",
        str(relabeled),
        "--fixture-report",
        str(fixture),
        "--output",
        str(tmp_path / "acceptance-summary.json"),
    )

    assert completed.returncode == 1
    assert "Readonly QMP evidence is incomplete" in completed.stderr
    assert PASS_LINE not in completed.stdout


def test_final_gate_rejects_target_only_readonly_graphs(
    tmp_path: Path,
) -> None:
    writable = tmp_path / "writable.summary.json"
    target_only = tmp_path / "readonly.summary.json"
    fixture = tmp_path / "fixture-report.json"
    _write_variant_summary(writable, "writable")
    _write_variant_summary(target_only, "readonly")
    readonly = json.loads(target_only.read_text(encoding="utf-8"))
    readonly["qmp_write_graph_before"] = {
        "target": {"wr_bytes": 0, "wr_operations": 0}
    }
    readonly["qmp_write_graph_after"] = {
        "target": {"wr_bytes": 0, "wr_operations": 0}
    }
    target_only.write_text(
        json.dumps(readonly, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _write_fixture_report(fixture)

    completed = _support_command(
        "finalize-evidence",
        "--variant-summary",
        str(writable),
        "--variant-summary",
        str(target_only),
        "--fixture-report",
        str(fixture),
        "--output",
        str(tmp_path / "acceptance-summary.json"),
    )

    assert completed.returncode == 1
    assert "QMP target parent statistics are absent" in completed.stderr
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


def test_harness_rejects_any_caller_supplied_target_path() -> None:
    completed = subprocess.run(
        [str(_bash()), HARNESS.as_posix(), "--target", "/dev/sda"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 2
    assert "Usage: run-agent-v1-dry-run-acceptance.sh" in completed.stderr
    assert PASS_LINE not in completed.stdout


def test_harness_exercises_its_executable_disposable_target_contract(
    tmp_path: Path,
) -> None:
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    qemu_img_log = tmp_path / "qemu-img.log"
    fake_qemu_img = fake_bin / "qemu-img"
    fake_qemu_img.write_text(
        """#!/bin/bash
set -eu
{
    printf 'arg'
    for argument in "$@"; do
        printf '\\t%s' "$argument"
    done
    printf '\\n'
} >>"$FAKE_QEMU_IMG_LOG"
if [[ "${!#}" == 64G ]]; then
    output="${@: -2:1}"
else
    output="${!#}"
fi
: >"$output"
""",
        encoding="utf-8",
        newline="\n",
    )
    fake_qemu_img.chmod(0o755)
    contract_tmp = tmp_path / "contract-tmp"
    contract_tmp.mkdir()
    environment = os.environ.copy()
    environment["PATH"] = f"{fake_bin}{os.pathsep}{environment['PATH']}"
    environment["FAKE_QEMU_IMG_LOG"] = qemu_img_log.as_posix()
    environment["TMPDIR"] = contract_tmp.as_posix()

    completed = subprocess.run(
        [str(_bash()), HARNESS.as_posix(), "--exercise-target-contract"],
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
    writable_work = contract["writable_variant_work"]
    readonly_work = contract["readonly_variant_work"]
    writable_backing = f"{writable_work}/backing.qcow2"
    writable_overlay = f"{writable_work}/target-overlay.qcow2"
    readonly_backing = f"{readonly_work}/backing.qcow2"

    assert writable_work == f"{workdir}/writable"
    assert readonly_work == f"{workdir}/readonly"
    assert contract["writable_target"] == writable_overlay
    assert contract["readonly_target"] == readonly_backing
    assert contract["writable_drive"] == (
        "id=target,if=none,format=qcow2,"
        f"file={writable_overlay},cache=none"
    )
    assert contract["readonly_drive"] == (
        "id=target,if=none,format=qcow2,"
        f"file={readonly_backing},cache=none,readonly=on"
    )
    assert contract["cleanup"] == "removed"
    assert "/dev/" not in completed.stdout

    assert qemu_img_log.read_text(encoding="utf-8").splitlines() == [
        f"arg\tcreate\t-f\tqcow2\t{writable_backing}\t64G",
        "arg\tcreate\t-f\tqcow2\t-F\tqcow2"
        f"\t-b\t{writable_backing}\t{writable_overlay}",
        f"arg\tcreate\t-f\tqcow2\t{readonly_backing}\t64G",
    ]
    assert not any(contract_tmp.iterdir())


def test_harness_reports_the_runtime_disposable_target_contract() -> None:
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
        "target_virtual_size=64G\n"
        "writable_target=qcow2-overlay-with-qcow2-backing\n"
        "readonly_target=qcow2-backing,readonly=on\n"
        "managed_iso_builder="
        "deploy/alt-linux/iso/agent-v1/build-managed-iso.sh\n"
        "source_identity_manifest="
        "deploy/alt-linux/iso/agent-v1/manifests/source_iso.json\n"
    )
