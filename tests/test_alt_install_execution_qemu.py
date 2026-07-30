from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import importlib.util
import hashlib
from io import StringIO
from pathlib import Path
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


REPO_ROOT = Path(__file__).resolve().parents[1]
QEMU_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "qemu"
CONTROL_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "control"
SUPPORT = QEMU_ROOT / "agent_v2_test_api.py"
HARNESS = QEMU_ROOT / "run-agent-v2-execution-acceptance.sh"
if str(CONTROL_ROOT) not in sys.path:
    sys.path.insert(0, str(CONTROL_ROOT))
PASS_LINE = (
    "PASS: root-authorized install wrote only the disposable target; "
    "authenticated postflight installed"
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
    target_write_bytes: int,
    sentinel_write_bytes: int,
    nested_sentinel_write_bytes: int = 0,
    target_read_only: bool = False,
    sentinel_read_only: bool = True,
    target_file: str = "target.qcow2",
    sentinel_file: str = "sentinel.qcow2",
    include_response_ids: bool = True,
    swap_inserted_files: bool = False,
    install_iso_file: str | None = None,
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

    block_devices = [
        {
            "device": "target",
            "inserted": {
                "backing_file_depth": 0,
                "drv": "qcow2",
                "file": (
                    sentinel_file
                    if swap_inserted_files
                    else target_file
                ),
                "ro": target_read_only,
            },
        },
        {
            "device": "sentinel",
            "inserted": {
                "backing_file_depth": 0,
                "drv": "qcow2",
                "file": (
                    target_file
                    if swap_inserted_files
                    else sentinel_file
                ),
                "ro": sentinel_read_only,
            },
        },
    ]
    if install_iso_file is not None:
        block_devices.append(
            {
                "device": "install-iso",
                "inserted": {
                    "drv": "raw",
                    "file": install_iso_file,
                    "ro": True,
                },
                "removable": True,
            }
        )
    messages = [
        {"QMP": {"version": {"qemu": {"major": 9, "minor": 0, "micro": 0}}}},
        {
            "return": {},
            **({"id": "capabilities"} if include_response_ids else {}),
        },
        {
            "return": [
                statistics("target", target_write_bytes),
                statistics(
                    "sentinel",
                    sentinel_write_bytes,
                    nested_writes=nested_sentinel_write_bytes,
                ),
            ],
            **({"id": "blockstats"} if include_response_ids else {}),
        },
        {
            "return": block_devices,
            **({"id": "block"} if include_response_ids else {}),
        },
    ]
    path.write_text(
        "".join(
            json.dumps(message, sort_keys=True) + "\n"
            for message in messages
        ),
        encoding="utf-8",
    )


def _write_boot_qmp(
    path: Path,
    manifest: dict[str, object],
    *,
    vm_instance_id: str | None = None,
    iso_inserted: bool = False,
) -> None:
    blocks = [
        {
            "device": name,
            "inserted": {
                "file": manifest["artifacts"][name]["canonical_path"],
            },
            "removable": False,
        }
        for name in ("target", "sentinel")
    ]
    if iso_inserted:
        blocks.append(
            {
                "device": "ide1-cd0",
                "inserted": {
                    "file": manifest["iso"]["canonical_path"],
                },
                "removable": True,
            }
        )
    messages = [
        {"QMP": {"version": {"qemu": {"major": 9}}}},
        {"id": "capabilities", "return": {}},
        {
            "id": "status",
            "return": {"running": True, "status": "running"},
        },
        {
            "id": "uuid",
            "return": {
                "UUID": vm_instance_id or manifest["vm_instance_id"]
            },
        },
        {"id": "block", "return": blocks},
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


def _reseal_public_evidence(module, state: Path, evidence: Path) -> None:
    evidence_hashes = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (evidence / "evidence").iterdir()
    }
    existing = json.loads(
        (
            evidence / "attestations" / "07-acceptance_evidence.json"
        ).read_text(encoding="utf-8")
    )
    payload = dict(existing["payload"])
    payload["evidence_sha256"] = evidence_hashes
    previous = json.loads(
        (
            evidence / "attestations" / "06-installed.json"
        ).read_text(encoding="utf-8")
    )
    seal = module.issue_attestation(
        state,
        event="acceptance_evidence",
        sequence=7,
        payload=payload,
        observed_at=existing["observed_at"],
        previous_sha256=module.attestation_sha256(previous),
    )
    (
        evidence / "attestations" / "07-acceptance_evidence.json"
    ).write_bytes(module._json_bytes(seal))
    index_path = evidence / "evidence-index.json"
    index = json.loads(index_path.read_text(encoding="utf-8"))
    index["evidence_sha256"] = evidence_hashes
    index["final_attestation_sha256"] = module.attestation_sha256(seal)
    index_path.write_bytes(module._json_bytes(index))


def _resign_public_authorization_request(
    module,
    state: Path,
    evidence: Path,
    mutate,
) -> None:
    attestation_dir = evidence / "attestations"
    previous_sha256 = None
    resigned: list[dict[str, object]] = []
    for sequence, path in enumerate(sorted(attestation_dir.iterdir())[:6], start=1):
        existing = json.loads(path.read_text(encoding="utf-8"))
        payload = existing["payload"]
        if sequence == 1:
            payload = dict(payload)
            request = dict(payload["request"])
            mutate(request)
            payload["request"] = request
        replacement = module.issue_attestation(
            state,
            event=existing["event"],
            sequence=sequence,
            payload=payload,
            observed_at=existing["observed_at"],
            previous_sha256=previous_sha256,
        )
        path.write_bytes(module._json_bytes(replacement))
        resigned.append(replacement)
        previous_sha256 = module.attestation_sha256(replacement)

    receipt_path = evidence / "acceptance-receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["attestation_chain_sha256"] = module.attestation_sha256(resigned[-1])
    receipt_path.write_bytes(module._json_bytes(receipt))

    for filename in (
        "postflight-delivery.json",
        "authenticated-postflight.json",
    ):
        postflight_path = evidence / "evidence" / filename
        postflight = json.loads(postflight_path.read_text(encoding="utf-8"))
        postflight["boot_attestation"] = resigned[4]
        postflight_path.write_bytes(module._json_bytes(postflight))

    seal_path = attestation_dir / "07-acceptance_evidence.json"
    existing_seal = json.loads(seal_path.read_text(encoding="utf-8"))
    seal_payload = dict(existing_seal["payload"])
    evidence_hashes = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (evidence / "evidence").iterdir()
    }
    seal_payload["evidence_sha256"] = evidence_hashes
    seal_payload["receipt_sha256"] = hashlib.sha256(
        receipt_path.read_bytes()
    ).hexdigest()
    replacement_seal = module.issue_attestation(
        state,
        event="acceptance_evidence",
        sequence=7,
        payload=seal_payload,
        observed_at=existing_seal["observed_at"],
        previous_sha256=previous_sha256,
    )
    seal_path.write_bytes(module._json_bytes(replacement_seal))

    index_path = evidence / "evidence-index.json"
    index = json.loads(index_path.read_text(encoding="utf-8"))
    index["final_attestation_sha256"] = module.attestation_sha256(
        replacement_seal
    )
    index["receipt_sha256"] = seal_payload["receipt_sha256"]
    index["evidence_sha256"] = evidence_hashes
    index_path.write_bytes(module._json_bytes(index))


def _support_module():
    specification = importlib.util.spec_from_file_location(
        "agent_v2_test_api_under_test", SUPPORT
    )
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _create_run_state(tmp_path: Path) -> tuple[Path, dict[str, object]]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    state = tmp_path / "run-state"
    state.mkdir()
    iso = tmp_path / "managed-v2.iso"
    target = tmp_path / "target.qcow2"
    sentinel = tmp_path / "sentinel.qcow2"
    iso.write_bytes(b"managed-v2-iso")
    target.write_bytes(b"target-initial")
    sentinel.write_bytes(b"sentinel-initial")
    completed = _support_command(
        "create-run",
        "--state-dir",
        str(state),
        "--iso",
        str(iso),
        "--expected-iso-sha256",
        hashlib.sha256(iso.read_bytes()).hexdigest(),
        "--target",
        str(target),
        "--sentinel",
        str(sentinel),
        "--vm-instance-id",
        str(uuid4()),
    )
    assert completed.returncode == 0, completed.stderr
    manifest = json.loads(
        (state / "run-manifest.json").read_text(encoding="utf-8")
    )
    return state, manifest


def _write_preflight_approval(module, state: Path, request: dict[str, object]) -> str:
    attestation = module.issue_attestation(
        state,
        event="preflight_approval",
        sequence=1,
        payload={
            "baseline_sha256": "a" * 64,
            "controller": {"plan_revision": 1, "state": "plan_published"},
            "request": request,
        },
        observed_at="2026-07-29T12:00:00+00:00",
        previous_sha256=None,
    )
    (state / "preflight-approval-attestation.json").write_bytes(
        module._json_bytes(attestation)
    )
    return module.attestation_sha256(attestation)


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
        "network=tap,dedicated-harness-netns\n"
        "cleanup=qemu,identity-bound-netns,temporary-directory;"
        "validated-harness-owned-only\n"
    )


def test_harness_uses_run_owned_authorization_and_postflight_chain() -> None:
    source = HARNESS.read_text(encoding="utf-8")
    assert "--timeline" not in source
    assert "--postflight <" not in source
    assert "create-authorization-request" in source
    assert source.index("--phase pending") < (
        source.index("create-authorization-request")
    )
    assert source.index("create-authorization-request") < source.index(
        "--phase before-authorization"
    )
    assert source.index(
        "--phase before-authorization"
    ) < source.index("authorize-execution")
    assert "issue-postflight-challenge" in source
    assert "--acceptance-state-dir \"$state_dir\"" in source
    assert "capture-authorization-boundary" in source
    assert "--observed-at" in source
    assert 'isoformat(timespec="microseconds")' in source
    assert "date -u +%Y-%m-%dT%H:%M:%S+00:00" not in source
    assert "verify-run-iso" in source
    assert "export-public-evidence" in source
    assert "remove-owned-workdir" in source
    assert "hold-network-namespace" in source
    assert "run-in-network-namespace" in source
    assert "stop-network-namespace" in source
    assert "delete-owned-tap" not in source
    assert 'rm -rf -- "$workdir"' not in source
    assert 'ip tuntap del dev "$tap_name"' not in source
    workdir_created = source.index(
        'workdir=$(mktemp -d "$evidence_root/.alt-agent-v2-qemu-work.'
    )
    ownership_recorded = source.index("record-workdir-ownership")
    assert workdir_created < ownership_recorded
    assert "prepare_storage" not in source[
        workdir_created:ownership_recorded
    ]


def test_harness_selects_the_v2_boot_menu_before_waiting_for_v1() -> None:
    source = HARNESS.read_text(encoding="utf-8")
    support = SUPPORT.read_text(encoding="utf-8")

    hotkey = 'qmp-send-v2-execution-hotkey'
    waiting = "'ALT install agent: waiting_for_approval'"
    assert hotkey in source
    assert source.index(hotkey) < source.index(waiting)
    assert (
        'for _ in $(seq 1 1200); do\n'
        '    python3 "$support" qmp-send-v2-execution-hotkey \\\n'
        '        --socket "$install_qmp" >/dev/null 2>&1 || true\n'
        in source
    )
    assert '"data": "x"' in support


def test_harness_cleanup_uses_only_identity_bound_process_termination() -> None:
    source = HARNESS.read_text(encoding="utf-8")
    cleanup_source = source[
        source.index("stop_qemu() {") : source.index("shopt -s extglob")
    ]

    assert "qmp-command" not in cleanup_source
    assert "--execute quit" not in cleanup_source
    for pid_name in (
        "qemu_pid",
        "execution_server_pid",
        "dnsmasq_pid",
    ):
        assert f'kill "${pid_name}"' not in cleanup_source
    assert "stop-owned-process" in source
    assert cleanup_source.count("stop_recorded_process") >= 3
    assert "cleanup-failures.log" in source
    assert (
        'if python3 "$support" stop-network-namespace' in cleanup_source
    )
    assert (
        'else\n            record_cleanup_failure "network namespace"'
        in cleanup_source
    )
    namespace_failure = cleanup_source.index(
        'record_cleanup_failure "network namespace"'
    )
    assert 'wait "$netns_holder_pid"' not in cleanup_source[
        namespace_failure:
    ]


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


def test_run_state_has_unpredictable_trust_anchor_and_exact_artifact_identity(
    tmp_path: Path,
) -> None:
    first_state, first = _create_run_state(tmp_path / "first")
    _second_state, second = _create_run_state(tmp_path / "second")

    assert first["run_id"] != second["run_id"]
    assert first["challenge"] != second["challenge"]
    assert first["vm_instance_id"] != second["vm_instance_id"]
    assert first["iso"]["sha256"] != "0" * 64
    assert set(first["artifacts"]) == {"target", "sentinel"}
    for name in ("target", "sentinel"):
        identity = first["artifacts"][name]
        path = Path(identity["canonical_path"])
        metadata = path.stat()
        assert identity["device"] == name
        assert identity["file_identity"] == {
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
            "size": metadata.st_size,
        }
        assert identity["initial_sha256"]
    private_key = first_state / "attestation-private.pem"
    assert private_key.is_file()
    assert "private" not in json.dumps(first, sort_keys=True).lower()
    public = serialization.load_pem_public_key(
        (first_state / "attestation-public.pem").read_bytes()
    )
    assert isinstance(public, Ed25519PublicKey)


@pytest.mark.parametrize("mutation", ["missing_ids", "swapped_files"])
def test_bound_qmp_rejects_response_or_inserted_file_relabeling(
    tmp_path: Path,
    mutation: str,
) -> None:
    state, manifest = _create_run_state(tmp_path)
    qmp = tmp_path / "snapshot.qmp.jsonl"
    _write_qmp(
        qmp,
        target_write_bytes=0,
        sentinel_write_bytes=0,
        target_file=manifest["artifacts"]["target"]["canonical_path"],
        sentinel_file=manifest["artifacts"]["sentinel"]["canonical_path"],
        include_response_ids=mutation != "missing_ids",
        swap_inserted_files=mutation == "swapped_files",
    )
    module = _support_module()

    with pytest.raises(
        module.AcceptanceError,
        match="response ID|inserted file",
    ):
        module.read_bound_qmp_snapshot(qmp, state)


def test_install_boundary_binds_current_iso_identity_and_qmp_cdrom(
    tmp_path: Path,
) -> None:
    state, manifest = _create_run_state(tmp_path)
    module = _support_module()
    qmp = tmp_path / "install.qmp.jsonl"
    _write_qmp(
        qmp,
        target_write_bytes=0,
        sentinel_write_bytes=0,
        target_file=manifest["artifacts"]["target"]["canonical_path"],
        sentinel_file=manifest["artifacts"]["sentinel"]["canonical_path"],
        install_iso_file=manifest["iso"]["canonical_path"],
    )

    module.verify_run_iso(state)
    module.read_bound_qmp_snapshot(qmp, state, require_iso=True)

    iso = Path(manifest["iso"]["canonical_path"])
    original = iso.read_bytes()
    iso.chmod(0o600)
    iso.write_bytes(original + b"-mutated")
    with pytest.raises(module.AcceptanceError, match="ISO"):
        module.read_bound_qmp_snapshot(qmp, state, require_iso=True)

    iso.write_bytes(original)
    iso.chmod(0o400)
    replacement = tmp_path / "replacement.iso"
    replacement.write_bytes(original)
    iso.chmod(0o600)
    iso.unlink()
    replacement.replace(iso)
    iso.chmod(0o400)
    with pytest.raises(module.AcceptanceError, match="ISO"):
        module.read_bound_qmp_snapshot(qmp, state, require_iso=True)


def test_create_run_rejects_source_iso_replaced_after_verification(
    tmp_path: Path,
) -> None:
    module = _support_module()
    state = tmp_path / "run-state"
    state.mkdir()
    iso = tmp_path / "managed.iso"
    target = tmp_path / "target.qcow2"
    sentinel = tmp_path / "sentinel.qcow2"
    verified = b"verified-managed-iso"
    iso.write_bytes(verified)
    target.write_bytes(b"target")
    sentinel.write_bytes(b"sentinel")
    expected_sha256 = hashlib.sha256(verified).hexdigest()
    iso.write_bytes(b"replacement-after-verifier")

    with pytest.raises(module.AcceptanceError, match="[Vv]erified ISO"):
        module.create_run_state(
            state,
            iso=iso,
            expected_iso_sha256=expected_sha256,
            target=target,
            sentinel=sentinel,
            vm_instance_id=str(uuid4()),
        )


def test_create_run_launches_owned_iso_copy_despite_source_path_replacement(
    tmp_path: Path,
) -> None:
    module = _support_module()
    state = tmp_path / "run-state"
    state.mkdir()
    iso = tmp_path / "managed.iso"
    target = tmp_path / "target.qcow2"
    sentinel = tmp_path / "sentinel.qcow2"
    verified = b"verified-managed-iso"
    iso.write_bytes(verified)
    target.write_bytes(b"target")
    sentinel.write_bytes(b"sentinel")
    manifest = module.create_run_state(
        state,
        iso=iso,
        expected_iso_sha256=hashlib.sha256(verified).hexdigest(),
        target=target,
        sentinel=sentinel,
        vm_instance_id=str(uuid4()),
    )

    owned_iso = Path(manifest["iso"]["canonical_path"])
    assert owned_iso == (state / "run-artifacts" / "install.iso").resolve()
    assert owned_iso.read_bytes() == verified
    iso.write_bytes(b"changed-again-after-create-run")
    assert module.verify_run_iso(state) == manifest["iso"]
    assert owned_iso.read_bytes() == verified


@pytest.mark.skipif(
    os.name != "posix",
    reason="POSIX permits replacement of an opened source path",
)
def test_create_run_open_descriptor_survives_source_path_replacement(
    tmp_path: Path,
) -> None:
    module = _support_module()
    state = tmp_path / "run-state"
    state.mkdir()
    iso = tmp_path / "managed.iso"
    target = tmp_path / "target.qcow2"
    sentinel = tmp_path / "sentinel.qcow2"
    verified = b"verified-managed-iso"
    iso.write_bytes(verified)
    target.write_bytes(b"target")
    sentinel.write_bytes(b"sentinel")
    replacement = tmp_path / "replacement.iso"
    replacement.write_bytes(b"unverified-replacement")

    def replace_source_after_open() -> None:
        iso.unlink()
        replacement.replace(iso)

    manifest = module.create_run_state(
        state,
        iso=iso,
        expected_iso_sha256=hashlib.sha256(verified).hexdigest(),
        target=target,
        sentinel=sentinel,
        vm_instance_id=str(uuid4()),
        after_iso_open=replace_source_after_open,
    )

    assert Path(manifest["iso"]["canonical_path"]).read_bytes() == verified
    assert iso.read_bytes() == b"unverified-replacement"


def test_install_boundary_rejects_missing_or_relabelled_iso_qmp(
    tmp_path: Path,
) -> None:
    state, manifest = _create_run_state(tmp_path)
    module = _support_module()
    qmp = tmp_path / "install.qmp.jsonl"
    common = {
        "target_write_bytes": 0,
        "sentinel_write_bytes": 0,
        "target_file": manifest["artifacts"]["target"]["canonical_path"],
        "sentinel_file": manifest["artifacts"]["sentinel"]["canonical_path"],
    }
    _write_qmp(qmp, **common)
    with pytest.raises(module.AcceptanceError, match="ISO"):
        module.read_bound_qmp_snapshot(qmp, state, require_iso=True)
    _write_qmp(
        qmp,
        **common,
        install_iso_file=str(tmp_path / "other.iso"),
    )
    with pytest.raises(module.AcceptanceError, match="ISO"):
        module.read_bound_qmp_snapshot(qmp, state, require_iso=True)


def test_bound_sha_rejects_relabel_and_replaced_file_identity(
    tmp_path: Path,
) -> None:
    state, manifest = _create_run_state(tmp_path)
    target = Path(manifest["artifacts"]["target"]["canonical_path"])
    record = tmp_path / "target.sha256"
    digest = manifest["artifacts"]["target"]["initial_sha256"]
    _write_sha(record, digest, str(target))
    module = _support_module()
    assert (
        module.read_bound_sha256_record(record, state, "target")
        == digest
    )

    _write_sha(record, digest, str(Path(manifest["artifacts"]["sentinel"]["canonical_path"])))
    with pytest.raises(module.AcceptanceError, match="filename"):
        module.read_bound_sha256_record(record, state, "target")

    replacement = tmp_path / "replacement"
    replacement.write_bytes(target.read_bytes())
    target.unlink()
    replacement.replace(target)
    _write_sha(record, digest, str(target))
    with pytest.raises(module.AcceptanceError, match="file identity"):
        module.read_bound_sha256_record(record, state, "target")


def test_disposable_preflight_approval_binds_one_new_waiting_session(
    tmp_path: Path,
) -> None:
    state, manifest = _create_run_state(tmp_path)
    module = _support_module()
    session_id = "install-20260730T120000Z-a1b2c3d4"
    inventory_sha256 = "a" * 64
    disk_fingerprint = "sha256:" + "b" * 64
    waiting = {
        "session_id": session_id,
        "state": "awaiting_approval",
        "inventory_sha256": inventory_sha256,
        "agent_status": {"reported_stage": "waiting_for_approval"},
    }
    plan_bytes = json.dumps(
        {
            "target_disk": {
                "fingerprint": disk_fingerprint,
                "path": "/dev/vda",
            }
        },
        sort_keys=True,
    ).encode()
    approved = {
        **waiting,
        "state": "plan_published",
        "plan_revision": 1,
    }
    calls: list[list[str]] = []

    baseline = module.capture_preflight_session_baseline(
        state, statuses=lambda: []
    )
    assert baseline["session_status_sha256"] == {}

    def cli(arguments, *, stdout, stderr) -> int:
        calls.append(arguments)
        if arguments[2] == "preview":
            stdout.write(
                json.dumps(
                    {
                        "status": "ok",
                        "preview": {
                            "session_id": session_id,
                            "inventory_sha256": inventory_sha256,
                            "target_disk": {
                                "path": "/dev/vda",
                                "fingerprint": disk_fingerprint,
                            },
                        },
                    }
                )
            )
        else:
            stdout.write(json.dumps({"status": "ok", "session": approved}))
        return 0

    attestation = module.approve_disposable_preflight(
        state,
        statuses=lambda: [waiting],
        status_loader=lambda observed: approved
        if observed == session_id
        else pytest.fail("unexpected session"),
        revision_file=lambda observed, filename: plan_bytes
        if (observed, filename) == (session_id, "plan.json")
        else pytest.fail("unexpected revision"),
        cli=cli,
        euid=lambda: 0,
        observed_at="2026-07-30T12:00:00+00:00",
    )

    assert calls == [
        ["--json", "install-sessions", "preview", session_id],
        [
            "--json",
            "install-sessions",
            "approve",
            session_id,
            "--inventory-sha256",
            inventory_sha256,
            "--disk-fingerprint",
            disk_fingerprint,
            "--reason",
            f"Disposable OVMF preflight {manifest['run_id']}",
        ]
    ]
    assert attestation["event"] == "preflight_approval"
    assert attestation["payload"]["request"] == {
        "disk_fingerprint": disk_fingerprint,
        "inventory_sha256": inventory_sha256,
        "plan_sha256": hashlib.sha256(plan_bytes).hexdigest(),
        "session_id": session_id,
        "target_disk": "/dev/vda",
    }


def test_disposable_preflight_allows_only_a_preexisting_expired_session_to_change(
    tmp_path: Path,
) -> None:
    """Creation expires stale records, which must not mask the run session."""
    state, _manifest = _create_run_state(tmp_path)
    module = _support_module()
    stale_id = "install-20260729T120000Z-a1b2c3d4"
    session_id = "install-20260730T120000Z-b1c2d3e4"
    inventory_sha256 = "a" * 64
    disk_fingerprint = "sha256:" + "b" * 64
    stale_before = {
        "session_id": stale_id,
        "state": "awaiting_approval",
        "expires_at": "2026-07-29T12:30:00+00:00",
    }
    stale_after = {
        **stale_before,
        "state": "expired",
        "expired_at": "2026-07-30T12:00:00+00:00",
        "updated_at": "2026-07-30T12:00:00+00:00",
    }
    waiting = {
        "session_id": session_id,
        "state": "awaiting_approval",
        "inventory_sha256": inventory_sha256,
        "agent_status": {"reported_stage": "waiting_for_approval"},
    }
    approved = {
        **waiting,
        "state": "plan_published",
        "plan_revision": 1,
    }
    plan_bytes = json.dumps(
        {
            "target_disk": {
                "fingerprint": disk_fingerprint,
                "path": "/dev/vda",
            }
        },
        sort_keys=True,
    ).encode()
    module.capture_preflight_session_baseline(
        state, statuses=lambda: [stale_before]
    )

    def cli(arguments, *, stdout, stderr) -> int:
        if arguments[2] == "preview":
            stdout.write(
                json.dumps(
                    {
                        "status": "ok",
                        "preview": {
                            "session_id": session_id,
                            "inventory_sha256": inventory_sha256,
                            "target_disk": {
                                "path": "/dev/vda",
                                "fingerprint": disk_fingerprint,
                            },
                        },
                    }
                )
            )
        else:
            stdout.write(json.dumps({"status": "ok", "session": approved}))
        return 0

    attestation = module.approve_disposable_preflight(
        state,
        statuses=lambda: [stale_after, waiting],
        status_loader=lambda observed: approved
        if observed == session_id
        else pytest.fail("unexpected session"),
        revision_file=lambda observed, filename: plan_bytes
        if (observed, filename) == (session_id, "plan.json")
        else pytest.fail("unexpected revision"),
        cli=cli,
        euid=lambda: 0,
        observed_at="2026-07-30T12:00:00+00:00",
    )

    assert attestation["payload"]["request"]["session_id"] == session_id


def test_signed_chain_rejects_stale_postflight_from_another_run(
    tmp_path: Path,
) -> None:
    first_state, _first = _create_run_state(tmp_path / "first")
    second_state, _second = _create_run_state(tmp_path / "second")
    first_module = _support_module()
    authorization = first_module.issue_attestation(
        first_state,
        event="authorization",
        sequence=1,
        payload={
            "controller": {
                "execution_id": (
                    "install-20260729T120000Z-a1b2c3d4:execution-0001"
                ),
                "state": "authorized",
            },
            "target_disk": "/dev/vda",
        },
        observed_at="2026-07-29T12:02:00+00:00",
        previous_sha256=None,
    )
    stale = first_module.issue_attestation(
        first_state,
        event="postflight",
        sequence=2,
        payload={
            "authenticated": True,
            "boot_id": str(uuid4()),
            "boot_nonce": "A" * 43,
            "controller_state": "installed",
            "iso_attached": False,
        },
        observed_at="2026-07-29T12:23:00+00:00",
        previous_sha256=first_module.attestation_sha256(authorization),
    )
    module = _support_module()

    with pytest.raises(module.AcceptanceError, match="run binding"):
        module.verify_attestation_chain(
            second_state, [authorization, stale]
        )


def test_signed_no_iso_boot_challenge_is_fresh_single_use_and_finalizes(
    tmp_path: Path,
) -> None:
    workdir = tmp_path / "work"
    state, manifest = _create_run_state(workdir)
    module = _support_module()
    target = Path(manifest["artifacts"]["target"]["canonical_path"])
    sentinel = Path(
        manifest["artifacts"]["sentinel"]["canonical_path"]
    )
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    initial_qmp = evidence / "pending.qmp.jsonl"
    immediate_qmp = evidence / "before-authorization.qmp.jsonl"
    after_qmp = evidence / "after-install.qmp.jsonl"
    common = {
        "target_file": str(target),
        "sentinel_file": str(sentinel),
    }
    boundary_times = iter(
        (
            "2026-07-29T12:01:00+00:00",
            "2026-07-29T12:01:01+00:00",
            "2026-07-29T12:01:02+00:00",
            "2026-07-29T12:01:03+00:00",
        )
    )

    def capture(_socket: Path, output: Path) -> None:
        _write_qmp(
            output,
            target_write_bytes=0,
            sentinel_write_bytes=0,
            install_iso_file=manifest["iso"]["canonical_path"],
            **common,
        )

    module.capture_authorization_boundary(
        state,
        socket_path=tmp_path / "install.qmp.sock",
        evidence_dir=evidence,
        phase="pending",
        qmp_capture=capture,
        clock=lambda: next(boundary_times),
    )
    module.capture_authorization_boundary(
        state,
        socket_path=tmp_path / "install.qmp.sock",
        evidence_dir=evidence,
        phase="before-authorization",
        qmp_capture=capture,
        clock=lambda: next(boundary_times),
    )
    initial_target = hashlib.sha256(target.read_bytes()).hexdigest()
    initial_sentinel = hashlib.sha256(sentinel.read_bytes()).hexdigest()
    sha_records: dict[str, Path] = {
        "initial_target": evidence / "pending.target.sha256",
        "initial_sentinel": evidence / "pending.sentinel.sha256",
        "immediate_target": (
            evidence / "before-authorization.target.sha256"
        ),
        "immediate_sentinel": (
            evidence / "before-authorization.sentinel.sha256"
        ),
    }
    plan_bytes = json.dumps(
        {
            "target_disk": {
                "fingerprint": "sha256:" + "d" * 64,
                "path": "/dev/vda",
            }
        },
        sort_keys=True,
    ).encode()
    request = {
        "disk_fingerprint": "sha256:" + "d" * 64,
        "inventory_sha256": "c" * 64,
        "plan_sha256": hashlib.sha256(plan_bytes).hexdigest(),
        "session_id": "install-20260729T120000Z-a1b2c3d4",
        "target_disk": "/dev/vda",
    }
    authorization = module.issue_attestation(
        state,
        event="authorization",
        sequence=1,
        payload={
            "authorization_observed_at": (
                "2026-07-29T12:01:04+00:00"
            ),
            "before_authorization_boundary_sha256": hashlib.sha256(
                (
                    evidence / "before-authorization-boundary.json"
                ).read_bytes()
            ).hexdigest(),
            "before_authorization_qmp_sha256": hashlib.sha256(
                immediate_qmp.read_bytes()
            ).hexdigest(),
            "controller": {
                "execution_id": (
                    f"{request['session_id']}:execution-0001"
                ),
                "state": "authorized",
            },
            "initial_qmp_sha256": hashlib.sha256(
                initial_qmp.read_bytes()
            ).hexdigest(),
            "initial_sentinel_sha256": initial_sentinel,
            "initial_target_sha256": initial_target,
            "pending_boundary_sha256": hashlib.sha256(
                (evidence / "pending-boundary.json").read_bytes()
            ).hexdigest(),
            "request": request,
            "sentinel_sha256_before_authorization": initial_sentinel,
            "target_disk": "/dev/vda",
            "target_sha256_before_authorization": initial_target,
        },
        observed_at="2026-07-29T12:01:05+00:00",
        previous_sha256=None,
    )
    chain = [authorization]
    for sequence, event in enumerate(
        ("claimed", "handoff_started", "installer_started"),
        start=2,
    ):
        item = module.issue_attestation(
            state,
            event=event,
            sequence=sequence,
            payload={
                "controller": {
                    "execution_id": (
                        f"{request['session_id']}:execution-0001"
                    ),
                    "state": event,
                },
                "session_id": request["session_id"],
            },
            observed_at=(
                f"2026-07-29T12:01:0{sequence + 4}+00:00"
            ),
            previous_sha256=module.attestation_sha256(chain[-1]),
        )
        chain.append(item)
    for item in chain:
        module.store_attestation(state, item)
    boot_qmp = evidence / "postflight-boot.qmp.jsonl"
    _write_boot_qmp(boot_qmp, manifest)
    delivery = module.issue_postflight_boot_challenge(
        state,
        qmp_path=boot_qmp,
        observed_at="2026-07-29T12:02:00+00:00",
    )
    assert delivery["boot_nonce"] != manifest["challenge"]
    postflight = {
        "boot_attestation": delivery["boot_attestation"],
        "boot_id": str(uuid4()),
        "boot_nonce": delivery["boot_nonce"],
        "challenge": manifest["challenge"],
        "reported_at": "2026-07-29T12:02:01+00:00",
        "run_id": manifest["run_id"],
        "schema_version": 1,
        "vm_instance_id": manifest["vm_instance_id"],
    }
    assert module.verify_postflight_document(
        state, request["session_id"], postflight
    )
    assert not module.verify_postflight_document(
        state, request["session_id"], postflight
    )
    module.attest_installed_state(
        state,
        status_loader=lambda _session: {
            "execution": {
                "installed_at": "2026-07-29T12:03:02+00:00",
                "revision": 1,
                "state": "installed",
            }
        },
    )
    target.write_bytes(target.read_bytes() + b"-installed")
    _write_qmp(
        after_qmp,
        target_write_bytes=8192,
        sentinel_write_bytes=0,
        install_iso_file=manifest["iso"]["canonical_path"],
        **common,
    )
    for name, path in (("target", target), ("sentinel", sentinel)):
        record = evidence / f"{name}.after.sha256"
        _write_sha(
            record, hashlib.sha256(path.read_bytes()).hexdigest(), str(path)
        )
        sha_records[f"after_{name}"] = record
    receipt = evidence / "acceptance-receipt.json"
    module.finalize_signed_evidence(
        state,
        initial_qmp=initial_qmp,
        before_authorization_qmp=immediate_qmp,
        after_install_qmp=after_qmp,
        postflight_boot_qmp=boot_qmp,
        initial_target_sha=sha_records["initial_target"],
        before_authorization_target_sha=sha_records[
            "immediate_target"
        ],
        after_target_sha=sha_records["after_target"],
        initial_sentinel_sha=sha_records["initial_sentinel"],
        before_authorization_sentinel_sha=sha_records[
            "immediate_sentinel"
        ],
        after_sentinel_sha=sha_records["after_sentinel"],
        output=receipt,
    )
    result = json.loads(receipt.read_text(encoding="utf-8"))
    assert result["schema_version"] == 2
    assert result["result"] == "pass"
    assert result["controller"]["state"] == "installed"
    assert result["postflight"]["iso_attached"] is False
    assert result["run"]["run_id"] == manifest["run_id"]
    corpus = {
        "pending-boundary.json": evidence / "pending-boundary.json",
        "pending.qmp.jsonl": initial_qmp,
        "pending.target.sha256": sha_records["initial_target"],
        "pending.sentinel.sha256": sha_records["initial_sentinel"],
        "before-authorization-boundary.json": (
            evidence / "before-authorization-boundary.json"
        ),
        "before-authorization.qmp.jsonl": immediate_qmp,
        "before-authorization.target.sha256": (
            sha_records["immediate_target"]
        ),
        "before-authorization.sentinel.sha256": (
            sha_records["immediate_sentinel"]
        ),
        "after-install.qmp.jsonl": after_qmp,
        "postflight-boot.qmp.jsonl": boot_qmp,
        "target.after.sha256": sha_records["after_target"],
        "sentinel.after.sha256": sha_records["after_sentinel"],
        "postflight-delivery.json": state / "postflight-delivery.json",
        "authenticated-postflight.json": (
            state / "authenticated-postflight.json"
        ),
    }
    with pytest.raises(module.AcceptanceError, match="corpus"):
        module.export_public_evidence(
            state,
            receipt=receipt,
            output=tmp_path / "missing-public-evidence",
            evidence_files={},
            euid=lambda: 0,
        )
    with pytest.raises(module.AcceptanceError, match="corpus"):
        module.export_public_evidence(
            state,
            receipt=receipt,
            output=tmp_path / "extra-public-evidence",
            evidence_files={
                **corpus,
                "unexpected.json": evidence / "pending-boundary.json",
            },
            euid=lambda: 0,
        )
    empty = tmp_path / "empty.qmp.jsonl"
    empty.touch()
    with pytest.raises(module.AcceptanceError, match="Evidence file"):
        module.export_public_evidence(
            state,
            receipt=receipt,
            output=tmp_path / "empty-public-evidence",
            evidence_files={**corpus, "pending.qmp.jsonl": empty},
            euid=lambda: 0,
        )
    public_evidence = tmp_path / "public-evidence"
    module.export_public_evidence(
        state,
        receipt=receipt,
        output=public_evidence,
        evidence_files=corpus,
        observed_at="2026-07-29T12:04:00+00:00",
        euid=lambda: 0,
    )
    assert not (
        public_evidence / "attestation-private.pem"
    ).exists()
    verified = module.verify_public_evidence(
        public_evidence, euid=lambda: 0
    )
    assert verified["receipt"]["result"] == "pass"
    assert verified["chain"][-1]["event"] == "acceptance_evidence"
    assert verified["chain"][-2]["event"] == "installed"

    authorization_mutations = (
        ("missing-plan", lambda value: value.pop("plan_sha256")),
        ("extra-key", lambda value: value.__setitem__("unexpected", "value")),
        (
            "changed-plan",
            lambda value: value.__setitem__("plan_sha256", "a" * 64),
        ),
        (
            "changed-inventory",
            lambda value: value.__setitem__("inventory_sha256", "b" * 64),
        ),
        (
            "changed-fingerprint",
            lambda value: value.__setitem__(
                "disk_fingerprint", "sha256:" + "e" * 64
            ),
        ),
    )
    for name, mutate in authorization_mutations:
        mutated = tmp_path / f"semantic-authorization-{name}"
        shutil.copytree(public_evidence, mutated)
        _resign_public_authorization_request(
            module,
            state,
            mutated,
            mutate,
        )
        with pytest.raises(
            module.AcceptanceError,
            match="authorization semantic controller binding",
        ):
            module.verify_public_evidence(mutated, euid=lambda: 0)

    postflight_mutations = (
        ("postflight-delivery.json", "schema_version", 2),
        ("postflight-delivery.json", "run_id", "other-run"),
        ("postflight-delivery.json", "challenge", "B" * 43),
        (
            "postflight-delivery.json",
            "vm_instance_id",
            str(uuid4()),
        ),
        (
            "postflight-delivery.json",
            "controller_url",
            "https://192.0.2.10:18092",
        ),
        (
            "postflight-delivery.json",
            "session_id",
            "install-20260729T120000Z-deadbeef",
        ),
        ("postflight-delivery.json", "boot_nonce", "C" * 43),
        (
            "postflight-delivery.json",
            "boot_attestation",
            chain[3],
        ),
        (
            "authenticated-postflight.json",
            "schema_version",
            2,
        ),
        ("authenticated-postflight.json", "run_id", "other-run"),
        ("authenticated-postflight.json", "challenge", "D" * 43),
        (
            "authenticated-postflight.json",
            "vm_instance_id",
            str(uuid4()),
        ),
        (
            "authenticated-postflight.json",
            "boot_id",
            str(uuid4()),
        ),
        (
            "authenticated-postflight.json",
            "boot_nonce",
            "E" * 43,
        ),
        (
            "authenticated-postflight.json",
            "reported_at",
            "2026-07-29T12:02:02+00:00",
        ),
        (
            "authenticated-postflight.json",
            "boot_attestation",
            chain[3],
        ),
    )
    for index, (filename, field, value) in enumerate(
        postflight_mutations
    ):
        mutated = tmp_path / f"semantic-postflight-{index}"
        shutil.copytree(public_evidence, mutated)
        path = mutated / "evidence" / filename
        document = json.loads(path.read_text(encoding="utf-8"))
        document[field] = value
        path.write_bytes(module._json_bytes(document))
        _reseal_public_evidence(module, state, mutated)
        with pytest.raises(module.AcceptanceError, match="semantic"):
            module.verify_public_evidence(mutated, euid=lambda: 0)

    zero_write = tmp_path / "semantic-zero-write"
    shutil.copytree(public_evidence, zero_write)
    _write_qmp(
        zero_write / "evidence" / "after-install.qmp.jsonl",
        target_write_bytes=0,
        sentinel_write_bytes=0,
        install_iso_file=manifest["iso"]["canonical_path"],
        **common,
    )
    _reseal_public_evidence(module, state, zero_write)
    with pytest.raises(module.AcceptanceError, match="semantic"):
        module.verify_public_evidence(zero_write, euid=lambda: 0)

    unchanged_target = tmp_path / "semantic-unchanged-target"
    shutil.copytree(public_evidence, unchanged_target)
    _write_sha(
        unchanged_target / "evidence" / "target.after.sha256",
        initial_target,
        str(target),
    )
    _reseal_public_evidence(module, state, unchanged_target)
    with pytest.raises(module.AcceptanceError, match="semantic"):
        module.verify_public_evidence(unchanged_target, euid=lambda: 0)

    absolute_ref = tmp_path / "semantic-absolute-ref"
    shutil.copytree(public_evidence, absolute_ref)
    pending_path = absolute_ref / "evidence" / "pending-boundary.json"
    pending_document = json.loads(
        pending_path.read_text(encoding="utf-8")
    )
    pending_document["qmp"]["file"] = str(
        tmp_path / "outside.qmp.jsonl"
    )
    pending_path.write_bytes(module._json_bytes(pending_document))
    _reseal_public_evidence(module, state, absolute_ref)
    with pytest.raises(module.AcceptanceError, match="semantic"):
        module.verify_public_evidence(absolute_ref, euid=lambda: 0)

    ownership = module.workdir_ownership(workdir)
    module.remove_owned_workdir(ownership, workdir)
    assert not workdir.exists()
    verified_after_cleanup = module.verify_public_evidence(
        public_evidence, euid=lambda: 0
    )
    assert verified_after_cleanup["receipt"]["result"] == "pass"


@pytest.mark.parametrize("mutation", ["wrong_vm", "iso_attached"])
def test_postflight_boot_rejects_wrong_vm_or_inserted_iso(
    tmp_path: Path,
    mutation: str,
) -> None:
    state, manifest = _create_run_state(tmp_path)
    boot_qmp = tmp_path / "boot.qmp.jsonl"
    _write_boot_qmp(
        boot_qmp,
        manifest,
        vm_instance_id=(
            str(uuid4()) if mutation == "wrong_vm" else None
        ),
        iso_inserted=mutation == "iso_attached",
    )
    module = _support_module()
    with pytest.raises(
        module.AcceptanceError, match="identity|ISO"
    ):
        module._read_postflight_boot_qmp(boot_qmp, state)


def test_authorization_boundary_defaults_to_the_real_controller_cli(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _support_module()
    calls: list[tuple[object, object]] = []

    def controller_cli_main(
        arguments: object, **keywords: object
    ) -> int:
        calls.append((arguments, keywords))
        return 17

    import types

    monkeypatch.setitem(
        sys.modules,
        "alt_deploy.cli",
        types.SimpleNamespace(main=controller_cli_main),
    )
    assert module.control_cli_main(["--json"]) == 17
    assert calls == [(["--json"], {})]


def test_authorization_request_is_derived_from_unique_controller_preflight(
    tmp_path: Path,
) -> None:
    state, _manifest = _create_run_state(tmp_path)
    module = _support_module()
    session_id = "install-20260729T120000Z-a1b2c3d4"
    plan = {
        "target_disk": {
            "fingerprint": "sha256:" + "d" * 64,
            "path": "/dev/vda",
        }
    }
    plan_bytes = (
        json.dumps(plan, separators=(",", ":"), sort_keys=True) + "\n"
    ).encode()
    status = {
        "agent_status": {"reported_stage": "preflight_ready"},
        "disk_fingerprint": plan["target_disk"]["fingerprint"],
        "inventory_sha256": "c" * 64,
        "session_id": session_id,
        "state": "plan_published",
    }
    approved_request = {
        "disk_fingerprint": plan["target_disk"]["fingerprint"],
        "inventory_sha256": "c" * 64,
        "plan_sha256": hashlib.sha256(plan_bytes).hexdigest(),
        "session_id": session_id,
        "target_disk": "/dev/vda",
    }
    preflight = module.issue_attestation(
        state,
        event="preflight_approval",
        sequence=1,
        payload={
            "baseline_sha256": "a" * 64,
            "controller": {
                "plan_revision": 1,
                "state": "plan_published",
            },
            "request": approved_request,
        },
        observed_at="2026-07-29T12:00:00+00:00",
        previous_sha256=None,
    )
    (state / "preflight-approval-attestation.json").write_bytes(
        module._json_bytes(preflight)
    )
    request = module.create_authorization_request(
        state,
        statuses=lambda: [status],
        revision_file=lambda observed, filename: (
            plan_bytes
            if (observed, filename) == (session_id, "plan.json")
            else pytest.fail("unexpected controller artifact")
        ),
    )
    assert request == {
        **approved_request,
        "preflight_approval_attestation_sha256": (
            module.attestation_sha256(preflight)
        ),
    }
    assert json.loads(
        (state / "authorization-request.json").read_text(
            encoding="utf-8"
        )
    ) == request


def test_authorization_boundary_captures_qmp_and_sha_as_one_signed_unit(
    tmp_path: Path,
) -> None:
    state, manifest = _create_run_state(tmp_path / "run")
    module = _support_module()
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    calls: list[str] = []
    timestamps = iter(
        (
            "2026-07-29T12:01:31+00:00",
            "2026-07-29T12:01:32+00:00",
        )
    )

    def capture(_socket: Path, output: Path) -> None:
        calls.append("qmp")
        _write_qmp(
            output,
            target_write_bytes=0,
            sentinel_write_bytes=0,
            target_file=manifest["artifacts"]["target"][
                "canonical_path"
            ],
            sentinel_file=manifest["artifacts"]["sentinel"][
                "canonical_path"
            ],
            install_iso_file=manifest["iso"]["canonical_path"],
        )

    boundary = module.capture_authorization_boundary(
        state,
        socket_path=tmp_path / "qmp.sock",
        evidence_dir=evidence,
        phase="pending",
        qmp_capture=capture,
        clock=lambda: next(timestamps),
    )

    assert calls == ["qmp"]
    assert boundary["phase"] == "pending"
    assert boundary["capture_started_at"] < boundary["captured_at"]
    assert boundary["iso"]["sha256"] == manifest["iso"]["sha256"]
    assert boundary["target"]["sha256"] == manifest["artifacts"][
        "target"
    ]["initial_sha256"]
    assert boundary["sentinel"]["sha256"] == manifest["artifacts"][
        "sentinel"
    ]["initial_sha256"]
    loaded = module.read_authorization_boundary(
        state,
        evidence / "pending-boundary.json",
        expected_phase="pending",
    )
    assert loaded == boundary


def test_authorization_boundary_excludes_iso_revalidation_from_short_capture_window(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state, manifest = _create_run_state(tmp_path / "run")
    module = _support_module()
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    timestamps = iter(
        (
            "2026-07-29T12:01:00+00:00",
            "2026-07-29T12:01:01+00:00",
        )
    )

    def expensive_verify(run_state: Path) -> dict[str, object]:
        pytest.fail("full ISO hashing must not occur inside the short window")

    def capture(_socket: Path, output: Path) -> None:
        _write_qmp(
            output,
            target_write_bytes=0,
            sentinel_write_bytes=0,
            target_file=manifest["artifacts"]["target"]["canonical_path"],
            sentinel_file=manifest["artifacts"]["sentinel"]["canonical_path"],
            install_iso_file=manifest["iso"]["canonical_path"],
        )

    monkeypatch.setattr(module, "verify_run_iso", expensive_verify)
    boundary = module.capture_authorization_boundary(
        state,
        socket_path=tmp_path / "qmp.sock",
        evidence_dir=evidence,
        phase="pending",
        qmp_capture=capture,
        clock=lambda: next(timestamps),
    )

    assert boundary["capture_started_at"] == "2026-07-29T12:01:00+00:00"
    assert boundary["captured_at"] == "2026-07-29T12:01:01+00:00"


def test_authorization_boundary_rejects_an_overlong_capture(
    tmp_path: Path,
) -> None:
    state, manifest = _create_run_state(tmp_path / "run")
    module = _support_module()
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    timestamps = iter(
        (
            "2026-07-29T12:01:00+00:00",
            "2026-07-29T12:01:11+00:00",
        )
    )

    def capture(_socket: Path, output: Path) -> None:
        _write_qmp(
            output,
            target_write_bytes=0,
            sentinel_write_bytes=0,
            target_file=manifest["artifacts"]["target"][
                "canonical_path"
            ],
            sentinel_file=manifest["artifacts"]["sentinel"][
                "canonical_path"
            ],
            install_iso_file=manifest["iso"]["canonical_path"],
        )

    with pytest.raises(module.AcceptanceError, match="freshness"):
        module.capture_authorization_boundary(
            state,
            socket_path=tmp_path / "qmp.sock",
            evidence_dir=evidence,
            phase="pending",
            qmp_capture=capture,
            clock=lambda: next(timestamps),
        )


@pytest.mark.parametrize(
    ("pending_captured", "preauth_started", "preauth_captured", "observed"),
    [
        (
            "2026-07-29T12:00:00+00:00",
            "2026-07-29T12:00:31+00:00",
            "2026-07-29T12:00:32+00:00",
            "2026-07-29T12:00:33+00:00",
        ),
        (
            "2026-07-29T12:00:00+00:00",
            "2026-07-29T12:00:01+00:00",
            "2026-07-29T12:00:02+00:00",
            "2026-07-29T12:00:13+00:00",
        ),
    ],
)
def test_authorization_rejects_stale_but_ordered_boundaries(
    pending_captured: str,
    preauth_started: str,
    preauth_captured: str,
    observed: str,
) -> None:
    module = _support_module()

    with pytest.raises(module.AcceptanceError, match="freshness"):
        module.validate_authorization_boundary_freshness(
            pending_captured_at=pending_captured,
            before_authorization_started_at=preauth_started,
            before_authorization_captured_at=preauth_captured,
            authorization_observed_at=observed,
        )


def test_cleanup_rejects_replaced_workdir_and_tap_ifindex(
    tmp_path: Path,
) -> None:
    module = _support_module()
    workdir = tmp_path / "work"
    workdir.mkdir()
    ownership = module.resource_ownership(
        workdir, tap_name="aiv21234", tap_ifindex=91
    )
    module.verify_resource_ownership(
        ownership,
        workdir,
        tap_name="aiv21234",
        tap_ifindex=91,
    )
    with pytest.raises(module.AcceptanceError, match="TAP"):
        module.verify_resource_ownership(
            ownership,
            workdir,
            tap_name="aiv21234",
            tap_ifindex=92,
        )

    original = tmp_path / "original"
    workdir.rename(original)
    workdir.mkdir()
    with pytest.raises(module.AcceptanceError, match="work directory"):
        module.verify_resource_ownership(
            ownership,
            workdir,
            tap_name="aiv21234",
            tap_ifindex=91,
        )


def test_cleanup_before_tap_uses_recorded_workdir_identity(
    tmp_path: Path,
) -> None:
    module = _support_module()
    workdir = tmp_path / "work"
    workdir.mkdir()
    (workdir / "partial").write_text("partial", encoding="utf-8")
    ownership = module.workdir_ownership(workdir)

    module.remove_owned_workdir(ownership, workdir)

    assert not workdir.exists()


def test_cleanup_refuses_workdir_replacement_race_without_deleting_it(
    tmp_path: Path,
) -> None:
    module = _support_module()
    workdir = tmp_path / "work"
    workdir.mkdir()
    (workdir / "original").write_text("original", encoding="utf-8")
    ownership = module.workdir_ownership(workdir)
    moved = tmp_path / "moved-original"

    def replace_after_open() -> None:
        workdir.rename(moved)
        workdir.mkdir()
        (workdir / "replacement").write_text(
            "must survive", encoding="utf-8"
        )

    with pytest.raises(module.AcceptanceError, match="identity changed"):
        module.remove_owned_workdir(
            ownership,
            workdir,
            before_final_remove=replace_after_open,
        )

    assert (workdir / "replacement").read_text(
        encoding="utf-8"
    ) == "must survive"


def test_network_namespace_cleanup_cannot_signal_a_reused_process() -> None:
    module = _support_module()
    ownership = module.network_namespace_ownership(
        pid=501,
        process_starttime=7001,
        namespace_device=42,
        namespace_inode=9001,
    )
    signaled: list[int] = []
    closed: list[int] = []

    with pytest.raises(module.AcceptanceError, match="namespace"):
        module.stop_owned_network_namespace(
            ownership,
            pidfd_open=lambda _pid: 73,
            process_starttime_reader=lambda _pid: 8002,
            namespace_identity_reader=lambda _pid: (42, 9002),
            signaler=signaled.append,
            waiter=lambda _pidfd: None,
            descriptor_close=closed.append,
        )
    assert signaled == []
    assert closed == [73]

    module.stop_owned_network_namespace(
        ownership,
        pidfd_open=lambda _pid: 74,
        process_starttime_reader=lambda _pid: 7001,
        namespace_identity_reader=lambda _pid: (42, 9001),
        signaler=signaled.append,
        waiter=lambda _pidfd: None,
        descriptor_close=closed.append,
    )
    assert signaled == [74]
    assert closed == [73, 74]


def test_owned_process_cleanup_cannot_signal_a_reused_process() -> None:
    module = _support_module()
    signaled: list[int] = []
    closed: list[int] = []

    with pytest.raises(module.AcceptanceError, match="process identity"):
        module.stop_owned_process(
            pid=501,
            process_starttime=7001,
            pidfd_open=lambda _pid: 81,
            process_starttime_reader=lambda _pid: 8002,
            signaler=signaled.append,
            waiter=lambda _pidfd: None,
            descriptor_close=closed.append,
        )

    assert signaled == []
    assert closed == [81]

    module.stop_owned_process(
        pid=501,
        process_starttime=7001,
        pidfd_open=lambda _pid: 82,
        process_starttime_reader=lambda _pid: 7001,
        signaler=signaled.append,
        waiter=lambda _pidfd: None,
        descriptor_close=closed.append,
    )
    assert signaled == [82]
    assert closed == [81, 82]


def test_network_namespace_cleanup_returns_after_bounded_wait_failure() -> None:
    module = _support_module()
    ownership = module.network_namespace_ownership(
        pid=501,
        process_starttime=7001,
        namespace_device=42,
        namespace_inode=9001,
    )
    signaled: list[int] = []
    closed: list[int] = []

    def timeout(_pidfd: int) -> None:
        raise module.AcceptanceError(
            "Harness network namespace holder did not exit"
        )

    with pytest.raises(module.AcceptanceError, match="did not exit"):
        module.stop_owned_network_namespace(
            ownership,
            pidfd_open=lambda _pid: 83,
            process_starttime_reader=lambda _pid: 7001,
            namespace_identity_reader=lambda _pid: (42, 9001),
            signaler=signaled.append,
            waiter=timeout,
            descriptor_close=closed.append,
        )

    assert signaled == [83]
    assert closed == [83]


def test_network_namespace_entry_uses_libc_when_python_lacks_setns() -> None:
    module = _support_module()
    calls: list[tuple[int, int]] = []

    class FakeSetns:
        argtypes: object | None = None
        restype: object | None = None

        def __call__(self, descriptor: int, flags: int) -> int:
            calls.append((descriptor, flags))
            return 0

    fake_setns = FakeSetns()
    module._enter_network_namespace(
        79,
        os_setns=None,
        libc_loader=lambda _name, *, use_errno: type(
            "Libc", (), {"setns": fake_setns}
        )(),
    )

    assert calls == [(79, 0x40000000)]
    assert fake_setns.argtypes is not None
    assert fake_setns.restype is not None


def test_network_namespace_entry_fails_closed_when_libc_setns_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _support_module()

    class FailingSetns:
        argtypes: object | None = None
        restype: object | None = None

        def __call__(self, _descriptor: int, _flags: int) -> int:
            return -1

    monkeypatch.setattr(module.ctypes, "get_errno", lambda: 1)
    with pytest.raises(module.AcceptanceError, match="entry is unavailable"):
        module._enter_network_namespace(
            79,
            os_setns=None,
            libc_loader=lambda _name, *, use_errno: type(
                "Libc", (), {"setns": FailingSetns()}
            )(),
        )


def test_network_namespace_entry_can_force_libc_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _support_module()
    calls: list[tuple[int, int]] = []

    def unexpected_os_setns(_descriptor: int, _flags: int) -> None:
        pytest.fail("Python os.setns must not be used in forced fallback")

    class FakeSetns:
        argtypes: object | None = None
        restype: object | None = None

        def __call__(self, descriptor: int, flags: int) -> int:
            calls.append((descriptor, flags))
            return 0

    monkeypatch.setattr(module.os, "setns", unexpected_os_setns, raising=False)
    module._enter_network_namespace(
        79,
        os_setns=None,
        libc_loader=lambda _name, *, use_errno: type(
            "Libc", (), {"setns": FakeSetns()}
        )(),
    )

    assert calls == [(79, 0x40000000)]


def test_authorization_wrapper_reaches_cli_with_same_second_boundary(
    tmp_path: Path,
) -> None:
    state, manifest = _create_run_state(tmp_path)
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    qmp_arguments = {
        "target_write_bytes": 0,
        "sentinel_write_bytes": 0,
        "target_file": manifest["artifacts"]["target"]["canonical_path"],
        "sentinel_file": manifest["artifacts"]["sentinel"]["canonical_path"],
        "install_iso_file": manifest["iso"]["canonical_path"],
    }
    module = _support_module()
    boundary_times = iter(
        (
            "2026-07-29T12:01:00.100000+00:00",
            "2026-07-29T12:01:00.200000+00:00",
            "2026-07-29T12:01:01.100000+00:00",
            "2026-07-29T12:01:01.900000+00:00",
        )
    )

    def capture(_socket: Path, output: Path) -> None:
        _write_qmp(output, **qmp_arguments)

    for phase in ("pending", "before-authorization"):
        module.capture_authorization_boundary(
            state,
            socket_path=tmp_path / "install.qmp.sock",
            evidence_dir=evidence,
            phase=phase,
            qmp_capture=capture,
            clock=lambda: next(boundary_times),
        )
    initial_qmp = evidence / "pending.qmp.jsonl"
    immediate_qmp = evidence / "before-authorization.qmp.jsonl"
    plan_bytes = json.dumps(
        {
            "target_disk": {
                "fingerprint": "sha256:" + "d" * 64,
                "path": "/dev/vda",
            }
        },
        sort_keys=True,
    ).encode()
    request = {
        "disk_fingerprint": "sha256:" + "d" * 64,
        "inventory_sha256": "c" * 64,
        "plan_sha256": hashlib.sha256(plan_bytes).hexdigest(),
        "session_id": "install-20260729T120000Z-a1b2c3d4",
        "target_disk": "/dev/vda",
    }
    request["preflight_approval_attestation_sha256"] = (
        _write_preflight_approval(module, state, request)
    )
    request_path = state / "authorization-request.json"
    request_path.write_text(
        json.dumps(request, sort_keys=True) + "\n", encoding="utf-8"
    )
    calls: list[list[str]] = []
    status_reads = 0

    def load_status(_session_id: str) -> dict[str, object]:
        nonlocal status_reads
        status_reads += 1
        base: dict[str, object] = {
            "agent_status": {"reported_stage": "preflight_ready"},
            "disk_fingerprint": request["disk_fingerprint"],
            "inventory_sha256": request["inventory_sha256"],
            "session_id": request["session_id"],
            "state": "plan_published",
        }
        if status_reads == 2:
            base["execution"] = {
                "authorized_at": (
                    "2026-07-29T12:01:01.950000+00:00"
                ),
                "disk_fingerprint": request["disk_fingerprint"],
                "inventory_sha256": request["inventory_sha256"],
                "plan_sha256": request["plan_sha256"],
                "revision": 1,
                "state": "authorized",
                "target_disk": "/dev/vda",
            }
        return base

    def real_cli_boundary(
        arguments: list[str],
        *,
        stdout: StringIO,
        stderr: StringIO,
    ) -> int:
        calls.append(arguments)
        stdout.write(
            json.dumps(
                {
                    "status": "ok",
                    "session": {
                        "execution_id": (
                            f"{request['session_id']}:execution-0001"
                        ),
                        "execution_state": "authorized",
                        "session_id": request["session_id"],
                    },
                }
            )
            + "\n"
        )
        return 0

    result = module.main(
        [
            "authorize-execution",
            "--state-dir",
            str(state),
            "--pending-boundary",
            str(evidence / "pending-boundary.json"),
            "--before-authorization-boundary",
            str(evidence / "before-authorization-boundary.json"),
            "--observed-at",
            "2026-07-29T12:01:01.900001+00:00",
        ],
        cli=real_cli_boundary,
        status_loader=load_status,
        revision_loader=lambda _session, _filename: plan_bytes,
        euid=lambda: 0,
    )

    assert result == 0
    assert calls == [
        [
            "--json",
            "install-sessions",
            "authorize-execution",
            request["session_id"],
            "--plan-sha256",
            request["plan_sha256"],
            "--inventory-sha256",
            request["inventory_sha256"],
            "--disk-fingerprint",
            request["disk_fingerprint"],
            "--confirm-target",
            "/dev/vda",
            "--reason",
            f"Disposable OVMF acceptance {manifest['run_id']}",
        ]
    ]
    attestation = module.load_attestation_chain(state)[0]
    assert attestation["event"] == "authorization"
    assert attestation["payload"]["controller"] == {
        "execution_id": (
            "install-20260729T120000Z-a1b2c3d4:execution-0001"
        ),
        "state": "authorized",
    }
    assert attestation["payload"]["initial_qmp_sha256"] == hashlib.sha256(
        initial_qmp.read_bytes()
    ).hexdigest()
    assert attestation["payload"][
        "before_authorization_qmp_sha256"
    ] == hashlib.sha256(immediate_qmp.read_bytes()).hexdigest()
    module.verify_attestation_chain(state, [attestation])


def test_root_authorization_refuses_nonroot_and_second_snapshot_writes(
    tmp_path: Path,
) -> None:
    state, manifest = _create_run_state(tmp_path)
    initial = tmp_path / "initial.qmp.jsonl"
    before = tmp_path / "before.qmp.jsonl"
    arguments = {
        "target_write_bytes": 0,
        "sentinel_write_bytes": 0,
        "target_file": manifest["artifacts"]["target"]["canonical_path"],
        "sentinel_file": manifest["artifacts"]["sentinel"]["canonical_path"],
    }
    _write_qmp(initial, **arguments)
    _write_qmp(before, **(arguments | {"target_write_bytes": 4096}))
    records = {}
    for phase in ("initial", "before"):
        for artifact in ("target", "sentinel"):
            record = tmp_path / f"{phase}-{artifact}.sha256"
            binding = manifest["artifacts"][artifact]
            _write_sha(
                record,
                binding["initial_sha256"],
                binding["canonical_path"],
            )
            records[f"{phase}_{artifact}"] = record
    module = _support_module()
    request = state / "authorization-request.json"
    plan_bytes = json.dumps(
        {
            "target_disk": {
                "fingerprint": "sha256:" + "d" * 64,
                "path": "/dev/vda",
            }
        },
        sort_keys=True,
    ).encode()
    approved = {
        "disk_fingerprint": "sha256:" + "d" * 64,
        "inventory_sha256": "c" * 64,
        "plan_sha256": hashlib.sha256(plan_bytes).hexdigest(),
        "session_id": "install-20260729T120000Z-a1b2c3d4",
        "target_disk": "/dev/vda",
    }
    request.write_text(
        json.dumps(
            {
                **approved,
                "preflight_approval_attestation_sha256": (
                    _write_preflight_approval(module, state, approved)
                ),
            }
        ),
        encoding="utf-8",
    )
    common = {
        "request_path": request,
        "initial_qmp": initial,
        "before_authorization_qmp": before,
        "initial_target_sha": records["initial_target"],
        "before_authorization_target_sha": records["before_target"],
        "initial_sentinel_sha": records["initial_sentinel"],
        "before_authorization_sentinel_sha": records["before_sentinel"],
        "observed_at": "2026-07-29T12:02:00+00:00",
        "cli": lambda *_args, **_kwargs: pytest.fail(
            "controller CLI must not run"
        ),
        "status_loader": lambda _session_id: {
            "agent_status": {"reported_stage": "preflight_ready"},
            "disk_fingerprint": "sha256:" + "d" * 64,
            "inventory_sha256": "c" * 64,
            "session_id": "install-20260729T120000Z-a1b2c3d4",
            "state": "plan_published",
        },
        "revision_loader": lambda _session, _filename: plan_bytes,
    }
    with pytest.raises(module.AcceptanceError, match="root"):
        module.invoke_root_execution_authorization(
            state, **common, euid=lambda: 1000
        )
    with pytest.raises(module.AcceptanceError, match="before authorization"):
        module.invoke_root_execution_authorization(
            state, **common, euid=lambda: 0
        )


def test_root_authorization_reports_safe_controller_error_code(
    tmp_path: Path,
) -> None:
    state, manifest = _create_run_state(tmp_path)
    initial = tmp_path / "initial.qmp.jsonl"
    before = tmp_path / "before.qmp.jsonl"
    qmp_arguments = {
        "target_write_bytes": 0,
        "sentinel_write_bytes": 0,
        "target_file": manifest["artifacts"]["target"]["canonical_path"],
        "sentinel_file": manifest["artifacts"]["sentinel"]["canonical_path"],
    }
    _write_qmp(initial, **qmp_arguments)
    _write_qmp(before, **qmp_arguments)
    records: dict[str, Path] = {}
    for phase in ("initial", "before"):
        for artifact in ("target", "sentinel"):
            record = tmp_path / f"{phase}-{artifact}.sha256"
            binding = manifest["artifacts"][artifact]
            _write_sha(
                record,
                binding["initial_sha256"],
                binding["canonical_path"],
            )
            records[f"{phase}_{artifact}"] = record
    module = _support_module()
    plan_bytes = json.dumps(
        {
            "target_disk": {
                "fingerprint": "sha256:" + "d" * 64,
                "path": "/dev/vda",
            }
        },
        sort_keys=True,
    ).encode()
    approved = {
        "disk_fingerprint": "sha256:" + "d" * 64,
        "inventory_sha256": "c" * 64,
        "plan_sha256": hashlib.sha256(plan_bytes).hexdigest(),
        "session_id": "install-20260729T120000Z-a1b2c3d4",
        "target_disk": "/dev/vda",
    }
    request = state / "authorization-request.json"
    request.write_text(
        json.dumps(
            {
                **approved,
                "preflight_approval_attestation_sha256": (
                    _write_preflight_approval(module, state, approved)
                ),
            }
        ),
        encoding="utf-8",
    )

    def rejected_cli(
        _arguments: list[str], *, stdout: StringIO, stderr: StringIO
    ) -> int:
        stdout.write(
            json.dumps(
                {
                    "status": "error",
                    "error": {
                        "code": "execution_inputs_unavailable",
                        "message": "Execution release inputs are unavailable",
                    },
                }
            )
            + "\n"
        )
        return 4

    with pytest.raises(
        module.AcceptanceError,
        match="execution_inputs_unavailable",
    ):
        module.invoke_root_execution_authorization(
            state,
            request_path=request,
            initial_qmp=initial,
            before_authorization_qmp=before,
            initial_target_sha=records["initial_target"],
            before_authorization_target_sha=records["before_target"],
            initial_sentinel_sha=records["initial_sentinel"],
            before_authorization_sentinel_sha=records["before_sentinel"],
            observed_at="2026-07-29T12:02:00+00:00",
            cli=rejected_cli,
            status_loader=lambda _session_id: {
                "agent_status": {"reported_stage": "preflight_ready"},
                "disk_fingerprint": approved["disk_fingerprint"],
                "inventory_sha256": approved["inventory_sha256"],
                "session_id": approved["session_id"],
                "state": "plan_published",
            },
            revision_loader=lambda _session, _filename: plan_bytes,
            euid=lambda: 0,
        )
