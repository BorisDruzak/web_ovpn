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
            "return": [
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
            ],
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


def test_harness_uses_run_owned_authorization_and_postflight_chain() -> None:
    source = HARNESS.read_text(encoding="utf-8")
    assert "--timeline" not in source
    assert "--postflight <" not in source
    assert "create-authorization-request" in source
    assert source.index("--output \"$evidence/initial.qmp.jsonl\"") < (
        source.index("create-authorization-request")
    )
    assert source.index("create-authorization-request") < source.index(
        "--output \"$evidence/before-authorization.qmp.jsonl\""
    )
    assert source.index(
        "--output \"$evidence/before-authorization.qmp.jsonl\""
    ) < source.index("authorize-execution")
    assert "issue-postflight-challenge" in source
    assert "--acceptance-state-dir \"$state_dir\"" in source
    assert "verify-resource-ownership" in source


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
    state, manifest = _create_run_state(tmp_path)
    module = _support_module()
    target = Path(manifest["artifacts"]["target"]["canonical_path"])
    sentinel = Path(
        manifest["artifacts"]["sentinel"]["canonical_path"]
    )
    initial_qmp = tmp_path / "initial.qmp.jsonl"
    immediate_qmp = tmp_path / "immediate.qmp.jsonl"
    after_qmp = tmp_path / "after.qmp.jsonl"
    common = {
        "target_file": str(target),
        "sentinel_file": str(sentinel),
    }
    _write_qmp(
        initial_qmp,
        target_write_bytes=0,
        sentinel_write_bytes=0,
        **common,
    )
    _write_qmp(
        immediate_qmp,
        target_write_bytes=0,
        sentinel_write_bytes=0,
        **common,
    )
    initial_target = hashlib.sha256(target.read_bytes()).hexdigest()
    initial_sentinel = hashlib.sha256(sentinel.read_bytes()).hexdigest()
    sha_records: dict[str, Path] = {}
    for phase in ("initial", "immediate"):
        for name, path, digest in (
            ("target", target, initial_target),
            ("sentinel", sentinel, initial_sentinel),
        ):
            record = tmp_path / f"{phase}-{name}.sha256"
            _write_sha(record, digest, str(path))
            sha_records[f"{phase}_{name}"] = record
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
            "request": request,
            "sentinel_sha256_before_authorization": initial_sentinel,
            "target_disk": "/dev/vda",
            "target_sha256_before_authorization": initial_target,
        },
        observed_at="2026-07-29T12:02:00+00:00",
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
                f"2026-07-29T12:02:0{sequence - 1}+00:00"
            ),
            previous_sha256=module.attestation_sha256(chain[-1]),
        )
        chain.append(item)
    for item in chain:
        module.store_attestation(state, item)
    boot_qmp = tmp_path / "postflight-boot.qmp.jsonl"
    _write_boot_qmp(boot_qmp, manifest)
    delivery = module.issue_postflight_boot_challenge(
        state,
        qmp_path=boot_qmp,
        observed_at="2026-07-29T12:03:00+00:00",
    )
    assert delivery["boot_nonce"] != manifest["challenge"]
    postflight = {
        "boot_attestation": delivery["boot_attestation"],
        "boot_id": str(uuid4()),
        "boot_nonce": delivery["boot_nonce"],
        "challenge": manifest["challenge"],
        "reported_at": "2026-07-29T12:03:01+00:00",
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
        **common,
    )
    for name, path in (("target", target), ("sentinel", sentinel)):
        record = tmp_path / f"after-{name}.sha256"
        _write_sha(
            record, hashlib.sha256(path.read_bytes()).hexdigest(), str(path)
        )
        sha_records[f"after_{name}"] = record
    receipt = tmp_path / "acceptance-receipt.json"
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
        "disk_fingerprint": plan["target_disk"]["fingerprint"],
        "inventory_sha256": "c" * 64,
        "plan_sha256": hashlib.sha256(plan_bytes).hexdigest(),
        "session_id": session_id,
        "target_disk": "/dev/vda",
    }
    assert json.loads(
        (state / "authorization-request.json").read_text(
            encoding="utf-8"
        )
    ) == request


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


def test_root_authorization_checks_two_zero_write_snapshots_then_calls_cli(
    tmp_path: Path,
) -> None:
    state, manifest = _create_run_state(tmp_path)
    initial_qmp = tmp_path / "initial.qmp.jsonl"
    immediate_qmp = tmp_path / "immediate-before-authorization.qmp.jsonl"
    qmp_arguments = {
        "target_write_bytes": 0,
        "sentinel_write_bytes": 0,
        "target_file": manifest["artifacts"]["target"]["canonical_path"],
        "sentinel_file": manifest["artifacts"]["sentinel"]["canonical_path"],
    }
    _write_qmp(initial_qmp, **qmp_arguments)
    _write_qmp(immediate_qmp, **qmp_arguments)
    sha_paths: dict[str, Path] = {}
    for phase in ("initial", "immediate"):
        for artifact in ("target", "sentinel"):
            path = tmp_path / f"{phase}-{artifact}.sha256"
            binding = manifest["artifacts"][artifact]
            _write_sha(
                path,
                binding["initial_sha256"],
                binding["canonical_path"],
            )
            sha_paths[f"{phase}_{artifact}"] = path
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
                "authorized_at": "2026-07-29T12:02:00+00:00",
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

    module = _support_module()
    attestation = module.invoke_root_execution_authorization(
        state,
        request_path=request_path,
        initial_qmp=initial_qmp,
        before_authorization_qmp=immediate_qmp,
        initial_target_sha=sha_paths["initial_target"],
        before_authorization_target_sha=sha_paths["immediate_target"],
        initial_sentinel_sha=sha_paths["initial_sentinel"],
        before_authorization_sentinel_sha=sha_paths["immediate_sentinel"],
        observed_at="2026-07-29T12:02:00+00:00",
        cli=real_cli_boundary,
        status_loader=load_status,
        revision_loader=lambda _session, _filename: plan_bytes,
        euid=lambda: 0,
    )

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
    request.write_text(
        json.dumps(
            {
                "disk_fingerprint": "sha256:" + "d" * 64,
                "inventory_sha256": "c" * 64,
                "plan_sha256": hashlib.sha256(plan_bytes).hexdigest(),
                "session_id": "install-20260729T120000Z-a1b2c3d4",
                "target_disk": "/dev/vda",
            }
        ),
        encoding="utf-8",
    )
    module = _support_module()
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
