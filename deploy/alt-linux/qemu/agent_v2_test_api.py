#!/usr/bin/env python3
"""QMP and evidence gates for disposable agent-v2 execution acceptance."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import socket
import stat
import sys
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from typing import Any, Callable, NoReturn, Sequence
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


REPO_ROOT = Path(__file__).resolve().parents[3]
CONTROL_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "control"
if str(CONTROL_ROOT) not in sys.path:
    sys.path.insert(0, str(CONTROL_ROOT))


def control_cli_main(*args: object, **kwargs: object) -> int:
    """Invoke the production controller CLI without a parallel implementation."""
    from alt_deploy.cli import main

    return main(*args, **kwargs)


def controller_status(session_id: str) -> dict[str, object]:
    """Read authoritative local controller state."""
    from alt_deploy.config import Settings
    from alt_deploy.install_session_repository import (
        InstallSessionRepository,
    )

    return InstallSessionRepository(Settings.from_env()).load_status(
        session_id
    )


def controller_revision_file(session_id: str, filename: str) -> bytes:
    """Read an authoritative, immutable controller revision artifact."""
    from alt_deploy.config import Settings
    from alt_deploy.install_session_repository import (
        InstallSessionRepository,
    )

    return InstallSessionRepository(Settings.from_env()).read_revision_file(
        session_id, filename
    )


def controller_statuses() -> list[dict[str, object]]:
    """List authoritative local controller sessions."""
    from alt_deploy.config import Settings
    from alt_deploy.install_session_repository import (
        InstallSessionRepository,
    )

    return InstallSessionRepository(Settings.from_env()).list_statuses()


PASS_LINE = (
    "PASS: root-authorized install wrote only the disposable target; "
    "authenticated postflight installed"
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SESSION_ID_RE = re.compile(
    r"^install-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$"
)
MAX_EVIDENCE_BYTES = 4 * 1024 * 1024
TIMELINE_KEYS = (
    "waiting_for_authorization_at",
    "preflight_ready_at",
    "root_authorized_at",
    "execution_claimed_at",
    "verified_handoff_at",
    "installer_completed_at",
    "postflight_authenticated_at",
)
RUN_ID_RE = re.compile(r"^run-[0-9a-f]{64}$")
NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
KEY_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class AcceptanceError(RuntimeError):
    """A bounded error containing no request or credential material."""


def _fail(message: str) -> NoReturn:
    raise AcceptanceError(message)


def _read_bytes(path: Path, *, maximum: int = MAX_EVIDENCE_BYTES) -> bytes:
    try:
        metadata = path.stat()
        if (
            not path.is_file()
            or path.is_symlink()
            or not 1 <= metadata.st_size <= maximum
        ):
            _fail(f"Evidence file is invalid: {path.name}")
        return path.read_bytes()
    except OSError as exc:
        raise AcceptanceError(
            f"Evidence file cannot be read: {path.name}"
        ) from exc


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError
        result[name] = value
    return result


def _read_json(path: Path) -> dict[str, object]:
    try:
        document = json.loads(
            _read_bytes(path).decode("utf-8"),
            object_pairs_hook=_strict_object,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise AcceptanceError(
            f"Evidence JSON is invalid: {path.name}"
        ) from exc
    if not isinstance(document, dict):
        _fail(f"Evidence JSON must be an object: {path.name}")
    return document


def _json_bytes(document: object) -> bytes:
    return (
        json.dumps(document, ensure_ascii=True, indent=2, sort_keys=True)
        + "\n"
    ).encode("utf-8")


def _write_new(path: Path, content: bytes, *, mode: int = 0o644) -> None:
    if not path.parent.is_dir() or path.is_symlink():
        _fail("Evidence output parent is unavailable")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    try:
        descriptor = os.open(path, flags, mode)
    except OSError as exc:
        raise AcceptanceError("Refusing to overwrite evidence output") from exc
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)
    os.chmod(path, mode)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(64 * 1024):
                digest.update(chunk)
    except OSError as exc:
        raise AcceptanceError("Run artifact cannot be hashed") from exc
    return digest.hexdigest()


def _canonical_regular(path: Path) -> tuple[Path, os.stat_result]:
    try:
        before = path.lstat()
        canonical = path.resolve(strict=True)
        opened = canonical.stat()
    except OSError as exc:
        raise AcceptanceError("Run artifact cannot be inspected") from exc
    if (
        not stat.S_ISREG(before.st_mode)
        or path.is_symlink()
        or not stat.S_ISREG(opened.st_mode)
        or before.st_dev != opened.st_dev
        or before.st_ino != opened.st_ino
    ):
        _fail("Run artifact identity is unsafe")
    return canonical, opened


def _file_identity(metadata: os.stat_result) -> dict[str, int]:
    return {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "size": metadata.st_size,
    }


def _urlsafe_nonce() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(
        "ascii"
    ).rstrip("=")


def create_run_state(
    state_dir: Path,
    *,
    iso: Path,
    target: Path,
    sentinel: Path,
    vm_instance_id: str,
) -> dict[str, object]:
    if not state_dir.is_dir() or any(state_dir.iterdir()):
        _fail("Run state directory must be empty")
    try:
        canonical_state = state_dir.resolve(strict=True)
        UUID(vm_instance_id)
    except (OSError, ValueError) as exc:
        raise AcceptanceError("Run state identity is invalid") from exc
    os.chmod(canonical_state, 0o700)
    paths: dict[str, tuple[Path, os.stat_result]] = {
        "iso": _canonical_regular(iso),
        "target": _canonical_regular(target),
        "sentinel": _canonical_regular(sentinel),
    }
    if len(
        {
            (metadata.st_dev, metadata.st_ino)
            for _path, metadata in paths.values()
        }
    ) != 3:
        _fail("Run artifacts must have distinct file identities")
    private = Ed25519PrivateKey.generate()
    private_bytes = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_bytes = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    raw_public = private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    key_id = "sha256:" + hashlib.sha256(raw_public).hexdigest()
    _write_new(
        canonical_state / "attestation-private.pem",
        private_bytes,
        mode=0o600,
    )
    _write_new(
        canonical_state / "attestation-public.pem",
        public_bytes,
        mode=0o644,
    )
    (canonical_state / "attestations").mkdir(mode=0o700)
    iso_path, iso_metadata = paths["iso"]
    manifest: dict[str, object] = {
        "artifacts": {
            name: {
                "canonical_path": str(paths[name][0]),
                "device": name,
                "file_identity": _file_identity(paths[name][1]),
                "initial_sha256": _sha256_file(paths[name][0]),
            }
            for name in ("target", "sentinel")
        },
        "challenge": _urlsafe_nonce(),
        "iso": {
            "canonical_path": str(iso_path),
            "file_identity": _file_identity(iso_metadata),
            "sha256": _sha256_file(iso_path),
        },
        "run_id": "run-" + secrets.token_hex(32),
        "schema_version": 1,
        "trust_anchor_key_id": key_id,
        "vm_instance_id": str(UUID(vm_instance_id)),
    }
    _write_new(
        canonical_state / "run-manifest.json",
        _json_bytes(manifest),
        mode=0o644,
    )
    return manifest


def _attestation_path(state_dir: Path, sequence: int, event: str) -> Path:
    return (
        state_dir.resolve(strict=True)
        / "attestations"
        / f"{sequence:02d}-{event}.json"
    )


def store_attestation(
    state_dir: Path, attestation: dict[str, object]
) -> Path:
    sequence = attestation.get("sequence")
    event = attestation.get("event")
    if (
        type(sequence) is not int
        or not isinstance(event, str)
        or not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", event)
    ):
        _fail("Attestation storage identity is invalid")
    path = _attestation_path(state_dir, sequence, event)
    _write_new(path, _json_bytes(attestation), mode=0o600)
    return path


def load_attestation_chain(state_dir: Path) -> list[dict[str, object]]:
    directory = state_dir.resolve(strict=True) / "attestations"
    expected_names = (
        "01-authorization.json",
        "02-claimed.json",
        "03-handoff_started.json",
        "04-installer_started.json",
        "05-postflight_boot.json",
    )
    try:
        paths = sorted(directory.iterdir())
    except OSError as exc:
        raise AcceptanceError(
            "Run attestation directory is unavailable"
        ) from exc
    allowed_names = [
        list(expected_names[:length])
        for length in range(1, len(expected_names) + 1)
    ]
    allowed_names.append([*expected_names, "06-installed.json"])
    if [path.name for path in paths] not in allowed_names:
        _fail("Run attestation set is incomplete or ambiguous")
    chain = [_read_json(path) for path in paths]
    verify_attestation_chain(state_dir, chain)
    return chain


def _load_run_manifest(state_dir: Path) -> dict[str, object]:
    manifest = _read_json(state_dir / "run-manifest.json")
    if (
        set(manifest)
        != {
            "artifacts",
            "challenge",
            "iso",
            "run_id",
            "schema_version",
            "trust_anchor_key_id",
            "vm_instance_id",
        }
        or manifest.get("schema_version") != 1
        or not isinstance(manifest.get("run_id"), str)
        or not RUN_ID_RE.fullmatch(str(manifest["run_id"]))
        or not isinstance(manifest.get("challenge"), str)
        or not NONCE_RE.fullmatch(str(manifest["challenge"]))
        or not isinstance(manifest.get("trust_anchor_key_id"), str)
        or not KEY_ID_RE.fullmatch(str(manifest["trust_anchor_key_id"]))
    ):
        _fail("Run manifest is invalid")
    return manifest


def _qmp_responses(path: Path) -> dict[str, dict[str, object]]:
    try:
        lines = _read_bytes(path).decode("utf-8").splitlines()
        messages = [
            json.loads(line, object_pairs_hook=_strict_object)
            for line in lines
            if line
        ]
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise AcceptanceError("QMP transcript is invalid") from exc
    responses: dict[str, dict[str, object]] = {}
    for message in messages:
        if not isinstance(message, dict):
            _fail("QMP transcript message is invalid")
        response_id = message.get("id")
        if response_id is None:
            continue
        if (
            response_id not in {"capabilities", "blockstats", "block"}
            or response_id in responses
        ):
            _fail("QMP response ID is invalid or duplicated")
        responses[str(response_id)] = message
    if set(responses) != {"capabilities", "blockstats", "block"}:
        _fail("QMP response ID evidence is incomplete")
    if responses["capabilities"].get("return") != {}:
        _fail("QMP capabilities response is invalid")
    if not isinstance(responses["blockstats"].get("return"), list):
        _fail("QMP blockstats response ID is invalid")
    if not isinstance(responses["block"].get("return"), list):
        _fail("QMP block response ID is invalid")
    return responses


def read_bound_qmp_snapshot(
    path: Path,
    state_dir: Path,
) -> dict[str, dict[str, object]]:
    manifest = _load_run_manifest(state_dir)
    responses = _qmp_responses(path)
    result = _read_qmp_snapshot(path)
    inserted = responses["block"]["return"]
    if not isinstance(inserted, list):
        _fail("QMP inserted file evidence is invalid")
    files = {
        item.get("device"): item.get("inserted", {}).get("file")
        for item in inserted
        if isinstance(item, dict)
        and isinstance(item.get("inserted"), dict)
    }
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict):
        _fail("Run artifact binding is invalid")
    for name in ("target", "sentinel"):
        binding = artifacts.get(name)
        if (
            not isinstance(binding, dict)
            or files.get(name) != binding.get("canonical_path")
        ):
            _fail(f"QMP {name} inserted file binding is invalid")
    return result


def read_bound_sha256_record(
    path: Path,
    state_dir: Path,
    artifact: str,
    *,
    require_initial_size: bool = True,
    require_current_bytes: bool = True,
) -> str:
    manifest = _load_run_manifest(state_dir)
    if artifact not in {"target", "sentinel"}:
        _fail("SHA-256 artifact binding is invalid")
    binding = manifest["artifacts"][artifact]
    if not isinstance(binding, dict):
        _fail("SHA-256 artifact binding is invalid")
    try:
        line = _read_bytes(path, maximum=4096).decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise AcceptanceError("SHA-256 record is not ASCII") from exc
    if len(line) != 1:
        _fail("SHA-256 record must contain exactly one line")
    fields = line[0].split(maxsplit=1)
    if (
        len(fields) != 2
        or not SHA256_RE.fullmatch(fields[0])
        or fields[1] != binding.get("canonical_path")
    ):
        _fail("SHA-256 record filename binding is invalid")
    canonical, metadata = _canonical_regular(Path(str(fields[1])))
    expected_identity = binding.get("file_identity")
    actual_identity = _file_identity(metadata)
    if (
        str(canonical) != binding.get("canonical_path")
        or not isinstance(expected_identity, dict)
        or actual_identity.get("device")
        != expected_identity.get("device")
        or actual_identity.get("inode")
        != expected_identity.get("inode")
        or (
            require_initial_size
            and actual_identity.get("size")
            != expected_identity.get("size")
        )
    ):
        _fail("SHA-256 artifact file identity changed")
    if require_current_bytes and _sha256_file(canonical) != fields[0]:
        _fail("SHA-256 record does not match artifact bytes")
    return fields[0]


def _private_attestation_key(state_dir: Path) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(
            _read_bytes(
                state_dir / "attestation-private.pem", maximum=16 * 1024
            ),
            password=None,
        )
    except ValueError as exc:
        raise AcceptanceError("Run attestation key is invalid") from exc
    if not isinstance(key, Ed25519PrivateKey):
        _fail("Run attestation key is invalid")
    return key


def _attestation_unsigned(document: dict[str, object]) -> bytes:
    return (
        json.dumps(
            document,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def issue_attestation(
    state_dir: Path,
    *,
    event: str,
    sequence: int,
    payload: dict[str, object],
    observed_at: str | None = None,
    previous_sha256: str | None,
) -> dict[str, object]:
    manifest = _load_run_manifest(state_dir)
    if (
        not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", event)
        or type(sequence) is not int
        or sequence < 1
        or not isinstance(payload, dict)
        or (
            previous_sha256 is not None
            and not SHA256_RE.fullmatch(previous_sha256)
        )
    ):
        _fail("Attestation input is invalid")
    _parse_timestamp(observed_at, field="observed_at")
    unsigned = {
        "challenge": manifest["challenge"],
        "event": event,
        "observed_at": observed_at,
        "payload": payload,
        "previous_attestation_sha256": previous_sha256,
        "run_id": manifest["run_id"],
        "schema_version": 1,
        "sequence": sequence,
        "trust_anchor_key_id": manifest["trust_anchor_key_id"],
    }
    signature = _private_attestation_key(state_dir).sign(
        _attestation_unsigned(unsigned)
    )
    return {
        **unsigned,
        "signature_b64": base64.b64encode(signature).decode("ascii"),
    }


def attestation_sha256(attestation: dict[str, object]) -> str:
    return hashlib.sha256(_json_bytes(attestation)).hexdigest()


def verify_attestation_chain(
    state_dir: Path,
    attestations: Sequence[dict[str, object]],
) -> None:
    manifest = _load_run_manifest(state_dir)
    try:
        public = serialization.load_pem_public_key(
            _read_bytes(
                state_dir / "attestation-public.pem", maximum=16 * 1024
            )
        )
    except ValueError as exc:
        raise AcceptanceError("Run trust anchor is invalid") from exc
    if not isinstance(public, Ed25519PublicKey):
        _fail("Run trust anchor is invalid")
    previous: str | None = None
    previous_time: datetime | None = None
    for expected_sequence, document in enumerate(attestations, start=1):
        if (
            not isinstance(document, dict)
            or document.get("run_id") != manifest["run_id"]
            or document.get("challenge") != manifest["challenge"]
            or document.get("trust_anchor_key_id")
            != manifest["trust_anchor_key_id"]
        ):
            _fail("Attestation run binding is invalid")
        signature_b64 = document.get("signature_b64")
        unsigned = dict(document)
        unsigned.pop("signature_b64", None)
        if (
            set(document)
            != {
                "challenge",
                "event",
                "observed_at",
                "payload",
                "previous_attestation_sha256",
                "run_id",
                "schema_version",
                "sequence",
                "signature_b64",
                "trust_anchor_key_id",
            }
            or document.get("schema_version") != 1
            or document.get("sequence") != expected_sequence
            or document.get("previous_attestation_sha256") != previous
            or not isinstance(signature_b64, str)
        ):
            _fail("Attestation chain is invalid")
        observed = _parse_timestamp(
            document.get("observed_at"), field="observed_at"
        )
        if previous_time is not None and observed <= previous_time:
            _fail("Attestation timeline is invalid")
        try:
            signature = base64.b64decode(signature_b64, validate=True)
            public.verify(signature, _attestation_unsigned(unsigned))
        except (InvalidSignature, ValueError):
            _fail("Attestation signature is invalid")
        previous = attestation_sha256(document)
        previous_time = observed


def resource_ownership(
    workdir: Path,
    *,
    tap_name: str,
    tap_ifindex: int,
) -> dict[str, object]:
    try:
        canonical = workdir.resolve(strict=True)
        metadata = canonical.stat()
    except OSError as exc:
        raise AcceptanceError("Harness work directory is unavailable") from exc
    if (
        not canonical.is_dir()
        or not re.fullmatch(r"aiv2[0-9]{1,10}", tap_name)
        or type(tap_ifindex) is not int
        or tap_ifindex < 1
    ):
        _fail("Harness resource ownership is invalid")
    return {
        "tap_ifindex": tap_ifindex,
        "tap_name": tap_name,
        "workdir": str(canonical),
        "workdir_device": metadata.st_dev,
        "workdir_inode": metadata.st_ino,
    }


def verify_resource_ownership(
    ownership: dict[str, object],
    workdir: Path,
    *,
    tap_name: str,
    tap_ifindex: int,
) -> None:
    current = resource_ownership(
        workdir, tap_name=tap_name, tap_ifindex=tap_ifindex
    )
    if (
        current["workdir"] != ownership.get("workdir")
        or current["workdir_device"] != ownership.get("workdir_device")
        or current["workdir_inode"] != ownership.get("workdir_inode")
    ):
        _fail("Harness work directory creation identity changed")
    if (
        current["tap_name"] != ownership.get("tap_name")
        or current["tap_ifindex"] != ownership.get("tap_ifindex")
    ):
        _fail("Harness TAP creation identity changed")


def create_authorization_request(
    state_dir: Path,
    *,
    statuses: Callable[[], list[dict[str, object]]] = controller_statuses,
    revision_file: Callable[[str, str], bytes] = controller_revision_file,
) -> dict[str, object]:
    """Derive the authorization request from the one live preflight session."""
    candidates = []
    for status in statuses():
        agent = status.get("agent_status")
        if (
            status.get("state") == "plan_published"
            and "execution" not in status
            and isinstance(agent, dict)
            and agent.get("reported_stage") == "preflight_ready"
        ):
            candidates.append(status)
    if len(candidates) != 1:
        _fail("Exactly one controller preflight session is required")
    status = candidates[0]
    session_id = status.get("session_id")
    if (
        not isinstance(session_id, str)
        or not SESSION_ID_RE.fullmatch(session_id)
    ):
        _fail("Controller preflight session identity is invalid")
    try:
        plan_bytes = revision_file(session_id, "plan.json")
        plan = json.loads(
            plan_bytes.decode("utf-8"),
            object_pairs_hook=_strict_object,
        )
        target = plan["target_disk"]
    except (
        KeyError,
        TypeError,
        UnicodeDecodeError,
        ValueError,
        json.JSONDecodeError,
    ):
        _fail("Controller preflight plan is invalid")
    if (
        not isinstance(plan, dict)
        or not isinstance(target, dict)
        or target.get("path") != "/dev/vda"
        or not isinstance(target.get("fingerprint"), str)
        or not re.fullmatch(
            r"sha256:[0-9a-f]{64}", str(target["fingerprint"])
        )
        or not isinstance(status.get("inventory_sha256"), str)
        or not SHA256_RE.fullmatch(str(status["inventory_sha256"]))
    ):
        _fail("Controller preflight plan binding is invalid")
    request = {
        "disk_fingerprint": target["fingerprint"],
        "inventory_sha256": status["inventory_sha256"],
        "plan_sha256": hashlib.sha256(plan_bytes).hexdigest(),
        "session_id": session_id,
        "target_disk": "/dev/vda",
    }
    output = state_dir.resolve(strict=True) / "authorization-request.json"
    _write_new(output, _json_bytes(request), mode=0o600)
    return request


def invoke_root_execution_authorization(
    state_dir: Path,
    *,
    request_path: Path,
    initial_qmp: Path,
    before_authorization_qmp: Path,
    initial_target_sha: Path,
    before_authorization_target_sha: Path,
    initial_sentinel_sha: Path,
    before_authorization_sentinel_sha: Path,
    observed_at: str,
    cli: Callable[..., int] = control_cli_main,
    status_loader: Callable[[str], dict[str, object]] = controller_status,
    revision_loader: Callable[
        [str, str], bytes
    ] = controller_revision_file,
    euid: Callable[[], int] = lambda: getattr(
        os, "geteuid", lambda: -1
    )(),
) -> dict[str, object]:
    if euid() != 0:
        _fail("Real root execution authorization is required")
    manifest = _load_run_manifest(state_dir)
    expected_request_path = (
        state_dir.resolve(strict=True) / "authorization-request.json"
    )
    try:
        actual_request_path = request_path.resolve(strict=True)
    except OSError as exc:
        raise AcceptanceError(
            "Execution authorization request is unavailable"
        ) from exc
    if actual_request_path != expected_request_path:
        _fail("Execution authorization request is not run-owned")
    request = _read_json(actual_request_path)
    if (
        set(request)
        != {
            "disk_fingerprint",
            "inventory_sha256",
            "plan_sha256",
            "session_id",
            "target_disk",
        }
        or not isinstance(request.get("session_id"), str)
        or not SESSION_ID_RE.fullmatch(str(request["session_id"]))
        or not isinstance(request.get("plan_sha256"), str)
        or not SHA256_RE.fullmatch(str(request["plan_sha256"]))
        or not isinstance(request.get("inventory_sha256"), str)
        or not SHA256_RE.fullmatch(str(request["inventory_sha256"]))
        or not isinstance(request.get("disk_fingerprint"), str)
        or not re.fullmatch(
            r"sha256:[0-9a-f]{64}", str(request["disk_fingerprint"])
        )
        or request.get("target_disk") != "/dev/vda"
    ):
        _fail("Execution authorization request binding is invalid")
    before_status = status_loader(str(request["session_id"]))
    agent = before_status.get("agent_status")
    try:
        plan_bytes = revision_loader(
            str(request["session_id"]), "plan.json"
        )
        plan = json.loads(
            plan_bytes.decode("utf-8"),
            object_pairs_hook=_strict_object,
        )
        plan_target = plan["target_disk"]
    except (
        KeyError,
        TypeError,
        UnicodeDecodeError,
        ValueError,
        json.JSONDecodeError,
    ):
        _fail("Controller pre-authorization plan is invalid")
    if (
        before_status.get("state") != "plan_published"
        or "execution" in before_status
        or before_status.get("inventory_sha256")
        != request["inventory_sha256"]
        or not isinstance(agent, dict)
        or agent.get("reported_stage") != "preflight_ready"
        or hashlib.sha256(plan_bytes).hexdigest()
        != request["plan_sha256"]
        or not isinstance(plan_target, dict)
        or plan_target.get("path") != "/dev/vda"
        or plan_target.get("fingerprint")
        != request["disk_fingerprint"]
    ):
        _fail("Controller pre-authorization state is invalid")
    initial = read_bound_qmp_snapshot(initial_qmp, state_dir)
    immediate = read_bound_qmp_snapshot(
        before_authorization_qmp, state_dir
    )
    for phase, snapshot in (
        ("initial", initial),
        ("immediately before authorization", immediate),
    ):
        if any(
            not _all_writes_zero(snapshot[name]["graph"])
            for name in ("target", "sentinel")
        ):
            _fail(f"QMP writes occurred {phase}")
    initial_target = read_bound_sha256_record(
        initial_target_sha, state_dir, "target"
    )
    immediate_target = read_bound_sha256_record(
        before_authorization_target_sha, state_dir, "target"
    )
    initial_sentinel = read_bound_sha256_record(
        initial_sentinel_sha,
        state_dir,
        "sentinel",
        require_current_bytes=False,
    )
    immediate_sentinel = read_bound_sha256_record(
        before_authorization_sentinel_sha,
        state_dir,
        "sentinel",
        require_current_bytes=False,
    )
    if (
        initial_target != immediate_target
        or initial_sentinel != immediate_sentinel
        or initial_target
        != manifest["artifacts"]["target"]["initial_sha256"]
        or initial_sentinel
        != manifest["artifacts"]["sentinel"]["initial_sha256"]
    ):
        _fail("Run artifact changed before authorization")
    stdout = StringIO()
    stderr = StringIO()
    arguments = [
        "--json",
        "install-sessions",
        "authorize-execution",
        str(request["session_id"]),
        "--plan-sha256",
        str(request["plan_sha256"]),
        "--inventory-sha256",
        str(request["inventory_sha256"]),
        "--disk-fingerprint",
        str(request["disk_fingerprint"]),
        "--confirm-target",
        "/dev/vda",
        "--reason",
        f"Disposable OVMF acceptance {manifest['run_id']}",
    ]
    result = cli(arguments, stdout=stdout, stderr=stderr)
    if result != 0 or stderr.getvalue():
        _fail("Controller execution authorization failed")
    try:
        response = json.loads(
            stdout.getvalue(), object_pairs_hook=_strict_object
        )
        session = response["session"]
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        _fail("Controller execution authorization response is invalid")
    expected_execution_id = (
        f"{request['session_id']}:execution-0001"
    )
    after_status = status_loader(str(request["session_id"]))
    execution = after_status.get("execution")
    if (
        not isinstance(response, dict)
        or set(response) != {"status", "session"}
        or response.get("status") != "ok"
        or not isinstance(session, dict)
        or set(session)
        != {"execution_id", "execution_state", "session_id"}
        or session.get("session_id") != request["session_id"]
        or session.get("execution_id") != expected_execution_id
        or session.get("execution_state") != "authorized"
        or not isinstance(execution, dict)
        or execution.get("revision") != 1
        or execution.get("state") != "authorized"
        or execution.get("plan_sha256") != request["plan_sha256"]
        or execution.get("inventory_sha256")
        != request["inventory_sha256"]
        or execution.get("disk_fingerprint")
        != request["disk_fingerprint"]
        or execution.get("target_disk") != "/dev/vda"
        or (
            observed_at is not None
            and execution.get("authorized_at") != observed_at
        )
    ):
        _fail("Controller execution authorization response is invalid")
    payload = {
        "before_authorization_qmp_sha256": hashlib.sha256(
            _read_bytes(before_authorization_qmp)
        ).hexdigest(),
        "controller": {
            "execution_id": session["execution_id"],
            "state": session["execution_state"],
        },
        "initial_qmp_sha256": hashlib.sha256(
            _read_bytes(initial_qmp)
        ).hexdigest(),
        "initial_sentinel_sha256": initial_sentinel,
        "initial_target_sha256": initial_target,
        "request": request,
        "sentinel_sha256_before_authorization": immediate_sentinel,
        "target_disk": "/dev/vda",
        "target_sha256_before_authorization": immediate_target,
    }
    return issue_attestation(
        state_dir,
        event="authorization",
        sequence=1,
        payload=payload,
        observed_at=str(execution["authorized_at"]),
        previous_sha256=None,
    )


def attest_controller_history(
    state_dir: Path,
    *,
    authorization: dict[str, object],
    status_loader: Callable[[str], dict[str, object]] = controller_status,
) -> list[dict[str, object]]:
    """Sign the persisted claimed/handoff/installer controller history."""
    verify_attestation_chain(state_dir, [authorization])
    payload = authorization.get("payload")
    if not isinstance(payload, dict):
        _fail("Authorization attestation payload is invalid")
    request = payload.get("request")
    controller = payload.get("controller")
    if not isinstance(request, dict) or not isinstance(controller, dict):
        _fail("Authorization controller binding is invalid")
    session_id = request.get("session_id")
    if not isinstance(session_id, str):
        _fail("Authorization session binding is invalid")
    status = status_loader(session_id)
    execution = status.get("execution")
    if (
        status.get("state") != "plan_published"
        or not isinstance(execution, dict)
        or execution.get("state") != "installer_started"
        or execution.get("revision") != 1
        or controller.get("execution_id")
        != f"{session_id}:execution-0001"
        or execution.get("plan_sha256") != request.get("plan_sha256")
        or execution.get("inventory_sha256")
        != request.get("inventory_sha256")
        or execution.get("disk_fingerprint")
        != request.get("disk_fingerprint")
        or execution.get("target_disk") != "/dev/vda"
    ):
        _fail("Controller installer history binding is invalid")
    history: list[dict[str, object]] = [authorization]
    for sequence, (event, timestamp_field, state) in enumerate(
        (
            ("claimed", "claimed_at", "claimed"),
            ("handoff_started", "handoff_started_at", "handoff_started"),
            (
                "installer_started",
                "installer_started_at",
                "installer_started",
            ),
        ),
        start=2,
    ):
        observed_at = execution.get(timestamp_field)
        attestation = issue_attestation(
            state_dir,
            event=event,
            sequence=sequence,
            payload={
                "controller": {
                    "execution_id": controller["execution_id"],
                    "state": state,
                },
                "session_id": session_id,
            },
            observed_at=str(observed_at),
            previous_sha256=attestation_sha256(history[-1]),
        )
        history.append(attestation)
    verify_attestation_chain(state_dir, history)
    return history


def _qmp_write_graph(
    node: dict[str, object],
    *,
    graph_path: str,
) -> dict[str, dict[str, int]]:
    statistics = node.get("stats")
    if not isinstance(statistics, dict):
        _fail(f"QMP write statistics are absent at {graph_path}")
    counters: dict[str, int] = {}
    for name, value in statistics.items():
        if not isinstance(name, str) or not name.startswith("wr_"):
            continue
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            _fail(f"QMP write counter is invalid at {graph_path}")
        counters[name] = value
    if not {"wr_bytes", "wr_operations"}.issubset(counters):
        _fail(f"QMP mandatory write counters are absent at {graph_path}")
    graph = {graph_path: dict(sorted(counters.items()))}
    for relation in ("parent", "backing"):
        child = node.get(relation)
        if child is None:
            continue
        if not isinstance(child, dict):
            _fail(f"QMP {relation} statistics are invalid at {graph_path}")
        graph.update(
            _qmp_write_graph(
                child,
                graph_path=f"{graph_path}.{relation}",
            )
        )
    return graph


def _validate_qmp_topology(
    graph: dict[str, dict[str, int]],
    *,
    device: str,
    backing_depth: int,
) -> None:
    format_path = device
    for _ in range(backing_depth + 1):
        if format_path not in graph:
            _fail(f"QMP {device} backing statistics do not match depth")
        parent_path = f"{format_path}.parent"
        if parent_path not in graph:
            _fail(f"QMP {format_path} parent statistics are absent")
        format_path = f"{format_path}.backing"
    if format_path in graph:
        _fail(f"QMP {device} backing statistics do not match depth")


def _read_qmp_snapshot(
    path: Path,
) -> dict[str, dict[str, object]]:
    try:
        text = _read_bytes(path).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AcceptanceError(
            f"QMP transcript is not UTF-8: {path.name}"
        ) from exc
    stats: dict[str, dict[str, object]] = {}
    blocks: dict[str, dict[str, object]] = {}
    for line in text.splitlines():
        if not line:
            continue
        try:
            message = json.loads(line, object_pairs_hook=_strict_object)
        except (json.JSONDecodeError, ValueError) as exc:
            raise AcceptanceError(
                f"QMP transcript contains invalid JSON: {path.name}"
            ) from exc
        if not isinstance(message, dict):
            _fail(f"QMP transcript message is invalid: {path.name}")
        returned = message.get("return")
        if not isinstance(returned, list):
            continue
        for item in returned:
            if not isinstance(item, dict):
                continue
            device = item.get("device")
            if device not in {"target", "sentinel"}:
                continue
            if isinstance(item.get("stats"), dict):
                if device in stats:
                    _fail(f"QMP {device} statistics are ambiguous")
                stats[device] = item
            if isinstance(item.get("inserted"), dict):
                if device in blocks:
                    _fail(f"QMP {device} query-block evidence is ambiguous")
                blocks[device] = item
    if set(stats) != {"target", "sentinel"}:
        _fail("QMP target and sentinel statistics are both required")
    if set(blocks) != {"target", "sentinel"}:
        _fail("QMP target and sentinel query-block evidence is required")

    result: dict[str, dict[str, object]] = {}
    for device in ("target", "sentinel"):
        inserted = blocks[device]["inserted"]
        if not isinstance(inserted, dict):
            _fail(f"QMP {device} inserted information is invalid")
        read_only = inserted.get("ro")
        depth = inserted.get("backing_file_depth")
        if not isinstance(read_only, bool):
            _fail(f"QMP {device} read-only state is invalid")
        if (
            isinstance(depth, bool)
            or not isinstance(depth, int)
            or not 0 <= depth <= 16
            or inserted.get("drv") != "qcow2"
        ):
            _fail(f"QMP {device} qcow2 topology is invalid")
        graph = _qmp_write_graph(stats[device], graph_path=device)
        _validate_qmp_topology(
            graph, device=device, backing_depth=depth
        )
        result[device] = {
            "backing_depth": depth,
            "graph": graph,
            "read_only": read_only,
            "write_bytes": graph[device]["wr_bytes"],
        }
    return result


def _all_writes_zero(
    graph: dict[str, dict[str, int]],
) -> bool:
    return all(
        value == 0
        for counters in graph.values()
        for name, value in counters.items()
        if name.startswith("wr_")
    )


def _read_sha256(path: Path) -> str:
    try:
        lines = _read_bytes(path, maximum=4096).decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise AcceptanceError("SHA-256 record is not ASCII") from exc
    if len(lines) != 1:
        _fail("SHA-256 record must contain exactly one line")
    fields = lines[0].split(maxsplit=1)
    if not fields or not SHA256_RE.fullmatch(fields[0]):
        _fail("SHA-256 record is invalid")
    return fields[0]


def _parse_timestamp(value: object, *, field: str) -> datetime:
    if not isinstance(value, str):
        _fail(f"Timeline {field} is invalid")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise AcceptanceError(f"Timeline {field} is invalid") from exc
    if (
        parsed.tzinfo is None
        or parsed.utcoffset() is None
        or parsed.astimezone(timezone.utc).isoformat() != value
    ):
        _fail(f"Timeline {field} is invalid")
    return parsed


def _validate_timeline(path: Path) -> dict[str, object]:
    timeline = _read_json(path)
    expected = {
        "schema_version",
        "session_id",
        "target_disk",
        "operator_uid",
        *TIMELINE_KEYS,
    }
    if (
        set(timeline) != expected
        or timeline.get("schema_version") != 1
        or type(timeline.get("schema_version")) is not int
        or timeline.get("operator_uid") != 0
        or type(timeline.get("operator_uid")) is not int
        or timeline.get("target_disk") != "/dev/vda"
        or not isinstance(timeline.get("session_id"), str)
        or not SESSION_ID_RE.fullmatch(str(timeline["session_id"]))
    ):
        _fail("Root authorization timeline is invalid")
    ordered = [
        _parse_timestamp(timeline[name], field=name)
        for name in TIMELINE_KEYS
    ]
    if any(later <= earlier for earlier, later in zip(ordered, ordered[1:])):
        _fail("Root authorization timeline is out of order")
    return timeline


def _validate_postflight(
    path: Path,
    *,
    timeline: dict[str, object],
) -> dict[str, object]:
    postflight = _read_json(path)
    if (
        set(postflight)
        != {
            "schema_version",
            "session_id",
            "authenticated",
            "boot_source",
            "state",
            "reported_at",
        }
        or postflight.get("schema_version") != 1
        or type(postflight.get("schema_version")) is not int
        or postflight.get("session_id") != timeline["session_id"]
        or postflight.get("authenticated") is not True
        or postflight.get("boot_source") != "target-without-iso"
        or postflight.get("state") != "installed"
        or postflight.get("reported_at")
        != timeline["postflight_authenticated_at"]
    ):
        _fail("Authenticated target-only postflight evidence is invalid")
    _parse_timestamp(postflight["reported_at"], field="reported_at")
    return postflight


def finalize_evidence(
    *,
    before_qmp: Path,
    after_qmp: Path,
    target_before_sha: Path,
    target_after_sha: Path,
    sentinel_before_sha: Path,
    sentinel_after_sha: Path,
    timeline_path: Path,
    postflight_path: Path,
    output: Path,
) -> None:
    _fail("Legacy caller-supplied evidence is unsupported")
    before = _read_qmp_snapshot(before_qmp)
    after = _read_qmp_snapshot(after_qmp)
    for snapshot in (before, after):
        if snapshot["target"]["read_only"] is not False:
            _fail("Disposable target is unexpectedly read-only")
        if snapshot["sentinel"]["read_only"] is not True:
            _fail("Sentinel is not QMP-confirmed read-only")
    if not _all_writes_zero(before["target"]["graph"]):
        _fail("Target wrote before authorization")
    if not _all_writes_zero(before["sentinel"]["graph"]):
        _fail("Forbidden sentinel write before authorization")
    if not _all_writes_zero(after["sentinel"]["graph"]):
        _fail("Forbidden sentinel write after installation")
    target_write_bytes = after["target"]["write_bytes"]
    if not isinstance(target_write_bytes, int) or target_write_bytes <= 0:
        _fail("No target write was observed after installation")

    target_before = _read_sha256(target_before_sha)
    target_after = _read_sha256(target_after_sha)
    sentinel_before = _read_sha256(sentinel_before_sha)
    sentinel_after = _read_sha256(sentinel_after_sha)
    if target_before == target_after:
        _fail("Target SHA-256 did not change")
    if sentinel_before != sentinel_after:
        _fail("Sentinel SHA-256 changed")

    timeline = _validate_timeline(timeline_path)
    postflight = _validate_postflight(
        postflight_path, timeline=timeline
    )
    before_summary = {
        "sentinel_read_only": True,
        "sentinel_sha256": sentinel_before,
        "sentinel_write_bytes": before["sentinel"]["write_bytes"],
        "target_read_only": False,
        "target_sha256": target_before,
        "target_write_bytes": before["target"]["write_bytes"],
    }
    after_summary = {
        "sentinel_read_only": True,
        "sentinel_sha256": sentinel_after,
        "sentinel_write_bytes": after["sentinel"]["write_bytes"],
        "target_read_only": False,
        "target_sha256": target_after,
        "target_write_bytes": target_write_bytes,
    }
    receipt = {
        "acceptance_scope": "generic-ovmf-disposable",
        "after_install": after_summary,
        "authorization_timeline": timeline,
        "before_authorization": before_summary,
        "firmware": "generic-ovmf",
        "postflight": {
            "authenticated": postflight["authenticated"],
            "boot_source": postflight["boot_source"],
            "reported_at": postflight["reported_at"],
        },
        "postflight_state": postflight["state"],
        "result": "pass",
        "schema_version": 1,
        "session_id": timeline["session_id"],
        "target_disk": "/dev/vda",
    }
    _write_new(output, _json_bytes(receipt))
    print(PASS_LINE)


def finalize_signed_evidence(
    state_dir: Path,
    *,
    initial_qmp: Path,
    before_authorization_qmp: Path,
    after_install_qmp: Path,
    postflight_boot_qmp: Path,
    initial_target_sha: Path,
    before_authorization_target_sha: Path,
    after_target_sha: Path,
    initial_sentinel_sha: Path,
    before_authorization_sentinel_sha: Path,
    after_sentinel_sha: Path,
    output: Path,
) -> None:
    """Gate PASS exclusively on the run-owned signed evidence chain."""
    manifest = _load_run_manifest(state_dir)
    initial = read_bound_qmp_snapshot(initial_qmp, state_dir)
    immediate = read_bound_qmp_snapshot(
        before_authorization_qmp, state_dir
    )
    after = read_bound_qmp_snapshot(after_install_qmp, state_dir)
    for phase, snapshot in (
        ("initial", initial),
        ("before authorization", immediate),
        ("after install", after),
    ):
        if snapshot["target"]["read_only"] is not False:
            _fail(f"Disposable target is read-only {phase}")
        if snapshot["sentinel"]["read_only"] is not True:
            _fail(f"Sentinel is writable {phase}")
    for phase, snapshot in (
        ("initial", initial),
        ("before authorization", immediate),
    ):
        if any(
            not _all_writes_zero(snapshot[name]["graph"])
            for name in ("target", "sentinel")
        ):
            _fail(f"QMP writes occurred {phase}")
    if not _all_writes_zero(after["sentinel"]["graph"]):
        _fail("Forbidden sentinel write after installation")
    if after["target"]["write_bytes"] <= 0:
        _fail("No target write was observed after installation")
    initial_target = read_bound_sha256_record(
        initial_target_sha,
        state_dir,
        "target",
        require_initial_size=False,
        require_current_bytes=False,
    )
    immediate_target = read_bound_sha256_record(
        before_authorization_target_sha,
        state_dir,
        "target",
        require_initial_size=False,
        require_current_bytes=False,
    )
    after_target = read_bound_sha256_record(
        after_target_sha,
        state_dir,
        "target",
        require_initial_size=False,
    )
    initial_sentinel = read_bound_sha256_record(
        initial_sentinel_sha, state_dir, "sentinel"
    )
    immediate_sentinel = read_bound_sha256_record(
        before_authorization_sentinel_sha, state_dir, "sentinel"
    )
    after_sentinel = read_bound_sha256_record(
        after_sentinel_sha,
        state_dir,
        "sentinel",
        require_initial_size=False,
    )
    if (
        initial_target != immediate_target
        or initial_target
        != manifest["artifacts"]["target"]["initial_sha256"]
        or after_target == initial_target
        or initial_sentinel != immediate_sentinel
        or initial_sentinel != after_sentinel
        or initial_sentinel
        != manifest["artifacts"]["sentinel"]["initial_sha256"]
    ):
        _fail("Run artifact SHA-256 transition is invalid")
    chain = load_attestation_chain(state_dir)
    if (
        len(chain) != 6
        or [item.get("event") for item in chain]
        != [
            "authorization",
            "claimed",
            "handoff_started",
            "installer_started",
            "postflight_boot",
            "installed",
        ]
    ):
        _fail("Acceptance attestation chain is incomplete")
    authorization_payload = chain[0].get("payload")
    boot_payload = chain[4].get("payload")
    installed_payload = chain[5].get("payload")
    if not all(
        isinstance(item, dict)
        for item in (
            authorization_payload,
            boot_payload,
            installed_payload,
        )
    ):
        _fail("Acceptance attestation payload is invalid")
    assert isinstance(authorization_payload, dict)
    assert isinstance(boot_payload, dict)
    assert isinstance(installed_payload, dict)
    request = authorization_payload.get("request")
    controller = authorization_payload.get("controller")
    if (
        not isinstance(request, dict)
        or not isinstance(controller, dict)
        or authorization_payload.get("initial_qmp_sha256")
        != hashlib.sha256(_read_bytes(initial_qmp)).hexdigest()
        or authorization_payload.get(
            "before_authorization_qmp_sha256"
        )
        != hashlib.sha256(
            _read_bytes(before_authorization_qmp)
        ).hexdigest()
        or authorization_payload.get("initial_target_sha256")
        != initial_target
        or authorization_payload.get("initial_sentinel_sha256")
        != initial_sentinel
        or authorization_payload.get(
            "target_sha256_before_authorization"
        )
        != immediate_target
        or authorization_payload.get(
            "sentinel_sha256_before_authorization"
        )
        != immediate_sentinel
        or request.get("target_disk") != "/dev/vda"
        or controller.get("execution_id")
        != f"{request.get('session_id')}:execution-0001"
        or controller.get("state") != "authorized"
    ):
        _fail("Authorization attestation evidence is invalid")
    boot = _read_postflight_boot_qmp(
        postflight_boot_qmp, state_dir
    )
    if (
        boot_payload.get("qmp_sha256") != boot["qmp_sha256"]
        or boot_payload.get("iso_attached") is not False
        or boot_payload.get("vm_instance_id")
        != manifest["vm_instance_id"]
        or boot_payload.get("session_id") != request["session_id"]
        or installed_payload.get("session_id") != request["session_id"]
        or installed_payload.get("boot_nonce")
        != boot_payload.get("boot_nonce")
        or installed_payload.get("controller")
        != {
            "execution_id": controller["execution_id"],
            "state": "installed",
        }
    ):
        _fail("Authenticated postflight evidence is invalid")
    receipt = {
        "acceptance_scope": "generic-ovmf-disposable",
        "artifacts": {
            "iso": manifest["iso"],
            "sentinel": {
                **manifest["artifacts"]["sentinel"],
                "after_sha256": after_sentinel,
            },
            "target": {
                **manifest["artifacts"]["target"],
                "after_sha256": after_target,
            },
        },
        "attestation_chain_sha256": attestation_sha256(chain[-1]),
        "controller": {
            "execution_id": controller["execution_id"],
            "session_id": request["session_id"],
            "state": "installed",
        },
        "firmware": "generic-ovmf",
        "postflight": {
            "boot_id": installed_payload["boot_id"],
            "boot_nonce": installed_payload["boot_nonce"],
            "iso_attached": False,
            "vm_instance_id": manifest["vm_instance_id"],
        },
        "result": "pass",
        "run": {
            "challenge": manifest["challenge"],
            "run_id": manifest["run_id"],
            "trust_anchor_key_id": manifest["trust_anchor_key_id"],
        },
        "schema_version": 2,
        "target_disk": "/dev/vda",
        "writes": {
            "after_install": {
                "sentinel_write_bytes": after["sentinel"][
                    "write_bytes"
                ],
                "target_write_bytes": after["target"]["write_bytes"],
            },
            "before_authorization": {
                "sentinel_write_bytes": immediate["sentinel"][
                    "write_bytes"
                ],
                "target_write_bytes": immediate["target"][
                    "write_bytes"
                ],
            },
        },
    }
    _write_new(output, _json_bytes(receipt))
    print(PASS_LINE)


def _qmp_receive(
    stream: Any,
    transcript: list[dict[str, object]],
    *,
    expected_id: str | None,
) -> dict[str, object]:
    while True:
        raw = stream.readline(MAX_EVIDENCE_BYTES + 1)
        if not raw or len(raw) > MAX_EVIDENCE_BYTES:
            _fail("QMP closed before returning a bounded response")
        try:
            message = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AcceptanceError("QMP returned invalid JSON") from exc
        if not isinstance(message, dict):
            _fail("QMP returned a non-object message")
        transcript.append(message)
        if expected_id is None or message.get("id") == expected_id:
            return message


def _qmp_connect(
    socket_path: Path,
) -> tuple[socket.socket, Any, list[dict[str, object]]]:
    if not hasattr(socket, "AF_UNIX"):
        _fail("QMP Unix sockets are unavailable on this platform")
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(5)
    try:
        client.connect(str(socket_path))
    except OSError as exc:
        client.close()
        raise AcceptanceError("QMP socket is unavailable") from exc
    stream = client.makefile("rwb", buffering=0)
    transcript: list[dict[str, object]] = []
    greeting = _qmp_receive(stream, transcript, expected_id=None)
    if "QMP" not in greeting:
        stream.close()
        client.close()
        _fail("QMP greeting is missing")
    request = {"execute": "qmp_capabilities", "id": "capabilities"}
    stream.write((json.dumps(request) + "\r\n").encode("ascii"))
    response = _qmp_receive(
        stream, transcript, expected_id="capabilities"
    )
    if "error" in response:
        stream.close()
        client.close()
        _fail("QMP capability negotiation failed")
    return client, stream, transcript


def qmp_query(socket_path: Path, output: Path) -> None:
    client, stream, transcript = _qmp_connect(socket_path)
    try:
        for execute, request_id in (
            ("query-blockstats", "blockstats"),
            ("query-block", "block"),
        ):
            request = {"execute": execute, "id": request_id}
            stream.write((json.dumps(request) + "\r\n").encode("ascii"))
            response = _qmp_receive(
                stream, transcript, expected_id=request_id
            )
            if "error" in response or not isinstance(
                response.get("return"), list
            ):
                _fail(f"QMP {execute} failed")
    finally:
        stream.close()
        client.close()
    _write_new(
        output,
        b"".join(
            (
                json.dumps(message, ensure_ascii=True, sort_keys=True)
                + "\n"
            ).encode("utf-8")
            for message in transcript
        ),
    )


def qmp_boot_query(socket_path: Path, output: Path) -> None:
    """Capture QMP-owned proof that the target-only VM is running."""
    client, stream, transcript = _qmp_connect(socket_path)
    try:
        for execute, request_id, expected_type in (
            ("query-status", "status", dict),
            ("query-uuid", "uuid", dict),
            ("query-block", "block", list),
        ):
            request = {"execute": execute, "id": request_id}
            stream.write((json.dumps(request) + "\r\n").encode("ascii"))
            response = _qmp_receive(
                stream, transcript, expected_id=request_id
            )
            if "error" in response or not isinstance(
                response.get("return"), expected_type
            ):
                _fail(f"QMP {execute} failed")
    finally:
        stream.close()
        client.close()
    _write_new(
        output,
        b"".join(
            (
                json.dumps(message, ensure_ascii=True, sort_keys=True)
                + "\n"
            ).encode("utf-8")
            for message in transcript
        ),
    )


def _read_postflight_boot_qmp(
    path: Path, state_dir: Path
) -> dict[str, object]:
    manifest = _load_run_manifest(state_dir)
    try:
        messages = [
            json.loads(line, object_pairs_hook=_strict_object)
            for line in _read_bytes(path).decode("utf-8").splitlines()
            if line
        ]
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise AcceptanceError(
            "Postflight QMP transcript is invalid"
        ) from exc
    responses: dict[str, dict[str, object]] = {}
    for message in messages:
        if not isinstance(message, dict) or "id" not in message:
            continue
        response_id = message.get("id")
        if (
            response_id
            not in {"capabilities", "status", "uuid", "block"}
            or response_id in responses
        ):
            _fail("Postflight QMP response ID is invalid")
        responses[str(response_id)] = message
    if set(responses) != {"capabilities", "status", "uuid", "block"}:
        _fail("Postflight QMP identity evidence is incomplete")
    status = responses["status"].get("return")
    identity = responses["uuid"].get("return")
    blocks = responses["block"].get("return")
    if (
        responses["capabilities"].get("return") != {}
        or not isinstance(status, dict)
        or status.get("running") is not True
        or status.get("status") != "running"
        or not isinstance(identity, dict)
        or identity.get("UUID") != manifest["vm_instance_id"]
        or not isinstance(blocks, list)
    ):
        _fail("Postflight QMP running VM identity is invalid")
    artifacts = manifest.get("artifacts")
    iso = manifest.get("iso")
    if not isinstance(artifacts, dict) or not isinstance(iso, dict):
        _fail("Postflight run artifact binding is invalid")
    inserted_files: dict[str, object] = {}
    for block in blocks:
        if not isinstance(block, dict):
            _fail("Postflight QMP block evidence is invalid")
        inserted = block.get("inserted")
        if inserted is None:
            continue
        if not isinstance(inserted, dict):
            _fail("Postflight QMP inserted evidence is invalid")
        filename = inserted.get("file")
        if filename == iso.get("canonical_path"):
            _fail("Postflight QMP still has the ISO attached")
        device = block.get("device")
        if device in {"target", "sentinel"}:
            if device in inserted_files:
                _fail("Postflight QMP device identity is ambiguous")
            inserted_files[str(device)] = filename
        elif block.get("removable") is True:
            _fail("Postflight QMP has inserted removable media")
    if any(
        inserted_files.get(name)
        != artifacts[name]["canonical_path"]
        for name in ("target", "sentinel")
    ):
        _fail("Postflight QMP target identity is invalid")
    return {
        "iso_attached": False,
        "qmp_sha256": hashlib.sha256(_read_bytes(path)).hexdigest(),
        "status": "running",
        "vm_instance_id": manifest["vm_instance_id"],
    }


def issue_postflight_boot_challenge(
    state_dir: Path,
    *,
    qmp_path: Path,
    observed_at: str,
) -> dict[str, object]:
    """Issue a fresh signed nonce only after QMP proves the no-ISO boot."""
    chain = load_attestation_chain(state_dir)
    if (
        len(chain) != 4
        or [item.get("event") for item in chain]
        != [
            "authorization",
            "claimed",
            "handoff_started",
            "installer_started",
        ]
    ):
        _fail("Postflight predecessor chain is invalid")
    boot = _read_postflight_boot_qmp(qmp_path, state_dir)
    authorization_payload = chain[0].get("payload")
    if not isinstance(authorization_payload, dict):
        _fail("Authorization payload is invalid")
    request = authorization_payload.get("request")
    if not isinstance(request, dict):
        _fail("Authorization request binding is invalid")
    manifest = _load_run_manifest(state_dir)
    nonce = _urlsafe_nonce()
    attestation = issue_attestation(
        state_dir,
        event="postflight_boot",
        sequence=5,
        payload={
            **boot,
            "boot_nonce": nonce,
            "controller": {
                "execution_id": (
                    f"{request['session_id']}:execution-0001"
                ),
                "state": "installer_started",
            },
            "session_id": request["session_id"],
        },
        observed_at=observed_at,
        previous_sha256=attestation_sha256(chain[-1]),
    )
    store_attestation(state_dir, attestation)
    delivery = {
        "boot_attestation": attestation,
        "boot_nonce": nonce,
        "challenge": manifest["challenge"],
        "controller_url": "https://192.168.100.17:18092",
        "run_id": manifest["run_id"],
        "schema_version": 1,
        "session_id": request["session_id"],
        "vm_instance_id": manifest["vm_instance_id"],
    }
    _write_new(
        state_dir.resolve(strict=True) / "postflight-delivery.json",
        _json_bytes(delivery),
        mode=0o600,
    )
    return delivery


def verify_postflight_document(
    state_dir: Path,
    session_id: str,
    document: dict[str, object],
) -> bool:
    """Consume the one fresh boot challenge for the real TLS API."""
    try:
        chain = load_attestation_chain(state_dir)
        manifest = _load_run_manifest(state_dir)
        delivery = _read_json(
            state_dir.resolve(strict=True) / "postflight-delivery.json"
        )
        if (
            len(chain) != 5
            or chain[-1].get("event") != "postflight_boot"
            or set(document)
            != {
                "boot_attestation",
                "boot_id",
                "boot_nonce",
                "challenge",
                "reported_at",
                "run_id",
                "schema_version",
                "vm_instance_id",
            }
            or document.get("schema_version") != 1
            or type(document.get("schema_version")) is not int
            or document.get("run_id") != manifest["run_id"]
            or document.get("challenge") != manifest["challenge"]
            or document.get("vm_instance_id")
            != manifest["vm_instance_id"]
            or document.get("boot_nonce") != delivery["boot_nonce"]
            or document.get("boot_attestation")
            != delivery["boot_attestation"]
            or document.get("boot_attestation") != chain[-1]
            or chain[-1]["payload"]["session_id"] != session_id
            or not isinstance(document.get("boot_id"), str)
        ):
            return False
        UUID(str(document["boot_id"]))
        reported = _parse_timestamp(
            document.get("reported_at"), field="reported_at"
        )
        challenged = _parse_timestamp(
            chain[-1].get("observed_at"), field="observed_at"
        )
        if reported <= challenged:
            return False
        consumed = state_dir.resolve(strict=True) / "authenticated-postflight.json"
        _write_new(consumed, _json_bytes(document), mode=0o600)
        return True
    except (AcceptanceError, KeyError, TypeError, ValueError, OSError):
        return False


def attest_installed_state(
    state_dir: Path,
    *,
    status_loader: Callable[[str], dict[str, object]] = controller_status,
) -> dict[str, object]:
    chain = load_attestation_chain(state_dir)
    postflight = _read_json(
        state_dir.resolve(strict=True) / "authenticated-postflight.json"
    )
    if len(chain) != 5:
        _fail("Installed predecessor chain is invalid")
    session_id = chain[-1]["payload"]["session_id"]
    status = status_loader(str(session_id))
    execution = status.get("execution")
    if (
        not isinstance(execution, dict)
        or execution.get("state") != "installed"
        or execution.get("revision") != 1
        or postflight.get("boot_attestation") != chain[-1]
    ):
        _fail("Installed controller state binding is invalid")
    attestation = issue_attestation(
        state_dir,
        event="installed",
        sequence=6,
        payload={
            "boot_id": postflight["boot_id"],
            "boot_nonce": postflight["boot_nonce"],
            "controller": {
                "execution_id": f"{session_id}:execution-0001",
                "state": "installed",
            },
            "reported_at": postflight["reported_at"],
            "session_id": session_id,
        },
        observed_at=str(execution.get("installed_at")),
        previous_sha256=attestation_sha256(chain[-1]),
    )
    store_attestation(state_dir, attestation)
    verify_attestation_chain(
        state_dir, [*chain, attestation]
    )
    return attestation


def qmp_command(socket_path: Path, execute: str) -> None:
    if execute not in {"cont", "quit", "system_reset"}:
        _fail("QMP command is not allowlisted")
    client, stream, _transcript = _qmp_connect(socket_path)
    try:
        request = {"execute": execute, "id": "command"}
        stream.write((json.dumps(request) + "\r\n").encode("ascii"))
        response = _qmp_receive(
            stream, _transcript, expected_id="command"
        )
        if "error" in response:
            _fail(f"QMP {execute} failed")
    finally:
        stream.close()
        client.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create-run", allow_abbrev=False)
    create.add_argument("--state-dir", required=True, type=Path)
    create.add_argument("--iso", required=True, type=Path)
    create.add_argument("--target", required=True, type=Path)
    create.add_argument("--sentinel", required=True, type=Path)
    create.add_argument("--vm-instance-id", required=True)
    authorization_request = commands.add_parser(
        "create-authorization-request", allow_abbrev=False
    )
    authorization_request.add_argument(
        "--state-dir", required=True, type=Path
    )
    authorize = commands.add_parser(
        "authorize-execution", allow_abbrev=False
    )
    authorize.add_argument("--state-dir", required=True, type=Path)
    authorize.add_argument("--initial-qmp", required=True, type=Path)
    authorize.add_argument(
        "--before-authorization-qmp", required=True, type=Path
    )
    authorize.add_argument(
        "--initial-target-sha", required=True, type=Path
    )
    authorize.add_argument(
        "--before-authorization-target-sha",
        required=True,
        type=Path,
    )
    authorize.add_argument(
        "--initial-sentinel-sha", required=True, type=Path
    )
    authorize.add_argument(
        "--before-authorization-sentinel-sha",
        required=True,
        type=Path,
    )
    history = commands.add_parser(
        "attest-controller-history", allow_abbrev=False
    )
    history.add_argument("--state-dir", required=True, type=Path)
    challenge = commands.add_parser(
        "issue-postflight-challenge", allow_abbrev=False
    )
    challenge.add_argument("--state-dir", required=True, type=Path)
    challenge.add_argument("--qmp", required=True, type=Path)
    installed = commands.add_parser(
        "attest-installed", allow_abbrev=False
    )
    installed.add_argument("--state-dir", required=True, type=Path)
    for command_name in (
        "record-resource-ownership",
        "verify-resource-ownership",
    ):
        ownership = commands.add_parser(
            command_name, allow_abbrev=False
        )
        ownership.add_argument("--record", required=True, type=Path)
        ownership.add_argument("--workdir", required=True, type=Path)
        ownership.add_argument("--tap-name", required=True)
        ownership.add_argument("--tap-ifindex", required=True, type=int)
    finalize = commands.add_parser(
        "finalize-evidence", allow_abbrev=False
    )
    finalize.add_argument("--state-dir", required=True, type=Path)
    finalize.add_argument("--initial-qmp", required=True, type=Path)
    finalize.add_argument(
        "--before-authorization-qmp", required=True, type=Path
    )
    finalize.add_argument(
        "--after-install-qmp", required=True, type=Path
    )
    finalize.add_argument(
        "--postflight-boot-qmp", required=True, type=Path
    )
    finalize.add_argument(
        "--initial-target-sha", required=True, type=Path
    )
    finalize.add_argument(
        "--before-authorization-target-sha",
        required=True,
        type=Path,
    )
    finalize.add_argument("--after-target-sha", required=True, type=Path)
    finalize.add_argument(
        "--initial-sentinel-sha", required=True, type=Path
    )
    finalize.add_argument(
        "--before-authorization-sentinel-sha",
        required=True,
        type=Path,
    )
    finalize.add_argument(
        "--after-sentinel-sha", required=True, type=Path
    )
    finalize.add_argument("--output", required=True, type=Path)
    query = commands.add_parser("qmp-query", allow_abbrev=False)
    query.add_argument("--socket", required=True, type=Path)
    query.add_argument("--output", required=True, type=Path)
    boot_query = commands.add_parser(
        "qmp-boot-query", allow_abbrev=False
    )
    boot_query.add_argument("--socket", required=True, type=Path)
    boot_query.add_argument("--output", required=True, type=Path)
    command = commands.add_parser("qmp-command", allow_abbrev=False)
    command.add_argument("--socket", required=True, type=Path)
    command.add_argument("--execute", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        if arguments.command == "create-run":
            manifest = create_run_state(
                arguments.state_dir,
                iso=arguments.iso,
                target=arguments.target,
                sentinel=arguments.sentinel,
                vm_instance_id=arguments.vm_instance_id,
            )
            print(f"run_id={manifest['run_id']}")
        elif arguments.command == "create-authorization-request":
            request = create_authorization_request(arguments.state_dir)
            print(f"session_id={request['session_id']}")
        elif arguments.command == "authorize-execution":
            attestation = invoke_root_execution_authorization(
                arguments.state_dir,
                request_path=(
                    arguments.state_dir / "authorization-request.json"
                ),
                initial_qmp=arguments.initial_qmp,
                before_authorization_qmp=(
                    arguments.before_authorization_qmp
                ),
                initial_target_sha=arguments.initial_target_sha,
                before_authorization_target_sha=(
                    arguments.before_authorization_target_sha
                ),
                initial_sentinel_sha=arguments.initial_sentinel_sha,
                before_authorization_sentinel_sha=(
                    arguments.before_authorization_sentinel_sha
                ),
            )
            store_attestation(arguments.state_dir, attestation)
            print("execution_state=authorized")
        elif arguments.command == "attest-controller-history":
            authorization = _read_json(
                _attestation_path(
                    arguments.state_dir, 1, "authorization"
                )
            )
            history = attest_controller_history(
                arguments.state_dir,
                authorization=authorization,
            )
            for attestation in history[1:]:
                store_attestation(arguments.state_dir, attestation)
            print("execution_state=installer_started")
        elif arguments.command == "issue-postflight-challenge":
            delivery = issue_postflight_boot_challenge(
                arguments.state_dir,
                qmp_path=arguments.qmp,
                observed_at=datetime.now(timezone.utc).isoformat(),
            )
            print(f"boot_nonce={delivery['boot_nonce']}")
        elif arguments.command == "attest-installed":
            attest_installed_state(arguments.state_dir)
            print("execution_state=installed")
        elif arguments.command == "record-resource-ownership":
            ownership = resource_ownership(
                arguments.workdir,
                tap_name=arguments.tap_name,
                tap_ifindex=arguments.tap_ifindex,
            )
            _write_new(
                arguments.record,
                _json_bytes(ownership),
                mode=0o600,
            )
            print("resource_ownership=recorded")
        elif arguments.command == "verify-resource-ownership":
            verify_resource_ownership(
                _read_json(arguments.record),
                arguments.workdir,
                tap_name=arguments.tap_name,
                tap_ifindex=arguments.tap_ifindex,
            )
            print("resource_ownership=verified")
        elif arguments.command == "finalize-evidence":
            finalize_signed_evidence(
                arguments.state_dir,
                initial_qmp=arguments.initial_qmp,
                before_authorization_qmp=(
                    arguments.before_authorization_qmp
                ),
                after_install_qmp=arguments.after_install_qmp,
                postflight_boot_qmp=arguments.postflight_boot_qmp,
                initial_target_sha=arguments.initial_target_sha,
                before_authorization_target_sha=(
                    arguments.before_authorization_target_sha
                ),
                after_target_sha=arguments.after_target_sha,
                initial_sentinel_sha=arguments.initial_sentinel_sha,
                before_authorization_sentinel_sha=(
                    arguments.before_authorization_sentinel_sha
                ),
                after_sentinel_sha=arguments.after_sentinel_sha,
                output=arguments.output,
            )
        elif arguments.command == "qmp-query":
            qmp_query(arguments.socket, arguments.output)
        elif arguments.command == "qmp-boot-query":
            qmp_boot_query(arguments.socket, arguments.output)
        else:
            qmp_command(arguments.socket, arguments.execute)
        return 0
    except AcceptanceError as exc:
        print(f"agent-v2-qemu: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
