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
import select
import signal
import socket
import stat
import sys
from datetime import datetime, timedelta, timezone
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
AUTHORIZATION_CAPTURE_MAX_SECONDS = 10
AUTHORIZATION_PENDING_TO_PREAUTH_MAX_SECONDS = 30
AUTHORIZATION_PREAUTH_TO_OBSERVED_MAX_SECONDS = 10
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
MANDATORY_PUBLIC_SOURCE_NAMES = frozenset(
    {
        "after-install.qmp.jsonl",
        "authenticated-postflight.json",
        "before-authorization-boundary.json",
        "before-authorization.qmp.jsonl",
        "before-authorization.sentinel.sha256",
        "before-authorization.target.sha256",
        "pending-boundary.json",
        "pending.qmp.jsonl",
        "pending.sentinel.sha256",
        "pending.target.sha256",
        "postflight-boot.qmp.jsonl",
        "postflight-delivery.json",
        "sentinel.after.sha256",
        "target.after.sha256",
    }
)
MANDATORY_PUBLIC_EVIDENCE_NAMES = (
    MANDATORY_PUBLIC_SOURCE_NAMES | {"iso-evidence.json"}
)


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


def _copy_verified_iso(
    source: Path,
    destination: Path,
    *,
    expected_sha256: str,
    after_open: Callable[[], None] | None = None,
) -> tuple[Path, os.stat_result, dict[str, int]]:
    if not SHA256_RE.fullmatch(expected_sha256):
        _fail("Verified ISO SHA-256 is invalid")
    canonical_source, source_metadata = _canonical_regular(source)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    try:
        source_descriptor = os.open(canonical_source, flags)
    except OSError as exc:
        raise AcceptanceError("Verified ISO cannot be opened") from exc
    destination_descriptor = -1
    try:
        opened_source = os.fstat(source_descriptor)
        if (
            not stat.S_ISREG(opened_source.st_mode)
            or opened_source.st_dev != source_metadata.st_dev
            or opened_source.st_ino != source_metadata.st_ino
            or opened_source.st_size != source_metadata.st_size
        ):
            _fail("Verified ISO source identity changed")
        if after_open is not None:
            after_open()
        destination_descriptor = os.open(
            destination,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | (getattr(os, "O_BINARY", 0)),
            0o400,
        )
        digest = hashlib.sha256()
        copied = 0
        while chunk := os.read(source_descriptor, 1024 * 1024):
            digest.update(chunk)
            copied += len(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(destination_descriptor, view)
                if written < 1:
                    _fail("Verified ISO copy was truncated")
                view = view[written:]
        os.fsync(destination_descriptor)
        copied_metadata = os.fstat(destination_descriptor)
        final_source = os.fstat(source_descriptor)
        if (
            copied != opened_source.st_size
            or digest.hexdigest() != expected_sha256
            or final_source.st_dev != opened_source.st_dev
            or final_source.st_ino != opened_source.st_ino
            or final_source.st_size != opened_source.st_size
            or copied_metadata.st_size != copied
        ):
            _fail("Verified ISO bytes changed before run ownership")
    except OSError as exc:
        raise AcceptanceError("Verified ISO copy failed closed") from exc
    finally:
        if destination_descriptor >= 0:
            os.close(destination_descriptor)
        os.close(source_descriptor)
    os.chmod(destination, 0o400)
    canonical_copy, copied_metadata = _canonical_regular(destination)
    return (
        canonical_copy,
        copied_metadata,
        _file_identity(opened_source),
    )


def _urlsafe_nonce() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(
        "ascii"
    ).rstrip("=")


def create_run_state(
    state_dir: Path,
    *,
    iso: Path,
    expected_iso_sha256: str,
    target: Path,
    sentinel: Path,
    vm_instance_id: str,
    after_iso_open: Callable[[], None] | None = None,
) -> dict[str, object]:
    if not state_dir.is_dir() or any(state_dir.iterdir()):
        _fail("Run state directory must be empty")
    try:
        canonical_state = state_dir.resolve(strict=True)
        UUID(vm_instance_id)
    except (OSError, ValueError) as exc:
        raise AcceptanceError("Run state identity is invalid") from exc
    os.chmod(canonical_state, 0o700)
    run_artifacts = canonical_state / "run-artifacts"
    run_artifacts.mkdir(mode=0o700)
    (
        owned_iso,
        owned_iso_metadata,
        source_iso_identity,
    ) = _copy_verified_iso(
        iso,
        run_artifacts / "install.iso",
        expected_sha256=expected_iso_sha256,
        after_open=after_iso_open,
    )
    paths: dict[str, tuple[Path, os.stat_result]] = {
        "iso": (owned_iso, owned_iso_metadata),
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
            "sha256": expected_iso_sha256,
            "verified_source_file_identity": source_iso_identity,
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
        "06-installed.json",
        "07-acceptance_evidence.json",
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


def verify_run_iso(state_dir: Path) -> dict[str, object]:
    manifest = _load_run_manifest(state_dir)
    binding = manifest.get("iso")
    if (
        not isinstance(binding, dict)
        or set(binding)
        != {
            "canonical_path",
            "file_identity",
            "sha256",
            "verified_source_file_identity",
        }
        or not isinstance(binding.get("file_identity"), dict)
        or not isinstance(
            binding.get("verified_source_file_identity"), dict
        )
        or set(binding["file_identity"]) != {"device", "inode", "size"}
        or set(binding["verified_source_file_identity"])
        != {"device", "inode", "size"}
        or not isinstance(binding.get("sha256"), str)
        or not SHA256_RE.fullmatch(str(binding["sha256"]))
    ):
        _fail("Run ISO binding is invalid")
    try:
        canonical, metadata = _canonical_regular(
            Path(str(binding["canonical_path"]))
        )
    except (KeyError, TypeError):
        _fail("Run ISO binding is invalid")
    expected_path = (
        state_dir.resolve(strict=True) / "run-artifacts" / "install.iso"
    )
    if (
        canonical != expected_path
        or str(canonical) != binding.get("canonical_path")
        or _file_identity(metadata) != binding.get("file_identity")
        or _sha256_file(canonical) != binding.get("sha256")
        or (
            os.name == "posix"
            and stat.S_IMODE(metadata.st_mode) != 0o400
        )
    ):
        _fail("Run ISO identity or SHA-256 changed")
    return binding


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
    *,
    require_iso: bool = False,
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
    if require_iso:
        iso = verify_run_iso(state_dir)
        install_iso = [
            item
            for item in inserted
            if isinstance(item, dict)
            and item.get("device") == "install-iso"
        ]
        if len(install_iso) != 1:
            _fail("QMP install ISO evidence is missing or ambiguous")
        iso_item = install_iso[0]
        iso_inserted = iso_item.get("inserted")
        if (
            not isinstance(iso_inserted, dict)
            or iso_inserted.get("file") != iso.get("canonical_path")
            or iso_inserted.get("ro") is not True
            or iso_item.get("removable") is not True
        ):
            _fail("QMP install ISO inserted file binding is invalid")
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


def _write_bound_sha_record(
    output: Path,
    state_dir: Path,
    artifact: str,
) -> dict[str, object]:
    manifest = _load_run_manifest(state_dir)
    binding = manifest["artifacts"][artifact]
    if not isinstance(binding, dict):
        _fail("Boundary artifact binding is invalid")
    canonical, metadata = _canonical_regular(
        Path(str(binding["canonical_path"]))
    )
    expected_identity = binding.get("file_identity")
    current_identity = _file_identity(metadata)
    if (
        not isinstance(expected_identity, dict)
        or current_identity != expected_identity
    ):
        _fail(f"Boundary {artifact} creation identity changed")
    digest = _sha256_file(canonical)
    _write_new(
        output,
        f"{digest}  {canonical}\n".encode("ascii"),
        mode=0o600,
    )
    return {
        "file_identity": current_identity,
        "record_file": output.name,
        "sha256": digest,
    }


def validate_authorization_boundary_freshness(
    *,
    pending_captured_at: str,
    before_authorization_started_at: str,
    before_authorization_captured_at: str,
    authorization_observed_at: str,
) -> None:
    pending_captured = _parse_timestamp(
        pending_captured_at, field="pending_captured_at"
    )
    preauth_started = _parse_timestamp(
        before_authorization_started_at,
        field="before_authorization_started_at",
    )
    preauth_captured = _parse_timestamp(
        before_authorization_captured_at,
        field="before_authorization_captured_at",
    )
    observed = _parse_timestamp(
        authorization_observed_at,
        field="authorization_observed_at",
    )
    if (
        not pending_captured
        < preauth_started
        < preauth_captured
        <= observed
        or (
            preauth_started - pending_captured
            > timedelta(
                seconds=AUTHORIZATION_PENDING_TO_PREAUTH_MAX_SECONDS
            )
        )
        or (
            observed - preauth_captured
            > timedelta(
                seconds=AUTHORIZATION_PREAUTH_TO_OBSERVED_MAX_SECONDS
            )
        )
    ):
        _fail("Authorization boundary freshness is invalid")


def capture_authorization_boundary(
    state_dir: Path,
    *,
    socket_path: Path,
    evidence_dir: Path,
    phase: str,
    qmp_capture: Callable[[Path, Path], None] | None = None,
    clock: Callable[[], str] = lambda: datetime.now(
        timezone.utc
    ).isoformat(timespec="microseconds"),
) -> dict[str, object]:
    if phase not in {"pending", "before-authorization"}:
        _fail("Authorization boundary phase is invalid")
    try:
        evidence_root = evidence_dir.resolve(strict=True)
    except OSError as exc:
        raise AcceptanceError(
            "Authorization evidence directory is unavailable"
        ) from exc
    if not evidence_root.is_dir() or evidence_dir.is_symlink():
        _fail("Authorization evidence directory is unsafe")
    started_at = clock()
    _parse_timestamp(started_at, field="capture_started_at")
    qmp_path = evidence_root / f"{phase}.qmp.jsonl"
    (qmp_capture or qmp_query)(socket_path, qmp_path)
    os.chmod(qmp_path, 0o600)
    snapshot = read_bound_qmp_snapshot(
        qmp_path, state_dir, require_iso=True
    )
    if any(
        not _all_writes_zero(snapshot[name]["graph"])
        for name in ("target", "sentinel")
    ):
        _fail(f"QMP writes occurred at {phase} boundary")
    target = _write_bound_sha_record(
        evidence_root / f"{phase}.target.sha256",
        state_dir,
        "target",
    )
    sentinel = _write_bound_sha_record(
        evidence_root / f"{phase}.sentinel.sha256",
        state_dir,
        "sentinel",
    )
    iso = dict(verify_run_iso(state_dir))
    captured_at = clock()
    started = _parse_timestamp(
        started_at, field="capture_started_at"
    )
    captured = _parse_timestamp(captured_at, field="captured_at")
    if (
        captured <= started
        or captured - started
        > timedelta(seconds=AUTHORIZATION_CAPTURE_MAX_SECONDS)
    ):
        _fail("Authorization boundary capture freshness is invalid")
    manifest = _load_run_manifest(state_dir)
    unsigned = {
        "capture_started_at": started_at,
        "captured_at": captured_at,
        "challenge": manifest["challenge"],
        "iso": iso,
        "phase": phase,
        "qmp": {
            "file": qmp_path.name,
            "sha256": hashlib.sha256(
                _read_bytes(qmp_path)
            ).hexdigest(),
        },
        "run_id": manifest["run_id"],
        "schema_version": 1,
        "sentinel": sentinel,
        "target": target,
        "trust_anchor_key_id": manifest["trust_anchor_key_id"],
    }
    signature = _private_attestation_key(state_dir).sign(
        _attestation_unsigned(unsigned)
    )
    document = {
        **unsigned,
        "signature_b64": base64.b64encode(signature).decode("ascii"),
    }
    _write_new(
        evidence_root / f"{phase}-boundary.json",
        _json_bytes(document),
        mode=0o600,
    )
    return document


def read_authorization_boundary(
    state_dir: Path,
    path: Path,
    *,
    expected_phase: str,
) -> dict[str, object]:
    if expected_phase not in {"pending", "before-authorization"}:
        _fail("Authorization boundary phase is invalid")
    expected_path = (
        path.parent.resolve(strict=True)
        / f"{expected_phase}-boundary.json"
    )
    try:
        actual_path = path.resolve(strict=True)
    except OSError as exc:
        raise AcceptanceError(
            "Authorization boundary is unavailable"
        ) from exc
    if actual_path != expected_path:
        _fail("Authorization boundary path is invalid")
    document = _read_json(actual_path)
    manifest = _load_run_manifest(state_dir)
    signature_b64 = document.get("signature_b64")
    unsigned = dict(document)
    unsigned.pop("signature_b64", None)
    if (
        set(document)
        != {
            "capture_started_at",
            "captured_at",
            "challenge",
            "iso",
            "phase",
            "qmp",
            "run_id",
            "schema_version",
            "sentinel",
            "signature_b64",
            "target",
            "trust_anchor_key_id",
        }
        or document.get("schema_version") != 1
        or document.get("phase") != expected_phase
        or document.get("run_id") != manifest["run_id"]
        or document.get("challenge") != manifest["challenge"]
        or document.get("trust_anchor_key_id")
        != manifest["trust_anchor_key_id"]
        or not isinstance(signature_b64, str)
    ):
        _fail("Authorization boundary binding is invalid")
    try:
        public = serialization.load_pem_public_key(
            _read_bytes(
                state_dir / "attestation-public.pem",
                maximum=16 * 1024,
            )
        )
        if not isinstance(public, Ed25519PublicKey):
            raise ValueError
        public.verify(
            base64.b64decode(signature_b64, validate=True),
            _attestation_unsigned(unsigned),
        )
    except (InvalidSignature, TypeError, ValueError):
        _fail("Authorization boundary signature is invalid")
    started = _parse_timestamp(
        document.get("capture_started_at"),
        field="capture_started_at",
    )
    captured = _parse_timestamp(
        document.get("captured_at"), field="captured_at"
    )
    if (
        captured <= started
        or captured - started
        > timedelta(seconds=AUTHORIZATION_CAPTURE_MAX_SECONDS)
    ):
        _fail("Authorization boundary capture freshness is invalid")
    parent = actual_path.parent
    qmp = document.get("qmp")
    if not isinstance(qmp, dict):
        _fail("Authorization boundary QMP binding is invalid")
    qmp_path = parent / f"{expected_phase}.qmp.jsonl"
    if (
        qmp.get("file") != qmp_path.name
        or qmp.get("sha256")
        != hashlib.sha256(_read_bytes(qmp_path)).hexdigest()
    ):
        _fail("Authorization boundary QMP binding is invalid")
    snapshot = read_bound_qmp_snapshot(
        qmp_path, state_dir, require_iso=True
    )
    if any(
        not _all_writes_zero(snapshot[name]["graph"])
        for name in ("target", "sentinel")
    ):
        _fail(f"QMP writes occurred at {expected_phase} boundary")
    for artifact in ("target", "sentinel"):
        item = document.get(artifact)
        record = parent / f"{expected_phase}.{artifact}.sha256"
        if (
            not isinstance(item, dict)
            or item.get("record_file") != record.name
            or item.get("sha256")
            != read_bound_sha256_record(record, state_dir, artifact)
        ):
            _fail(
                f"Authorization boundary {artifact} binding is invalid"
            )
    if document.get("iso") != verify_run_iso(state_dir):
        _fail("Authorization boundary ISO binding is invalid")
    return document


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


def workdir_ownership(workdir: Path) -> dict[str, object]:
    try:
        canonical = workdir.resolve(strict=True)
        metadata = canonical.stat()
        parent = canonical.parent.resolve(strict=True)
        parent_metadata = parent.stat()
    except OSError as exc:
        raise AcceptanceError(
            "Harness work directory is unavailable"
        ) from exc
    if (
        not canonical.is_dir()
        or workdir.is_symlink()
        or canonical.name in {"", ".", ".."}
    ):
        _fail("Harness work directory creation identity is invalid")
    return {
        "parent": str(parent),
        "parent_device": parent_metadata.st_dev,
        "parent_inode": parent_metadata.st_ino,
        "schema_version": 1,
        "workdir": str(canonical),
        "workdir_device": metadata.st_dev,
        "workdir_inode": metadata.st_ino,
        "workdir_name": canonical.name,
    }


def _verify_workdir_identity(
    ownership: dict[str, object], workdir: Path
) -> None:
    if (
        set(ownership)
        != {
            "parent",
            "parent_device",
            "parent_inode",
            "schema_version",
            "workdir",
            "workdir_device",
            "workdir_inode",
            "workdir_name",
        }
        or ownership.get("schema_version") != 1
        or workdir_ownership(workdir) != ownership
    ):
        _fail("Harness work directory identity changed")


def _empty_directory_fd(descriptor: int) -> None:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    for name in os.listdir(descriptor):
        metadata = os.stat(
            name, dir_fd=descriptor, follow_symlinks=False
        )
        if stat.S_ISDIR(metadata.st_mode):
            child = os.open(
                name,
                os.O_RDONLY | directory | nofollow,
                dir_fd=descriptor,
            )
            try:
                _empty_directory_fd(child)
            finally:
                os.close(child)
            os.rmdir(name, dir_fd=descriptor)
        else:
            os.unlink(name, dir_fd=descriptor)


def _empty_directory_path(path: Path) -> None:
    for child in path.iterdir():
        metadata = child.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            _empty_directory_path(child)
            child.rmdir()
        else:
            if os.name == "nt":
                child.chmod(0o600)
            child.unlink()


def remove_owned_workdir(
    ownership: dict[str, object],
    workdir: Path,
    *,
    before_final_remove: Callable[[], None] | None = None,
) -> None:
    _verify_workdir_identity(ownership, workdir)
    if os.name == "posix":
        parent = Path(str(ownership["parent"]))
        parent_descriptor = os.open(
            parent,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        child_descriptor = -1
        try:
            parent_metadata = os.fstat(parent_descriptor)
            if (
                parent_metadata.st_dev
                != ownership["parent_device"]
                or parent_metadata.st_ino
                != ownership["parent_inode"]
            ):
                _fail("Harness work directory parent identity changed")
            child_descriptor = os.open(
                str(ownership["workdir_name"]),
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent_descriptor,
            )
            child_metadata = os.fstat(child_descriptor)
            if (
                child_metadata.st_dev
                != ownership["workdir_device"]
                or child_metadata.st_ino
                != ownership["workdir_inode"]
            ):
                _fail("Harness work directory identity changed")
            if before_final_remove is not None:
                before_final_remove()
            current = os.stat(
                str(ownership["workdir_name"]),
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            if (
                current.st_dev != ownership["workdir_device"]
                or current.st_ino != ownership["workdir_inode"]
            ):
                _fail("Harness work directory identity changed")
            _empty_directory_fd(child_descriptor)
            current = os.stat(
                str(ownership["workdir_name"]),
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            if (
                current.st_dev != ownership["workdir_device"]
                or current.st_ino != ownership["workdir_inode"]
            ):
                _fail("Harness work directory identity changed")
            os.close(child_descriptor)
            child_descriptor = -1
            os.rmdir(
                str(ownership["workdir_name"]),
                dir_fd=parent_descriptor,
            )
        except OSError as exc:
            raise AcceptanceError(
                "Harness work directory cleanup failed closed"
            ) from exc
        finally:
            if child_descriptor >= 0:
                os.close(child_descriptor)
            os.close(parent_descriptor)
        return
    if before_final_remove is not None:
        before_final_remove()
    _verify_workdir_identity(ownership, workdir)
    _empty_directory_path(workdir)
    _verify_workdir_identity(ownership, workdir)
    workdir.rmdir()


def network_namespace_ownership(
    *,
    pid: int,
    process_starttime: int,
    namespace_device: int,
    namespace_inode: int,
) -> dict[str, object]:
    if (
        any(
            type(value) is not int or value < 1
            for value in (
                pid,
                process_starttime,
                namespace_device,
                namespace_inode,
            )
        )
    ):
        _fail("Harness network namespace identity is invalid")
    return {
        "namespace_device": namespace_device,
        "namespace_inode": namespace_inode,
        "pid": pid,
        "process_starttime": process_starttime,
        "schema_version": 1,
    }


def _process_starttime(pid: int) -> int:
    try:
        text = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        close = text.rfind(")")
        fields = text[close + 2 :].split()
        value = int(fields[19])
        if close < 1 or value < 1:
            raise ValueError
        return value
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise AcceptanceError(
            "Harness network namespace process identity is unavailable"
        ) from exc


def _network_namespace_identity(pid: int) -> tuple[int, int]:
    try:
        metadata = Path(f"/proc/{pid}/ns/net").stat()
    except OSError as exc:
        raise AcceptanceError(
            "Harness network namespace identity is unavailable"
        ) from exc
    return metadata.st_dev, metadata.st_ino


def _signal_pidfd(pidfd: int) -> None:
    if not hasattr(signal, "pidfd_send_signal"):
        _fail("Harness pidfd signaling is unavailable")
    signal.pidfd_send_signal(pidfd, signal.SIGTERM)


def _open_pidfd(pid: int) -> int:
    if not hasattr(os, "pidfd_open"):
        _fail("Harness pidfd ownership is unavailable")
    return os.pidfd_open(pid)


def _wait_pidfd(pidfd: int) -> None:
    poller = select.poll()
    poller.register(pidfd, select.POLLIN)
    if not poller.poll(5000):
        _fail("Harness network namespace holder did not exit")


def stop_owned_process(
    *,
    pid: int,
    process_starttime: int,
    pidfd_open: Callable[[int], int] = _open_pidfd,
    process_starttime_reader: Callable[[int], int] = _process_starttime,
    signaler: Callable[[int], None] = _signal_pidfd,
    waiter: Callable[[int], None] = _wait_pidfd,
    descriptor_close: Callable[[int], None] = os.close,
) -> None:
    if (
        type(pid) is not int
        or pid < 1
        or type(process_starttime) is not int
        or process_starttime < 1
    ):
        _fail("Harness owned process identity is invalid")
    try:
        pidfd = pidfd_open(pid)
    except ProcessLookupError:
        return
    try:
        try:
            observed_starttime = process_starttime_reader(pid)
        except OSError as exc:
            raise AcceptanceError(
                "Harness owned process identity is unavailable"
            ) from exc
        if observed_starttime != process_starttime:
            _fail("Harness owned process identity changed")
        signaler(pidfd)
        waiter(pidfd)
    finally:
        descriptor_close(pidfd)


def stop_owned_network_namespace(
    ownership: dict[str, object],
    *,
    pidfd_open: Callable[[int], int] = _open_pidfd,
    process_starttime_reader: Callable[[int], int] = _process_starttime,
    namespace_identity_reader: Callable[
        [int], tuple[int, int]
    ] = _network_namespace_identity,
    signaler: Callable[[int], None] = _signal_pidfd,
    waiter: Callable[[int], None] = _wait_pidfd,
    descriptor_close: Callable[[int], None] = os.close,
) -> None:
    if (
        set(ownership)
        != {
            "namespace_device",
            "namespace_inode",
            "pid",
            "process_starttime",
            "schema_version",
        }
        or ownership.get("schema_version") != 1
        or any(
            type(ownership.get(name)) is not int
            or int(ownership[name]) < 1
            for name in (
                "namespace_device",
                "namespace_inode",
                "pid",
                "process_starttime",
            )
        )
    ):
        _fail("Harness network namespace ownership record is invalid")
    pid = int(ownership["pid"])
    try:
        pidfd = pidfd_open(pid)
    except ProcessLookupError:
        return
    try:
        namespace_device, namespace_inode = (
            namespace_identity_reader(pid)
        )
        if (
            process_starttime_reader(pid)
            != ownership["process_starttime"]
            or namespace_device != ownership["namespace_device"]
            or namespace_inode != ownership["namespace_inode"]
        ):
            _fail("Harness network namespace identity changed")
        signaler(pidfd)
        waiter(pidfd)
    finally:
        descriptor_close(pidfd)


def hold_network_namespace(record: Path) -> None:
    pid = os.getpid()
    namespace_device, namespace_inode = _network_namespace_identity(pid)
    ownership = network_namespace_ownership(
        pid=pid,
        process_starttime=_process_starttime(pid),
        namespace_device=namespace_device,
        namespace_inode=namespace_inode,
    )
    _write_new(record, _json_bytes(ownership), mode=0o600)
    while True:
        signal.pause()


def run_in_owned_network_namespace(
    ownership: dict[str, object], command: Sequence[str]
) -> NoReturn:
    if not command or any(not item for item in command):
        _fail("Harness network namespace command is invalid")
    pid = ownership.get("pid")
    if type(pid) is not int:
        _fail("Harness network namespace ownership record is invalid")
    try:
        descriptor = os.open(
            f"/proc/{pid}/ns/net",
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError as exc:
        raise AcceptanceError(
            "Harness network namespace cannot be entered"
        ) from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            _process_starttime(pid) != ownership.get("process_starttime")
            or metadata.st_dev != ownership.get("namespace_device")
            or metadata.st_ino != ownership.get("namespace_inode")
        ):
            _fail("Harness network namespace identity changed")
        if not hasattr(os, "setns"):
            _fail("Harness network namespace entry is unavailable")
        os.setns(descriptor, getattr(os, "CLONE_NEWNET", 0))
    finally:
        os.close(descriptor)
    os.execvp(command[0], list(command))
    raise AssertionError("unreachable")


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
    observed_at: str,
    pending_boundary: Path | None = None,
    before_authorization_boundary: Path | None = None,
    initial_qmp: Path | None = None,
    before_authorization_qmp: Path | None = None,
    initial_target_sha: Path | None = None,
    before_authorization_target_sha: Path | None = None,
    initial_sentinel_sha: Path | None = None,
    before_authorization_sentinel_sha: Path | None = None,
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
    authorization_observed = _parse_timestamp(
        observed_at, field="authorization_observed_at"
    )
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
    boundary_payload: dict[str, object] = {}
    if (
        pending_boundary is not None
        or before_authorization_boundary is not None
    ):
        if (
            pending_boundary is None
            or before_authorization_boundary is None
            or any(
                item is not None
                for item in (
                    initial_qmp,
                    before_authorization_qmp,
                    initial_target_sha,
                    before_authorization_target_sha,
                    initial_sentinel_sha,
                    before_authorization_sentinel_sha,
                )
            )
        ):
            _fail("Authorization boundary selection is ambiguous")
        pending = read_authorization_boundary(
            state_dir,
            pending_boundary,
            expected_phase="pending",
        )
        immediate_boundary = read_authorization_boundary(
            state_dir,
            before_authorization_boundary,
            expected_phase="before-authorization",
        )
        validate_authorization_boundary_freshness(
            pending_captured_at=str(pending["captured_at"]),
            before_authorization_started_at=str(
                immediate_boundary["capture_started_at"]
            ),
            before_authorization_captured_at=str(
                immediate_boundary["captured_at"]
            ),
            authorization_observed_at=observed_at,
        )
        boundary_parent = pending_boundary.parent.resolve(strict=True)
        before_parent = (
            before_authorization_boundary.parent.resolve(strict=True)
        )
        initial_qmp = boundary_parent / str(pending["qmp"]["file"])
        before_authorization_qmp = (
            before_parent / str(immediate_boundary["qmp"]["file"])
        )
        initial_target_sha = (
            boundary_parent / str(pending["target"]["record_file"])
        )
        before_authorization_target_sha = (
            before_parent
            / str(immediate_boundary["target"]["record_file"])
        )
        initial_sentinel_sha = (
            boundary_parent / str(pending["sentinel"]["record_file"])
        )
        before_authorization_sentinel_sha = (
            before_parent
            / str(immediate_boundary["sentinel"]["record_file"])
        )
        boundary_payload = {
            "before_authorization_boundary_sha256": hashlib.sha256(
                _read_bytes(before_authorization_boundary)
            ).hexdigest(),
            "pending_boundary_sha256": hashlib.sha256(
                _read_bytes(pending_boundary)
            ).hexdigest(),
        }
    elif any(
        item is None
        for item in (
            initial_qmp,
            before_authorization_qmp,
            initial_target_sha,
            before_authorization_target_sha,
            initial_sentinel_sha,
            before_authorization_sentinel_sha,
        )
    ):
        _fail("Authorization boundary evidence is incomplete")
    assert initial_qmp is not None
    assert before_authorization_qmp is not None
    assert initial_target_sha is not None
    assert before_authorization_target_sha is not None
    assert initial_sentinel_sha is not None
    assert before_authorization_sentinel_sha is not None
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
        initial_sentinel_sha, state_dir, "sentinel"
    )
    immediate_sentinel = read_bound_sha256_record(
        before_authorization_sentinel_sha, state_dir, "sentinel"
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
    try:
        authorized_at = _parse_timestamp(
            execution.get("authorized_at")
            if isinstance(execution, dict)
            else None,
            field="authorized_at",
        )
    except AcceptanceError:
        _fail("Controller execution authorization response is invalid")
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
        or authorized_at < authorization_observed
        or authorized_at - authorization_observed
        > timedelta(seconds=30)
    ):
        _fail("Controller execution authorization response is invalid")
    payload = {
        **boundary_payload,
        "authorization_observed_at": observed_at,
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


def _copy_public_file(source: Path, output: Path) -> str:
    content = _read_bytes(source)
    _write_new(output, content, mode=0o600)
    return hashlib.sha256(content).hexdigest()


def _portable_qmp_snapshot(
    path: Path,
    manifest: dict[str, object],
    *,
    require_iso: bool,
) -> dict[str, dict[str, object]]:
    responses = _qmp_responses(path)
    snapshot = _read_qmp_snapshot(path)
    blocks = responses["block"].get("return")
    artifacts = manifest.get("artifacts")
    iso = manifest.get("iso")
    if (
        not isinstance(blocks, list)
        or not isinstance(artifacts, dict)
        or not isinstance(iso, dict)
    ):
        _fail("Public evidence QMP semantic binding is invalid")
    inserted: dict[str, dict[str, object]] = {}
    for item in blocks:
        if not isinstance(item, dict):
            _fail("Public evidence QMP semantic binding is invalid")
        device = item.get("device")
        details = item.get("inserted")
        if device in {"target", "sentinel", "install-iso"}:
            if (
                not isinstance(device, str)
                or device in inserted
                or not isinstance(details, dict)
            ):
                _fail("Public evidence QMP semantic binding is invalid")
            inserted[device] = details
    for artifact in ("target", "sentinel"):
        binding = artifacts.get(artifact)
        if (
            not isinstance(binding, dict)
            or inserted.get(artifact, {}).get("file")
            != binding.get("canonical_path")
        ):
            _fail("Public evidence QMP semantic binding is invalid")
    install_iso = inserted.get("install-iso")
    if require_iso:
        install_blocks = [
            item
            for item in blocks
            if isinstance(item, dict)
            and item.get("device") == "install-iso"
        ]
        if (
            len(install_blocks) != 1
            or not isinstance(install_iso, dict)
            or install_iso.get("file") != iso.get("canonical_path")
            or install_iso.get("ro") is not True
            or install_blocks[0].get("removable") is not True
        ):
            _fail("Public evidence ISO QMP semantic binding is invalid")
    elif install_iso is not None:
        _fail("Public evidence unexpectedly contains an install ISO")
    return snapshot


def _portable_sha256_record(
    path: Path,
    manifest: dict[str, object],
    artifact: str,
) -> str:
    try:
        lines = _read_bytes(path, maximum=4096).decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise AcceptanceError(
            "Public SHA-256 evidence is not ASCII"
        ) from exc
    artifacts = manifest.get("artifacts")
    binding = (
        artifacts.get(artifact)
        if isinstance(artifacts, dict)
        else None
    )
    fields = lines[0].split(maxsplit=1) if len(lines) == 1 else []
    if (
        not isinstance(binding, dict)
        or len(fields) != 2
        or not SHA256_RE.fullmatch(fields[0])
        or fields[1] != binding.get("canonical_path")
    ):
        _fail("Public SHA-256 semantic binding is invalid")
    return fields[0]


def _public_attestation_key(root: Path) -> Ed25519PublicKey:
    try:
        public = serialization.load_pem_public_key(
            _read_bytes(
                root / "attestation-public.pem", maximum=16 * 1024
            )
        )
    except ValueError as exc:
        raise AcceptanceError(
            "Public acceptance key is invalid"
        ) from exc
    if not isinstance(public, Ed25519PublicKey):
        _fail("Public acceptance key is invalid")
    return public


def _verify_portable_boundary(
    root: Path,
    manifest: dict[str, object],
    *,
    phase: str,
    public: Ed25519PublicKey,
) -> dict[str, object]:
    evidence = root / "evidence"
    document_path = evidence / f"{phase}-boundary.json"
    document = _read_json(document_path)
    signature = document.get("signature_b64")
    unsigned = dict(document)
    unsigned.pop("signature_b64", None)
    qmp = document.get("qmp")
    if (
        set(document)
        != {
            "capture_started_at",
            "captured_at",
            "challenge",
            "iso",
            "phase",
            "qmp",
            "run_id",
            "schema_version",
            "sentinel",
            "signature_b64",
            "target",
            "trust_anchor_key_id",
        }
        or document.get("schema_version") != 1
        or document.get("phase") != phase
        or document.get("run_id") != manifest.get("run_id")
        or document.get("challenge") != manifest.get("challenge")
        or document.get("trust_anchor_key_id")
        != manifest.get("trust_anchor_key_id")
        or document.get("iso") != manifest.get("iso")
        or not isinstance(signature, str)
        or not isinstance(qmp, dict)
        or set(qmp) != {"file", "sha256"}
        or qmp.get("file") != f"{phase}.qmp.jsonl"
    ):
        _fail("Public boundary semantic binding is invalid")
    try:
        public.verify(
            base64.b64decode(signature, validate=True),
            _attestation_unsigned(unsigned),
        )
    except (InvalidSignature, ValueError):
        _fail("Public boundary signature is invalid")
    started = _parse_timestamp(
        document.get("capture_started_at"),
        field="capture_started_at",
    )
    captured = _parse_timestamp(
        document.get("captured_at"), field="captured_at"
    )
    if (
        captured <= started
        or captured - started
        > timedelta(seconds=AUTHORIZATION_CAPTURE_MAX_SECONDS)
    ):
        _fail("Public boundary semantic freshness is invalid")
    qmp_path = evidence / str(qmp["file"])
    if qmp.get("sha256") != hashlib.sha256(
        _read_bytes(qmp_path)
    ).hexdigest():
        _fail("Public boundary QMP hash is invalid")
    snapshot = _portable_qmp_snapshot(
        qmp_path, manifest, require_iso=True
    )
    if (
        snapshot["target"]["read_only"] is not False
        or snapshot["sentinel"]["read_only"] is not True
        or any(
            not _all_writes_zero(snapshot[name]["graph"])
            for name in ("target", "sentinel")
        )
    ):
        _fail("Public boundary QMP semantic predicate is invalid")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict):
        _fail("Public boundary artifact binding is invalid")
    for artifact in ("target", "sentinel"):
        item = document.get(artifact)
        record_name = f"{phase}.{artifact}.sha256"
        binding = artifacts.get(artifact)
        if (
            not isinstance(item, dict)
            or set(item) != {"file_identity", "record_file", "sha256"}
            or item.get("record_file") != record_name
            or not isinstance(binding, dict)
            or item.get("file_identity") != binding.get("file_identity")
            or item.get("sha256")
            != _portable_sha256_record(
                evidence / record_name, manifest, artifact
            )
        ):
            _fail("Public boundary artifact semantic binding is invalid")
    return document


def _replay_public_acceptance(
    root: Path,
    manifest: dict[str, object],
    chain: list[dict[str, object]],
    receipt: dict[str, object],
) -> None:
    evidence = root / "evidence"
    public = _public_attestation_key(root)
    pending = _verify_portable_boundary(
        root, manifest, phase="pending", public=public
    )
    preauth = _verify_portable_boundary(
        root,
        manifest,
        phase="before-authorization",
        public=public,
    )
    preauth_snapshot = _portable_qmp_snapshot(
        root / "evidence" / "before-authorization.qmp.jsonl",
        manifest,
        require_iso=True,
    )
    events = [item.get("event") for item in chain]
    if events != [
        "authorization",
        "claimed",
        "handoff_started",
        "installer_started",
        "postflight_boot",
        "installed",
        "acceptance_evidence",
    ]:
        _fail("Public controller lifecycle semantic chain is invalid")
    authorization = chain[0].get("payload")
    if (
        not isinstance(authorization, dict)
        or set(authorization)
        != {
            "authorization_observed_at",
            "before_authorization_boundary_sha256",
            "before_authorization_qmp_sha256",
            "controller",
            "initial_qmp_sha256",
            "initial_sentinel_sha256",
            "initial_target_sha256",
            "pending_boundary_sha256",
            "request",
            "sentinel_sha256_before_authorization",
            "target_disk",
            "target_sha256_before_authorization",
        }
    ):
        _fail("Public authorization semantic evidence is invalid")
    validate_authorization_boundary_freshness(
        pending_captured_at=str(pending["captured_at"]),
        before_authorization_started_at=str(
            preauth["capture_started_at"]
        ),
        before_authorization_captured_at=str(preauth["captured_at"]),
        authorization_observed_at=str(
            authorization.get("authorization_observed_at")
        ),
    )
    authorization_observed = _parse_timestamp(
        authorization.get("authorization_observed_at"),
        field="authorization_observed_at",
    )
    controller_authorized = _parse_timestamp(
        chain[0].get("observed_at"), field="authorized_at"
    )
    if (
        controller_authorized < authorization_observed
        or controller_authorized - authorization_observed
        > timedelta(seconds=30)
    ):
        _fail("Public authorization semantic freshness is invalid")
    pending_qmp = evidence / "pending.qmp.jsonl"
    preauth_qmp = evidence / "before-authorization.qmp.jsonl"
    if (
        authorization.get("pending_boundary_sha256")
        != hashlib.sha256(
            _read_bytes(evidence / "pending-boundary.json")
        ).hexdigest()
        or authorization.get("before_authorization_boundary_sha256")
        != hashlib.sha256(
            _read_bytes(
                evidence / "before-authorization-boundary.json"
            )
        ).hexdigest()
        or authorization.get("initial_qmp_sha256")
        != hashlib.sha256(_read_bytes(pending_qmp)).hexdigest()
        or authorization.get("before_authorization_qmp_sha256")
        != hashlib.sha256(_read_bytes(preauth_qmp)).hexdigest()
    ):
        _fail("Public authorization semantic hash binding is invalid")
    request = authorization.get("request")
    controller = authorization.get("controller")
    if (
        not isinstance(request, dict)
        or not isinstance(controller, dict)
        or request.get("target_disk") != "/dev/vda"
        or controller
        != {
            "execution_id": (
                f"{request.get('session_id')}:execution-0001"
            ),
            "state": "authorized",
        }
    ):
        _fail("Public authorization semantic controller binding is invalid")
    session_id = request.get("session_id")
    execution_id = controller["execution_id"]
    for attestation, state in zip(
        chain[1:4],
        ("claimed", "handoff_started", "installer_started"),
        strict=True,
    ):
        payload = attestation.get("payload")
        if (
            not isinstance(payload, dict)
            or set(payload) != {"controller", "session_id"}
            or payload.get("session_id") != session_id
            or payload.get("controller")
            != {"execution_id": execution_id, "state": state}
        ):
            _fail("Public controller lifecycle semantic chain is invalid")
    initial_target = _portable_sha256_record(
        evidence / "pending.target.sha256", manifest, "target"
    )
    preauth_target = _portable_sha256_record(
        evidence / "before-authorization.target.sha256",
        manifest,
        "target",
    )
    after_target = _portable_sha256_record(
        evidence / "target.after.sha256", manifest, "target"
    )
    initial_sentinel = _portable_sha256_record(
        evidence / "pending.sentinel.sha256", manifest, "sentinel"
    )
    preauth_sentinel = _portable_sha256_record(
        evidence / "before-authorization.sentinel.sha256",
        manifest,
        "sentinel",
    )
    after_sentinel = _portable_sha256_record(
        evidence / "sentinel.after.sha256", manifest, "sentinel"
    )
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict):
        _fail("Public artifact semantic transition is invalid")
    target_binding = artifacts.get("target")
    sentinel_binding = artifacts.get("sentinel")
    if (
        not isinstance(target_binding, dict)
        or not isinstance(sentinel_binding, dict)
        or initial_target != target_binding.get("initial_sha256")
        or preauth_target != initial_target
        or after_target == initial_target
        or initial_sentinel != sentinel_binding.get("initial_sha256")
        or preauth_sentinel != initial_sentinel
        or after_sentinel != initial_sentinel
        or authorization.get("initial_target_sha256") != initial_target
        or authorization.get("target_sha256_before_authorization")
        != preauth_target
        or authorization.get("initial_sentinel_sha256")
        != initial_sentinel
        or authorization.get("sentinel_sha256_before_authorization")
        != preauth_sentinel
    ):
        _fail("Public artifact semantic transition is invalid")
    after = _portable_qmp_snapshot(
        evidence / "after-install.qmp.jsonl",
        manifest,
        require_iso=True,
    )
    if (
        after["target"]["read_only"] is not False
        or after["sentinel"]["read_only"] is not True
        or after["target"]["write_bytes"] <= 0
        or not _all_writes_zero(after["sentinel"]["graph"])
    ):
        _fail("Public QMP semantic write transition is invalid")
    boot = _read_postflight_boot_qmp(
        evidence / "postflight-boot.qmp.jsonl", root
    )
    boot_payload = chain[4].get("payload")
    installed_payload = chain[5].get("payload")
    delivery = _read_json(evidence / "postflight-delivery.json")
    authenticated = _read_json(
        evidence / "authenticated-postflight.json"
    )
    if (
        not isinstance(boot_payload, dict)
        or not isinstance(installed_payload, dict)
        or set(boot_payload)
        != {
            "boot_nonce",
            "controller",
            "iso_attached",
            "qmp_sha256",
            "session_id",
            "status",
            "vm_instance_id",
        }
        or set(installed_payload)
        != {
            "boot_id",
            "boot_nonce",
            "controller",
            "reported_at",
            "session_id",
        }
        or set(delivery)
        != {
            "boot_attestation",
            "boot_nonce",
            "challenge",
            "controller_url",
            "run_id",
            "schema_version",
            "session_id",
            "vm_instance_id",
        }
        or set(authenticated)
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
        or boot_payload.get("qmp_sha256") != boot["qmp_sha256"]
        or boot_payload.get("iso_attached") is not False
        or boot_payload.get("session_id") != session_id
        or boot_payload.get("vm_instance_id")
        != manifest.get("vm_instance_id")
        or boot_payload.get("controller")
        != {
            "execution_id": execution_id,
            "state": "installer_started",
        }
        or type(delivery.get("schema_version")) is not int
        or delivery.get("schema_version") != 1
        or delivery.get("run_id") != manifest.get("run_id")
        or delivery.get("challenge") != manifest.get("challenge")
        or delivery.get("vm_instance_id")
        != manifest.get("vm_instance_id")
        or delivery.get("controller_url")
        != "https://192.168.100.17:18092"
        or delivery.get("boot_attestation") != chain[4]
        or delivery.get("boot_nonce") != boot_payload.get("boot_nonce")
        or delivery.get("session_id") != session_id
        or type(authenticated.get("schema_version")) is not int
        or authenticated.get("schema_version") != 1
        or authenticated.get("run_id") != manifest.get("run_id")
        or authenticated.get("challenge") != manifest.get("challenge")
        or authenticated.get("vm_instance_id")
        != manifest.get("vm_instance_id")
        or authenticated.get("boot_attestation") != chain[4]
        or authenticated.get("boot_nonce") != boot_payload.get("boot_nonce")
        or authenticated.get("boot_id") != installed_payload.get("boot_id")
        or authenticated.get("reported_at")
        != installed_payload.get("reported_at")
        or installed_payload.get("session_id") != session_id
        or installed_payload.get("controller")
        != {"execution_id": execution_id, "state": "installed"}
    ):
        _fail("Public postflight semantic evidence is invalid")
    iso = manifest.get("iso")
    iso_evidence = _read_json(evidence / "iso-evidence.json")
    receipt_artifacts = receipt.get("artifacts")
    receipt_controller = receipt.get("controller")
    receipt_writes = receipt.get("writes")
    receipt_postflight = receipt.get("postflight")
    if (
        not isinstance(iso, dict)
        or not isinstance(receipt_artifacts, dict)
        or not isinstance(receipt_controller, dict)
        or not isinstance(receipt_writes, dict)
        or not isinstance(receipt_writes.get("after_install"), dict)
        or not isinstance(
            receipt_writes.get("before_authorization"), dict
        )
        or not isinstance(receipt_postflight, dict)
        or iso_evidence
        != {
            "file_identity": iso.get("file_identity"),
            "owned_file": "run-artifacts/install.iso",
            "schema_version": 1,
            "sha256": iso.get("sha256"),
            "verified_source_file_identity": iso.get(
                "verified_source_file_identity"
            ),
        }
        or receipt_artifacts.get("iso") != iso
        or not isinstance(receipt_artifacts.get("target"), dict)
        or receipt_artifacts["target"].get("after_sha256") != after_target
        or not isinstance(receipt_artifacts.get("sentinel"), dict)
        or receipt_artifacts["sentinel"].get("after_sha256")
        != after_sentinel
        or receipt_controller
        != {
            "execution_id": execution_id,
            "session_id": session_id,
            "state": "installed",
        }
        or receipt_writes["before_authorization"]
        != {
            "sentinel_write_bytes": preauth_snapshot["sentinel"][
                "write_bytes"
            ],
            "target_write_bytes": preauth_snapshot["target"][
                "write_bytes"
            ],
        }
        or receipt_writes["after_install"]
        != {
            "sentinel_write_bytes": after["sentinel"]["write_bytes"],
            "target_write_bytes": after["target"]["write_bytes"],
        }
        or receipt_postflight
        != {
            "boot_id": installed_payload.get("boot_id"),
            "boot_nonce": installed_payload.get("boot_nonce"),
            "iso_attached": False,
            "vm_instance_id": manifest.get("vm_instance_id"),
        }
    ):
        _fail("Public receipt or ISO semantic evidence is invalid")


def export_public_evidence(
    state_dir: Path,
    *,
    receipt: Path,
    output: Path,
    evidence_files: dict[str, Path] | None = None,
    observed_at: str | None = None,
    euid: Callable[[], int] = lambda: getattr(
        os, "geteuid", lambda: -1
    )(),
) -> dict[str, object]:
    if euid() != 0:
        _fail("Root is required to export acceptance evidence")
    chain = load_attestation_chain(state_dir)
    if len(chain) != 6 or chain[-1].get("event") != "installed":
        _fail("Acceptance transition chain is incomplete")
    receipt_document = _read_json(receipt)
    manifest = _load_run_manifest(state_dir)
    if (
        receipt_document.get("result") != "pass"
        or receipt_document.get("attestation_chain_sha256")
        != attestation_sha256(chain[-1])
        or receipt_document.get("run", {}).get("run_id")
        != manifest["run_id"]
    ):
        _fail("Acceptance receipt chain binding is invalid")
    sources = evidence_files or {}
    if set(sources) != MANDATORY_PUBLIC_SOURCE_NAMES:
        _fail("Public acceptance evidence corpus is incomplete or ambiguous")
    if any(
        not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", name)
        for name in sources
    ):
        _fail("Public evidence name is invalid")
    if len(sources) != len(set(sources)):
        _fail("Public evidence names are ambiguous")
    try:
        if output.exists() or output.is_symlink():
            _fail("Refusing to overwrite public evidence")
        output.mkdir(mode=0o700)
        os.chmod(output, 0o700)
        (output / "attestations").mkdir(mode=0o700)
        (output / "evidence").mkdir(mode=0o700)
        os.chmod(output / "attestations", 0o700)
        os.chmod(output / "evidence", 0o700)
    except OSError as exc:
        raise AcceptanceError(
            "Public evidence directory cannot be created"
        ) from exc
    evidence_sha256: dict[str, str] = {}
    for name, source in sorted(sources.items()):
        evidence_sha256[name] = hashlib.sha256(
            _read_bytes(source)
        ).hexdigest()
    iso = manifest.get("iso")
    if not isinstance(iso, dict):
        _fail("Run ISO binding is invalid")
    iso_evidence = {
        "file_identity": iso.get("file_identity"),
        "owned_file": "run-artifacts/install.iso",
        "schema_version": 1,
        "sha256": iso.get("sha256"),
        "verified_source_file_identity": iso.get(
            "verified_source_file_identity"
        ),
    }
    iso_evidence_bytes = _json_bytes(iso_evidence)
    evidence_sha256["iso-evidence.json"] = hashlib.sha256(
        iso_evidence_bytes
    ).hexdigest()
    public_key = state_dir / "attestation-public.pem"
    manifest_path = state_dir / "run-manifest.json"
    seal = issue_attestation(
        state_dir,
        event="acceptance_evidence",
        sequence=7,
        payload={
            "evidence_sha256": evidence_sha256,
            "manifest_sha256": hashlib.sha256(
                _read_bytes(manifest_path)
            ).hexdigest(),
            "public_key_sha256": hashlib.sha256(
                _read_bytes(public_key)
            ).hexdigest(),
            "receipt_sha256": hashlib.sha256(
                _read_bytes(receipt)
            ).hexdigest(),
        },
        observed_at=(
            observed_at
            or datetime.now(timezone.utc).isoformat()
        ),
        previous_sha256=attestation_sha256(chain[-1]),
    )
    store_attestation(state_dir, seal)
    _copy_public_file(
        manifest_path, output / "run-manifest.json"
    )
    _copy_public_file(
        public_key, output / "attestation-public.pem"
    )
    _copy_public_file(
        receipt, output / "acceptance-receipt.json"
    )
    for attestation_path in sorted(
        (state_dir / "attestations").iterdir()
    ):
        _copy_public_file(
            attestation_path,
            output / "attestations" / attestation_path.name,
        )
    for name, source in sorted(sources.items()):
        _copy_public_file(source, output / "evidence" / name)
    _write_new(
        output / "evidence" / "iso-evidence.json",
        iso_evidence_bytes,
        mode=0o600,
    )
    index = {
        "evidence_sha256": evidence_sha256,
        "final_attestation_sha256": attestation_sha256(seal),
        "manifest_sha256": seal["payload"]["manifest_sha256"],
        "public_key_sha256": seal["payload"]["public_key_sha256"],
        "receipt_sha256": seal["payload"]["receipt_sha256"],
        "run_id": manifest["run_id"],
        "schema_version": 1,
    }
    _write_new(
        output / "evidence-index.json",
        _json_bytes(index),
        mode=0o600,
    )
    verify_public_evidence(output, euid=euid)
    print(PASS_LINE)
    return index


def verify_public_evidence(
    evidence_dir: Path,
    *,
    euid: Callable[[], int] = lambda: getattr(
        os, "geteuid", lambda: -1
    )(),
) -> dict[str, object]:
    if euid() != 0:
        _fail("Root is required to verify acceptance evidence")
    try:
        root = evidence_dir.resolve(strict=True)
    except OSError as exc:
        raise AcceptanceError(
            "Public evidence directory is unavailable"
        ) from exc
    if (
        not root.is_dir()
        or evidence_dir.is_symlink()
        or any(path.is_symlink() for path in root.rglob("*"))
        or any("private" in path.name.casefold() for path in root.rglob("*"))
    ):
        _fail("Public evidence directory is unsafe")
    if {path.name for path in root.iterdir()} != {
        "acceptance-receipt.json",
        "attestation-public.pem",
        "attestations",
        "evidence",
        "evidence-index.json",
        "run-manifest.json",
    }:
        _fail("Public evidence file set is invalid")
    paths = [
        root,
        root / "attestations",
        root / "evidence",
        *[path for path in root.rglob("*") if path.is_file()],
    ]
    for path in paths:
        metadata = path.stat()
        expected_mode = 0o700 if path.is_dir() else 0o600
        if (
            os.name == "posix"
            and stat.S_IMODE(metadata.st_mode) != expected_mode
        ):
            _fail("Public evidence permissions are invalid")
        if os.name == "posix" and metadata.st_uid != 0:
            _fail("Public evidence owner is invalid")
        if path.is_file():
            content = _read_bytes(path)
            if (
                b"PRIVATE KEY-----" in content
                or b"Bearer " in content
                or b'"credential"' in content
            ):
                _fail("Public evidence contains private material")
    manifest = _load_run_manifest(root)
    chain = load_attestation_chain(root)
    if (
        len(chain) != 7
        or chain[-1].get("event") != "acceptance_evidence"
    ):
        _fail("Public acceptance evidence seal is absent")
    seal_payload = chain[-1].get("payload")
    if not isinstance(seal_payload, dict):
        _fail("Public acceptance evidence seal is invalid")
    index = _read_json(root / "evidence-index.json")
    receipt_path = root / "acceptance-receipt.json"
    receipt = _read_json(receipt_path)
    if (
        index.get("schema_version") != 1
        or index.get("run_id") != manifest["run_id"]
        or index.get("final_attestation_sha256")
        != attestation_sha256(chain[-1])
        or index.get("manifest_sha256")
        != hashlib.sha256(
            _read_bytes(root / "run-manifest.json")
        ).hexdigest()
        or index.get("public_key_sha256")
        != hashlib.sha256(
            _read_bytes(root / "attestation-public.pem")
        ).hexdigest()
        or index.get("receipt_sha256")
        != hashlib.sha256(_read_bytes(receipt_path)).hexdigest()
        or index.get("evidence_sha256")
        != seal_payload.get("evidence_sha256")
        or index.get("manifest_sha256")
        != seal_payload.get("manifest_sha256")
        or index.get("public_key_sha256")
        != seal_payload.get("public_key_sha256")
        or index.get("receipt_sha256")
        != seal_payload.get("receipt_sha256")
        or receipt.get("result") != "pass"
        or receipt.get("attestation_chain_sha256")
        != attestation_sha256(chain[5])
        or receipt.get("run", {}).get("run_id") != manifest["run_id"]
    ):
        _fail("Public acceptance evidence hash linkage is invalid")
    evidence_hashes = seal_payload.get("evidence_sha256")
    if not isinstance(evidence_hashes, dict):
        _fail("Public evidence hash set is invalid")
    actual_names = {
        path.name for path in (root / "evidence").iterdir()
    }
    if (
        actual_names != MANDATORY_PUBLIC_EVIDENCE_NAMES
        or set(evidence_hashes) != MANDATORY_PUBLIC_EVIDENCE_NAMES
    ):
        _fail("Public evidence file set is invalid")
    for name, expected_sha256 in evidence_hashes.items():
        if (
            not isinstance(name, str)
            or not isinstance(expected_sha256, str)
            or hashlib.sha256(
                _read_bytes(root / "evidence" / name)
            ).hexdigest()
            != expected_sha256
        ):
            _fail("Public evidence file hash is invalid")
    _replay_public_acceptance(root, manifest, chain, receipt)
    return {"chain": chain, "index": index, "receipt": receipt}


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
    create.add_argument("--expected-iso-sha256", required=True)
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
    authorize.add_argument(
        "--pending-boundary", required=True, type=Path
    )
    authorize.add_argument(
        "--before-authorization-boundary",
        required=True,
        type=Path,
    )
    authorize.add_argument("--observed-at", required=True)
    capture = commands.add_parser(
        "capture-authorization-boundary", allow_abbrev=False
    )
    capture.add_argument("--state-dir", required=True, type=Path)
    capture.add_argument("--socket", required=True, type=Path)
    capture.add_argument("--evidence-dir", required=True, type=Path)
    capture.add_argument(
        "--phase",
        required=True,
        choices=("pending", "before-authorization"),
    )
    verify_iso = commands.add_parser(
        "verify-run-iso", allow_abbrev=False
    )
    verify_iso.add_argument("--state-dir", required=True, type=Path)
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
    record_workdir = commands.add_parser(
        "record-workdir-ownership", allow_abbrev=False
    )
    record_workdir.add_argument("--record", required=True, type=Path)
    record_workdir.add_argument("--workdir", required=True, type=Path)
    remove_workdir = commands.add_parser(
        "remove-owned-workdir", allow_abbrev=False
    )
    remove_workdir.add_argument("--record", required=True, type=Path)
    remove_workdir.add_argument("--workdir", required=True, type=Path)
    hold_netns = commands.add_parser(
        "hold-network-namespace", allow_abbrev=False
    )
    hold_netns.add_argument("--record", required=True, type=Path)
    run_netns = commands.add_parser(
        "run-in-network-namespace", allow_abbrev=False
    )
    run_netns.add_argument("--record", required=True, type=Path)
    run_netns.add_argument("network_command", nargs=argparse.REMAINDER)
    stop_netns = commands.add_parser(
        "stop-network-namespace", allow_abbrev=False
    )
    stop_netns.add_argument("--record", required=True, type=Path)
    stop_process = commands.add_parser(
        "stop-owned-process", allow_abbrev=False
    )
    stop_process.add_argument("--pid", required=True, type=int)
    stop_process.add_argument(
        "--process-starttime", required=True, type=int
    )
    export = commands.add_parser(
        "export-public-evidence", allow_abbrev=False
    )
    export.add_argument("--state-dir", required=True, type=Path)
    export.add_argument("--receipt", required=True, type=Path)
    export.add_argument("--output", required=True, type=Path)
    export.add_argument(
        "--evidence", action="append", default=[], metavar="NAME=PATH"
    )
    verify_public = commands.add_parser(
        "verify-public-evidence", allow_abbrev=False
    )
    verify_public.add_argument("--evidence-dir", required=True, type=Path)
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


def main(
    argv: Sequence[str] | None = None,
    *,
    cli: Callable[..., int] = control_cli_main,
    status_loader: Callable[[str], dict[str, object]] = controller_status,
    revision_loader: Callable[
        [str, str], bytes
    ] = controller_revision_file,
    euid: Callable[[], int] = lambda: getattr(
        os, "geteuid", lambda: -1
    )(),
) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        if arguments.command == "create-run":
            manifest = create_run_state(
                arguments.state_dir,
                iso=arguments.iso,
                expected_iso_sha256=arguments.expected_iso_sha256,
                target=arguments.target,
                sentinel=arguments.sentinel,
                vm_instance_id=arguments.vm_instance_id,
            )
            print(f"run_id={manifest['run_id']}")
        elif arguments.command == "create-authorization-request":
            request = create_authorization_request(arguments.state_dir)
            print(f"session_id={request['session_id']}")
        elif arguments.command == "capture-authorization-boundary":
            boundary = capture_authorization_boundary(
                arguments.state_dir,
                socket_path=arguments.socket,
                evidence_dir=arguments.evidence_dir,
                phase=arguments.phase,
            )
            print(f"boundary_phase={boundary['phase']}")
        elif arguments.command == "verify-run-iso":
            binding = verify_run_iso(arguments.state_dir)
            print(f"run_iso_path={binding['canonical_path']}")
        elif arguments.command == "authorize-execution":
            attestation = invoke_root_execution_authorization(
                arguments.state_dir,
                request_path=(
                    arguments.state_dir / "authorization-request.json"
                ),
                observed_at=arguments.observed_at,
                pending_boundary=arguments.pending_boundary,
                before_authorization_boundary=(
                    arguments.before_authorization_boundary
                ),
                cli=cli,
                status_loader=status_loader,
                revision_loader=revision_loader,
                euid=euid,
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
        elif arguments.command == "record-workdir-ownership":
            _write_new(
                arguments.record,
                _json_bytes(workdir_ownership(arguments.workdir)),
                mode=0o600,
            )
            print("workdir_ownership=recorded")
        elif arguments.command == "remove-owned-workdir":
            remove_owned_workdir(
                _read_json(arguments.record), arguments.workdir
            )
            print("workdir=removed")
        elif arguments.command == "hold-network-namespace":
            hold_network_namespace(arguments.record)
        elif arguments.command == "run-in-network-namespace":
            network_command = list(arguments.network_command)
            if network_command[:1] == ["--"]:
                network_command = network_command[1:]
            run_in_owned_network_namespace(
                _read_json(arguments.record), network_command
            )
        elif arguments.command == "stop-network-namespace":
            stop_owned_network_namespace(_read_json(arguments.record))
            print("network_namespace=stopped")
        elif arguments.command == "stop-owned-process":
            stop_owned_process(
                pid=arguments.pid,
                process_starttime=arguments.process_starttime,
            )
            print("owned_process=stopped")
        elif arguments.command == "export-public-evidence":
            evidence_files: dict[str, Path] = {}
            for item in arguments.evidence:
                if (
                    not isinstance(item, str)
                    or item.count("=") != 1
                ):
                    _fail("Public evidence argument is invalid")
                name, raw_path = item.split("=", 1)
                if name in evidence_files:
                    _fail("Public evidence argument is duplicated")
                evidence_files[name] = Path(raw_path)
            export_public_evidence(
                arguments.state_dir,
                receipt=arguments.receipt,
                output=arguments.output,
                evidence_files=evidence_files,
            )
        elif arguments.command == "verify-public-evidence":
            verify_public_evidence(arguments.evidence_dir)
            print("public_evidence=verified")
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
