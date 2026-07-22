from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from .components import (
    COMPONENT_FILENAMES,
    COMPONENT_NAMES,
    COMPONENT_NAMESPACES,
)
from .errors import BackupError
from .secrets import SecretIdentity
from .systemd import MANAGED_UNITS, UnitState


SCHEMA_VERSION = 1
BACKUP_ID_RE = re.compile(
    r"^backup-\d{8}T\d{6}Z-[0-9a-f]{8}$"
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9_.@:-]{1,255}$")
SAFE_ACCOUNT_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
SAFE_CHECK_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,99}$")
SAFE_SSH_FINGERPRINT_RE = re.compile(
    r"^ssh-public-fingerprint:SHA256:[A-Za-z0-9+/=_-]{1,200}$"
)

_MANIFEST_KEYS = frozenset(
    {
        "schema_version",
        "utility_version",
        "backup_id",
        "created_at",
        "controller",
        "components",
        "systemd_units",
        "secret_identities",
        "preflight",
        "restore_order",
    }
)
_CONTROLLER_KEYS = frozenset(
    {
        "hostname",
        "machine_id",
        "os_id",
        "os_version_id",
        "os_pretty_name",
        "repository_commit",
    }
)
_COMPONENT_KEYS = frozenset(
    {
        "name",
        "filename",
        "namespace",
        "size_bytes",
        "sha256",
        "paths",
        "archive_format",
    }
)
_PATH_KEYS = frozenset(
    {
        "absolute_path",
        "present",
        "uid",
        "gid",
        "owner",
        "group",
        "mode",
        "kind",
    }
)
_UNIT_KEYS = frozenset(
    {
        "name",
        "load_state",
        "enabled_state",
        "active_state",
        "sub_state",
        "failed",
    }
)
_SECRET_KEYS = frozenset(
    {
        "path",
        "kind",
        "uid",
        "gid",
        "owner",
        "group",
        "mode",
        "size",
        "identity",
    }
)
_PREFLIGHT_KEYS = frozenset(
    {
        "active_jobs_empty",
        "transient_units_empty",
        "pending_registration_empty",
        "processor_inactive",
        "secrets_valid",
        "sources_safe",
        "disk_space_sufficient",
    }
)
_VERIFICATION_KEYS = frozenset(
    {
        "schema_version",
        "utility_version",
        "backup_id",
        "completed_at",
        "manifest_sha256",
        "component_hashes",
        "secret_identities",
        "passed_checks",
        "status",
    }
)
_REHEARSAL_KEYS = frozenset(
    {
        "schema_version",
        "utility_version",
        "backup_id",
        "completed_at",
        "manifest_sha256",
        "verification_sha256",
        "secret_identities",
        "passed_checks",
        "status",
    }
)

_SECRET_PATHS = {
    "vault": "/home/altserver/ansible/group_vars/vault.yml",
    "vault_password": "/home/altserver/.ansible-vault-pass",
    "ssh_private_key": "/home/altserver/.ssh/id_ed25519",
}
_SECRET_ORDER = tuple(_SECRET_PATHS)

_ALLOWED_PATH_KINDS = frozenset(
    {"directory", "regular", "symlink", "absent"}
)
_ALLOWED_LOAD_STATES = frozenset({"loaded", "not-found"})
_ALLOWED_ENABLED_STATES = frozenset(
    {
        "enabled",
        "enabled-runtime",
        "disabled",
        "static",
        "indirect",
        "generated",
        "transient",
        "alias",
        "not-found",
    }
)
_ALLOWED_ACTIVE_STATES = frozenset(
    {
        "active",
        "inactive",
        "failed",
        "activating",
        "deactivating",
        "reloading",
        "maintenance",
    }
)


def _invalid(message: str) -> BackupError:
    return BackupError(
        code="backup_manifest_invalid",
        message=message,
        exit_code=4,
    )


def _json_bytes(payload: Mapping[str, object]) -> bytes:
    return (
        json.dumps(
            dict(payload),
            ensure_ascii=False,
            indent=2,
        )
        + "\n"
    ).encode("utf-8")


def _pairs_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key: {key}")
        result[key] = value
    return result


def _decode(raw: bytes) -> dict[str, object]:
    if len(raw) > 16 * 1024 * 1024:
        raise _invalid("Backup JSON exceeds the size limit")
    try:
        text = raw.decode("utf-8")
        payload = json.loads(text, object_pairs_hook=_pairs_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise _invalid("Backup JSON is invalid") from exc
    if not isinstance(payload, dict):
        raise _invalid("Backup JSON must be an object")
    return payload


def _exact_object(
    value: object,
    keys: frozenset[str],
    context: str,
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise _invalid(f"{context} keys are invalid")
    return value


def _string(
    value: object,
    context: str,
    *,
    allow_empty: bool = False,
    maximum: int = 500,
) -> str:
    if not isinstance(value, str):
        raise _invalid(f"{context} must be a string")
    if (not allow_empty and not value) or len(value) > maximum:
        raise _invalid(f"{context} is invalid")
    return value


def _optional_string(
    value: object,
    context: str,
    *,
    maximum: int = 500,
) -> str | None:
    if value is None:
        return None
    return _string(value, context, maximum=maximum)


def _integer(
    value: object,
    context: str,
    *,
    minimum: int = 0,
    maximum: int | None = None,
) -> int:
    if type(value) is not int or value < minimum:
        raise _invalid(f"{context} must be an integer")
    if maximum is not None and value > maximum:
        raise _invalid(f"{context} is outside the allowed range")
    return value


def _boolean(value: object, context: str) -> bool:
    if type(value) is not bool:
        raise _invalid(f"{context} must be boolean")
    return value


def _utc_timestamp(value: object, context: str) -> str:
    text = _string(value, context, maximum=100)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise _invalid(f"{context} is not an ISO timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise _invalid(f"{context} must be UTC")
    return text


def _sha256(value: object, context: str) -> str:
    text = _string(value, context, maximum=64)
    if not SHA256_RE.fullmatch(text):
        raise _invalid(f"{context} is not a SHA-256 value")
    return text


def _version(value: object, context: str) -> str:
    text = _string(value, context, maximum=32)
    if not VERSION_RE.fullmatch(text):
        raise _invalid(f"{context} is invalid")
    return text


def _backup_id(value: object) -> str:
    text = _string(value, "backup_id", maximum=64)
    if not BACKUP_ID_RE.fullmatch(text):
        raise _invalid("Backup identifier is invalid")
    return text


def _absolute_path(value: object, context: str) -> str:
    text = _string(value, context, maximum=4096)
    path = Path(text)
    if not path.is_absolute() or ".." in path.parts:
        raise _invalid(f"{context} is not a safe absolute path")
    return text


def _safe_account(value: object, context: str) -> str:
    text = _string(value, context, maximum=64)
    if not SAFE_ACCOUNT_RE.fullmatch(text):
        raise _invalid(f"{context} is invalid")
    return text


def _safe_checks(value: object, context: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise _invalid(f"{context} must be a non-empty list")
    checks: list[str] = []
    for item in value:
        check = _string(item, context, maximum=100)
        if not SAFE_CHECK_RE.fullmatch(check):
            raise _invalid(f"{context} contains an invalid check")
        checks.append(check)
    if len(checks) > 100 or len(set(checks)) != len(checks):
        raise _invalid(f"{context} contains duplicates or too many values")
    return tuple(checks)


@dataclass(frozen=True)
class PathRecord:
    absolute_path: str
    present: bool
    uid: int | None
    gid: int | None
    owner: str | None
    group: str | None
    mode: int | None
    kind: str

    def to_dict(self) -> dict[str, object]:
        return {
            "absolute_path": self.absolute_path,
            "present": self.present,
            "uid": self.uid,
            "gid": self.gid,
            "owner": self.owner,
            "group": self.group,
            "mode": self.mode,
            "kind": self.kind,
        }


@dataclass(frozen=True)
class ComponentRecord:
    name: str
    filename: str
    namespace: str
    size_bytes: int
    sha256: str
    paths: tuple[PathRecord, ...]
    archive_format: str

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "filename": self.filename,
            "namespace": self.namespace,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "paths": [path.to_dict() for path in self.paths],
            "archive_format": self.archive_format,
        }


@dataclass(frozen=True)
class ControllerRecord:
    hostname: str
    machine_id: str | None
    os_id: str
    os_version_id: str
    os_pretty_name: str
    repository_commit: str | None

    def to_dict(self) -> dict[str, object]:
        return {
            "hostname": self.hostname,
            "machine_id": self.machine_id,
            "os_id": self.os_id,
            "os_version_id": self.os_version_id,
            "os_pretty_name": self.os_pretty_name,
            "repository_commit": self.repository_commit,
        }


@dataclass(frozen=True)
class PreflightRecord:
    active_jobs_empty: bool
    transient_units_empty: bool
    pending_registration_empty: bool
    processor_inactive: bool
    secrets_valid: bool
    sources_safe: bool
    disk_space_sufficient: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "active_jobs_empty": self.active_jobs_empty,
            "transient_units_empty": self.transient_units_empty,
            "pending_registration_empty": self.pending_registration_empty,
            "processor_inactive": self.processor_inactive,
            "secrets_valid": self.secrets_valid,
            "sources_safe": self.sources_safe,
            "disk_space_sufficient": self.disk_space_sufficient,
        }


@dataclass(frozen=True)
class BackupManifest:
    schema_version: int
    utility_version: str
    backup_id: str
    created_at: str
    controller: ControllerRecord
    components: tuple[ComponentRecord, ...]
    systemd_units: tuple[UnitState, ...]
    secret_identities: tuple[SecretIdentity, ...]
    preflight: PreflightRecord
    restore_order: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "utility_version": self.utility_version,
            "backup_id": self.backup_id,
            "created_at": self.created_at,
            "controller": self.controller.to_dict(),
            "components": [item.to_dict() for item in self.components],
            "systemd_units": [
                _unit_to_dict(item) for item in self.systemd_units
            ],
            "secret_identities": [
                _secret_to_dict(item)
                for item in self.secret_identities
            ],
            "preflight": self.preflight.to_dict(),
            "restore_order": list(self.restore_order),
        }

    def to_bytes(self) -> bytes:
        return _json_bytes(self.to_dict())


@dataclass(frozen=True)
class VerificationEvidence:
    schema_version: int
    utility_version: str
    backup_id: str
    completed_at: str
    manifest_sha256: str
    component_hashes: dict[str, str]
    secret_identities: tuple[SecretIdentity, ...]
    passed_checks: tuple[str, ...]
    status: str

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "utility_version": self.utility_version,
            "backup_id": self.backup_id,
            "completed_at": self.completed_at,
            "manifest_sha256": self.manifest_sha256,
            "component_hashes": dict(self.component_hashes),
            "secret_identities": [
                _secret_to_dict(item)
                for item in self.secret_identities
            ],
            "passed_checks": list(self.passed_checks),
            "status": self.status,
        }

    def to_bytes(self) -> bytes:
        return _json_bytes(self.to_dict())


@dataclass(frozen=True)
class RehearsalEvidence:
    schema_version: int
    utility_version: str
    backup_id: str
    completed_at: str
    manifest_sha256: str
    verification_sha256: str
    secret_identities: tuple[SecretIdentity, ...]
    passed_checks: tuple[str, ...]
    status: str

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "utility_version": self.utility_version,
            "backup_id": self.backup_id,
            "completed_at": self.completed_at,
            "manifest_sha256": self.manifest_sha256,
            "verification_sha256": self.verification_sha256,
            "secret_identities": [
                _secret_to_dict(item)
                for item in self.secret_identities
            ],
            "passed_checks": list(self.passed_checks),
            "status": self.status,
        }

    def to_bytes(self) -> bytes:
        return _json_bytes(self.to_dict())


def _unit_to_dict(unit: UnitState) -> dict[str, object]:
    return {
        "name": unit.name,
        "load_state": unit.load_state,
        "enabled_state": unit.enabled_state,
        "active_state": unit.active_state,
        "sub_state": unit.sub_state,
        "failed": unit.failed,
    }


def _secret_to_dict(secret: SecretIdentity) -> dict[str, object]:
    return {
        "path": secret.path,
        "kind": secret.kind,
        "uid": secret.uid,
        "gid": secret.gid,
        "owner": secret.owner,
        "group": secret.group,
        "mode": secret.mode,
        "size": secret.size,
        "identity": secret.identity,
    }


def _parse_path(value: object) -> PathRecord:
    payload = _exact_object(value, _PATH_KEYS, "component path")
    absolute_path = _absolute_path(
        payload["absolute_path"],
        "component absolute_path",
    )
    present = _boolean(payload["present"], "component present")
    kind = _string(payload["kind"], "component kind", maximum=32)
    if kind not in _ALLOWED_PATH_KINDS:
        raise _invalid("Component path kind is invalid")

    if present:
        if kind == "absent":
            raise _invalid("Present component path cannot be absent")
        uid = _integer(payload["uid"], "component uid")
        gid = _integer(payload["gid"], "component gid")
        owner = _safe_account(payload["owner"], "component owner")
        group = _safe_account(payload["group"], "component group")
        mode = _integer(
            payload["mode"],
            "component mode",
            maximum=0o7777,
        )
    else:
        if kind != "absent" or any(
            payload[key] is not None
            for key in ("uid", "gid", "owner", "group", "mode")
        ):
            raise _invalid("Absent component path metadata is invalid")
        uid = None
        gid = None
        owner = None
        group = None
        mode = None

    return PathRecord(
        absolute_path=absolute_path,
        present=present,
        uid=uid,
        gid=gid,
        owner=owner,
        group=group,
        mode=mode,
        kind=kind,
    )


def _parse_component(
    value: object,
    index: int,
) -> ComponentRecord:
    payload = _exact_object(value, _COMPONENT_KEYS, "component")
    expected_name = COMPONENT_NAMES[index]
    expected_filename = COMPONENT_FILENAMES[index]
    expected_namespace = COMPONENT_NAMESPACES[index]
    name = _string(payload["name"], "component name", maximum=64)
    filename = _string(
        payload["filename"],
        "component filename",
        maximum=128,
    )
    namespace = _string(
        payload["namespace"],
        "component namespace",
        maximum=128,
    )
    if (
        name != expected_name
        or filename != expected_filename
        or namespace != expected_namespace
    ):
        raise _invalid("Component identity or order is invalid")
    size_bytes = _integer(payload["size_bytes"], "component size")
    digest = _sha256(payload["sha256"], "component sha256")
    if payload["archive_format"] != "tar.zst":
        raise _invalid("Component archive format is invalid")
    raw_paths = payload["paths"]
    if not isinstance(raw_paths, list) or not raw_paths:
        raise _invalid("Component paths are invalid")
    paths = tuple(_parse_path(item) for item in raw_paths)
    absolute_paths = [path.absolute_path for path in paths]
    if len(set(absolute_paths)) != len(absolute_paths):
        raise _invalid("Component paths contain duplicates")
    return ComponentRecord(
        name=name,
        filename=filename,
        namespace=namespace,
        size_bytes=size_bytes,
        sha256=digest,
        paths=paths,
        archive_format="tar.zst",
    )


def _parse_controller(value: object) -> ControllerRecord:
    payload = _exact_object(value, _CONTROLLER_KEYS, "controller")
    hostname = _string(payload["hostname"], "controller hostname", maximum=253)
    if not SAFE_NAME_RE.fullmatch(hostname):
        raise _invalid("Controller hostname is invalid")
    machine_id = _optional_string(
        payload["machine_id"],
        "controller machine_id",
        maximum=256,
    )
    os_id = _string(payload["os_id"], "controller os_id", maximum=100)
    os_version_id = _string(
        payload["os_version_id"],
        "controller os_version_id",
        maximum=100,
    )
    os_pretty_name = _string(
        payload["os_pretty_name"],
        "controller os_pretty_name",
        maximum=500,
    )
    repository_commit = _optional_string(
        payload["repository_commit"],
        "controller repository_commit",
        maximum=256,
    )
    return ControllerRecord(
        hostname=hostname,
        machine_id=machine_id,
        os_id=os_id,
        os_version_id=os_version_id,
        os_pretty_name=os_pretty_name,
        repository_commit=repository_commit,
    )


def _parse_unit(value: object, index: int) -> UnitState:
    payload = _exact_object(value, _UNIT_KEYS, "systemd unit")
    name = _string(payload["name"], "systemd unit name", maximum=200)
    if name != MANAGED_UNITS[index]:
        raise _invalid("Systemd unit order is invalid")
    load_state = _string(payload["load_state"], "systemd load state", maximum=32)
    enabled_state = _string(
        payload["enabled_state"],
        "systemd enabled state",
        maximum=32,
    )
    active_state = _string(
        payload["active_state"],
        "systemd active state",
        maximum=32,
    )
    sub_state = _string(payload["sub_state"], "systemd sub state", maximum=100)
    failed = _boolean(payload["failed"], "systemd failed")
    if (
        load_state not in _ALLOWED_LOAD_STATES
        or enabled_state not in _ALLOWED_ENABLED_STATES
        or active_state not in _ALLOWED_ACTIVE_STATES
        or not SAFE_NAME_RE.fullmatch(sub_state)
        or failed != (active_state == "failed")
    ):
        raise _invalid("Systemd unit values are invalid")
    if load_state == "not-found" and enabled_state != "not-found":
        raise _invalid("Missing systemd unit enablement is invalid")
    return UnitState(
        name=name,
        load_state=load_state,
        enabled_state=enabled_state,
        active_state=active_state,
        sub_state=sub_state,
        failed=failed,
    )


def _parse_secret(value: object, index: int) -> SecretIdentity:
    payload = _exact_object(value, _SECRET_KEYS, "secret identity")
    kind = _string(payload["kind"], "secret kind", maximum=64)
    if kind != _SECRET_ORDER[index]:
        raise _invalid("Secret identity order is invalid")
    path = _absolute_path(payload["path"], "secret path")
    if path != _SECRET_PATHS[kind]:
        raise _invalid("Secret identity path is invalid")
    uid = _integer(payload["uid"], "secret uid")
    gid = _integer(payload["gid"], "secret gid")
    owner = _safe_account(payload["owner"], "secret owner")
    group = _safe_account(payload["group"], "secret group")
    mode = _integer(payload["mode"], "secret mode", maximum=0o7777)
    size = _integer(payload["size"], "secret size")
    identity = _string(payload["identity"], "secret identity", maximum=500)
    if kind == "vault" and not re.fullmatch(
        r"sha256:[0-9a-f]{64}", identity
    ):
        raise _invalid("Vault identity is invalid")
    if kind == "vault_password" and not re.fullmatch(
        r"hmac-sha256:[0-9a-f]{64}", identity
    ):
        raise _invalid("Vault password identity is invalid")
    if kind == "ssh_private_key" and not SAFE_SSH_FINGERPRINT_RE.fullmatch(identity):
        raise _invalid("SSH identity is invalid")
    return SecretIdentity(
        path=path,
        kind=kind,
        uid=uid,
        gid=gid,
        owner=owner,
        group=group,
        mode=mode,
        size=size,
        identity=identity,
    )


def _parse_secrets(value: object) -> tuple[SecretIdentity, ...]:
    if not isinstance(value, list) or len(value) != len(_SECRET_ORDER):
        raise _invalid("Secret identity set is invalid")
    return tuple(_parse_secret(item, index) for index, item in enumerate(value))


def _parse_preflight(value: object) -> PreflightRecord:
    payload = _exact_object(value, _PREFLIGHT_KEYS, "preflight")
    values = {
        key: _boolean(payload[key], f"preflight {key}")
        for key in _PREFLIGHT_KEYS
    }
    if not all(values.values()):
        raise _invalid("Published manifest preflight is not successful")
    return PreflightRecord(
        active_jobs_empty=values["active_jobs_empty"],
        transient_units_empty=values["transient_units_empty"],
        pending_registration_empty=values["pending_registration_empty"],
        processor_inactive=values["processor_inactive"],
        secrets_valid=values["secrets_valid"],
        sources_safe=values["sources_safe"],
        disk_space_sufficient=values["disk_space_sufficient"],
    )


def parse_manifest(raw: bytes) -> BackupManifest:
    payload = _exact_object(_decode(raw), _MANIFEST_KEYS, "manifest")
    schema_version = _integer(
        payload["schema_version"],
        "schema_version",
        minimum=1,
    )
    if schema_version != SCHEMA_VERSION:
        raise _invalid("Manifest schema version is unsupported")
    utility_version = _version(payload["utility_version"], "utility_version")
    backup_id = _backup_id(payload["backup_id"])
    created_at = _utc_timestamp(payload["created_at"], "created_at")
    controller = _parse_controller(payload["controller"])

    raw_components = payload["components"]
    if not isinstance(raw_components, list) or len(raw_components) != len(COMPONENT_NAMES):
        raise _invalid("Manifest component count is invalid")
    components = tuple(
        _parse_component(item, index)
        for index, item in enumerate(raw_components)
    )

    raw_units = payload["systemd_units"]
    if not isinstance(raw_units, list) or len(raw_units) != len(MANAGED_UNITS):
        raise _invalid("Manifest systemd unit count is invalid")
    units = tuple(
        _parse_unit(item, index)
        for index, item in enumerate(raw_units)
    )
    secrets = _parse_secrets(payload["secret_identities"])
    preflight = _parse_preflight(payload["preflight"])

    restore_order_raw = payload["restore_order"]
    if not isinstance(restore_order_raw, list) or tuple(restore_order_raw) != COMPONENT_NAMES:
        raise _invalid("Manifest restore order is invalid")

    return BackupManifest(
        schema_version=schema_version,
        utility_version=utility_version,
        backup_id=backup_id,
        created_at=created_at,
        controller=controller,
        components=components,
        systemd_units=units,
        secret_identities=secrets,
        preflight=preflight,
        restore_order=COMPONENT_NAMES,
    )


def _component_hashes(value: object) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != set(COMPONENT_FILENAMES):
        raise _invalid("Evidence component hash set is invalid")
    return {
        filename: _sha256(value[filename], f"component hash {filename}")
        for filename in COMPONENT_FILENAMES
    }


def parse_verification_evidence(raw: bytes) -> VerificationEvidence:
    payload = _exact_object(
        _decode(raw),
        _VERIFICATION_KEYS,
        "verification evidence",
    )
    schema_version = _integer(
        payload["schema_version"],
        "verification schema_version",
        minimum=1,
    )
    if schema_version != SCHEMA_VERSION:
        raise _invalid("Verification schema version is unsupported")
    status = _string(payload["status"], "verification status", maximum=16)
    if status != "ok":
        raise _invalid("Verification status is invalid")
    return VerificationEvidence(
        schema_version=schema_version,
        utility_version=_version(
            payload["utility_version"],
            "verification utility_version",
        ),
        backup_id=_backup_id(payload["backup_id"]),
        completed_at=_utc_timestamp(
            payload["completed_at"],
            "verification completed_at",
        ),
        manifest_sha256=_sha256(
            payload["manifest_sha256"],
            "verification manifest_sha256",
        ),
        component_hashes=_component_hashes(payload["component_hashes"]),
        secret_identities=_parse_secrets(payload["secret_identities"]),
        passed_checks=_safe_checks(
            payload["passed_checks"],
            "verification passed_checks",
        ),
        status=status,
    )


def parse_rehearsal_evidence(raw: bytes) -> RehearsalEvidence:
    payload = _exact_object(
        _decode(raw),
        _REHEARSAL_KEYS,
        "rehearsal evidence",
    )
    schema_version = _integer(
        payload["schema_version"],
        "rehearsal schema_version",
        minimum=1,
    )
    if schema_version != SCHEMA_VERSION:
        raise _invalid("Rehearsal schema version is unsupported")
    status = _string(payload["status"], "rehearsal status", maximum=16)
    if status != "ok":
        raise _invalid("Rehearsal status is invalid")
    return RehearsalEvidence(
        schema_version=schema_version,
        utility_version=_version(
            payload["utility_version"],
            "rehearsal utility_version",
        ),
        backup_id=_backup_id(payload["backup_id"]),
        completed_at=_utc_timestamp(
            payload["completed_at"],
            "rehearsal completed_at",
        ),
        manifest_sha256=_sha256(
            payload["manifest_sha256"],
            "rehearsal manifest_sha256",
        ),
        verification_sha256=_sha256(
            payload["verification_sha256"],
            "rehearsal verification_sha256",
        ),
        secret_identities=_parse_secrets(payload["secret_identities"]),
        passed_checks=_safe_checks(
            payload["passed_checks"],
            "rehearsal passed_checks",
        ),
        status=status,
    )
