from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import os
import re
import stat
import tarfile
from collections.abc import Callable, Mapping
from contextlib import nullcontext
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any

from .config import Settings
from .errors import ControlError
from .install_execution_manifest import (
    ExecutionManifestV1,
    build_execution_manifest,
    canonical_execution_manifest_bytes,
    canonical_execution_signature_bytes,
    parse_execution_manifest_bytes,
    parse_execution_signature_bytes,
    sign_execution_manifest,
    verify_execution_manifest_signature,
)
from .install_policy import load_profile
from .install_renderer import (
    RendererSecrets,
    RenderError,
    parse_execution_plan_bytes,
    render_install_bundle,
)
from .install_session_repository import InstallSessionRepository
from .install_session_state import validate_execution_status
from .install_session_signing import (
    load_private_signer,
    load_public_verifier,
    public_key_metadata,
    verify_plan_signature,
)
from .vault import VaultHealthChecker, extract_execution_password_hashes


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_DEVICE_RE = re.compile(r"^/dev/[A-Za-z0-9._+-]{1,63}$")
_ARCHIVE_MEMBER_RE = re.compile(
    r"^(?!/)(?!.*(?:^|/)\.\.(?:/|$))[A-Za-z0-9._+@/-]{1,256}/?$"
)
_RELEASE_ARCHIVE_NAMES = ("pkg-groups.tar", "install-scripts.tar")
_RELEASE_MANIFEST_NAME = "manifest.json"
_MAX_RELEASE_MANIFEST_BYTES = 64 * 1024
_MAX_RELEASE_ARCHIVE_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True)
class ReleaseArchiveSource:
    path: Path
    sha256: str
    members: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            not isinstance(self.path, Path)
            or not isinstance(self.sha256, str)
            or not _SHA256_RE.fullmatch(self.sha256)
            or not isinstance(self.members, tuple)
            or not self.members
            or len(set(self.members)) != len(self.members)
            or any(
                not isinstance(name, str)
                or not _ARCHIVE_MEMBER_RE.fullmatch(name)
                for name in self.members
            )
        ):
            raise ValueError("Execution release archive identity is invalid")


def _release_invalid() -> ControlError:
    return ControlError(
        "execution_release_invalid",
        "Execution release manifest is invalid",
        4,
    )


def canonical_execution_release_manifest_bytes(
    sources: Mapping[str, ReleaseArchiveSource],
) -> bytes:
    if (
        not isinstance(sources, Mapping)
        or set(sources) != set(_RELEASE_ARCHIVE_NAMES)
        or any(
            not isinstance(sources[name], ReleaseArchiveSource)
            or sources[name].path.name != name
            for name in _RELEASE_ARCHIVE_NAMES
        )
    ):
        raise _release_invalid()
    return (
        json.dumps(
            {
                "archives": {
                    name: {
                        "members": list(sources[name].members),
                        "sha256": sources[name].sha256,
                    }
                    for name in _RELEASE_ARCHIVE_NAMES
                },
                "schema_version": 1,
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )


def _held_release_file(
    path: Path,
    *,
    maximum_size: int,
    capture: bool,
) -> tuple[bytes, str]:
    try:
        before = path.lstat()
    except OSError as exc:
        raise _release_invalid() from exc
    if not stat.S_ISREG(before.st_mode):
        raise _release_invalid()
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise _release_invalid() from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino
            or not 1 <= opened.st_size <= maximum_size
        ):
            raise _release_invalid()
        if os.name != "nt" and (
            opened.st_uid != 0
            or opened.st_gid != 0
            or stat.S_IMODE(opened.st_mode) != 0o444
        ):
            raise _release_invalid()
        digest = hashlib.sha256()
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > maximum_size:
                raise _release_invalid()
            digest.update(chunk)
            if capture:
                chunks.append(chunk)
        if size != opened.st_size:
            raise _release_invalid()
        return b"".join(chunks), digest.hexdigest()
    finally:
        os.close(descriptor)


def load_execution_release_archives(
    settings: Settings,
) -> dict[str, ReleaseArchiveSource]:
    root = settings.install_execution_release_root
    try:
        metadata = root.lstat()
    except OSError as exc:
        raise _release_invalid() from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise _release_invalid()
    if os.name != "nt" and (
        metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o755
    ):
        raise _release_invalid()
    raw, _manifest_digest = _held_release_file(
        root / _RELEASE_MANIFEST_NAME,
        maximum_size=_MAX_RELEASE_MANIFEST_BYTES,
        capture=True,
    )

    def strict_object(
        pairs: list[tuple[str, object]],
    ) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError
            result[key] = value
        return result

    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=strict_object,
        )
        if (
            not isinstance(document, dict)
            or set(document) != {"schema_version", "archives"}
            or document.get("schema_version") != 1
            or type(document.get("schema_version")) is not int
            or not isinstance(document.get("archives"), dict)
            or set(document["archives"]) != set(_RELEASE_ARCHIVE_NAMES)
        ):
            raise ValueError
        sources: dict[str, ReleaseArchiveSource] = {}
        for name in _RELEASE_ARCHIVE_NAMES:
            entry = document["archives"][name]
            if (
                not isinstance(entry, dict)
                or set(entry) != {"sha256", "members"}
                or not isinstance(entry.get("sha256"), str)
                or not _SHA256_RE.fullmatch(entry["sha256"])
                or not isinstance(entry.get("members"), list)
                or not entry["members"]
                or len(set(entry["members"])) != len(entry["members"])
                or any(
                    not isinstance(member, str)
                    or not _ARCHIVE_MEMBER_RE.fullmatch(member)
                    for member in entry["members"]
                )
            ):
                raise ValueError
            path = root / name
            _content, actual_sha256 = _held_release_file(
                path,
                maximum_size=_MAX_RELEASE_ARCHIVE_BYTES,
                capture=False,
            )
            if actual_sha256 != entry["sha256"]:
                raise ValueError
            sources[name] = ReleaseArchiveSource(
                path=path,
                sha256=entry["sha256"],
                members=tuple(entry["members"]),
            )
        if canonical_execution_release_manifest_bytes(sources) != raw:
            raise ValueError
        return sources
    except (KeyError, TypeError, UnicodeDecodeError, ValueError):
        raise _release_invalid() from None


@dataclass(frozen=True)
class ExecutionAuthorizationResult:
    manifest: ExecutionManifestV1
    status: MappingProxyType[str, object]


class ExecutionAuthorizationService:
    """Root-only, single-use authorization for the future V2 handoff.

    This class deliberately creates no installer artifact and executes no
    command.  It records the narrow authorization prerequisite that later
    bundle publication and agent handoff consume.
    """

    def __init__(
        self,
        settings: Settings,
        *,
        repository: InstallSessionRepository | None = None,
        clock: Callable[[], str],
        euid: Callable[[], int] = lambda: getattr(os, "geteuid", lambda: 0)(),
        release_archives: dict[str, ReleaseArchiveSource] | None = None,
        secrets_provider: Callable[[], RendererSecrets] | None = None,
    ) -> None:
        self.settings = settings
        self.repository = repository or InstallSessionRepository(settings)
        self.clock = clock
        self.euid = euid
        self.release_archives = (
            dict(release_archives) if release_archives is not None else None
        )
        self.secrets_provider = secrets_provider or self._vault_secrets

    @staticmethod
    def _error(code: str, message: str) -> ControlError:
        return ControlError(code, message, 4)

    def _now(self) -> datetime:
        try:
            value = datetime.fromisoformat(self.clock())
        except ValueError as exc:
            raise self._error("execution_clock_invalid", "Execution clock is invalid") from exc
        if value.tzinfo is None:
            raise self._error("execution_clock_invalid", "Execution clock is invalid")
        return value.astimezone(timezone.utc)

    def _vault_secrets(self) -> RendererSecrets:
        decrypted = VaultHealthChecker(self.settings)._decrypt()
        if decrypted is None:
            raise ValueError("execution password material is unavailable")
        values = extract_execution_password_hashes(decrypted)
        return RendererSecrets(**values)

    @staticmethod
    def _bounded_text(value: object, *, code: str, description: str) -> str:
        if (
            not isinstance(value, str)
            or not 1 <= len(value.strip()) <= 256
            or "$y$" in value
        ):
            raise ExecutionAuthorizationService._error(code, description)
        return value.strip()

    @staticmethod
    def _timestamp(value: object) -> datetime:
        if not isinstance(value, str):
            raise ExecutionAuthorizationService._error(
                "execution_plan_invalid",
                "Published execution plan is invalid",
            )
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError as exc:
            raise ExecutionAuthorizationService._error(
                "execution_plan_invalid",
                "Published execution plan is invalid",
            ) from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ExecutionAuthorizationService._error(
                "execution_plan_invalid",
                "Published execution plan is invalid",
            )
        return parsed.astimezone(timezone.utc)

    def _verify_published_plan_signature(
        self,
        session_id: str,
        raw: bytes,
        expected_sha256: str,
        expected_created_at: str,
    ) -> None:
        try:
            signature_raw = self.repository.read_revision_file(
                session_id, "plan-signature.json"
            )
            if not 1 <= len(signature_raw) <= 16 * 1024:
                raise ValueError

            def strict_object(
                pairs: list[tuple[str, object]],
            ) -> dict[str, object]:
                result: dict[str, object] = {}
                for name, value in pairs:
                    if name in result:
                        raise ValueError
                    result[name] = value
                return result

            signature = json.loads(
                signature_raw.decode("utf-8"),
                object_pairs_hook=strict_object,
            )
            if not isinstance(signature, dict) or set(signature) != {
                "schema_version",
                "algorithm",
                "key_id",
                "signed_file",
                "plan_sha256",
                "signature_b64",
                "created_at",
            }:
                raise ValueError
            encoded = signature["signature_b64"]
            if not isinstance(encoded, str):
                raise ValueError
            raw_signature = base64.b64decode(encoded, validate=True)
            created_at = signature["created_at"]
            if (
                not isinstance(created_at, str)
                or created_at != expected_created_at
                or self._timestamp(created_at).isoformat() != created_at
                or len(raw_signature) != 64
                or base64.b64encode(raw_signature).decode("ascii")
                != encoded
                or signature_raw
                != (
                    json.dumps(
                        signature,
                        ensure_ascii=True,
                        sort_keys=True,
                    )
                    + "\n"
                ).encode("utf-8")
            ):
                raise ValueError
            verifier = load_public_verifier(
                self.settings.install_signing_public_key
            )
            if (
                type(signature["schema_version"]) is not int
                or signature["schema_version"] != 1
                or signature["algorithm"] != "ed25519"
                or signature["signed_file"] != "plan.json"
                or signature["plan_sha256"] != expected_sha256
                or not verify_plan_signature(
                    verifier,
                    raw,
                    raw_signature,
                    signature["key_id"],
                )
            ):
                raise ValueError
        except (
            ControlError,
            KeyError,
            TypeError,
            UnicodeDecodeError,
            ValueError,
            json.JSONDecodeError,
        ):
            raise self._error(
                "execution_plan_signature_invalid",
                "Published execution plan signature is invalid",
            ) from None

    def _load_bound_plan(
        self,
        session_id: str,
        *,
        plan_sha256: object,
        inventory_sha256: object,
        disk_fingerprint_value: object,
        confirm_target: object,
        now: datetime,
    ) -> tuple[Any, datetime]:
        if not isinstance(plan_sha256, str) or not _SHA256_RE.fullmatch(plan_sha256):
            raise self._error("execution_plan_sha256_invalid", "Execution plan SHA-256 is invalid")
        if not isinstance(inventory_sha256, str) or not _SHA256_RE.fullmatch(inventory_sha256):
            raise self._error("execution_inventory_sha256_invalid", "Execution inventory SHA-256 is invalid")
        if not isinstance(disk_fingerprint_value, str) or not disk_fingerprint_value.startswith("sha256:") or not _SHA256_RE.fullmatch(disk_fingerprint_value[7:]):
            raise self._error("execution_disk_fingerprint_invalid", "Execution disk fingerprint is invalid")
        if not isinstance(confirm_target, str) or not _DEVICE_RE.fullmatch(confirm_target):
            raise self._error("execution_target_invalid", "Execution target acknowledgement is invalid")
        try:
            raw = self.repository.read_revision_file(session_id, "plan.json")
            plan = parse_execution_plan_bytes(raw)
        except (ControlError, RenderError) as exc:
            raise self._error("execution_plan_invalid", "Published execution plan is invalid") from exc
        if hashlib.sha256(raw).hexdigest() != plan_sha256:
            raise self._error("execution_plan_mismatch", "Execution plan digest differs")
        if plan.session_id != session_id:
            raise self._error(
                "execution_plan_mismatch", "Execution plan identity differs"
            )
        self._verify_published_plan_signature(
            session_id, raw, plan_sha256, plan.approved_at
        )
        target = plan.target_disk
        if (
            plan.inventory_sha256 != inventory_sha256
            or target.get("fingerprint") != disk_fingerprint_value
            or target.get("path") != confirm_target
        ):
            raise self._error("execution_plan_mismatch", "Execution authorization differs from plan")
        expiry = self._timestamp(plan.expires_at)
        if expiry <= now:
            raise self._error("execution_plan_expired", "Published execution plan is expired")
        try:
            profile = load_profile(
                self.settings.install_profile_root,
                plan.profile_id,
                plan.profile_version,
            )
        except ValueError:
            raise self._error(
                "execution_profile_invalid",
                "Execution release profile is invalid",
            ) from None
        if (
            plan.iso_id != profile.iso_id
            or plan.iso_sha256 != profile.iso_sha256
            or plan.firmware != profile.firmware
            or plan.package_set != profile.package_set
            or plan.disk_layout["wipe_mode"] != profile.wipe_mode
            or plan.disk_layout["swap_mib"] != profile.swap_mib
            or plan.disk_layout["filesystem"] != profile.filesystem
            or plan.disk_layout["btrfs_minimum_mib"]
            != profile.btrfs_minimum_mib
            or plan.disk_layout["grow"] != profile.grow
            or dict(plan.disk_layout["subvolumes"])
            != dict(profile.subvolumes)
        ):
            raise self._error(
                "execution_profile_mismatch",
                "Execution plan differs from its release profile",
            )
        return plan, expiry

    def _validate_preflight(
        self,
        status: dict[str, object],
        *,
        plan_approved_at: str,
        now: datetime,
    ) -> None:
        agent_status = status.get("agent_status")
        if not isinstance(agent_status, dict) or set(agent_status) != {
            "schema_version",
            "boot_id",
            "agent_version",
            "sequence",
            "reported_stage",
            "sent_at",
        }:
            raise self._error(
                "execution_preflight_required",
                "Execution requires current preflight",
            )
        sent_at = self._timestamp(agent_status.get("sent_at"))
        if (
            agent_status.get("schema_version") != 1
            or agent_status.get("reported_stage") != "preflight_ready"
            or agent_status.get("boot_id") != status.get("agent_boot_id")
            or type(agent_status.get("sequence")) is not int
            or agent_status["sequence"] < 0
            or sent_at < self._timestamp(plan_approved_at)
            or sent_at > now
            or now - sent_at > timedelta(minutes=5)
        ):
            raise self._error(
                "execution_preflight_stale",
                "Execution preflight is stale",
            )

    @staticmethod
    def _read_release_archive(source: ReleaseArchiveSource) -> bytes:
        try:
            inspected = source.path.lstat()
        except OSError:
            raise ExecutionAuthorizationService._error(
                "execution_archive_invalid",
                "Execution release archive is invalid",
            ) from None
        if not stat.S_ISREG(inspected.st_mode):
            raise ExecutionAuthorizationService._error(
                "execution_archive_invalid",
                "Execution release archive is invalid",
            )
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(source.path, flags)
        except OSError:
            raise ExecutionAuthorizationService._error(
                "execution_archive_invalid",
                "Execution release archive is invalid",
            ) from None
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or (
                    hasattr(inspected, "st_ino")
                    and (
                        inspected.st_ino != metadata.st_ino
                        or inspected.st_dev != metadata.st_dev
                    )
                )
                or not 1024 <= metadata.st_size <= 64 * 1024 * 1024
            ):
                raise ExecutionAuthorizationService._error(
                    "execution_archive_invalid",
                    "Execution release archive is invalid",
                )
            chunks: list[bytes] = []
            while True:
                chunk = os.read(descriptor, 64 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
        finally:
            os.close(descriptor)
        content = b"".join(chunks)
        if (
            len(content) % 512 != 0
            or content[-1024:] != b"\0" * 1024
            or not hmac.compare_digest(
                hashlib.sha256(content).hexdigest(), source.sha256
            )
        ):
            raise ExecutionAuthorizationService._error(
                "execution_archive_invalid",
                "Execution release archive is invalid",
            )
        try:
            with tarfile.open(fileobj=io.BytesIO(content), mode="r:") as archive:
                members = archive.getmembers()
        except (tarfile.TarError, EOFError, OSError):
            raise ExecutionAuthorizationService._error(
                "execution_archive_invalid",
                "Execution release archive is invalid",
            ) from None
        if (
            tuple(member.name for member in members) != source.members
            or any(not (member.isfile() or member.isdir()) for member in members)
        ):
            raise ExecutionAuthorizationService._error(
                "execution_archive_invalid",
                "Execution release archive is invalid",
            )
        return content

    def _bundle_artifacts(self, plan: Any) -> dict[str, bytes]:
        if (
            self.release_archives is None
            or set(self.release_archives)
            != {"pkg-groups.tar", "install-scripts.tar"}
            or any(
                not isinstance(source, ReleaseArchiveSource)
                for source in self.release_archives.values()
            )
        ):
            raise self._error(
                "execution_inputs_unavailable",
                "Execution release inputs are unavailable",
            )
        try:
            secrets = self.secrets_provider()
            if (
                not isinstance(secrets, RendererSecrets)
                or secrets.root_yescrypt_hash == secrets.admin_yescrypt_hash
            ):
                raise ValueError
        except Exception:
            raise self._error(
                "execution_secrets_invalid",
                "Execution password material is invalid",
            ) from None
        try:
            rendered = render_install_bundle(
                plan,
                secrets,
                self.settings.install_profile_root.parent / "templates",
            )
        except RenderError:
            raise self._error(
                "execution_render_failed",
                "Execution artifacts cannot be rendered",
            ) from None
        return {
            "autoinstall.scm": rendered.files["autoinstall.scm"],
            "vm-profile.scm": rendered.files["vm-profile.scm"],
            "pkg-groups.tar": self._read_release_archive(
                self.release_archives["pkg-groups.tar"]
            ),
            "install-scripts.tar": self._read_release_archive(
                self.release_archives["install-scripts.tar"]
            ),
        }

    def _verify_signed_execution_files(
        self,
        files: Mapping[str, bytes],
    ) -> ExecutionManifestV1:
        if set(files) != {
            "execution-manifest.json",
            "execution-manifest-signature.json",
            "autoinstall.scm",
            "vm-profile.scm",
            "pkg-groups.tar",
            "install-scripts.tar",
        }:
            raise ValueError("Execution bundle file set is invalid")
        manifest_bytes = files["execution-manifest.json"]
        signature_bytes = files["execution-manifest-signature.json"]
        manifest = parse_execution_manifest_bytes(manifest_bytes)
        signature = parse_execution_signature_bytes(signature_bytes)
        verifier = load_public_verifier(
            self.settings.install_signing_public_key
        )
        if not verify_execution_manifest_signature(
            verifier, manifest_bytes, signature
        ):
            raise ValueError("Execution bundle signature is invalid")
        for name, metadata in manifest.artifacts.items():
            artifact = files[name]
            if (
                len(artifact) != metadata["size_bytes"]
                or hashlib.sha256(artifact).hexdigest()
                != metadata["sha256"]
            ):
                raise ValueError("Execution artifact binding is invalid")
        return manifest

    def _reconcile_execution_orphan(
        self,
        status: dict[str, object],
    ) -> None:
        session_id = str(status["session_id"])
        if not self.repository.has_execution_publication(session_id):
            return
        try:
            files = self.repository.read_execution_files(session_id)
            manifest = self._verify_signed_execution_files(files)
            plan_raw = self.repository.read_revision_file(
                session_id, "plan.json"
            )
            plan = parse_execution_plan_bytes(plan_raw)
            plan_digest = hashlib.sha256(plan_raw).hexdigest()
            self._verify_published_plan_signature(
                session_id,
                plan_raw,
                plan_digest,
                plan.approved_at,
            )
            if (
                manifest.session_id != session_id
                or manifest.plan_sha256 != plan_digest
                or manifest.inventory_sha256
                != status.get("inventory_sha256")
                or manifest.inventory_sha256 != plan.inventory_sha256
                or manifest.target_disk != plan.target_disk["path"]
                or manifest.disk_fingerprint
                != plan.target_disk["fingerprint"]
                or manifest.profile_id != plan.profile_id
                or manifest.profile_version != plan.profile_version
                or manifest.iso_id != plan.iso_id
                or manifest.iso_sha256 != plan.iso_sha256
            ):
                raise ValueError("Execution orphan binding is invalid")
            self.repository.discard_partial_execution(
                session_id, expected_files=files
            )
        except (ControlError, KeyError, TypeError, ValueError):
            raise self._error(
                "execution_orphan_invalid",
                "Install execution orphan is invalid",
            ) from None

    def authorize(
        self,
        session_id: str,
        *,
        plan_sha256: object,
        inventory_sha256: object,
        disk_fingerprint_value: object,
        confirm_target: object,
        reason: object,
    ) -> ExecutionAuthorizationResult:
        if self.euid() != 0:
            raise self._error("execution_root_required", "Execution authorization requires root")
        reason_text = self._bounded_text(
            reason,
            code="execution_reason_invalid",
            description="Execution authorization reason is invalid",
        )
        lock = nullcontext() if os.name == "nt" else __import__(
            "alt_deploy.locks", fromlist=["exclusive_lock"]
        ).exclusive_lock(self.settings.install_sessions_lock)
        with lock:
            status = self.repository.load_status(session_id)
            if status.get("state") in {"cancelled", "expired"}:
                raise self._error("execution_session_terminal", "Execution session is terminal")
            if status.get("state") != "plan_published":
                raise self._error("execution_plan_unavailable", "Execution plan is not published")
            if "execution" in status:
                raise self._error(
                    "execution_already_authorized",
                    "Install execution is already authorized",
                )
            now = self._now()
            plan, plan_expiry = self._load_bound_plan(
                session_id,
                plan_sha256=plan_sha256,
                inventory_sha256=inventory_sha256,
                disk_fingerprint_value=disk_fingerprint_value,
                confirm_target=confirm_target,
                now=now,
            )
            self._validate_preflight(
                status, plan_approved_at=plan.approved_at, now=now
            )
            self._reconcile_execution_orphan(status)
            artifacts = self._bundle_artifacts(plan)
            expires_at = min(
                plan_expiry, now + timedelta(minutes=5)
            ).isoformat()
            manifest = build_execution_manifest(
                plan=plan.to_dict(),
                plan_sha256=plan_sha256,
                authorized_at=now.isoformat(),
                expires_at=expires_at,
                artifacts=artifacts,
            )
            manifest_bytes = canonical_execution_manifest_bytes(manifest)
            try:
                signer = load_private_signer(
                    self.settings.install_signing_private_key
                )
                verifier = load_public_verifier(
                    self.settings.install_signing_public_key
                )
                if public_key_metadata(
                    signer.public_key()
                ) != public_key_metadata(verifier):
                    raise ValueError
                signature = sign_execution_manifest(
                    signer, manifest_bytes
                )
                signature_bytes = canonical_execution_signature_bytes(
                    signature
                )
            except ValueError:
                raise self._error(
                    "execution_signing_key_invalid",
                    "Execution signing key material is invalid",
                ) from None
            manifest_sha256 = hashlib.sha256(
                manifest_bytes
            ).hexdigest()
            updated = deepcopy(status)
            updated["execution"] = {
                "schema_version": 1,
                "revision": 1,
                "state": "authorized",
                "authorized_at": now.isoformat(),
                "expires_at": expires_at,
                "plan_sha256": plan_sha256,
                "inventory_sha256": inventory_sha256,
                "disk_fingerprint": disk_fingerprint_value,
                "target_disk": confirm_target,
                "reason": reason_text,
                "profile_id": plan.profile_id,
                "profile_version": plan.profile_version,
                "iso_id": plan.iso_id,
                "iso_sha256": plan.iso_sha256,
                "manifest_sha256": manifest_sha256,
                "claimed_at": None,
                "handoff_started_at": None,
                "installer_started_at": None,
                "installed_at": None,
                "failed_at": None,
                "failure_code": None,
                "cancelled_at": None,
                "cancel_reason": None,
                "expired_at": None,
            }
            updated["updated_at"] = now.isoformat()
            files = {
                "execution-manifest.json": manifest_bytes,
                "execution-manifest-signature.json": signature_bytes,
                **artifacts,
            }
            published = False
            try:
                self.repository.publish_execution(
                    session_id, files=files
                )
                published = True
                self.repository.replace_status(
                    session_id, updated, allow_execution=True
                )
            except ControlError as exc:
                if (
                    published
                    and exc.code
                    != "install_session_status_commit_uncertain"
                ):
                    self.repository.discard_partial_execution(
                        session_id, expected_files=files
                    )
                raise
            return ExecutionAuthorizationResult(
                manifest=manifest,
                status=MappingProxyType(deepcopy(updated)),
            )

    @staticmethod
    def _cancelled_before_authorization(
        *,
        now: str,
        reason: str,
    ) -> dict[str, object]:
        return {
            "schema_version": 1,
            "revision": 1,
            "state": "cancelled",
            "authorized_at": None,
            "expires_at": None,
            "plan_sha256": None,
            "inventory_sha256": None,
            "disk_fingerprint": None,
            "target_disk": None,
            "reason": None,
            "profile_id": None,
            "profile_version": None,
            "iso_id": None,
            "iso_sha256": None,
            "manifest_sha256": None,
            "claimed_at": None,
            "handoff_started_at": None,
            "installer_started_at": None,
            "installed_at": None,
            "failed_at": None,
            "failure_code": None,
            "cancelled_at": now,
            "cancel_reason": reason,
            "expired_at": None,
        }

    def _expire_execution(
        self,
        session_id: str,
        status: dict[str, object],
        now: datetime,
    ) -> bool:
        execution = status.get("execution")
        if not isinstance(execution, dict) or execution.get("state") not in {
            "authorized",
            "claimed",
            "handoff_started",
        }:
            return False
        expires_at = self._timestamp(execution.get("expires_at"))
        if now < expires_at:
            return False
        updated = deepcopy(status)
        next_execution = dict(updated["execution"])
        next_execution.update(
            {"state": "expired", "expired_at": now.isoformat()}
        )
        updated["execution"] = next_execution
        updated["updated_at"] = now.isoformat()
        self.repository.replace_status(
            session_id, updated, allow_execution=True
        )
        return True

    def cancel(
        self,
        session_id: str,
        *,
        reason: object,
    ) -> dict[str, object]:
        if self.euid() != 0:
            raise self._error(
                "execution_root_required",
                "Execution cancellation requires root",
            )
        reason_text = self._bounded_text(
            reason,
            code="execution_reason_invalid",
            description="Execution cancellation reason is invalid",
        )
        lock = nullcontext() if os.name == "nt" else __import__(
            "alt_deploy.locks", fromlist=["exclusive_lock"]
        ).exclusive_lock(self.settings.install_sessions_lock)
        with lock:
            status = self.repository.load_status(session_id)
            if status.get("state") in {"cancelled", "expired"}:
                raise self._error(
                    "execution_session_terminal",
                    "Execution session is terminal",
                )
            now = self._now()
            execution = status.get("execution")
            if isinstance(execution, dict):
                validate_execution_status(execution)
                if execution.get("state") == "cancelled":
                    if execution.get("cancel_reason") == reason_text:
                        return status
                    raise self._error(
                        "execution_cancel_conflict",
                        "Execution was cancelled with another reason",
                    )
                if execution.get("state") in {
                    "expired",
                    "installer_started",
                    "installed",
                    "failed",
                }:
                    raise self._error(
                        "execution_terminal",
                        "Execution is terminal",
                    )
                if self._expire_execution(session_id, status, now):
                    raise self._error(
                        "execution_expired", "Execution authorization expired"
                    )
                next_execution = deepcopy(execution)
                next_execution.update(
                    {
                        "state": "cancelled",
                        "cancelled_at": now.isoformat(),
                        "cancel_reason": reason_text,
                    }
                )
            elif execution is None:
                self._reconcile_execution_orphan(status)
                next_execution = self._cancelled_before_authorization(
                    now=now.isoformat(), reason=reason_text
                )
            else:
                raise self._error(
                    "execution_status_invalid",
                    "Execution status is invalid",
                )
            updated = deepcopy(status)
            updated["execution"] = next_execution
            updated["updated_at"] = now.isoformat()
            self.repository.replace_status(
                session_id, updated, allow_execution=True
            )
            return updated

    def _verify_claim_bundle(
        self,
        status: dict[str, object],
    ) -> ExecutionManifestV1:
        session_id = str(status["session_id"])
        execution = status["execution"]
        try:
            files = self.repository.read_execution_files(session_id)
            manifest = self._verify_signed_execution_files(files)
            manifest_bytes = files["execution-manifest.json"]
            if (
                manifest.session_id != session_id
                or manifest.plan_sha256 != execution["plan_sha256"]
                or manifest.inventory_sha256
                != execution["inventory_sha256"]
                or manifest.target_disk != execution["target_disk"]
                or manifest.disk_fingerprint
                != execution["disk_fingerprint"]
                or manifest.profile_id != execution["profile_id"]
                or manifest.profile_version
                != execution["profile_version"]
                or manifest.iso_id != execution["iso_id"]
                or manifest.iso_sha256 != execution["iso_sha256"]
                or manifest.authorized_at != execution["authorized_at"]
                or manifest.expires_at != execution["expires_at"]
                or hashlib.sha256(manifest_bytes).hexdigest()
                != execution["manifest_sha256"]
            ):
                raise ValueError
        except (ControlError, KeyError, TypeError, ValueError):
            raise self._error(
                "execution_bundle_invalid",
                "Execution bundle is invalid",
            ) from None
        return manifest

    def claim(self, session_id: str) -> dict[str, object]:
        lock = nullcontext() if os.name == "nt" else __import__(
            "alt_deploy.locks", fromlist=["exclusive_lock"]
        ).exclusive_lock(self.settings.install_sessions_lock)
        with lock:
            status = self.repository.load_status(session_id)
            if status.get("state") in {"cancelled", "expired"}:
                raise self._error(
                    "execution_session_terminal",
                    "Execution session is terminal",
                )
            if status.get("state") != "plan_published":
                raise self._error(
                    "execution_plan_unavailable",
                    "Execution plan is not published",
                )
            execution = status.get("execution")
            if not isinstance(execution, dict):
                raise self._error(
                    "execution_not_authorized",
                    "Execution is not authorized",
                )
            validate_execution_status(execution)
            if execution.get("state") != "authorized":
                raise self._error(
                    "execution_claim_conflict",
                    "Install execution cannot be claimed",
                )
            now = self._now()
            if self._expire_execution(session_id, status, now):
                raise self._error(
                    "execution_expired", "Execution authorization expired"
                )
            try:
                plan = parse_execution_plan_bytes(
                    self.repository.read_revision_file(
                        session_id, "plan.json"
                    )
                )
            except (ControlError, RenderError):
                raise self._error(
                    "execution_plan_invalid",
                    "Published execution plan is invalid",
                ) from None
            self._validate_preflight(
                status, plan_approved_at=plan.approved_at, now=now
            )
            self._verify_claim_bundle(status)
            updated = deepcopy(status)
            next_execution = dict(updated["execution"])
            next_execution.update(
                {"state": "claimed", "claimed_at": now.isoformat()}
            )
            updated["execution"] = next_execution
            updated["updated_at"] = now.isoformat()
            self.repository.replace_status(
                session_id, updated, allow_execution=True
            )
            return updated

    def handoff_started(self, session_id: str) -> dict[str, object]:
        lock = nullcontext() if os.name == "nt" else __import__(
            "alt_deploy.locks", fromlist=["exclusive_lock"]
        ).exclusive_lock(self.settings.install_sessions_lock)
        with lock:
            status = self.repository.load_status(session_id)
            if status.get("state") in {"cancelled", "expired"}:
                raise self._error(
                    "execution_session_terminal",
                    "Execution session is terminal",
                )
            if status.get("state") != "plan_published":
                raise self._error(
                    "execution_plan_unavailable",
                    "Execution plan is not published",
                )
            execution = status.get("execution")
            if not isinstance(execution, dict):
                raise self._error(
                    "execution_not_authorized",
                    "Execution is not authorized",
                )
            validate_execution_status(execution)
            if execution.get("state") != "claimed":
                raise self._error(
                    "execution_handoff_conflict",
                    "Install execution handoff cannot be recorded",
                )
            now = self._now()
            if self._expire_execution(session_id, status, now):
                raise self._error(
                    "execution_expired", "Execution authorization expired"
                )
            self._verify_claim_bundle(status)
            updated = deepcopy(status)
            next_execution = dict(updated["execution"])
            next_execution.update(
                {
                    "state": "handoff_started",
                    "handoff_started_at": now.isoformat(),
                }
            )
            updated["execution"] = next_execution
            updated["updated_at"] = now.isoformat()
            self.repository.replace_status(
                session_id, updated, allow_execution=True
            )
            return updated

    def installer_started(self, session_id: str) -> dict[str, object]:
        lock = nullcontext() if os.name == "nt" else __import__(
            "alt_deploy.locks", fromlist=["exclusive_lock"]
        ).exclusive_lock(self.settings.install_sessions_lock)
        with lock:
            status = self.repository.load_status(session_id)
            execution = status.get("execution")
            if (
                status.get("state") != "plan_published"
                or not isinstance(execution, dict)
            ):
                raise self._error(
                    "execution_installer_conflict",
                    "Install execution installer cannot be recorded",
                )
            validate_execution_status(execution)
            if execution.get("state") != "handoff_started":
                raise self._error(
                    "execution_installer_conflict",
                    "Install execution installer cannot be recorded",
                )
            self._verify_claim_bundle(status)
            now = self._now().isoformat()
            updated = deepcopy(status)
            next_execution = dict(updated["execution"])
            next_execution.update(
                {
                    "state": "installer_started",
                    "installer_started_at": now,
                }
            )
            updated["execution"] = next_execution
            updated["updated_at"] = now
            self.repository.replace_status(
                session_id, updated, allow_execution=True
            )
            return updated

    def postflight_installed(
        self, session_id: str
    ) -> dict[str, object]:
        lock = nullcontext() if os.name == "nt" else __import__(
            "alt_deploy.locks", fromlist=["exclusive_lock"]
        ).exclusive_lock(self.settings.install_sessions_lock)
        with lock:
            status = self.repository.load_status(session_id)
            execution = status.get("execution")
            if (
                status.get("state") != "plan_published"
                or not isinstance(execution, dict)
            ):
                raise self._error(
                    "execution_postflight_conflict",
                    "Install execution postflight cannot be recorded",
                )
            validate_execution_status(execution)
            if execution.get("state") != "installer_started":
                raise self._error(
                    "execution_postflight_conflict",
                    "Install execution postflight cannot be recorded",
                )
            now = self._now().isoformat()
            updated = deepcopy(status)
            next_execution = dict(updated["execution"])
            next_execution.update(
                {"state": "installed", "installed_at": now}
            )
            updated["execution"] = next_execution
            updated["updated_at"] = now
            self.repository.replace_status(
                session_id, updated, allow_execution=True
            )
            return updated
