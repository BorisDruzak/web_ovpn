#!/usr/bin/env python3
"""Fail-closed release installation and service-user Endpoint smoke gate.

The null committed lock is intentional: a published release has not been
supplied. Release preparation must fill version/wheel/sha256 and supply that
wheel in deploy/wheels. No index, branch, source checkout, or HTTP fallback.
Smoke runs before enabling the feature and never persists the enabled flag.
"""
from __future__ import annotations

import argparse
from dataclasses import replace
from email.parser import BytesParser
import hashlib
import importlib
from importlib import metadata
import json
import math
import os
from pathlib import Path
import re
import ssl
import stat
import subprocess
import sys
from urllib.parse import unquote, urlsplit
import unicodedata
from uuid import UUID
import zipfile


class VerificationError(RuntimeError):
    """Only static redacted codes may cross the CLI boundary."""


def verify_artifact(lock_path: Path) -> tuple[Path, dict]:
    try:
        manifest = json.loads(lock_path.read_text(encoding="utf-8"))
        if any(manifest.get(key) is None for key in ("version", "wheel", "sha256")):
            raise VerificationError("endpoint_platform_sdk_release_required")
        version, filename, digest = (manifest[key] for key in ("version", "wheel", "sha256"))
        if (
            manifest.get("distribution") != "endpoint-platform-client"
            or not isinstance(version, str)
            or not re.fullmatch(r"[0-9][A-Za-z0-9.!+_-]*", version)
            or not isinstance(filename, str)
            or not re.fullmatch(r"endpoint_platform_client-[A-Za-z0-9_.+!-]+\.whl", filename)
            or not isinstance(digest, str)
            or not re.fullmatch(r"[a-f0-9]{64}", digest)
        ):
            raise ValueError()
        wheel = lock_path.parent / "wheels" / filename
        if wheel.is_symlink() or not wheel.is_file():
            raise ValueError()
        with wheel.open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != digest:
                raise ValueError()
        with zipfile.ZipFile(wheel) as archive:
            names = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
            if len(names) != 1:
                raise ValueError()
            info = BytesParser().parsebytes(archive.read(names[0]))
            if info.get("Name", "").lower().replace("_", "-") != manifest["distribution"] or info.get("Version") != version:
                raise ValueError()
        return wheel, manifest
    except VerificationError:
        raise
    except Exception:
        raise VerificationError("endpoint_platform_sdk_artifact_invalid") from None


def verify_installed(manifest: dict) -> None:
    try:
        distribution = metadata.distribution("endpoint-platform-client")
        direct = json.loads(distribution.read_text("direct_url.json") or "{}")
        url = urlsplit(direct.get("url", ""))
        if (
            distribution.version != manifest["version"]
            or direct.get("dir_info") is not None
            or url.scheme != "file"
            or Path(unquote(url.path)).name != manifest["wheel"]
            or direct.get("archive_info", {}).get("hashes", {}).get("sha256") != manifest["sha256"]
        ):
            raise ValueError()
        sdk = importlib.import_module("endpoint_platform_client")
        if not callable(getattr(sdk, "EndpointPlatformClient", None)):
            raise ValueError()
    except Exception:
        raise VerificationError("endpoint_platform_sdk_installed_invalid") from None


def validate_file_metadata(info, service_gid: int, *, secret: bool) -> None:
    mode = stat.S_IMODE(info.st_mode)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or mode & 0o022
        or (secret and (info.st_gid != service_gid or mode != 0o640))
    ):
        raise VerificationError("endpoint_platform_file_permissions_invalid")


def check_managed_file(path: Path, service_gid: int, *, secret: bool) -> bytes:
    try:
        if not path.is_absolute() or path.is_symlink() or path.resolve() != path:
            raise ValueError()
        validate_file_metadata(path.stat(), service_gid, secret=secret)
        content = path.read_bytes()
        if not content.strip():
            raise ValueError()
        return content
    except VerificationError:
        raise
    except Exception:
        raise VerificationError("endpoint_platform_file_unreadable") from None


def service_group() -> int:
    try:
        import grp
        import pwd
        if pwd.getpwuid(os.geteuid()).pw_name != "openvpn-web":
            raise ValueError()
        return grp.getgrnam("openvpn-web").gr_gid
    except Exception:
        raise VerificationError("endpoint_platform_service_user_required") from None


def load_environment(path: Path, service_gid: int) -> None:
    # Supported systemd EnvironmentFile subset: single-line assignments, optional
    # enclosing quotes, literal inline #, and ignored surrounding whitespace.
    # Reject continuations/escapes/multiline quoting anywhere, including other
    # keys, so an Endpoint assignment cannot be hidden inside another value.
    content = check_managed_file(path, service_gid, secret=True).decode("utf-8")
    values = {}
    try:
        if any(
            character not in "\t\r\n "
            and (unicodedata.category(character) in {"Cc", "Cf", "Cs", "Zl", "Zp", "Zs"})
            for character in content
        ):
            raise ValueError()
        for line in content.split("\n"):
            line = line.strip(" \t\r")
            if not line or line.startswith(("#", ";")):
                continue
            key, separator, raw = line.partition("=")
            key, raw = key.strip(" \t\r"), raw.strip(" \t\r")
            if not separator or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) or "\\" in raw:
                raise ValueError()
            if raw.startswith(("'", '"')):
                if len(raw) < 2 or not raw.endswith(raw[0]) or raw[0] in raw[1:-1]:
                    raise ValueError()
                raw = raw[1:-1]
            if not key.startswith("ENDPOINT_PLATFORM_"):
                continue
            if key in values:
                raise ValueError()
            values[key] = raw
        # Environment file, not caller shell state, is authoritative.
        for key in list(os.environ):
            if key.startswith("ENDPOINT_PLATFORM_"):
                del os.environ[key]
        os.environ.update(values)
        timeout = float(values.get("ENDPOINT_PLATFORM_TIMEOUT_SECONDS", "5"))
        if not math.isfinite(timeout) or timeout <= 0 or timeout > 120:
            raise ValueError()
    except Exception:
        raise VerificationError("endpoint_platform_config_invalid") from None


def validate_settings(settings) -> None:
    url = urlsplit(settings.endpoint_platform_base_url)
    timeout = settings.endpoint_platform_timeout_seconds
    if (
        url.scheme != "https" or not url.hostname or url.username or url.password
        or url.query or url.fragment or url.path not in ("", "/")
        or not isinstance(settings.endpoint_platform_smoke_device_id, UUID)
        or not math.isfinite(timeout) or not 0 < timeout <= 120
        or not settings.endpoint_platform_token_file.is_absolute()
        or not settings.endpoint_platform_ca_file.is_absolute()
    ):
        raise VerificationError("endpoint_platform_config_invalid")


def verify_api(settings, artifact_digest: str) -> None:
    from app.endpoint_context_adapter import EndpointContextAdapter
    from app.endpoint_platform_client import (
        EndpointPlatformServiceClient, EndpointPlatformServiceScopeDenied,
    )
    validate_settings(settings)
    adapter = None
    try:
        adapter = EndpointContextAdapter(EndpointPlatformServiceClient(replace(settings, endpoint_platform_enabled=True)))
        device = settings.endpoint_platform_smoke_device_id
        # Actual authorized SDK calls prove the three required capabilities.
        devices = adapter.list_devices()  # devices.read
        if not any(str(row.get("id")) == str(device) and not row.get("retired_at") for row in devices):
            raise VerificationError("endpoint_platform_smoke_device_unavailable")
        adapter.list_agent_network_identities()
        adapter.read_profiles(device)  # context.read; absent profiles are valid
        # Stable per release/device: repeated verifier runs do not queue copies.
        key = f"web-ovpn-smoke:{device}:{artifact_digest[:16]}"
        result = adapter.request_collection(device, "baseline_v1", key)  # context.collect
        if (not result.get("id") or str(result.get("device_id")) != str(device)
                or result.get("profile") != "baseline_v1"
                or result.get("status") not in {"requested", "queued", "dispatched", "running", "completed"}):
            raise VerificationError("endpoint_platform_collection_unavailable")
    except VerificationError:
        raise
    except EndpointPlatformServiceScopeDenied:
        raise VerificationError("endpoint_platform_scope_denied") from None
    except Exception:
        raise VerificationError("endpoint_platform_unavailable") from None
    finally:
        if adapter is not None:
            adapter.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app-dir", type=Path, default=Path("/opt/openvpn-web"))
    parser.add_argument("--env-file", type=Path, default=Path("/etc/openvpn-web/openvpn-web.env"))
    parser.add_argument("--if-enabled", action="store_true", help="exit 77 when configured disabled")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--artifact-only", action="store_true")
    modes.add_argument("--install", action="store_true", help="install locked local wheel before smoke")
    args = parser.parse_args(argv)
    try:
        sys.path.insert(0, str(args.app_dir))
        if not args.artifact_only:
            gid = service_group()
            load_environment(args.env_file, gid)
            from app.config import get_settings
            get_settings.cache_clear()
            settings = get_settings()
            if args.if_enabled and not settings.endpoint_platform_enabled:
                print("endpoint_platform_disabled")
                return 77
            validate_settings(settings)
        wheel, manifest = verify_artifact(args.app_dir / "deploy/endpoint-platform-client.lock")
        if args.artifact_only:
            print("endpoint_platform_artifact_verified")
            return 0
        if args.install:
            result = subprocess.run([sys.executable, "-m", "pip", "install", "--no-index", "--no-deps", "--force-reinstall", str(wheel)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            if result.returncode:
                raise VerificationError("endpoint_platform_sdk_install_failed")
        verify_installed(manifest)
        check_managed_file(settings.endpoint_platform_token_file, gid, secret=True)
        check_managed_file(settings.endpoint_platform_ca_file, gid, secret=False)
        try:
            ssl.create_default_context(cafile=str(settings.endpoint_platform_ca_file))
        except Exception:
            raise VerificationError("endpoint_platform_ca_invalid") from None
        verify_api(settings, manifest["sha256"])
        print("endpoint_platform_verified")
        return 0
    except VerificationError as error:
        print(str(error))
    except Exception:
        print("endpoint_platform_verification_failed")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
