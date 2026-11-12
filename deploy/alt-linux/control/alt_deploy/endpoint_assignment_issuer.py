"""Issue the approved ALT installation assignment from the staging controller."""

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


STAGING_ORIGIN = "https://endpoint-staging.sosnadmin.local"
TOKEN_FILE = Path("/etc/alt-deploy-endpoint/staging-assignments.token")
CA_FILE = Path("/etc/alt-deploy-endpoint/staging-ca.pem")
ISSUER_PYTHON = Path("/opt/alt-deploy-endpoint-sdk/bin/python")
_SDK_VERSION = "0.2.1"
# The pinned native coordinator allows up to 120 seconds for enrollment notification.
_NOTIFICATION_WINDOW = timedelta(seconds=120)
_INPUT_LIMIT = 2048
_FINGERPRINT = re.compile(r"sha256:[0-9a-f]{64}")


def _require_file(path, *, secret):
    for parent in path.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError
    info = path.lstat()
    mode = stat.S_IMODE(info.st_mode)
    if (
        not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
        or not 0 < info.st_size <= (4096 if secret else 65536)
        or mode not in ((0o640,) if secret else (0o640, 0o644))
        or (mode == 0o640 and info.st_gid != os.getegid())
    ):
        raise ValueError


def assignment_issuer_available(*, runner=None):
    """Read-only local check used while constructing an executable plan."""
    runner = runner or subprocess.run
    try:
        result = runner(
            [str(ISSUER_PYTHON), "-I", str(Path(__file__).resolve()), "--preflight"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            check=False, timeout=15,
        )
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _load_sdk():
    from importlib.metadata import version
    from endpoint_platform_client import EndpointPlatformClient

    if version("endpoint-platform-client") != _SDK_VERSION or not callable(
        getattr(EndpointPlatformClient, "issue_inventory_installation", None)
    ):
        raise ValueError
    return EndpointPlatformClient


def main(*, stdin=None, clock=None, client_factory=None, preflight=False):
    try:
        from alt_deploy.endpoint_installation import installation_matches_machine

        if not preflight:
            source = stdin if stdin is not None else sys.stdin.buffer
            raw = source.read(_INPUT_LIMIT + 1)
            if len(raw) > _INPUT_LIMIT:
                raise ValueError
            request = json.loads(raw)
            if not isinstance(request, dict) or set(request) != {"installation_id", "machine_uuid", "hardware_fingerprint"}:
                raise ValueError
            installation_id = request["installation_id"]
            fingerprint = request["hardware_fingerprint"]
            if (
                not installation_matches_machine(installation_id, request["machine_uuid"])
                or not isinstance(fingerprint, str) or not _FINGERPRINT.fullmatch(fingerprint)
            ):
                raise ValueError
        _require_file(TOKEN_FILE, secret=True)
        _require_file(CA_FILE, secret=False)
        client_factory = client_factory or _load_sdk()
        with client_factory(STAGING_ORIGIN, token_file=TOKEN_FILE, ca_file=CA_FILE, timeout_seconds=10) as client:
            if preflight:
                return 0
            receipt = client.issue_inventory_installation(installation_id, fingerprint, "linux")
        current = clock() if clock is not None else datetime.now(timezone.utc)
        if receipt.expires_at - current < _NOTIFICATION_WINDOW:
            raise ValueError
    except Exception:
        print("endpoint_native_assignment_unavailable")
        return 1
    return 0


if __name__ == "__main__":
    # The isolated interpreter admits only the root-owned installed controller package.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    arguments = sys.argv[1:]
    if arguments not in ([], ["--preflight"]):
        print("endpoint_native_assignment_unavailable")
        raise SystemExit(1)
    raise SystemExit(main(preflight=bool(arguments)))
