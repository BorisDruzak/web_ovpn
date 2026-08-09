from __future__ import annotations

import subprocess

from .models import NmapFingerprint
from .parser import NmapParseError, parse_nmap_xml
from .policy import validate_target_ipv4


HELPER_COMMAND = (
    "/usr/bin/sudo",
    "--non-interactive",
    "/usr/local/libexec/netctl-nmap-fingerprint",
)
HELPER_TIMEOUT_SECONDS = 30


class NmapRunnerError(RuntimeError):
    """A sanitized failure returned by the restricted fingerprint runner."""

    def __init__(self, error_class: str, message: str) -> None:
        super().__init__(message)
        self.error_class = error_class


def run_nmap_fingerprint(target_ip: str) -> NmapFingerprint:
    """Run the restricted one-target helper and parse normalized XML fields."""
    target = validate_target_ipv4(target_ip)
    try:
        completed = subprocess.run(
            [*HELPER_COMMAND, target],
            capture_output=True,
            check=False,
            shell=False,
            timeout=HELPER_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        raise NmapRunnerError("timeout", "fingerprint helper timed out") from None
    except FileNotFoundError:
        raise NmapRunnerError(
            "helper_unavailable", "fingerprint helper is unavailable"
        ) from None
    except PermissionError:
        raise NmapRunnerError(
            "helper_permission_denied", "fingerprint helper permission denied"
        ) from None
    except OSError:
        raise NmapRunnerError("helper_error", "fingerprint helper failed") from None
    if completed.returncode != 0:
        raise NmapRunnerError("scan_failed", "fingerprint helper failed")
    try:
        return parse_nmap_xml(completed.stdout)
    except NmapParseError:
        raise NmapRunnerError(
            "invalid_output", "fingerprint helper returned invalid output"
        ) from None
