"""Isolated queue worker for tightly-scoped SSH server draft checks.

This module deliberately has no FastAPI dependency.  Candidate host keys and
all subprocess output stay in ``private_dir``; results are public projections.
"""

from __future__ import annotations

from dataclasses import dataclass
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Callable

from app.server_drafts import DraftRequest, make_draft_request, write_public_result


COMMAND_TIMEOUT_SECONDS = 20
SCAN_TIMEOUT_SECONDS = 8
OBSERVER_KEY_PATH = "/etc/openvpn-web/server-observer.key"
_FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]{1,86}={0,2}")
_CANDIDATE = re.compile(r"^[^\s]+\s+ssh-ed25519\s+[A-Za-z0-9+/]+={0,3}\s*$")


class DraftWorkerError(RuntimeError):
    """A request cannot safely advance through the draft workflow."""


@dataclass(frozen=True)
class DraftPaths:
    queue_dir: Path
    results_dir: Path
    private_dir: Path


Runner = Callable[..., subprocess.CompletedProcess[str]]


def process_queue(queue_dir: Path, results_dir: Path, private_dir: Path, runner: Runner = subprocess.run) -> int:
    """Consume valid JSON requests once, returning the number dispatched."""
    paths = DraftPaths(Path(queue_dir), Path(results_dir), Path(private_dir))
    processed = 0
    for request_path in sorted(paths.queue_dir.glob("*.json")):
        try:
            request = _read_request(request_path)
            process_request(request, paths, runner)
        except (DraftWorkerError, OSError, ValueError, json.JSONDecodeError):
            # Do not expose malformed requests or tool diagnostics to the web layer.
            try:
                draft_id = request_path.stem
                make_draft_request(draft_id, "invalid", "invalid", 22, "scan")
                write_public_result(paths.results_dir, draft_id, {"status": "invalid_response"})
            except ValueError:
                pass
        else:
            processed += 1
        finally:
            try:
                request_path.unlink()
            except FileNotFoundError:
                pass
    return processed


def process_request(request: DraftRequest, paths: DraftPaths, runner: Runner = subprocess.run) -> int:
    """Process exactly one validated request; return zero for a duplicate check."""
    if request.action == "cleanup":
        cleanup_request = make_draft_request(request.id, "cleanup", "cleanup", 22, "cleanup")
        _cleanup(cleanup_request.id, paths)
        return 1
    request = make_draft_request(
        request.id, request.host, request.ssh_user, request.port, request.action, request.expected_fingerprint
    )
    if request.action == "scan":
        _scan(request, paths, runner)
        return 1
    if request.action == "confirm":
        _confirm(request, paths, runner)
        return 1
    if request.action == "check":
        if not _claim_check(paths, request.id):
            return 0
        try:
            _check(request, paths, runner)
        finally:
            _release_check(paths, request.id)
        return 1
    raise DraftWorkerError("action is not allowed")


def _scan(request: DraftRequest, paths: DraftPaths, runner: Runner) -> None:
    try:
        completed = _run(
            runner, ["ssh-keyscan", "-p", str(request.port), "-T", str(SCAN_TIMEOUT_SECONDS), "-t", "ed25519", request.host]
        )
    except subprocess.TimeoutExpired:
        write_public_result(paths.results_dir, request.id, {"status": "timeout"})
        return
    if completed.returncode != 0 or not completed.stdout.strip():
        write_public_result(paths.results_dir, request.id, {"status": "transport"})
        return
    candidate = completed.stdout.strip() + "\n"
    if not _CANDIDATE.fullmatch(candidate):
        write_public_result(paths.results_dir, request.id, {"status": "invalid_response"})
        return
    try:
        fingerprint = _fingerprint(candidate, runner)
    except DraftWorkerError:
        write_public_result(paths.results_dir, request.id, {"status": "invalid_response"})
        return
    _write_private(_candidate_path(paths, request.id), candidate)
    algorithm = candidate.split()[1]
    write_public_result(paths.results_dir, request.id, {"status": "pending", "algorithm": algorithm, "fingerprint": fingerprint})


def _confirm(request: DraftRequest, paths: DraftPaths, runner: Runner) -> None:
    if request.expected_fingerprint is None:
        raise DraftWorkerError("fingerprint is required")
    try:
        candidate = _candidate_path(paths, request.id).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise DraftWorkerError("candidate is unavailable") from exc
    fingerprint = _fingerprint(candidate, runner)
    if fingerprint != request.expected_fingerprint:
        raise DraftWorkerError("fingerprint does not match scanned candidate")
    _write_private(_known_hosts_path(paths, request.id), candidate)
    write_public_result(paths.results_dir, request.id, {"status": "pending", "fingerprint": fingerprint})


def _check(request: DraftRequest, paths: DraftPaths, runner: Runner) -> None:
    known_hosts = _known_hosts_path(paths, request.id)
    if not known_hosts.is_file():
        raise DraftWorkerError("confirmed known-hosts file is unavailable")
    command = [
        "ssh", "-i", OBSERVER_KEY_PATH, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={known_hosts}", "-p", str(request.port),
        f"{request.ssh_user}@{request.host}", "true",
    ]
    try:
        completed = _run(runner, command)
    except subprocess.TimeoutExpired:
        write_public_result(paths.results_dir, request.id, {"status": "timeout"})
        return
    if completed.returncode == 0:
        write_public_result(paths.results_dir, request.id, {"status": "ok"})
    else:
        write_public_result(paths.results_dir, request.id, {"status": _ssh_failure_status(completed.stderr)})


def _run(runner: Runner, command: list[str]) -> subprocess.CompletedProcess[str]:
    return runner(command, capture_output=True, text=True, errors="replace", timeout=COMMAND_TIMEOUT_SECONDS)


def _fingerprint(candidate: str, runner: Runner) -> str:
    try:
        completed = runner(
            ["ssh-keygen", "-lf", "-", "-E", "sha256"], input=candidate, capture_output=True,
            text=True, errors="replace", timeout=COMMAND_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise DraftWorkerError("fingerprint command timed out") from exc
    match = _FINGERPRINT.search(completed.stdout) if completed.returncode == 0 else None
    if match is None:
        raise DraftWorkerError("fingerprint could not be derived")
    return match.group(0)


def _ssh_failure_status(stderr: str) -> str:
    message = (stderr or "").lower()
    if "host key" in message or "known hosts" in message:
        return "host_key_mismatch"
    if "permission denied" in message or "authentication" in message:
        return "authentication"
    return "transport"


def _read_request(path: Path) -> DraftRequest:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("request must be an object")
    if payload.get("action") == "cleanup":
        return make_draft_request(payload.get("id"), "cleanup", "cleanup", 22, "cleanup")
    return make_draft_request(
        payload.get("id"), payload.get("host"), payload.get("ssh_user"), payload.get("port"),
        payload.get("action"), payload.get("expected_fingerprint"),
    )


def _candidate_path(paths: DraftPaths, draft_id: str) -> Path:
    return paths.private_dir / f"{draft_id}.candidate"


def _known_hosts_path(paths: DraftPaths, draft_id: str) -> Path:
    return paths.private_dir / f"{draft_id}.known_hosts"


def _check_lock_path(paths: DraftPaths, draft_id: str) -> Path:
    return paths.private_dir / f"{draft_id}.check.lock"


def _claim_check(paths: DraftPaths, draft_id: str) -> bool:
    paths.private_dir.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(_check_lock_path(paths, draft_id), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        return False
    os.close(descriptor)
    return True


def _release_check(paths: DraftPaths, draft_id: str) -> None:
    try:
        _check_lock_path(paths, draft_id).unlink()
    except FileNotFoundError:
        pass


def _cleanup(draft_id: str, paths: DraftPaths) -> None:
    for path in (_candidate_path(paths, draft_id), _known_hosts_path(paths, draft_id),
                 paths.queue_dir / f"{draft_id}.json", paths.results_dir / f"{draft_id}.json"):
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def _write_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write(path, text, 0o600)


def _atomic_write(path: Path, text: str, mode: int) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as temporary:
            temporary.write(text)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.chmod(temporary_path, mode)
        os.replace(temporary_path, path)
    except Exception:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass
        raise


def main(argv: list[str] | None = None) -> int:
    """Run one isolated queue-consumer pass without importing the web app."""
    parser = argparse.ArgumentParser(description="Process SSH server draft requests")
    parser.add_argument("--queue-dir", type=Path, required=True)
    parser.add_argument("--results-dir", type=Path, required=True)
    parser.add_argument("--private-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    process_queue(args.queue_dir, args.results_dir, args.private_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
