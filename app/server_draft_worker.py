"""Isolated queue worker for tightly-scoped SSH server draft checks.

This module deliberately has no FastAPI dependency.  Candidate host keys and
all subprocess output stay in ``private_dir``; results are public projections.
"""

from __future__ import annotations

from dataclasses import dataclass
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
from typing import Callable

from app.server_drafts import DraftRequest, make_draft_request, write_public_result


COMMAND_TIMEOUT_SECONDS = 20
SCAN_TIMEOUT_SECONDS = 8
SERVICE_RUNTIME_BUDGET_SECONDS = 120
DISPATCH_RESERVE_SECONDS = 45
OBSERVER_KEY_PATH = "/etc/openvpn-web/server-observer.key"
_FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]{43}(?![A-Za-z0-9+/=])")
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
    """Drain requests to quiescence, with cleanup reservations taking priority."""
    processed, _backlog = _drain_queue(queue_dir, results_dir, private_dir, runner)
    return processed


def process_service_cycle(
    queue_dir: Path,
    results_dir: Path,
    private_dir: Path,
    runner: Runner = subprocess.run,
    *,
    monotonic: Callable[[], float] = time.monotonic,
    runtime_budget_seconds: float = SERVICE_RUNTIME_BUDGET_SECONDS,
) -> tuple[int, bool]:
    """Reconcile crash state and drain until the safe systemd runtime budget.

    The path unit uses persistent glob conditions for both public requests and
    hidden claims, so ``True`` backlog is intentionally left visible for the
    next successful oneshot activation instead of using bounded restarts.
    """
    if runtime_budget_seconds < DISPATCH_RESERVE_SECONDS:
        raise ValueError("runtime budget cannot fit one bounded request")
    paths = DraftPaths(Path(queue_dir), Path(results_dir), Path(private_dir))
    deadline = monotonic() + runtime_budget_seconds
    _clear_stale_private_locks(paths)
    recovered, recovery_backlog = _recover_stale_claims(
        paths, runner, deadline=deadline, monotonic=monotonic
    )
    if recovery_backlog:
        return recovered, True
    processed, backlog = _drain_queue(
        paths.queue_dir,
        paths.results_dir,
        paths.private_dir,
        runner,
        deadline=deadline,
        monotonic=monotonic,
    )
    return recovered + processed, backlog


def _drain_queue(
    queue_dir: Path,
    results_dir: Path,
    private_dir: Path,
    runner: Runner = subprocess.run,
    *,
    deadline: float | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> tuple[int, bool]:
    """Return processed count and whether durable work remains visible."""
    paths = DraftPaths(Path(queue_dir), Path(results_dir), Path(private_dir))
    processed = 0
    while True:
        cleanup_paths = sorted(paths.queue_dir.glob("*.cleanup.json"))
        pass_processed = 0
        for cleanup_path in cleanup_paths:
            pass_processed += _process_cleanup_queue_path(cleanup_path, paths, runner)

        request_paths = sorted(
            path for path in paths.queue_dir.glob("*.json")
            if not path.name.endswith(".cleanup.json")
        )
        for request_path in request_paths:
            if deadline is not None and deadline - monotonic() < DISPATCH_RESERVE_SECONDS:
                return processed + pass_processed, _queue_has_work(paths)
            pass_processed += _process_normal_queue_path(request_path, paths, runner)
        processed += pass_processed

        if not cleanup_paths and not request_paths:
            return processed, _queue_has_work(paths)
        # Nothing was claimable in this snapshot. Another worker owns it, or a
        # claim will be reconciled by the next systemd-singleton activation.
        if pass_processed == 0:
            snapshot = set(cleanup_paths) | set(request_paths)
            current = set(paths.queue_dir.glob("*.json"))
            if current - snapshot:
                continue
            return processed, _queue_has_work(paths)


def _queue_has_work(paths: DraftPaths) -> bool:
    return any(paths.queue_dir.glob("*.json")) or any(paths.queue_dir.glob(".*.json.claim"))


def _clear_stale_private_locks(paths: DraftPaths) -> None:
    paths.private_dir.mkdir(parents=True, exist_ok=True)
    for pattern in ("*.dispatch.lock", "*.check.lock"):
        for path in paths.private_dir.glob(pattern):
            try:
                path.unlink()
            except FileNotFoundError:
                pass


def _recover_stale_claims(
    paths: DraftPaths,
    runner: Runner,
    *,
    deadline: float,
    monotonic: Callable[[], float],
) -> tuple[int, bool]:
    processed = 0
    claims = sorted(paths.queue_dir.glob(".*.cleanup.json.claim")) + sorted(
        path for path in paths.queue_dir.glob(".*.json.claim")
        if not path.name.endswith(".cleanup.json.claim")
    )
    for claim_path in claims:
        if deadline - monotonic() < DISPATCH_RESERVE_SECONDS:
            return processed, True
        request_name = claim_path.name.removeprefix(".").removesuffix(".claim")
        request_path = paths.queue_dir / request_name
        if request_name.endswith(".cleanup.json"):
            processed += _process_claimed_cleanup_path(request_path, claim_path, paths, runner)
        else:
            processed += _process_claimed_normal_path(request_path, claim_path, paths, runner)
    return processed, _queue_has_work(paths) and any(paths.queue_dir.glob(".*.json.claim"))


def _process_cleanup_queue_path(cleanup_path: Path, paths: DraftPaths, runner: Runner) -> int:
    draft_id = cleanup_path.name.removesuffix(".cleanup.json")
    request_path = paths.queue_dir / f"{draft_id}.json"
    if _dispatch_path(paths, draft_id).exists():
        return 0
    active_claim = _claim_path(request_path)
    if active_claim.exists():
        return 0

    if request_path.exists():
        pending_claim = _claim_request(request_path)
        if pending_claim is None:
            return 0
        _release_claim(request_path, pending_claim, remove_request=True)
        if request_path.exists() or active_claim.exists():
            return 0

    claim_path = _claim_request(cleanup_path)
    if claim_path is None:
        return 0
    return _process_claimed_cleanup_path(cleanup_path, claim_path, paths, runner)


def _process_claimed_cleanup_path(
    cleanup_path: Path, claim_path: Path, paths: DraftPaths, runner: Runner
) -> int:
    draft_id = cleanup_path.name.removesuffix(".cleanup.json")
    completed = False
    try:
        try:
            request = make_draft_request(draft_id, "cleanup", "cleanup", 22, "cleanup")
        except ValueError:
            # Invalid names can never identify scoped private state. Consume
            # them so the persistent path condition cannot spin forever.
            completed = True
            return 0
        process_request(request, paths, runner)
        _mark_deleted(paths, draft_id)
        completed = True
        return 1
    except (DraftWorkerError, OSError):
        # Keep cleanup durable for a later retry.
        return 0
    finally:
        _release_claim(cleanup_path, claim_path, remove_request=completed)


def _process_normal_queue_path(request_path: Path, paths: DraftPaths, runner: Runner) -> int:
    draft_id = request_path.stem
    if _cleanup_reserved(paths, draft_id):
        _cancel_pending_request(request_path)
        return 0

    claim_path = _claim_request(request_path)
    if claim_path is None:
        return 0
    return _process_claimed_normal_path(request_path, claim_path, paths, runner)


def _process_claimed_normal_path(
    request_path: Path, claim_path: Path, paths: DraftPaths, runner: Runner
) -> int:
    draft_id = request_path.stem
    dispatch_path: Path | None = None
    consume_request = True
    try:
        if _cleanup_reserved(paths, draft_id):
            return 0
        request = _read_request(claim_path)
        if request.id != draft_id:
            raise ValueError("request id does not match its queue name")
        dispatch_path = _claim_dispatch(paths, draft_id)
        if dispatch_path is None:
            consume_request = False
            return 0
        # This second check closes the claim-to-dispatch race: cleanup that
        # became visible before dispatch reservation always cancels the action.
        if _cleanup_reserved(paths, draft_id):
            return 0
        process_request(request, paths, runner)
    except (DraftWorkerError, OSError, ValueError, json.JSONDecodeError):
        # Do not expose malformed requests or tool diagnostics to the web layer.
        try:
            make_draft_request(draft_id, "invalid", "invalid", 22, "scan")
            write_public_result(paths.results_dir, draft_id, {"status": "invalid_response"})
        except ValueError:
            pass
    else:
        return 1
    finally:
        if dispatch_path is not None:
            _release_dispatch(dispatch_path)
        _release_claim(request_path, claim_path, remove_request=consume_request)
    return 0


def _cleanup_reserved(paths: DraftPaths, draft_id: str) -> bool:
    return (
        (paths.queue_dir / f"{draft_id}.cleanup.json").is_file()
        or (paths.queue_dir / f"{draft_id}.deleted").is_file()
    )


def _cancel_pending_request(request_path: Path) -> bool:
    claim_path = _claim_request(request_path)
    if claim_path is None:
        return False
    _release_claim(request_path, claim_path, remove_request=True)
    return True


def process_request(request: DraftRequest, paths: DraftPaths, runner: Runner = subprocess.run) -> int:
    """Process exactly one validated request; return zero for a duplicate check."""
    if request.action == "cleanup":
        cleanup_request = make_draft_request(request.id, "cleanup", "cleanup", 22, "cleanup")
        _cleanup(cleanup_request.id, paths)
        return 1
    request = make_draft_request(
        request.id, request.host, request.ssh_user, request.port, request.action,
        request.expected_fingerprint, request.pin_generation,
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
            if not _check(request, paths, runner):
                return 0
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
    if request.expected_fingerprint is None or request.pin_generation is None:
        raise DraftWorkerError("fingerprint and pin generation are required")
    try:
        candidate = _candidate_path(paths, request.id).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise DraftWorkerError("candidate is unavailable") from exc
    fingerprint = _fingerprint(candidate, runner)
    if fingerprint != request.expected_fingerprint:
        raise DraftWorkerError("fingerprint does not match scanned candidate")
    _write_private(_known_hosts_path(paths, request.id), candidate)
    _write_private(_pin_generation_path(paths, request.id), request.pin_generation + "\n")
    write_public_result(
        paths.results_dir,
        request.id,
        {
            "status": "ok",
            "fingerprint": fingerprint,
            "checked_at": datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z"),
            "pin_generation": request.pin_generation,
        },
    )


def _check(request: DraftRequest, paths: DraftPaths, runner: Runner) -> bool:
    known_hosts = _known_hosts_path(paths, request.id)
    if not known_hosts.is_file():
        raise DraftWorkerError("confirmed known-hosts file is unavailable")
    try:
        pinned_generation = _pin_generation_path(paths, request.id).read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError) as exc:
        raise DraftWorkerError("pin generation is unavailable") from exc
    if request.pin_generation != pinned_generation:
        raise DraftWorkerError("pin generation is stale")
    check_generation = _check_generation_path(paths, request.id)
    try:
        consumed_generation = check_generation.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        consumed_generation = ""
    except (OSError, UnicodeDecodeError) as exc:
        raise DraftWorkerError("check generation is unavailable") from exc
    if consumed_generation == request.pin_generation:
        return False
    _write_private(check_generation, request.pin_generation + "\n")
    command = [
        "ssh", "-F", "/dev/null", "-i", OBSERVER_KEY_PATH,
        "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
        "-o", "StrictHostKeyChecking=yes", "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", f"UserKnownHostsFile={known_hosts}", "-p", str(request.port), "--",
        f"{request.ssh_user}@{request.host}", "true",
    ]
    try:
        completed = _run(runner, command)
    except subprocess.TimeoutExpired:
        write_public_result(paths.results_dir, request.id, {"status": "timeout"})
        return True
    if completed.returncode == 0:
        write_public_result(paths.results_dir, request.id, {"status": "ok"})
    else:
        write_public_result(paths.results_dir, request.id, {"status": _ssh_failure_status(completed.stderr)})
    return True


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
        payload.get("action"), payload.get("expected_fingerprint"), payload.get("pin_generation"),
    )


def _candidate_path(paths: DraftPaths, draft_id: str) -> Path:
    return paths.private_dir / f"{draft_id}.candidate"


def _known_hosts_path(paths: DraftPaths, draft_id: str) -> Path:
    return paths.private_dir / f"{draft_id}.known_hosts"


def _pin_generation_path(paths: DraftPaths, draft_id: str) -> Path:
    return paths.private_dir / f"{draft_id}.pin-generation"


def _check_lock_path(paths: DraftPaths, draft_id: str) -> Path:
    return paths.private_dir / f"{draft_id}.check.lock"


def _check_generation_path(paths: DraftPaths, draft_id: str) -> Path:
    return paths.private_dir / f"{draft_id}.check-generation"


def _dispatch_path(paths: DraftPaths, draft_id: str) -> Path:
    return paths.private_dir / f"{draft_id}.dispatch.lock"


def _claim_dispatch(paths: DraftPaths, draft_id: str) -> Path | None:
    paths.private_dir.mkdir(parents=True, exist_ok=True)
    path = _dispatch_path(paths, draft_id)
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        return None
    os.close(descriptor)
    return path


def _release_dispatch(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass


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
    for path in (
        _candidate_path(paths, draft_id),
        _known_hosts_path(paths, draft_id),
        _pin_generation_path(paths, draft_id),
        _check_lock_path(paths, draft_id),
        _check_generation_path(paths, draft_id),
        _dispatch_path(paths, draft_id),
        paths.results_dir / f"{draft_id}.json",
    ):
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def _claim_path(request_path: Path) -> Path:
    return request_path.with_name(f".{request_path.name}.claim")


def _claim_request(request_path: Path) -> Path | None:
    claim_path = _claim_path(request_path)
    try:
        os.link(request_path, claim_path)
    except (FileExistsError, FileNotFoundError):
        return None
    return claim_path


def _mark_deleted(paths: DraftPaths, draft_id: str) -> None:
    terminal_path = paths.queue_dir / f"{draft_id}.deleted"
    try:
        descriptor = os.open(terminal_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o640)
    except FileExistsError:
        return
    os.close(descriptor)


def _release_claim(request_path: Path, claim_path: Path, *, remove_request: bool) -> None:
    if remove_request:
        try:
            if os.path.samefile(request_path, claim_path):
                request_path.unlink()
        except FileNotFoundError:
            pass
    try:
        claim_path.unlink()
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
    process_service_cycle(args.queue_dir, args.results_dir, args.private_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
