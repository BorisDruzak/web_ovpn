import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
import subprocess
from uuid import uuid4

import pytest

from app.config import get_settings, reset_settings_cache
from app.models import ServerDraft
from app import server_draft_worker, server_drafts
from app.server_drafts import (
    create_draft_request,
    make_draft_request,
    observer_public_key,
    read_public_result,
    write_public_result,
)
from app.server_draft_worker import (
    DraftPaths,
    DraftWorkerError,
    process_queue,
    process_request,
)


VALID_FINGERPRINT = "SHA256:" + "Q" * 43
OTHER_FINGERPRINT = "SHA256:" + "R" * 43


@pytest.fixture
def fake_runner():
    from unittest.mock import Mock

    return Mock()


def draft_paths(tmp_path):
    return DraftPaths(tmp_path / "queue", tmp_path / "results", tmp_path / "private")


def draft_request(action, **kwargs):
    if action in {"confirm", "check"}:
        kwargs.setdefault("pin_generation", str(uuid4()))
    return make_draft_request(
        kwargs.pop("draft_id", str(uuid4())),
        kwargs.pop("host", "server.example"),
        kwargs.pop("ssh_user", "observer"),
        kwargs.pop("port", 22),
        action,
        **kwargs,
    )


def completed_scan(output):
    return subprocess.CompletedProcess(["ssh-keyscan"], 0, stdout=output, stderr="")


def seed_pinned_private(paths, request):
    paths.private_dir.mkdir(parents=True, exist_ok=True)
    (paths.private_dir / f"{request.id}.known_hosts").write_text(
        "server.example ssh-ed25519 AAA\n", encoding="utf-8"
    )
    (paths.private_dir / f"{request.id}.pin-generation").write_text(
        f"{request.pin_generation}\n", encoding="utf-8"
    )


def test_scan_returns_only_algorithm_and_fingerprint(tmp_path, fake_runner):
    request = draft_request("scan")
    fake_runner.side_effect = [
        completed_scan("server.example ssh-ed25519 AAA"),
        subprocess.CompletedProcess(["ssh-keygen"], 0, stdout=f"256 {VALID_FINGERPRINT} server\n", stderr=""),
    ]

    process_request(request, draft_paths(tmp_path), fake_runner)

    result = read_public_result(draft_paths(tmp_path).results_dir, request.id)
    assert result["status"] == "pending"
    assert result["fingerprint"].startswith("SHA256:")
    assert "AAA" not in json.dumps(result)


def test_confirm_requires_exact_scanned_fingerprint(tmp_path, fake_runner):
    request = draft_request("confirm", expected_fingerprint=OTHER_FINGERPRINT)
    paths = draft_paths(tmp_path)
    paths.private_dir.mkdir(parents=True)
    (paths.private_dir / f"{request.id}.candidate").write_text(
        "server.example ssh-ed25519 AAA", encoding="utf-8"
    )
    fake_runner.return_value = subprocess.CompletedProcess(
        ["ssh-keygen"], 0, stdout=f"256 {VALID_FINGERPRINT} server\n", stderr=""
    )

    with pytest.raises(DraftWorkerError, match="fingerprint"):
        process_request(request, paths, fake_runner)


def test_confirm_publishes_completed_pin_as_safe_ok_result(tmp_path, fake_runner):
    request = draft_request("confirm", expected_fingerprint=VALID_FINGERPRINT)
    paths = draft_paths(tmp_path)
    paths.private_dir.mkdir(parents=True)
    candidate = "server.example ssh-ed25519 AAA\n"
    (paths.private_dir / f"{request.id}.candidate").write_text(candidate, encoding="utf-8")
    fake_runner.return_value = subprocess.CompletedProcess(
        ["ssh-keygen"], 0, stdout=f"256 {VALID_FINGERPRINT} server\n", stderr="raw private diagnostic"
    )

    process_request(request, paths, fake_runner)

    result = read_public_result(paths.results_dir, request.id)
    assert set(result) == {"status", "fingerprint", "checked_at", "pin_generation"}
    assert result["status"] == "ok"
    assert result["fingerprint"] == VALID_FINGERPRINT
    assert result["pin_generation"] == request.pin_generation
    assert datetime.fromisoformat(result["checked_at"].replace("Z", "+00:00")).tzinfo is not None
    assert (paths.private_dir / f"{request.id}.known_hosts").read_text(encoding="utf-8") == candidate
    assert "AAA" not in json.dumps(result)
    assert "diagnostic" not in json.dumps(result)


def test_check_uses_fixed_true_and_strict_known_host(tmp_path, fake_runner):
    request = draft_request("check")
    paths = draft_paths(tmp_path)
    seed_pinned_private(paths, request)
    fake_runner.return_value = subprocess.CompletedProcess(["ssh"], 0, stdout="", stderr="")

    process_request(request, paths, fake_runner)

    command = fake_runner.call_args.args[0]
    assert command[-1] == "true"
    assert "BatchMode=yes" in command
    assert "StrictHostKeyChecking=yes" in command
    assert "IdentitiesOnly=yes" in command
    assert "IdentityAgent=none" in command
    assert "GlobalKnownHostsFile=/dev/null" in command
    assert "-F" in command
    assert command[command.index("-F") + 1] == "/dev/null"
    assert sum(value.startswith("UserKnownHostsFile=") for value in command) == 1


def test_cleanup_removes_only_the_uuid_private_files(tmp_path, fake_runner):
    request = draft_request("cleanup")
    paths = draft_paths(tmp_path)
    for directory, suffix in ((paths.private_dir, ".candidate"), (paths.private_dir, ".known_hosts")):
        directory.mkdir(parents=True, exist_ok=True)
        (directory / f"{request.id}{suffix}").write_text("private", encoding="utf-8")
    paths.queue_dir.mkdir(parents=True)
    (paths.queue_dir / f"{request.id}.json").write_text("{}", encoding="utf-8")
    paths.results_dir.mkdir(parents=True)
    (paths.results_dir / f"{request.id}.json").write_text("{}", encoding="utf-8")

    process_request(request, paths, fake_runner)

    assert not list(paths.private_dir.glob(f"{request.id}.*"))
    assert (paths.queue_dir / f"{request.id}.json").exists()
    assert not (paths.results_dir / f"{request.id}.json").exists()
    fake_runner.assert_not_called()


def test_cleanup_removes_its_stale_check_lock_without_running_runner(tmp_path, fake_runner):
    request = draft_request("cleanup")
    other_id = str(uuid4())
    paths = draft_paths(tmp_path)
    paths.private_dir.mkdir(parents=True)
    lock_path = paths.private_dir / f"{request.id}.check.lock"
    other_lock_path = paths.private_dir / f"{other_id}.check.lock"
    lock_path.write_text("", encoding="utf-8")
    other_lock_path.write_text("", encoding="utf-8")

    process_request(request, paths, fake_runner)

    assert not lock_path.exists()
    assert other_lock_path.exists()
    fake_runner.assert_not_called()


def test_cleanup_queue_request_ignores_malformed_unrelated_fields(tmp_path, fake_runner):
    draft_id = str(uuid4())
    paths = draft_paths(tmp_path)
    for directory, suffix in ((paths.private_dir, ".candidate"), (paths.private_dir, ".known_hosts")):
        directory.mkdir(parents=True, exist_ok=True)
        (directory / f"{draft_id}{suffix}").write_text("private", encoding="utf-8")
    paths.queue_dir.mkdir(parents=True)
    request_path = paths.queue_dir / f"{draft_id}.cleanup.json"
    request_path.write_text(
        json.dumps({"id": draft_id, "action": "cleanup", "host": None, "ssh_user": "bad;user", "port": 0}),
        encoding="utf-8",
    )
    paths.results_dir.mkdir(parents=True)
    (paths.results_dir / f"{draft_id}.json").write_text('{"status": "pending"}', encoding="utf-8")

    assert process_queue(paths.queue_dir, paths.results_dir, paths.private_dir, fake_runner) == 1

    assert not list(paths.private_dir.glob(f"{draft_id}.*"))
    assert not request_path.exists()
    assert (paths.queue_dir / f"{draft_id}.deleted").is_file()
    assert not (paths.results_dir / f"{draft_id}.json").exists()
    fake_runner.assert_not_called()


def test_cleanup_queue_filename_is_authoritative_over_a_mismatched_payload_id(
    tmp_path, fake_runner
):
    queued_id = str(uuid4())
    injected_id = str(uuid4())
    paths = draft_paths(tmp_path)
    paths.private_dir.mkdir(parents=True)
    queued_private = paths.private_dir / f"{queued_id}.candidate"
    injected_private = paths.private_dir / f"{injected_id}.candidate"
    queued_private.write_text("queued", encoding="utf-8")
    injected_private.write_text("injected", encoding="utf-8")
    paths.queue_dir.mkdir(parents=True)
    (paths.queue_dir / f"{queued_id}.cleanup.json").write_text(
        json.dumps({"id": injected_id, "action": "cleanup"}), encoding="utf-8"
    )

    assert process_queue(paths.queue_dir, paths.results_dir, paths.private_dir, fake_runner) == 1

    assert not queued_private.exists()
    assert injected_private.exists()
    assert (paths.queue_dir / f"{queued_id}.deleted").is_file()
    fake_runner.assert_not_called()


def test_duplicate_check_private_claim_is_not_run_twice(tmp_path, fake_runner):
    request = draft_request("check")
    paths = draft_paths(tmp_path)
    seed_pinned_private(paths, request)
    (paths.private_dir / f"{request.id}.check.lock").write_text("", encoding="utf-8")

    assert process_request(request, paths, fake_runner) == 0
    fake_runner.assert_not_called()
    assert read_public_result(paths.results_dir, request.id) == {"status": "pending"}


def test_check_never_publishes_internal_claim_status(tmp_path, fake_runner):
    request = draft_request("check")
    paths = draft_paths(tmp_path)
    seed_pinned_private(paths, request)
    paths.results_dir.mkdir(parents=True)
    (paths.results_dir / f"{request.id}.json").write_text(
        json.dumps({"status": "pending", "algorithm": "ssh-ed25519", "fingerprint": VALID_FINGERPRINT}),
        encoding="utf-8",
    )

    def runner(*_args, **_kwargs):
        assert read_public_result(paths.results_dir, request.id)["status"] == "pending"
        assert (paths.private_dir / f"{request.id}.check.lock").exists()
        return subprocess.CompletedProcess(["ssh"], 0, stdout="", stderr="")

    process_request(request, paths, runner)

    assert read_public_result(paths.results_dir, request.id) == {"status": "ok"}
    assert not (paths.private_dir / f"{request.id}.check.lock").exists()


def test_timeout_writes_only_safe_category(tmp_path, fake_runner):
    request = draft_request("check")
    paths = draft_paths(tmp_path)
    seed_pinned_private(paths, request)
    fake_runner.side_effect = subprocess.TimeoutExpired(["ssh"], 20, output="raw response")

    process_request(request, paths, fake_runner)

    assert read_public_result(paths.results_dir, request.id) == {"status": "timeout"}


def test_scan_timeout_writes_only_safe_category(tmp_path, fake_runner):
    request = draft_request("scan")
    paths = draft_paths(tmp_path)
    fake_runner.side_effect = subprocess.TimeoutExpired(["ssh-keyscan"], 20, output="raw host key")

    process_request(request, paths, fake_runner)

    assert read_public_result(paths.results_dir, request.id) == {"status": "timeout"}


def test_server_draft_persists_only_public_metadata():
    columns = ServerDraft.__table__.columns

    assert set(columns.keys()) == {
        "id",
        "name",
        "host",
        "ssh_user",
        "port",
        "created_at",
        "updated_at",
    }
    assert columns["id"].type.length == 36
    assert columns["host"].type.length == 253
    assert columns["ssh_user"].type.length == 64
    assert columns["port"].default.arg == 22


def test_settings_define_isolated_draft_paths(monkeypatch):
    monkeypatch.setenv("SERVER_DRAFT_QUEUE_DIR", "/tmp/queue")
    monkeypatch.setenv("SERVER_DRAFT_RESULTS_DIR", "/tmp/results")
    monkeypatch.setenv("SERVER_DRAFT_PRIVATE_DIR", "/tmp/private")
    monkeypatch.setenv("OBSERVER_PUBLIC_KEY_PATH", "/tmp/observer.pub")
    reset_settings_cache()

    try:
        settings = get_settings()

        assert settings.server_draft_queue_dir == Path("/tmp/queue")
        assert settings.server_draft_results_dir == Path("/tmp/results")
        assert settings.server_draft_private_dir == Path("/tmp/private")
        assert settings.observer_public_key_path == Path("/tmp/observer.pub")
    finally:
        reset_settings_cache()


def test_request_rejects_unsafe_components_and_bad_port():
    with pytest.raises(ValueError):
        make_draft_request("not-a-uuid", "host;id", "user", 22, "scan")
    with pytest.raises(ValueError):
        make_draft_request(str(uuid4()), "host", "user", 0, "scan")
    with pytest.raises(ValueError):
        make_draft_request(str(uuid4()), "host", "user", 22, "id;whoami")


def test_queue_is_atomic_and_has_no_private_material(tmp_path, monkeypatch):
    request = make_draft_request(str(uuid4()), "server.example", "observer", 22, "scan")
    chmod_calls = []
    original_chmod = server_drafts.os.chmod

    def record_chmod(path, mode):
        chmod_calls.append(mode)
        original_chmod(path, mode)

    monkeypatch.setattr(server_drafts.os, "chmod", record_chmod)

    path = create_draft_request(tmp_path, request)

    assert path == tmp_path / f"{request.id}.json"
    assert json.loads(path.read_text(encoding="utf-8")) == {
        "action": "scan",
        "host": "server.example",
        "id": request.id,
        "port": 22,
        "ssh_user": "observer",
    }
    assert chmod_calls == [0o640]
    assert "PRIVATE KEY" not in path.read_text(encoding="utf-8")
    assert not list(tmp_path.glob(".*.tmp"))


def test_concurrent_request_publication_reserves_one_action_without_replacement(tmp_path):
    draft_id = str(uuid4())
    scan = make_draft_request(draft_id, "server.example", "observer", 22, "scan")
    check = make_draft_request(
        draft_id, "server.example", "observer", 22, "check", pin_generation=str(uuid4())
    )

    def publish(request):
        try:
            return create_draft_request(tmp_path, request).read_text(encoding="utf-8")
        except FileExistsError:
            return "reserved"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(publish, (scan, check)))

    assert outcomes.count("reserved") == 1
    queued = json.loads((tmp_path / f"{draft_id}.json").read_text(encoding="utf-8"))
    assert queued["action"] in {"scan", "check"}


def test_worker_claim_does_not_unlink_and_drains_a_newer_replacement(tmp_path):
    draft_id = str(uuid4())
    paths = draft_paths(tmp_path)
    create_draft_request(
        paths.queue_dir,
        make_draft_request(draft_id, "server.example", "observer", 22, "scan"),
    )
    replacement = make_draft_request(draft_id, "new.example", "observer", 22, "scan")
    replaced = False
    scanned_hosts = []

    def runner(command, **_kwargs):
        nonlocal replaced
        if command[0] == "ssh-keyscan":
            scanned_hosts.append(command[-1])
            if not replaced:
                (paths.queue_dir / f"{draft_id}.json").unlink()
                create_draft_request(paths.queue_dir, replacement)
                replaced = True
            return completed_scan(f"{command[-1]} ssh-ed25519 AAA")
        return subprocess.CompletedProcess(
            command, 0, stdout=f"256 {VALID_FINGERPRINT} server\n", stderr=""
        )

    assert process_queue(paths.queue_dir, paths.results_dir, paths.private_dir, runner) == 2

    assert scanned_hosts == ["server.example", "new.example"]
    assert not (paths.queue_dir / f"{draft_id}.json").exists()


def test_service_cycle_yields_before_systemd_timeout_and_leaves_visible_backlog(tmp_path):
    draft_id = str(uuid4())
    paths = draft_paths(tmp_path)
    request = make_draft_request(draft_id, "server.example", "observer", 22, "scan")
    create_draft_request(paths.queue_dir, request)
    scans = 0
    clock = [0.0]

    def runner(command, **_kwargs):
        nonlocal scans
        if command[0] == "ssh-keyscan":
            scans += 1
            if scans == 1:
                (paths.queue_dir / f"{draft_id}.json").unlink()
                create_draft_request(paths.queue_dir, request)
            clock[0] += 46.0
            return completed_scan("server.example ssh-ed25519 AAA")
        return subprocess.CompletedProcess(
            command, 0, stdout=f"256 {VALID_FINGERPRINT} server\n", stderr=""
        )

    processed, backlog = server_draft_worker.process_service_cycle(
        paths.queue_dir,
        paths.results_dir,
        paths.private_dir,
        runner,
        monotonic=lambda: clock[0],
        runtime_budget_seconds=50,
    )

    assert (processed, backlog) == (1, True)
    assert scans == 1
    assert (paths.queue_dir / f"{draft_id}.json").is_file()

    clock[0] = 0.0
    processed, backlog = server_draft_worker.process_service_cycle(
        paths.queue_dir,
        paths.results_dir,
        paths.private_dir,
        runner,
        monotonic=lambda: clock[0],
        runtime_budget_seconds=50,
    )
    assert (processed, backlog) == (1, False)
    assert not (paths.queue_dir / f"{draft_id}.json").exists()


def test_worker_main_exits_successfully_when_path_unit_must_reconcile_backlog(tmp_path, monkeypatch):
    paths = draft_paths(tmp_path)
    monkeypatch.setattr(server_draft_worker, "process_service_cycle", lambda *_args: (64, True))

    assert server_draft_worker.main(
        [
            "--queue-dir", str(paths.queue_dir),
            "--results-dir", str(paths.results_dir),
            "--private-dir", str(paths.private_dir),
        ]
    ) == 0


def test_worker_service_cycle_consumes_invalid_cleanup_without_a_path_activation_loop(tmp_path):
    paths = draft_paths(tmp_path)
    paths.queue_dir.mkdir(parents=True)
    (paths.queue_dir / "not-a-uuid.cleanup.json").write_text(
        '{"id":"not-a-uuid","action":"cleanup"}', encoding="utf-8"
    )

    assert server_draft_worker.process_service_cycle(
        paths.queue_dir, paths.results_dir, paths.private_dir
    ) == (0, False)
    assert not list(paths.queue_dir.glob("*.json"))
    assert not list(paths.queue_dir.glob(".*.claim"))


def test_worker_rescans_for_request_arriving_during_processing(tmp_path):
    first_id = str(uuid4())
    second_id = str(uuid4())
    paths = draft_paths(tmp_path)
    create_draft_request(
        paths.queue_dir,
        make_draft_request(first_id, "first.example", "observer", 22, "scan"),
    )

    def runner(command, **_kwargs):
        if command[0] == "ssh-keyscan":
            if command[-1] == "first.example":
                create_draft_request(
                    paths.queue_dir,
                    make_draft_request(second_id, "second.example", "observer", 22, "scan"),
                )
            return completed_scan(f"{command[-1]} ssh-ed25519 AAA")
        return subprocess.CompletedProcess(
            command, 0, stdout=f"256 {VALID_FINGERPRINT} server\n", stderr=""
        )

    assert process_queue(paths.queue_dir, paths.results_dir, paths.private_dir, runner) == 2

    assert not list(paths.queue_dir.glob("*.json"))
    assert read_public_result(paths.results_dir, first_id)["status"] == "pending"
    assert read_public_result(paths.results_dir, second_id)["status"] == "pending"


def test_cleanup_reservation_cancels_pending_normal_request_before_execution(tmp_path, fake_runner):
    draft_id = str(uuid4())
    paths = draft_paths(tmp_path)
    create_draft_request(
        paths.queue_dir,
        make_draft_request(draft_id, "server.example", "observer", 22, "scan"),
    )
    create_draft_request(
        paths.queue_dir,
        make_draft_request(draft_id, "cleanup", "cleanup", 22, "cleanup"),
    )

    assert process_queue(paths.queue_dir, paths.results_dir, paths.private_dir, fake_runner) == 1

    assert not (paths.queue_dir / f"{draft_id}.json").exists()
    assert not (paths.queue_dir / f"{draft_id}.cleanup.json").exists()
    assert (paths.queue_dir / f"{draft_id}.deleted").is_file()
    fake_runner.assert_not_called()


def test_cleanup_arriving_after_claim_but_before_dispatch_cancels_subprocess(
    tmp_path, fake_runner, monkeypatch
):
    draft_id = str(uuid4())
    paths = draft_paths(tmp_path)
    create_draft_request(
        paths.queue_dir,
        make_draft_request(draft_id, "server.example", "observer", 22, "scan"),
    )
    original_claim_dispatch = server_draft_worker._claim_dispatch

    def reserve_then_delete(worker_paths, claimed_id):
        reservation = original_claim_dispatch(worker_paths, claimed_id)
        create_draft_request(
            worker_paths.queue_dir,
            make_draft_request(claimed_id, "cleanup", "cleanup", 22, "cleanup"),
        )
        return reservation

    monkeypatch.setattr(server_draft_worker, "_claim_dispatch", reserve_then_delete)

    assert process_queue(paths.queue_dir, paths.results_dir, paths.private_dir, fake_runner) == 1

    assert (paths.queue_dir / f"{draft_id}.deleted").is_file()
    assert not list(paths.private_dir.glob(f"{draft_id}.*"))
    fake_runner.assert_not_called()


def test_service_cycle_recovers_a_stale_claim_without_a_new_queue_event(tmp_path):
    draft_id = str(uuid4())
    paths = draft_paths(tmp_path)
    request_path = create_draft_request(
        paths.queue_dir,
        make_draft_request(draft_id, "server.example", "observer", 22, "scan"),
    )
    claim_path = server_draft_worker._claim_request(request_path)
    request_path.unlink()
    calls = []

    def runner(command, **_kwargs):
        calls.append(command[0])
        if command[0] == "ssh-keyscan":
            return completed_scan("server.example ssh-ed25519 AAA")
        return subprocess.CompletedProcess(
            command, 0, stdout=f"256 {VALID_FINGERPRINT} server\n", stderr=""
        )

    assert claim_path is not None and claim_path.is_file()
    assert server_draft_worker.process_service_cycle(
        paths.queue_dir, paths.results_dir, paths.private_dir, runner
    ) == (1, False)

    assert calls == ["ssh-keyscan", "ssh-keygen"]
    assert not claim_path.exists()
    assert not request_path.exists()


def test_stale_dispatch_reservation_never_discards_the_durable_request(tmp_path, fake_runner):
    draft_id = str(uuid4())
    paths = draft_paths(tmp_path)
    request_path = create_draft_request(
        paths.queue_dir,
        make_draft_request(draft_id, "server.example", "observer", 22, "scan"),
    )
    paths.private_dir.mkdir(parents=True)
    (paths.private_dir / f"{draft_id}.dispatch.lock").write_text("", encoding="utf-8")

    assert process_queue(paths.queue_dir, paths.results_dir, paths.private_dir, fake_runner) == 0

    assert request_path.is_file()
    fake_runner.assert_not_called()


def test_replayed_check_generation_never_dispatches_ssh_twice(tmp_path, fake_runner):
    request = draft_request("check")
    paths = draft_paths(tmp_path)
    seed_pinned_private(paths, request)
    fake_runner.return_value = subprocess.CompletedProcess(["ssh"], 0, stdout="", stderr="")

    assert process_request(request, paths, fake_runner) == 1
    assert process_request(request, paths, fake_runner) == 0

    assert fake_runner.call_count == 1
    assert (paths.private_dir / f"{request.id}.check-generation").read_text(
        encoding="utf-8"
    ).strip() == request.pin_generation


def test_cleanup_intent_survives_an_active_request_and_becomes_terminal(tmp_path):
    draft_id = str(uuid4())
    paths = draft_paths(tmp_path)
    create_draft_request(
        paths.queue_dir,
        make_draft_request(draft_id, "server.example", "observer", 22, "scan"),
    )

    def runner(command, **_kwargs):
        if command[0] == "ssh-keyscan":
            create_draft_request(
                paths.queue_dir,
                make_draft_request(draft_id, "cleanup", "cleanup", 22, "cleanup"),
            )
            return completed_scan("server.example ssh-ed25519 AAA")
        return subprocess.CompletedProcess(
            command, 0, stdout=f"256 {VALID_FINGERPRINT} server\n", stderr=""
        )

    assert process_queue(paths.queue_dir, paths.results_dir, paths.private_dir, runner) == 2

    assert not (paths.queue_dir / f"{draft_id}.json").exists()
    assert not (paths.queue_dir / f"{draft_id}.cleanup.json").exists()
    assert (paths.queue_dir / f"{draft_id}.deleted").is_file()
    assert not (paths.results_dir / f"{draft_id}.json").exists()
    assert not list(paths.private_dir.glob(f"{draft_id}.*"))


@pytest.mark.parametrize(
    "payload",
    [
        {"status": "ok", "fingerprint": VALID_FINGERPRINT, "checked_at": "2026-07-19T00:00:00Z"},
        {
            "status": "ok",
            "fingerprint": "SHA256:short",
            "checked_at": "2026-07-19T00:00:00.000000Z",
            "pin_generation": str(uuid4()),
        },
        {
            "status": "ok",
            "fingerprint": VALID_FINGERPRINT,
            "checked_at": "2026-07-19T05:00:00+05:00",
            "pin_generation": str(uuid4()),
        },
        {"status": "transport", "stderr": "private"},
    ],
)
def test_public_result_rejects_noncanonical_or_nonexact_worker_projection(tmp_path, payload):
    draft_id = str(uuid4())
    (tmp_path / f"{draft_id}.json").write_text(json.dumps(payload), encoding="utf-8")

    assert read_public_result(tmp_path, draft_id) == {"status": "invalid_response"}
    with pytest.raises(ValueError):
        write_public_result(tmp_path, draft_id, payload)


def test_completed_pin_projection_requires_and_preserves_generation(tmp_path):
    draft_id = str(uuid4())
    generation = str(uuid4())
    result = {
        "status": "ok",
        "fingerprint": VALID_FINGERPRINT,
        "checked_at": "2026-07-19T00:00:00.000000Z",
        "pin_generation": generation,
    }

    write_public_result(tmp_path, draft_id, result)

    assert read_public_result(tmp_path, draft_id) == result


def test_public_result_rejects_host_key_and_stderr_instead_of_projecting_them(tmp_path):
    draft_id = str(uuid4())
    (tmp_path / f"{draft_id}.json").write_text(
        json.dumps(
            {
                "status": "transport",
                "stderr": "raw",
                "host_key": "ssh-ed25519 AAA",
                "algorithm": "ssh-ed25519",
                "fingerprint": "SHA256:public",
                "checked_at": "2026-07-19T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )

    assert read_public_result(tmp_path, draft_id) == {"status": "invalid_response"}


def test_public_helpers_reject_private_or_unsafe_inputs(tmp_path):
    with pytest.raises(ValueError):
        read_public_result(tmp_path, "not-a-uuid")

    public_key = tmp_path / "observer.pub"
    public_key.write_text("ssh-ed25519 AAA observer\n", encoding="utf-8")
    assert observer_public_key(public_key) == "ssh-ed25519 AAA observer\n"

    public_key.write_text("-----BEGIN PRIVATE KEY-----\nraw\n", encoding="utf-8")
    with pytest.raises(ValueError):
        observer_public_key(public_key)
