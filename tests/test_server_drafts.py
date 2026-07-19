import json
from pathlib import Path
import subprocess
from uuid import uuid4

import pytest

from app.config import get_settings, reset_settings_cache
from app.models import ServerDraft
from app import server_drafts
from app.server_drafts import (
    create_draft_request,
    make_draft_request,
    observer_public_key,
    read_public_result,
)
from app.server_draft_worker import (
    DraftPaths,
    DraftWorkerError,
    process_request,
)


@pytest.fixture
def fake_runner():
    from unittest.mock import Mock

    return Mock()


def draft_paths(tmp_path):
    return DraftPaths(tmp_path / "queue", tmp_path / "results", tmp_path / "private")


def draft_request(action, **kwargs):
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


def test_scan_returns_only_algorithm_and_fingerprint(tmp_path, fake_runner):
    request = draft_request("scan")
    fake_runner.side_effect = [
        completed_scan("server.example ssh-ed25519 AAA"),
        subprocess.CompletedProcess(["ssh-keygen"], 0, stdout="256 SHA256:scanned server\n", stderr=""),
    ]

    process_request(request, draft_paths(tmp_path), fake_runner)

    result = read_public_result(draft_paths(tmp_path).results_dir, request.id)
    assert result["status"] == "pending"
    assert result["fingerprint"].startswith("SHA256:")
    assert "AAA" not in json.dumps(result)


def test_confirm_requires_exact_scanned_fingerprint(tmp_path, fake_runner):
    request = draft_request("confirm", expected_fingerprint="SHA256:other")
    paths = draft_paths(tmp_path)
    paths.private_dir.mkdir(parents=True)
    (paths.private_dir / f"{request.id}.candidate").write_text(
        "server.example ssh-ed25519 AAA", encoding="utf-8"
    )
    fake_runner.return_value = subprocess.CompletedProcess(
        ["ssh-keygen"], 0, stdout="256 SHA256:scanned server\n", stderr=""
    )

    with pytest.raises(DraftWorkerError, match="fingerprint"):
        process_request(request, paths, fake_runner)


def test_check_uses_fixed_true_and_strict_known_host(tmp_path, fake_runner):
    request = draft_request("check")
    paths = draft_paths(tmp_path)
    paths.private_dir.mkdir(parents=True)
    (paths.private_dir / f"{request.id}.known_hosts").write_text(
        "server.example ssh-ed25519 AAA\n", encoding="utf-8"
    )
    fake_runner.return_value = subprocess.CompletedProcess(["ssh"], 0, stdout="", stderr="")

    process_request(request, paths, fake_runner)

    command = fake_runner.call_args.args[0]
    assert command[-1] == "true"
    assert "BatchMode=yes" in command
    assert "StrictHostKeyChecking=yes" in command


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
    assert not (paths.queue_dir / f"{request.id}.json").exists()
    assert not (paths.results_dir / f"{request.id}.json").exists()
    fake_runner.assert_not_called()


def test_duplicate_check_is_not_run_twice(tmp_path, fake_runner):
    request = draft_request("check")
    paths = draft_paths(tmp_path)
    paths.results_dir.mkdir(parents=True)
    (paths.results_dir / f"{request.id}.json").write_text('{"status": "checking"}', encoding="utf-8")

    assert process_request(request, paths, fake_runner) == 0
    fake_runner.assert_not_called()


def test_timeout_writes_only_safe_category(tmp_path, fake_runner):
    request = draft_request("check")
    paths = draft_paths(tmp_path)
    paths.private_dir.mkdir(parents=True)
    (paths.private_dir / f"{request.id}.known_hosts").write_text(
        "server.example ssh-ed25519 AAA\n", encoding="utf-8"
    )
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


def test_public_result_removes_host_key_and_stderr(tmp_path):
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

    assert read_public_result(tmp_path, draft_id) == {
        "status": "transport",
        "algorithm": "ssh-ed25519",
        "fingerprint": "SHA256:public",
        "checked_at": "2026-07-19T00:00:00Z",
    }


def test_public_helpers_reject_private_or_unsafe_inputs(tmp_path):
    with pytest.raises(ValueError):
        read_public_result(tmp_path, "not-a-uuid")

    public_key = tmp_path / "observer.pub"
    public_key.write_text("ssh-ed25519 AAA observer\n", encoding="utf-8")
    assert observer_public_key(public_key) == "ssh-ed25519 AAA observer\n"

    public_key.write_text("-----BEGIN PRIVATE KEY-----\nraw\n", encoding="utf-8")
    with pytest.raises(ValueError):
        observer_public_key(public_key)
