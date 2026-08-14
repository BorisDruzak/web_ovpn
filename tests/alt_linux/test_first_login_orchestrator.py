from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest


RECONCILE_PATH = (
    Path(__file__).resolve().parents[2]
    / "deploy"
    / "alt-linux"
    / "api"
    / "reconcile_first_login.py"
)


def _load_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "reconcile_first_login_under_test",
        RECONCILE_PATH,
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _record(root: Path) -> Path:
    path = root / "53b03180-5d78-11f0-bd95-f027db877a00.json"
    path.write_text(
        json.dumps(
            {
                "machine_uuid": "53b03180-5d78-11f0-bd95-f027db877a00",
                "ip": "192.168.101.56",
                "request": {"assigned_domain_user": "alt-test-2@sosnadmin.local"},
                "status": "awaiting_first_domain_login",
            }
        ),
        encoding="utf-8",
    )
    return path


def test_first_login_worker_waits_without_modifying_before_home_exists(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_module()
    path = _record(tmp_path)
    monkeypatch.setattr(module, "first_login_root", lambda: tmp_path)
    monkeypatch.setattr(
        module,
        "run_user_stage",
        lambda record: (False, "desktop_shortcuts_user_home_unavailable"),
    )

    module.reconcile()

    assert json.loads(path.read_text(encoding="utf-8"))["status"] == (
        "awaiting_first_domain_login"
    )


def test_first_login_worker_marks_profile_ready_only_after_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_module()
    path = _record(tmp_path)
    monkeypatch.setattr(module, "first_login_root", lambda: tmp_path)
    monkeypatch.setattr(module, "run_user_stage", lambda record: (True, None))

    module.reconcile()

    result = json.loads(path.read_text(encoding="utf-8"))
    assert result["status"] == "ready"
    assert result["profile_finalized"] is True


def test_first_login_worker_preserves_retryable_transport_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_module()
    path = _record(tmp_path)
    monkeypatch.setattr(module, "first_login_root", lambda: tmp_path)
    monkeypatch.setattr(
        module,
        "run_user_stage",
        lambda record: (False, "first_login_transport_unavailable"),
    )

    module.reconcile()

    assert json.loads(path.read_text(encoding="utf-8"))["status"] == (
        "awaiting_first_domain_login"
    )


def test_first_login_worker_records_only_safe_terminal_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_module()
    path = _record(tmp_path)
    monkeypatch.setattr(module, "first_login_root", lambda: tmp_path)
    monkeypatch.setattr(
        module,
        "run_user_stage",
        lambda record: (False, "remote_access_profile_invalid"),
    )

    module.reconcile()

    result = json.loads(path.read_text(encoding="utf-8"))
    assert result["status"] == "failed"
    assert result["error"] == "remote_access_profile_invalid"
