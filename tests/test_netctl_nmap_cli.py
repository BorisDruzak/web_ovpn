from __future__ import annotations

import json
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest


ASSET_KEY = "mac:AA:BB:CC:DD:EE:01"


def _db_url(tmp_path: Path) -> str:
    return f"sqlite:///{(tmp_path / 'nmap-cli.sqlite').as_posix()}"


def _seed_asset(db_url: str) -> None:
    from netctl.db import connect

    conn = connect(db_url)
    now = "2026-08-09T08:00:00Z"
    try:
        asset_id = conn.execute(
            """INSERT INTO assets
               (asset_key, identity_method, identity_confidence, provisional,
                first_seen_at, last_seen_at, created_at, updated_at)
               VALUES (?, 'manual', 100, 0, ?, ?, ?, ?)""",
            (ASSET_KEY, now, now, now, now),
        ).lastrowid
        conn.execute(
            """INSERT INTO ip_observations
               (asset_id, source_key, ip, first_seen_at, last_seen_at,
                is_current, observation_source)
               VALUES (?, 'source-a', '192.168.100.55', ?, ?, 1, 'collector_host')""",
            (asset_id, now, now),
        )
        conn.commit()
    finally:
        conn.close()


def _run_cli(args: list[str], capsys) -> tuple[int, dict[str, object]]:
    from netctl.cli import main

    rc = main(args)
    captured = capsys.readouterr()
    assert captured.err == ""
    return rc, json.loads(captured.out)


def _empty_fingerprint():
    from netctl.nmap.models import NmapFingerprint

    return NmapFingerprint(nmap_version="7.95", ports=(), os_matches=())


@pytest.mark.parametrize(
    "arguments",
    [
        ["fingerprint", "ensure", "--asset-key", ASSET_KEY, "--ip", "192.168.1.1"],
        ["fingerprint", "ensure", "--asset-key", ASSET_KEY, "--ports", "1-65535"],
        ["fingerprint", "ensure", "--asset-key", ASSET_KEY, "--script", "default"],
        ["fingerprint", "all"],
        ["fingerprint", "subnet", "192.168.1.0/24"],
    ],
)
def test_fingerprint_parser_has_no_ip_profile_or_network_wide_inputs(
    arguments: list[str],
) -> None:
    """Adding any caller-controlled target/profile argument would widen scan scope."""
    from netctl.cli import build_parser

    with pytest.raises(SystemExit):
        build_parser().parse_args(arguments)


def test_fingerprint_status_reports_not_run_without_starting_scan(
    tmp_path: Path, capsys
) -> None:
    db_url = _db_url(tmp_path)
    _seed_asset(db_url)

    rc, payload = _run_cli(
        ["--json", "--db", db_url, "fingerprint", "status", "--asset-key", ASSET_KEY],
        capsys,
    )

    assert rc == 0
    assert payload["status"] == "ok"
    assert payload["fingerprint"] == {
        "asset_key": ASSET_KEY,
        "target_ip": "192.168.100.55",
        "profile": "asset-fingerprint-v1",
        "status": "not_run",
        "fresh": False,
        "ports": [],
        "os_matches": [],
    }


def test_fingerprint_ensure_executes_only_the_resolved_asset_ip(
    tmp_path: Path, capsys, monkeypatch
) -> None:
    import netctl.cli as cli

    db_url = _db_url(tmp_path)
    _seed_asset(db_url)
    targets: list[str] = []
    monkeypatch.setattr(
        cli,
        "run_nmap_fingerprint",
        lambda ip: targets.append(ip) or _empty_fingerprint(),
    )

    rc, payload = _run_cli(
        ["--json", "--db", db_url, "fingerprint", "ensure", "--asset-key", ASSET_KEY],
        capsys,
    )

    assert rc == 0
    assert payload["status"] == "ok"
    assert payload["fingerprint"]["status"] == "success"
    assert targets == ["192.168.100.55"]


def test_fingerprint_ensure_returns_sanitized_failure(
    tmp_path: Path, capsys, monkeypatch
) -> None:
    import netctl.cli as cli
    from netctl.nmap.runner import NmapRunnerError

    db_url = _db_url(tmp_path)
    _seed_asset(db_url)
    monkeypatch.setattr(
        cli,
        "run_nmap_fingerprint",
        lambda _ip: (_ for _ in ()).throw(
            NmapRunnerError("scan_failed", "private raw stderr")
        ),
    )

    rc, payload = _run_cli(
        ["--json", "--db", db_url, "fingerprint", "ensure", "--asset-key", ASSET_KEY],
        capsys,
    )

    assert rc == 1
    assert payload["status"] == "error"
    assert payload["message"] == "fingerprint failed"
    assert payload["fingerprint"]["error_message"] == "fingerprint helper failed"
    assert "private" not in repr(payload)


def test_fingerprint_timing_configuration_is_bounded_and_immutable() -> None:
    from netctl.nmap.policy import configured_fingerprint_profile

    profile = configured_fingerprint_profile(
        {
            "NETCTL_NMAP_TTL_SECONDS": "120",
            "NETCTL_NMAP_STALE_RUNNING_SECONDS": "45",
        }
    )

    assert profile.ttl_seconds == 120
    assert profile.stale_running_seconds == 45
    with pytest.raises(FrozenInstanceError):
        profile.ttl_seconds = 1  # type: ignore[misc]
    with pytest.raises(ValueError, match="NETCTL_NMAP_TTL_SECONDS"):
        configured_fingerprint_profile({"NETCTL_NMAP_TTL_SECONDS": "0"})
    with pytest.raises(ValueError, match="NETCTL_NMAP_STALE_RUNNING_SECONDS"):
        configured_fingerprint_profile({"NETCTL_NMAP_STALE_RUNNING_SECONDS": "30"})


def test_asset_context_projects_stored_fingerprint_without_raw_fields(tmp_path: Path) -> None:
    from netctl.context_query import inspect_asset_context
    from netctl.db import connect
    from netctl.nmap.store import ensure_fingerprint

    db_url = _db_url(tmp_path)
    _seed_asset(db_url)
    conn = connect(db_url)
    try:
        ensure_fingerprint(
            conn,
            ASSET_KEY,
            executor=lambda _ip: _empty_fingerprint(),
            now="2026-08-09T08:00:00Z",
        )
        context = inspect_asset_context(conn, ASSET_KEY)
    finally:
        conn.close()

    assert context is not None
    assert context["fingerprint"]["status"] == "success"
    assert context["fingerprint"]["target_ip"] == "192.168.100.55"
    assert "raw_xml" not in repr(context["fingerprint"])
    assert "stderr" not in repr(context["fingerprint"])
