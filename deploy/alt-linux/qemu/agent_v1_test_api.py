#!/usr/bin/env python3
"""Disposable controller fixture and evidence gates for agent-v1 QEMU tests."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import signal
import socket
import struct
import sys
import threading
import time
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, NoReturn, Sequence

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


REPO_ROOT = Path(__file__).resolve().parents[3]
CONTROL_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "control"
API_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "api"
PROFILE_ROOT = (
    REPO_ROOT / "deploy" / "alt-linux" / "autoinstall" / "profiles"
)
for package_root in (CONTROL_ROOT, API_ROOT):
    if str(package_root) not in sys.path:
        sys.path.insert(0, str(package_root))

from alt_deploy.config import Settings
from alt_deploy.errors import ControlError
from alt_deploy.install_session_approval import InstallSessionApprovalService
from alt_deploy.install_session_repository import InstallSessionRepository
from alt_deploy.install_session_signing import public_key_metadata
from install_session_api import create_install_session_server


PASS_LINE = (
    "PASS: signed plan verified; disk preflight passed; no target writes"
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
KEY_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SESSION_ID_RE = re.compile(r"^install-[A-Za-z0-9-]{4,64}$")
MAX_EVIDENCE_BYTES = 4 * 1024 * 1024


class AcceptanceError(RuntimeError):
    """A bounded, non-secret acceptance failure."""


def _fail(message: str) -> NoReturn:
    raise AcceptanceError(message)


def _read_bytes(path: Path, *, maximum: int = MAX_EVIDENCE_BYTES) -> bytes:
    try:
        metadata = path.stat()
        if not path.is_file() or metadata.st_size < 1 or metadata.st_size > maximum:
            _fail(f"Evidence file is invalid: {path.name}")
        return path.read_bytes()
    except OSError as exc:
        raise AcceptanceError(
            f"Evidence file cannot be read: {path.name}"
        ) from exc


def _read_json(path: Path) -> dict[str, object]:
    try:
        document = json.loads(_read_bytes(path).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AcceptanceError(
            f"Evidence JSON is invalid: {path.name}"
        ) from exc
    if not isinstance(document, dict):
        _fail(f"Evidence JSON must be an object: {path.name}")
    return document


def _json_bytes(document: object) -> bytes:
    return (
        json.dumps(document, ensure_ascii=True, sort_keys=True, indent=2)
        + "\n"
    ).encode("utf-8")


def _write_new(path: Path, content: bytes, *, mode: int) -> None:
    if not path.parent.is_dir():
        _fail(f"Output parent directory is missing: {path.parent}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        descriptor = os.open(path, flags, mode)
    except OSError as exc:
        raise AcceptanceError(
            f"Refusing to overwrite output: {path}"
        ) from exc
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)
    os.chmod(path, mode)


def _replace_private_json(path: Path, document: object) -> None:
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    if temporary.exists():
        _fail("Private fixture temporary file already exists")
    _write_new(temporary, _json_bytes(document), mode=0o600)
    os.replace(temporary, path)
    os.chmod(path, 0o600)


def _fixture_paths(state_dir: Path) -> dict[str, Path]:
    return {
        "private_key": state_dir / "install-plan-ed25519.pem",
        "public_key": state_dir / "install-plan-ed25519.pub",
        "sessions": state_dir / "sessions",
        "lock": state_dir / "sessions.lock",
        "events": state_dir / "fixture-events.json",
        "ready": state_dir / "server.ready",
    }


def prepare_fixture(state_dir: Path) -> None:
    if not state_dir.is_dir():
        _fail("Fixture state directory must already exist")
    if any(state_dir.iterdir()):
        _fail("Fixture state directory must be empty")
    os.chmod(state_dir, 0o700)
    paths = _fixture_paths(state_dir)
    paths["sessions"].mkdir(mode=0o700)

    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    _write_new(paths["private_key"], private_bytes, mode=0o600)
    _write_new(
        paths["public_key"],
        _json_bytes(public_key_metadata(private_key.public_key())),
        mode=0o644,
    )
    _replace_private_json(paths["events"], {"events": []})
    print(f"prepared_fixture={state_dir}")
    print(f"public_key={paths['public_key']}")


def require_real_root(effective_uid: int | None = None) -> None:
    if effective_uid is None:
        effective_uid = os.geteuid() if hasattr(os, "geteuid") else -1
    if effective_uid != 0:
        raise RuntimeError(
            "real root approval is required for the QEMU test fixture"
        )


def _settings(state_dir: Path) -> Settings:
    paths = _fixture_paths(state_dir)
    return replace(
        Settings.from_env(),
        install_sessions_dir=paths["sessions"],
        install_sessions_lock=paths["lock"],
        install_profile_root=PROFILE_ROOT,
        install_signing_private_key=paths["private_key"],
        install_signing_public_key=paths["public_key"],
    )


def _validate_prepared_fixture(state_dir: Path) -> None:
    paths = _fixture_paths(state_dir)
    if not state_dir.is_dir():
        _fail("Fixture state directory is missing")
    for name in ("private_key", "public_key"):
        if not paths[name].is_file():
            _fail(f"Prepared fixture is missing {name}")
    if not paths["sessions"].is_dir():
        _fail("Prepared fixture is missing sessions directory")


def _append_event(
    paths: dict[str, Path],
    events: list[dict[str, object]],
    event: dict[str, object],
) -> None:
    events.append(event)
    _replace_private_json(paths["events"], {"events": events})


def serve_fixture(state_dir: Path, listen_address: str, listen_port: int) -> None:
    require_real_root()
    if listen_address != "127.0.0.1" or listen_port != 18089:
        _fail("The QEMU fixture may listen only on 127.0.0.1:18089")
    _validate_prepared_fixture(state_dir)
    settings = _settings(state_dir)
    paths = _fixture_paths(state_dir)
    repository = InstallSessionRepository(settings)
    approval = InstallSessionApprovalService(
        settings,
        repository=repository,
        clock=lambda: datetime.now(timezone.utc).isoformat(),
    )
    events: list[dict[str, object]] = []
    stop = threading.Event()

    def request_stop(_signum: int, _frame: object) -> None:
        stop.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    try:
        server = create_install_session_server(
            settings,
            listen_address=listen_address,
            listen_port=listen_port,
        )
    except OSError as exc:
        raise AcceptanceError(
            "Test API could not bind 127.0.0.1:18089"
        ) from exc
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    _write_new(
        paths["ready"],
        f"{os.getpid()}\n".encode("ascii"),
        mode=0o600,
    )
    print(
        "READY: disposable test API listening on 127.0.0.1:18089",
        flush=True,
    )
    observed: set[tuple[str, int, str]] = set()
    approved: set[str] = set()
    try:
        while not stop.wait(0.2):
            for status in repository.list_statuses():
                session_id = str(status.get("session_id", ""))
                if not SESSION_ID_RE.fullmatch(session_id):
                    _fail("Fixture observed an invalid session identifier")
                agent_status = status.get("agent_status")
                if isinstance(agent_status, dict):
                    sequence = agent_status.get("sequence")
                    reported_stage = agent_status.get("reported_stage")
                    if type(sequence) is int and isinstance(
                        reported_stage, str
                    ):
                        event_key = (session_id, sequence, reported_stage)
                        if event_key not in observed:
                            _append_event(
                                paths,
                                events,
                                {
                                    "event": "heartbeat",
                                    "reported_stage": reported_stage,
                                    "sequence": sequence,
                                    "session_id": session_id,
                                },
                            )
                            observed.add(event_key)
                else:
                    reported_stage = None
                if (
                    status.get("state") == "awaiting_approval"
                    and reported_stage == "waiting_for_approval"
                    and session_id not in approved
                ):
                    preview = approval.preview(session_id)
                    target = preview.get("target_disk")
                    if not isinstance(target, dict):
                        _fail("Approval preview omitted the target disk")
                    published = approval.approve(
                        session_id,
                        inventory_sha256=preview.get("inventory_sha256"),
                        disk_fingerprint_value=target.get("fingerprint"),
                        reason=(
                            "Approved disposable QEMU dry-run target; "
                            "no installation handoff"
                        ),
                    )
                    approval_record = repository.load_approval(session_id)
                    if (
                        published.get("state") != "plan_published"
                        or approval_record.get("operator_uid") != 0
                    ):
                        _fail("Fixture root approval did not publish a plan")
                    _append_event(
                        paths,
                        events,
                        {
                            "event": "root_approval",
                            "operator_uid": approval_record["operator_uid"],
                            "plan_revision": published.get("plan_revision"),
                            "session_id": session_id,
                        },
                    )
                    approved.add(session_id)
    except ControlError as exc:
        raise AcceptanceError(
            f"Controller fixture rejected the acceptance sequence: {exc.code}"
        ) from exc
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def export_fixture_evidence(
    state_dir: Path,
    output: Path,
    expected_sessions: int,
) -> None:
    _validate_prepared_fixture(state_dir)
    settings = _settings(state_dir)
    repository = InstallSessionRepository(settings)
    public_document = _read_json(_fixture_paths(state_dir)["public_key"])
    key_id = public_document.get("key_id")
    if not isinstance(key_id, str) or not KEY_ID_RE.fullmatch(key_id):
        _fail("Fixture public key identifier is invalid")
    statuses = repository.list_statuses()
    if len(statuses) != expected_sessions:
        _fail(
            "Fixture session count differs from the two QEMU variants"
        )
    sessions: list[dict[str, object]] = []
    for status in statuses:
        session_id = str(status.get("session_id", ""))
        agent_status = status.get("agent_status")
        approval = repository.load_approval(session_id)
        reported_stage = (
            agent_status.get("reported_stage")
            if isinstance(agent_status, dict)
            else None
        )
        record = {
            "operator_uid": approval.get("operator_uid"),
            "plan_revision": status.get("plan_revision"),
            "reported_stage": reported_stage,
            "root_approved": approval.get("operator_uid") == 0,
            "session_id": session_id,
            "state": status.get("state"),
        }
        if (
            not SESSION_ID_RE.fullmatch(session_id)
            or record["operator_uid"] != 0
            or record["plan_revision"] != 1
            or record["reported_stage"] != "preflight_ready"
            or record["root_approved"] is not True
            or record["state"] != "plan_published"
        ):
            _fail(
                "Fixture session did not reach root-approved preflight_ready"
            )
        sessions.append(record)
    sessions.sort(key=lambda item: str(item["session_id"]))
    _write_new(
        output,
        _json_bytes({"public_key_id": key_id, "sessions": sessions}),
        mode=0o644,
    )


def _qmp_write_graph(
    node: dict[str, object],
    *,
    graph_path: str,
) -> dict[str, dict[str, int]]:
    stats = node.get("stats")
    if not isinstance(stats, dict):
        _fail(f"QMP target statistics are absent at {graph_path}")
    counters: dict[str, int] = {}
    for key, value in stats.items():
        if not isinstance(key, str) or not key.startswith("wr_"):
            continue
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            _fail(f"QMP target write counter is invalid at {graph_path}")
        counters[key] = value
    if not {"wr_bytes", "wr_operations"}.issubset(counters):
        _fail(
            f"QMP mandatory target write counters are absent at {graph_path}"
        )
    for key, value in counters.items():
        if value != 0:
            _fail(
                "non-zero QMP target write counter: "
                f"{graph_path}.{key}={value}"
            )
    graph = {graph_path: dict(sorted(counters.items()))}
    for relation in ("parent", "backing"):
        child = node.get(relation)
        if child is None:
            continue
        if not isinstance(child, dict):
            _fail(f"QMP target {relation} statistics are invalid")
        graph.update(
            _qmp_write_graph(
                child,
                graph_path=f"{graph_path}.{relation}",
            )
        )
    return graph


def _validate_qmp_topology(
    graph: dict[str, dict[str, int]],
    *,
    backing_depth: int,
) -> None:
    format_path = "target"
    for _ in range(backing_depth + 1):
        if format_path not in graph:
            _fail(
                "QMP backing statistics do not match query-block depth"
            )
        parent_path = f"{format_path}.parent"
        if parent_path not in graph:
            _fail(
                f"QMP {format_path} parent statistics are absent"
            )
        format_path = f"{format_path}.backing"
    if format_path in graph:
        _fail("QMP backing statistics do not match query-block depth")


def _read_qmp_snapshot(
    path: Path,
    device: str,
) -> tuple[dict[str, dict[str, int]], bool, int]:
    try:
        text = _read_bytes(path).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AcceptanceError(
            f"QMP transcript is not UTF-8: {path.name}"
        ) from exc
    stats_matches: list[dict[str, object]] = []
    block_matches: list[dict[str, object]] = []
    for line in text.splitlines():
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError as exc:
            raise AcceptanceError(
                f"QMP transcript contains invalid JSON: {path.name}"
            ) from exc
        if not isinstance(message, dict):
            _fail(f"QMP transcript message is invalid: {path.name}")
        returned = message.get("return")
        if not isinstance(returned, list):
            continue
        stats_candidates = [
            item
            for item in returned
            if (
                isinstance(item, dict)
                and item.get("device") == device
                and isinstance(item.get("stats"), dict)
            )
        ]
        block_candidates = [
            item
            for item in returned
            if (
                isinstance(item, dict)
                and item.get("device") == device
                and isinstance(item.get("inserted"), dict)
            )
        ]
        if len(stats_candidates) > 1 or len(block_candidates) > 1:
            _fail("QMP target device is ambiguous")
        stats_matches.extend(stats_candidates)
        block_matches.extend(block_candidates)
    if not stats_matches and not block_matches:
        _fail("QMP target device is absent")
    if len(stats_matches) != 1:
        _fail("QMP target block statistics are absent")
    if len(block_matches) != 1:
        _fail("QMP target query-block evidence is absent")
    inserted = block_matches[0]["inserted"]
    if not isinstance(inserted, dict):
        _fail("QMP target inserted information is invalid")
    read_only = inserted.get("ro")
    backing_depth = inserted.get("backing_file_depth")
    if not isinstance(read_only, bool):
        _fail("QMP target inserted read-only state is invalid")
    if (
        isinstance(backing_depth, bool)
        or not isinstance(backing_depth, int)
        or not 0 <= backing_depth <= 16
    ):
        _fail("QMP target backing depth is invalid")
    if inserted.get("drv") != "qcow2":
        _fail("QMP target is not qcow2")
    graph = _qmp_write_graph(stats_matches[0], graph_path="target")
    _validate_qmp_topology(graph, backing_depth=backing_depth)
    return graph, read_only, backing_depth


def _read_sha256_record(path: Path) -> str:
    try:
        lines = [
            line
            for line in _read_bytes(path, maximum=4096)
            .decode("ascii")
            .splitlines()
            if line
        ]
    except UnicodeDecodeError as exc:
        raise AcceptanceError("SHA-256 record is not ASCII") from exc
    if len(lines) != 1:
        _fail("SHA-256 record must contain exactly one line")
    digest = lines[0].split(maxsplit=1)[0]
    if not SHA256_RE.fullmatch(digest):
        _fail("SHA-256 record is invalid")
    return digest


def verify_variant(
    *,
    variant: str,
    before_qmp: Path,
    after_qmp: Path,
    before_sha: Path,
    after_sha: Path,
    output: Path,
) -> None:
    if variant not in {"writable", "readonly"}:
        _fail("QEMU variant is invalid")
    before_graph, before_read_only, before_depth = _read_qmp_snapshot(
        before_qmp, "target"
    )
    after_graph, after_read_only, after_depth = _read_qmp_snapshot(
        after_qmp, "target"
    )
    expected_read_only = variant == "readonly"
    expected_depth = 0 if expected_read_only else 1
    if before_read_only != expected_read_only or (
        after_read_only != expected_read_only
    ):
        _fail(
            "readonly QEMU variant is not read-only"
            if expected_read_only
            else "writable QEMU variant is unexpectedly read-only"
        )
    if before_depth != expected_depth or after_depth != expected_depth:
        _fail(
            "QMP backing depth does not match the disposable "
            f"{variant} topology"
        )
    before_digest = _read_sha256_record(before_sha)
    after_digest = _read_sha256_record(after_sha)
    if before_digest != after_digest:
        _fail("Backing SHA-256 changed")
    summary = {
        "backing_sha256": before_digest,
        "device": "target",
        "qmp_write_counters_after": after_graph["target"],
        "qmp_write_counters_before": before_graph["target"],
        "qmp_backing_depth_after": after_depth,
        "qmp_backing_depth_before": before_depth,
        "qmp_inserted_read_only_after": after_read_only,
        "qmp_inserted_read_only_before": before_read_only,
        "qmp_write_graph_after": after_graph,
        "qmp_write_graph_before": before_graph,
        "variant": variant,
        "zero_target_writes": True,
    }
    _write_new(output, _json_bytes(summary), mode=0o644)


def finalize_evidence(
    *,
    variant_summaries: Sequence[Path],
    fixture_report: Path,
    output: Path,
) -> None:
    variants: dict[str, dict[str, object]] = {}
    for path in variant_summaries:
        summary = _read_json(path)
        variant = summary.get("variant")
        if not isinstance(variant, str) or variant in variants:
            _fail("Variant evidence is invalid or duplicated")
        if (
            summary.get("zero_target_writes") is not True
            or summary.get("device") != "target"
            or not isinstance(summary.get("backing_sha256"), str)
            or not SHA256_RE.fullmatch(str(summary["backing_sha256"]))
        ):
            _fail("Variant zero-write evidence is incomplete")
        for field in ("qmp_write_graph_before", "qmp_write_graph_after"):
            graph = summary.get(field)
            if not isinstance(graph, dict) or "target" not in graph:
                _fail("Variant QMP graph counters are incomplete")
            for graph_path, counters in graph.items():
                if (
                    not isinstance(graph_path, str)
                    or not isinstance(counters, dict)
                    or not {"wr_bytes", "wr_operations"}.issubset(counters)
                    or any(
                        isinstance(value, bool)
                        or not isinstance(value, int)
                        or value != 0
                        for value in counters.values()
                    )
                ):
                    _fail("Variant QMP graph counters are incomplete")
        expected_read_only = variant == "readonly"
        expected_depth = 0 if expected_read_only else 1
        if (
            summary.get("qmp_inserted_read_only_before")
            is not expected_read_only
            or summary.get("qmp_inserted_read_only_after")
            is not expected_read_only
        ):
            _fail(
                "Readonly QMP evidence is incomplete"
                if expected_read_only
                else "Writable QMP evidence is incomplete"
            )
        for suffix in ("before", "after"):
            depth = summary.get(f"qmp_backing_depth_{suffix}")
            graph = summary.get(f"qmp_write_graph_{suffix}")
            if (
                isinstance(depth, bool)
                or not isinstance(depth, int)
                or depth != expected_depth
                or not isinstance(graph, dict)
            ):
                _fail("Variant QMP topology evidence is incomplete")
            _validate_qmp_topology(graph, backing_depth=depth)
        variants[variant] = summary
    if set(variants) != {"writable", "readonly"}:
        _fail("writable and readonly evidence are both required")

    fixture = _read_json(fixture_report)
    key_id = fixture.get("public_key_id")
    sessions = fixture.get("sessions")
    if (
        not isinstance(key_id, str)
        or not KEY_ID_RE.fullmatch(key_id)
        or not isinstance(sessions, list)
        or len(sessions) != 2
    ):
        _fail("Fixture root-approval evidence is incomplete")
    session_ids: set[str] = set()
    for item in sessions:
        if not isinstance(item, dict):
            _fail("Fixture session evidence is invalid")
        session_id = item.get("session_id")
        if (
            not isinstance(session_id, str)
            or not SESSION_ID_RE.fullmatch(session_id)
            or session_id in session_ids
            or item.get("operator_uid") != 0
            or item.get("plan_revision") != 1
            or item.get("reported_stage") != "preflight_ready"
            or item.get("root_approved") is not True
            or item.get("state") != "plan_published"
        ):
            _fail("Fixture session evidence is invalid")
        session_ids.add(session_id)
    _write_new(
        output,
        _json_bytes(
            {
                "public_key_id": key_id,
                "result": "pass",
                "session_count": len(sessions),
                "variants": sorted(variants),
            }
        ),
        mode=0o644,
    )
    print(PASS_LINE)


def _qmp_receive(
    stream: Any,
    transcript: list[dict[str, object]],
    *,
    expected_id: str | None,
) -> dict[str, object]:
    while True:
        raw = stream.readline(MAX_EVIDENCE_BYTES + 1)
        if not raw or len(raw) > MAX_EVIDENCE_BYTES:
            _fail("QMP closed before returning a bounded response")
        try:
            message = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AcceptanceError("QMP returned invalid JSON") from exc
        if not isinstance(message, dict):
            _fail("QMP returned a non-object message")
        transcript.append(message)
        if expected_id is None or message.get("id") == expected_id:
            return message


def _qmp_connect(socket_path: Path) -> tuple[socket.socket, Any, list[dict[str, object]]]:
    if not hasattr(socket, "AF_UNIX"):
        _fail("QMP Unix sockets are unavailable on this platform")
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(5)
    try:
        client.connect(str(socket_path))
    except OSError as exc:
        client.close()
        raise AcceptanceError("QMP socket is unavailable") from exc
    stream = client.makefile("rwb", buffering=0)
    transcript: list[dict[str, object]] = []
    greeting = _qmp_receive(stream, transcript, expected_id=None)
    if "QMP" not in greeting:
        stream.close()
        client.close()
        _fail("QMP greeting is missing")
    request = {"execute": "qmp_capabilities", "id": "capabilities"}
    stream.write((json.dumps(request) + "\r\n").encode("ascii"))
    response = _qmp_receive(
        stream, transcript, expected_id="capabilities"
    )
    if "error" in response:
        stream.close()
        client.close()
        _fail("QMP capability negotiation failed")
    return client, stream, transcript


def qmp_query(socket_path: Path, output: Path) -> None:
    client, stream, transcript = _qmp_connect(socket_path)
    try:
        request = {"execute": "query-blockstats", "id": "blockstats"}
        stream.write((json.dumps(request) + "\r\n").encode("ascii"))
        response = _qmp_receive(
            stream, transcript, expected_id="blockstats"
        )
        if "error" in response or not isinstance(response.get("return"), list):
            _fail("QMP query-blockstats failed")
        request = {"execute": "query-block", "id": "block"}
        stream.write((json.dumps(request) + "\r\n").encode("ascii"))
        response = _qmp_receive(stream, transcript, expected_id="block")
        if "error" in response or not isinstance(response.get("return"), list):
            _fail("QMP query-block failed")
    finally:
        stream.close()
        client.close()
    content = b"".join(
        (
            json.dumps(message, ensure_ascii=True, sort_keys=True)
            + "\n"
        ).encode("utf-8")
        for message in transcript
    )
    _write_new(output, content, mode=0o644)


def qmp_command(socket_path: Path, execute: str) -> None:
    if execute not in {"cont", "send-key", "quit"}:
        _fail("QMP command is not allowlisted")
    client, stream, transcript = _qmp_connect(socket_path)
    try:
        request: dict[str, object] = {
            "execute": execute,
            "id": "command",
        }
        if execute == "send-key":
            request["arguments"] = {
                "keys": [{"type": "qcode", "data": "s"}]
            }
        stream.write((json.dumps(request) + "\r\n").encode("ascii"))
        response = _qmp_receive(
            stream, transcript, expected_id="command"
        )
        if "error" in response:
            _fail(f"QMP {execute} failed")
    finally:
        stream.close()
        client.close()


def _receive_exact(client: socket.socket, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        chunk = client.recv(size - len(result))
        if not chunk:
            _fail("VNC server closed the connection")
        result.extend(chunk)
    return bytes(result)


def vnc_send_s(socket_path: Path) -> None:
    if not hasattr(socket, "AF_UNIX"):
        _fail("VNC Unix sockets are unavailable on this platform")
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(3)
    try:
        client.connect(str(socket_path))
        version = _receive_exact(client, 12)
        if not version.startswith(b"RFB 003."):
            _fail("VNC protocol version is unexpected")
        client.sendall(version)
        security_count = _receive_exact(client, 1)[0]
        security_types = _receive_exact(client, security_count)
        if 1 not in security_types:
            _fail("VNC unauthenticated local socket mode is unavailable")
        client.sendall(b"\x01")
        if _receive_exact(client, 4) != b"\x00\x00\x00\x00":
            _fail("VNC security handshake failed")
        client.sendall(b"\x01")
        header = _receive_exact(client, 24)
        name_length = struct.unpack(">I", header[20:24])[0]
        if name_length > 4096:
            _fail("VNC server name is oversized")
        _receive_exact(client, name_length)
        key = struct.pack(">BBHI", 4, 1, 0, ord("s"))
        client.sendall(key)
        client.sendall(struct.pack(">BBHI", 4, 0, 0, ord("s")))
    except OSError as exc:
        raise AcceptanceError("VNC socket is unavailable") from exc
    finally:
        client.close()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)

    prepare = commands.add_parser("prepare")
    prepare.add_argument("--state-dir", type=Path, required=True)

    serve = commands.add_parser("serve")
    serve.add_argument("--state-dir", type=Path, required=True)
    serve.add_argument("--listen-address", default="127.0.0.1")
    serve.add_argument("--listen-port", type=int, default=18089)

    export = commands.add_parser("export-evidence")
    export.add_argument("--state-dir", type=Path, required=True)
    export.add_argument("--output", type=Path, required=True)
    export.add_argument("--expected-sessions", type=int, default=2)

    verify = commands.add_parser("verify-variant")
    verify.add_argument(
        "--variant", choices=("writable", "readonly"), required=True
    )
    verify.add_argument("--before-qmp", type=Path, required=True)
    verify.add_argument("--after-qmp", type=Path, required=True)
    verify.add_argument("--before-sha", type=Path, required=True)
    verify.add_argument("--after-sha", type=Path, required=True)
    verify.add_argument("--output", type=Path, required=True)

    finalize = commands.add_parser("finalize-evidence")
    finalize.add_argument(
        "--variant-summary",
        type=Path,
        action="append",
        required=True,
    )
    finalize.add_argument("--fixture-report", type=Path, required=True)
    finalize.add_argument("--output", type=Path, required=True)

    query = commands.add_parser("qmp-query")
    query.add_argument("--socket", type=Path, required=True)
    query.add_argument("--output", type=Path, required=True)

    qmp = commands.add_parser("qmp-command")
    qmp.add_argument("--socket", type=Path, required=True)
    qmp.add_argument(
        "--execute", choices=("cont", "send-key", "quit"), required=True
    )

    vnc = commands.add_parser("vnc-send-s")
    vnc.add_argument("--socket", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "prepare":
            prepare_fixture(arguments.state_dir)
        elif arguments.command == "serve":
            serve_fixture(
                arguments.state_dir,
                arguments.listen_address,
                arguments.listen_port,
            )
        elif arguments.command == "export-evidence":
            if arguments.expected_sessions != 2:
                _fail("Exactly two QEMU sessions are required")
            export_fixture_evidence(
                arguments.state_dir,
                arguments.output,
                arguments.expected_sessions,
            )
        elif arguments.command == "verify-variant":
            verify_variant(
                variant=arguments.variant,
                before_qmp=arguments.before_qmp,
                after_qmp=arguments.after_qmp,
                before_sha=arguments.before_sha,
                after_sha=arguments.after_sha,
                output=arguments.output,
            )
        elif arguments.command == "finalize-evidence":
            finalize_evidence(
                variant_summaries=arguments.variant_summary,
                fixture_report=arguments.fixture_report,
                output=arguments.output,
            )
        elif arguments.command == "qmp-query":
            qmp_query(arguments.socket, arguments.output)
        elif arguments.command == "qmp-command":
            qmp_command(arguments.socket, arguments.execute)
        elif arguments.command == "vnc-send-s":
            vnc_send_s(arguments.socket)
        else:
            _fail("Unknown fixture command")
    except (AcceptanceError, RuntimeError) as exc:
        print(f"agent-v1-qemu: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
