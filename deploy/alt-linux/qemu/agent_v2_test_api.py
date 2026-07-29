#!/usr/bin/env python3
"""QMP and evidence gates for disposable agent-v2 execution acceptance."""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, NoReturn, Sequence


PASS_LINE = (
    "PASS: root-authorized install wrote only the disposable target; "
    "authenticated postflight installed"
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SESSION_ID_RE = re.compile(
    r"^install-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$"
)
MAX_EVIDENCE_BYTES = 4 * 1024 * 1024
TIMELINE_KEYS = (
    "waiting_for_authorization_at",
    "preflight_ready_at",
    "root_authorized_at",
    "execution_claimed_at",
    "verified_handoff_at",
    "installer_completed_at",
    "postflight_authenticated_at",
)


class AcceptanceError(RuntimeError):
    """A bounded error containing no request or credential material."""


def _fail(message: str) -> NoReturn:
    raise AcceptanceError(message)


def _read_bytes(path: Path, *, maximum: int = MAX_EVIDENCE_BYTES) -> bytes:
    try:
        metadata = path.stat()
        if (
            not path.is_file()
            or path.is_symlink()
            or not 1 <= metadata.st_size <= maximum
        ):
            _fail(f"Evidence file is invalid: {path.name}")
        return path.read_bytes()
    except OSError as exc:
        raise AcceptanceError(
            f"Evidence file cannot be read: {path.name}"
        ) from exc


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError
        result[name] = value
    return result


def _read_json(path: Path) -> dict[str, object]:
    try:
        document = json.loads(
            _read_bytes(path).decode("utf-8"),
            object_pairs_hook=_strict_object,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise AcceptanceError(
            f"Evidence JSON is invalid: {path.name}"
        ) from exc
    if not isinstance(document, dict):
        _fail(f"Evidence JSON must be an object: {path.name}")
    return document


def _json_bytes(document: object) -> bytes:
    return (
        json.dumps(document, ensure_ascii=True, indent=2, sort_keys=True)
        + "\n"
    ).encode("utf-8")


def _write_new(path: Path, content: bytes, *, mode: int = 0o644) -> None:
    if not path.parent.is_dir() or path.is_symlink():
        _fail("Evidence output parent is unavailable")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    try:
        descriptor = os.open(path, flags, mode)
    except OSError as exc:
        raise AcceptanceError("Refusing to overwrite evidence output") from exc
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)
    os.chmod(path, mode)


def _qmp_write_graph(
    node: dict[str, object],
    *,
    graph_path: str,
) -> dict[str, dict[str, int]]:
    statistics = node.get("stats")
    if not isinstance(statistics, dict):
        _fail(f"QMP write statistics are absent at {graph_path}")
    counters: dict[str, int] = {}
    for name, value in statistics.items():
        if not isinstance(name, str) or not name.startswith("wr_"):
            continue
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            _fail(f"QMP write counter is invalid at {graph_path}")
        counters[name] = value
    if not {"wr_bytes", "wr_operations"}.issubset(counters):
        _fail(f"QMP mandatory write counters are absent at {graph_path}")
    graph = {graph_path: dict(sorted(counters.items()))}
    for relation in ("parent", "backing"):
        child = node.get(relation)
        if child is None:
            continue
        if not isinstance(child, dict):
            _fail(f"QMP {relation} statistics are invalid at {graph_path}")
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
    device: str,
    backing_depth: int,
) -> None:
    format_path = device
    for _ in range(backing_depth + 1):
        if format_path not in graph:
            _fail(f"QMP {device} backing statistics do not match depth")
        parent_path = f"{format_path}.parent"
        if parent_path not in graph:
            _fail(f"QMP {format_path} parent statistics are absent")
        format_path = f"{format_path}.backing"
    if format_path in graph:
        _fail(f"QMP {device} backing statistics do not match depth")


def _read_qmp_snapshot(
    path: Path,
) -> dict[str, dict[str, object]]:
    try:
        text = _read_bytes(path).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AcceptanceError(
            f"QMP transcript is not UTF-8: {path.name}"
        ) from exc
    stats: dict[str, dict[str, object]] = {}
    blocks: dict[str, dict[str, object]] = {}
    for line in text.splitlines():
        if not line:
            continue
        try:
            message = json.loads(line, object_pairs_hook=_strict_object)
        except (json.JSONDecodeError, ValueError) as exc:
            raise AcceptanceError(
                f"QMP transcript contains invalid JSON: {path.name}"
            ) from exc
        if not isinstance(message, dict):
            _fail(f"QMP transcript message is invalid: {path.name}")
        returned = message.get("return")
        if not isinstance(returned, list):
            continue
        for item in returned:
            if not isinstance(item, dict):
                continue
            device = item.get("device")
            if device not in {"target", "sentinel"}:
                continue
            if isinstance(item.get("stats"), dict):
                if device in stats:
                    _fail(f"QMP {device} statistics are ambiguous")
                stats[device] = item
            if isinstance(item.get("inserted"), dict):
                if device in blocks:
                    _fail(f"QMP {device} query-block evidence is ambiguous")
                blocks[device] = item
    if set(stats) != {"target", "sentinel"}:
        _fail("QMP target and sentinel statistics are both required")
    if set(blocks) != {"target", "sentinel"}:
        _fail("QMP target and sentinel query-block evidence is required")

    result: dict[str, dict[str, object]] = {}
    for device in ("target", "sentinel"):
        inserted = blocks[device]["inserted"]
        if not isinstance(inserted, dict):
            _fail(f"QMP {device} inserted information is invalid")
        read_only = inserted.get("ro")
        depth = inserted.get("backing_file_depth")
        if not isinstance(read_only, bool):
            _fail(f"QMP {device} read-only state is invalid")
        if (
            isinstance(depth, bool)
            or not isinstance(depth, int)
            or not 0 <= depth <= 16
            or inserted.get("drv") != "qcow2"
        ):
            _fail(f"QMP {device} qcow2 topology is invalid")
        graph = _qmp_write_graph(stats[device], graph_path=device)
        _validate_qmp_topology(
            graph, device=device, backing_depth=depth
        )
        result[device] = {
            "backing_depth": depth,
            "graph": graph,
            "read_only": read_only,
            "write_bytes": graph[device]["wr_bytes"],
        }
    return result


def _all_writes_zero(
    graph: dict[str, dict[str, int]],
) -> bool:
    return all(
        value == 0
        for counters in graph.values()
        for name, value in counters.items()
        if name.startswith("wr_")
    )


def _read_sha256(path: Path) -> str:
    try:
        lines = _read_bytes(path, maximum=4096).decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise AcceptanceError("SHA-256 record is not ASCII") from exc
    if len(lines) != 1:
        _fail("SHA-256 record must contain exactly one line")
    fields = lines[0].split(maxsplit=1)
    if not fields or not SHA256_RE.fullmatch(fields[0]):
        _fail("SHA-256 record is invalid")
    return fields[0]


def _parse_timestamp(value: object, *, field: str) -> datetime:
    if not isinstance(value, str):
        _fail(f"Timeline {field} is invalid")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise AcceptanceError(f"Timeline {field} is invalid") from exc
    if (
        parsed.tzinfo is None
        or parsed.utcoffset() is None
        or parsed.astimezone(timezone.utc).isoformat() != value
    ):
        _fail(f"Timeline {field} is invalid")
    return parsed


def _validate_timeline(path: Path) -> dict[str, object]:
    timeline = _read_json(path)
    expected = {
        "schema_version",
        "session_id",
        "target_disk",
        "operator_uid",
        *TIMELINE_KEYS,
    }
    if (
        set(timeline) != expected
        or timeline.get("schema_version") != 1
        or type(timeline.get("schema_version")) is not int
        or timeline.get("operator_uid") != 0
        or type(timeline.get("operator_uid")) is not int
        or timeline.get("target_disk") != "/dev/vda"
        or not isinstance(timeline.get("session_id"), str)
        or not SESSION_ID_RE.fullmatch(str(timeline["session_id"]))
    ):
        _fail("Root authorization timeline is invalid")
    ordered = [
        _parse_timestamp(timeline[name], field=name)
        for name in TIMELINE_KEYS
    ]
    if any(later <= earlier for earlier, later in zip(ordered, ordered[1:])):
        _fail("Root authorization timeline is out of order")
    return timeline


def _validate_postflight(
    path: Path,
    *,
    timeline: dict[str, object],
) -> dict[str, object]:
    postflight = _read_json(path)
    if (
        set(postflight)
        != {
            "schema_version",
            "session_id",
            "authenticated",
            "boot_source",
            "state",
            "reported_at",
        }
        or postflight.get("schema_version") != 1
        or type(postflight.get("schema_version")) is not int
        or postflight.get("session_id") != timeline["session_id"]
        or postflight.get("authenticated") is not True
        or postflight.get("boot_source") != "target-without-iso"
        or postflight.get("state") != "installed"
        or postflight.get("reported_at")
        != timeline["postflight_authenticated_at"]
    ):
        _fail("Authenticated target-only postflight evidence is invalid")
    _parse_timestamp(postflight["reported_at"], field="reported_at")
    return postflight


def finalize_evidence(
    *,
    before_qmp: Path,
    after_qmp: Path,
    target_before_sha: Path,
    target_after_sha: Path,
    sentinel_before_sha: Path,
    sentinel_after_sha: Path,
    timeline_path: Path,
    postflight_path: Path,
    output: Path,
) -> None:
    before = _read_qmp_snapshot(before_qmp)
    after = _read_qmp_snapshot(after_qmp)
    for snapshot in (before, after):
        if snapshot["target"]["read_only"] is not False:
            _fail("Disposable target is unexpectedly read-only")
        if snapshot["sentinel"]["read_only"] is not True:
            _fail("Sentinel is not QMP-confirmed read-only")
    if not _all_writes_zero(before["target"]["graph"]):
        _fail("Target wrote before authorization")
    if not _all_writes_zero(before["sentinel"]["graph"]):
        _fail("Forbidden sentinel write before authorization")
    if not _all_writes_zero(after["sentinel"]["graph"]):
        _fail("Forbidden sentinel write after installation")
    target_write_bytes = after["target"]["write_bytes"]
    if not isinstance(target_write_bytes, int) or target_write_bytes <= 0:
        _fail("No target write was observed after installation")

    target_before = _read_sha256(target_before_sha)
    target_after = _read_sha256(target_after_sha)
    sentinel_before = _read_sha256(sentinel_before_sha)
    sentinel_after = _read_sha256(sentinel_after_sha)
    if target_before == target_after:
        _fail("Target SHA-256 did not change")
    if sentinel_before != sentinel_after:
        _fail("Sentinel SHA-256 changed")

    timeline = _validate_timeline(timeline_path)
    postflight = _validate_postflight(
        postflight_path, timeline=timeline
    )
    before_summary = {
        "sentinel_read_only": True,
        "sentinel_sha256": sentinel_before,
        "sentinel_write_bytes": before["sentinel"]["write_bytes"],
        "target_read_only": False,
        "target_sha256": target_before,
        "target_write_bytes": before["target"]["write_bytes"],
    }
    after_summary = {
        "sentinel_read_only": True,
        "sentinel_sha256": sentinel_after,
        "sentinel_write_bytes": after["sentinel"]["write_bytes"],
        "target_read_only": False,
        "target_sha256": target_after,
        "target_write_bytes": target_write_bytes,
    }
    receipt = {
        "acceptance_scope": "generic-ovmf-disposable",
        "after_install": after_summary,
        "authorization_timeline": timeline,
        "before_authorization": before_summary,
        "firmware": "generic-ovmf",
        "postflight": {
            "authenticated": postflight["authenticated"],
            "boot_source": postflight["boot_source"],
            "reported_at": postflight["reported_at"],
        },
        "postflight_state": postflight["state"],
        "result": "pass",
        "schema_version": 1,
        "session_id": timeline["session_id"],
        "target_disk": "/dev/vda",
    }
    _write_new(output, _json_bytes(receipt))
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


def _qmp_connect(
    socket_path: Path,
) -> tuple[socket.socket, Any, list[dict[str, object]]]:
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
        for execute, request_id in (
            ("query-blockstats", "blockstats"),
            ("query-block", "block"),
        ):
            request = {"execute": execute, "id": request_id}
            stream.write((json.dumps(request) + "\r\n").encode("ascii"))
            response = _qmp_receive(
                stream, transcript, expected_id=request_id
            )
            if "error" in response or not isinstance(
                response.get("return"), list
            ):
                _fail(f"QMP {execute} failed")
    finally:
        stream.close()
        client.close()
    _write_new(
        output,
        b"".join(
            (
                json.dumps(message, ensure_ascii=True, sort_keys=True)
                + "\n"
            ).encode("utf-8")
            for message in transcript
        ),
    )


def qmp_command(socket_path: Path, execute: str) -> None:
    if execute not in {"cont", "quit", "system_reset"}:
        _fail("QMP command is not allowlisted")
    client, stream, _transcript = _qmp_connect(socket_path)
    try:
        request = {"execute": execute, "id": "command"}
        stream.write((json.dumps(request) + "\r\n").encode("ascii"))
        response = _qmp_receive(
            stream, _transcript, expected_id="command"
        )
        if "error" in response:
            _fail(f"QMP {execute} failed")
    finally:
        stream.close()
        client.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True)
    finalize = commands.add_parser(
        "finalize-evidence", allow_abbrev=False
    )
    finalize.add_argument("--before-qmp", required=True, type=Path)
    finalize.add_argument("--after-qmp", required=True, type=Path)
    finalize.add_argument("--target-before-sha", required=True, type=Path)
    finalize.add_argument("--target-after-sha", required=True, type=Path)
    finalize.add_argument(
        "--sentinel-before-sha", required=True, type=Path
    )
    finalize.add_argument(
        "--sentinel-after-sha", required=True, type=Path
    )
    finalize.add_argument("--timeline", required=True, type=Path)
    finalize.add_argument("--postflight", required=True, type=Path)
    finalize.add_argument("--output", required=True, type=Path)
    query = commands.add_parser("qmp-query", allow_abbrev=False)
    query.add_argument("--socket", required=True, type=Path)
    query.add_argument("--output", required=True, type=Path)
    command = commands.add_parser("qmp-command", allow_abbrev=False)
    command.add_argument("--socket", required=True, type=Path)
    command.add_argument("--execute", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        if arguments.command == "finalize-evidence":
            finalize_evidence(
                before_qmp=arguments.before_qmp,
                after_qmp=arguments.after_qmp,
                target_before_sha=arguments.target_before_sha,
                target_after_sha=arguments.target_after_sha,
                sentinel_before_sha=arguments.sentinel_before_sha,
                sentinel_after_sha=arguments.sentinel_after_sha,
                timeline_path=arguments.timeline,
                postflight_path=arguments.postflight,
                output=arguments.output,
            )
        elif arguments.command == "qmp-query":
            qmp_query(arguments.socket, arguments.output)
        else:
            qmp_command(arguments.socket, arguments.execute)
        return 0
    except AcceptanceError as exc:
        print(f"agent-v2-qemu: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
