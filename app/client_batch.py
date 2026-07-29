from __future__ import annotations

import csv
import io
import os
import re
import uuid
import zipfile
from ipaddress import ip_network
from pathlib import Path
from typing import Iterable, Sequence


CLIENT_RE = re.compile(r"^[A-Za-z0-9._-]+$")


class ClientBatchInputError(ValueError):
    pass


def _append_name(names: list[str], seen: set[str], value: str) -> None:
    name = value.strip()
    if not name:
        return
    if not CLIENT_RE.fullmatch(name):
        raise ClientBatchInputError(f"invalid client name: {name}")
    if name not in seen:
        seen.add(name)
        names.append(name)


def parse_batch_client_names(pasted: str, csv_bytes: bytes | None) -> list[str]:
    names: list[str] = []
    seen: set[str] = set()
    for value in re.split(r"[,\r\n]+", pasted or ""):
        _append_name(names, seen, value)
    if csv_bytes:
        try:
            text = csv_bytes.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise ClientBatchInputError("CSV must be UTF-8 encoded") from exc
        reader = csv.DictReader(io.StringIO(text))
        if not reader.fieldnames or "client_name" not in reader.fieldnames:
            raise ClientBatchInputError("CSV must contain a client_name column")
        for row in reader:
            for key in ("profile", "vpn_ip"):
                if str(row.get(key) or "").strip():
                    raise ClientBatchInputError(f"CSV column {key} is not supported for shared batches")
            _append_name(names, seen, str(row.get("client_name") or ""))
    if not names:
        raise ClientBatchInputError("provide at least one client name")
    return names


def parse_custom_cidrs(raw: str) -> list[str]:
    cidrs: list[str] = []
    seen: set[str] = set()
    for value in re.split(r"[,\r\n]+", raw or ""):
        value = value.strip()
        if not value:
            continue
        try:
            normalized = str(ip_network(value, strict=False))
        except ValueError as exc:
            raise ClientBatchInputError(f"invalid CIDR: {value}") from exc
        if normalized not in seen:
            seen.add(normalized)
            cidrs.append(normalized)
    if not cidrs:
        raise ClientBatchInputError("provide at least one custom network")
    return cidrs


def create_batch_zip(paths: Sequence[Path], archive_dir: Path, out_dir: Path) -> Path:
    output_root = out_dir.resolve()
    archive_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(archive_dir, 0o700)
    validated: list[Path] = []
    for path in paths:
        resolved = path.resolve()
        if resolved.suffix != ".ovpn" or not resolved.is_file() or output_root not in resolved.parents:
            raise ClientBatchInputError("batch archive source is invalid")
        validated.append(resolved)
    archive = archive_dir / f"batch-{uuid.uuid4().hex}.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as result:
        for path in validated:
            result.write(path, arcname=path.name)
    os.chmod(archive, 0o600)
    return archive
