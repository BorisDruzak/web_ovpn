#!/usr/bin/env python3
"""Validation and canonical index generation for managed ISO releases."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


RELEASE_ID_RE = re.compile(r"^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{7,12}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
KEY_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
CONTROLLER_URL = "http://192.168.100.17:18090"
INDEX_FIELDS = {"schema_version", "releases"}
ENTRY_FIELDS = {
    "created_at",
    "git_commit",
    "helper_sha256",
    "managed_iso_sha256",
    "public_key_id",
    "release_id",
    "source_iso_sha256",
}
SIDECAR_FIELDS = {
    "build_id",
    "controller_url",
    "format",
    "helper_sha256",
    "managed_initrd_sha256",
    "managed_iso_sha256",
    "payload_manifest_sha256",
    "public_key_id",
    "public_key_sha256",
    "source_iso_sha256",
}


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("JSON input is invalid") from exc
    if not isinstance(value, dict):
        raise ValueError("JSON input must be an object")
    return value


def _canonical(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def validate_release_id(value: str) -> None:
    if not RELEASE_ID_RE.fullmatch(value):
        raise ValueError("release ID is invalid")


def _sha(value: object) -> bool:
    return isinstance(value, str) and SHA256_RE.fullmatch(value) is not None


def _validate_entry(entry: object) -> dict[str, Any]:
    if not isinstance(entry, dict) or set(entry) != ENTRY_FIELDS:
        raise ValueError("release index entry fields are invalid")
    validate_release_id(str(entry.get("release_id", "")))
    if not isinstance(entry["git_commit"], str) or not COMMIT_RE.fullmatch(entry["git_commit"]):
        raise ValueError("release index commit is invalid")
    if not isinstance(entry["created_at"], str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", entry["created_at"]):
        raise ValueError("release index creation time is invalid")
    for key in ("source_iso_sha256", "managed_iso_sha256", "helper_sha256"):
        if not _sha(entry[key]):
            raise ValueError("release index digest is invalid")
    if not isinstance(entry["public_key_id"], str) or not KEY_ID_RE.fullmatch(entry["public_key_id"]):
        raise ValueError("release index public key ID is invalid")
    return entry


def _load_index(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    index = _read_json(path)
    if set(index) != INDEX_FIELDS or index.get("schema_version") != 1 or not isinstance(index.get("releases"), list):
        raise ValueError("release index is invalid")
    releases = [_validate_entry(item) for item in index["releases"]]
    if releases != sorted(releases, key=lambda item: item["release_id"]):
        raise ValueError("release index ordering is invalid")
    if len({item["release_id"] for item in releases}) != len(releases):
        raise ValueError("release index IDs are not unique")
    return releases


def _entry_from_sidecar(sidecar: Path, release_id: str, commit: str, created_at: str) -> dict[str, Any]:
    validate_release_id(release_id)
    if not COMMIT_RE.fullmatch(commit):
        raise ValueError("source commit is invalid")
    document = _read_json(sidecar)
    if set(document) != SIDECAR_FIELDS or document.get("format") != "alt-install-agent-managed-iso-v1":
        raise ValueError("managed ISO sidecar is invalid")
    if document.get("controller_url") != CONTROLLER_URL:
        raise ValueError("managed ISO controller URL is invalid")
    if document.get("build_id") != f"release-{release_id}":
        raise ValueError("managed ISO build ID is invalid")
    for key in (
        "source_iso_sha256",
        "managed_iso_sha256",
        "helper_sha256",
        "managed_initrd_sha256",
        "payload_manifest_sha256",
        "public_key_sha256",
    ):
        if not _sha(document.get(key)):
            raise ValueError("managed ISO sidecar digest is invalid")
    if not isinstance(document.get("public_key_id"), str) or not KEY_ID_RE.fullmatch(document["public_key_id"]):
        raise ValueError("managed ISO sidecar public key ID is invalid")
    entry = {
        "created_at": created_at,
        "git_commit": commit,
        "helper_sha256": document["helper_sha256"],
        "managed_iso_sha256": document["managed_iso_sha256"],
        "public_key_id": document["public_key_id"],
        "release_id": release_id,
        "source_iso_sha256": document["source_iso_sha256"],
    }
    return _validate_entry(entry)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate-release-id")
    validate.add_argument("--release-id", required=True)
    update = commands.add_parser("update-index")
    update.add_argument("--index", type=Path, required=True)
    update.add_argument("--sidecar", type=Path, required=True)
    update.add_argument("--release-id", required=True)
    update.add_argument("--commit", required=True)
    update.add_argument("--created-at", required=True)
    update.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "validate-release-id":
            validate_release_id(args.release_id)
        else:
            if args.output.exists() or not args.output.parent.is_dir():
                raise ValueError("release index output path is unavailable")
            releases = _load_index(args.index)
            entry = _entry_from_sidecar(args.sidecar, args.release_id, args.commit, args.created_at)
            if any(item["release_id"] == entry["release_id"] for item in releases):
                raise ValueError("release ID already exists")
            args.output.write_bytes(_canonical({"schema_version": 1, "releases": sorted([*releases, entry], key=lambda item: item["release_id"])}))
    except ValueError as exc:
        print(f"release-contract: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
