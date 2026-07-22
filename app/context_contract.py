"""Signed, opaque pagination cursors for the read-only context API."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from pathlib import Path
from typing import Any


class ContextCursorError(ValueError):
    """A client-facing cursor validation error without secret detail."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _credential_key() -> bytes:
    directory = os.environ.get("CREDENTIALS_DIRECTORY", "")
    if not directory:
        raise ContextCursorError("context_pagination_unavailable")
    path = Path(directory) / "context-api-cursor-signing-key"
    try:
        if path.is_symlink() or not path.is_file():
            raise OSError("invalid credential")
        key = path.read_bytes()
    except OSError as exc:
        raise ContextCursorError("context_pagination_unavailable") from exc
    if len(key) < 32:
        raise ContextCursorError("context_pagination_unavailable")
    return key


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, UnicodeEncodeError) as exc:
        raise ContextCursorError("cursor_invalid") from exc


def encode_search_cursor(*, snapshot: dict[str, Any], query: str, limit: int, after: dict[str, Any]) -> str:
    payload = {
        "v": 1,
        "snapshot": snapshot,
        "query": query.strip().lower(),
        "limit": limit,
        "after": {"kind": str(after.get("kind", "")), "id": int(after.get("id", 0))},
        "exp": int(time.time()) + 900,
    }
    encoded = _b64encode(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    signature = _b64encode(hmac.new(_credential_key(), encoded.encode("ascii"), hashlib.sha256).digest())
    return f"{encoded}.{signature}"


def decode_search_cursor(token: str, *, query: str, limit: int) -> dict[str, Any]:
    try:
        encoded, supplied_signature = token.split(".", 1)
        expected_signature = _b64encode(hmac.new(_credential_key(), encoded.encode("ascii"), hashlib.sha256).digest())
        if not hmac.compare_digest(supplied_signature, expected_signature):
            raise ContextCursorError("cursor_invalid")
        payload = json.loads(_b64decode(encoded))
        after = payload["after"]
        if (
            payload.get("v") != 1
            or payload.get("query") != query.strip().lower()
            or payload.get("limit") != limit
            or after.get("kind") not in {"asset", "user"}
            or int(after.get("id", 0)) <= 0
            or not isinstance(payload.get("snapshot"), dict)
        ):
            raise ContextCursorError("cursor_filter_mismatch")
        if int(payload.get("exp", 0)) < int(time.time()):
            raise ContextCursorError("cursor_expired")
        return payload
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        if isinstance(exc, ContextCursorError):
            raise
        raise ContextCursorError("cursor_invalid") from exc
