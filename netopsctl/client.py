from __future__ import annotations

import json
import socket
import uuid
from typing import Any

from .protocol import MAX_RESPONSE_BYTES, PROTOCOL_VERSION, ProtocolError, encode_response


def request(
    socket_path: str,
    *,
    action: str,
    payload: dict[str, Any],
    authorization: dict[str, Any],
    signature: str,
    timeout: float = 5.0,
) -> dict[str, Any]:
    envelope = {
        "protocol_version": PROTOCOL_VERSION, "request_id": str(uuid.uuid4()),
        "action": action, "payload": payload, "authorization": authorization, "signature": signature,
    }
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(timeout)
        client.connect(socket_path)
        client.sendall(encode_response(envelope))
        response = client.recv(MAX_RESPONSE_BYTES + 1)
    if not response or len(response) > MAX_RESPONSE_BYTES:
        raise ProtocolError("invalid broker response")
    try:
        value = json.loads(response.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("invalid broker response") from exc
    if not isinstance(value, dict) or value.get("request_id") != envelope["request_id"]:
        raise ProtocolError("broker response correlation failed")
    return value
