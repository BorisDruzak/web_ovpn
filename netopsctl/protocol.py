from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass
from typing import Any


PROTOCOL_VERSION = 2
MAX_REQUEST_BYTES = 16_384
MAX_RESPONSE_BYTES = 16_384
ACTIONS = frozenset({"plan.create", "plan.approve", "plan.apply", "plan.verify", "plan.rollback", "policy.reconcile", "status"})
_PLAN_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class ProtocolError(ValueError):
    pass


@dataclass(frozen=True)
class BrokerRequest:
    request_id: str
    action: str
    payload: dict[str, Any]
    authorization: dict[str, Any]
    signature: str


def _validate_payload(action: str, payload: object) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ProtocolError("payload must be an object")
    if action == "status":
        if payload:
            raise ProtocolError("status does not accept payload")
        return {}
    if action in {"plan.approve", "plan.apply", "plan.verify", "plan.rollback"}:
        if set(payload) != {"plan_key"} or not isinstance(payload.get("plan_key"), str) or not _PLAN_KEY_RE.fullmatch(str(payload["plan_key"])):
            raise ProtocolError("invalid plan payload")
        return {"plan_key": str(payload["plan_key"])}
    if action == "policy.reconcile":
        if set(payload) - {"limit"} or not isinstance(payload.get("limit", 64), int) or not 1 <= int(payload.get("limit", 64)) <= 256:
            raise ProtocolError("invalid reconcile payload")
        return {"limit": int(payload.get("limit", 64))}
    if action == "plan.create":
        if set(payload) != {"plan"} or not isinstance(payload.get("plan"), dict):
            raise ProtocolError("invalid plan-create payload")
        plan = payload["plan"]
        forbidden = {"command", "path", "shell", "argv"}
        if forbidden & set(plan) or len(json.dumps(plan, separators=(",", ":"))) > 8_192:
            raise ProtocolError("unsafe plan-create payload")
        return {"plan": plan}
    raise ProtocolError("unsupported action")


def decode_request(data: bytes) -> BrokerRequest:
    if not data or len(data) > MAX_REQUEST_BYTES or b"\n" in data or b"\r" in data:
        raise ProtocolError("invalid request framing")
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("invalid request JSON") from exc
    if not isinstance(value, dict) or set(value) != {"protocol_version", "request_id", "action", "payload", "authorization", "signature"}:
        raise ProtocolError("unknown or missing request fields")
    if value["protocol_version"] != PROTOCOL_VERSION or not isinstance(value["request_id"], str):
        raise ProtocolError("unsupported protocol")
    try:
        uuid.UUID(value["request_id"])
    except ValueError as exc:
        raise ProtocolError("invalid request id") from exc
    action = value["action"]
    if action not in ACTIONS:
        raise ProtocolError("invalid action")
    authorization, signature = value["authorization"], value["signature"]
    if not isinstance(authorization, dict) or not isinstance(signature, str) or not re.fullmatch(r"[A-Za-z0-9_-]{16,256}", signature):
        raise ProtocolError("invalid authorization envelope")
    return BrokerRequest(value["request_id"], action, _validate_payload(action, value["payload"]), authorization, signature)


def encode_response(value: dict[str, Any]) -> bytes:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_RESPONSE_BYTES or b"\n" in encoded or b"\r" in encoded:
        raise ProtocolError("response exceeds protocol bounds")
    return encoded
