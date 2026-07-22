from __future__ import annotations

import json
import uuid

import pytest


def _request(**extra):
    value = {
        "protocol_version": 1,
        "request_id": str(uuid.uuid4()),
        "actor": "api:network-admin",
        "action": "plan.apply",
        "payload": {"plan_key": "plan-20260722-0001"},
    }
    value.update(extra)
    return value


def test_broker_protocol_accepts_only_registered_bounded_envelopes() -> None:
    from netopsctl.protocol import decode_request, encode_response

    request = decode_request(json.dumps(_request()).encode())

    assert request.action == "plan.apply"
    assert request.payload == {"plan_key": "plan-20260722-0001"}
    assert json.loads(encode_response({"status": "ok", "request_id": request.request_id})) == {
        "status": "ok", "request_id": request.request_id,
    }


@pytest.mark.parametrize("mutate", [
    lambda value: value.update({"command": "rm -rf /"}),
    lambda value: value.update({"action": "shell.exec"}),
    lambda value: value.update({"payload": {"plan_key": "../../etc/passwd"}}),
    lambda value: value.update({"payload": {"plan_key": "plan-1\nrun"}}),
])
def test_broker_protocol_rejects_unknown_or_injectable_requests(mutate) -> None:
    from netopsctl.protocol import ProtocolError, decode_request

    request = _request()
    mutate(request)
    with pytest.raises(ProtocolError):
        decode_request(json.dumps(request).encode())


def test_broker_protocol_rejects_newlines_and_oversized_payloads() -> None:
    from netopsctl.protocol import MAX_REQUEST_BYTES, ProtocolError, decode_request

    with pytest.raises(ProtocolError):
        decode_request(json.dumps(_request()).encode() + b"\n")
    with pytest.raises(ProtocolError):
        decode_request(b"{" + b" " * MAX_REQUEST_BYTES + b"}")
