from __future__ import annotations

import os
import socket
from typing import Any

from .protocol import BrokerRequest, ProtocolError, decode_request, encode_response


def handle(request: BrokerRequest) -> dict[str, Any]:
    """Dispatch only registered control-plane verbs; adapters are wired in later tasks."""
    if request.action == "status":
        return {"status": "ok", "request_id": request.request_id, "service": "netopsctl"}
    return {"status": "error", "request_id": request.request_id, "error": "action not yet enabled"}


def serve(listener: socket.socket) -> None:
    while True:
        connection, _ = listener.accept()
        with connection:
            try:
                data = connection.recv(16_385)
                request = decode_request(data)
                response = handle(request)
            except ProtocolError as exc:
                response = {"status": "error", "request_id": "", "error": str(exc)}
            connection.sendall(encode_response(response))


def _socket_from_activation() -> socket.socket:
    listen_fds = int(os.environ.get("LISTEN_FDS", "0"))
    if listen_fds != 1:
        raise RuntimeError("netopsctl requires one systemd-activated socket")
    return socket.fromfd(3, socket.AF_UNIX, socket.SOCK_STREAM)


def main() -> None:
    serve(_socket_from_activation())


if __name__ == "__main__":
    main()
