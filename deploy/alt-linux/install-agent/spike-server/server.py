from __future__ import annotations

import argparse
import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from repository import SpikeRepository

MAX_PAYLOAD_BYTES = 32768


class SpikeHandler(BaseHTTPRequestHandler):
    repository: SpikeRepository

    def do_POST(self) -> None:  # noqa: N802
        if self.path == "/spike/v1/sessions":
            self._create_session()
            return
        prefix = "/spike/v1/sessions/"
        suffix = "/state"
        if self.path.startswith(prefix) and self.path.endswith(suffix):
            self._report_state(self.path[len(prefix) : -len(suffix)])
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def _payload(self) -> dict[str, object]:
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError as error:
            raise ValueError("invalid content length") from error
        if length <= 0:
            raise ValueError("empty payload")
        if length > MAX_PAYLOAD_BYTES:
            raise OverflowError
        payload = json.loads(self.rfile.read(length))
        if not isinstance(payload, dict):
            raise ValueError("object required")
        return payload

    def _create_session(self) -> None:
        try:
            payload = self._payload()
            session = self.repository.create_session(payload, self.client_address[0])
        except OverflowError:
            self.send_error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            return
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            self.send_error(HTTPStatus.BAD_REQUEST)
            return
        self._plain(HTTPStatus.CREATED, session)

    def _report_state(self, session: str) -> None:
        try:
            payload = self._payload()
            if set(payload) != {"state"} or not isinstance(payload["state"], str):
                raise ValueError("invalid state payload")
            self.repository.report_state(session, payload["state"])
        except OverflowError:
            self.send_error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            return
        except (KeyError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
            self.send_error(HTTPStatus.BAD_REQUEST)
            return
        self._empty(HTTPStatus.NO_CONTENT)

    def do_GET(self) -> None:  # noqa: N802
        prefix = "/spike/v1/sessions/"
        suffix = "/decision"
        if not self.path.startswith(prefix) or not self.path.endswith(suffix):
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        session = self.path[len(prefix) : -len(suffix)]
        try:
            self._plain(HTTPStatus.OK, self.repository.decision(session))
        except KeyError:
            self.send_error(HTTPStatus.NOT_FOUND)

    def _plain(self, status: HTTPStatus, value: str) -> None:
        body = (value + "\n").encode("ascii")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=us-ascii")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _empty(self, status: HTTPStatus) -> None:
        self.send_response(status)
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        return


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--state", required=True, type=Path)
    args = parser.parse_args()
    SpikeHandler.repository = SpikeRepository(args.state)
    with ThreadingHTTPServer((args.listen, args.port), SpikeHandler) as server:
        server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
