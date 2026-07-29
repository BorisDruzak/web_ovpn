from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from alt_deploy.config import Settings
from alt_deploy.install_tls import (
    TLSMaterial,
    create_execution_server_context,
    load_execution_tls_material,
)


INSTALL_EXECUTION_LISTEN_ADDRESS = "192.168.100.17"
INSTALL_EXECUTION_LISTEN_PORT = 18092


def create_execution_tls_server(
    settings: Settings,
    material: TLSMaterial,
    *,
    listen_port: int | None = None,
    credential_key_path: Path | None = None,
) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        server_version = "ALTInstallExecution/1.0"

        def log_message(self, format: str, *args: object) -> None:
            return

        def do_GET(self) -> None:
            if self.path != "/health":
                self.send_error(404)
                return
            body = json.dumps(
                {"schema_version": 1, "service": "alt-install-execution", "status": "ok"},
                separators=(",", ":"),
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(
        (settings.install_execution_listen_address, listen_port or settings.install_execution_listen_port),
        Handler,
    )
    server.socket = create_execution_server_context(
        material, key_path=credential_key_path
    ).wrap_socket(server.socket, server_side=True)
    return server


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen-address", required=True)
    parser.add_argument("--listen-port", required=True, type=int)
    parser.add_argument("--credential-key", required=True)
    parsed = parser.parse_args(argv)
    if parsed.listen_address != INSTALL_EXECUTION_LISTEN_ADDRESS:
        parser.error("listen address must be 192.168.100.17")
    if parsed.listen_port != INSTALL_EXECUTION_LISTEN_PORT:
        parser.error("listen port must be 18092")
    settings = Settings.from_env()
    if (
        settings.install_execution_listen_address != INSTALL_EXECUTION_LISTEN_ADDRESS
        or settings.install_execution_listen_port != INSTALL_EXECUTION_LISTEN_PORT
    ):
        parser.error("configured V2 listener does not match fixed endpoint")
    material = load_execution_tls_material(settings)
    server = create_execution_tls_server(
        settings,
        material,
        listen_port=parsed.listen_port,
        credential_key_path=Path(parsed.credential_key),
    )
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
