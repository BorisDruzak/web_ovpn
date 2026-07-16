#!/usr/bin/python3

from __future__ import annotations

import ipaddress
import json
import os
import re
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

LISTEN_ADDRESS = "0.0.0.0"
LISTEN_PORT = 8088

PENDING_DIR = Path("/srv/alt-deploy/registration/pending")

ALLOWED_NETWORKS = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("192.168.100.0/23"),
)

HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9.-]{0,62}$")
MAC_RE = re.compile(r"^[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}$")
UUID_RE = re.compile(r"^[0-9a-fA-F-]{8,64}$")


class RegisterHandler(BaseHTTPRequestHandler):
    server_version = "ALTDeployRegister/1.0"

    def send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(
            payload,
            ensure_ascii=False,
            indent=2,
        ).encode("utf-8")

        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def client_is_allowed(self) -> bool:
        try:
            address = ipaddress.ip_address(self.client_address[0])
        except ValueError:
            return False

        return any(address in network for network in ALLOWED_NETWORKS)

    def do_GET(self) -> None:
        if self.path.split("?", 1)[0] != "/health":
            self.send_json(404, {"status": "not_found"})
            return

        self.send_json(200, {"status": "ok"})

    def do_POST(self) -> None:
        if self.path.split("?", 1)[0] != "/register":
            self.send_json(404, {"status": "not_found"})
            return

        if not self.client_is_allowed():
            self.send_json(403, {"status": "forbidden"})
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_json(400, {"status": "invalid_content_length"})
            return

        if content_length < 1 or content_length > 16384:
            self.send_json(413, {"status": "invalid_payload_size"})
            return

        try:
            raw_body = self.rfile.read(content_length)
            payload = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self.send_json(400, {"status": "invalid_json"})
            return

        hostname = str(payload.get("hostname", "")).strip().lower()
        mac = str(payload.get("mac", "")).strip().lower()
        machine_uuid = str(payload.get("uuid", "")).strip().lower()

        if not HOSTNAME_RE.fullmatch(hostname):
            self.send_json(400, {"status": "invalid_hostname"})
            return

        if not MAC_RE.fullmatch(mac):
            self.send_json(400, {"status": "invalid_mac"})
            return

        if machine_uuid and not UUID_RE.fullmatch(machine_uuid):
            self.send_json(400, {"status": "invalid_uuid"})
            return

        machine_key = machine_uuid or mac.replace(":", "")

        record = {
            "machine_key": machine_key,
            "hostname": hostname,
            "ip": self.client_address[0],
            "mac": mac,
            "uuid": machine_uuid,
            "registered_at": datetime.now(timezone.utc).isoformat(),
            "status": "pending",
        }

        PENDING_DIR.mkdir(parents=True, exist_ok=True)

        destination = PENDING_DIR / f"{machine_key}.json"
        temporary = PENDING_DIR / f".{machine_key}.{os.getpid()}.tmp"

        temporary.write_text(
            json.dumps(record, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        os.chmod(temporary, 0o600)
        os.replace(temporary, destination)

        self.send_json(
            201,
            {
                "status": "registered",
                "machine_key": machine_key,
                "ip": self.client_address[0],
            },
        )


if __name__ == "__main__":
    server = ThreadingHTTPServer(
        (LISTEN_ADDRESS, LISTEN_PORT),
        RegisterHandler,
    )
    server.serve_forever()
