#!/usr/bin/python3

from __future__ import annotations

import ipaddress
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from alt_deploy.config import Settings
from alt_deploy.errors import ControlError
from alt_deploy.registration_admission import (
    RegistrationAdmissionService,
    RegistrationRequest,
)

LISTEN_ADDRESS = "0.0.0.0"
LISTEN_PORT = 8088

ALLOWED_NETWORKS = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("192.168.100.0/23"),
)

HOSTNAME_RE = re.compile(
    r"^[a-zA-Z0-9][a-zA-Z0-9.-]{0,62}$"
)
MAC_RE = re.compile(
    r"^[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}$"
)
UUID_RE = re.compile(r"^[0-9a-fA-F-]{8,64}$")

SETTINGS = Settings.from_env()


def handle_registration(
    payload: object,
    client_ip: str,
    settings: Settings,
) -> tuple[int, dict[str, object]]:
    if not isinstance(payload, dict):
        return 400, {"status": "invalid_json_object"}

    hostname = str(
        payload.get("hostname", "")
    ).strip().lower()
    mac = str(
        payload.get("mac", "")
    ).strip().lower()
    machine_uuid = str(
        payload.get("uuid", "")
    ).strip().lower()

    if not HOSTNAME_RE.fullmatch(hostname):
        return 400, {"status": "invalid_hostname"}
    if not MAC_RE.fullmatch(mac):
        return 400, {"status": "invalid_mac"}
    if machine_uuid and not UUID_RE.fullmatch(machine_uuid):
        return 400, {"status": "invalid_uuid"}

    try:
        decision = RegistrationAdmissionService(
            settings
        ).admit(
            RegistrationRequest(
                hostname=hostname,
                mac=mac,
                machine_uuid=machine_uuid,
                ip=client_ip,
            )
        )
    except ControlError as exc:
        status = {
            "machine_assigned": 409,
            "machine_busy": 409,
            "machine_archive_cleanup_required": 409,
            "machine_identity_conflict": 409,
            "machine_record_invalid": 409,
            "machine_record_unsafe": 409,
            "machine_archive_invalid": 409,
            "registration_storage_failed": 500,
            "controller_lock_unsafe": 500,
        }.get(exc.code, 500)
        return status, exc.to_dict()

    return decision.http_status, decision.payload


class RegisterHandler(BaseHTTPRequestHandler):
    server_version = "ALTDeployRegister/2.0"

    def send_json(
        self,
        status: int,
        payload: dict[str, object],
    ) -> None:
        body = json.dumps(
            payload,
            ensure_ascii=False,
            indent=2,
        ).encode("utf-8")

        self.send_response(status)
        self.send_header(
            "Content-Type",
            "application/json; charset=utf-8",
        )
        self.send_header(
            "Content-Length",
            str(len(body)),
        )
        self.end_headers()
        self.wfile.write(body)

    def client_is_allowed(self) -> bool:
        try:
            address = ipaddress.ip_address(
                self.client_address[0]
            )
        except ValueError:
            return False

        return any(
            address in network
            for network in ALLOWED_NETWORKS
        )

    def do_GET(self) -> None:
        if self.path.split("?", 1)[0] != "/health":
            self.send_json(
                404,
                {"status": "not_found"},
            )
            return

        self.send_json(200, {"status": "ok"})

    def do_POST(self) -> None:
        if self.path.split("?", 1)[0] != "/register":
            self.send_json(
                404,
                {"status": "not_found"},
            )
            return

        if not self.client_is_allowed():
            self.send_json(
                403,
                {"status": "forbidden"},
            )
            return

        try:
            content_length = int(
                self.headers.get("Content-Length", "0")
            )
        except ValueError:
            self.send_json(
                400,
                {"status": "invalid_content_length"},
            )
            return

        if content_length < 1 or content_length > 16384:
            self.send_json(
                413,
                {"status": "invalid_payload_size"},
            )
            return

        try:
            raw_body = self.rfile.read(content_length)
            payload = json.loads(
                raw_body.decode("utf-8")
            )
        except (UnicodeDecodeError, json.JSONDecodeError):
            self.send_json(
                400,
                {"status": "invalid_json"},
            )
            return

        status, response = handle_registration(
            payload,
            self.client_address[0],
            SETTINGS,
        )
        self.send_json(status, response)


if __name__ == "__main__":
    server = ThreadingHTTPServer(
        (LISTEN_ADDRESS, LISTEN_PORT),
        RegisterHandler,
    )
    server.serve_forever()
