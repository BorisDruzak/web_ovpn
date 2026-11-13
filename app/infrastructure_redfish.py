"""Read host power from a verified management controller."""

import base64
import hashlib
import http.client
import json
import re
import ssl
from datetime import datetime, timezone
from pathlib import Path

from .infrastructure_map import observation_is_fresh


def _read_power(spec: dict, credential: Path | None) -> str | None:
    pin = spec.get("tls_sha256", "")
    path = spec.get("path", "")
    if credential is None or not re.fullmatch(r"[a-fA-F0-9]{64}", pin):
        return None
    if not re.fullmatch(r"/redfish/v1/Systems/[A-Za-z0-9_-]{1,64}", path):
        return None
    try:
        with credential.open("rb") as stream:
            secret = stream.read(1025)
        if not 1 <= len(secret) <= 1024 or b":" not in secret or not all(32 <= byte <= 126 for byte in secret):
            return None
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        tls.check_hostname = False
        tls.verify_mode = ssl.CERT_NONE
        with_connection = http.client.HTTPSConnection(spec["ip"], 443, timeout=4, context=tls)
        try:
            with_connection.connect()
            peer = with_connection.sock.getpeercert(binary_form=True)
            if not peer or hashlib.sha256(peer).hexdigest() != pin.lower():
                return None
            authorization = "Basic " + base64.b64encode(secret).decode("ascii")
            with_connection.request("GET", path, headers={"Accept": "application/json", "Authorization": authorization})
            response = with_connection.getresponse()
            if response.status != 200:
                return None
            payload = response.read(65537)
            if len(payload) > 65536:
                return None
            document = json.loads(payload)
        finally:
            with_connection.close()
    except (OSError, http.client.HTTPException, ValueError, RecursionError):
        return None
    if isinstance(document, dict) and document.get("@odata.id") == path:
        power = document.get("PowerState")
        if power in ("On", "Off", "PoweringOn", "PoweringOff"):
            return power
    return None


def collect_redfish_power(graph: dict, specs: dict, credentials: Path | None, now: datetime) -> None:
    nodes = {node["id"]: node for node in graph["nodes"]}
    for controller_id, spec in specs.items():
        controller = nodes.get(controller_id, {})
        if (not re.fullmatch(r"[a-z0-9-]{1,64}", controller_id)
                or controller.get("kind") != "Контроллер управления"
                or not isinstance(spec, dict) or not spec.get("ip")
                or controller.get("probeTargetIP") != spec["ip"]
                or not observation_is_fresh(controller.get("probeTargetIdentityAt"), now)):
            continue
        hosts = {edge["b"] for edge in graph["links"] if edge["a"] == controller_id
                 and edge["kind"] == "Управление оборудованием" and edge["confirmed"]}
        if len(hosts) != 1:
            continue
        host = nodes[next(iter(hosts))]
        if host["kind"] != "Сервер" or host.get("guest"):
            continue
        credential = credentials / f"redfish-{controller_id}" if credentials else None
        if power := _read_power(spec, credential):
            host["hardwarePower"] = {"state": power, "controllerId": controller_id,
                                     "checkedAt": datetime.now(timezone.utc).isoformat()}
