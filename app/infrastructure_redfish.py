"""Read host power from a verified management controller."""

import base64
import hashlib
import http.client
import json
import re
import ssl
from datetime import datetime, timezone
from pathlib import Path

from .infrastructure_map import NETWORK_KINDS, REDFISH_PAIR_MAX_AGE, REDFISH_PAIR_SOURCE, observation_is_fresh, port_label_key


def _read_resource(spec: dict, credential: Path | None, path: str) -> dict | None:
    pin = spec.get("tls_sha256", "")
    if credential is None or not re.fullmatch(r"[a-fA-F0-9]{64}", pin):
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
        return document
    return None


def _read_power(spec: dict, credential: Path | None) -> dict:
    path = spec.get("path", "")
    if not isinstance(path, str) or not re.fullmatch(r"/redfish/v1/Systems/[A-Za-z0-9_-]{1,64}", path):
        return {}
    system = _read_resource(spec, credential, path) or {}
    power = system.get("PowerState")
    if power not in ("On", "Off", "PoweringOn", "PoweringOff"):
        return {}
    result = {"state": power, "restorePolicy": system.get("PowerRestorePolicy"), "lastResetAt": system.get("LastResetTime")}
    if isinstance(status := system.get("Status"), dict):
        result.update(health=status.get("Health"), healthRollup=status.get("HealthRollup"))
    if isinstance(memory := system.get("MemorySummary"), dict):
        result["totalSystemMemoryGiB"] = memory.get("TotalSystemMemoryGiB")
    return result


def _confirm_management_pair(graph, nodes, controller_id, spec, credential, now):
    path = spec.get("interface_path")
    if not isinstance(path, str) or not re.fullmatch(
        r"/redfish/v1/Managers/[A-Za-z0-9_-]{1,64}/EthernetInterfaces/[A-Za-z0-9_-]{1,64}", path,
    ):
        return
    name = path.rsplit("/", 1)[-1]
    reading = _read_resource(spec, credential, path) or {}
    mac = str(reading.get("MACAddress", "")).lower()
    addresses = reading.get("IPv4Addresses")
    speed = reading.get("SpeedMbps")
    if (reading.get("Id") != name or reading.get("LinkStatus") != "LinkUp"
            or reading.get("InterfaceEnabled") is not True or not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac)
            or type(speed) is not int or not 1 <= speed <= 1_000_000 or not isinstance(addresses, list)
            or not any(isinstance(row, dict) and row.get("Address") == spec["ip"] for row in addresses)):
        return
    matches = {}
    for edge in graph["links"]:
        if not edge["confirmed"] or edge["kind"] != "Путь по MAC-таблице" or controller_id not in (edge["a"], edge["b"]):
            continue
        side = "b" if edge["a"] == controller_id else "a"
        switch = edge[side]
        for report in edge.get("portEvidence", []):
            if (nodes[switch]["kind"] == NETWORK_KINDS[0] and report["confirmed"] and report["source"] == "netctl FDB"
                    and report.get("managementAddress") == spec["ip"]
                    and report.get("learnedEndpoint") == {"switchId": switch, "deviceId": controller_id, "mac": mac}
                    and observation_is_fresh(report.get("at"), now, max_age=REDFISH_PAIR_MAX_AGE)):
                matches[switch, port_label_key(report[side])] = report["at"]
    if len(matches) != 1:
        return
    ((switch, label), observed), = matches.items()
    ports = [port for port in nodes[switch].get("ports", []) if port_label_key(port["name"]) == label]
    if len(ports) != 1:
        return
    port, = ports
    learned = port.get("fdbLearned", {})
    if (port.get("state") != "up" or learned.get("partial") is not False or learned.get("learnedMacCount") != 1
            or learned.get("checkedAt") != port.get("checkedAt")
            or not observation_is_fresh(learned.get("checkedAt"), now, max_age=REDFISH_PAIR_MAX_AGE)
            or abs(datetime.fromisoformat(observed) - datetime.fromisoformat(learned["checkedAt"])).total_seconds() > 30
            or port.get("speedBps") != speed * 1_000_000):
        return
    for edge in graph["links"]:
        if edge["kind"] != "Сетевое соединение" or not edge["confirmed"] or {edge["a"], edge["b"]} != {switch, controller_id}:
            continue
        a, b = (port["name"], name) if edge["a"] == switch else (name, port["name"])
        evidence = edge.get("portEvidence", [])
        if any(row["confirmed"] and row["source"] == "GitHub"
               and port_label_key(row["a"]) == port_label_key(a) and port_label_key(row["b"]) == port_label_key(b)
               for row in evidence):
            evidence.append({"a": a, "b": b, "source": REDFISH_PAIR_SOURCE, "confirmed": True,
                             "at": min(datetime.fromisoformat(observed), datetime.fromisoformat(learned["checkedAt"])).isoformat()})


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
            host["hardwarePower"] = {**power, "controllerId": controller_id,
                                     "checkedAt": datetime.now(timezone.utc).isoformat()}
        _confirm_management_pair(graph, nodes, controller_id, spec, credential, now)
