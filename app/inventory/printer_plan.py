"""Bounded, fail-closed same-location Kyocera selection and private bundle export."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import uuid

CATALOG = (
    Path(__file__).resolve().parents[2]
    / "deploy/alt-linux/ansible/roles/inventory_printers/files/driver_catalog.json"
)
MAX_PRINTERS = 16
MAX_BYTES = 16 * 1024 * 1024


class PrinterPlanError(ValueError):
    pass


def canonical(value):
    return json.dumps(
        value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":")
    ).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def driver_catalog():
    return json.loads(CATALOG.read_text(encoding="utf-8"))


def normalize_model(value):
    value = re.sub(r"\b(KYOCERA|KYOSERA|ECOSYS|KPDL)\b", "", str(value or "").upper())
    return re.sub("[^A-Z0-9]", "", value)


def normalized_mac(value):
    raw = re.sub("[:-]", "", str(value or "")).upper()
    if (
        not re.fullmatch("[0-9A-F]{12}", raw)
        or int(raw[:2], 16) & 1
        or int(raw, 16) == 0
    ):
        raise PrinterPlanError("printer_mac_invalid")
    return ":".join(raw[n : n + 2] for n in range(0, 12, 2))


def _uuid(value):
    try:
        if str(uuid.UUID(value)) != value or uuid.UUID(value).int == 0:
            raise ValueError
    except (ValueError, TypeError, AttributeError):
        raise PrinterPlanError("printer_identity_invalid") from None
    return value


def _ip(value):
    try:
        ip = ipaddress.IPv4Address(value)
        if (
            str(ip) != value
            or ip.is_multicast
            or ip.is_unspecified
            or ip.is_loopback
            or ip.is_link_local
            or int(ip) == 0xFFFFFFFF
        ):
            raise ValueError
        return str(ip)
    except (ValueError, TypeError):
        raise PrinterPlanError("printer_ip_invalid") from None


def _now(value):
    value = value or datetime.now(timezone.utc)
    if value.tzinfo is None:
        raise PrinterPlanError("printer_clock_invalid")
    return value.astimezone(timezone.utc)


def validate_ppd(payload, model, expected_sha):
    if (
        not isinstance(payload, bytes)
        or len(payload) > 1048576
        or hashlib.sha256(payload).hexdigest() != expected_sha
    ):
        raise PrinterPlanError("printer_driver_hash_invalid")
    text = payload.decode("latin1")
    if not text.startswith("*PPD-Adobe:") or "\x00" in text:
        raise PrinterPlanError("printer_driver_invalid")
    if re.search(
        r"^\*(?:cupsFilter2?|cupsPreFilter|cupsPortMonitor|FoomaticRIPCommandLine|APAutoSetupTool)\s*:",
        text,
        re.M,
    ):
        raise PrinterPlanError("printer_driver_external_filter")
    names = re.findall(r'^\*ModelName:\s*"([^"]+)"', text, re.M)
    if len(names) != 1 or normalize_model(names[0]) != model:
        raise PrinterPlanError("printer_driver_model_invalid")


def build_plan(snapshot, pc_id, target_uuid, probe, *, now=None):
    now = _now(now)
    _uuid(pc_id)
    _uuid(target_uuid)
    if len(canonical(snapshot)) > MAX_BYTES or len(snapshot["assets"]) > 10000:
        raise PrinterPlanError("printer_inventory_limit")
    assets = {a["id"]: a for a in snapshot["assets"]}
    if len(assets) != len(snapshot["assets"]):
        raise PrinterPlanError("printer_inventory_ambiguous")
    pc = assets.get(pc_id)
    if (
        not pc
        or pc["type"] != "PC"
        or pc.get("location_id") not in snapshot["locations"]
    ):
        raise PrinterPlanError("printer_pc_location_invalid")
    identifiers = defaultdict(lambda: defaultdict(set))
    owners = defaultdict(set)
    for item in snapshot["identifiers"]:
        if item["asset_id"] not in assets or item["type"] not in ("ip", "mac"):
            continue
        value = item["value"]
        try:
            value = normalized_mac(value) if item["type"] == "mac" else _ip(value)
        except PrinterPlanError:
            value = "INVALID:" + str(value)
        identifiers[item["asset_id"]][item["type"]].add(value)
        owners[(item["type"], value)].add(item["asset_id"])
    macs = sorted(
        value
        for value in identifiers[pc_id]["mac"]
        if not value.startswith("INVALID:") and owners[("mac", value)] == {pc_id}
    )
    if not macs:
        raise PrinterPlanError("printer_pc_mac_unverified")
    details = {
        p["asset_id"]: p.get("connection_type") for p in snapshot["printer_details"]
    }
    candidates = [
        a
        for a in assets.values()
        if a["type"] == "PRINTER"
        and a.get("location_id") == pc["location_id"]
        and (
            str(a.get("manufacturer") or "").strip().lower() in ("kyocera", "kyosera")
            or not a.get("manufacturer")
            and normalize_model(a.get("model")) in driver_catalog()
        )
        and a.get("status")
        not in ("broken", "storage", "reserve", "repair", "to_writeoff", "written_off")
        and details.get(a["id"]) != "usb"
    ]
    if len(candidates) > MAX_PRINTERS:
        raise PrinterPlanError("printer_candidate_limit")
    printers, excluded = [], []
    catalog = driver_catalog()
    for a in sorted(candidates, key=lambda a: a["id"]):
        reason = None
        addresses = identifiers[a["id"]]["ip"]
        if a.get("status") != "in_use":
            reason = "printer_status_unknown"
        elif details.get(a["id"]) != "network":
            reason = "printer_connection_unknown"
        elif not addresses:
            reason = "printer_ip_missing"
        elif len(addresses) != 1:
            reason = "printer_ip_ambiguous"
        else:
            ip = next(iter(addresses))
            if ip.startswith("INVALID:"):
                reason = "printer_ip_invalid"
            elif owners[("ip", ip)] != {a["id"]}:
                reason = "printer_ip_conflict"
        if reason is None:
            try:
                reply = probe(["printer", "inspect-ip", "--target", ip], 30)
                result = reply.get("printer", {})
                if reply.get("status") != "ok" or result.get("status") != "found":
                    raise ValueError
                evidence = result.get("suggestions", {})
                if not isinstance(evidence, dict):
                    raise ValueError
            except Exception:
                reason = "printer_snmp_unavailable"
        if reason is None:
            model = normalize_model(evidence.get("model"))
            stored_model = normalize_model(a.get("model"))
            serial = str(evidence.get("serial_number") or "").strip()
            try:
                mac = normalized_mac(evidence.get("mac"))
            except PrinterPlanError:
                mac = ""
            stored_serial = str(a.get("serial") or "").strip()
            expected_macs = identifiers[a["id"]]["mac"]
            if not model or not (serial or mac):
                reason = "printer_snmp_identity_missing"
            elif not stored_model or model != stored_model:
                reason = "printer_model_conflict"
            elif model not in catalog:
                reason = "printer_driver_unavailable"
            elif stored_serial not in ("", "-", "unknown") and serial != stored_serial:
                reason = "printer_serial_conflict"
            elif expected_macs and (not mac or mac not in expected_macs):
                reason = "printer_mac_conflict"
            elif not (expected_macs or stored_serial not in ("", "-", "unknown")):
                reason = "printer_inventory_identity_missing"
        if reason:
            excluded.append({"asset_id": a["id"], "reason": reason})
        else:
            _uuid(a["id"])
            printers.append(
                {
                    "asset_id": a["id"],
                    "queue": "inv_kyocera_" + a["id"].replace("-", ""),
                    "ip": ip,
                    "model": model,
                    "driver": catalog[model],
                    "snmp": {
                        "version": result.get("snmp_version"),
                        "serial": serial,
                        "mac": mac,
                    },
                }
            )
    plan = {
        "schema_version": 1,
        "created_at": now.isoformat(),
        "expires_at": (now + timedelta(minutes=10)).isoformat(),
        "target": {"uuid": target_uuid, "macs": macs, "pc_asset_id": pc_id},
        "location_id": pc["location_id"],
        "source_sha256": digest(snapshot),
        "printers": printers,
        "excluded": excluded,
        "ready": bool(printers) and not excluded,
    }
    return dict(plan, sha256=digest(plan))


def export_plan(plan, snapshot, probe, source_dir, destination, *, now=None):
    now = _now(now)
    try:
        if (
            plan["sha256"] != digest({k: v for k, v in plan.items() if k != "sha256"})
            or not plan["ready"]
        ):
            raise ValueError
        created = datetime.fromisoformat(plan["created_at"])
        expires = datetime.fromisoformat(plan["expires_at"])
        if not created <= now < expires or expires - created != timedelta(minutes=10):
            raise ValueError
        refreshed = build_plan(
            snapshot,
            plan["target"]["pc_asset_id"],
            plan["target"]["uuid"],
            probe,
            now=now,
        )
        if any(
            refreshed[k] != plan[k]
            for k in (
                "target",
                "location_id",
                "source_sha256",
                "printers",
                "excluded",
                "ready",
            )
        ):
            raise ValueError
    except (ValueError, KeyError, TypeError):
        raise PrinterPlanError("printer_plan_changed_or_expired") from None
    payloads = {}
    for row in plan["printers"]:
        name = row["driver"]["filename"]
        path = Path(source_dir) / name
        if Path(name).name != name or any(
            p.is_symlink() for p in (path, *path.parents)
        ):
            raise PrinterPlanError("printer_driver_path_invalid")
        try:
            if not path.is_file() or path.stat().st_size > 1048576:
                raise OSError
            payload = path.read_bytes()
        except OSError:
            raise PrinterPlanError("printer_driver_missing") from None
        validate_ppd(payload, row["model"], row["driver"]["sha256"])
        payloads[name] = payload
    destination = Path(destination)
    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    (destination / "drivers").mkdir(mode=0o700)
    for name, payload in payloads.items():
        path = destination / "drivers" / name
        path.write_bytes(payload)
        path.chmod(0o600)
    for name, value in (
        ("request.json", plan),
        (
            "vars.json",
            {
                "inventory_printer_request": plan,
                "inventory_printer_driver_dir": str(
                    (destination / "drivers").resolve()
                ),
            },
        ),
    ):
        path = destination / name
        path.write_bytes(canonical(value) + b"\n")
        path.chmod(0o600)
    return {
        "status": "ok",
        "bundle": str(destination),
        "queues": len(plan["printers"]),
        "sha256": plan["sha256"],
    }
