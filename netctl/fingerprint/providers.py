from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Mapping
from dataclasses import asdict
from pathlib import Path

from ..normalizer import normalize_mac
from .models import SUPPORTED_DEVICE_TYPES, FingerprintEvidence
from .oui import DEFAULT_OUI_PATH, OUIDatabase
from ..util import utc_now


_LLDP_TYPES = {
    "bridge": "network",
    "router": "network",
    "telephone": "phone",
    "wlan_access_point": "network",
}
_TEXT_PATTERNS = {
    "camera": re.compile(r"(?:^|[^a-z0-9])(cam(?:era)?|hikvision|dahua|hiwatch)(?:[^a-z0-9]|$)"),
    "network": re.compile(r"(?:^|[^a-z0-9])(router|switch|gateway|mikrotik|access[ -]?point|\bap)(?:[^a-z0-9]|$)"),
    "pc": re.compile(r"(?:^|[^a-z0-9])(pc|workstation|desktop|laptop|notebook)(?:[^a-z0-9]|$)"),
    "phone": re.compile(r"(?:^|[^a-z0-9])(phone|telephone|voip|grandstream|yealink)(?:[^a-z0-9]|$)"),
    "printer": re.compile(r"(?:^|[^a-z0-9])(printer|print|kyocera|brother|xerox|laserjet)(?:[^a-z0-9]|$)"),
    "server": re.compile(r"(?:^|[^a-z0-9])(server|srv|pve|proxmox|nas)(?:[^a-z0-9]|$)"),
}


def _evidence(
    provider: str,
    signal: str,
    candidate_type: str,
    weight: int,
    summary: str,
) -> FingerprintEvidence:
    return FingerprintEvidence(provider, signal, candidate_type, weight, summary)


def _string_list(value: object, *, limit: int = 64) -> tuple[str, ...]:
    try:
        decoded = json.loads(str(value or "[]"))
    except (TypeError, ValueError, json.JSONDecodeError):
        return ()
    if not isinstance(decoded, list):
        return ()
    return tuple(str(item)[:512] for item in decoded[:limit] if isinstance(item, str))


def _dictionary_list(value: object, *, limit: int = 32) -> tuple[dict[str, object], ...]:
    try:
        decoded = json.loads(str(value or "[]"))
    except (TypeError, ValueError, json.JSONDecodeError):
        return ()
    if not isinstance(decoded, list):
        return ()
    return tuple(dict(item) for item in decoded[:limit] if isinstance(item, dict))


def endpoint_agent_evidence(
    record: Mapping[str, object] | None,
) -> tuple[FingerprintEvidence, ...]:
    if not record or record.get("state") != "confirmed":
        return ()
    device_type = record.get("device_type")
    if isinstance(device_type, str) and device_type in SUPPORTED_DEVICE_TYPES - {"unknown"}:
        return (
            _evidence(
                "endpoint_agent",
                "device_type",
                device_type,
                100,
                f"Confirmed endpoint-agent device type: {device_type}",
            ),
        )
    os_family = " ".join(str(record.get("os_family") or "").split()).casefold()
    if any(
        value in os_family
        for value in (
            "routeros",
            "network os",
            "cisco ios",
            "ios xe",
            "ios-xe",
            "nx-os",
            "nxos",
        )
    ):
        candidates = ("network",)
    elif (
        "android" in os_family
        or os_family == "ios"
        or os_family.startswith("ios ")
        or os_family.startswith("apple ios")
        or os_family.startswith("iphone os")
        or os_family.startswith("ipados")
    ):
        candidates = ("phone",)
    elif any(value in os_family for value in ("mac os", "macos")):
        candidates = ("pc",)
    elif any(value in os_family for value in ("windows", "linux")):
        candidates = ("pc", "server")
    else:
        candidates = ()
    return tuple(
        _evidence(
            "endpoint_agent",
            "os_family",
            candidate,
            90,
            f"Confirmed endpoint-agent OS family suggests {candidate}",
        )
        for candidate in candidates
    )


def store_endpoint_agent_evidence(
    conn: sqlite3.Connection,
    asset_id: int,
    record: Mapping[str, object],
    *,
    observed_at: str,
) -> None:
    """Store only confirmed, bounded agent classification fields for DB-only recompute."""
    if conn.execute("SELECT 1 FROM assets WHERE id = ?", (asset_id,)).fetchone() is None:
        raise ValueError("asset not found")
    device_type = record.get("device_type")
    safe_device_type = (
        device_type
        if isinstance(device_type, str)
        and device_type in SUPPORTED_DEVICE_TYPES - {"unknown"}
        else ""
    )
    os_family = record.get("os_family")
    safe_os_family = " ".join(os_family.split())[:128] if isinstance(os_family, str) else ""
    confirmed = record.get("state") == "confirmed" and bool(
        endpoint_agent_evidence(
            {
                "state": "confirmed",
                "device_type": safe_device_type,
                "os_family": safe_os_family,
            }
        )
    )
    if not confirmed:
        conn.execute(
            "DELETE FROM asset_endpoint_agent_evidence_current WHERE asset_id = ?",
            (asset_id,),
        )
        return
    conn.execute(
        """INSERT INTO asset_endpoint_agent_evidence_current
           (asset_id, device_type, os_family, observed_at)
           VALUES (?, ?, ?, ?)
           ON CONFLICT(asset_id) DO UPDATE SET
               device_type = excluded.device_type,
               os_family = excluded.os_family,
               observed_at = excluded.observed_at""",
        (asset_id, safe_device_type, safe_os_family, observed_at),
    )


def replace_endpoint_agent_evidence(
    conn: sqlite3.Connection,
    records: object,
    *,
    observed_at: str,
    oui_path: str | Path = DEFAULT_OUI_PATH,
) -> dict[str, int]:
    """Atomically replace the bounded endpoint-agent snapshot and recompute V2.

    This is deliberately a DB-only ingestion boundary. It never performs endpoint
    discovery or starts Nmap, and it accepts no caller-supplied asset identifiers
    other than exact existing asset keys.
    """
    if not isinstance(records, list) or len(records) > 1000:
        raise ValueError("endpoint-agent evidence must be a list of at most 1000 records")
    normalized: list[dict[str, object]] = []
    seen_asset_keys: set[str] = set()
    for item in records:
        if not isinstance(item, Mapping):
            raise ValueError("endpoint-agent evidence record must be an object")
        asset_key = item.get("asset_key")
        state = item.get("state")
        if (
            not isinstance(asset_key, str)
            or not asset_key
            or len(asset_key) > 512
            or "\x00" in asset_key
            or state not in {"confirmed", "ambiguous", "no_agent"}
            or asset_key in seen_asset_keys
        ):
            raise ValueError("endpoint-agent evidence record is invalid")
        seen_asset_keys.add(asset_key)
        normalized.append(
            {
                "asset_key": asset_key,
                "state": state,
                "device_type": item.get("device_type"),
                "os_family": item.get("os_family"),
            }
        )

    if conn.in_transaction:
        raise ValueError("endpoint-agent evidence sync requires a clean transaction")
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("DELETE FROM asset_endpoint_agent_evidence_current")
        matched = 0
        confirmed = 0
        for record in normalized:
            asset = conn.execute(
                "SELECT id FROM assets WHERE asset_key = ?",
                (record["asset_key"],),
            ).fetchone()
            if asset is None:
                continue
            matched += 1
            asset_id = int(asset["id"])
            store_endpoint_agent_evidence(
                conn,
                asset_id,
                record,
                observed_at=observed_at,
            )
            if conn.execute(
                """SELECT 1 FROM asset_endpoint_agent_evidence_current
                   WHERE asset_id = ?""",
                (asset_id,),
            ).fetchone() is not None:
                confirmed += 1
        fingerprints = recompute_all_asset_fingerprints(
            conn,
            computed_at=observed_at,
            oui_path=oui_path,
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return {
        "assets": matched,
        "confirmed": confirmed,
        "fingerprints": fingerprints,
    }


def oui_vendor_evidence(vendor: str) -> tuple[FingerprintEvidence, ...]:
    value = vendor.casefold()
    rules = (
        (("hikvision", "dahua", "hiwatch"), "camera", "camera_vendor"),
        (("grandstream", "yealink"), "phone", "phone_vendor"),
        (("kyocera", "brother", "xerox"), "printer", "printer_vendor"),
        (("mikrotik",), "network", "network_vendor"),
    )
    for needles, candidate, signal in rules:
        if any(needle in value for needle in needles):
            matched = next(needle for needle in needles if needle in value)
            return (
                _evidence(
                    "oui",
                    matched,
                    candidate,
                    50,
                    f"Local OUI vendor suggests {candidate}: {vendor[:128]}",
                ),
            )
    return ()


def port_role_evidence(role: str) -> tuple[FingerprintEvidence, ...]:
    if role != "endpoint":
        return ()
    return tuple(
        _evidence(
            "port_role",
            "endpoint",
            candidate,
            10,
            "Attached switch port has an endpoint role",
        )
        for candidate in ("camera", "pc", "phone", "printer", "server")
    )


def _text_evidence(
    provider: str, signal: str, value: object, weight: int
) -> tuple[FingerprintEvidence, ...]:
    if not isinstance(value, str) or not value.strip():
        return ()
    normalized = value.casefold()
    return tuple(
        _evidence(
            provider,
            signal,
            candidate,
            weight,
            f"{provider.replace('_', ' ').title()} text suggests {candidate}",
        )
        for candidate, pattern in _TEXT_PATTERNS.items()
        if pattern.search(normalized)
    )


def _snmp_evidence(
    conn: sqlite3.Connection, asset_id: int
) -> tuple[FingerprintEvidence, ...]:
    row = conn.execute(
        """SELECT sources.name
           FROM switch_devices AS devices
           JOIN network_sources AS sources ON sources.id = devices.source_id
           WHERE devices.runtime_asset_id = ?
           ORDER BY sources.name, sources.id LIMIT 1""",
        (asset_id,),
    ).fetchone()
    if row is None:
        return ()
    return (
        _evidence(
            "snmp",
            "known_switch",
            "network",
            100,
            f"Known SNMP switch identity: {str(row['name'])[:128]}",
        ),
    )


def _lldp_evidence(
    conn: sqlite3.Connection, asset_id: int, macs: set[str]
) -> tuple[FingerprintEvidence, ...]:
    if not macs:
        return ()
    evidence: set[FingerprintEvidence] = set()
    rows = conn.execute(
        """SELECT chassis_id, chassis_id_subtype, port_id, port_id_subtype,
                  system_capabilities_json, enabled_capabilities_json
           FROM current_switch_lldp_neighbors
           ORDER BY source_id, local_port_key, chassis_id, port_id"""
    )
    for row in rows:
        identifiers = {
            normalized
            for value, subtype in (
                (row["chassis_id"], str(row["chassis_id_subtype"] or "")),
                (row["port_id"], str(row["port_id_subtype"] or "")),
            )
            if subtype in {"", "mac_address"}
            and (normalized := normalize_mac(value)) is not None
        }
        if not identifiers.intersection(macs):
            continue
        capabilities = {
            *_string_list(row["system_capabilities_json"], limit=16),
            *_string_list(row["enabled_capabilities_json"], limit=16),
        }
        for capability in sorted(capabilities):
            candidate = _LLDP_TYPES.get(capability)
            if candidate is not None:
                evidence.add(
                    _evidence(
                        "lldp",
                        capability,
                        candidate,
                        90,
                        f"LLDP {capability} capability",
                    )
                )
    return tuple(sorted(evidence, key=lambda item: (item.candidate_type, item.signal)))


def _quality_weight(base: int, quality: int | None, *, maximum: int) -> int | None:
    if type(quality) is not int or not 0 <= quality <= maximum:
        return None
    ratio = quality / maximum
    if ratio >= 0.85:
        return base
    if ratio >= 0.70:
        return max(30, base - 15)
    if ratio >= 0.60:
        return max(30, base - 25)
    return None


def _nmap_os_evidence(
    classes_json: object, match_accuracy: object
) -> tuple[FingerprintEvidence, ...]:
    evidence: set[FingerprintEvidence] = set()
    for item in _dictionary_list(classes_json):
        device_class = str(item.get("type") or "").casefold()
        family = str(item.get("osfamily") or "").casefold()
        combined = f"{device_class} {family} {str(item.get('vendor') or '').casefold()}"
        qualities = [
            value
            for value in (item.get("accuracy"), match_accuracy)
            if type(value) is int and 0 <= value <= 100
        ]
        quality = min(qualities) if qualities else None
        if any(value in combined for value in ("network device", "router", "switch", "wap")):
            candidate_weights = (("network", 70, "network_device"),)
        elif any(value in combined for value in ("phone", "voip")):
            candidate_weights = (("phone", 70, "phone"),)
        elif "printer" in combined:
            candidate_weights = (("printer", 70, "printer"),)
        elif any(value in combined for value in ("camera", "webcam")):
            candidate_weights = (("camera", 70, "camera"),)
        elif "windows" in family and "general purpose" in device_class:
            candidate_weights = (
                ("pc", 40, "windows_general_purpose"),
                ("server", 40, "windows_general_purpose"),
            )
        elif "linux" in family and "general purpose" in device_class:
            candidate_weights = (("server", 40, "linux_general_purpose"),)
        elif any(value in family for value in ("mac os", "ios")) and "general purpose" in device_class:
            candidate_weights = (("pc", 40, "desktop_os"),)
        else:
            candidate_weights = ()
        for candidate, base_weight, signal in candidate_weights:
            weight = _quality_weight(base_weight, quality, maximum=100)
            if weight is not None:
                evidence.add(
                    _evidence(
                        "nmap_os",
                        signal,
                        candidate,
                        weight,
                        f"Nmap OS class suggests {candidate} at {quality}% accuracy",
                    )
                )
    return tuple(sorted(evidence, key=lambda item: (item.candidate_type, item.signal)))


def _nmap_evidence(
    conn: sqlite3.Connection, asset_id: int
) -> tuple[FingerprintEvidence, ...]:
    run = conn.execute(
        """SELECT runs.id
           FROM nmap_fingerprint_runs AS runs
           WHERE runs.asset_id = ? AND runs.status = 'success'
             AND EXISTS (
                 SELECT 1 FROM ip_observations AS ips
                 WHERE ips.asset_id = runs.asset_id AND ips.is_current = 1
                   AND ips.ip = runs.target_ip
             )
           ORDER BY runs.finished_at DESC, runs.id DESC LIMIT 1""",
        (asset_id,),
    ).fetchone()
    if run is None:
        return ()
    run_id = int(run["id"])
    evidence: set[FingerprintEvidence] = set()
    for row in conn.execute(
        """SELECT service_name, product, version, extra_info, method,
                  confidence, cpe_json
           FROM nmap_fingerprint_ports
           WHERE run_id = ? AND state = 'open'
           ORDER BY protocol, port, id""",
        (run_id,),
    ):
        text = " ".join(
            (
                str(row["service_name"] or ""),
                str(row["product"] or ""),
                str(row["version"] or ""),
                str(row["extra_info"] or ""),
                *_string_list(row["cpe_json"]),
            )
        ).casefold()
        method = str(row["method"] or "").casefold()
        base_weight = 60 if method == "probed" else 40 if method == "table" else 0
        if base_weight == 0:
            continue
        weight = _quality_weight(base_weight, row["confidence"], maximum=10)
        if weight is None:
            continue
        quality_summary = (
            f" from {method} detection at {int(row['confidence'])}/10 confidence"
        )
        if any(value in text for value in ("rtsp", "hikvision", "dahua", "hiwatch")):
            evidence.add(_evidence("nmap_service", "camera_product", "camera", weight, f"Nmap service/product suggests a camera{quality_summary}"))
        if any(value in text for value in ("jetdirect", "ipp", "printer", "laserjet")):
            evidence.add(_evidence("nmap_service", "printer_product", "printer", weight, f"Nmap service/product suggests a printer{quality_summary}"))
        if any(value in text for value in ("routeros", "mikrotik")):
            evidence.add(_evidence("nmap_service", "network_product", "network", weight, f"Nmap service/product suggests network equipment{quality_summary}"))
    for row in conn.execute(
        """SELECT accuracy, classes_json FROM nmap_fingerprint_os_matches
           WHERE run_id = ? ORDER BY position, id""",
        (run_id,),
    ):
        evidence.update(_nmap_os_evidence(row["classes_json"], row["accuracy"]))
    return tuple(sorted(evidence, key=lambda item: (item.candidate_type, item.provider, item.signal)))


def _port_evidence(
    conn: sqlite3.Connection, asset_id: int
) -> tuple[FingerprintEvidence, ...]:
    roles = {
        str(row["role"])
        for row in conn.execute(
            """SELECT roles.role
               FROM asset_attachment_resolutions AS resolutions
               JOIN current_switch_port_roles AS roles
                 ON roles.source_id = resolutions.selected_source_id
                AND roles.port_key = resolutions.selected_port_key
               WHERE resolutions.asset_id = ? AND resolutions.status = 'confirmed'
               ORDER BY roles.source_id, roles.port_key""",
            (asset_id,),
        )
    }
    return tuple(item for role in sorted(roles) for item in port_role_evidence(role))


def collect_asset_evidence(
    conn: sqlite3.Connection,
    asset_id: int,
    *,
    oui_path: str | Path = DEFAULT_OUI_PATH,
) -> tuple[FingerprintEvidence, ...]:
    """Collect bounded Fingerprinting V2 evidence using database state and local OUI only."""
    asset = conn.execute(
        """SELECT kind, display_name, manual_name, legacy_comment
           FROM assets WHERE id = ?""",
        (asset_id,),
    ).fetchone()
    if asset is None:
        raise ValueError("asset not found")
    macs = {
        normalized
        for row in conn.execute(
            """SELECT mac FROM asset_interfaces
               WHERE asset_id = ? AND lifecycle = 'active' AND mac IS NOT NULL
               ORDER BY id""",
            (asset_id,),
        )
        if (normalized := normalize_mac(row["mac"])) is not None
    }
    evidence: set[FingerprintEvidence] = set()
    agent = conn.execute(
        """SELECT device_type, os_family
           FROM asset_endpoint_agent_evidence_current WHERE asset_id = ?""",
        (asset_id,),
    ).fetchone()
    if agent is not None:
        evidence.update(
            endpoint_agent_evidence(
                {
                    "state": "confirmed",
                    "device_type": str(agent["device_type"] or ""),
                    "os_family": str(agent["os_family"] or ""),
                }
            )
        )
    evidence.update(_snmp_evidence(conn, asset_id))
    evidence.update(_lldp_evidence(conn, asset_id, macs))
    evidence.update(_nmap_evidence(conn, asset_id))

    oui = OUIDatabase(oui_path)
    for mac in sorted(macs):
        evidence.update(oui_vendor_evidence(oui.lookup(mac)))

    for row in conn.execute(
        """SELECT hostname, source_type FROM hostname_observations
           WHERE asset_id = ? AND is_current = 1
           ORDER BY source_type, hostname, id LIMIT 64""",
        (asset_id,),
    ):
        source_type = str(row["source_type"] or "").casefold()
        provider = "dns_ptr" if "dns" in source_type or "ptr" in source_type else "hostname"
        signal = "dns_ptr" if provider == "dns_ptr" else "dhcp_hostname"
        evidence.update(_text_evidence(provider, signal, row["hostname"], 20))

    evidence.update(_text_evidence("display_name", "display_name", asset["display_name"], 15))
    evidence.update(_text_evidence("display_name", "manual_name", asset["manual_name"], 15))
    evidence.update(_text_evidence("legacy", "comment", asset["legacy_comment"], 15))
    raw_kind = str(asset["kind"] or "").casefold()
    if raw_kind in SUPPORTED_DEVICE_TYPES - {"unknown"}:
        evidence.add(_evidence("legacy", "raw_kind", raw_kind, 15, f"Raw runtime kind suggests {raw_kind}"))
    evidence.update(_port_evidence(conn, asset_id))
    return tuple(
        sorted(
            evidence,
            key=lambda item: (
                item.provider,
                item.signal,
                item.candidate_type,
                -item.weight,
                item.summary,
            ),
        )
    )


def recompute_asset_fingerprint(
    conn: sqlite3.Connection,
    asset_id: int,
    *,
    computed_at: str | None = None,
    oui_path: str | Path = DEFAULT_OUI_PATH,
):
    """Recompute and upsert one derived fingerprint without committing its caller."""
    from .engine import classify_evidence

    fingerprint = classify_evidence(
        collect_asset_evidence(conn, asset_id, oui_path=oui_path)
    )
    conn.execute(
        """INSERT INTO asset_fingerprint_current
           (asset_id, device_type, confidence, evidence_json, alternatives_json,
            fingerprint_version, computed_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(asset_id) DO UPDATE SET
               device_type = excluded.device_type,
               confidence = excluded.confidence,
               evidence_json = excluded.evidence_json,
               alternatives_json = excluded.alternatives_json,
               fingerprint_version = excluded.fingerprint_version,
               computed_at = excluded.computed_at""",
        (
            asset_id,
            fingerprint.device_type,
            fingerprint.confidence,
            json.dumps(
                [asdict(item) for item in fingerprint.evidence],
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
            json.dumps(
                list(fingerprint.alternatives),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
            fingerprint.version,
            computed_at or utc_now(),
        ),
    )
    return fingerprint


def recompute_all_asset_fingerprints(
    conn: sqlite3.Connection,
    *,
    computed_at: str | None = None,
    oui_path: str | Path = DEFAULT_OUI_PATH,
) -> int:
    asset_ids = [
        int(row["id"])
        for row in conn.execute("SELECT id FROM assets ORDER BY id")
    ]
    for asset_id in asset_ids:
        recompute_asset_fingerprint(
            conn,
            asset_id,
            computed_at=computed_at,
            oui_path=oui_path,
        )
    return len(asset_ids)


def current_asset_fingerprint(
    conn: sqlite3.Connection, asset_id: int
) -> dict[str, object] | None:
    row = conn.execute(
        "SELECT * FROM asset_fingerprint_current WHERE asset_id = ?", (asset_id,)
    ).fetchone()
    if row is None:
        return None
    evidence = []
    for item in _dictionary_list(row["evidence_json"], limit=64):
        candidate = item.get("candidate_type")
        weight = item.get("weight")
        if (
            isinstance(item.get("provider"), str)
            and isinstance(item.get("signal"), str)
            and isinstance(candidate, str)
            and candidate in SUPPORTED_DEVICE_TYPES - {"unknown"}
            and type(weight) is int
            and 1 <= weight <= 100
            and isinstance(item.get("summary"), str)
        ):
            evidence.append(
                {
                    key: item[key]
                    for key in (
                        "provider",
                        "signal",
                        "candidate_type",
                        "weight",
                        "summary",
                    )
                }
            )
    alternatives = []
    for item in _dictionary_list(row["alternatives_json"], limit=8):
        candidate = item.get("device_type")
        score = item.get("score")
        if (
            isinstance(candidate, str)
            and candidate in SUPPORTED_DEVICE_TYPES - {"unknown"}
            and type(score) is int
            and 0 <= score <= 100
        ):
            alternatives.append({"device_type": candidate, "score": score})
    return {
        "device_type": str(row["device_type"]),
        "confidence": int(row["confidence"]),
        "evidence": evidence,
        "alternatives": alternatives,
        "fingerprint_version": str(row["fingerprint_version"]),
        "computed_at": str(row["computed_at"]),
    }
