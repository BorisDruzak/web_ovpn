from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

from .collect_lock import CollectLock
from .config import DEFAULT_CONFIG, DEFAULT_DB_URL, load_secrets, normalize_source, validate_source_yaml_scalars, write_source_yaml
from .context import context_summary, load_context_bytes, load_schema, normalise_import_entities, validate_context, validate_import_semantics
from .context_diff import diff_snapshots
from .context_import import import_context, load_active_snapshot, record_context_import_validation_error
from .db import context_revision_public, connect, connect_read_only, get_context_head, get_source, latest_context_revision, list_sources, record_context_revision, source_public, sync_config_sources, upsert_source
from .drivers import driver_for, legacy_driver_for, snmp_driver_for
from .runtime_assets import (
    inspect_runtime_asset,
    list_runtime_identity_findings,
    runtime_identity_status,
)
from .store import add_device_tag, dashboard_summary, inspect_host, list_device_tags, query_hosts, related_for_host, remove_device_tag, save_collection, set_device_tags
from .switch_queries import (
    DEFAULT_PAGE_SIZE,
    OPTIONAL_STATE_DEFAULT_PAGE_SIZE,
    OPTIONAL_STATE_MAX_PAGE_SIZE,
    query_switch_capabilities,
    query_switch_events,
    query_switch_fdb,
    query_switch_lldp_neighbors,
    query_switch_ports,
    query_switch_status,
    query_switch_stp,
    query_switch_vlans,
    validate_pagination,
)
from .switch_store import collect_and_save_switch
from .switch_discovery_store import (
    UnknownSwitchFingerprint,
    list_unknown_fingerprints,
    record_unknown_fingerprint,
)
from .snmp.models import SwitchDiscoveryCapability
from .snmp.profiles import detect_profile
from .util import utc_now, validate_source_name


def emit(data: dict[str, Any]) -> None:
    print(json.dumps(data, ensure_ascii=False, default=str))


def ok(**data: Any) -> dict[str, Any]:
    return {"status": "ok", **data}


def err(message: str, **data: Any) -> dict[str, Any]:
    return {"status": "error", "message": message, **data}


def source_from_args(args: argparse.Namespace) -> dict[str, Any]:
    source = normalize_source(
        {
            "name": args.source,
            "driver": "mikrotik_api",
            "host": args.host,
            "port": args.port,
            "username": args.username,
            "secret_ref": args.secret_ref,
            "tls": args.tls,
            "verify_tls": args.verify_tls,
            "site": args.site,
            "role": args.role,
            "enabled": True,
        }
    )
    validate_source_yaml_scalars(source)
    return source


def snmp_source_from_args(args: argparse.Namespace) -> dict[str, Any]:
    host = str(args.host)
    if not host or any(character.isspace() for character in host):
        raise ValueError("SNMP host is invalid")
    if type(args.port) is not int or not 1 <= args.port <= 65535:
        raise ValueError("SNMP port must be between 1 and 65535")
    source = normalize_source(
        {
            "name": args.source,
            "driver": "snmp_switch",
            "host": args.host,
            "port": args.port,
            "secret_ref": args.secret_ref,
            "tls": False,
            "verify_tls": False,
            "site": args.site,
            "role": args.role,
            "enabled": False,
            "snmp_version": args.snmp_version,
            "snmp_timeout_seconds": args.timeout_seconds,
            "snmp_retries": args.retries,
            "snmp_max_repetitions": args.max_repetitions,
            "snmp_profile_hint": args.profile_hint,
            "snmp_capability_ttl_hours": args.capability_ttl_hours,
            "snmp_raw_retention_hours": args.raw_retention_hours,
            "snmp_counter_retention_days": args.counter_retention_days,
            "snmp_event_retention_days": args.event_retention_days,
            "snmp_access_port_mac_threshold": args.access_port_mac_threshold,
            "snmp_low_speed_threshold_bps": args.low_speed_threshold_bps,
            "runtime_asset_key": args.runtime_asset_key,
            "intent_context_id": args.intent_context_id,
            "intent_stable_id": args.intent_stable_id,
        }
    )
    validate_source_yaml_scalars(source)
    return source


def _sanitize_snmp_result(value: Any) -> dict[str, Any]:
    """Fail closed to the bounded ``sources test`` public contract."""
    if not isinstance(value, dict):
        return {"profile": {}, "system": {}, "capabilities": [], "counts": {}}
    profile = value.get("profile")
    system = value.get("system")
    counts = value.get("counts")
    capabilities = value.get("capabilities")
    return {
        "profile": {
            key: profile[key]
            for key in ("id", "fingerprint")
            if isinstance(profile, dict) and key in profile
        },
        "system": {
            key: system[key]
            for key in ("sys_descr", "sys_object_id", "sys_name")
            if isinstance(system, dict) and key in system
        },
        "capabilities": [
            {
                key: row[key]
                for key in ("capability", "outcome")
                if key in row
            }
            for row in (capabilities[:32] if isinstance(capabilities, list) else [])
            if isinstance(row, dict)
        ],
        "counts": {
            key: counts[key]
            for key in ("ports", "fdb")
            if isinstance(counts, dict) and key in counts
        },
    }


def _discovery_capabilities(value: object) -> list[dict[str, str]]:
    if not isinstance(value, tuple):
        return []
    result: list[dict[str, str]] = []
    for row in value:
        if not isinstance(row, SwitchDiscoveryCapability):
            continue
        if not row.capability.startswith("sys_"):
            continue
        result.append({"capability": row.capability, "outcome": row.outcome.value})
    return result


def _discovery_public_result(
    *, source: str, status: str, profile: object | None = None
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "source": source,
        "status": status,
    }
    if profile is not None:
        result["profile"] = {
            "id": profile.profile_id,
            "fingerprint": profile.profile_fingerprint,
        }
    return result


def _discovery_profile(source: dict[str, Any], system: object):
    options = source.get("driver_options")
    hint = options.get("profile_hint") if isinstance(options, dict) else None
    try:
        profile = detect_profile(system, profile_hint=hint)
    except ValueError:
        return None
    return None if profile.profile_id == "generic" else profile


def prepare_conn(args: argparse.Namespace):
    conn = connect(args.db)
    sync_config_sources(conn, args.config)
    return conn


def cmd_sources(args: argparse.Namespace) -> tuple[int, dict[str, Any]]:
    conn = prepare_conn(args)
    try:
        if args.sources_command == "list":
            return 0, ok(sources=[source_public(source) for source in list_sources(conn)])
        if args.sources_command == "inspect":
            validate_source_name(args.source)
            source = get_source(conn, args.source)
            if not source:
                return 1, err("source not found", source=args.source)
            return 0, ok(source=source_public(source))
        if args.sources_command == "add-mikrotik":
            try:
                source = source_from_args(args)
            except ValueError as exc:
                return 2, err(str(exc))
            upsert_source(conn, source)
            write_source_yaml(args.config, source)
            return 0, ok(source=source_public(source))
        if args.sources_command == "add-snmp-switch":
            try:
                source = snmp_source_from_args(args)
            except ValueError as exc:
                return 2, err(str(exc))
            upsert_source(conn, source)
            write_source_yaml(args.config, source)
            return 0, ok(source=source_public(source))
        if args.sources_command == "disable":
            validate_source_name(args.source)
            conn.execute("UPDATE network_sources SET enabled = 0, updated_at = ? WHERE name = ?", (utc_now(), args.source))
            conn.commit()
            return 0, ok(source=args.source, enabled=False)
        if args.sources_command == "test":
            validate_source_name(args.source)
            source = get_source(conn, args.source)
            if not source:
                return 1, err("source not found", source=args.source)
            try:
                result = driver_for(source, load_secrets()).test()
            except Exception as exc:
                message = (
                    "SNMP source test failed"
                    if source.get("driver") == "snmp_switch"
                    else str(exc)
                )
                conn.execute(
                    "UPDATE network_sources SET last_status = ?, last_error = ? WHERE id = ?",
                    ("error", message, source["id"]),
                )
                conn.commit()
                return 1, err(message, source=args.source)
            conn.execute("UPDATE network_sources SET last_status = ?, last_error = ? WHERE id = ?", ("ok", "", source["id"]))
            conn.commit()
            if source.get("driver") == "snmp_switch":
                result = _sanitize_snmp_result(result)
            return 0, ok(source=args.source, result=result)
        if args.sources_command == "discover":
            validate_source_name(args.source)
            source = get_source(conn, args.source)
            if not source:
                return 1, err("source not found", source=args.source)
            if source.get("driver") != "snmp_switch":
                return 2, err("source is not an SNMP switch", source=args.source)
            try:
                discovery = driver_for(source, load_secrets()).discover()
            except Exception:
                return 1, err("SNMP switch discovery failed", source=args.source)
            profile = _discovery_profile(source, discovery.system)
            if profile is not None:
                return 0, _discovery_public_result(
                    source=args.source,
                    status="known",
                    profile=profile,
                )
            digest = hashlib.sha256(
                f"{discovery.system.sys_object_id}\n{discovery.system.sys_descr}".encode(
                    "utf-8"
                )
            ).hexdigest()
            try:
                record_unknown_fingerprint(
                    conn,
                    UnknownSwitchFingerprint(
                        source_id=source["id"],
                        sys_object_id=discovery.system.sys_object_id,
                        sys_descr=discovery.system.sys_descr,
                        fingerprint_sha256=digest,
                        capabilities_json=json.dumps(
                            _discovery_capabilities(discovery.capabilities),
                            ensure_ascii=True,
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                        status="requires_profile",
                        observed_at=utc_now(),
                    ),
                )
            except ValueError:
                return 1, err("SNMP switch discovery failed", source=args.source)
            return 0, _discovery_public_result(
                source=args.source,
                status="requires_profile",
            )
    finally:
        conn.close()
    return 2, err("unsupported sources command")


def collect_one(conn, args: argparse.Namespace, source_name: str) -> tuple[int, dict[str, Any]]:
    source = get_source(conn, source_name)
    if not source:
        return 1, err("source not found", source=source_name)
    if not source.get("enabled"):
        return 1, err("source disabled", source=source_name)
    started = utc_now()
    try:
        if source.get("driver") == "snmp_switch":
            driver = snmp_driver_for(source, load_secrets())
            result = collect_and_save_switch(conn, source, driver, started)
            completed = result["status"] in {"success", "partial"}
            conn.execute(
                """
                UPDATE network_sources
                SET last_collect_at = ?, last_status = ?, last_error = ?
                WHERE id = ?
                """,
                (
                    started if completed else source.get("last_collect_at"),
                    result["status"],
                    result["error_message"],
                    source["id"],
                ),
            )
            conn.commit()
            if not completed:
                return 1, err(
                    result["error_message"],
                    source=source_name,
                    error_class=result["error_class"],
                    summary=result["counts"],
                    run_id=result["run_id"],
                )
            return 0, ok(
                source=source_name,
                collected_at=started,
                summary=result["counts"],
                run_id=result["run_id"],
                fdb_outcome=result["fdb_outcome"],
                collection_status=result["status"],
            )
        driver = legacy_driver_for(source, load_secrets())
        snapshot = driver.collect(
            include_connections=bool(getattr(args, "include_connections", False))
        )
        counts = save_collection(conn, source, snapshot, started)
    except Exception as exc:
        message = (
            "SNMP collection failed"
            if source.get("driver") == "snmp_switch"
            else str(exc)
        )
        conn.execute(
            "UPDATE network_sources SET last_status = ?, last_error = ? WHERE id = ?",
            ("error", message, source["id"]),
        )
        conn.commit()
        return 1, err(message, source=source_name)
    return 0, ok(source=source_name, collected_at=utc_now(), summary=counts)


def cmd_collect(args: argparse.Namespace) -> tuple[int, dict[str, Any]]:
    conn = prepare_conn(args)
    try:
        with CollectLock(args.db):
            if args.source == "all":
                results = []
                rc = 0
                for source in list_sources(conn):
                    if not source.get("enabled"):
                        continue
                    item_rc, data = collect_one(conn, args, source["name"])
                    rc = max(rc, item_rc)
                    results.append(data)
                return rc, ok(results=results)
            validate_source_name(args.source)
            return collect_one(conn, args, args.source)
    except RuntimeError as exc:
        return 1, err(str(exc))
    finally:
        conn.close()


def cmd_hosts(args: argparse.Namespace) -> tuple[int, dict[str, Any]]:
    conn = prepare_conn(args)
    try:
        if args.hosts_command == "list":
            return 0, ok(hosts=query_hosts(conn, q=args.q or "", category=args.category or "", status=args.status or ""))
        if args.hosts_command == "inspect":
            host = inspect_host(conn, args.host)
            if not host:
                return 1, err("host not found", host=args.host)
            return 0, ok(host=host, **related_for_host(conn, host))
    finally:
        conn.close()
    return 2, err("unsupported hosts command")


def cmd_tags(args: argparse.Namespace) -> tuple[int, dict[str, Any]]:
    conn = prepare_conn(args)
    try:
        try:
            if args.tags_command == "list":
                return 0, ok(tags=list_device_tags(conn))
            if args.tags_command == "add":
                return 0, ok(**add_device_tag(conn, args.target, args.tag))
            if args.tags_command == "remove":
                return 0, ok(**remove_device_tag(conn, args.target, args.tag))
            if args.tags_command == "set":
                tags = [item for item in args.tags.split(",") if item.strip()]
                return 0, ok(**set_device_tags(conn, args.target, tags))
        except ValueError as exc:
            return 2, err(str(exc))
    finally:
        conn.close()
    return 2, err("unsupported tags command")


def _rows(conn, table: str, source_name: str = "") -> list[dict[str, Any]]:
    params: list[Any] = []
    where = ""
    if source_name:
        where = " WHERE t.source_id = (SELECT id FROM network_sources WHERE name = ?)"
        params.append(source_name)
    return [
        dict(row)
        for row in conn.execute(
            f"SELECT t.*, s.name AS source FROM {table} t LEFT JOIN network_sources s ON s.id = t.source_id{where} ORDER BY t.id DESC LIMIT 1000",
            params,
        ).fetchall()
    ]


def cmd_table(args: argparse.Namespace, table: str, key: str) -> tuple[int, dict[str, Any]]:
    conn = prepare_conn(args)
    try:
        return 0, ok(**{key: _rows(conn, table, getattr(args, "source", "") or "")})
    finally:
        conn.close()


def cmd_switches(args: argparse.Namespace) -> tuple[int, dict[str, Any]]:
    source = getattr(args, "source", "") or ""
    if source:
        try:
            validate_source_name(source)
        except ValueError as exc:
            return 2, err(str(exc))
    if args.switches_command not in {"status", "unknown-fingerprints"}:
        try:
            maximum = (
                OPTIONAL_STATE_MAX_PAGE_SIZE
                if args.switches_command in {"vlans", "lldp", "stp"}
                else None
            )
            if maximum is None:
                validate_pagination(args.limit, args.offset)
            else:
                validate_pagination(args.limit, args.offset, maximum=maximum)
        except ValueError as exc:
            return 2, err(str(exc))
    if args.switches_command == "fdb" and args.vlan is not None:
        if not 1 <= args.vlan <= 4094:
            return 2, err("vlan must be between 1 and 4094")

    conn = connect_read_only(args.db)
    try:
        if args.switches_command == "status":
            return 0, ok(switches=query_switch_status(conn))
        if args.switches_command == "unknown-fingerprints":
            fingerprints = []
            for row in list_unknown_fingerprints(conn):
                try:
                    capabilities = json.loads(str(row["capabilities_json"]))
                except (KeyError, TypeError, ValueError):
                    continue
                if not isinstance(capabilities, list):
                    continue
                fingerprints.append(
                    {
                        "source": row["source"],
                        "sys_object_id": row["sys_object_id"],
                        "sys_descr": row["sys_descr"],
                        "fingerprint_sha256": row["fingerprint_sha256"],
                        "capabilities": capabilities,
                        "status": row["status"],
                        "observed_at": row["observed_at"],
                    }
                )
            return 0, ok(fingerprints=fingerprints)
        common = {
            "source": source,
            "limit": args.limit,
            "offset": args.offset,
        }
        if args.switches_command == "ports":
            page = query_switch_ports(conn, **common)
            return 0, ok(ports=page["items"], pagination=page["pagination"])
        if args.switches_command == "fdb":
            page = query_switch_fdb(conn, vlan=args.vlan, **common)
            return 0, ok(fdb=page["items"], pagination=page["pagination"])
        if args.switches_command == "events":
            page = query_switch_events(
                conn, event_type=args.event_type, **common
            )
            return 0, ok(events=page["items"], pagination=page["pagination"])
        if args.switches_command == "capabilities":
            page = query_switch_capabilities(conn, **common)
            return 0, ok(
                capabilities=page["items"], pagination=page["pagination"]
            )
        if args.switches_command == "vlans":
            page = query_switch_vlans(conn, **common)
            return 0, ok(vlans=page["items"], pagination=page["pagination"])
        if args.switches_command == "lldp":
            page = query_switch_lldp_neighbors(conn, **common)
            return 0, ok(
                lldp_neighbors=page["items"], pagination=page["pagination"]
            )
        if args.switches_command == "stp":
            page = query_switch_stp(conn, **common)
            return 0, ok(stp=page["items"], pagination=page["pagination"])
        return 2, err("unsupported switches command")
    finally:
        conn.close()


def _ipsec_source_status(source: dict[str, Any]) -> dict[str, Any]:
    snapshot = legacy_driver_for(source, load_secrets()).ipsec_status()
    policies = list(snapshot.get("policies", []))
    active_peers = list(snapshot.get("active_peers", []))
    installed_sas = list(snapshot.get("installed_sas", []))
    errors = list(snapshot.get("errors", []))
    established = sum(1 for policy in policies if policy.get("established"))
    if errors and not (policies or active_peers or installed_sas):
        status = "error"
    elif active_peers and established:
        status = "ok"
    elif policies or active_peers or installed_sas:
        status = "warn"
    else:
        status = "warn"
    return {
        "source": source["name"],
        "host": source.get("host") or "",
        "site": source.get("site") or "",
        "role": source.get("role") or "",
        "status": status,
        "summary": {
            "active_peers": len(active_peers),
            "installed_sas": len(installed_sas),
            "policies_total": len(policies),
            "policies_established": established,
        },
        "active_peers": active_peers,
        "policies": policies,
        "installed_sas": installed_sas,
        "errors": errors,
    }


def _ipsec_site_checks(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_pair: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for item in results:
        if item.get("status") == "error":
            continue
        source_name = str(item.get("source") or "")
        for policy in item.get("policies", []):
            if not policy.get("established"):
                continue
            src = str(policy.get("src_address") or "")
            dst = str(policy.get("dst_address") or "")
            if not src or not dst or src == "::/0" or dst == "::/0":
                continue
            network_a, network_b = sorted([src, dst])
            by_pair.setdefault((network_a, network_b), []).append(
                {
                    "source": source_name,
                    "src_address": src,
                    "dst_address": dst,
                    "ph2_count": int(policy.get("ph2_count") or 0),
                }
            )
    checks: list[dict[str, Any]] = []
    for (network_a, network_b), directions in sorted(by_pair.items()):
        has_a_to_b = any(item["src_address"] == network_a and item["dst_address"] == network_b for item in directions)
        has_b_to_a = any(item["src_address"] == network_b and item["dst_address"] == network_a for item in directions)
        ordered = sorted(directions, key=lambda item: (item["src_address"], item["dst_address"], item["source"]))
        checks.append(
            {
                "status": "ok" if has_a_to_b and has_b_to_a else "warn",
                "network_a": network_a,
                "network_b": network_b,
                "directions": ordered,
            }
        )
    return checks


def cmd_ipsec(args: argparse.Namespace) -> tuple[int, dict[str, Any]]:
    conn = prepare_conn(args)
    try:
        if args.ipsec_command != "status":
            return 2, err("unsupported ipsec command")
        sources = list_sources(conn)
        if args.source:
            validate_source_name(args.source)
            sources = [source for source in sources if source["name"] == args.source]
            if not sources:
                return 1, err("source not found", source=args.source)
        sources = [source for source in sources if source.get("enabled")]
        results = []
        for source in sources:
            try:
                results.append(_ipsec_source_status(source))
            except Exception as exc:
                results.append(
                    {
                        "source": source["name"],
                        "host": source.get("host") or "",
                        "site": source.get("site") or "",
                        "role": source.get("role") or "",
                        "status": "error",
                        "summary": {"active_peers": 0, "installed_sas": 0, "policies_total": 0, "policies_established": 0},
                        "active_peers": [],
                        "policies": [],
                        "installed_sas": [],
                        "errors": [{"section": "source", "message": str(exc)}],
                    }
                )
        summary = {
            "sources": len(results),
            "ok": sum(1 for item in results if item.get("status") == "ok"),
            "warn": sum(1 for item in results if item.get("status") == "warn"),
            "error": sum(1 for item in results if item.get("status") == "error"),
        }
        site_checks = _ipsec_site_checks(results)
        summary["site_checks_ok"] = sum(1 for item in site_checks if item.get("status") == "ok")
        summary["site_checks_warn"] = sum(1 for item in site_checks if item.get("status") == "warn")
        return (1 if results and summary["ok"] == 0 and summary["error"] else 0), ok(summary=summary, sources=results, site_checks=site_checks)
    finally:
        conn.close()


def cmd_dashboard(args: argparse.Namespace) -> tuple[int, dict[str, Any]]:
    conn = prepare_conn(args)
    try:
        return 0, ok(**dashboard_summary(conn))
    finally:
        conn.close()


def cmd_validate(args: argparse.Namespace) -> tuple[int, dict[str, Any]]:
    conn = prepare_conn(args)
    errors = []
    try:
        for source in list_sources(conn):
            try:
                validate_source_name(source["name"])
            except ValueError as exc:
                errors.append(f"{source['name']}: {exc}")
        return (1 if errors else 0), {"status": "error" if errors else "ok", "errors": errors}
    finally:
        conn.close()


def cmd_logs(args: argparse.Namespace) -> tuple[int, dict[str, Any]]:
    conn = prepare_conn(args)
    try:
        rows = [dict(row) for row in conn.execute("SELECT * FROM network_events ORDER BY id DESC LIMIT ?", (args.n,)).fetchall()]
        return 0, ok(events=rows)
    finally:
        conn.close()


def cmd_runtime_assets(args: argparse.Namespace) -> tuple[int, dict[str, Any]]:
    if (
        args.runtime_assets_command == "findings"
        and args.finding_status not in {"open", "acknowledged", "resolved"}
    ):
        return 2, err(
            "invalid finding status",
            finding_status=args.finding_status,
        )

    conn = connect_read_only(args.db)
    try:
        if args.runtime_assets_command == "status":
            return 0, ok(runtime_identity=runtime_identity_status(conn))
        if args.runtime_assets_command == "inspect":
            asset = inspect_runtime_asset(conn, args.asset_key)
            if asset is None:
                return 1, err("runtime asset not found", asset_key=args.asset_key)
            return 0, ok(runtime_asset=asset)
        if args.runtime_assets_command == "findings":
            return 0, ok(
                findings=list_runtime_identity_findings(conn, args.finding_status)
            )
        return 2, err("unsupported runtime-assets command")
    finally:
        conn.close()


def resolve_context_schema(path: Path, explicit_schema: str) -> Path:
    candidates = [Path(explicit_schema)] if explicit_schema else []
    candidates.append(path.parent.parent / "schemas" / "network-context.schema.json")
    if os.environ.get("NETCTL_CONTEXT_SCHEMA"):
        candidates.append(Path(os.environ["NETCTL_CONTEXT_SCHEMA"]))
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise FileNotFoundError("network context schema not found; use --schema or NETCTL_CONTEXT_SCHEMA")


def cmd_context(args: argparse.Namespace) -> tuple[int, dict[str, Any]]:
    if args.context_command in {"validate", "import", "diff"} and not args.path:
        return 1, err("context path is required", errors=[])
    if args.context_command == "import" and not args.git_sha.strip():
        return 1, err("context git SHA is required", errors=[])

    conn = connect(args.db)
    try:
        if args.context_command == "status":
            revision = latest_context_revision(conn)
            if revision is None:
                return 1, err("no successful context validation found", errors=[])
            head = get_context_head(conn, revision["context_id"])
            return 0, ok(
                context=revision,
                latest_validated_revision=revision,
                active_head=_context_head_public(conn, head),
                errors=[],
            )

        path = Path(args.path)
        try:
            raw_bytes = path.read_bytes()
        except Exception as exc:
            return 1, err(str(exc), errors=[])

        try:
            document = load_context_bytes(raw_bytes)
        except Exception as exc:
            errors = [{"path": "document", "message": str(exc)}]
            if args.context_command == "import":
                result = record_context_import_validation_error(
                    conn, None, raw_bytes, path, args.git_sha, errors
                )
                return 1, err("network context import failed", **result)
            return 1, err(str(exc), errors=[])

        try:
            schema = load_schema(resolve_context_schema(path, args.schema))
            errors = validate_context(document, schema)
        except Exception as exc:
            errors = [{"path": "schema", "message": str(exc)}]
            if args.context_command == "import":
                result = record_context_import_validation_error(
                    conn, document, raw_bytes, path, args.git_sha, errors
                )
                return 1, err("network context import failed", **result)
            return 1, err(str(exc), errors=[])

        if errors:
            if args.context_command == "import":
                result = record_context_import_validation_error(conn, document, raw_bytes, path, args.git_sha, errors)
                return 1, err("network context import failed", **result)
            return 1, err("network context validation failed", errors=errors)

        if args.context_command == "diff":
            semantic_errors = validate_import_semantics(document)
            if semantic_errors:
                return 1, err("network context validation failed", errors=semantic_errors)
            context_id = context_summary(document, raw_bytes)["context_id"]
            head = get_context_head(conn, context_id)
            base_snapshot = load_active_snapshot(conn, context_id) or {}
            try:
                changes = diff_snapshots(base_snapshot, normalise_import_entities(document))
            except (TypeError, ValueError) as exc:
                errors = [{"path": "canonicalization", "message": str(exc)}]
                return 1, err(
                    "network context validation failed",
                    result="validation_error",
                    errors=errors,
                )
            return 0, ok(
                base_revision=_head_revision(conn, head),
                changes=changes,
                summary={name: sum(item["change"] == name for item in changes) for name in ("added", "changed", "removed", "unchanged")},
                errors=[],
            )

        if args.context_command == "import":
            result = import_context(conn, document, raw_bytes, path, args.git_sha)
            if result["result"] in {"success_imported", "success_noop_same_content", "success_activated_existing_content"}:
                return 0, ok(**result)
            return 1, err("network context import failed", **result)

        revision = record_context_revision(conn, context_summary(document, raw_bytes), path, args.git_sha)
        conn.commit()
        return 0, ok(context=revision, errors=[])
    finally:
        conn.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="netctl")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG))
    parser.add_argument("--db", default=DEFAULT_DB_URL)
    sub = parser.add_subparsers(dest="command", required=True)

    sources = sub.add_parser("sources")
    sources_sub = sources.add_subparsers(dest="sources_command", required=True)
    sources_sub.add_parser("list")
    inspect = sources_sub.add_parser("inspect")
    inspect.add_argument("source")
    test = sources_sub.add_parser("test")
    test.add_argument("source")
    discover = sources_sub.add_parser("discover")
    discover.add_argument("source")
    disable = sources_sub.add_parser("disable")
    disable.add_argument("source")
    add = sources_sub.add_parser("add-mikrotik")
    add.add_argument("source")
    add.add_argument("--host", required=True)
    add.add_argument("--port", type=int, default=8729)
    add.add_argument("--username", required=True)
    add.add_argument("--secret-ref", required=True)
    add.add_argument("--tls", action="store_true")
    add.add_argument("--verify-tls", action="store_true")
    add.add_argument("--site", default="main")
    add.add_argument("--role", default="core-router")
    add_snmp = sources_sub.add_parser("add-snmp-switch")
    add_snmp.add_argument("source")
    add_snmp.add_argument("--host", required=True)
    add_snmp.add_argument("--port", type=int, default=161)
    add_snmp.add_argument("--secret-ref", required=True)
    add_snmp.add_argument("--site", default="main")
    add_snmp.add_argument("--role", default="access-switch")
    add_snmp.add_argument("--snmp-version", default="2c")
    add_snmp.add_argument("--timeout-seconds", type=int, default=2)
    add_snmp.add_argument("--retries", type=int, default=1)
    add_snmp.add_argument("--max-repetitions", type=int, default=25)
    add_snmp.add_argument("--profile-hint")
    add_snmp.add_argument("--capability-ttl-hours", type=int, default=168)
    add_snmp.add_argument("--raw-retention-hours", type=int, default=24)
    add_snmp.add_argument("--counter-retention-days", type=int, default=14)
    add_snmp.add_argument("--event-retention-days", type=int, default=180)
    add_snmp.add_argument("--access-port-mac-threshold", type=int, default=10)
    add_snmp.add_argument(
        "--low-speed-threshold-bps", type=int, default=100_000_000
    )
    add_snmp.add_argument("--runtime-asset-key", default="")
    add_snmp.add_argument("--intent-context-id", default="")
    add_snmp.add_argument("--intent-stable-id", default="")

    collect = sub.add_parser("collect")
    collect.add_argument("source")
    collect.add_argument("--include-connections", action="store_true")

    hosts = sub.add_parser("hosts")
    hosts_sub = hosts.add_subparsers(dest="hosts_command", required=True)
    hosts_list = hosts_sub.add_parser("list")
    hosts_list.add_argument("--q", default="")
    hosts_list.add_argument("--category", default="")
    hosts_list.add_argument("--status", default="")
    hosts_inspect = hosts_sub.add_parser("inspect")
    hosts_inspect.add_argument("host")

    tags = sub.add_parser("tags")
    tags_sub = tags.add_subparsers(dest="tags_command", required=True)
    tags_sub.add_parser("list")
    tags_add = tags_sub.add_parser("add")
    tags_add.add_argument("target")
    tags_add.add_argument("tag")
    tags_remove = tags_sub.add_parser("remove")
    tags_remove.add_argument("target")
    tags_remove.add_argument("tag")
    tags_set = tags_sub.add_parser("set")
    tags_set.add_argument("target")
    tags_set.add_argument("--tags", required=True)

    for command, table, key in [
        ("interfaces", "network_interfaces", "interfaces"),
        ("routes", "network_routes", "routes"),
        ("dhcp-leases", "dhcp_leases", "dhcp_leases"),
        ("arp", "arp_entries", "arp"),
        ("neighbors", "network_neighbors", "neighbors"),
        ("bridge-hosts", "bridge_hosts", "bridge_hosts"),
    ]:
        parent = sub.add_parser(command)
        parent_sub = parent.add_subparsers(dest=f"{command}_command", required=True)
        list_parser = parent_sub.add_parser("list")
        list_parser.add_argument("--source", default="")
        list_parser.set_defaults(table=table, table_key=key)

    observations = sub.add_parser("observations")
    observations_sub = observations.add_subparsers(dest="observations_command", required=True)
    observations_list = observations_sub.add_parser("list")
    observations_list.add_argument("--host", default="")

    switches = sub.add_parser("switches")
    switches_sub = switches.add_subparsers(
        dest="switches_command", required=True
    )
    switches_sub.add_parser("status")
    switches_sub.add_parser("unknown-fingerprints")
    for name in (
        "capabilities",
        "ports",
        "fdb",
        "events",
        "vlans",
        "lldp",
        "stp",
    ):
        switch_query = switches_sub.add_parser(name)
        switch_query.add_argument("--source", default="")
        switch_query.add_argument(
            "--limit",
            type=int,
            default=(
                OPTIONAL_STATE_DEFAULT_PAGE_SIZE
                if name in {"vlans", "lldp", "stp"}
                else DEFAULT_PAGE_SIZE
            ),
        )
        switch_query.add_argument("--offset", type=int, default=0)
        if name == "fdb":
            switch_query.add_argument("--vlan", type=int)
        if name == "events":
            switch_query.add_argument(
                "--event-type",
                choices=("appeared", "moved", "disappeared"),
                default="",
            )

    ipsec = sub.add_parser("ipsec")
    ipsec_sub = ipsec.add_subparsers(dest="ipsec_command", required=True)
    ipsec_status = ipsec_sub.add_parser("status")
    ipsec_status.add_argument("--source", default="")

    sub.add_parser("dashboard")
    sub.add_parser("validate")
    logs = sub.add_parser("logs")
    logs.add_argument("-n", type=int, default=100)

    runtime_assets = sub.add_parser("runtime-assets")
    runtime_assets_sub = runtime_assets.add_subparsers(
        dest="runtime_assets_command", required=True
    )
    runtime_assets_sub.add_parser("status")
    runtime_assets_inspect = runtime_assets_sub.add_parser("inspect")
    runtime_assets_inspect.add_argument("--asset-key", required=True)
    runtime_assets_findings = runtime_assets_sub.add_parser("findings")
    runtime_assets_findings.add_argument("--status", dest="finding_status", default="open")

    context = sub.add_parser("context")
    context_sub = context.add_subparsers(dest="context_command", required=True)
    for name in ("validate", "status", "import", "diff"):
        context_command = context_sub.add_parser(name)
        context_command.add_argument("--path", required=name in {"import", "diff"}, default="")
        context_command.add_argument("--schema", default="")
        context_command.add_argument("--git-sha", default="")
    return parser


def _head_revision(conn, head: dict[str, Any] | None) -> dict[str, Any] | None:
    if head is None:
        return None
    row = conn.execute("SELECT * FROM context_revisions WHERE id = ?", (head["context_revision_id"],)).fetchone()
    return context_revision_public(row)


def _context_head_public(conn, head: dict[str, Any] | None) -> dict[str, Any] | None:
    if head is None:
        return None
    public = dict(head)
    row = conn.execute(
        "SELECT git_sha FROM context_import_runs WHERE id = ?",
        (head["activated_by_import_run_id"],),
    ).fetchone()
    public["git_sha"] = str(row["git_sha"]) if row else ""
    return public


def dispatch(args: argparse.Namespace) -> tuple[int, dict[str, Any]]:
    if args.command == "sources":
        return cmd_sources(args)
    if args.command == "collect":
        return cmd_collect(args)
    if args.command == "hosts":
        return cmd_hosts(args)
    if args.command == "tags":
        return cmd_tags(args)
    if hasattr(args, "table"):
        return cmd_table(args, args.table, args.table_key)
    if args.command == "observations":
        return cmd_table(args, "host_observations", "observations")
    if args.command == "switches":
        return cmd_switches(args)
    if args.command == "ipsec":
        return cmd_ipsec(args)
    if args.command == "dashboard":
        return cmd_dashboard(args)
    if args.command == "validate":
        return cmd_validate(args)
    if args.command == "logs":
        return cmd_logs(args)
    if args.command == "runtime-assets":
        return cmd_runtime_assets(args)
    if args.command == "context":
        return cmd_context(args)
    return 2, err("unsupported command")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    rc, data = dispatch(args)
    emit(data)
    return rc


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
