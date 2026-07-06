from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .collect_lock import CollectLock
from .config import DEFAULT_CONFIG, DEFAULT_DB_URL, load_secrets, normalize_source, write_source_yaml
from .db import connect, get_source, list_sources, source_public, sync_config_sources, upsert_source
from .drivers import driver_for
from .store import add_device_tag, dashboard_summary, inspect_host, list_device_tags, query_hosts, related_for_host, remove_device_tag, save_collection, set_device_tags
from .util import utc_now, validate_source_name


def emit(data: dict[str, Any]) -> None:
    print(json.dumps(data, ensure_ascii=False, default=str))


def ok(**data: Any) -> dict[str, Any]:
    return {"status": "ok", **data}


def err(message: str, **data: Any) -> dict[str, Any]:
    return {"status": "error", "message": message, **data}


def source_from_args(args: argparse.Namespace) -> dict[str, Any]:
    return normalize_source(
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
                conn.execute(
                    "UPDATE network_sources SET last_status = ?, last_error = ? WHERE id = ?",
                    ("error", str(exc), source["id"]),
                )
                conn.commit()
                return 1, err(str(exc), source=args.source)
            conn.execute("UPDATE network_sources SET last_status = ?, last_error = ? WHERE id = ?", ("ok", "", source["id"]))
            conn.commit()
            return 0, ok(source=args.source, result=result)
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
        snapshot = driver_for(source, load_secrets()).collect(include_connections=bool(getattr(args, "include_connections", False)))
        counts = save_collection(conn, source, snapshot, started)
    except Exception as exc:
        conn.execute(
            "UPDATE network_sources SET last_status = ?, last_error = ? WHERE id = ?",
            ("error", str(exc), source["id"]),
        )
        conn.commit()
        return 1, err(str(exc), source=source_name)
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


def _ipsec_source_status(source: dict[str, Any]) -> dict[str, Any]:
    snapshot = driver_for(source, load_secrets()).ipsec_status()
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

    ipsec = sub.add_parser("ipsec")
    ipsec_sub = ipsec.add_subparsers(dest="ipsec_command", required=True)
    ipsec_status = ipsec_sub.add_parser("status")
    ipsec_status.add_argument("--source", default="")

    sub.add_parser("dashboard")
    sub.add_parser("validate")
    logs = sub.add_parser("logs")
    logs.add_argument("-n", type=int, default=100)
    return parser


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
    if args.command == "ipsec":
        return cmd_ipsec(args)
    if args.command == "dashboard":
        return cmd_dashboard(args)
    if args.command == "validate":
        return cmd_validate(args)
    if args.command == "logs":
        return cmd_logs(args)
    return 2, err("unsupported command")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    rc, data = dispatch(args)
    emit(data)
    return rc


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
