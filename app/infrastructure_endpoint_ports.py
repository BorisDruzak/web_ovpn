"""Publish Windows route probe observations on the infrastructure map."""

from datetime import datetime, timedelta

from .infrastructure_map import (
    ENDPOINT_PAIR_SOURCE, NETWORK_KINDS, WINDOWS_ADAPTER_SOURCE, WINDOWS_PROBE_SOURCE, observation_is_fresh, port_label_key,
)
from .network_probe_profiles import load_probe_profiles
from .network_route_receipt_timing import MAX_AGE as RECEIPT_MAX_AGE
from .network_route_spool import read_adapter_observation, read_measurements


def _verified_route(result, probe, now):
    route = result.get("kernel_route", {})
    fields = route.get("result", {})
    return (observation_is_fresh(result.get("measured_at"), now, max_age=RECEIPT_MAX_AGE)
            and route.get("status") == "route_found" and fields.get("dst") == probe.target
            and fields.get("from", fields.get("prefsrc")) == probe.source_address
            and fields.get("dev") == probe.expected_kernel_interface
            and (not probe.expected_kernel_gateway or fields.get("gateway") == probe.expected_kernel_gateway))


def _link_probe_source(graph, station_id, service_id):
    graph["links"].append({"a": station_id, "b": service_id, "kind": "Источник проверки", "source": "Настройки карты",
                           "confirmed": True})


def read_windows_dns_neighbors(bindings: dict, now: datetime) -> dict:
    configured = bindings.get("endpoint_dns", {})
    if not configured:
        return {}
    profiles = load_probe_profiles(routes_only=True).routes
    observations = {}
    for spec in configured.values():
        if not isinstance(spec, dict) or not isinstance(selected := spec.get("probes"), list):
            continue
        profile_id, origin, target = (spec.get(key) for key in ("profile", "origin", "neighbor_address"))
        if not all(isinstance(value, str) for value in (profile_id, origin, target)) or profile_id not in profiles:
            continue
        profile = profiles[profile_id]
        probes = [probe for probe in profile.probes if probe.id in selected and probe.push_origin == origin
                  and probe.target == target and probe.protocol == "dns" and not probe.expected_kernel_gateway]
        if not probes:
            continue
        adapter = read_adapter_observation(origin, profile_id, profile, now)
        if not (mac := adapter.get("neighbors", {}).get(target)):
            continue
        results = read_measurements(profile_id, profile)
        if any((result := results.get(probe.id, {})).get("status") == "reachable"
               and result.get("measured_at") == adapter["checkedAt"] and _verified_route(result, probe, now)
               and not result["kernel_route"]["result"].get("gateway") for probe in probes):
            observations.setdefault(target, {})[mac] = adapter["checkedAt"]
    return {address: next(iter(peers.items())) for address, peers in observations.items() if len(peers) == 1}


def collect_endpoint_http(graph: dict, bindings: dict, now: datetime) -> None:
    profiles = load_probe_profiles(routes_only=True).routes
    nodes = {node["id"]: node for node in graph["nodes"]}
    for service_id, spec in bindings.items():
        service = nodes.get(service_id, {})
        if service.get("kind") != "Сервис" or not isinstance(spec, dict):
            continue
        station, origin, profile_id, probe_id = (spec.get(key) for key in ("station", "origin", "profile", "probe"))
        if not all(isinstance(value, str) for value in (station, origin, profile_id, probe_id)):
            continue
        profile = profiles.get(profile_id)
        if profile is None or nodes.get(station, {}).get("kind") != "Рабочая станция":
            continue
        probe = next((probe for probe in profile.probes if probe.id == probe_id and probe.push_origin == origin), None)
        if not probe or probe.protocol != "http" or not (probe.source_address and probe.expected_kernel_interface):
            continue
        target, port, path = probe.target, probe.port or 80, probe.http_path or "/"
        checks = service.get("serviceChecks", [])
        if not any(c.get("required") and c.get("source") == "UI_VPN" and c.get("method") == "HTTP"
                   and (c.get("target"), c.get("port"), c.get("path"), c.get("httpHost"))
                   == (target, port, path, probe.server_name) for c in checks):
            continue
        result = read_measurements(profile_id, profile).get(probe_id, {})
        verified = _verified_route(result, probe, now)
        evidence = result.get("evidence", {}) if verified else {}
        status = {"reachable": "reachable", "unreachable": "unreachable"}.get(result.get("status"), "unknown") if verified else "unknown"
        reason = {"http_status_mismatch": "http_status", "timeout": "timeout"}.get(evidence.get("reason"))
        checks.append({"state": status, "source": WINDOWS_PROBE_SOURCE, "method": "HTTP", "supplemental": True,
                       "target": target, "port": port, "path": path, "httpHost": probe.server_name,
                       "via": probe.expected_kernel_gateway, "httpStatus": evidence.get("http_status"),
                       "checkedAt": result["measured_at"] if verified else now.isoformat(),
                       **({"reason": reason} if reason else {})})
        _link_probe_source(graph, station, service_id)


def collect_endpoint_dns(graph: dict, bindings: dict, now: datetime) -> None:
    profiles = load_probe_profiles(routes_only=True).routes
    nodes = {node["id"]: node for node in graph["nodes"]}
    for service_id, spec in bindings.items():
        service = nodes.get(service_id, {})
        if service.get("kind") != "Сервис" or not isinstance(spec, dict):
            continue
        origin, profile_id, station_id = (spec.get(key) for key in ("origin", "profile", "station"))
        if not all(isinstance(value, str) for value in (origin, profile_id, station_id)):
            continue
        station, profile = nodes.get(station_id, {}), profiles.get(profile_id)
        selected = spec.get("probes")
        if (station.get("kind") != "Рабочая станция" or profile is None or not isinstance(selected, list)
                or len(selected) != 2 or not all(isinstance(probe_id, str) for probe_id in selected)):
            continue
        probes = [probe for probe in profile.probes if probe.id in selected and probe.push_origin == origin
                  and probe.protocol == "dns" and probe.dns_type in (None, "A", "AAAA") and probe.expected_dns_answers
                  and probe.target == service.get("probeTargetIP") and probe.source_address and probe.expected_kernel_interface]
        if (len(probes) != 2 or {probe.dns_transport for probe in probes} != {"udp", "tcp"}
                or len({(probe.target, probe.port, probe.source_address, probe.expected_kernel_interface, probe.dns_name,
                         probe.dns_type, tuple(probe.expected_dns_answers)) for probe in probes}) != 1):
            continue
        results = read_measurements(profile_id, profile)
        checks = []
        for probe in probes:
            result = results.get(probe.id, {})
            stamp = result.get("measured_at")
            evidence = result.get("evidence", {})
            verified = _verified_route(result, probe, now)
            status = result.get("status") if verified else None
            dns = {"name": probe.dns_name.rstrip(".") + ".", "record": probe.dns_type or "A",
                   "transport": probe.dns_transport.upper()}
            if verified and evidence.get("dns_transport") == dns["transport"]:
                dns.update(rcode=evidence.get("dns_rcode"), answersMatch=evidence.get("dns_answers_match"))
            reason = {"dns_answer_mismatch": "dns_address_mismatch", "dns_no_answer": "dns_no_answer",
                      "dns_rcode": "dns_rcode", "timeout": "timeout"}.get(evidence.get("reason")) if verified else None
            state = "reachable" if status == "reachable" else "unreachable" if status == "unreachable" else "unknown"
            checks.append({"state": state, "source": WINDOWS_PROBE_SOURCE, "method": "DNS", "required": True,
                           "target": probe.target, "port": probe.port or 53, "dns": dns,
                           "checkedAt": stamp if verified else now.isoformat(), **({"reason": reason} if reason else {})})
        service.setdefault("serviceChecks", []).extend(checks)
        service["reachability"] = {"state": "unknown", "source": "Проверка сервиса", "method": "DNS",
                                   "checkedAt": now.isoformat()}
        _link_probe_source(graph, station_id, service_id)


def confirm_endpoint_ports(graph: dict, bindings: dict, now: datetime) -> None:
    profiles = load_probe_profiles(routes_only=True).routes
    nodes = {node["id"]: node for node in graph["nodes"]}
    for node_id, spec in bindings.items():
        node = nodes.get(node_id, {})
        if node.get("kind") != "Рабочая станция" or not isinstance(spec, dict):
            continue
        origin, profile_id = spec.get("origin"), spec.get("profile")
        if not isinstance(origin, str) or not isinstance(profile_id, str) or profile_id not in profiles:
            continue
        adapter = read_adapter_observation(origin, profile_id, profiles[profile_id], now)
        if not adapter or node.get("endpointKey", "").casefold() != "mac:" + adapter["mac"]:
            continue
        observed = datetime.fromisoformat(adapter["checkedAt"])
        matches = []
        for edge in graph["links"]:
            if not edge["confirmed"] or edge["kind"] != "Сетевое соединение" or node_id not in (edge["a"], edge["b"]):
                continue
            side, peer = ("b", "a") if edge["a"] == node_id else ("a", "b")
            switch = nodes[edge[side]]
            if switch["kind"] != NETWORK_KINDS[0]:
                continue
            for row in edge.get("portEvidence", []):
                if not row["confirmed"] or row["source"] != "GitHub" or row[peer] != adapter["name"]:
                    continue
                ports = [port for port in switch.get("ports", []) if port_label_key(row[side]) == port_label_key(port["name"])]
                if len(ports) != 1:
                    continue
                port, = ports
                sample = port.get("linkCheck", {})
                endpoint = sample.get("endpointMac", {})
                learned = port.get("fdbLearned", {})
                if (sample.get("state") == "up" and endpoint == {"deviceId": node_id, "mac": adapter["mac"]}
                        and observation_is_fresh(sample.get("checkedAt"), now, max_age=timedelta(minutes=3))
                        and learned.get("partial") is False and learned.get("learnedMacCount") == 1
                        and observation_is_fresh(learned.get("checkedAt"), now, max_age=timedelta(minutes=8))):
                    stamp = min(observed, datetime.fromisoformat(sample["checkedAt"]))
                    matches.append((edge, {"a": row["a"], "b": row["b"], "source": ENDPOINT_PAIR_SOURCE,
                                           "at": stamp.isoformat(), "confirmed": True, "windowsAdapter": {
                                               "ifIndex": adapter["index"], "checkedAt": adapter["checkedAt"],
                                               "switchCheckedAt": sample["checkedAt"],
                                           }}))
        if len(matches) == 1:
            (edge, reading), = matches
            edge["portEvidence"].append(reading)
            node.setdefault("ports", []).append({
                "name": adapter["name"], "state": "up", "source": WINDOWS_ADAPTER_SOURCE, "checkedAt": reading["at"],
            })
