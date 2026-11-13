"""Publish Windows route probe observations on the infrastructure map."""

from datetime import datetime, timedelta

from .infrastructure_map import ENDPOINT_PAIR_SOURCE, NETWORK_KINDS, WINDOWS_DNS_SOURCE, observation_is_fresh, port_label_key
from .network_probe_profiles import load_probe_profiles
from .network_route_receipt_timing import MAX_AGE as RECEIPT_MAX_AGE
from .network_route_spool import read_adapter_observation, read_measurements


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
            route = result.get("kernel_route", {})
            fields = route.get("result", {})
            verified = (observation_is_fresh(stamp, now, max_age=RECEIPT_MAX_AGE)
                        and route.get("status") == "route_found" and fields.get("dst") == probe.target
                        and fields.get("from", fields.get("prefsrc")) == probe.source_address
                        and fields.get("dev") == probe.expected_kernel_interface
                        and (not probe.expected_kernel_gateway or fields.get("gateway") == probe.expected_kernel_gateway))
            status = result.get("status") if verified else None
            dns = {"name": probe.dns_name.rstrip(".") + ".", "record": probe.dns_type or "A",
                   "transport": probe.dns_transport.upper()}
            if verified and evidence.get("dns_transport") == dns["transport"]:
                dns.update(rcode=evidence.get("dns_rcode"), answersMatch=evidence.get("dns_answers_match"))
            reason = {"dns_answer_mismatch": "dns_address_mismatch", "dns_no_answer": "dns_no_answer",
                      "dns_rcode": "dns_rcode", "timeout": "timeout"}.get(evidence.get("reason")) if verified else None
            state = "reachable" if status == "reachable" else "unreachable" if status == "unreachable" else "unknown"
            checks.append({"state": state, "source": WINDOWS_DNS_SOURCE, "method": "DNS", "required": True,
                           "target": probe.target, "port": probe.port or 53, "dns": dns,
                           "checkedAt": stamp if verified else now.isoformat(), **({"reason": reason} if reason else {})})
        service.setdefault("serviceChecks", []).extend(checks)
        service["reachability"] = {"state": "unknown", "source": "Проверка сервиса", "method": "DNS",
                                   "checkedAt": now.isoformat()}
        graph["links"].append({"a": station_id, "b": service_id, "kind": "Источник проверки", "source": "Настройки карты",
                               "confirmed": True})


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
