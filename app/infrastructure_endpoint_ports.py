"""Match a Windows route probe's physical adapter to a monitored access port."""

from datetime import datetime, timedelta

from .infrastructure_map import ENDPOINT_PAIR_SOURCE, NETWORK_KINDS, observation_is_fresh, port_label_key
from .network_probe_profiles import load_probe_profiles
from .network_route_spool import read_adapter_observation


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
