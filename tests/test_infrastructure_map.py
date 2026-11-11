import json
import re
from datetime import datetime, timedelta, timezone

from test_context_api import make_client


def test_map_colors_use_node_and_confirmed_service_availability(tmp_path):
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    stamp = now.isoformat()

    def node(key, state, kind="Сервер", **extra):
        return {"id": key, "name": key, "kind": kind,
                "reachability": {"state": state, "checkedAt": stamp}, **extra}

    directum = node("role:directum", "unreachable", "Сервис",
                    sources=[{"name": "Server Observer", "at": stamp}],
                    checks=[{"name": "directumrx_active", "status": "critical"}])
    graph = {
        "schema": 1, "snapshotAt": stamp,
        "nodes": [node("green", "reachable"), node("yellow", "reachable"),
                  node("red", "unreachable"), node("grey", "reachable"),
                  node("off", "stopped"), node("unknown-host", "unknown"),
                  node("http", "reachable", "Сервис"), node("dns", "unknown", "Сервис"), directum],
        "links": [
            {"a": host, "b": service, "kind": "Цель проверки", "confirmed": confirmed}
            for host, service, confirmed in [
                ("green", "http", True), ("green", "dns", False),
                ("yellow", "role:directum", True), ("yellow", "dns", True),
                ("red", "http", True), ("grey", "dns", True), ("unknown-host", "role:directum", True),
            ]
        ],
    }
    path = tmp_path / "infrastructure.json"
    path.write_text(json.dumps(graph), encoding="utf-8")

    states = {item["id"]: item for item in load_infrastructure_map(path, now)["nodes"]}
    assert [states[key]["mapStatus"] for key in ("green", "yellow", "red", "grey", "off", "unknown-host")] == [
        "ok", "warn", "critical", "unknown", "critical", "unknown",
    ]
    assert states["yellow"]["reachability"]["state"] == "reachable"
    assert states["yellow"]["serviceAvailability"] == {"unavailable": ["role:directum"], "unknown": ["dns"]}
    directum["reachability"]["state"] = "unknown"
    path.write_text(json.dumps(graph), encoding="utf-8")
    states = {item["id"]: item for item in load_infrastructure_map(path, now)["nodes"]}
    assert states["role:directum"]["reachability"]["state"] == "unknown"
    assert states["yellow"]["mapStatus"] == "unknown"


def test_service_requires_all_http_checks_and_rejects_unexpected_response():
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from threading import Thread
    from app.infrastructure_service_probes import apply_service_probes

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            code, payload = {
                "/client": (200, b"<script src='client.js'></script>"),
                "/healthy": (200, b"Healthy"),
                "/unexpected": (200, b"Sign in"),
                "/unavailable": (503, b"Unavailable"),
            }[self.path]
            self.send_response(code)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(payload)

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        worker = Thread(target=server.serve_forever)
        worker.start()
        try:
            base = {"ip": "127.0.0.1", "port": server.server_port, "type": "http"}
            client = {**base, "path": "/client", "body_contains": "client.js"}
            nodes = [{"id": path, "kind": "Сервис"} for path in ("/healthy", "/unexpected", "/unavailable")]
            apply_service_probes(nodes, {
                node["id"]: [client, {**base, "path": node["id"], "body": "Healthy"}] for node in nodes
            })
        finally:
            server.shutdown()
            worker.join()
    assert [node["reachability"]["state"] for node in nodes] == ["reachable", "unknown", "unreachable"]
    assert [[check["state"] for check in node["serviceChecks"]] for node in nodes] == [
        ["reachable", "reachable"], ["reachable", "unknown"], ["reachable", "unreachable"],
    ]
    assert nodes[1]["serviceChecks"][1]["path"] == "/unexpected"


def test_asset_https_probe_validates_certificate_before_sending_request(monkeypatch):
    from hashlib import sha256
    from types import SimpleNamespace
    from app.infrastructure_collect import build_graph
    from app import infrastructure_service_probes as probes

    now = datetime.now(timezone.utc)
    events = []
    cert = b"peer-certificate"

    class Connection:
        def __init__(self, ip, port, *, timeout, context):
            assert (ip, port) == ("192.0.2.14", 8007)
            assert context.verify_mode == probes.ssl.CERT_NONE
            self.sock = SimpleNamespace(getpeercert=lambda **_: cert)

        def connect(self):
            events.append("connect")

        def request(self, method, path, headers):
            events.append((method, path))

        def getresponse(self):
            return SimpleNamespace(status=200, getheader=lambda *_: "text/html",
                                   read=lambda _: b'<script src="/js/proxmox-backup-gui.js">')

        def close(self):
            events.append("close")

    monkeypatch.setattr(probes.http.client, "HTTPSConnection", Connection)
    context = {"devices": [{"id": "pbs", "name": "PBS", "kind": "backup_server",
                            "management_ip": "192.0.2.14"}]}
    bindings = {"asset_services": {"pbs-web": {"asset": "pbs", "label": "PBS Web"}}}
    graph = build_graph(context, {}, {}, {}, bindings, now)
    node = next(node for node in graph["nodes"] if node["id"] == "pbs-web")
    assert any(link["a"] == "pbs" and link["b"] == "pbs-web" and link["confirmed"] for link in graph["links"])
    spec = {"type": "https", "ip": "192.0.2.15", "port": 8007, "path": "/",
            "content_type": "text/html", "body_contains": "/js/proxmox-backup-gui.js",
            "tls_sha256": "0" * 64}
    configured = {"pbs-web": [spec]}
    probes.apply_service_probes(graph["nodes"], configured)
    assert not events
    spec["ip"] = "192.0.2.14"
    probes.apply_service_probes(graph["nodes"], configured)
    assert events == ["connect", "close"]
    assert node["reachability"]["state"] == "unknown"
    events.clear()
    spec["tls_sha256"] = sha256(cert).hexdigest()
    probes.apply_service_probes(graph["nodes"], configured)
    assert events == ["connect", ("GET", "/"), "close"]
    assert node["reachability"]["state"] == "reachable"


def test_zabbix_version_checks_matching_json_rpc_response():
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from threading import Thread
    from app.infrastructure_service_probes import apply_service_probes

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            assert request == {"jsonrpc": "2.0", "method": "apiinfo.version", "params": [], "id": 1}
            code = 503 if self.path == "/failed" else 200
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            response = {"jsonrpc": "2.0", "id": 2 if self.path == "/wrong-id" else 1, "result": "7.0.21"}
            self.wfile.write(json.dumps(response).encode())

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        worker = Thread(target=server.serve_forever)
        worker.start()
        try:
            paths = ("/zabbix/api_jsonrpc.php", "/wrong-id", "/failed")
            nodes = [{"id": path, "kind": "Сервис"} for path in paths]
            specs = {path: [{"type": "zabbix_api", "ip": "127.0.0.1", "port": server.server_port, "path": path}]
                     for path in paths}
            apply_service_probes(nodes, specs)
        finally:
            server.shutdown()
            worker.join()
    assert [n["reachability"]["state"] for n in nodes] == ["reachable", "unknown", "unreachable"]
    assert nodes[0]["serviceChecks"][0]["path"] == paths[0]


def test_guest_service_requires_matching_mac_and_arp_to_enable_probe(monkeypatch):
    from app.infrastructure_collect import build_graph
    from app import infrastructure_service_probes as probes

    now = datetime.now(timezone.utc)
    mac, address = "02:00:00:00:00:03", "192.0.2.21"
    pve = {
        "cluster": [], "nodes": [],
        "guests": [{"vmid": 108, "node": "pve1", "type": "qemu", "status": "running"}],
        "configs": {"108": {"net0": f"virtio={mac},bridge=vmbr0"}},
    }
    arp = {"ip": address, "mac": mac, "last_seen_at": now.isoformat()}
    network = {"arp": [arp]}
    binding = {"guest_probe_ips": {"108": address},
               "guest_services": {"zabbix-api": {"label": "Zabbix API", "vmid": 108, "mac": mac}}}
    configured = {"zabbix-api": [{"ip": address, "port": 80, "type": "zabbix_api"}]}
    monkeypatch.setattr(probes, "_probe", lambda spec: "reachable")

    def build():
        graph = build_graph({}, network, {}, pve, binding, now)
        probes.apply_service_probes(graph["nodes"], configured)
        return graph, next(n for n in graph["nodes"] if n["id"] == "zabbix-api")

    graph, service = build()
    assert service["reachability"]["state"] == "reachable"
    assert any(e["a"] == "pve-guest:108" and e["b"] == "zabbix-api" and e["confirmed"] for e in graph["links"])
    configured["zabbix-api"][0]["ip"] = "192.0.2.22"
    assert "reachability" not in build()[1]
    configured["zabbix-api"][0]["ip"] = address
    network["arp"] = []
    assert "reachability" not in build()[1]
    network["arp"] = [arp]
    pve["configs"]["108"]["net0"] = "virtio=02:00:00:00:00:99,bridge=vmbr0"
    graph, service = build()
    assert "reachability" not in service
    assert not any(e["b"] == "zabbix-api" for e in graph["links"])


def test_port_evidence_keeps_direction_and_parallel_links(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    observed = (now - timedelta(minutes=1)).isoformat()
    devices = [{"id": key, "name": key, "kind": "switch", "management_ip": ip}
               for key, ip in (("west", "192.0.2.1"), ("east", "192.0.2.2"))]
    declared = {"endpoint_a": {"device": "west", "interface": "west-1"},
                "endpoint_b": {"device": "east", "interface": "east-1"}}
    network = {
        "sources": [{"id": index, "name": d["id"], "host": d["management_ip"]}
                    for index, d in enumerate(devices, 1)],
        "ports": [{"source": "east", "port_key": "index:2", "name": "east-2"}],
        "links": [{"source_a_id": 2, "source_b_id": 1, "port_a_key": "index:2",
                   "port_b_key": "west-2", "last_seen_at": now.isoformat(), "state": "confirmed",
                   "evidence": [
                       {"endpoint_a": {"source_id": 2, "port_key": "index:2"},
                        "endpoint_b": {"source_id": 1, "port_key": "west-2"},
                        "evidence_type": "lldp_chassis_mac", "observed_at": observed},
                   ]}],
        "lldp": [{"source": "west", "system_name": "east", "local_port_key": "west-3",
                  "port_id_subtype": 3, "port_id": "00:01:02:03:04:05", "observed_at": observed}],
    }
    graph = build_graph({"devices": devices, "links": [declared]}, network, {}, {}, {}, now)
    path = tmp_path / "infrastructure.json"
    path.write_text(json.dumps(graph), encoding="utf-8")
    link, = load_infrastructure_map(path, now)["links"]
    assert (link["a"], link["b"]) == ("west", "east")
    assert [(row["a"], row["b"], row["confirmed"]) for row in link["portEvidence"]] == [
        ("west-1", "east-1", False), ("west-2", "east-2", True), ("west-3", "", True),
    ]
    stale_link, = load_infrastructure_map(path, now + timedelta(hours=1))["links"]
    assert not stale_link["confirmed"]
    assert all(not row["confirmed"] for row in stale_link["portEvidence"])
    assert link["portEvidence"][1]["at"] == observed

    network.pop("lldp")
    network["links"][0]["evidence"][0]["observed_at"] = (now - timedelta(hours=1)).isoformat()
    graph = build_graph({"devices": devices, "links": [declared]}, network, {}, {}, {}, now)
    assert not graph["links"][0]["confirmed"]


def test_lldp_direct_neighbor_overrides_conflicting_fdb_ports():
    from app.infrastructure_collect import build_graph

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    context = {"devices": [{"id": key, "name": name, "kind": kind}
                            for key, name, kind in (("core", "SNR", "switch"), ("ito", "ITO", "switch"),
                                                    ("router", "RB3011", "router"), ("other", "Other", "router"))]}
    sources = [{"id": i, "name": key, "driver": "snmp_switch", "driver_options": {"intent_stable_id": key}}
               for i, key in enumerate(("core", "ito", "router", "other"), 1)]
    inferred = [{"source_a_id": 1, "source_b_id": peer, "state": "confirmed", "evidence": [
        {"evidence_type": "fdb_management_mac", "endpoint_a": {"source_id": 1, "port_key": "ge23"},
         "endpoint_b": {"source_id": peer}, "observed_at": at},
    ]} for peer in (3, 4)]
    lldp = [{"source": "core", "local_port_key": port, "system_name": name, "chassis_id": mac,
             "port_id": "ether1", "port_id_subtype": "interface_name", "observed_at": at}
            for port, name, mac in (("ge23", "ITO", "02:00:00:00:00:02"),
                                    ("ge24", "RB3011", "02:00:00:00:00:03"))]
    graph = build_graph(context, {"sources": sources, "links": inferred, "lldp": lldp}, {}, {}, {}, now)
    links = {e["b"]: e for e in graph["links"] if e["a"] == "core"}
    assert links["ito"]["confirmed"]
    assert links["router"]["confirmed"]
    assert [(p["a"], p["confirmed"]) for p in links["router"]["portEvidence"]] == [("ge23", False), ("ge24", True)]
    assert not links["other"]["confirmed"]
    assert not links["other"]["portEvidence"][0]["confirmed"]


def test_reciprocal_lldp_confirms_numeric_alias_and_unnamed_peer():
    from app.infrastructure_collect import build_graph

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    a_mac, b_mac = "02:00:00:00:00:01", "02:00:00:00:00:02"
    sources = [{"id": i, "name": name, "host": ip, "enabled": 1, "driver": "snmp_switch"}
               for i, name, ip in ((1, "dgs", "192.0.2.16"), (2, "snr", "192.0.2.254"))]
    ports = [{"source": source, "port_key": f"ifindex:{index}", "if_index": index, "name": label,
              "mac": mac, "oper_status": "up", "last_seen_at": at}
             for source, index, label, mac in (("dgs", 52, "Slot0/52", None), ("snr", 5021, "ge21", b_mac))]
    lldp = [
        {"source": "dgs", "local_port_key": "ifindex:52", "chassis_id": b_mac, "chassis_id_subtype": "mac_address", "port_id": "ge21",
         "port_id_subtype": "interface_name", "observed_at": at},
        {"source": "snr", "local_port_key": "ifindex:5021", "chassis_id": a_mac, "chassis_id_subtype": "mac_address", "port_id": "52",
         "port_id_subtype": "interface_alias", "observed_at": at},
    ]
    network = {"sources": sources, "ports": ports, "lldp": lldp,
               "arp": [{"ip": "192.0.2.16", "mac": a_mac, "last_seen_at": at}]}

    def pairs():
        graph = build_graph({}, network, {}, {}, {}, now)
        return [(p["a"], p["b"]) for e in graph["links"] for p in e.get("portEvidence", [])
                if p["confirmed"] and p["source"] == "LLDP · двустороннее"]

    assert pairs() == [("Slot0/52", "ge21")]
    lldp[1]["port_id"] = "53"
    assert pairs() == []
    lldp[1]["port_id"] = "52"
    lldp.append({**lldp[0], "chassis_id": "02:00:00:00:00:99"})
    assert pairs() == []
    lldp.pop()
    lldp[1]["observed_at"] = (now - timedelta(hours=1)).isoformat()
    assert pairs() == []


def test_lldp_multiple_neighbors_on_one_port_do_not_confirm_direct_links():
    from app.infrastructure_collect import build_graph

    now = datetime.now(timezone.utc)
    devices = [{"id": name, "name": name, "kind": "router"} for name in ("one", "two")]
    network = {"sources": [{"id": 1, "name": "switch", "driver": "snmp_switch"}], "lldp": [
        {"source": "switch", "system_name": name, "local_port_key": "48",
         "chassis_id": f"02:00:00:00:00:0{index}", "observed_at": now.isoformat()}
        for index, name in enumerate(("one", "two"), 1)
    ]}
    graph = build_graph({"devices": devices}, network, {}, {}, {}, now)
    assert len(graph["links"]) == 2
    assert all(not link["confirmed"] and not link["portEvidence"][0]["confirmed"] for link in graph["links"])


def test_fdb_ports_require_fresh_unambiguous_device_identity(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    fresh = (now - timedelta(minutes=1)).isoformat()
    old = (now - timedelta(hours=1)).isoformat()
    first, duplicate, stale, virtual = [f"02:00:00:00:00:0{n}" for n in range(1, 5)]
    devices = [{"id": name, "name": name, "kind": "server", **identity} for name, identity in [
        ("server", {"management_ip": "192.0.2.4"}),
        ("duplicate-a", {"mac_addresses": [duplicate]}),
        ("duplicate-b", {"mac_addresses": [duplicate]}),
        ("stale", {"mac_addresses": [stale]}),
        ("guest", {"mac_addresses": [virtual]}),
        ("hypervisor", {}),
    ]]
    network = {
        "sources": [{"id": 5, "name": "switch", "driver": "snmp_switch"}],
        "ports": [{"source": "switch", "port_key": "1/1", "name": "Gi1/1"}],
        "hosts": [{"ip": "192.0.2.4", "mac": first, "last_seen_at": fresh}],
        "attachments": [{"source_id": 5, "port_key": "1/1", "mac": mac,
                         "observed_at": observed, "vlan_id": 100}
                        for mac, observed in [(first, fresh), (duplicate, fresh), (stale, old), (virtual, fresh)]],
    }
    placement = {"endpoint_a": {"device": "guest"}, "endpoint_b": {"device": "hypervisor"},
                 "relation": "virtualized_on"}
    graph = build_graph({"devices": devices, "links": [placement]}, network, {}, {}, {}, now)
    path = tmp_path / "infrastructure.json"
    path.write_text(json.dumps(graph), encoding="utf-8")
    link, = (link for link in load_infrastructure_map(path, now)["links"] if link["source"] == "netctl FDB")
    assert (link["a"], link["b"], link["confirmed"]) == ("observer:switch", "server", True)
    assert link["portEvidence"] == [{"a": "Gi1/1", "b": "", "source": "netctl FDB",
                                     "at": fresh, "confirmed": True, "vlan": 100}]
    assert first not in path.read_text(encoding="utf-8")


def test_matching_fdb_attachment_adds_evidence_and_supplemental_ip_check(monkeypatch):
    from app.infrastructure_collect import build_graph
    from app import infrastructure_service_probes as probes

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    mac, address = "02:00:00:00:00:14", "192.0.2.14"
    context = {"devices": [
        {"id": "pc", "name": "PC", "kind": "endpoint", "mac_addresses": [mac],
         "observed_ipv4_addresses": [address]},
        {"id": "sw", "name": "CSS", "kind": "switch", "management_ip": "192.0.2.254"},
    ], "links": [{"endpoint_a": {"device": "pc", "interface": "Ethernet"},
                  "endpoint_b": {"device": "sw", "interface": "Port7"},
                  "relation": "connected_to", "state": {"verified": True}}]}
    network = {"sources": [{"id": 1, "name": "css", "host": "192.0.2.254", "driver": "snmp_switch"}],
               "attachments": [{"source_id": 1, "port_key": "Port7", "mac": mac, "observed_at": at, "vlan_id": 20}]}
    bindings = {"asset_ip_checks": {"pc": address}}
    configured = {"pc": [{"type": "icmp", "ip": address}]}
    monkeypatch.setattr(probes, "_probe", lambda spec: "reachable")

    def build():
        graph = build_graph(context, network, {}, {}, bindings, now)
        probes.apply_service_probes(graph["nodes"], configured)
        return graph, next(n for n in graph["nodes"] if n["id"] == "pc")

    graph, node = build()
    link, = graph["links"]
    assert link["confirmed"] and link["source"] == "GitHub"
    assert [(p["a"], p["b"]) for p in link["portEvidence"]] == [("Ethernet", "Port7"), ("", "Port7")]
    assert node["serviceChecks"][0]["state"] == "reachable"
    assert "reachability" not in node
    network["attachments"][0]["port_key"] = "Port8"
    graph, node = build()
    assert len(graph["links"]) == 2
    assert "serviceChecks" not in node


def test_lacp_confirms_only_ports_whose_partner_matches_fresh_arp(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    mac, address = "02:00:00:00:00:14", "192.0.2.14"
    context = {"devices": [
        {"id": "pbs", "name": "PBS", "kind": "backup_server", "management_ip": address},
        {"id": "sw", "name": "SNR", "kind": "switch", "management_ip": "192.0.2.254"},
    ], "links": [
        {"endpoint_a": {"device": "sw", "interface": port}, "endpoint_b": {"device": "pbs", "interface": alias},
         "relation": "connected_to"} for port, alias in (("po1", "data_lag"), ("xe1", "backup_10g"))
    ]}
    network = {
        "sources": [{"id": 1, "name": "snr", "host": "192.0.2.254", "driver": "snmp_switch"}],
        "arp": [{"ip": address, "mac": mac, "last_seen_at": at}],
        "lacp": [{"source": "snr", "asset": "pbs", "aggregate": "po1", "expected": 2, "at": at,
                  "members": [{"port": "ge6", "partner_port": 1, "mac": mac},
                              {"port": "ge7", "partner_port": 2, "mac": "02:00:00:00:00:99"}]}],
    }
    path = tmp_path / "map.json"

    def link(stamp=now):
        graph = build_graph(context, network, {}, {}, {}, now)
        path.write_text(json.dumps(graph), encoding="utf-8")
        return next(e for e in load_infrastructure_map(path, stamp)["links"] if {e["a"], e["b"]} == {"sw", "pbs"})

    result = link()
    assert result["confirmed"] and result["source"] == "SNMP LACP + ARP"
    assert [(p["a"], p["b"]) for p in result["portEvidence"] if p["confirmed"]] == [("po1 / ge6", "LACP 1")]
    assert not link(now + timedelta(hours=1))["confirmed"]
    network["arp"].append({**network["arp"][0], "mac": "02:00:00:00:00:98"})
    assert not link()["confirmed"]
    assert mac not in path.read_text(encoding="utf-8")


def test_proxmox_management_port_joins_unique_fdb_and_active_bridge(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    mac, address = "02:00:00:00:00:13", "192.0.2.13"
    context = {"devices": [
        {"id": "pve3", "name": "pve3", "kind": "hypervisor", "management_ip": address},
        {"id": "sw", "name": "SNR", "kind": "switch", "management_ip": "192.0.2.254"},
    ], "links": [{"endpoint_a": {"device": "sw", "interface": "ge11"},
                  "endpoint_b": {"device": "pve3", "interface": "data_1g"}, "relation": "connected_to"}]}
    source = {"id": 1, "name": "snr", "host": "192.0.2.254", "driver": "snmp_switch"}
    attachment = {"mac": mac, "source_id": 1, "port_key": "ge11", "vlan_id": 1, "observed_at": at}
    network = {"sources": [source], "attachments": [attachment],
               "hosts": [{"ip": address, "mac": mac, "last_seen_at": at}],
               "arp": [{"ip": address, "mac": mac, "last_seen_at": at}]}
    pve = {"at": at, "nodes": [{"node": "pve3", "status": "online"}], "cluster": [], "guests": [],
           "management": {"pve3": {"address": address, "port": "enp2s0f0"}}}
    path = tmp_path / "map.json"

    def load(stamp=now):
        graph = build_graph(context, network, {}, pve, {}, now)
        path.write_text(json.dumps(graph), encoding="utf-8")
        return [link for link in load_infrastructure_map(path, stamp)["links"]
                if {link["a"], link["b"]} == {"sw", "pve3"}]

    link, = load()
    assert link["confirmed"]
    assert any(p["confirmed"] and p["a"] == "ge11" and p["b"] == "enp2s0f0" for p in link["portEvidence"])
    assert not load(now + timedelta(hours=1))[0]["confirmed"]
    network["attachments"].append({**attachment, "port_key": "ge12"})
    assert not any(p["b"] == "enp2s0f0" for link in load() for p in link["portEvidence"])
    network["attachments"].pop()
    network["arp"].clear()
    assert not any(p["b"] == "enp2s0f0" for link in load() for p in link["portEvidence"])


def test_lldp_management_address_requires_matching_inventory_and_host_mac():
    from app.infrastructure_collect import build_graph

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    mac = "02:00:00:00:00:03"
    address = "192.0.2.13"
    context = {"devices": [{"id": "remote", "name": "Remote", "kind": "switch", "mac_addresses": [mac]}]}
    host = {"ip": address, "mac": mac, "last_seen_at": at, "availability": {
        "checked_at": at, "run_status": "success", "state": "online", "reason": "active_probe", "active_method": "icmp",
    }}
    network = {"sources": [{"id": 1, "name": "local", "driver": "snmp_switch"}], "hosts": [host], "lldp": [
        {"source": "local", "local_port_key": "51", "system_name": "Remote", "chassis_id": mac,
         "port_id": "Ge1", "port_id_subtype": "interface_name", "management_addresses": [address], "observed_at": at},
    ]}
    graph = build_graph(context, network, {}, {}, {}, now)
    remote = next(node for node in graph["nodes"] if node["id"] == "remote")
    assert remote["reachability"]["state"] == "reachable"
    assert remote["properties"]["Адрес управления по LLDP"] == address
    link, = graph["links"]
    assert link["portEvidence"][0]["b"] == "Ge1"
    host["mac"] = "02:00:00:00:00:04"
    graph = build_graph(context, network, {}, {}, {}, now)
    remote = next(node for node in graph["nodes"] if node["id"] == "remote")
    assert "reachability" not in remote

    network["router_neighbors"] = [{"identity": "Remote", "address": address, "mac": host["mac"], "last_seen_at": at}]
    graph = build_graph(context, network, {}, {}, {}, now)
    remote = next(node for node in graph["nodes"] if node["id"] == "remote")
    assert remote["reachability"]["state"] == "reachable"
    assert remote["properties"]["Адрес управления по LLDP"] == address

    available = host["availability"]
    host["availability"] = {}
    alternate = {**host, "ip": "192.0.2.14", "mac": mac, "availability": available}
    network["hosts"].append(alternate)
    graph = build_graph(context, network, {}, {}, {}, now)
    remote = next(node for node in graph["nodes"] if node["id"] == "remote")
    assert remote["reachability"]["state"] == "reachable"
    assert remote["properties"]["Адрес управления по LLDP"] == address
    assert remote["properties"]["IP по MAC"] == alternate["ip"]
    host["availability"] = available
    network["hosts"].pop()

    network["lldp"][0]["chassis_id"] = host["mac"]
    graph = build_graph(context, network, {}, {}, {}, now)
    remote = next(node for node in graph["nodes"] if node["id"] == "remote")
    assert "reachability" not in remote
    assert remote["properties"]["IP заявлен в LLDP"] == address
    assert "MAC шасси" in remote["properties"]["Сопоставление LLDP"]
    assert not graph["links"][0]["confirmed"]


def test_openvpn_requires_connected_daemon_and_active_session(monkeypatch):
    from io import BytesIO
    from app import infrastructure_service_probes as probes

    class Management:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def settimeout(self, timeout):
            assert timeout > 0

        def connect(self, path):
            assert path == "/run/openvpn/server.sock"

        def sendall(self, command):
            assert command == b"state\nstatus 3\n"

        def makefile(self, mode):
            return BytesIO(self.response)

    connection = Management()
    monkeypatch.setattr(probes.socket, "AF_UNIX", 1, raising=False)
    monkeypatch.setattr(probes.socket, "socket", lambda family: connection)
    ready = b"123,CONNECTED,SUCCESS,,\nEND\r\n"
    header = b"HEADER\tCLIENT_LIST\tCommon Name\n"
    client = b"CLIENT_LIST\tsample\n"
    spec = {"type": "openvpn_management", "port": 1194}
    connection.response = ready + header + client + b"END\n"
    assert probes._probe(spec) == "reachable"
    for response in (ready + header + b"END\n", header + client + b"END\n", ready + header + client):
        connection.response = response
        assert probes._probe(spec) == "unknown"


def test_network_device_without_management_ip_uses_unique_current_mac_binding():
    from app.infrastructure_collect import build_graph

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    mac = "02:00:00:00:00:03"
    address = "192.0.2.15"
    device = {"id": "router", "name": "Router", "kind": "router", "mac_addresses": [mac]}
    host = {"ip": address, "mac": mac, "last_seen_at": at, "availability": {
        "checked_at": at, "run_status": "success", "state": "online", "reason": "active_probe", "active_method": "icmp",
    }}

    def build(devices, hosts):
        return build_graph({"devices": devices}, {"hosts": hosts}, {}, {}, {}, now)["nodes"][0]

    node = build([device], [host])
    assert node["reachability"]["state"] == "reachable"
    assert node["properties"]["IP по MAC"] == address
    assert "reachability" not in build([device, {**device, "id": "other"}], [host])
    assert "reachability" not in build([device], [host, {**host, "ip": "192.0.2.17"}])
    assert "reachability" not in build([device], [{**host, "last_seen_at": (now - timedelta(hours=1)).isoformat()}])


def test_switch_ports_expose_fresh_link_state_and_age(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    recent = (now - timedelta(minutes=2)).isoformat()
    old = (now - timedelta(hours=1)).isoformat()
    network = {
        "sources": [{"id": 1, "name": "sw", "driver": "snmp_switch"}],
        "ports": [
            {"source": "sw", "name": "ge1", "oper_status": "up", "admin_status": "up",
             "speed_bps": 1_000_000_000, "last_seen_at": recent, "mac": "hidden", "collector_run_id": 2},
            {"source": "sw", "name": "ge2", "oper_status": "up", "last_seen_at": old, "collector_run_id": 2},
            {"source": "sw", "name": "ge3", "oper_status": "down", "admin_status": "down",
             "last_seen_at": recent, "collector_run_id": 2},
            {"source": "sw", "name": "ge1", "oper_status": "up", "last_seen_at": old, "collector_run_id": 1},
        ],
    }
    graph = build_graph({}, network, {}, {}, {}, now)
    path = tmp_path / "graph.json"
    path.write_text(json.dumps(graph), encoding="utf-8")
    node, = load_infrastructure_map(path, now)["nodes"]
    assert "hidden" not in path.read_text(encoding="utf-8")
    assert node["ports"] == [
        {"name": "ge1", "state": "up", "speedBps": 1_000_000_000, "checkedAt": recent, "stale": False},
        {"name": "ge2", "state": "unknown", "speedBps": None, "checkedAt": old, "stale": True},
        {"name": "ge3", "state": "disabled", "speedBps": None, "checkedAt": recent, "stale": False},
    ]


def test_guest_placement_includes_current_bridge_and_configured_members(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    pve = {
        "at": at, "cluster": [], "nodes": [{"node": "pve1", "status": "online"}],
        "guests": [{"vmid": 103, "node": "pve1", "type": "qemu", "status": "running"}],
        "configs": {"103": {"net0": "virtio=02:00:00:00:00:03,bridge=vmbr1,tag=100,link_down=1",
                            "net1": "virtio=02:00:00:00:00:04", "net2": "bridge=bad/path"}},
        "bridges": {"pve1": {"vmbr1": {"type": "bridge", "bridge_ports": "bond0 eno2", "active": 1}}},
    }
    graph = build_graph({}, {}, {}, pve, {}, now)
    path = tmp_path / "graph.json"
    path.write_text(json.dumps(graph), encoding="utf-8")
    assert "02:00:00:00:00:03" not in path.read_text(encoding="utf-8")
    link = next(link for link in load_infrastructure_map(path, now)["links"] if link["b"] == "pve-guest:103")
    assert link["portEvidence"] == [{
        "a": "vmbr1", "b": "net0", "source": "Proxmox · конфигурация ВМ", "at": at,
        "confirmed": True, "vlan": 100,
        "virtual": {"linkDisabled": True, "bridgeActive": True, "uplinks": ["bond0", "eno2"], "switchPorts": []},
    }]
    stale_link = next(link for link in load_infrastructure_map(path, now + timedelta(hours=1))["links"]
                      if link["b"] == "pve-guest:103")
    assert not stale_link["confirmed"]
    assert not stale_link["portEvidence"][0]["confirmed"]


def test_vm_switch_observation_requires_current_mac_and_declared_host_port(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    mac = "02:00:00:00:00:03"
    context = {
        "devices": [{"id": name, "name": name, "kind": kind}
                    for name, kind in [("pve1", "hypervisor"), ("sw", "switch")]],
        "links": [{"relation": "connected_to", "state": {"verified": True},
                   "endpoint_a": {"device": "sw", "interface": "XE3"},
                   "endpoint_b": {"device": "pve1", "interface": "vm_net_10g"}}],
    }
    pve = {
        "at": at, "cluster": [], "nodes": [{"node": "pve1", "status": "online"}],
        "guests": [{"vmid": 103, "node": "pve1", "type": "qemu", "status": "running"}],
        "configs": {"103": {"net0": f"virtio={mac},bridge=vmbr1"}},
        "bridges": {"pve1": {"vmbr1": {"active": 1, "bridge_ports": "ens7f1np1"}}},
        "activePorts": {"pve1": ["ens7f1np1"]},
    }
    network = {
        "sources": [{"id": 1, "name": "switch-source", "driver": "snmp_switch",
                     "driver_options": {"intent_stable_id": "sw"}}],
        "ports": [{"source": "switch-source", "port_key": "index:3", "name": "xe3"}],
        "guest_fdb": [{"mac": mac, "source_id": 1, "port_key": port, "vlan_id": 1, "observed_at": at}
                      for port in ("index:3", "unrelated")],
    }
    path = tmp_path / "graph.json"

    def switch_ports(rendered_at):
        graph = build_graph(context, network, {}, pve, {}, now)
        path.write_text(json.dumps(graph), encoding="utf-8")
        assert mac not in path.read_text(encoding="utf-8")
        link = next(edge for edge in load_infrastructure_map(path, rendered_at)["links"] if edge["b"] == "pve-guest:103")
        return link["portEvidence"][0]["virtual"]["switchPorts"]

    def physical_ports():
        graph = build_graph(context, network, {}, pve, {}, now)
        link = next(e for e in graph["links"] if {e["a"], e["b"]} == {"sw", "pve1"})
        return [(p["a"], p["b"]) for p in link["portEvidence"] if p["source"] == "netctl FDB + Proxmox"]

    assert switch_ports(now) == [{"id": "sw", "port": "xe3", "vlan": 1, "at": at}]
    assert physical_ports() == [("xe3", "ens7f1np1")]
    pve["activePorts"]["pve1"] = []
    assert physical_ports() == []
    pve["activePorts"]["pve1"] = ["ens7f1np1"]
    pve["bridges"]["pve1"]["vmbr1"]["bridge_ports"] += " ens7f0np0"
    assert physical_ports() == []
    pve["bridges"]["pve1"]["vmbr1"]["bridge_ports"] = "ens7f1np1"
    assert switch_ports(now + timedelta(hours=1)) == []
    pve["configs"]["103"]["net0"] += ",link_down=1"
    assert switch_ports(now) == []
    assert physical_ports() == []


def test_collection_reads_source_registry_without_syncing_config(monkeypatch):
    from app import infrastructure_collect as collector

    calls = []

    class ReadConnection:
        def execute(self, statement):
            assert statement.lstrip().startswith("SELECT")
            return []

        def close(self):
            calls.append("closed")

    def netctl(args, **kwargs):
        payloads = {
            ("switches", "status"): {"switches": []},
            ("topology", "links"): {"links": []},
            ("hosts", "export"): {"hosts": []},
            ("switches", "ports"): {"ports": [], "pagination": {"next_offset": None}},
            ("switches", "lldp"): {"lldp_neighbors": [], "pagination": {"next_offset": None}},
        }
        return payloads[tuple(args[:2])]

    monkeypatch.setattr(collector, "connect_read_only", lambda url: ReadConnection())
    monkeypatch.setattr(collector, "list_sources", lambda conn: [{"id": 1, "name": "test"}])
    monkeypatch.setattr(collector, "query_confirmed_attachment_ports", lambda conn: [])
    monkeypatch.setattr(collector, "run_netctl", netctl)
    assert collector.read_network()["sources"] == [{"id": 1, "name": "test"}]
    assert calls == ["closed"]


def test_route_evidence_is_scoped_and_does_not_mark_service_available():
    from app.infrastructure_collect import build_graph

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    context = {
        "services": [{"id": "vpn", "name": "VPN"}],
        "routing_intent": [{"id": "vpn-routes", "next_hop": "192.0.2.1", "routing_table": "main",
                            "destinations": ["198.51.100.0/24", "203.0.113.0/24"]}],
    }
    network = {"routes": [
        {"source": source, "gateway": "192.0.2.1", "routing_table": table,
         "dst_address": dest, "active": 1, "disabled": 0, "last_seen_at": at}
        for source, table, dest in [("router", "main", "198.51.100.0/24"),
                                    ("router", "other", "203.0.113.0/24"),
                                    ("other", "main", "203.0.113.0/24")]
    ]}
    bindings = {"route_evidence": {"vpn": {"source": "router", "intent": "vpn-routes"}}}
    node, = build_graph(context, network, {}, {}, bindings, now)["nodes"]
    assert "reachability" not in node
    assert [(check["target"], check["state"]) for check in node["serviceChecks"]] == [
        ("198.51.100.0/24", "reachable"), ("203.0.113.0/24", "unknown"),
    ]


def test_sip_options_validates_transaction_and_treats_silence_as_unknown(monkeypatch):
    from app import infrastructure_service_probes as probes

    class Datagram:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def settimeout(self, timeout):
            pass

        def connect(self, address):
            assert address == ("192.0.2.13", 5060)

        def getsockname(self):
            return ("192.0.2.14", 12345)

        def sendall(self, request):
            assert request.startswith(b"OPTIONS sip:192.0.2.13:5060 SIP/2.0")
            self.headers = [line for line in request.split(b"\r\n") if line.startswith((b"Call-ID:", b"CSeq:"))]

        def recv(self, size):
            if self.code is None:
                raise TimeoutError
            headers = self.headers if self.match else [b"Call-ID: unrelated", b"CSeq: 1 OPTIONS"]
            return b"\r\n".join([b"SIP/2.0 " + self.code, *headers, b"", b""])

    wire = Datagram()
    monkeypatch.setattr(probes.socket, "socket", lambda *args: wire)
    spec = {"type": "sip_options", "ip": "192.0.2.13", "port": 5060}
    for code, match, state in [(b"200 OK", True, "reachable"), (b"503 Busy", True, "unreachable"),
                               (b"200 OK", False, "unknown"), (None, True, "unknown")]:
        wire.code, wire.match = code, match
        assert probes._probe(spec) == state


def test_infrastructure_map_serves_only_public_snapshot(tmp_path, monkeypatch):
    path = tmp_path / "infrastructure.json"
    monkeypatch.setenv("INFRASTRUCTURE_MAP_SNAPSHOT_PATH", str(path))
    now = datetime.now(timezone.utc)
    path.write_text(json.dumps({
        "schema": 1, "snapshotAt": now.isoformat(),
        "nodes": [
            {"id": "vm:103", "name": "Directum VM", "kind": "Виртуальная машина",
             "properties": {"Состояние ВМ": "Запущена"}, "status": "ok", "guest": True, "vmid": 103,
             "sources": [{"name": "Proxmox", "status": "ok", "at": (now - timedelta(hours=1)).isoformat()}],
             "credential": "must-not-leave-the-source"},
        ],
        "links": [{"a": "vm:103", "b": "missing", "kind": "placement", "confirmed": True}],
    }), encoding="utf-8")
    client, headers, _ = make_client(tmp_path, monkeypatch)

    assert client.get("/network/infrastructure", follow_redirects=False).status_code == 303
    assert client.get("/api/v1/network/infrastructure").status_code == 401
    response = client.get("/api/v1/network/infrastructure", headers=headers)
    assert response.status_code == 200
    graph = response.json()["infrastructure"]
    assert graph["nodes"][0]["status"] == "unknown"
    assert graph["nodes"][0]["reachability"]["state"] == "unknown"
    assert graph["nodes"][0]["sources"][0]["stale"]
    assert graph["links"] == []
    assert "must-not-leave-the-source" not in response.text
    assert response.headers["cache-control"] == "no-store"


def test_missing_infrastructure_snapshot_has_explicit_empty_state(tmp_path, monkeypatch):
    monkeypatch.setenv("INFRASTRUCTURE_MAP_SNAPSHOT_PATH", str(tmp_path / "missing.json"))
    client, headers, _ = make_client(tmp_path, monkeypatch)

    response = client.get("/api/v1/network/infrastructure", headers=headers)
    assert response.status_code == 200
    assert response.json()["infrastructure"]["availability"] == "missing"


def test_browser_can_refresh_snapshot_only_with_a_web_session(tmp_path, monkeypatch):
    path = tmp_path / "map.json"
    monkeypatch.setenv("INFRASTRUCTURE_MAP_SNAPSHOT_PATH", str(path))
    client, _, _ = make_client(tmp_path, monkeypatch)
    endpoint = "/network/infrastructure/snapshot"
    assert client.get(endpoint, follow_redirects=False).status_code == 303
    login = client.get("/login")
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', login.text).group(1)
    response = client.post("/login", data={"csrf_token": csrf, "username": "admin", "password": "admin-pass"},
                           follow_redirects=False)
    assert response.headers["location"] == "/"
    assert client.get(endpoint).json()["infrastructure"]["availability"] == "missing"
    stamp = datetime.now(timezone.utc).isoformat()
    path.write_text(json.dumps({"schema": 1, "snapshotAt": stamp, "nodes": [], "links": []}), encoding="utf-8")
    updated = client.get(endpoint)
    assert updated.headers["cache-control"] == "no-store"
    assert updated.json()["infrastructure"]["snapshotAt"] == stamp
    assert 'data-snapshot-url="/network/infrastructure/snapshot"' in client.get("/network/infrastructure").text


def test_guest_reachability_accepts_current_arp_with_newer_successful_probe():
    from app.infrastructure_collect import build_graph

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    mac, other = "02:00:00:00:00:03", "02:00:00:00:00:04"
    address = "192.0.2.21"
    pve = {
        "at": at, "cluster": [], "nodes": [{"node": "pve1", "status": "online"}],
        "guests": [{"vmid": 108, "node": "pve1", "type": "qemu", "status": "running"}],
        "configs": {"108": {"net0": f"virtio={mac},bridge=vmbr0"}},
    }
    seen = (now - timedelta(minutes=1)).isoformat()
    host = {"ip": address, "mac": other, "availability": {"state": "online", "reason": "active_probe",
            "active_method": "icmp", "checked_at": at, "run_status": "success"}}
    arp = {"ip": address, "mac": mac, "last_seen_at": seen}
    network = {"hosts": [host], "arp": [arp]}

    def guest():
        graph = build_graph({}, network, {}, pve, {}, now)
        return next(node for node in graph["nodes"] if node.get("vmid") == 108)

    node = guest()
    assert node["reachability"]["state"] == "reachable"
    assert node["properties"]["IP проверки по ARP"] == address
    network["arp"].append({**arp, "mac": other})
    assert "reachability" not in guest()
    network["arp"].pop()
    host["availability"]["checked_at"] = (now - timedelta(minutes=2)).isoformat()
    assert "reachability" not in guest()
    host["availability"]["checked_at"] = at
    pve["configs"]["108"]["net0"] += ",link_down=1"
    assert "reachability" not in guest()


def test_guest_arp_probe_requires_on_link_identity_and_current_proxmox_interface(monkeypatch):
    from app import infrastructure_collect as collector

    now = datetime.now(timezone.utc)
    ip, mac = "192.0.2.21", "02:00:00:00:00:03"
    guest = {"vmid": 108, "node": "pve1", "type": "qemu", "status": "running"}
    config = {"net0": f"virtio={mac},bridge=vmbr0"}
    pve = {"cluster": [], "nodes": [], "guests": [guest], "configs": {"108": config}}
    arp = {"ip": ip, "mac": mac, "last_seen_at": now.isoformat()}
    network = {"arp": [arp]}
    route = {"dev": "ens18"}
    neighbor = {"dst": ip, "lladdr": mac, "state": ["DELAY"]}
    pings = []
    monkeypatch.setattr(collector, "probe_icmp", lambda address: pings.append(address) or True)
    monkeypatch.setattr(collector.subprocess, "check_output",
                        lambda args, **_: json.dumps([route if args[2] == "route" else neighbor]).encode())

    def collect():
        return collector._collect_guest_arp_probes(pve, network, {"108": ip}, now)

    network["guest_arp_probes"] = collect()
    graph = collector.build_graph({}, network, {}, pve, {}, datetime.now(timezone.utc))
    node = next(node for node in graph["nodes"] if node.get("vmid") == 108)
    assert node["reachability"]["source"] == "UI_VPN"
    assert node["properties"]["IP проверки по ARP"] == ip
    assert pings == [ip]
    route["gateway"] = "192.0.2.1"
    assert collect() == {}
    assert pings == [ip]
    del route["gateway"]
    neighbor["lladdr"] = "02:00:00:00:00:05"
    assert collect() == {}
    assert pings == [ip, ip]
    network["arp"].append({**arp, "mac": neighbor["lladdr"]})
    assert collect() == {}
    network["arp"].pop()
    config["net0"] += ",link_down=1"
    assert collect() == {}
    assert pings == [ip, ip]


def test_inventory_binding_needs_matching_guest_mac():
    from app.infrastructure_collect import build_graph

    context = {"devices": [{"id": "document-server", "name": "Document server", "kind": "server"}]}
    pve = {
        "cluster": [{"type": "cluster", "name": "example", "quorate": 1}],
        "nodes": [{"node": "pve-a", "status": "online"}],
        "guests": [{"vmid": 103, "node": "pve-a", "type": "qemu", "name": "guest", "status": "running"}],
        "configs": {"103": {"net0": "virtio=02:00:00:00:00:03,bridge=vmbr0"}},
    }
    binding = {"103": {"asset": "document-server", "mac": "02:00:00:00:00:03"}}
    graph = build_graph(context, {}, {}, pve, {"guests": binding}, datetime.now(timezone.utc))
    assert graph["overviewGuests"] == ["document-server"]
    assert any(edge["a"] == "pve-a" and edge["b"] == "document-server" for edge in graph["links"])

    pve["configs"]["103"]["net0"] = "virtio=02:00:00:00:00:99,bridge=vmbr0"
    graph = build_graph(context, {}, {}, pve, {"guests": binding}, datetime.now(timezone.utc))
    assert graph["overviewGuests"] == []
    assert any(node["id"] == "pve-guest:103" for node in graph["nodes"])


def test_reachability_uses_active_network_evidence_not_vm_power(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    active = {"state": "online", "run_status": "success", "reason": "active_probe",
              "active_method": "icmp", "checked_at": now.isoformat()}
    negative = {**active, "state": "offline", "reason": "active_negative_no_passive_evidence"}
    network = {"hosts": [
        {"ip": "192.0.2.10", "mac": "02:00:00:00:00:10", "availability": active},
        {"ip": "192.0.2.20", "mac": "02:00:00:00:00:20", "availability": negative},
        {"ip": "192.0.2.30", "mac": "02:00:00:00:00:30",
         "availability": {**active, "state": "seen", "reason": "passive_evidence"}},
    ]}
    pve = {
        "cluster": [], "nodes": [{"node": "pve-a", "status": "online"}],
        "guests": [
            {"vmid": i, "node": "pve-a", "type": "qemu", "status": status}
            for i, status in [(10, "running"), (20, "running"), (30, "running"), (40, "stopped"), (50, "running")]
        ],
        "configs": {
            str(i): {"net0": f"virtio=02:00:00:00:00:{i},bridge=vmbr0"} for i in (10, 20, 30)
        },
    }
    graph = build_graph({}, network, {}, pve, {}, now)
    path = tmp_path / "map.json"
    path.write_text(json.dumps(graph), encoding="utf-8")
    published = load_infrastructure_map(path, now)
    states = {node["vmid"]: node["reachability"]["state"] for node in published["nodes"] if node["guest"]}
    assert states == {10: "reachable", 20: "unreachable", 30: "unknown", 40: "stopped", 50: "unknown"}
    expired = load_infrastructure_map(path, now + timedelta(minutes=26))
    assert all(node["reachability"]["state"] == "unknown" for node in expired["nodes"])
