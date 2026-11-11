import json
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


def test_collection_reads_source_registry_without_syncing_config(monkeypatch):
    from app import infrastructure_collect as collector

    calls = []

    class ReadConnection:
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
