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
    assert states["yellow"]["serviceAvailability"] == {
        "unavailable": ["role:directum"], "degraded": [], "unknown": ["dns"],
    }
    directum["reachability"]["state"] = "unknown"
    path.write_text(json.dumps(graph), encoding="utf-8")
    states = {item["id"]: item for item in load_infrastructure_map(path, now)["nodes"]}
    assert states["role:directum"]["reachability"]["state"] == "unknown"
    assert states["yellow"]["mapStatus"] == "unknown"


def test_service_color_includes_required_observer_checks_and_confirmed_dependencies(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    stamp = now.isoformat()
    path = tmp_path / "infrastructure.json"

    def read(component="ok", database="reachable", observer_at=stamp, confirmed=True, cycle=False, missing=False):
        checks = [] if component is None else [{"name": "redis_tcp_6379", "status": component}]
        checks.append({"name": "c_disk_free", "status": "critical"})
        target = {"role": "directum", "status": "critical", "observed_at": observer_at, "checks": checks}
        report = {"freshness": "missing" if missing else "current", "targets": [] if missing else [target]}
        context = {"devices": [{"id": "vm", "name": "VM", "kind": "server"}]}
        graph = build_graph(context, {}, report, {}, {
            "roles": {"directum": {"asset": "vm", "required_observer_checks": ["redis_tcp_6379"]}},
        }, now)
        graph["nodes"].append({"id": "db", "name": "PostgreSQL", "kind": "Сервис"})
        for node in graph["nodes"]:
            state = database if node["id"] == "db" else "reachable"
            node["reachability"] = {"state": state, "checkedAt": stamp}
        graph["links"].append({"a": "role:directum", "b": "db", "kind": "Зависимость сервиса",
                               "confirmed": confirmed})
        if cycle:
            graph["links"].append({"a": "db", "b": "role:directum", "kind": "Зависимость сервиса",
                                   "confirmed": True})
        path.write_text(json.dumps(graph), encoding="utf-8")
        return {node["id"]: node for node in load_infrastructure_map(path, now)["nodes"]}

    assert read()["vm"]["mapStatus"] == "ok"
    for observed in (read(component="critical"), read(database="unreachable", cycle=True)):
        assert observed["role:directum"]["reachability"]["state"] == "reachable"
        assert observed["role:directum"]["mapStatus"] == "warn"
        assert observed["vm"]["mapStatus"] == "warn"
        assert observed["vm"]["serviceAvailability"]["unavailable"] == []
        assert observed["vm"]["serviceAvailability"]["degraded"] == ["role:directum"]
    assert read(database="unreachable", confirmed=False)["vm"]["mapStatus"] == "ok"
    assert read(component=None)["vm"]["mapStatus"] == "unknown"
    assert read(missing=True)["vm"]["mapStatus"] == "unknown"
    assert read(database="unknown")["vm"]["mapStatus"] == "unknown"
    assert read(observer_at=(now - timedelta(minutes=30)).isoformat())["vm"]["mapStatus"] == "unknown"
    assert read(cycle=True)["vm"]["mapStatus"] == "ok"


def test_observer_disk_measurements_publish_units_and_reported_warning_threshold(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    stamp = now.isoformat()
    snapshot = tmp_path / "infrastructure.json"
    report = {"freshness": "current", "targets": [
        {"role": "directum", "status": "critical", "observed_at": stamp, "checks": [
            {"name": "c_disk_free", "status": "critical", "observed": 5.32, "expected": 15},
            {"name": "rxdata_log_bytes", "status": "ok", "observed": 9 * 2**30, "expected": 20 * 2**30},
            {"name": "data_disk_free", "status": "ok", "observed": 102, "expected": "unrelated"},
            {"name": "unrelated_metric", "status": "ok", "observed": 42, "expected": 45},
        ]},
    ]}
    snapshot.write_text(json.dumps(build_graph({}, {}, report, {}, {}, now)), encoding="utf-8")

    def read(when=now):
        node, = load_infrastructure_map(snapshot, when)["nodes"]
        return {c["name"]: c for c in node["checks"]}

    checks = read()
    disk = checks["c_disk_free"]
    assert disk["label"] == "Свободно на диске C:"
    assert (disk["unit"], disk["observed"], disk["warningThreshold"]) == ("percent", 5.32, 15)
    logs = checks["rxdata_log_bytes"]
    assert (logs["unit"], logs["observed"], logs["warningThreshold"]) == ("bytes", 9 * 2**30, 20 * 2**30)
    assert checks["data_disk_free"]["observed"] is None
    assert "warningThreshold" not in checks["data_disk_free"]
    assert "warningThreshold" not in checks["unrelated_metric"]
    old = read(now + timedelta(minutes=26))["c_disk_free"]
    assert old["stale"] and old["status"] == "unknown"
    assert old["observed"] == 5.32 and old["checkedAt"] == stamp


def test_qemu_prelaunch_reports_guest_state_backup_lock_and_configured_bridge(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    stamp = now.isoformat()
    path = tmp_path / "infrastructure.json"
    guest = {"vmid": 104, "node": "pve1", "name": "Sirius", "type": "qemu",
             "status": "prelaunch", "lock": "backup"}
    pve = {"at": stamp, "cluster": [], "nodes": [{"node": "pve1", "status": "online"}],
           "guests": [guest], "configs": {"104": {"net0": "virtio=02:00:00:00:00:04,bridge=vmbr1"}}}

    def read(when=now):
        path.write_text(json.dumps(build_graph({}, {}, {}, pve, {}, now)), encoding="utf-8")
        graph = load_infrastructure_map(path, when)
        return next(node for node in graph["nodes"] if node["id"] == "pve-guest:104"), graph["links"]

    node, links = read()
    assert node["reachability"]["state"] == "unreachable"
    assert node["reachability"]["source"] == "Proxmox"
    assert node["mapStatus"] == "critical"
    assert node["properties"]["Состояние ВМ"] == "Гостевая ОС ещё не запущена"
    assert node["properties"]["Блокировка Proxmox"] == "Резервное копирование"
    placement = next(link for link in links if link["b"] == "pve-guest:104")
    port, = placement["portEvidence"]
    assert (port["a"], port["b"]) == ("vmbr1", "net0")
    assert port["virtual"]["switchPorts"] == []

    node, _ = read(now + timedelta(minutes=26))
    assert node["mapStatus"] == "unknown"
    assert "Блокировка Proxmox" not in node["properties"]
    guest.update(status="running")
    node, _ = read()
    assert node["reachability"]["state"] == "unknown"
    assert node["properties"]["Блокировка Proxmox"] == "Резервное копирование"


def test_cluster_health_distinguishes_quorum_members_and_api(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    path = tmp_path / "infrastructure.json"
    cluster = {"type": "cluster", "name": "example", "quorate": 1, "nodes": 2}
    members = [{"type": "node", "name": "pve1", "online": 1}, {"type": "node", "name": "pve2", "online": 1}]

    def read(when=now):
        pve = {"at": now.isoformat(), "cluster": [cluster, *members], "guests": [],
               "nodes": [{"node": "pve1", "status": "online"}, {"node": "pve2", "status": "online"}]}
        graph = build_graph({}, {}, {}, pve, {}, now)
        path.write_text(json.dumps(graph), encoding="utf-8")
        return next(node for node in load_infrastructure_map(path, when)["nodes"] if node["id"] == "proxmox:cluster")

    healthy = read()
    assert healthy["mapStatus"] == "ok"
    assert [(c["method"], c["state"]) for c in healthy["serviceChecks"]] == [
        ("Кворум", "reachable"), ("Участники кластера", "reachable"),
    ]
    assert healthy["properties"]["Узлы"] == "2 из 2 в сети"
    cluster["quorate"] = 0
    no_quorum = read()
    assert no_quorum["reachability"]["state"] == "reachable"
    assert no_quorum["mapStatus"] == "warn"
    cluster["quorate"] = 1
    members[1]["online"] = 0
    assert read()["mapStatus"] == "warn"
    assert read()["properties"]["Узлы"] == "1 из 2 в сети"
    members.pop()
    assert read()["mapStatus"] == "unknown"
    cluster["quorate"] = "1"
    assert read()["serviceChecks"][0]["state"] == "unknown"
    assert read(now + timedelta(hours=1))["reachability"]["state"] == "unknown"


def test_guest_disks_publish_storage_assignments_without_volume_paths(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    pve = {"at": now.isoformat(), "cluster": [],
           "nodes": [{"node": node, "status": "online"} for node in ("pve1", "pve2")],
           "guests": [{"vmid": 103, "node": "pve1", "type": "qemu", "status": "stopped"},
                      {"vmid": 105, "node": "pve1", "type": "lxc", "status": "running"},
                      {"vmid": 106, "node": "pve2", "type": "qemu", "status": "running"}],
           "configs": {"103": {"sata0": "zfs-vm-storage:private-volume-name,size=450G",
                                "scsi1": "file=main-zfs:private-volume-name,size=1.5T",
                                "ide2": "local:iso/private-image.iso,media=cdrom,size=9G",
                                "ide3": "local:vm-103-cloudinit,size=4M",
                                "unused0": "zfs-vm-storage:detached,size=10G",
                                "virtio0": "/dev/disk/by-id/private-device,size=2G"},
                       "105": {"rootfs": "volume=local-lvm:private-volume-name,size=8G",
                               "mp0": "/srv/private-path,mp=/private-directory",
                               "mp1": "local-lvm:private-volume-name,mp=/private-directory,size=bad"},
                       "106": {"scsi0": "zfs-vm-storage:private-volume-name,size=8G"}}}
    path = tmp_path / "infrastructure.json"
    graph = build_graph({}, {}, {}, pve, {}, now)
    raw = json.dumps(graph)
    assert "private-" not in raw
    path.write_text(raw, encoding="utf-8")

    def read(vmid, when=now):
        return next(node for node in load_infrastructure_map(path, when)["nodes"] if node["vmid"] == vmid)

    assert read(103)["guestStorage"] == {"checkedAt": now.isoformat(), "disks": [
        {"device": "sata0", "storage": "zfs-vm-storage", "sizeBytes": 450 * 2**30},
        {"device": "scsi1", "storage": "main-zfs", "sizeBytes": 1536 * 2**30},
    ]}
    assert read(105)["guestStorage"]["disks"] == [
        {"device": "rootfs", "storage": "local-lvm", "sizeBytes": 8 * 2**30},
        {"device": "mp1", "storage": "local-lvm"},
    ]
    public = load_infrastructure_map(path, now)
    cluster = next(node for node in public["nodes"] if node["id"] == public["clusterId"])
    assert cluster["storageAssignments"] == {"checkedAt": now.isoformat(), "hosts": [
        {"id": "pve1", "storages": [
            {"id": "local-lvm", "guestCount": 1, "diskCount": 2},
            {"id": "main-zfs", "guestCount": 1, "diskCount": 1},
            {"id": "zfs-vm-storage", "guestCount": 1, "diskCount": 1},
        ]},
        {"id": "pve2", "storages": [{"id": "zfs-vm-storage", "guestCount": 1, "diskCount": 1}]},
    ]}
    expired = load_infrastructure_map(path, now + timedelta(hours=1))
    assert "storageAssignments" not in next(node for node in expired["nodes"] if node["id"] == expired["clusterId"])
    assert "guestStorage" not in read(103, now + timedelta(hours=1))


def test_hypervisor_smart_checks_report_fresh_disk_health(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    pve = {"at": at, "cluster": [], "nodes": [{"node": "pve1", "status": "online"}], "guests": [],
           "disks": {"pve1": {"checkedAt": at, "disks": [
               {"device": "/dev/sda", "kind": "ssd", "smartState": "ok", "endurancePercent": 95,
                "sizeBytes": 2**40, "serial": "private serial"},
               {"device": "/dev/sdb", "kind": "hdd", "smartState": "critical", "endurancePercent": "N/A"},
           ]}}}
    snapshot = tmp_path / "map.json"
    snapshot.write_text(json.dumps(build_graph({}, {}, {}, pve, {}, now)), encoding="utf-8")
    assert "private serial" not in snapshot.read_text(encoding="utf-8")

    def node(when):
        return next(n for n in load_infrastructure_map(snapshot, when)["nodes"] if n["id"] == "pve1")

    current = node(now)
    assert current["reachability"]["state"] == "reachable" and current["mapStatus"] == "warn"
    assert current["hardwareDisks"]["disks"] == [
        {"device": "/dev/sda", "kind": "ssd", "smartState": "ok", "endurancePercent": 95, "sizeBytes": 2**40},
        {"device": "/dev/sdb", "kind": "hdd", "smartState": "critical"},
    ]
    assert "hardwareDisks" not in node(now + timedelta(hours=1))


def test_hypervisor_zfs_health_is_current_and_warns_on_degraded_pool(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    pool = {"name": "pool", "health": "DEGRADED", "sizeBytes": 100, "freeBytes": 30}
    pve = {"at": at, "cluster": [], "nodes": [{"node": "pve1", "status": "online"}], "guests": [],
           "zfs": {"pve1": {"checkedAt": at, "pools": [pool, {"name": "../private", "health": "ONLINE"}]}}}
    snapshot = tmp_path / "map.json"

    def node(when=now):
        snapshot.write_text(json.dumps(build_graph({}, {}, {}, pve, {}, now)), encoding="utf-8")
        assert "../private" not in snapshot.read_text(encoding="utf-8")
        return next(n for n in load_infrastructure_map(snapshot, when)["nodes"] if n["id"] == "pve1")

    current = node()
    assert current["reachability"]["state"] == "reachable" and current["mapStatus"] == "warn"
    assert current["zfsPools"] == {"checkedAt": at, "pools": [pool]}
    assert "zfsPools" not in node(now + timedelta(hours=1))
    pool["health"] = "ONLINE"
    assert node()["mapStatus"] == "ok"
    pool["freeBytes"] = 101
    assert "freeBytes" not in node()["zfsPools"]["pools"][0]


def test_lvm_thin_capacity_warns_for_either_dimension(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    pool = {"volumeGroup": "pve", "name": "data", "sizeBytes": 100, "usedBytes": 30,
            "metadataSizeBytes": 100, "metadataUsedBytes": 90}
    pve = {"at": at, "cluster": [], "nodes": [{"node": "pve1", "status": "online"}], "guests": [],
           "lvmThin": {"pve1": {"checkedAt": at, "pools": [pool]}}}
    path = tmp_path / "map.json"

    def read(when=now):
        path.write_text(json.dumps(build_graph({}, {}, {}, pve, {}, now)), encoding="utf-8")
        return next(n for n in load_infrastructure_map(path, when)["nodes"] if n["id"] == "pve1")

    assert read()["mapStatus"] == "warn"
    assert read()["lvmThinPools"]["pools"][0] == {**pool, "capacityStatus": "warn"}
    pool.update(usedBytes=100, metadataUsedBytes=1)
    assert read()["mapStatus"] == "warn"
    pool["usedBytes"] = 5
    assert read()["lvmThinPools"]["pools"][0]["capacityStatus"] == "ok"
    pool["metadataUsedBytes"] = 101
    assert read()["lvmThinPools"]["pools"][0]["capacityStatus"] == "unknown"
    assert "lvmThinPools" not in read(now + timedelta(hours=1))


def test_hypervisor_resources_require_current_online_node_data(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    path = tmp_path / "infrastructure.json"
    node = {"node": "pve1", "status": "online", "cpu": 0.0, "maxcpu": 72, "mem": 512,
            "maxmem": 1024, "disk": 0, "maxdisk": 4096, "uptime": 30}

    def read(when=now):
        graph = build_graph({}, {}, {}, {"at": now.isoformat(), "cluster": [], "nodes": [node], "guests": []}, {}, now)
        path.write_text(json.dumps(graph), encoding="utf-8")
        return next(n for n in load_infrastructure_map(path, when)["nodes"] if n["id"] == "pve1")

    assert read()["resources"] == {"checkedAt": now.isoformat(), "cpuRatio": 0.0, "logicalCpus": 72,
                                    "memoryUsedBytes": 512, "memoryTotalBytes": 1024,
                                    "rootUsedBytes": 0, "rootTotalBytes": 4096, "uptimeSeconds": 30}
    assert "resources" not in read(now + timedelta(hours=1))
    node.update(status="offline")
    assert "resources" not in read()
    node.update(status="online", cpu=True, mem=1025, disk=-1, maxcpu="72", uptime=None)
    assert "resources" not in read()
    node["cpu"] = 0.42
    assert read()["resources"] == {"checkedAt": now.isoformat(), "cpuRatio": 0.42}


def test_backup_state_requires_a_valid_watchdog_report(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    target = {"role": "acti_backup", "status": "critical", "observed_at": now.isoformat(), "checks": []}
    path = tmp_path / "infrastructure.json"

    def read(watchdog, snapshot, capacity="ok", freshness="current"):
        target["checks"] = [{"name": name, "status": status} for name, status in (
            ("watchdog_fresh", watchdog), ("backup_snapshot_fresh", snapshot), ("repository_capacity", capacity),
        ) if status is not None]
        graph = build_graph({}, {}, {"freshness": freshness, "targets": [target]}, {}, {}, now)
        path.write_text(json.dumps(graph), encoding="utf-8")
        node, = load_infrastructure_map(path, now)["nodes"]
        return node

    node = read("critical", "critical", "critical")
    assert node["mapStatus"] == "unknown"
    assert [(check["label"], check["status"]) for check in node["checks"]] == [
        ("Свежесть отчёта watchdog", "critical"), ("Свежесть резервной копии", "unknown"),
        ("Ёмкость хранилища копий", "unknown"),
    ]
    assert read(None, "critical")["mapStatus"] == "unknown"
    assert read("ok", "critical")["mapStatus"] == "critical"
    assert read("ok", "ok", capacity="critical")["mapStatus"] == "ok"
    assert read("ok", "critical", freshness="stale")["mapStatus"] == "unknown"


def test_acti_service_reflects_backup_dependency_on_inventory_host(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    stamp = now.isoformat()
    report = {"freshness": "current", "targets": [
        {"role": "acti_backup", "status": "critical", "observed_at": stamp,
         "checks": [{"name": "watchdog_fresh", "status": "ok"},
                    {"name": "backup_snapshot_fresh", "status": "critical"}]},
        {"role": "acti", "status": "ok", "observed_at": stamp,
         "checks": [{"name": "https_ready", "status": "ok"}]},
    ]}
    context = {"devices": [{"id": "fileserver", "name": "File server", "kind": "server"},
                           {"id": "acti-vm", "name": "ACTI VM", "kind": "server",
                            "management_ip": "192.0.2.45"}]}
    network = {"hosts": [{"ip": "192.0.2.45", "availability": {
        "checked_at": stamp, "run_status": "success", "state": "online",
        "reason": "active_probe", "active_method": "icmp",
    }}]}
    bindings = {"roles": {"acti": {"asset": "acti-vm"},
                          "acti_backup": {"asset": "fileserver", "used_by": ["role:acti"]}}}
    path = tmp_path / "infrastructure.json"

    def read():
        graph = build_graph(context, network, report, {}, bindings, now)
        path.write_text(json.dumps(graph), encoding="utf-8")
        public = load_infrastructure_map(path, now)
        return {n["id"]: n for n in public["nodes"]}, public["links"]

    nodes, links = read()
    assert any(l["a"] == "role:acti" and l["b"] == "role:acti_backup"
               and l["kind"] == "Зависимость сервиса" and l["confirmed"] for l in links)
    assert nodes["role:acti"]["reachability"]["state"] == "reachable"
    assert nodes["role:acti"]["mapStatus"] == nodes["acti-vm"]["mapStatus"] == "warn"
    assert nodes["role:acti"]["serviceAvailability"]["unavailable"] == ["role:acti_backup"]
    report["targets"][0]["checks"][1]["status"] = "ok"
    assert read()[0]["acti-vm"]["mapStatus"] == "ok"
    report["targets"][0]["checks"][0]["status"] = "critical"
    assert read()[0]["acti-vm"]["mapStatus"] == "unknown"
    context["devices"].pop(0)
    assert read()[0]["acti-vm"]["mapStatus"] == "ok"


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


def test_http_probe_matches_json_health_fields_without_fixing_the_version():
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from threading import Thread
    from app.infrastructure_service_probes import _probe

    responses = {
        "/ready": (200, b'{"version": "2", "database": "ok", "service": "example", "status": "ok"}'),
        "/wrong": (200, b'{"status":"ok","service":"example","database":"down"}'),
        "/reported-down": (200, b'{"status":"DOWN","service":"example"}'),
        "/invalid": (200, b"not json"),
        "/large": (200, b'{"status":"ok","service":"example","database":"ok"}' + b" " * 32768),
        "/down": (503, b'{"status":"unavailable"}'),
    }

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            status, body = responses[self.path]
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        worker = Thread(target=server.serve_forever)
        worker.start()
        try:
            base = {"type": "http", "ip": "127.0.0.1", "port": server.server_port,
                    "json_fields": {"status": "ok", "database": "ok", "service": "example"},
                    "json_unavailable": {"status": "DOWN", "service": "example"}}
            results = [_probe({**base, "path": path}) for path in responses]
        finally:
            server.shutdown()
            worker.join()
    assert results == ["reachable", "unknown", "unreachable", "unknown", "unknown", "unreachable"]


def test_dns_probe_requires_an_answer_to_the_actual_query(monkeypatch):
    import dns.message
    import dns.rrset

    from app import infrastructure_service_probes as probes

    spec = {"type": "dns", "ip": "192.0.2.53", "port": 53, "name": "service.example.", "record": "A"}

    def check(*answers):
        def reply(query, *args, **kwargs):
            response = dns.message.make_response(query)
            response.answer.extend(dns.rrset.from_text(owner, 60, "IN", kind, *records)
                                   for owner, kind, records in answers)
            return dns.message.from_wire(response.to_wire()), False

        monkeypatch.setattr(probes.dns.query, "udp_with_fallback", reply)
        return probes._probe(spec)

    assert check(("unrelated.example.", "A", ["192.0.2.10"])) == "unreachable"
    alias = ("service.example.", "CNAME", ["host.example."])
    assert check(alias, ("host.example.", "A", ["192.0.2.11"])) == "reachable"

    spec["expected_addresses"] = ["192.0.2.10", "192.0.2.11"]
    assert check(alias, ("host.example.", "A", ["192.0.2.11"])) == "unreachable"
    assert check(alias, ("host.example.", "A", ["192.0.2.11", "192.0.2.10"])) == "reachable"
    assert check(alias, ("host.example.", "A", ["192.0.2.11", "192.0.2.10", "192.0.2.12"])) == "unreachable"
    spec["expected_addresses"] = ["2001:db8::10"]
    assert check(alias, ("host.example.", "A", ["192.0.2.10"])) == "unknown"


def test_https_probe_checks_dns_name_against_ca_while_connecting_to_verified_ip(monkeypatch, tmp_path):
    from contextlib import nullcontext
    from types import SimpleNamespace
    from app import infrastructure_service_probes as probes

    name = "service.example.test"
    ip = "192.0.2.15"
    ca = str(tmp_path / "ca.pem")
    raw, secured = object(), object()
    events = []

    class Context:
        def wrap_socket(self, transport, *, server_hostname):
            assert transport is raw
            events.append(("tls", server_hostname))
            if server_hostname != name:
                raise probes.ssl.SSLCertVerificationError("hostname mismatch")
            return secured

    class Connection:
        def __init__(self, host, port, *, timeout, context):
            self.host = host
            assert port == 443
            assert isinstance(context, Context)

        def request(self, method, path, headers):
            assert self.sock is secured
            events.append((self.host, method, path))

        def getresponse(self):
            return SimpleNamespace(status=200, getheader=lambda *_: "text/plain", read=lambda _: b"ready")

        def close(self):
            pass

    def connect(address, *, timeout):
        events.append(("tcp", address))
        return nullcontext(raw)

    def trust(*, cafile):
        assert cafile == ca
        return Context()

    monkeypatch.setattr(probes.socket, "create_connection", connect)
    monkeypatch.setattr(probes.ssl, "create_default_context", trust)
    monkeypatch.setattr(probes.http.client, "HTTPSConnection", Connection)
    spec = {"type": "https", "ip": ip, "port": 443, "path": "/ready", "body": "ready",
            "tls_server_name": name, "tls_ca_file": ca}
    assert probes._probe(spec) == "reachable"
    assert events == [("tcp", (ip, 443)), ("tls", name), (name, "GET", "/ready")]
    events.clear()
    assert probes._probe({**spec, "tls_server_name": "wrong.example.test"}) == "unknown"
    assert events == [("tcp", (ip, 443)), ("tls", "wrong.example.test")]
    events.clear()
    assert probes._probe({**spec, "tls_sha256": "0" * 64}) == "unknown"
    assert not events


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


def test_postgresql_probe_requires_protocol_response(monkeypatch):
    from app import infrastructure_service_probes as probes

    class Connection:
        response = b"S"

        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def sendall(self, payload):
            assert payload.hex() == "0000000804d2162f"

        def recv(self, size):
            assert size == 1
            return self.response

    connection = Connection()
    monkeypatch.setattr(probes.socket, "create_connection", lambda *_args, **_kwargs: connection)
    spec = {"type": "postgresql", "ip": "192.0.2.27", "port": 5432}
    assert probes._probe(spec) == "reachable"
    connection.response = b"N"
    assert probes._probe(spec) == "reachable"
    connection.response = b"H"
    assert probes._probe(spec) == "unreachable"


def test_observer_service_attaches_to_the_vm_with_the_expected_mac():
    from app.infrastructure_collect import build_graph

    now = datetime.now(timezone.utc)
    mac = "02:00:00:00:00:03"
    pve = {"at": now.isoformat(), "cluster": [], "nodes": [],
           "guests": [{"vmid": 211, "node": "pve2", "type": "qemu", "status": "running"}],
           "configs": {"211": {"net0": f"virtio={mac},bridge=vmbr1"}}}
    bindings = {"roles": {"nextcloud": {"label": "Nextcloud", "vmid": 211, "mac": mac}}}
    server = {"freshness": "current", "targets": [{"role": "nextcloud", "status": "ok",
              "observed_at": now.isoformat(), "checks": [{"name": "nextcloud_status", "status": "ok"}]}]}

    def load(at=now):
        graph = build_graph({}, {}, server, pve, bindings, at)
        item, = [n for n in graph["nodes"] if n["id"] == "role:nextcloud"]
        links = [e for e in graph["links"] if e["b"] == item["id"]]
        return item, links

    item, links = load()
    assert item["reachability"]["source"] == "Server Observer"
    assert [(e["a"], e["source"], e["confirmed"]) for e in links] == [("pve-guest:211", "Proxmox", True)]
    assert load(now + timedelta(hours=1))[1] == []
    pve["configs"]["211"]["net0"] = "virtio=02:00:00:00:00:04,bridge=vmbr1"
    assert load()[1] == []


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
               "guest_services": {"zabbix-api": {"label": "Zabbix API", "vmid": 108, "mac": mac,
                                                "used_by": ["consumer"]}}}
    context = {"services": [{"id": "consumer", "name": "Consumer"}]}
    configured = {"zabbix-api": [{"ip": address, "port": 80, "type": "zabbix_api"}]}
    monkeypatch.setattr(probes, "_probe", lambda spec: "reachable")

    def build():
        graph = build_graph(context, network, {}, pve, binding, now)
        probes.apply_service_probes(graph["nodes"], configured)
        return graph, next(n for n in graph["nodes"] if n["id"] == "zabbix-api")

    graph, service = build()
    assert service["reachability"]["state"] == "reachable"
    assert any(e["a"] == "pve-guest:108" and e["b"] == "zabbix-api" and e["confirmed"] for e in graph["links"])
    assert any(e["a"] == "consumer" and e["b"] == "zabbix-api" and e["confirmed"]
               and e["kind"] == "Зависимость сервиса" for e in graph["links"])
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


def test_fdb_only_topology_does_not_create_or_confirm_physical_links():
    from app.infrastructure_collect import build_graph

    now = datetime.now(timezone.utc)
    context = {"devices": [{"id": key, "name": key, "kind": "switch"} for key in ("core", "access", "remote")],
               "links": [{"relation": "connected_to", "state": {"verified": False},
                          "endpoint_a": {"device": "core", "interface": "ge5"},
                          "endpoint_b": {"device": "access", "interface": "Port1"}}]}
    sources = [{"id": i, "name": key, "driver": "snmp_switch", "driver_options": {"intent_stable_id": key}}
               for i, key in enumerate(("core", "access", "remote"), 1)]
    network = {"sources": sources, "links": [{"source_a_id": 1, "source_b_id": peer, "state": "confirmed",
                "evidence": [{"evidence_type": "fdb_management_mac", "observed_at": now.isoformat(),
                              "endpoint_a": {"source_id": 1, "port_key": "ge5"},
                              "endpoint_b": {"source_id": peer}}]} for peer in (2, 3)]}
    links = {edge["b"]: edge for edge in build_graph(context, network, {}, {}, {}, now)["links"]}
    assert links["access"]["kind"] == "Сетевое соединение" and not links["access"]["confirmed"]
    assert all(not p["confirmed"] for p in links["access"]["portEvidence"])
    assert links["remote"]["kind"] == "Путь по MAC-таблице" and not links["remote"]["confirmed"]
    assert links["remote"]["portEvidence"][0]["a"] == "ge5"


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
    assert [(p["a"], p["confirmed"]) for p in links["router"]["portEvidence"]] == [("ge24", True), ("ge23", False)]
    assert links["other"]["kind"] == "Путь по MAC-таблице"
    assert not links["other"]["confirmed"]
    assert not links["other"]["portEvidence"][0]["confirmed"]


def test_map_reports_port_state_for_declared_pair_without_confirming_cable(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    context = {"devices": [{"id": key, "name": key, "kind": "switch"} for key in ("core", "access")],
               "links": [{"relation": "connected_to", "state": {"verified": False},
                          "endpoint_a": {"device": "core", "interface": "Gi1/0/18"},
                          "endpoint_b": {"device": "access", "interface": "Port5"}}]}
    sources = [{"id": i, "name": key, "driver": "snmp_switch", "driver_options": {"intent_stable_id": key}}
               for i, key in enumerate(("core", "access"), 1)]
    ports = [
        {"source": "core", "port_key": "ifindex:49170", "name": "gigabitEthernet 1/0/18",
         "oper_status": "up", "last_seen_at": at},
        {"source": "access", "port_key": "physical:5", "name": "p5_uplink_IT_TP",
         "oper_status": "down", "last_seen_at": at},
    ]
    path = tmp_path / "graph.json"

    def load(when=now):
        graph = build_graph(context, {"sources": sources, "ports": ports}, {}, {}, {}, now)
        path.write_text(json.dumps(graph), encoding="utf-8")
        link, = load_infrastructure_map(path, when)["links"]
        report, = link["portEvidence"]
        assert not link["confirmed"] and not report["confirmed"]
        return report.get("portStates", {})

    assert load() == {
        "a": {"name": "gigabitEthernet 1/0/18", "state": "up", "checkedAt": at, "speedBps": None, "stale": False},
        "b": {"name": "p5_uplink_IT_TP", "state": "down", "checkedAt": at, "speedBps": None, "stale": False},
    }
    assert not load(now + timedelta(hours=1))
    ports.append({**ports[0], "port_key": "ifindex:42", "name": "Gi1/0/18"})
    assert set(load()) == {"b"}


def test_reciprocal_switch_management_macs_verify_path_without_proving_direct_link(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    context = {"devices": [{"id": key, "name": key, "kind": "switch"} for key in ("core", "access")],
               "links": [{"relation": "connected_to", "state": {"verified": False},
                          "endpoint_a": {"device": "core", "interface": "Gi1/0/18"},
                          "endpoint_b": {"device": "access", "interface": "Port5"}}]}
    sources = [{"id": i, "name": key, "driver": "snmp_switch", "driver_options": {"intent_stable_id": key}}
               for i, key in enumerate(("core", "access"), 1)]
    ports = [
        {"source": "core", "port_key": "ifindex:49170", "name": "gigabitEthernet 1/0/18",
         "oper_status": "up", "last_seen_at": at},
        {"source": "access", "port_key": "physical:5", "name": "p5_uplink_IT_TP",
         "oper_status": "up", "last_seen_at": at},
    ]
    sightings = [
        {"source_id": 1, "peer_source_id": 2, "port_key": "ifindex:49170", "observed_at": at},
        {"source_id": 2, "peer_source_id": 1, "port_key": "physical:5", "observed_at": at},
    ]

    def paths(when=now):
        graph = build_graph(context, {"sources": sources, "ports": ports, "switch_management_fdb": sightings},
                            {}, {}, {}, now)
        path = tmp_path / "snapshot.json"
        path.write_text(json.dumps(graph), encoding="utf-8")
        graph = load_infrastructure_map(path, when)
        assert not next(e for e in graph["links"] if e["kind"] == "Сетевое соединение")["confirmed"]
        access = next(node for node in graph["nodes"] if node["id"] == "access")
        assert access["ports"][0]["aliases"] == ["Port5"]
        return [e for e in graph["links"] if e["kind"] == "Путь по MAC-таблице"]

    path, = paths()
    assert path["confirmed"]
    assert [(p["a"], p["b"], p["at"]) for p in path["portEvidence"]] == [
        ("gigabitEthernet 1/0/18", "p5_uplink_IT_TP", at),
    ]
    expired, = paths(now + timedelta(hours=1))
    assert not expired["confirmed"] and not expired["portEvidence"][0]["confirmed"]
    sightings.append({**sightings[0], "port_key": "ifindex:999"})
    assert not paths()
    sightings.pop()
    sightings[1]["observed_at"] = (now - timedelta(hours=1)).isoformat()
    assert not paths()
    sightings[1]["observed_at"] = at
    ports[1]["oper_status"] = "down"
    assert not paths()


def test_verified_switch_ports_require_fresh_bidirectional_fdb_and_live_ports(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    earlier = (now - timedelta(minutes=1)).isoformat()
    devices = [{"id": key, "name": key, "kind": "switch"} for key in ("core", "access", "other")]
    declared = {"relation": "connected_to", "state": {"verified": True},
                "endpoint_a": {"device": "core", "interface": "ge22"},
                "endpoint_b": {"device": "access", "interface": "Port24"}}
    sources = [{"id": i, "name": key, "driver": "snmp_switch", "driver_options": {"intent_stable_id": key}}
               for i, key in enumerate(("core", "access"), 1)]
    ports = [{"source": source, "port_key": name, "name": name, "oper_status": "up", "last_seen_at": at}
             for source, name in (("core", "ge22"), ("access", "Port24"))]
    one_way = {"evidence_type": "fdb_management_mac", "endpoint_a": {"source_id": 1, "port_key": "ge22"},
               "endpoint_b": {"source_id": 2}, "observed_at": at}
    reverse = {"evidence_type": "fdb_management_mac", "endpoint_a": {"source_id": 1},
               "endpoint_b": {"source_id": 2, "port_key": "Port24"}, "observed_at": earlier}
    evidence = [one_way, reverse]
    network = {"sources": sources, "ports": ports, "links": [
        {"source_a_id": 1, "source_b_id": 2, "state": "confirmed", "evidence": evidence},
    ]}
    path = tmp_path / "graph.json"

    def paired(when=now):
        graph = build_graph({"devices": devices, "links": [declared]}, network, {}, {}, {}, when)
        path.write_text(json.dumps(graph), encoding="utf-8")
        link = next(edge for edge in load_infrastructure_map(path, when)["links"] if {edge["a"], edge["b"]} == {"core", "access"})
        return [p for p in link["portEvidence"] if p["source"] == "SNMP · двусторонний FDB"]

    report, = paired()
    assert {key: report[key] for key in ("a", "b", "at", "confirmed")} == {
        "a": "ge22", "b": "Port24", "at": earlier, "confirmed": True,
    }
    assert {side: port["state"] for side, port in report["portStates"].items()} == {"a": "up", "b": "up"}
    assert not paired(now + timedelta(hours=1))
    evidence.pop()
    assert not paired()
    evidence.append(reverse)
    evidence.append({**one_way, "endpoint_a": {"source_id": 1, "port_key": "ge23"}})
    assert not paired()
    evidence.pop()
    ports[1]["oper_status"] = "down"
    assert not paired()
    ports[1]["oper_status"] = "up"
    network["lldp"] = [{"source": "core", "local_port_key": "ge22", "system_name": "other",
                        "port_id": "ether1", "port_id_subtype": "interface_name", "observed_at": at}]
    assert not paired()


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


def test_shared_lldp_ports_publish_paths_and_require_live_port_and_unique_chassis(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    first, second, unexpected = (f"02:00:00:00:00:0{i}" for i in (1, 2, 3))
    context = {"devices": [{"id": "switch", "name": "switch", "kind": "switch"},
                           {"id": "one", "name": "one", "kind": "router", "mac_addresses": [first]},
                           {"id": "two", "name": "two", "kind": "router", "mac_addresses": [second]}],
               "links": [{"relation": "connected_to", "state": {"verified": False,
                          "observed": "lldp_neighbor_on_shared_or_intermediate_l2_path"},
                          "endpoint_a": {"device": "switch", "interface": "Gi1/0/48"},
                          "endpoint_b": {"device": "one", "interface": "bridge/ether3"}}]}
    port = {"source": "switch", "port_key": "ifindex:48", "name": "gigabitEthernet 1/0/48",
            "oper_status": "up", "last_seen_at": at}
    rows = [{"source": "switch", "system_name": name, "local_port_key": "ifindex:48",
             "chassis_id": chassis, "port_id": "bridge/ether3", "port_id_subtype": "interface_name",
             "observed_at": at} for name, chassis in (("one", first), ("two", unexpected))]
    network = {"sources": [{"id": 1, "name": "switch", "driver": "snmp_switch",
                            "driver_options": {"intent_stable_id": "switch"}}], "ports": [port], "lldp": rows}
    path = tmp_path / "snapshot.json"

    def read(when=now):
        graph = build_graph(context, network, {}, {}, {}, now)
        path.write_text(json.dumps(graph), encoding="utf-8")
        return {e["b"]: e for e in load_infrastructure_map(path, when)["links"] if e["a"] == "switch"}

    links = read()
    assert all(e["kind"] == "Путь через общий порт" for e in links.values())
    assert links["one"]["confirmed"] and not links["two"]["confirmed"]
    proof = next(p for p in links["one"]["portEvidence"] if p["confirmed"])
    assert (proof["a"], proof["b"], proof["portStates"]["a"]["state"]) == ("gigabitEthernet 1/0/48", "", "up")
    assert not read(now + timedelta(hours=1))["one"]["confirmed"]
    address = "192.0.2.22"
    rows[1]["management_addresses"] = [address]
    network["arp"] = [{"ip": address, "mac": unexpected, "last_seen_at": at}]
    network["hosts"] = [{"ip": address, "mac": unexpected, "last_seen_at": at}]
    neighbors = [{"identity": "two", "address": address, "mac": unexpected, "last_seen_at": at}]
    network["router_neighbors"] = neighbors
    assert read()["two"]["confirmed"]
    neighbors[0]["last_seen_at"] = (now - timedelta(hours=1)).isoformat()
    assert not read()["two"]["confirmed"]
    neighbors[0]["last_seen_at"] = at
    neighbors.append({**neighbors[0], "mac": first})
    assert not read()["two"]["confirmed"]
    neighbors.pop()
    context["devices"][1]["management_ip"] = address
    assert not read()["two"]["confirmed"]
    context["devices"][1].pop("management_ip")
    rows.append({**rows[0], "local_port_key": "ifindex:47"})
    assert not read()["one"]["confirmed"]
    rows.pop()
    rows.pop()
    assert read()["one"]["kind"] == "Путь через общий порт"
    port["oper_status"] = "down"
    assert not read()["one"]["confirmed"]


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


def test_matching_fdb_attachment_adds_evidence_and_supplemental_ip_check(monkeypatch, tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map
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
               "ports": [{"source": "css", "port_key": "Port7", "name": "Port7",
                          "oper_status": "up", "last_seen_at": at}],
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
    snapshot = tmp_path / "map.json"
    snapshot.write_text(json.dumps(graph), encoding="utf-8")
    public = load_infrastructure_map(snapshot, datetime.now(timezone.utc))
    assert public["links"][0]["portEvidence"][-1]["portStates"]["b"]["state"] == "up"
    endpoint = next(node for node in public["nodes"] if node["id"] == "pc")
    assert endpoint["mapStatus"] == "unknown"
    assert endpoint["serviceChecks"][0]["reason"] == "icmp_identity_unconfirmed"
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

    layer2 = {"state": "reachable", "source": "router", "method": "MAC ping · L2", "checkedAt": at}
    network["asset_mac_checks"] = {"remote": layer2}
    graph = build_graph(context, network, {}, {}, {}, now)
    remote = next(node for node in graph["nodes"] if node["id"] == "remote")
    assert remote["properties"]["Адрес управления по LLDP"] == address
    assert remote["reachability"]["method"] == "ICMP"
    assert remote["serviceChecks"] == [layer2]
    host["availability"] = {}
    graph = build_graph(context, network, {}, {}, {}, now)
    remote = next(node for node in graph["nodes"] if node["id"] == "remote")
    assert remote["properties"]["Адрес управления по LLDP"] == address
    assert remote["reachability"] == layer2
    host["availability"] = available
    del network["asset_mac_checks"]

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
    from app.infrastructure_map import _public_service_check

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

    def check(response):
        connection.response = response
        node = {"id": "vpn", "kind": "Сервис"}
        probes.apply_service_probes([node], {"vpn": [spec]})
        raw, = node["serviceChecks"]
        return _public_service_check(raw, datetime.now(timezone.utc))

    observed = check(ready + header + client + b"CLIENT_LIST\tprivate-second\nEND\n")
    assert observed["method"] == "OpenVPN Management"
    assert observed["port"] is None and observed["configuredPort"] == 1194
    assert observed["sessionCount"] == 2 and observed["daemonReady"] is True
    assert "sample" not in json.dumps(observed) and "private-second" not in json.dumps(observed)
    empty = check(ready + header + b"END\n")
    assert empty["state"] == "unknown" and empty["sessionCount"] == 0 and empty["daemonReady"] is True
    assert "sessionCount" not in check(ready + header + client)


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


def test_running_vm_is_unreachable_when_every_configured_adapter_is_disconnected(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    mac = "02:00:00:00:00:03"
    disconnected = f"virtio={mac},bridge=vmbr1,link_down=1"
    pve = {
        "at": now.isoformat(), "cluster": [], "nodes": [{"node": "pve1", "status": "online"}],
        "guests": [{"vmid": 122, "node": "pve1", "type": "qemu", "status": "running"}],
        "configs": {"122": {"net0": disconnected, "directNetworkOnly": True}},
    }
    network = {"hosts": [{"mac": mac, "availability": {
        "checked_at": now.isoformat(), "run_status": "success", "state": "online",
        "reason": "active_probe", "active_method": "icmp",
    }}]}
    path = tmp_path / "graph.json"

    def load(at=now):
        graph = build_graph({}, network, {}, pve, {}, at)
        path.write_text(json.dumps(graph), encoding="utf-8")
        return next(node for node in load_infrastructure_map(path, at)["nodes"] if node["vmid"] == 122)

    node = load()
    assert node["properties"]["Состояние ВМ"] == "Запущена"
    assert node["mapStatus"] == "critical"
    assert node["reachability"]["source"] == "Proxmox"
    assert node["reachability"]["method"] == "Все адаптеры ВМ отключены"
    config = pve["configs"]["122"]
    config["net1"] = "virtio=02:00:00:00:00:04"
    assert load()["mapStatus"] == "unknown"
    del config["net1"]
    del config["directNetworkOnly"]
    assert load()["mapStatus"] == "unknown"
    config["directNetworkOnly"] = True
    assert load(now + timedelta(hours=1))["mapStatus"] == "unknown"
    config.clear()
    assert load()["mapStatus"] == "unknown"


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

    def guest_uplink(vmid, rendered_at=now):
        graph = build_graph(context, network, {}, pve, {}, now)
        path.write_text(json.dumps(graph), encoding="utf-8")
        link = next(edge for edge in load_infrastructure_map(path, rendered_at)["links"]
                    if edge["b"] == f"pve-guest:{vmid}")
        return link["portEvidence"][0]["virtual"].get("switchUplink")

    assert switch_ports(now) == [{"id": "sw", "port": "xe3", "vlan": 1, "at": at}]
    assert physical_ports() == [("xe3", "ens7f1np1")]
    pve["guests"].append({**pve["guests"][0], "vmid": 104})
    pve["configs"]["104"] = {"net0": "virtio=02:00:00:00:00:04,bridge=vmbr1"}
    assert guest_uplink(103) is None
    assert guest_uplink(104) == {"id": "sw", "port": "xe3", "at": at}
    pve["guests"][1]["status"] = "stopped"
    assert guest_uplink(104) == {"id": "sw", "port": "xe3", "at": at, "configuredOnly": True}
    pve["guests"][1]["status"] = "running"
    assert guest_uplink(104, now + timedelta(hours=1)) is None
    context["devices"].append({"id": "other", "name": "Other", "kind": "router"})
    network["lldp"] = [{"source": "switch-source", "local_port_key": "index:3",
                        "system_name": "Other", "observed_at": at}]
    assert guest_uplink(104) is None
    del network["lldp"]
    pve["configs"]["104"]["net0"] += ",link_down=1"
    assert guest_uplink(104) == {"id": "sw", "port": "xe3", "at": at, "configuredOnly": True}
    pve["configs"]["104"]["net0"] = pve["configs"]["104"]["net0"].removesuffix(",link_down=1")
    pve["activePorts"]["pve1"] = []
    assert physical_ports() == []
    assert guest_uplink(104) is None
    pve["activePorts"]["pve1"] = ["ens7f1np1"]
    pve["bridges"]["pve1"]["vmbr1"]["bridge_ports"] += " ens7f0np0"
    assert physical_ports() == []
    assert guest_uplink(104) is None
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


def test_ipsec_phase_two_requires_expected_peers_and_both_policy_directions():
    from app.infrastructure_collect import build_graph

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    local, remote = "192.0.2.0/24", "198.51.100.0/24"
    feature = {"id": "office-tunnel", "kind": "policy_based_ipsec", "local_device": "left", "remote_device": "right",
               "central_peer": {"name": "office"}, "remote_peer": {"name": "main"}, "policy_destinations": [local]}
    context = {"devices": [{"id": name, "name": name, "kind": "router"} for name in ("left", "right")],
               "features": [feature], "segments": [{"id": "office-lan", "cidr": remote}]}
    binding = {"ipsec_links": {"office-tunnel": {"label": "IPsec", "local_source": "local-router",
               "remote_source": "remote-router", "remote_segment": "office-lan"}}}
    policy = {"action": "encrypt", "tunnel": True, "established": True}
    reply = {**policy, "peer": "main", "src_address": remote, "dst_address": local}
    network = {"sources": [
        {"name": "local-router", "driver": "mikrotik_api", "driver_options": {"intent_stable_id": "left"}},
        {"name": "remote-router", "driver": "mikrotik_api", "driver_options": {"intent_stable_id": "right"}},
    ], "ipsec": {
        "local-router": {"at": at, "policies": [{**policy, "peer": "office", "src_address": local, "dst_address": remote}]},
        "remote-router": {"at": at, "policies": [reply]},
    }}

    def build():
        graph = build_graph(context, network, {}, {}, binding, now)
        node = next(n for n in graph["nodes"] if n["id"] == "ipsec:office-tunnel")
        return graph, node["reachability"]["state"]

    graph, state = build()
    assert state == "reachable"
    assert {e["a"] for e in graph["links"] if e["b"] == "ipsec:office-tunnel" and e["confirmed"]} == {"left", "right"}
    reply["peer"] = "another-peer"
    assert build()[1] == "unreachable"
    network["ipsec"].pop("remote-router")
    assert build()[1] == "unknown"


def test_ipsec_path_checks_explicit_sources_in_both_directions(monkeypatch):
    from app import infrastructure_collect as collector

    now = datetime.now(timezone.utc)
    context = {"devices": [
        {"id": "ui", "name": "UI", "kind": "server", "management_ip": "192.0.2.30"},
        {"id": "left", "name": "Central", "kind": "router"},
        {"id": "right", "name": "Branch", "kind": "router", "management_ip": "198.51.100.1"},
    ], "features": [
        {"id": "office", "kind": "policy_based_ipsec", "local_device": "left", "remote_device": "right",
         "policy_destinations": ["192.0.2.0/24"], "central_peer": {"name": "branch"}, "remote_peer": {"name": "central"}},
    ], "segments": [{"id": "branch-lan", "cidr": "198.51.100.0/24"}]}
    configured = {"office": {"label": "IPsec phase 2", "local_source": "center", "remote_source": "branch",
                              "remote_segment": "branch-lan", "connectivity": {"asset": "ui", "label": "ICMP link"}}}
    sources = [
        {"name": "center", "driver": "mikrotik_api", "enabled": True, "driver_options": {"intent_stable_id": "left"}},
        {"name": "branch", "driver": "mikrotik_ssh", "enabled": True, "host": "198.51.100.1",
         "driver_options": {"intent_stable_id": "right"}},
    ]
    calls = []
    class Remote:
        def ping_ipv4(self, address, source):
            calls.append(("branch", address, source))
            return True

    monkeypatch.setattr(collector, "legacy_driver_for", lambda *_: Remote())
    monkeypatch.setattr(collector, "load_secrets", lambda: {})
    monkeypatch.setattr(collector, "probe_icmp", lambda address, *, source_ip: calls.append(("ui", address, source_ip)) or True)
    observations = collector._collect_ipsec_connectivity(context, sources, configured)
    assert calls == [("ui", "198.51.100.1", "192.0.2.30"), ("branch", "192.0.2.30", "198.51.100.1")]
    graph = collector.build_graph(context, {"sources": sources, "ipsec_connectivity": observations},
                                  {}, {}, {"ipsec_links": configured}, datetime.now(timezone.utc))
    path = next(n for n in graph["nodes"] if n["id"] == "ipsec:office:connectivity")
    assert path["reachability"]["state"] == "reachable"
    assert [c["target"] for c in path["serviceChecks"]] == ["198.51.100.1", "192.0.2.30"]
    phase = next(n for n in graph["nodes"] if n["id"] == "ipsec:office")
    assert phase["reachability"]["state"] == "unknown"
    context["devices"][0]["management_ip"] = "203.0.113.30"
    assert collector._collect_ipsec_connectivity(context, sources, configured) == {}
    assert len(calls) == 2


def test_routeros_ping_uses_one_packet_and_rejects_injected_addresses(monkeypatch):
    from types import SimpleNamespace
    import pytest
    from netctl.drivers import mikrotik_ssh

    calls = []
    def run(args, **kwargs):
        calls.append(args[-1])
        return SimpleNamespace(returncode=0, stdout="sent=1 received=1 packet-loss=0%")

    monkeypatch.setattr(mikrotik_ssh.subprocess, "run", run)
    driver = mikrotik_ssh.MikroTikSshDriver({"host": "198.51.100.1", "username": "observer"}, {})
    assert driver.ping_ipv4("192.0.2.30", "198.51.100.1")
    with pytest.raises(ValueError):
        driver.ping_ipv4("192.0.2.30 count=100", "198.51.100.1")
    assert calls == ["/ping address=192.0.2.30 src-address=198.51.100.1 count=1"]


def test_transit_port_requires_direct_route_running_ethernet_and_neighbor_arp():
    from app.infrastructure_collect import build_graph

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    context = {"devices": [{"id": name, "name": name, "kind": "router"} for name in ("rb", "coordinator")],
               "segments": [{"id": "transit", "cidr": "192.0.2.0/30", "local_address": "192.0.2.1", "gateway_device": "rb"}]}
    binding = {"transit_links": {"transit": {"asset": "coordinator", "source": "main",
                                              "peer": "192.0.2.2", "label": "Transit"}}}
    network = {
        "sources": [{"id": 1, "name": "main", "driver": "mikrotik_api", "driver_options": {"intent_stable_id": "rb"}}],
        "routes": [{"source": "main", "dst_address": "192.0.2.0/30", "gateway": "ether8", "immediate_gateway": "ether8",
                    "routing_table": "main", "active": 1, "disabled": 0, "dynamic": 1, "route_type": "unicast", "last_seen_at": at}],
        "router_interfaces": [{"source": "main", "name": "ether8", "type": "ether", "running": 1, "disabled": 0, "last_seen_at": at}],
        "arp": [{"ip": "192.0.2.2", "mac": "02:00:00:00:00:08", "source": "main", "interface": "ether8", "last_seen_at": at}],
    }

    def build():
        graph = build_graph(context, network, {}, {}, binding, now)
        service = next(n for n in graph["nodes"] if n["id"] == "transit:transit")
        edges = [e for e in graph["links"] if {e["a"], e["b"]} == {"rb", "coordinator"}]
        return service, edges

    service, (link,) = build()
    assert service["probeTargetIP"] == "192.0.2.2"
    assert link["confirmed"] and link["portEvidence"][0]["a"] == "ether8"
    assert link["portEvidence"][0]["b"] == ""
    network["arp"][0]["interface"] = "bridge1"
    assert build()[0]["probeTargetIP"] is None and build()[1] == []
    network["arp"][0]["interface"] = "ether8"
    network["routes"][0]["immediate_gateway"] = "192.0.2.1%ether8"
    assert build()[0]["probeTargetIP"] is None
    network["routes"][0]["immediate_gateway"] = "ether8"
    network["router_interfaces"][0]["running"] = 0
    assert build()[0]["probeTargetIP"] is None


def test_observed_fdb_resolves_ifindex_only_with_matching_live_port_collection():
    import sqlite3
    from contextlib import closing
    from netctl.switch_queries import query_observed_mac_ports

    with closing(sqlite3.connect(":memory:")) as conn:
        conn.row_factory = sqlite3.Row
        conn.executescript("""
            CREATE TABLE network_sources (id INTEGER, enabled INTEGER);
            CREATE TABLE switch_ports (source_id INTEGER, port_key TEXT, collector_run_id INTEGER, oper_status TEXT);
            CREATE TABLE current_switch_fdb (source_id INTEGER, port_key TEXT, if_index INTEGER,
                collector_run_id INTEGER, mac TEXT, vlan_id INTEGER, last_seen_at TEXT, status TEXT);
            INSERT INTO network_sources VALUES (1, 1);
            INSERT INTO switch_ports VALUES (1, 'ifindex:49175', 5, 'up');
            INSERT INTO current_switch_fdb VALUES (1, 'physical:23', 49175, 5,
                '02:00:00:00:00:23', 1, '2026-11-11T18:36:04Z', 'learned');
        """)
        macs = {"02:00:00:00:00:23"}
        report, = query_observed_mac_ports(conn, macs)
        assert report["port_key"] == "ifindex:49175"
        assert query_observed_mac_ports(conn, macs, learned_only=True) == [report]
        conn.execute("UPDATE current_switch_fdb SET status='static'")
        assert query_observed_mac_ports(conn, macs, learned_only=True) == []
        assert query_observed_mac_ports(conn, macs) == [report]
        conn.execute("UPDATE switch_ports SET collector_run_id=6")
        assert query_observed_mac_ports(conn, macs) == []
        conn.execute("UPDATE switch_ports SET collector_run_id=5")
        conn.execute("INSERT INTO switch_ports VALUES (1, 'physical:23', 4, 'up')")
        assert query_observed_mac_ports(conn, macs) == [report]
        conn.execute("UPDATE switch_ports SET collector_run_id=5, oper_status='down' WHERE port_key='physical:23'")
        assert query_observed_mac_ports(conn, macs) == []


def test_confirmed_attachment_requires_fdb_and_port_from_same_collection():
    import sqlite3
    from contextlib import closing
    from netctl.switch_queries import query_confirmed_attachment_ports

    with closing(sqlite3.connect(":memory:")) as conn:
        conn.row_factory = sqlite3.Row
        conn.executescript("""
            CREATE TABLE network_sources (id INTEGER, enabled INTEGER);
            CREATE TABLE asset_interfaces (id INTEGER, mac TEXT, lifecycle TEXT);
            CREATE TABLE asset_attachment_resolutions (asset_interface_id INTEGER, selected_source_id INTEGER,
                selected_port_key TEXT, selected_vlan_key TEXT, correlation_run_id INTEGER, status TEXT);
            CREATE TABLE asset_attachment_candidates (asset_interface_id INTEGER, switch_source_id INTEGER,
                port_key TEXT, vlan_key TEXT, vlan_id INTEGER, correlation_run_id INTEGER,
                candidate_class TEXT, observed_at TEXT);
            CREATE TABLE switch_ports (source_id INTEGER, port_key TEXT, collector_run_id INTEGER, oper_status TEXT);
            CREATE TABLE current_switch_fdb (source_id INTEGER, port_key TEXT, if_index INTEGER,
                collector_run_id INTEGER, mac TEXT, vlan_key TEXT, status TEXT);
            INSERT INTO network_sources VALUES (1, 1);
            INSERT INTO asset_interfaces VALUES (2, '02:00:00:00:00:17', 'active');
            INSERT INTO asset_attachment_resolutions VALUES (2, 1, 'physical:17', '1', 50, 'confirmed');
            INSERT INTO asset_attachment_candidates VALUES (2, 1, 'physical:17', '1', 1, 50,
                'direct', '2026-11-11T20:40:00Z');
            INSERT INTO switch_ports VALUES (1, 'physical:17', 4, 'up');
            INSERT INTO current_switch_fdb VALUES (1, 'physical:17', 5017, 5,
                '02:00:00:00:00:17', '1', 'learned');
        """)
        assert query_confirmed_attachment_ports(conn) == []
        conn.execute("INSERT INTO switch_ports VALUES (1, 'ifindex:5017', 5, 'up')")
        report, = query_confirmed_attachment_ports(conn)
        assert report["port_key"] == "ifindex:5017"
        assert report["observed_at"] == "2026-11-11T20:40:00Z"
        conn.execute("UPDATE switch_ports SET collector_run_id=5, oper_status='down' WHERE port_key='physical:17'")
        assert query_confirmed_attachment_ports(conn) == []
        conn.execute("UPDATE switch_ports SET oper_status='up' WHERE port_key='physical:17'")
        report, = query_confirmed_attachment_ports(conn)
        assert report["port_key"] == "physical:17"
        conn.execute("UPDATE current_switch_fdb SET mac='02:00:00:00:00:18'")
        assert query_confirmed_attachment_ports(conn) == []


def test_configured_asset_fdb_path_is_scoped_and_requires_a_unique_live_port():
    from app.infrastructure_collect import build_graph

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    address, mac = "192.0.2.22", "02:00:00:00:00:23"
    context = {"devices": [{"id": "gateway", "name": "Gateway", "kind": "fxs_gateway",
                            "management_ip": address, "mac_addresses": [mac]}]}
    network = {
        "sources": [{"id": 1, "name": "access", "driver": "snmp_switch", "enabled": True},
                    {"id": 2, "name": "core", "driver": "snmp_switch", "enabled": True}],
        "arp": [{"ip": address, "mac": mac, "last_seen_at": at}],
        "ports": [{"source": "access", "port_key": "physical:23", "name": "Gi1/0/23",
                   "oper_status": "up", "last_seen_at": at}],
        "asset_fdb": [{"source_id": 1, "mac": mac, "port_key": "physical:23", "vlan_id": 1, "observed_at": at},
                      {"source_id": 2, "mac": mac, "port_key": "physical:47", "vlan_id": 1, "observed_at": at}],
    }
    bindings = {"asset_fdb_paths": {"gateway": "access"}}

    def links(at=now):
        return build_graph(context, network, {}, {}, bindings, at)["links"]

    path, = links()
    assert path["a"] == "observer:access" and path["b"] == "gateway"
    assert path["kind"] == "Путь по MAC-таблице" and path["confirmed"]
    assert path["portEvidence"] == [{"a": "Gi1/0/23", "b": "", "source": "netctl FDB",
                                     "at": at, "confirmed": True, "vlan": 1}]
    assert links(now + timedelta(hours=1)) == []
    network["asset_fdb"].append({**network["asset_fdb"][0], "port_key": "physical:24"})
    assert links() == []
    network["asset_fdb"].pop()
    network["ports"][0]["oper_status"] = "down"
    assert links() == []
    network["ports"][0]["oper_status"] = "up"
    network["arp"][0]["mac"] = "02:00:00:00:00:24"
    assert links() == []


def test_hypervisor_fdb_path_reports_management_interface_without_claiming_direct_cable(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    earlier = (now - timedelta(minutes=1)).isoformat()
    address, mac = "192.0.2.11", "02:00:00:00:00:11"
    context = {"devices": [{"id": "pve1", "name": "pve1", "kind": "hypervisor",
                            "management_ip": address, "mac_addresses": [mac]}]}
    network = {"sources": [{"id": 1, "name": "core", "driver": "snmp_switch", "enabled": True}],
               "arp": [{"ip": address, "mac": mac, "last_seen_at": at}],
               "ports": [{"source": "core", "port_key": "physical:12", "name": "ge12",
                          "oper_status": "up", "last_seen_at": at}],
               "asset_fdb": [{"source_id": 1, "mac": mac, "port_key": "physical:12", "vlan_id": 1, "observed_at": at}]}
    pve = {"at": earlier, "cluster": [], "nodes": [{"node": "pve1", "status": "online"}],
           "guests": [{"vmid": 108, "node": "pve1", "type": "qemu", "status": "running"}],
           "configs": {"108": {"net0": "virtio=02:00:00:00:00:08,bridge=vmbr0"}},
           "bridges": {"pve1": {"vmbr0": {"active": 1, "bridge_ports": "enp134s0"}}},
           "activePorts": {"pve1": ["enp134s0"]},
           "management": {"pve1": {"address": address, "port": "enp134s0"}}}
    bindings = {"asset_fdb_paths": {"pve1": "core"}}

    def proof():
        graph = build_graph(context, network, {}, pve, bindings, now)
        path, = [edge for edge in graph["links"] if edge["a"] == "observer:core"]
        assert path["kind"] == "Путь по MAC-таблице" and path["confirmed"]
        report, = path["portEvidence"]
        return report

    def guest_uplink(rendered_at=now):
        raw = build_graph(context, network, {}, pve, bindings, now)
        path = tmp_path / "infrastructure.json"
        path.write_text(json.dumps(raw), encoding="utf-8")
        graph = load_infrastructure_map(path, rendered_at)
        placement = next(link for link in graph["links"] if link["b"] == "pve-guest:108")
        virtual = placement["portEvidence"][0]["virtual"]
        assert virtual["switchPorts"] == []
        return virtual.get("switchUplink")

    assert proof() == {"a": "ge12", "b": "enp134s0", "source": "netctl FDB + Proxmox",
                       "at": earlier, "confirmed": True, "vlan": 1}
    assert guest_uplink() == {"id": "observer:core", "port": "ge12", "at": earlier, "viaMacTable": True}
    assert guest_uplink(now + timedelta(minutes=25)) is None
    pve["activePorts"]["pve1"] = []
    assert guest_uplink() is None
    pve["activePorts"]["pve1"] = ["enp134s0"]
    context["devices"].append({"id": "router", "name": "Other router", "kind": "router"})
    network["lldp"] = [{"source": "core", "local_port_key": "physical:12",
                        "system_name": "Other router", "observed_at": at}]
    assert guest_uplink() is None
    del network["lldp"]
    pve["management"]["pve1"]["address"] = "192.0.2.12"
    assert proof()["b"] == "" and proof()["source"] == "netctl FDB"
    assert guest_uplink() is None
    pve["management"]["pve1"]["address"] = address
    pve["at"] = (now - timedelta(hours=1)).isoformat()
    assert proof()["b"] == ""


def test_transit_peer_management_port_requires_fresh_arp_fdb_and_active_ethernet(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    address, mac = "198.51.100.20", "02:00:00:00:00:07"
    context = {"devices": [{"id": "rb", "name": "RB", "kind": "router"},
                           {"id": "coordinator", "name": "Coordinator", "kind": "security_gateway",
                            "management_ip": address}],
               "segments": [{"id": "transit", "cidr": "192.0.2.0/30",
                             "local_address": "192.0.2.1", "gateway_device": "rb"}]}
    bindings = {"transit_links": {"transit": {"asset": "coordinator", "source": "main",
                                            "peer": "192.0.2.2", "label": "Transit", "lan_bridge": "bridge-lan"}}}
    learned = {"source": "main", "mac": mac, "bridge": "bridge-lan", "interface": "ether7", "last_seen_at": at}
    network = {
        "sources": [{"name": "main", "driver": "mikrotik_api", "driver_options": {"intent_stable_id": "rb"}}],
        "arp": [{"source": "main", "ip": address, "mac": mac, "interface": "bridge-lan", "last_seen_at": at}],
        "router_bridge_hosts": [learned],
        "router_interfaces": [{"source": "main", "name": "ether7", "type": "ether",
                               "running": 1, "disabled": 0, "last_seen_at": at}],
    }
    path = tmp_path / "graph.json"

    def lan(at=now, public_at=now):
        graph = build_graph(context, network, {}, {}, bindings, at)
        path.write_text(json.dumps(graph), encoding="utf-8")
        return [e for e in load_infrastructure_map(path, public_at)["links"] if e["a"] == "rb" and e["b"] == "coordinator"]

    link, = lan()
    assert link["kind"] == "Путь по MAC-таблице" and link["confirmed"]
    assert link["portEvidence"] == [{"a": "ether7", "b": "", "source": "MikroTik · ARP + FDB", "at": at, "confirmed": True}]
    assert not lan(public_at=now + timedelta(hours=1))[0]["confirmed"]
    assert lan(at=now + timedelta(hours=1), public_at=now + timedelta(hours=1)) == []
    network["router_bridge_hosts"].append({**learned, "interface": "ether6"})
    assert lan() == []
    network["router_bridge_hosts"].pop()
    network["router_interfaces"][0]["running"] = 0
    assert lan() == []


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


def test_route_checks_report_mismatch_inactive_and_missing_observation():
    from app.infrastructure_collect import _route_checks
    from app.infrastructure_map import _public_service_check

    now = datetime.now(timezone.utc)
    current = now.isoformat()
    stale = (now - timedelta(minutes=26)).isoformat()
    destination, gateway = "198.51.100.0/24", "192.0.2.1"
    intent = {"destinations": [destination], "next_hop": gateway}
    route = {"source": "router", "routing_table": "main", "dst_address": destination,
             "gateway": gateway, "active": 1, "disabled": 0, "last_seen_at": current}

    def read(*routes):
        check, = _route_checks(intent, "router", list(routes), now)
        return _public_service_check(check, now)

    other = read({**route, "gateway": "192.0.2.2"})
    assert (other["state"], other["reason"], other["via"], other["observedVia"]) == (
        "unreachable", "route_other_gateway", gateway, "192.0.2.2",
    )
    assert read({**route, "active": 0})["reason"] == "route_inactive"
    assert read({**route, "disabled": 1})["state"] == "unreachable"
    assert read({**route, "route_type": "blackhole"})["reason"] == "route_rejecting"
    mixed = read(route, {**route, "gateway": "192.0.2.2"})
    assert mixed["state"] == "unknown" and mixed["reason"] == "route_multiple_gateways"
    assert read({**route, "gateway": "192.0.2.2"}, {**route, "gateway": "192.0.2.3"})["state"] == "unknown"
    old = read({**route, "active": 0, "last_seen_at": stale})
    assert old["state"] == "unknown" and old["stale"] and old["checkedAt"] == stale
    assert "reason" not in old
    missing = read({**route, "routing_table": "other"})
    assert missing["state"] == "unknown" and missing["method"] == "Маршрут"
    assert missing["checkedAt"] is None

    host = "198.51.100.12/32"
    checks = _route_checks(intent, "router", [route, {**route, "dst_address": host}], now,
                           host_routes=[host, host, "203.0.113.10/32", "198.51.100.0/28", "invalid"])
    assert [(check["target"], check["state"]) for check in checks] == [
        (destination, "reachable"), (host, "reachable"),
    ]


def test_sip_options_validates_transaction_and_treats_silence_as_unknown(monkeypatch):
    import ipaddress
    import struct
    from app import infrastructure_service_probes as probes
    from app.infrastructure_map import _public_node

    class Datagram:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def settimeout(self, timeout):
            pass

        def setsockopt(self, level, option, value):
            self.option = (level, option)

        def setblocking(self, blocking):
            assert not blocking

        def connect(self, address):
            assert address == ("192.0.2.13", 5060)

        def getsockname(self):
            return ("192.0.2.14", 12345)

        def sendall(self, request):
            assert request.startswith(b"OPTIONS sip:192.0.2.13:5060 SIP/2.0")
            self.requests.append(request)
            self.headers = [line for line in request.split(b"\r\n") if line.startswith((b"Call-ID:", b"CSeq:"))]

        def recv(self, size):
            if len(self.requests) <= self.drop_count:
                raise TimeoutError
            if self.code == b"refused":
                raise ConnectionRefusedError
            if self.code is None:
                raise TimeoutError
            headers = self.headers if self.match else [b"Call-ID: unrelated", b"CSeq: 1 OPTIONS"]
            return b"\r\n".join([b"SIP/2.0 " + self.code, *headers, b"", b""])

        def recvmsg(self, size, ancillary_size, flags):
            if not self.offender:
                raise BlockingIOError
            extended = struct.pack("=IBBBBII", 111, 2, 3, 3, 0, 0, 0)
            address = struct.pack("=HH", probes.socket.AF_INET, 0) + ipaddress.ip_address(self.offender).packed
            return b"", [(*self.option, extended + address)], 0, ("192.0.2.13", 5060)

    wire = Datagram()
    wire.drop_count = 0
    monkeypatch.setattr(probes.socket, "socket", lambda *args: wire)
    monkeypatch.setattr(probes.socket, "MSG_ERRQUEUE", 8192, raising=False)
    spec = {"type": "sip_options", "ip": "192.0.2.13", "port": 5060}
    node = {"id": "pbx", "kind": "Сервис"}
    for code, match, offender, state, reason, response_code in [
        (b"200 OK", True, None, "reachable", "sip_response", 200),
        (b"503 Busy", True, None, "unreachable", "sip_response", 503),
        (b"200 OK", False, None, "unknown", "unexpected_response", None),
        (None, True, None, "unknown", "timeout", None),
        (b"refused", True, None, "unknown", "connection_refused", None),
        (b"refused", True, "192.0.2.13", "unreachable", "icmp_port_unreachable", None),
        (b"refused", True, "192.0.2.1", "unknown", "icmp_rejected", None),
    ]:
        wire.code, wire.match, wire.offender = code, match, offender
        wire.requests = []
        probes.apply_service_probes([node], {"pbx": [spec]})
        check = node["serviceChecks"][-1]
        assert node["reachability"]["state"] == check["state"] == state
        public = _public_node(node, datetime.now(timezone.utc))["serviceChecks"][-1]
        assert (public["source"], public["reason"], public.get("responseCode")) == ("UI_VPN", reason, response_code)
        assert public.get("errorSource") == offender
        assert public["attempts"] == len(wire.requests) == (3 if code is None else 1)
    node["serviceChecks"][-1].update(reason="arbitrary output", responseCode=900, attempts=4)
    public = _public_node(node, datetime.now(timezone.utc))["serviceChecks"][-1]
    assert "reason" not in public and "responseCode" not in public and "attempts" not in public
    wire.requests, wire.drop_count = [], 1
    wire.code, wire.match, wire.offender = b"200 OK", True, None
    probes.apply_service_probes([node], {"pbx": [spec]})
    result = _public_node(node, datetime.now(timezone.utc))["serviceChecks"][-1]
    assert result["state"] == "reachable" and result["attempts"] == 2
    assert len(wire.requests) == 2 and wire.requests[0] == wire.requests[1]


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


def test_router_layer2_probe_requires_a_reply_from_the_expected_mac(monkeypatch):
    from contextlib import nullcontext

    from netctl.drivers.mikrotik_api import MikroTikApiDriver

    mac = "02:00:00:00:00:03"
    calls = []
    rows = [{"host": mac, "sent": "1", "received": "1"}]

    class Api:
        def call(self, words):
            calls.append(words)
            return rows

    monkeypatch.setattr(MikroTikApiDriver, "_client", lambda self: nullcontext(Api()))
    driver = MikroTikApiDriver({}, {})
    assert driver.probe_layer2("bridge-lan", mac)
    assert driver.probe_layer2("bridge-lan", mac, address="192.0.2.21")
    assert calls == [
        ["/ping", f"=address={mac}", "=interface=bridge-lan", "=count=1"],
        ["/ping", "=address=192.0.2.21", "=interface=bridge-lan", "=count=1", "=arp-ping=yes"],
    ]
    rows[0]["host"] = "02:00:00:00:00:07"
    assert not driver.probe_layer2("bridge-lan", mac, address="192.0.2.21")
    rows[0].update(host=mac, received="0")
    assert not driver.probe_layer2("bridge-lan", mac)


def test_router_layer2_checks_follow_inventory_and_guest_arp_identity(monkeypatch):
    from app import infrastructure_collect as collector

    now = datetime.now(timezone.utc)
    ip, mac = "192.0.2.21", "02:00:00:00:00:03"
    ap_mac = "02:00:00:00:00:04"
    pve = {"cluster": [], "nodes": [], "guests": [{"vmid": 108, "node": "pve1", "status": "running"}],
           "configs": {"108": {"net0": f"virtio={mac},bridge=vmbr0"}}}
    source = {"name": "router", "enabled": True, "driver": "mikrotik_api"}
    arp = {"ip": ip, "mac": mac, "source": "router", "interface": "bridge-lan", "last_seen_at": now.isoformat()}
    network = {"arp": [arp], "sources": [source]}
    context = {"devices": [{"id": "ap", "name": "AP", "kind": "wireless_access_point", "mac_addresses": [ap_mac]}]}
    bindings = {"asset_mac_probes": {"ap": {"source": "router", "interface": "bridge-lan", "mac": ap_mac}},
                "guest_router_arp_sources": {"108": "router"}}
    calls = []

    class Driver:
        def probe_layer2(self, interface, target, *, address=None):
            calls.append((interface, target, address))
            return True

    monkeypatch.setattr(collector, "load_secrets", lambda: {})
    monkeypatch.setattr(collector, "legacy_driver_for", lambda *_: Driver())
    monkeypatch.setattr(collector, "_probe_on_link_guest", lambda *_: False)
    network["asset_mac_checks"] = collector._collect_asset_mac_probes(context, [source], bindings["asset_mac_probes"])
    network["guest_arp_probes"] = collector._collect_guest_arp_probes(
        pve, network, {"108": ip}, now, bindings["guest_router_arp_sources"],
    )
    graph = collector.build_graph(context, network, {}, pve, bindings, datetime.now(timezone.utc))
    nodes = {row["id"]: row for row in graph["nodes"]}
    assert nodes["ap"]["reachability"]["method"] == "MAC ping · L2"
    assert nodes["pve-guest:108"]["reachability"]["method"] == "ARP · L2"
    assert calls == [("bridge-lan", ap_mac, None), ("bridge-lan", mac, ip)]
    arp["source"] = "other-router"
    assert collector._collect_guest_arp_probes(pve, network, {"108": ip}, now, bindings["guest_router_arp_sources"]) == {}
    context["devices"][0]["mac_addresses"] = [mac]
    assert collector._collect_asset_mac_probes(context, [source], bindings["asset_mac_probes"]) == {}
    assert len(calls) == 2


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
