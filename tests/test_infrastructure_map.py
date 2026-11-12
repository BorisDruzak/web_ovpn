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
        if component == "error":
            checks[0]["error"] = "timeout"
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
        assert observed["role:directum"]["status"] == "warn"
        assert observed["role:directum"]["sourceStatus"] == "critical"
        assert observed["vm"]["mapStatus"] == "warn"
        assert observed["vm"]["serviceAvailability"]["unavailable"] == []
        assert observed["vm"]["serviceAvailability"]["degraded"] == ["role:directum"]
    assert read(database="unreachable", confirmed=False)["vm"]["mapStatus"] == "ok"
    assert read(component=None)["vm"]["mapStatus"] == "unknown"
    timed_out = read(component="error")["role:directum"]
    assert timed_out["status"] == "unknown"
    assert timed_out["checks"][0]["error"] == "timeout"
    assert "error" not in read(component="error", observer_at=(now - timedelta(minutes=30)).isoformat())[
        "role:directum"]["checks"][0]
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
    graph = build_graph({}, {}, report, {}, {}, now)
    graph["serverObserverAt"] = stamp
    snapshot.write_text(json.dumps(graph), encoding="utf-8")

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
    old = read(now + timedelta(minutes=16))["c_disk_free"]
    assert old["stale"] and old["status"] == "unknown"
    assert old["observed"] == 5.32 and old["checkedAt"] == stamp
    public = load_infrastructure_map(snapshot, now + timedelta(minutes=16))
    assert public["availability"] == "ready" and public["collectionIssues"] == ["server_observer_stale"]


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


def test_guest_network_reports_an_empty_configuration_only_after_a_successful_read(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    pve = {"at": at, "cluster": [], "nodes": [{"node": "pve1", "status": "online"}],
           "guests": [{"vmid": 127, "node": "pve1", "type": "lxc", "status": "running"}],
           "configs": {"127": {"networkConfigRead": True}}}
    path = tmp_path / "snapshot.json"

    def read(when=now):
        path.write_text(json.dumps(build_graph({}, {}, {}, pve, {}, now)), encoding="utf-8")
        return next(node for node in load_infrastructure_map(path, when)["nodes"] if node.get("vmid") == 127)

    node = read()
    assert node["guestNetwork"] == {"checkedAt": at, "configured": 0, "enabled": 0, "disabled": 0}
    assert node["mapStatus"] == "unknown"
    assert node["reachability"]["method"] == "Адаптеры Proxmox не заданы"
    assert "guestNetwork" not in read(now + timedelta(hours=1))
    pve["configs"]["127"].update(
        net0="name=eth0,bridge=vmbr0,hwaddr=02:00:00:00:00:01",
        net1="name=eth1,bridge=vmbr1,hwaddr=02:00:00:00:00:02,link_down=1",
        net2="name=eth2",
    )
    node = read()
    assert node["guestNetwork"] == {"checkedAt": at, "configured": 3, "enabled": 1, "disabled": 1}
    assert node["reachability"]["method"] == ""
    pve["configs"]["127"] = {}
    assert "guestNetwork" not in read()


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


def test_proxmox_capacity_uses_available_root_space_and_reports_missing_data(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    stamp = now.isoformat()
    status = {"checkedAt": stamp, "rootfs": {"avail": 100, "free": 400, "total": 1000},
              "swap": {"used": 0, "total": 0}, "memory": {"free": 22, "total": 1000}}
    pve = {"at": stamp, "cluster": [], "nodes": [{"node": "pve1", "status": "online"}], "guests": [],
           "nodeStatus": {"pve1": status}}
    path = tmp_path / "infrastructure.json"

    def read(at=now):
        path.write_text(json.dumps(build_graph({}, {}, {}, pve, {}, now)), encoding="utf-8")
        return next(node for node in load_infrastructure_map(path, at)["nodes"] if node["id"] == "pve1")

    node = read()
    assert node["resourceCapacity"]["root"] == {"availableBytes": 100, "totalBytes": 1000, "status": "warn"}
    assert node["resourceCapacity"]["swap"]["status"] == "not_configured"
    assert node["resourceCapacity"]["memory"]["freeBytes"] == 22
    assert node["mapStatus"] == "warn" and node["reachability"]["state"] == "reachable"
    status["rootfs"]["avail"] = 101
    assert read()["mapStatus"] == "ok"
    status["swap"] = {"used": 90, "total": 100}
    assert read()["mapStatus"] == "warn"
    status["swap"]["used"] = True
    assert read()["mapStatus"] == "unknown"
    assert read(now + timedelta(minutes=6))["resourceCapacity"]["root"] == {"status": "unknown"}
    pve["nodeStatus"].clear()
    assert read()["mapStatus"] == "unknown"


def test_backup_state_requires_a_valid_watchdog_report(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    target = {"role": "acti_backup", "status": "critical", "observed_at": now.isoformat(), "checks": []}
    path = tmp_path / "infrastructure.json"

    def read(watchdog, snapshot, capacity="ok", freshness="current", *, duplicate=False):
        target["checks"] = [{"name": name, "status": status} for name, status in (
            ("watchdog_fresh", watchdog), ("backup_snapshot_fresh", snapshot), ("repository_capacity", capacity),
        ) if status is not None]
        if duplicate:
            target["checks"].append({"name": "backup_snapshot_fresh", "status": "critical"})
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
    assert read("ok", "ok", capacity="critical")["mapStatus"] == "warn"
    assert read("ok", "ok", capacity=None)["mapStatus"] == "unknown"
    assert read("ok", "ok", duplicate=True)["mapStatus"] == "unknown"
    assert read("ok", "critical", freshness="stale")["mapStatus"] == "unknown"


def test_acti_service_reflects_backup_dependency_on_inventory_host(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    stamp = now.isoformat()
    report = {"freshness": "current", "targets": [
        {"role": "acti_backup", "status": "critical", "observed_at": stamp,
         "checks": [{"name": "watchdog_fresh", "status": "ok"},
                    {"name": "backup_snapshot_fresh", "status": "critical"},
                    {"name": "repository_capacity", "status": "ok"}]},
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


def test_service_distinguishes_partial_failure_and_unconfirmed_http_responses(monkeypatch):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from threading import Thread
    from app.infrastructure_map import _map_statuses, _public_node, _public_service_check
    from app.infrastructure_service_probes import apply_service_probes
    from app import infrastructure_service_probes as probes

    original_request = probes.http.client.HTTPConnection.request

    def request(connection, method, path, **kwargs):
        if path == "/timeout":
            raise TimeoutError
        return original_request(connection, method, path, **kwargs)

    monkeypatch.setattr(probes.http.client.HTTPConnection, "request", request)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            code, payload = {
                "/client": (200, b"<script src='client.js'></script>"),
                "/healthy": (200, b"Healthy"),
                "/unexpected": (200, b"Sign in"),
                "/unavailable": (503, b"Unavailable"),
                "/redirect": (302, b"Redirect"),
                "/named": (200, b"Healthy") if self.headers["Host"] == f"directum.example:{self.server.server_port}"
                else (404, b"Wrong host"),
            }[self.path]
            self.send_response(code)
            self.send_header("Content-Type", "text/html")
            if code == 302:
                self.send_header("Location", "/login?session=private")
            self.end_headers()
            self.wfile.write(payload)

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        worker = Thread(target=server.serve_forever)
        worker.start()
        try:
            base = {"ip": "127.0.0.1", "port": server.server_port, "type": "http"}
            client = {**base, "path": "/client", "body_contains": "client.js"}
            paths = ("/healthy", "/unexpected", "/unavailable", "/redirect", "/primary-down",
                     "/partial", "/all-down", "/incomplete", "/timeout", "/named", "/bad-host")
            nodes = [{"id": path, "kind": "Сервис"} for path in paths]
            specs = {
                node["id"]: [client, {**base, "path": node["id"], "body": "Healthy"}] for node in nodes[:4]
            }
            failed = {**base, "path": "/unavailable", "body": "Healthy"}
            specs["/primary-down"] = [{**client, "component": True}, failed]
            specs["/partial"] = [client, {**failed, "component": True}]
            specs["/all-down"] = [failed, failed]
            timeout = {**base, "path": "/timeout", "body": "Healthy"}
            specs["/incomplete"] = [failed, timeout]
            specs["/timeout"] = [timeout]
            specs["/named"] = [{**base, "path": "/named", "body": "Healthy", "http_host": "directum.example"}]
            specs["/bad-host"] = [{**specs["/named"][0], "http_host": "directum.example\r\nX-Injected: value"}]
            apply_service_probes(nodes, specs)
        finally:
            server.shutdown()
            worker.join()
    assert [node["reachability"]["state"] for node in nodes] == [
        "reachable", "reachable", "reachable", "reachable", "unreachable", "reachable", "unreachable", "unknown", "unknown",
        "reachable", "unknown",
    ]
    assert [[check["state"] for check in node["serviceChecks"]] for node in nodes[:4]] == [
        ["reachable", "reachable"], ["reachable", "unknown"], ["reachable", "unreachable"], ["reachable", "unknown"],
    ]
    assert nodes[1]["serviceChecks"][1]["path"] == "/unexpected"
    now = datetime.now(timezone.utc)
    public = {node["id"]: _public_node(node, now) for node in nodes}
    _map_statuses(public, [])
    assert [node["mapStatus"] for node in public.values()] == [
        "ok", "unknown", "warn", "unknown", "critical", "warn", "critical", "unknown", "unknown", "ok", "unknown",
    ]
    assert [node["status"] for node in public.values()] == [node["mapStatus"] for node in public.values()]
    assert public["/named"]["serviceChecks"][0]["httpHost"] == "directum.example"
    assert public["/bad-host"]["serviceChecks"][0]["reason"] == "http_configuration"
    assert "httpHost" not in public["/bad-host"]["serviceChecks"][0]
    assert public["/timeout"]["serviceChecks"][0]["reason"] == "timeout"
    assert public["/primary-down"]["serviceChecks"][0]["component"] is True
    assert public["/partial"]["serviceChecks"][1]["required"] is True
    checks = [_public_service_check(node["serviceChecks"][1], now) for node in nodes[:4]]
    assert [(check["httpStatus"], check.get("reason")) for check in checks] == [
        (200, None), (200, "http_payload_mismatch"), (503, "http_status"), (302, "http_status"),
    ]
    assert "private" not in json.dumps(checks)
    foreign = {**nodes[0]["serviceChecks"][1], "method": "DNS", "reason": "http_status"}
    assert "httpStatus" not in _public_service_check(foreign, now)
    assert "reason" not in _public_service_check(foreign, now)


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


def test_http_probe_checks_nested_boolean_health_fields(monkeypatch):
    from app.infrastructure_service_probes import _http_probe

    class Response:
        status = 200
        payload = {}

        def getheader(self, name, default):
            return "application/json"

        def read(self, limit):
            return json.dumps(self.payload).encode()

    class Connection:
        def __init__(self, *args, **kwargs):
            pass

        def request(self, *args, **kwargs):
            pass

        def getresponse(self):
            return response

        def close(self):
            pass

    response = Response()
    monkeypatch.setattr("app.infrastructure_service_probes.http.client.HTTPConnection", Connection)
    spec = {"type": "http", "ip": "192.0.2.10", "port": 80, "path": "/ready",
            "json_fields": {"ProductName": "Directum RX", "MaintenanceModeState.IsEnabled": False},
            "json_unavailable": {"ProductName": "Directum RX", "MaintenanceModeState.IsEnabled": True}}
    for value, expected in [(False, "reachable"), (True, "unreachable"), (0, "unknown"),
                            ("false", "unknown"), (None, "unknown")]:
        response.payload = {"ProductName": "Directum RX", "MaintenanceModeState": {"IsEnabled": value}}
        assert _http_probe(spec)["state"] == expected
    response.payload = {"ProductName": "Directum RX", "MaintenanceModeState.IsEnabled": False}
    assert _http_probe(spec)["state"] == "unknown"


def test_malformed_service_probe_config_cannot_leave_observer_green():
    from app.infrastructure_map import _map_statuses, _public_node
    from app.infrastructure_service_probes import apply_service_probes

    for invalid in ([], {}, [None], [{}] * 5, [{"type": "typo"}]):
        node = {"id": "service", "kind": "Сервис", "reachability": {
            "state": "reachable", "source": "Server Observer", "method": "HTTPS",
            "checkedAt": datetime.now(timezone.utc).isoformat(),
        }}
        apply_service_probes([node], {"service": invalid})
        public = _public_node(node, datetime.now(timezone.utc))
        _map_statuses({"service": public}, [])
        assert public["mapStatus"] == "unknown"
        assert public["serviceChecks"][0]["reason"] == "probe_configuration"


def test_dns_probe_requires_an_answer_to_the_actual_query(monkeypatch):
    import dns.message
    import dns.rrset

    from app import infrastructure_service_probes as probes
    from app.infrastructure_map import _public_service_check

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
    node = {"id": "dns", "kind": "Сервис"}
    probes.apply_service_probes([node], {"dns": [spec]})
    detail = _public_service_check(node["serviceChecks"][0], datetime.now(timezone.utc))
    assert detail["state"] == "unreachable" and detail["reason"] == "dns_address_mismatch"
    assert detail["dns"] == {"name": "service.example.", "record": "A", "rcode": "NOERROR",
                             "transport": "UDP", "addresses": ["192.0.2.10", "192.0.2.11", "192.0.2.12"]}
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
    assert node["serviceChecks"][-1]["reason"] == "http_certificate_pin"
    assert "httpStatus" not in node["serviceChecks"][-1]
    events.clear()
    spec["tls_sha256"] = sha256(cert).hexdigest()
    probes.apply_service_probes(graph["nodes"], configured)
    assert events == ["connect", ("GET", "/"), "close"]
    assert node["reachability"]["state"] == "reachable"
    assert node["serviceChecks"][-1]["httpStatus"] == 200


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


def test_smb_requires_complete_negotiate_reply_and_reports_dialect(monkeypatch):
    from io import BytesIO
    import struct
    from app import infrastructure_service_probes as probes
    from app.infrastructure_map import _public_service_check

    response = bytearray(128)
    response[:4] = b"\xfeSMB"
    struct.pack_into("<H", response, 4, 64)
    struct.pack_into("<I", response, 16, 1)
    struct.pack_into("<HHH", response, 64, 65, 3, 0x0302)

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def sendall(self, request):
            assert request[4:8] == b"\xfeSMB"
            self.wire = BytesIO(len(self.payload).to_bytes(4, "big") + self.payload)

        def recv(self, size):
            return self.wire.read(min(size, 11))

        def settimeout(self, timeout):
            assert 0 < timeout <= probes.TIMEOUT

    connection = Connection()
    monkeypatch.setattr(probes.socket, "create_connection", lambda *_args, **_kwargs: connection)
    spec = {"type": "smb", "ip": "192.0.2.20", "port": 445}

    def check(payload):
        connection.payload = payload
        node = {"id": "share", "kind": "Сервис"}
        probes.apply_service_probes([node], {"share": [spec]})
        return _public_service_check(node["serviceChecks"][0], datetime.now(timezone.utc))

    assert check(response[:70])["state"] == "unknown"
    check_result = check(response)
    assert check_result["state"] == "reachable"
    assert check_result["smbDialect"] == "3.0.2"
    assert check_result["smbSigningRequired"] is True
    struct.pack_into("<Q", response, 24, 1)
    assert check(response)["state"] == "unknown"
    struct.pack_into("<Q", response, 24, 0)
    struct.pack_into("<HH", response, 120, 128, 12)
    assert check(response)["state"] == "unknown"


def test_postgresql_probe_requires_protocol_response(monkeypatch):
    from app import infrastructure_service_probes as probes
    from app.infrastructure_map import _public_service_check

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

    class TLS:
        fails = False

        def wrap_socket(self, socket):
            assert socket is connection and not self.check_hostname
            assert self.verify_mode == probes.ssl.CERT_NONE
            if self.fails:
                raise probes.ssl.SSLError("internal TLS details")
            return self

        def version(self):
            return "TLSv1.3"

        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

    tls = TLS()
    monkeypatch.setattr(probes.ssl, "SSLContext", lambda *_: tls)
    spec = {"type": "postgresql", "ip": "192.0.2.27", "port": 5432}
    assert probes._probe(spec) == "reachable"

    def public():
        node = {"id": "db", "kind": "Сервис"}
        probes.apply_service_probes([node], {"db": [spec]})
        return _public_service_check(node["serviceChecks"][0], datetime.now(timezone.utc))

    check = public()
    assert (check["state"], check["postgresqlTls"], check["tlsVersion"]) == ("reachable", "negotiated", "TLSv1.3")
    tls.fails = True
    check = public()
    assert (check["state"], check["postgresqlTls"], check["reason"]) == ("unknown", "failed", "postgresql_tls_handshake")
    assert "internal TLS details" not in json.dumps(check)
    connection.response = b"N"
    assert probes._probe(spec) == "reachable"
    assert public()["postgresqlTls"] == "declined"
    connection.response = b"H"
    assert probes._probe(spec) == "unreachable"
    assert public()["reason"] == "unexpected_response"


def test_observer_service_attaches_to_the_vm_with_the_expected_mac(monkeypatch):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import _map_statuses, _public_node
    from app import infrastructure_service_probes as probes

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
    pve["guests"][0]["status"] = "stopped"
    stopped, _ = load()
    assert stopped["reachability"]["state"] == "stopped"
    assert stopped["reachability"]["source"] == "Proxmox"
    def unexpected_probe(spec):
        raise AssertionError("probe ran")

    monkeypatch.setattr(probes, "_http_probe", unexpected_probe)
    probes.apply_service_probes([stopped], {stopped["id"]: [{"type": "https", "port": 443}]})
    public = _public_node(stopped, datetime.now(timezone.utc))
    _map_statuses({public["id"]: public}, [])
    assert public["status"] == "critical"
    assert public["serviceChecks"][0]["reason"] == "probe_host_stopped"
    pve["guests"][0]["status"] = "running"
    assert load(now + timedelta(hours=1))[1] == []
    pve["configs"]["211"]["net0"] = "virtio=02:00:00:00:00:04,bridge=vmbr1"
    assert load()[1] == []


def test_guest_service_requires_matching_mac_and_arp_to_enable_probe(monkeypatch):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import _public_service_check
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
    calls = []
    monkeypatch.setattr(probes, "_probe", lambda spec: calls.append(spec["ip"]) or "reachable")

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
    mismatch = build()[1]
    assert "reachability" not in mismatch
    assert mismatch["serviceChecks"][0]["reason"] == "probe_target_mismatch"
    assert mismatch["serviceChecks"][0]["skipped"] is True
    configured["zabbix-api"][0]["ip"] = address
    network["arp"] = []
    unconfirmed = build()[1]
    assert "reachability" not in unconfirmed
    check = _public_service_check(unconfirmed["serviceChecks"][0], datetime.now(timezone.utc))
    assert check["state"] == "unknown" and check["skipped"] is True and check["reason"] == "probe_target_unconfirmed"
    assert check["target"] == "" and check["method"] == "Zabbix API"
    assert calls == [address]
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


def test_lldp_neighbor_count_on_ports_and_declared_links_uses_current_poll(tmp_path):
    from app.infrastructure_collect import build_graph, publish_snapshot
    from app.infrastructure_map import load_infrastructure_map, summarize_topology

    now = datetime.now(timezone.utc)
    stamp = now.isoformat()
    devices = [{"id": key, "name": key, "kind": "switch", "management_ip": f"192.0.2.{index}"}
               for index, key in enumerate(("a", "b"), 1)]
    context = {"devices": devices, "links": [{
        "endpoint_a": {"device": "a", "interface": "ge1"}, "endpoint_b": {"device": "b", "interface": "ge1"},
        "relation": "connected_to",
    }]}
    sources = [{"id": index, "name": key, "driver": "snmp_switch", "host": f"192.0.2.{index}", "enabled": 1}
               for index, key in enumerate(("a", "b"), 1)]
    ports = [{"source": key, "name": "ge1", "port_key": "ifindex:1", "if_index": 1,
              "oper_status": "up", "last_seen_at": stamp, "collector_run_id": 7} for key in ("a", "b")]
    neighbor = {"source": "a", "local_port_key": "ifindex:1", "observed_at": stamp, "collector_run_id": 7,
                "chassis_id": "00:11:22:33:44:55", "port_id": "eth0", "system_name": "Phone",
                "management_addresses": ["192.0.2.90"], "system_description": "private"}
    lldp = [neighbor, neighbor.copy(), {**neighbor, "port_id": "eth1"},
            {**neighbor, "chassis_id": "00:11:22:33:44:66"},
            {**neighbor, "port_id": "eth2", "collector_run_id": 6},
            {**neighbor, "port_id": "eth3", "observed_at": (now - timedelta(minutes=1)).isoformat()}]
    hosts = [{"ip": "192.0.2.66", "mac": "00:11:22:33:44:66", "hostname": "workstation", "last_seen_at": stamp},
             {"ip": "192.0.2.66", "mac": "00:11:22:33:44:66", "hostname": "old-name",
              "last_seen_at": (now - timedelta(hours=1)).isoformat()}]
    graph = build_graph(context, {"sources": sources, "ports": ports, "lldp": lldp, "hosts": hosts}, {}, {}, {}, now)
    path = tmp_path / "map.json"
    publish_snapshot(path, graph)
    public = load_infrastructure_map(path, now)
    nodes = {node["id"]: node for node in public["nodes"]}
    assert nodes["a"]["ports"][0]["lldpNeighborCount"] == 3
    assert nodes["a"]["ports"][0]["lldpChassisCount"] == 2
    assert "lldpNeighborCount" not in nodes["b"]["ports"][0]
    direct = next(edge for edge in public["links"] if edge["kind"] == "Сетевое соединение")
    assert not direct["confirmed"]
    report = direct["portEvidence"][0]
    assert report["portStates"]["a"]["lldpNeighborCount"] == 3
    assert report["portStates"]["a"]["lldpChassisCount"] == 2
    assert "lldpNeighborCount" not in report["portStates"]["b"]
    details = nodes["a"]["ports"][0]["lldpNeighbors"]
    assert [row["portId"] for row in details] == ["eth0", "eth1", "eth0"]
    assert details[0] == {"chassisId": "00:11:22:33:44:55", "portId": "eth0", "systemName": "Phone"}
    assert details[2]["hostName"] == "workstation"
    assert "private" not in json.dumps(details) and "192.0.2.90" not in json.dumps(details)
    pending, = summarize_topology(public)["topologyAudit"]["pending"]
    assert pending["lldpObservations"] == {"a": {"checkedAt": stamp, "neighbors": details}}
    aged = load_infrastructure_map(path, now + timedelta(hours=1))
    assert all(not {"lldpNeighborCount", "lldpChassisCount", "lldpNeighbors"} & port.keys()
               for node in aged["nodes"] for port in node["ports"])


def test_direct_link_compares_contemporaneous_port_samples(tmp_path):
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    stamp = now.isoformat()
    nodes = [{"id": key, "name": key, "kind": "Коммутатор",
              "ports": [{"name": "ge1", "state": "up", "speedBps": 10**9, "checkedAt": stamp}]}
             for key in ("a", "b")]
    report = {"a": "ge1", "b": "ge1", "source": "LLDP · двустороннее", "confirmed": True, "at": stamp}
    link = {"a": "a", "b": "b", "kind": "Сетевое соединение", "source": report["source"],
            "confirmed": True, "observedAt": stamp, "portEvidence": [report]}
    path = tmp_path / "map.json"

    def comparison():
        path.write_text(json.dumps({"schema": 1, "snapshotAt": stamp, "nodes": nodes, "links": [link]}),
                        encoding="utf-8")
        return load_infrastructure_map(path, now)["links"][0]["portEvidence"][0].get("portComparison")

    assert comparison() == {"state": "both_up", "checkedAt": stamp}
    nodes[1]["ports"][0]["speedBps"] = 100_000_000
    assert comparison()["state"] == "speed_mismatch"
    nodes[1]["ports"][0]["state"] = "down"
    assert comparison()["state"] == "one_down"
    nodes[0]["ports"][0]["state"] = "disabled"
    assert comparison()["state"] == "both_down"
    nodes[1]["ports"][0]["checkedAt"] = (now - timedelta(minutes=3)).isoformat()
    assert comparison() is None
    nodes[1]["ports"][0]["checkedAt"] = stamp
    nodes[1]["ports"][0].update(source="Proxmox", proxmoxActive=True, state="up")
    assert comparison() is None
    nodes[1]["ports"][0].pop("source")
    link["kind"] = "Путь по MAC-таблице"
    assert comparison() is None


def test_live_snmp_sample_compares_ports_without_redating_inventory(tmp_path):
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    stamp = now.isoformat()
    previous = (now - timedelta(minutes=4)).isoformat()
    switch = {"id": "switch", "name": "Switch", "kind": "Коммутатор", "ports": [
        {"name": "xe1", "state": "up", "speedBps": 10**9, "checkedAt": previous,
         "fdbLearned": {"checkedAt": previous, "learnedMacCount": 3, "partial": False},
         "telemetry": {"checkedAt": previous, "intervalSeconds": 300, "rxBps": 100},
         "linkCheck": {"state": "up", "speedBps": 10**10, "checkedAt": stamp}},
    ]}
    host = {"id": "host", "name": "Host", "kind": "Гипервизор", "ports": [
        {"name": "eth0", "source": "Proxmox · sysfs", "state": "up", "speedBps": 10**10, "checkedAt": stamp},
    ]}
    evidence = {"a": "xe1", "b": "eth0", "source": "GitHub", "confirmed": True}
    edge = {"a": "switch", "b": "host", "kind": "Сетевое соединение", "confirmed": True,
            "portEvidence": [evidence]}
    path = tmp_path / "map.json"

    def read(at):
        path.write_text(json.dumps({"schema": 1, "snapshotAt": stamp, "nodes": [switch, host], "links": [edge]}),
                        encoding="utf-8")
        graph = load_infrastructure_map(path, at)
        return graph["nodes"][0]["ports"][0], graph["links"][0]["portEvidence"][0]

    port, pair = read(now)
    assert (port["checkedAt"], port["speedBps"]) == (stamp, 10**10)
    assert port["fdbLearned"]["checkedAt"] == previous
    assert port["telemetry"]["checkedAt"] == previous
    assert pair["portComparison"] == {"state": "both_up", "checkedAt": stamp}
    switch["ports"][0]["linkCheck"]["state"] = "down"
    port, pair = read(now)
    assert port["state"] == "down" and port["speedBps"] is None and "telemetry" not in port
    assert pair["portComparison"]["state"] == "one_down"
    port, pair = read(now + timedelta(minutes=6))
    assert port["checkedAt"] == previous and "portComparison" not in pair


def test_live_snmp_poll_uses_confirmed_pairs_and_rechecks_ifindex_name(monkeypatch):
    import asyncio

    from app import infrastructure_collect as collector
    from netctl.snmp.models import CapabilityResult, SnmpVarBind
    from netctl.snmp.oids import IF_ADMIN_STATUS, IF_HIGH_SPEED, IF_NAME, IF_OPER_STATUS
    from netctl.snmp.outcomes import SnmpOutcome

    now = datetime.now(timezone.utc)
    names = {5: b"xe1", 6: b"reused-index"}
    calls = []

    class Transport:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def get(self, oid):
            calls.append(oid)
            column, index = oid[:-1], oid[-1]
            kind, value = {
                IF_NAME: ("octet_string", names[index]), IF_ADMIN_STATUS: ("integer", 1),
                IF_OPER_STATUS: ("integer", 1), IF_HIGH_SPEED: ("gauge32", 10_000),
            }[column]
            return CapabilityResult("", SnmpOutcome.SUCCESS_WITH_ROWS, (SnmpVarBind(oid, kind, value),))

    monkeypatch.setattr(collector.SnmpTransport, "from_source", lambda _: Transport())
    links = [
        {"endpoint_a": {"device": "switch", "interface": f"xe{i}"},
         "endpoint_b": {"device": "host", "interface": f"eth{i}"},
         "relation": "connected_to", "state": {"verified": i < 3}}
        for i in (1, 2, 3)
    ]
    context = {"devices": [{"id": "switch", "kind": "switch", "management_ip": "192.0.2.1"}], "links": links}
    network = {
        "sources": [{"name": "observer", "host": "192.0.2.1", "driver": "snmp_switch", "enabled": True}],
        "ports": [{"source": "observer", "name": f"xe{i}", "if_index": i + 4, "collector_run_id": 1,
                   "last_seen_at": now.isoformat()} for i in (1, 2, 3)],
    }
    pve = {"physicalPorts": {"host": [{"name": f"eth{i}", "source": "Proxmox · sysfs"}
                                    for i in (1, 2, 3)]}}
    asyncio.run(collector._check_confirmed_switch_ports(context, network, pve, now))
    first, second, third = network["ports"]
    assert first["linkCheck"]["state"] == "up" and first["linkCheck"]["speedBps"] == 10**10
    assert "linkCheck" not in second and "linkCheck" not in third
    assert calls == [(*column, 5) for column in (IF_NAME, IF_ADMIN_STATUS, IF_OPER_STATUS, IF_HIGH_SPEED)] + [(*IF_NAME, 6)]


def test_confirmed_switch_port_checks_require_two_observed_ends(monkeypatch):
    import asyncio

    from app import infrastructure_collect as collector

    now = datetime.now(timezone.utc)
    calls = []

    class Transport:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

    async def read(transport, index, name):
        calls.append((index, name))
        return {"state": "up", "speedBps": 10**9}

    monkeypatch.setattr(collector.SnmpTransport, "from_source", lambda _: Transport())
    monkeypatch.setattr(collector, "read_interface_link", read)
    context = {
        "devices": [{"id": f"s{i}", "kind": "switch", "management_ip": f"192.0.2.{i}"} for i in (1, 2, 3)],
        "links": [
            {"relation": "connected_to", "state": {"verified": True},
             "endpoint_a": {"device": "s1", "interface": "Port52"},
             "endpoint_b": {"device": "s2", "interface": "ge21"}},
            {"relation": "connected_to", "state": {"verified": True},
             "endpoint_a": {"device": "s1", "interface": "Slot0/51"},
             "endpoint_b": {"device": "s3", "interface": "ge1"}},
            {"relation": "connected_to", "state": {"verified": False},
             "endpoint_a": {"device": "s1", "interface": "Slot0/15"},
             "endpoint_b": {"device": "s2", "interface": "ge22"}},
        ],
    }
    network = {
        "sources": [{"name": f"s{i}", "host": f"192.0.2.{i}", "driver": "snmp_switch", "enabled": True}
                    for i in (1, 2, 3)],
        "ports": [{"source": source, "name": name, "port_key": f"ifindex:{index}", "if_index": index,
                   "collector_run_id": 1, "last_seen_at": now.isoformat()}
                  for source, name, index in (("s1", "Slot0/52", 52), ("s2", "ge21", 5021),
                                              ("s1", "Slot0/51", 51), ("s1", "Slot0/15", 15), ("s2", "ge22", 5022))],
    }
    asyncio.run(collector._check_confirmed_switch_ports(context, network, {}, now))
    assert set(calls) == {(52, "Slot0/52"), (5021, "ge21")}
    assert sum("linkCheck" in row for row in network["ports"]) == 2


def test_proxmox_backup_checks_match_storage_and_guest_and_expire():
    from app.infrastructure_collect import build_graph
    from app.infrastructure_backup import backup_service_checks, read_proxmox_backup
    from app.infrastructure_map import _map_statuses, _public_node, _public_service_check

    now = datetime.now(timezone.utc)
    ended = int((now - timedelta(hours=26)).timestamp())
    recent = int((now - timedelta(hours=2)).timestamp())

    def task(upid, endtime, status="OK"):
        return {"upid": upid, "node": "pve1", "type": "vzdump", "starttime": endtime - 30,
                "endtime": endtime, "status": status}

    backup = task("UPID:pve1:backup", ended)
    other_storage = task("UPID:pve1:other", recent)
    failed = task("UPID:pve1:failed", recent, "job errors")
    tasks = [backup, other_storage, failed]
    logs = {
        "backup": ["INFO: starting new backup job: vzdump 102 --storage pbs",
                   "INFO: Finished Backup of VM 102 (00:00:30)", "TASK OK"],
        "other": ["INFO: starting new backup job: vzdump 102 --storage local",
                  "INFO: Finished Backup of VM 102 (00:00:30)", "TASK OK"],
        "failed": ["INFO: starting new backup job: vzdump 104 --storage pbs",
                   "ERROR: Backup of VM 104 failed - private details", "TASK ERROR: job errors"],
    }

    def get(path):
        if path == "cluster/backup":
            return [{"type": "vzdump", "enabled": 1, "storage": "pbs", "vmid": "102,104,106"}]
        if "?typefilter=vzdump" in path:
            return tasks
        for name, lines in logs.items():
            if f"%3A{name}/log?" in path:
                return [{"t": line} for line in lines]
        raise AssertionError(path)

    def check():
        observation = read_proxmox_backup(get, ["pve1"], "pbs", now)
        return {row["backupVmid"]: row for row in backup_service_checks(observation, {102: 24, 104: 30, 106: 192}, now)}

    results = check()
    assert [results[vm]["reason"] for vm in (102, 104, 106)] == [
        "backup_overdue", "backup_task_failed", "backup_no_result",
    ]
    assert results[102]["backupCompletedAt"] == datetime.fromtimestamp(ended, timezone.utc).isoformat()
    assert "private details" not in json.dumps(results)
    stale = _public_service_check(results[104], now + timedelta(minutes=6))
    assert stale["stale"] and stale["state"] == "unknown"
    graph = build_graph({"devices": [{"id": "pbs", "name": "PBS", "kind": "backup_server"}]}, {}, {},
                        {"cluster": [], "nodes": [], "guests": [], "at": now.isoformat(),
                         "backup": read_proxmox_backup(get, ["pve1"], "pbs", now)},
                        {"proxmox_backup_monitor": {"asset": "pbs", "storage": "pbs",
                                                    "max_age_hours": {"102": 30, "104": 30, "106": 192}}}, now)
    nodes = {node["id"]: _public_node(node, now) for node in graph["nodes"]}
    nodes["pbs"]["reachability"]["state"] = "reachable"
    _map_statuses(nodes, graph["links"])
    assert nodes["proxmox-pbs-backups"]["mapStatus"] == nodes["pbs"]["mapStatus"] == "warn"
    logs["other"].pop()
    assert check()[102]["reason"] == "backup_no_result"
    logs["other"] = ["INFO: starting new backup job: vzdump 102 --storage pbs", "TASK ERROR: setup failed"]
    assert check()[102]["reason"] == "backup_no_result"


def test_guest_backup_coverage_is_scoped_and_failures_apply_to_the_right_guest():
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import _map_statuses, _public_node

    now = datetime.now(timezone.utc)
    stamp = now.isoformat()
    pve = {"cluster": [], "nodes": [{"node": "pve1", "status": "online"}], "at": stamp,
           "guests": [{"vmid": vmid, "node": "pve1", "name": f"vm-{vmid}", "type": "qemu", "status": "running"}
                      for vmid in (102, 103, 104)],
           "backup": {"guests": {102, 104}, "checkedAt": stamp,
                      "results": {102: {"successful": False, "completedAt": now},
                                  104: {"successful": True, "completedAt": now}}}}
    bindings = {"proxmox_backup_monitor": {"asset": "pbs", "storage": "pbs",
                                           "max_age_hours": {"102": 30, "104": 30}}}
    context = {"devices": [{"id": "pbs", "name": "PBS", "kind": "backup_server"}]}

    def read(at=now):
        graph = build_graph(context, {}, {}, pve, bindings, now)
        nodes = {row["id"]: _public_node(row, at) for row in graph["nodes"]}
        for vmid in (102, 103, 104):
            nodes[f"pve-guest:{vmid}"]["reachability"]["state"] = "reachable"
        _map_statuses(nodes, graph["links"])
        return [nodes[f"pve-guest:{vmid}"] for vmid in (102, 103, 104)]

    failed, outside, healthy = read()
    assert failed["backupCoverage"] == {"storage": "pbs", "serviceId": "proxmox-pbs-backups",
                                        "state": "scheduled", "checkedAt": stamp, "stale": False}
    assert failed["mapStatus"] == "warn"
    assert failed["serviceChecks"][0]["reason"] == "backup_task_failed"
    assert outside["backupCoverage"]["state"] == "not_scheduled" and outside["serviceChecks"] == []
    assert outside["mapStatus"] == healthy["mapStatus"] == "ok"
    pve["backup"]["incomplete"] = True
    assert read()[1]["backupCoverage"]["state"] == "unknown"
    expired = read(now + timedelta(minutes=6))[0]
    assert expired["backupCoverage"]["stale"] and expired["backupCoverage"]["state"] == "unknown"
    assert expired["mapStatus"] == "unknown"


def test_proxmox_port_observer_verifies_target_and_only_updates_inventory_ports(tmp_path, monkeypatch):
    from app import infrastructure_port_ssh as observer
    from app.infrastructure_map import _public_port

    now = datetime.now(timezone.utc)
    nodes = [{"node": "pve1", "status": "online"}, {"node": "pve2", "status": "offline"}]
    ports = [{"name": "eth0", "state": "unknown", "source": "Proxmox", "proxmoxActive": True,
              "checkedAt": now.isoformat()}, {"name": "eth1", "state": "unknown", "source": "Proxmox"}]
    pve = {"nodes": nodes, "physicalPorts": {"pve1": ports}}
    context = {"devices": [
        {"id": "pve1", "kind": "hypervisor", "management_ip": "192.0.2.1"},
        {"id": "pve2", "kind": "hypervisor", "management_ip": "192.0.2.2"},
    ]}
    for name in ("pve-port-ssh-key", "pve-port-known-hosts"):
        (tmp_path / name).touch()
    calls = []
    payload = {"hostname": "pve2", "ports": {"eth0": {"state": "up", "speedMbps": 1000},
                                         "extra0": {"state": "disabled"}}}

    def run(args, **options):
        calls.append(args)
        return observer.subprocess.CompletedProcess(args, 0, stdout=json.dumps(payload).encode())

    monkeypatch.setattr(observer.subprocess, "run", run)
    observer.collect_proxmox_port_states(context, pve, tmp_path)
    assert ports[0]["state"] == "unknown"
    payload["hostname"] = "pve1"
    observer.collect_proxmox_port_states(context, pve, tmp_path)
    assert len(calls) == 2 and all(args[-1] == "ui-vpn-ports@192.0.2.1" for args in calls)
    assert all("StrictHostKeyChecking=yes" in args for args in calls)
    assert [row["name"] for row in ports] == ["eth0", "eth1"]
    public = _public_port(ports[0], datetime.now(timezone.utc))
    assert (public["source"], public["state"], public["speedBps"], public["proxmoxActive"]) == (
        "Proxmox · sysfs", "up", 10**9, True,
    )
    assert ports[1]["state"] == "unknown"


def test_css_root_port_stp_projects_only_fresh_unambiguous_observations():
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import _public_node

    now = datetime.now(timezone.utc)
    stamp = now.isoformat()
    network = {
        "sources": [{"name": "css", "driver": "snmp_switch", "host": "192.0.2.2", "enabled": True}],
        "ports": [{"source": "css", "name": "Port13", "bridge_port": 13, "port_key": "physical:13",
                   "collector_run_id": 1, "last_seen_at": stamp, "oper_status": "up"}],
        "stp_root_paths": {"css": {"rootPortNumber": 13, "designatedBridgeMac": "2c:c8:1b:9c:31:ea",
                                    "designatedPortId": "80:03", "checkedAt": stamp}},
    }

    def read(devices=()):
        graph = build_graph({"devices": devices}, network, {}, {}, {}, now)
        assert graph["links"] == []
        return _public_node(next(node for node in graph["nodes"] if node["name"] == "css"), now)

    assert read()["stpRootPath"] == {
        "localPort": "Port13", "designatedBridgeMac": "2c:c8:1b:9c:31:ea",
        "designatedPortId": "80:03", "checkedAt": stamp,
    }
    bridge = {"id": "root", "kind": "switch", "name": "Root",
              "observed_state": {"rstp": {"bridge_id": "32768.2C:C8:1B:9C:31:EA"}}}
    assert read([bridge])["stpRootPath"]["bridgeDeviceId"] == "root"
    assert "bridgeDeviceId" not in read([bridge, {**bridge, "id": "duplicate"}])["stpRootPath"]
    network["ports"].append({**network["ports"][0], "name": "Port14"})
    assert "stpRootPath" not in read()
    network["ports"].pop()
    network["stp_root_paths"]["css"]["checkedAt"] = (now - timedelta(minutes=6)).isoformat()
    assert "stpRootPath" not in read()


def test_css_root_port_stp_rejects_root_port_change_during_poll():
    import asyncio

    from netctl.snmp.models import CapabilityResult, SnmpVarBind
    from netctl.snmp.outcomes import SnmpOutcome
    from netctl.snmp.stp import read_stp_root_path

    class Transport:
        def __init__(self, last_port):
            self.values = iter([13, bytes.fromhex("80002cc81b9c31ea"), bytes.fromhex("8003"), last_port])

        async def get(self, oid):
            value = next(self.values)
            kind = "octet_string" if isinstance(value, bytes) else "integer"
            return CapabilityResult("", SnmpOutcome.SUCCESS_WITH_ROWS, (SnmpVarBind(oid, kind, value),))

    assert asyncio.run(read_stp_root_path(Transport(13))) == {
        "rootPortNumber": 13, "designatedBridgeMac": "2c:c8:1b:9c:31:ea", "designatedPortId": "80:03",
    }
    assert asyncio.run(read_stp_root_path(Transport(5))) == {}


def test_topology_port_alerts_require_confirmed_pairs_and_fresh_states(tmp_path):
    from app.infrastructure_map import load_infrastructure_map, summarize_topology

    now = datetime.now(timezone.utc)
    stamp = now.isoformat()
    old = (now - timedelta(minutes=26)).isoformat()
    a = {"id": "a", "name": "Switch A", "kind": "Коммутатор", "ports": [
        {"name": "ge1", "state": "up", "speedBps": 10**9, "checkedAt": stamp},
    ]}
    b = {"id": "b", "name": "Switch B", "kind": "Коммутатор", "ports": [
        {"name": "ge2", "state": "up", "speedBps": 10**8, "checkedAt": stamp},
    ]}
    inventory = {"a": "ge1", "b": "ge2", "source": "GitHub", "confirmed": True}
    observed = {**inventory, "source": "LLDP · двустороннее", "at": stamp}
    edge = {"a": "a", "b": "b", "kind": "Сетевое соединение", "confirmed": True,
            "portEvidence": [inventory, observed]}
    path = tmp_path / "map.json"

    def read():
        path.write_text(json.dumps({"schema": 1, "snapshotAt": stamp, "nodes": [a, b], "links": [edge]}),
                        encoding="utf-8")
        graph = load_infrastructure_map(path, now)
        audit = summarize_topology(graph)["topologyAudit"]
        alerts = graph["links"][0].get("portAlerts", [])
        assert audit["portAlertTotal"] == len(alerts)
        assert audit["portAlerts"] == [
            {"a": "a", "b": "b", "nameA": "Switch A", "nameB": "Switch B", **alert} for alert in alerts
        ]
        return alerts

    assert read() == [{"portA": "ge1", "portB": "ge2", "state": "speed_mismatch", "checkedAt": stamp}]
    b["ports"][0].update(state="down")
    assert read() == [{"portA": "ge1", "portB": "ge2", "state": "one_down", "checkedAt": stamp}]
    a["ports"][0].update(checkedAt=old)
    assert read() == [{"portA": "ge1", "portB": "ge2", "state": "port_down",
                       "downSides": ["b"], "checkedAt": stamp}]
    b["ports"][0].update(checkedAt=old)
    assert read() == []
    b["ports"][0].update(checkedAt=stamp)
    edge["kind"] = "Путь по MAC-таблице"
    assert read() == []
    edge["kind"] = "Сетевое соединение"
    inventory["confirmed"] = observed["confirmed"] = False
    assert read() == []


def test_slot_port_alias_requires_matching_snmp_ifindex():
    from app.infrastructure_map import _public_node, index_port_states

    now = datetime.now(timezone.utc)
    port = {"name": "Slot0/52", "key": "ifindex:52", "state": "up",
            "speedBps": 10**9, "checkedAt": now.isoformat()}
    node = _public_node({"ports": [port]}, now)
    assert node["ports"][0]["aliases"] == ["Port52"]
    assert index_port_states([port], now)["port52"]["speedBps"] == 10**9
    for changed in ({**port, "key": "ifindex:51"}, {**port, "name": "Slot1/52"}):
        assert "port52" not in index_port_states([changed], now)


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
    ports[1].update(port_key="physical:24", name="uplink-to-core")
    one_way = {"evidence_type": "fdb_management_mac", "endpoint_a": {"source_id": 1, "port_key": "ge22"},
               "endpoint_b": {"source_id": 2}, "observed_at": at}
    reverse = {"evidence_type": "fdb_management_mac", "endpoint_a": {"source_id": 1},
               "endpoint_b": {"source_id": 2, "port_key": "physical:24"}, "observed_at": earlier}
    evidence = [one_way, reverse]
    network = {"sources": sources, "ports": ports, "links": [
        {"source_a_id": 1, "source_b_id": 2, "state": "confirmed", "evidence": evidence},
    ]}
    path = tmp_path / "graph.json"

    def paired(when=now):
        graph = build_graph({"devices": devices, "links": [declared]}, network, {}, {}, {}, when)
        path.write_text(json.dumps(graph), encoding="utf-8")
        link = next(edge for edge in load_infrastructure_map(path, when)["links"] if {edge["a"], edge["b"]} == {"core", "access"})
        configured = next(p for p in link["portEvidence"] if p["source"] == "GitHub")
        assert configured["pairEvidence"] == "verified_inventory"
        return [p for p in link["portEvidence"] if p["source"] == "SNMP · двусторонний FDB"]

    report, = paired()
    assert {key: report[key] for key in ("a", "b", "at", "confirmed")} == {
        "a": "ge22", "b": "uplink-to-core", "at": earlier, "confirmed": True,
    }
    assert report["pairEvidence"] == "current"
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
    monkeypatch.setattr(probes, "_icmp_check", lambda ip: {"state": "reachable"})

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
    skipped, = node["serviceChecks"]
    assert skipped["skipped"] and skipped["supplemental"] and skipped["reason"] == "probe_target_unconfirmed"


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
        "ports": [{"source": "snr", "port_key": name, "name": name, "oper_status": "up",
                   "speed_bps": speed, "last_seen_at": at} for name, speed in (("po1", 2*10**9), ("ge6", 10**9))],
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
    member = next(p for p in result["portEvidence"] if p["confirmed"])
    assert member["portStates"]["a"]["name"] == "ge6"
    assert member["portStates"]["a"]["speedBps"] == 10**9
    assert "b" not in member["portStates"] and "portComparison" not in member
    assert {key: member["lacp"][key] for key in ("side", "aggregate", "member", "partnerPort")} == {
        "side": "a", "aggregate": "po1", "member": "ge6", "partnerPort": 1,
    }
    assert member["lacp"]["aggregateState"]["speedBps"] == 2*10**9
    expired = link(now + timedelta(hours=1))
    assert not expired["confirmed"] and all("lacp" not in p for p in expired["portEvidence"])
    network["arp"].append({**network["arp"][0], "mac": "02:00:00:00:00:98"})
    assert not link()["confirmed"]
    assert mac not in path.read_text(encoding="utf-8")


def test_lacp_health_warns_on_explicit_link_failure_and_expires_port_evidence(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    mac = "02:00:00:00:00:14"
    devices = [{"id": "pbs", "name": "PBS", "kind": "backup_server", "management_ip": "192.0.2.14"},
               {"id": "snr", "name": "SNR", "kind": "switch", "management_ip": "192.0.2.254"}]
    bindings = {"lacp_links": [{"source": "switch", "asset": "pbs", "aggregate": "po1", "members": ["ge6", "ge7"]}]}
    sources = [{"id": 1, "name": "switch", "enabled": True, "driver": "snmp_switch", "host": "192.0.2.254"}]
    ports = [{"source": "switch", "port_key": name, "name": name, "oper_status": "up", "last_seen_at": at}
             for name in ("ge6", "ge7")]
    report = {**bindings["lacp_links"][0], "expected": 2, "at": at, "members": [
        {"port": "ge6", "partner_port": 1, "mac": mac}, {"port": "ge7", "partner_port": 2, "mac": mac}]}
    network = {"sources": sources, "ports": ports, "lacp": [report],
               "arp": [{"ip": "192.0.2.14", "mac": mac, "last_seen_at": at}]}
    path = tmp_path / "map.json"

    def read(stamp=now):
        context = {"devices": devices, "links": [{"endpoint_a": {"device": "snr", "interface": "po1"},
                    "endpoint_b": {"device": "pbs", "interface": "bond0"}, "relation": "connected_to"}]}
        graph = build_graph(context, network, {}, {}, bindings, now)
        next(node for node in graph["nodes"] if node["id"] == "pbs")["reachability"] = {
            "state": "reachable", "source": "netctl", "method": "ICMP", "checkedAt": at}
        path.write_text(json.dumps(graph), encoding="utf-8")
        node = next(node for node in load_infrastructure_map(path, stamp)["nodes"] if node["id"] == "pbs")
        return node["mapStatus"], node["lacpHealth"][0]

    color, health = read()
    assert (color, health["status"]) == ("ok", "ok")
    assert [member["partnerPort"] for member in health["members"]] == [1, 2]
    network["arp"][0]["last_seen_at"] = (now - timedelta(minutes=6)).isoformat()
    assert read()[0] == "ok"
    network["arp"][0]["last_seen_at"] = (now - timedelta(minutes=9)).isoformat()
    assert read()[0] == "unknown"
    network["arp"][0]["last_seen_at"] = at
    report["members"].pop()
    assert read()[0] == "unknown"
    ports[1]["oper_status"] = "down"
    color, health = read()
    assert (color, health["status"]) == ("warn", "warn")
    assert health["members"][1] == {"name": "ge7", "status": "down", "checkedAt": at}
    assert read(now + timedelta(minutes=6))[0] == "unknown"
    network.clear()
    assert read()[0] == "unknown"


def test_collection_keeps_network_fresh_during_proxmox_api_failure(tmp_path, monkeypatch):
    import hashlib
    import sys
    from urllib.error import URLError
    from app import infrastructure_collect as collector
    from app.infrastructure_map import load_infrastructure_map

    context = tmp_path / "context.yaml"
    context.write_text("devices: []\n", encoding="utf-8")
    path = tmp_path / "graph.json"
    now = datetime.now(timezone.utc)
    stamp = (now - timedelta(minutes=2)).isoformat()
    guest = {"id": "vm", "name": "Directum VM", "kind": "Виртуальная машина", "vmid": 103, "guest": True,
             "pveHost": "pve1", "reachability": {"state": "stopped", "checkedAt": stamp, "source": "Proxmox"}}
    collector.publish_snapshot(path, {
        "schema": 1, "snapshotAt": stamp, "contextSha256": hashlib.sha256(context.read_bytes()).hexdigest(),
        "clusterId": "proxmox:cluster", "nodeOrder": ["pve1"], "nodes": [
            {"id": "proxmox:cluster", "name": "Proxmox", "kind": "Кластер Proxmox"},
            {"id": "pve1", "name": "pve1", "kind": "Гипервизор"}, guest,
        ], "links": [{"a": "pve1", "b": "vm", "kind": "Размещение ВМ", "confirmed": True, "source": "Proxmox"}],
    })

    def unavailable(*args):
        raise URLError("internal exception detail")

    monkeypatch.setattr(collector, "read_proxmox", unavailable)
    monkeypatch.setattr(collector, "load_schema", lambda _: {})
    monkeypatch.setattr(collector, "validate_context", lambda *_: [])
    monkeypatch.setattr(collector, "read_network", lambda *args, **kwargs: {"sources": [
        {"name": "switch", "driver": "snmp_switch", "enabled": 1, "last_status": "success",
         "last_collect_at": now.isoformat()},
    ]})
    monkeypatch.setattr(collector, "build_server_health_view", lambda *_: {})
    monkeypatch.setattr(sys, "argv", ["infrastructure_collect", "--context", str(context), "--schema", str(context),
                                     "--server-health", str(context), "--output", str(path),
                                     "--proxmox-url", "https://pve.example", "--proxmox-token-file", str(context)])
    assert collector.main() == 0
    result = load_infrastructure_map(path)
    nodes = {n["id"]: n for n in result["nodes"]}
    assert result["snapshotAt"] > stamp and result["collectionIssues"] == ["proxmox"]
    assert nodes["observer:switch"]["mapStatus"] == "ok"
    assert nodes["vm"]["vmid"] == 103 and nodes["vm"]["mapStatus"] == "unknown"
    assert not nodes["vm"]["pveHost"]
    assert result["nodeOrder"] == ["pve1"] and result["clusterId"] == "proxmox:cluster"
    assert len(result["links"]) == 1 and not result["links"][0]["confirmed"]
    assert "internal exception detail" not in path.read_text(encoding="utf-8")
    assert collector.main() == 0
    assert any(n["id"] == "vm" for n in load_infrastructure_map(path)["nodes"])
    monkeypatch.setattr(collector, "read_proxmox", lambda *args: {"cluster": [], "nodes": [], "guests": []})
    assert collector.main() == 0
    recovered = load_infrastructure_map(path)
    assert "collectionIssues" not in recovered
    assert all(n["id"] != "vm" for n in recovered["nodes"])


def test_network_observer_failure_keeps_proxmox_and_independent_checks(tmp_path, monkeypatch):
    import sys
    from app import infrastructure_collect as collector
    from app import infrastructure_service_probes as probes
    from app.infrastructure_map import load_infrastructure_map

    context = tmp_path / "context.yaml"
    context.write_text(
        "devices:\n- id: switch\n  kind: switch\n  name: Switch\nservices:\n- id: web\n  name: Web\n",
        encoding="utf-8",
    )
    bindings = tmp_path / "bindings.json"
    bindings.write_text(json.dumps({"service_probes": {"web": [{"type": "http", "ip": "192.0.2.20",
                         "port": 80, "path": "/ready", "body": "ready"}]}}), encoding="utf-8")
    path = tmp_path / "graph.json"
    monkeypatch.setattr(collector, "load_schema", lambda _: {})
    monkeypatch.setattr(collector, "validate_context", lambda *_: [])
    monkeypatch.setattr(collector, "read_proxmox", lambda *args: {
        "cluster": [], "nodes": [{"node": "pve1", "status": "online"}],
        "guests": [{"vmid": 103, "name": "Guest", "node": "pve1", "type": "qemu", "status": "stopped"}],
    })

    def unavailable(*args, **kwargs):
        raise collector.NetctlError("internal netctl details")

    monkeypatch.setattr(collector, "read_network", unavailable)
    monkeypatch.setattr(collector, "build_server_health_view", lambda *_: {})
    monkeypatch.setattr(probes, "_http_probe", lambda _: {"state": "reachable", "httpStatus": 200})
    monkeypatch.setattr(sys, "argv", ["infrastructure_collect", "--context", str(context), "--schema", str(context),
                                     "--server-health", str(context), "--bindings", str(bindings), "--output", str(path),
                                     "--proxmox-url", "https://pve.example", "--proxmox-token-file", str(context)])
    assert collector.main() == 0
    graph = load_infrastructure_map(path)
    assert graph["availability"] == "ready" and graph["collectionIssues"] == ["network_observer"]
    nodes = {n["id"]: n for n in graph["nodes"]}
    assert nodes["switch"]["mapStatus"] == "unknown" and nodes["switch"]["ports"] == []
    assert nodes["pve1"]["mapStatus"] == "ok"
    assert nodes["pve-guest:103"]["reachability"]["state"] == "stopped"
    assert nodes["web"]["serviceChecks"][0]["httpStatus"] == 200
    assert "internal netctl details" not in path.read_text(encoding="utf-8")
    monkeypatch.setattr(collector, "read_network", lambda *args, **kwargs: {"sources": []})
    assert collector.main() == 0
    assert "collectionIssues" not in load_infrastructure_map(path)
    monkeypatch.setattr(collector, "build_server_health_view", lambda *_: {"freshness": "missing", "targets": []})
    assert collector.main() == 0
    incomplete = load_infrastructure_map(path)
    assert incomplete["collectionIssues"] == ["server_observer_unavailable"]
    assert next(n for n in incomplete["nodes"] if n["id"] == "web")["serviceChecks"][0]["httpStatus"] == 200


def test_proxmox_physical_port_inventory_preserves_admin_state_without_carrier(tmp_path, monkeypatch):
    from io import BytesIO
    from urllib.error import HTTPError
    from app import infrastructure_collect as collector
    from app.infrastructure_map import load_infrastructure_map

    token = tmp_path / "pve-token"
    token.write_text("PVEAPIToken=test@pve!monitor=test", encoding="utf-8")
    responses = {
        "cluster/status": [],
        "cluster/resources?type=node": [{"node": "pve1", "status": "online"}, {"node": "pve2", "status": "online"}],
        "cluster/resources?type=vm": [],
        "nodes/pve1/status": {"rootfs": {"avail": 900, "total": 1000}, "swap": {"used": 0, "total": 100},
                              "memory": {"free": 70, "available": 200, "total": 1000}, "private": "ignore"},
        "nodes/pve1/network?type=eth": [
            {"iface": "eno1", "type": "eth", "exists": 1, "active": 1},
            {"iface": "eno2", "type": "eth", "exists": 1},
            {"iface": "eno3", "type": "eth"},
            {"iface": "vmbr0", "type": "bridge", "exists": 1, "active": 1},
        ],
    }

    class Opener:
        def open(self, request, timeout):
            path = request.full_url.split("/api2/json/", 1)[1]
            if path in {"nodes/pve2/network?type=eth", "nodes/pve2/status"}:
                raise HTTPError(request.full_url, 403, "Forbidden", {}, None)
            return BytesIO(json.dumps({"data": responses.get(path, [])}).encode())

    monkeypatch.setattr(collector, "build_opener", lambda *args: Opener())
    pve = collector.read_proxmox("https://pve.example", token, None, set())
    context = {"devices": [{"id": "switch", "name": "Switch", "kind": "switch"},
                           {"id": "pve1", "name": "pve1", "kind": "hypervisor"}], "links": [{
        "endpoint_a": {"device": "switch", "interface": "ge1"},
        "endpoint_b": {"device": "pve1", "interface": "eno1"},
        "relation": "connected_to",
    }]}
    now = datetime.now(timezone.utc)
    path = tmp_path / "graph.json"
    collector.publish_snapshot(path, collector.build_graph(context, {}, {}, pve, {}, now))
    graph = load_infrastructure_map(path, now)
    nodes = {node["id"]: node for node in graph["nodes"]}
    assert [(p["name"], p["proxmoxActive"], p["state"]) for p in nodes["pve1"]["ports"]] == [
        ("eno1", True, "unknown"), ("eno2", False, "unknown"),
    ]
    assert not nodes["pve2"]["ports"]
    assert nodes["pve1"]["resourceCapacity"]["memory"]["availableBytes"] == 200
    assert nodes["pve1"]["mapStatus"] == "ok" and nodes["pve2"]["mapStatus"] == "unknown"
    assert "private" not in json.dumps(pve["nodeStatus"])
    link = next(e for e in graph["links"] if e["kind"] == "Сетевое соединение")
    assert not link["confirmed"]
    report, = link["portEvidence"]
    assert report["portStates"]["b"]["proxmoxActive"] is True
    assert "portComparison" not in report
    aged = load_infrastructure_map(path, now + timedelta(hours=1))
    assert all("proxmoxActive" not in port for node in aged["nodes"] for port in node["ports"])


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


def test_lldp_management_address_requires_matching_inventory_and_host_mac(monkeypatch):
    from app.infrastructure_collect import build_graph
    from app import infrastructure_service_probes as probes
    from app.infrastructure_map import _public_service_check

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
    network["arp"] = [{"ip": address, "mac": mac, "last_seen_at": at}]
    bindings = {"asset_ip_checks": {"remote": address}}
    graph = build_graph(context, network, {}, {}, bindings, now)
    remote = next(node for node in graph["nodes"] if node["id"] == "remote")
    assert remote["reachability"]["state"] == "reachable"
    assert remote["properties"]["Адрес управления по LLDP"] == address
    assert remote["probeTargetIP"] == address
    monkeypatch.setattr(probes, "_icmp_check", lambda ip: {"state": "reachable", "roundTripMs": 0.8})
    probes.apply_service_probes([remote], {"remote": [{"type": "icmp", "ip": address}]})
    assert remote["reachability"]["method"] == "ICMP · LLDP + ARP"
    check = _public_service_check(remote["serviceChecks"][0], datetime.now(timezone.utc))
    assert check["identityCheckedAt"] == at and check["roundTripMs"] == 0.8
    raw_check = remote["serviceChecks"][0]
    stale = _public_service_check({**raw_check, "identityCheckedAt": (now - timedelta(hours=1)).isoformat()},
                                  datetime.now(timezone.utc))
    assert stale["state"] == "unknown" and stale["stale"] and "identityCheckedAt" not in stale
    without_arp = build_graph(context, {**network, "arp": []}, {}, {}, bindings, now)
    assert "probeTargetIP" not in next(node for node in without_arp["nodes"] if node["id"] == "remote")
    context["devices"][0]["management_ip"] = address
    registered = build_graph(context, network, {}, {}, bindings, now)
    target = next(node for node in registered["nodes"] if node["id"] == "remote")
    assert target["reachability"]["state"] == "reachable"
    assert target["probeTargetIP"] == address and target["probeTargetIdentityAt"] == at
    host["mac"] = "02:00:00:00:00:04"
    registered = build_graph(context, network, {}, {}, bindings, now)
    target = next(node for node in registered["nodes"] if node["id"] == "remote")
    assert "reachability" not in target and "probeTargetIP" not in target
    context["devices"][0].pop("management_ip")
    link, = graph["links"]
    assert link["portEvidence"][0]["b"] == "Ge1"
    host["mac"] = "02:00:00:00:00:04"
    graph = build_graph(context, network, {}, {}, bindings, now)
    remote = next(node for node in graph["nodes"] if node["id"] == "remote")
    assert "reachability" not in remote
    assert "probeTargetIP" not in remote

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


def test_downstream_devices_require_the_expected_live_lldp_pair(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map, summarize_topology

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    switch_mac, endpoint_mac = "02:00:00:00:00:03", "02:00:00:00:00:04"
    address = "192.0.2.111"
    context = {"devices": [{"id": "core", "name": "Core", "kind": "switch", "management_ip": "192.0.2.1"},
                           {"id": "poe", "name": "PoE", "kind": "switch", "mac_addresses": [switch_mac]}],
               "links": [{"id": "core-to-poe", "relation": "connected_to", "state": {"verified": True},
                          "endpoint_a": {"device": "core", "interface": "Slot0/51"},
                          "endpoint_b": {"device": "poe", "interface": "Ge1"}}]}
    lldp = {"source": "main", "local_port_key": "ifindex:51", "system_name": "PoE", "chassis_id": switch_mac,
            "port_id": "Ge1", "port_id_subtype": "interface_name", "observed_at": at}
    network = {"sources": [{"id": 1, "name": "main", "host": "192.0.2.1", "driver": "snmp_switch", "enabled": True}],
               "ports": [{"source": "main", "port_key": "ifindex:51", "name": "Slot0/51", "oper_status": "up",
                          "last_seen_at": at, "collector_run_id": 2}],
               "lldp": [lldp], "downstream_fdb": {"core-to-poe": {"source": "main", "at": at,
                                                                    "macs": [switch_mac, endpoint_mac]}},
               "arp": [{"ip": address, "mac": endpoint_mac, "last_seen_at": at}],
               "hosts": [{"ip": address, "mac": endpoint_mac, "last_seen_at": at, "availability": {
                   "checked_at": at, "run_status": "success", "state": "online", "reason": "active_probe",
                   "active_method": "icmp"}}]}
    snapshot = tmp_path / "map.json"

    def read(when=now):
        graph = build_graph(context, network, {}, {}, {"downstream_mac_links": ["core-to-poe"]}, now)
        snapshot.write_text(json.dumps(graph), encoding="utf-8")
        result = load_infrastructure_map(snapshot, when)
        return result, next(n for n in result["nodes"] if n["id"] == "poe")

    graph, node = read()
    downstream = node["downstream"]
    assert downstream["upstreamId"] == "core" and downstream["port"] == "Slot0/51"
    endpoint, = downstream["devices"]
    assert endpoint["mac"] == endpoint_mac and endpoint["ip"] == address
    assert endpoint["reachability"]["state"] == "reachable"
    assert len(graph["nodes"]) == 2 and len(graph["links"]) == 1
    assert summarize_topology(graph)["topologyAudit"]["downstreamSwitches"][0]["devices"] == downstream["devices"]
    context["devices"][1]["management_ip"] = "192.0.2.2"
    network["sources"].append({"id": 2, "name": "remote", "host": "192.0.2.2", "driver": "snmp_switch", "enabled": True})
    network["ports"].append({"source": "remote", "port_key": "ifindex:2", "name": "Ge2", "oper_status": "up",
                             "last_seen_at": at, "collector_run_id": 2})
    sample = network["downstream_fdb"]["core-to-poe"]
    sample["remote"] = {"source": "remote", "readings": [
        {"mac": endpoint_mac, "name": "Ge2", "at": at.replace("+00:00", "Z")},
    ]}
    endpoint, = read()[1]["downstream"]["devices"]
    assert endpoint["switchPort"] == {"name": "Ge2", "checkedAt": at}
    sample["remote"]["readings"].append({"mac": endpoint_mac, "name": "Ge1", "at": at})
    endpoint, = read()[1]["downstream"]["devices"]
    assert "switchPort" not in endpoint
    sample["remote"]["readings"].pop()
    context["devices"][1]["mac_addresses"] = []
    endpoint, = read()[1]["downstream"]["devices"]
    assert endpoint["switchPort"]["name"] == "Ge2"
    context["devices"][1]["mac_addresses"] = [switch_mac]
    del sample["remote"]
    network["arp"].clear()
    endpoint, = read()[1]["downstream"]["devices"]
    assert "ip" not in endpoint and endpoint["reachability"]["state"] == "unknown"
    assert "downstream" not in read(now + timedelta(minutes=26))[1]
    lldp["port_id"] = "Ge2"
    assert "downstream" not in read()[1]


def test_downstream_local_probe_requires_unique_observed_address_and_mac(monkeypatch):
    from app import infrastructure_collect as collector

    now = datetime.now(timezone.utc)
    ip, mac = "192.0.2.113", "02:00:00:00:00:04"
    device = {"mac": mac}
    nodes = [{"downstream": {"devices": [device]}}]
    host = {"ip": ip, "mac": mac, "last_seen_at": now.isoformat()}
    network = {"hosts": [host]}
    probes = []

    def check(address, identity, *, fresh_only=False):
        probes.append((address, identity, fresh_only))
        return True

    monkeypatch.setattr(collector, "_probe_on_link_mac", check)
    collector._check_downstream_addresses(nodes, network, now)
    assert probes == [(ip, mac, True)]
    assert device["ip"] == ip and device["reachability"]["state"] == "reachable"
    assert device["identityCheckedAt"] == device["reachability"]["checkedAt"]
    probes.clear()
    device.clear()
    device["mac"] = mac
    network["arp"] = [{**host, "mac": "02:00:00:00:00:09"}]
    collector._check_downstream_addresses(nodes, network, now)
    assert not probes and device == {"mac": mac}


def test_direct_probe_waits_for_neighbor_revalidation_when_required(monkeypatch):
    from app import infrastructure_collect as collector

    ip, mac = "192.0.2.113", "02:00:00:00:00:04"
    responses = iter(([{"dev": "eth0"}], [{"dst": ip, "lladdr": mac, "state": ["DELAY"]}],
                      [{"dst": ip, "lladdr": mac, "state": ["REACHABLE"]}]))
    waits = []
    monkeypatch.setattr(collector, "probe_icmp", lambda address: address == ip)
    monkeypatch.setattr(collector, "sleep", waits.append)
    monkeypatch.setattr(collector.subprocess, "check_output", lambda *args, **kwargs: json.dumps(next(responses)))
    assert collector._probe_on_link_mac(ip, mac, fresh_only=True)
    assert waits == [6]


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


def test_smb_mount_checks_the_configured_live_share_without_local_fallback(monkeypatch):
    from app import infrastructure_service_probes as probes
    from app.infrastructure_map import _map_statuses, _public_node

    spec = {"type": "smb_mount", "ip": "192.0.2.4", "share": "Soft",
            "mount": "/mnt/share", "component": True}
    mounts = [{"id": 41, "source": "//192.0.2.4/Soft", "target": "/mnt/share", "fstype": "cifs"}]
    reads = []
    replace_mount = False

    def command(args, **kwargs):
        if args[0] == "/usr/bin/findmnt":
            return json.dumps({"filesystems": mounts}).encode()
        assert args == ["/usr/bin/stat", "--cached=never", "--format=%F", "--", "/mnt/share"]
        reads.append(args)
        if replace_mount:
            mounts[0]["id"] += 1
        return b"directory\n"

    monkeypatch.setattr(probes.subprocess, "check_output", command)
    monkeypatch.setattr(probes, "_smb", lambda spec: {"state": "reachable"})

    def check():
        node = {"id": "files", "kind": "Сервис"}
        probes.apply_service_probes([node], {"files": [{"type": "smb", "ip": spec["ip"], "port": 445}, spec]})
        public = _public_node(node, datetime.now(timezone.utc))
        _map_statuses({"files": public}, [])
        return public["mapStatus"], public["serviceChecks"][1]

    status, result = check()
    assert status == "ok" and result["state"] == "reachable" and result["component"]
    assert result["smbShare"] == "//192.0.2.4/Soft"
    replace_mount = True
    status, result = check()
    assert (status, result["reason"]) == ("unknown", "smb_mount_changed")
    mounts[0]["source"] = "//192.0.2.4/Other"
    status, result = check()
    assert (status, result["reason"]) == ("warn", "smb_mount_source")
    mounts[0].update(source="systemd-1", fstype="autofs")
    assert check()[0] == "unknown"
    mounts.clear()
    assert check()[1]["reason"] == "smb_mount_missing"
    assert len(reads) == 2


def test_openvpn_tunnel_checks_kernel_link_and_address_as_required_component(monkeypatch):
    from app import infrastructure_service_probes as probes
    from app.infrastructure_map import _map_statuses, _public_node

    spec = {"type": "openvpn_tunnel", "interface": "tun0", "address": "192.0.2.1/24", "component": True}
    kernel = [{"ifname": "tun0", "flags": ["UP", "LOWER_UP"],
               "linkinfo": {"info_kind": "tun", "info_data": {"type": "tun"}},
               "addr_info": [{"family": "inet", "local": "192.0.2.1", "prefixlen": 24}]}]

    def output(command, *, timeout):
        assert command == ["/usr/sbin/ip", "-j", "-d", "address", "show"]
        assert timeout == probes.TIMEOUT
        return json.dumps(kernel).encode()

    monkeypatch.setattr(probes.subprocess, "check_output", output)
    monkeypatch.setattr(probes, "_openvpn_management",
                        lambda: {"state": "reachable", "daemonReady": True, "sessionCount": 1})

    def check():
        node = {"id": "vpn", "kind": "Сервис"}
        probes.apply_service_probes([node], {"vpn": [{"type": "openvpn_management", "port": 1194}, spec]})
        public = _public_node(node, datetime.now(timezone.utc))
        _map_statuses({"vpn": public}, [])
        return public["mapStatus"], public["serviceChecks"][1]

    status, result = check()
    assert status == "ok" and result["state"] == "reachable" and result["component"]
    assert (result["tunnelInterface"], result["tunnelAddress"]) == ("tun0", "192.0.2.1/24")
    kernel[0]["flags"] = ["UP"]
    status, result = check()
    assert (status, result["state"], result["reason"]) == ("warn", "unreachable", "openvpn_tunnel_down")
    kernel[0]["flags"] = ["UP", "LOWER_UP"]
    kernel[0]["addr_info"][0]["prefixlen"] = 25
    assert check()[1]["reason"] == "openvpn_tunnel_address"
    kernel[0]["linkinfo"]["info_data"]["type"] = "tap"
    assert check()[1]["reason"] == "openvpn_tunnel_kind"
    kernel.clear()
    assert check()[1]["reason"] == "openvpn_tunnel_missing"
    kernel.append("invalid kernel data")
    assert check()[0] == "unknown"


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


def test_switch_vlans_join_current_port_by_unique_ifindex(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    context = {"devices": [{"id": "sw", "name": "Switch", "kind": "switch"}]}
    base = {"source": "core", "collector_run_id": 11, "if_index": 5012}
    membership = {**base, "port_key": "physical:12", "observed_at": at, "vlan_id": 20,
                  "egress": 1, "untagged": 0, "pvid": 0}
    network = {"sources": [{"id": 1, "name": "core", "driver": "snmp_switch",
                            "driver_options": {"intent_stable_id": "sw"}}],
               "ports": [{**base, "port_key": "ifindex:5012", "name": "ge12",
                          "oper_status": "up", "last_seen_at": at}],
               "port_vlans": [membership, {**membership, "vlan_id": 1, "untagged": 1, "pvid": 1},
                              {**membership, "vlan_id": 99, "collector_run_id": 10}],
               "port_fdb_learned": [{**base, "port_key": "ifindex:5012", "observed_at": at,
                                     "learned_mac_count": 2, "partial": 0},
                                    {**base, "port_key": "alternate", "observed_at": at,
                                     "learned_mac_count": 0, "partial": 1}],
               "port_fdb_vlans": [{**base, "port_key": "ifindex:5012", "observed_at": at,
                                   "vlan_id": 30, "learned_mac_count": 2},
                                  {**base, "port_key": "ifindex:5012", "observed_at": at,
                                   "vlan_id": 99, "learned_mac_count": 4, "collector_run_id": 10}]}
    path = tmp_path / "map.json"

    def read(when=now):
        path.write_text(json.dumps(build_graph(context, network, {}, {}, {}, now)), encoding="utf-8")
        return load_infrastructure_map(path, when)["nodes"][0]["ports"]

    assert read()[0]["vlanMemberships"] == {"checkedAt": at, "vlans": [
        {"id": 1, "egress": "untagged", "pvid": True}, {"id": 20, "egress": "tagged", "pvid": False},
    ]}
    assert read()[0]["fdbVlans"] == {"checkedAt": at, "vlans": [{"id": 30, "learnedMacCount": 2}]}
    assert read()[0]["fdbLearned"] == {"checkedAt": at, "learnedMacCount": 2, "partial": False}
    assert "vlanMemberships" not in read(now + timedelta(hours=1))[0]
    assert "fdbVlans" not in read(now + timedelta(hours=1))[0]
    assert "fdbLearned" not in read(now + timedelta(hours=1))[0]
    network["ports"].append({**network["ports"][0], "port_key": "alternate", "name": "ge13"})
    assert all("vlanMemberships" not in port for port in read())
    assert read()[1]["fdbLearned"] == {"checkedAt": at, "learnedMacCount": 0, "partial": True}
    network["port_fdb_learned"][1]["collector_run_id"] = 10
    assert "fdbLearned" not in read()[1]


def test_switch_port_telemetry_requires_matching_current_collection(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    context = {"devices": [{"id": "sw", "name": "Switch", "kind": "switch"}]}
    sample = {"source": "core", "port_key": "physical:7", "collector_run_id": 11, "observed_at": at,
              "sample_interval_seconds": 300, "rx_bps": 250000, "tx_bps": 0, "in_errors_delta": 2}
    network = {"sources": [{"id": 1, "name": "core", "driver": "snmp_switch",
                            "driver_options": {"intent_stable_id": "sw"}}],
               "ports": [{"source": "core", "port_key": "physical:7", "name": "Port7",
                          "collector_run_id": 11, "oper_status": "up", "last_seen_at": at}],
               "port_telemetry": [sample]}
    path = tmp_path / "map.json"

    def read(when=now):
        path.write_text(json.dumps(build_graph(context, network, {}, {}, {}, now)), encoding="utf-8")
        return load_infrastructure_map(path, when)["nodes"][0]["ports"][0]

    assert read()["telemetry"] == {"checkedAt": at, "intervalSeconds": 300,
                                    "rxBps": 250000, "txBps": 0, "rxErrors": 2}
    assert "telemetry" not in read(now + timedelta(minutes=21))
    sample["collector_run_id"] = 10
    assert "telemetry" not in read()


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
    from app.infrastructure_collect import _read_downstream_fdb
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
        conn.executescript("""
            ALTER TABLE switch_ports ADD name TEXT DEFAULT 'Ge23';
            ALTER TABLE switch_ports ADD last_seen_at TEXT DEFAULT '2026-11-11T18:36:04Z';
            ALTER TABLE switch_ports ADD admin_status TEXT DEFAULT 'up';
        """)
        sources = [{"id": 1, "name": "core", "host": "192.0.2.1", "driver": "snmp_switch", "enabled": True}]
        scopes = {"link": ("192.0.2.1", {"interface": "ge23"}, {})}
        assert _read_downstream_fdb(conn, sources, scopes) == {"link": {
            "source": "core", "at": "2026-11-11T18:36:04Z", "macs": ["02:00:00:00:00:23"],
        }}
        conn.execute("UPDATE switch_ports SET name='gigabitEthernet 1/0/23'")
        alias_scope = {"link": ("192.0.2.1", {"interface": "Gi1/0/23"}, {})}
        assert _read_downstream_fdb(conn, sources, alias_scope)["link"]["macs"] == list(macs)
        conn.execute("""INSERT INTO switch_ports VALUES
            (1, 'ifindex:49176', 5, 'up', 'Gi1/0/23', '2026-11-11T18:36:04Z', 'up')""")
        assert _read_downstream_fdb(conn, sources, alias_scope) == {}
        conn.execute("DELETE FROM switch_ports WHERE port_key='ifindex:49176'")
        conn.execute("UPDATE switch_ports SET name='Ge23'")
        conn.executescript("""
            INSERT INTO network_sources VALUES (2, 1);
            INSERT INTO switch_ports VALUES (2, 'ifindex:7', 8, 'up', 'Ge7', '2026-11-11T18:36:04Z', 'up');
            INSERT INTO current_switch_fdb VALUES (2, 'ifindex:7', 7, 8,
                '02:00:00:00:00:23', 1, '2026-11-11T18:36:04Z', 'learned');
        """)
        remote_source = {"id": 2, "name": "peer", "host": "192.0.2.2", "driver": "snmp_switch", "enabled": True}
        remote_scope = {"link": ("192.0.2.1", {"interface": "ge23"}, {"address": "192.0.2.2"})}
        assert _read_downstream_fdb(conn, [*sources, remote_source], remote_scope)["link"]["remote"] == {
            "source": "peer", "readings": [{"mac": "02:00:00:00:00:23", "name": "Ge7", "at": "2026-11-11T18:36:04Z"}],
        }
        conn.executescript("DELETE FROM current_switch_fdb WHERE source_id=2; DELETE FROM switch_ports WHERE source_id=2;")
        conn.execute("UPDATE switch_ports SET last_seen_at='2026-11-11T18:36:05Z'")
        assert _read_downstream_fdb(conn, sources, scopes) == {}
        conn.execute("UPDATE current_switch_fdb SET status='static'")
        assert query_observed_mac_ports(conn, macs, learned_only=True) == []
        assert query_observed_mac_ports(conn, macs) == [report]
        conn.execute("UPDATE switch_ports SET collector_run_id=6")
        assert query_observed_mac_ports(conn, macs) == []
        conn.execute("UPDATE switch_ports SET collector_run_id=5")
        conn.execute("INSERT INTO switch_ports(source_id, port_key, collector_run_id, oper_status) VALUES (1, 'physical:23', 4, 'up')")
        assert query_observed_mac_ports(conn, macs) == [report]
        conn.execute("UPDATE switch_ports SET collector_run_id=5, oper_status='down' WHERE port_key='physical:23'")
        assert query_observed_mac_ports(conn, macs) == []
        conn.execute("UPDATE current_switch_fdb SET port_key='lag:po1', if_index=100001, status='learned'")
        conn.execute("INSERT INTO switch_ports(source_id, port_key, collector_run_id, oper_status) VALUES (1, 'ifindex:100001', 5, 'up')")
        lag, = query_observed_mac_ports(conn, macs, learned_only=True)
        assert lag["port_key"] == "ifindex:100001"


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


def test_configured_asset_fdb_path_is_scoped_and_requires_a_unique_live_port(monkeypatch, tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map
    from app.infrastructure_service_probes import apply_service_probes

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
                   "oper_status": "up", "last_seen_at": at, "collector_run_id": 1}],
        "port_telemetry": [{"source": "access", "port_key": "physical:23", "collector_run_id": 1,
                            "observed_at": at, "sample_interval_seconds": 300, "in_errors_delta": 3}],
        "asset_fdb": [{"source_id": 1, "mac": mac, "port_key": "physical:23", "vlan_id": 1, "observed_at": at},
                      {"source_id": 2, "mac": mac, "port_key": "physical:47", "vlan_id": 1, "observed_at": at}],
    }
    bindings = {"asset_fdb_paths": {"gateway": "access"}, "asset_ip_checks": {"gateway": address}}

    def links(at=now):
        return build_graph(context, network, {}, {}, bindings, at)["links"]

    path, = links()
    assert path["a"] == "observer:access" and path["b"] == "gateway"
    assert path["kind"] == "Путь по MAC-таблице" and path["confirmed"]
    assert path["portEvidence"] == [{"a": "Gi1/0/23", "b": "", "source": "netctl FDB",
                                     "at": at, "confirmed": True, "vlan": 1}]
    monkeypatch.setattr("app.infrastructure_service_probes._icmp_check", lambda ip: {"state": "reachable"})
    graph = build_graph(context, network, {}, {}, bindings, now)
    gateway = next(node for node in graph["nodes"] if node["id"] == "gateway")
    apply_service_probes([gateway], {"gateway": [{"type": "icmp", "ip": address}]})
    assert gateway["reachability"]["method"] == "ICMP · ARP + FDB"
    assert gateway["serviceChecks"][0]["identityCheckedAt"] == at
    snapshot = tmp_path / "map.json"
    snapshot.write_text(json.dumps(graph), encoding="utf-8")
    public = load_infrastructure_map(snapshot)
    observed, = public["links"]
    evidence, = observed["portEvidence"]
    assert evidence["portStates"]["a"]["telemetry"]["rxErrors"] == 3
    assert "pairEvidence" not in evidence
    assert links(now + timedelta(hours=1)) == []
    network["asset_fdb"].append({**network["asset_fdb"][0], "port_key": "physical:24"})
    assert links() == []
    network["asset_fdb"].pop()
    network["ports"][0]["oper_status"] = "down"
    assert links() == []
    network["ports"][0]["oper_status"] = "up"
    network["arp"][0]["mac"] = "02:00:00:00:00:24"
    assert links() == []
    graph = build_graph(context, network, {}, {}, bindings, now)
    assert "probeTargetIP" not in next(node for node in graph["nodes"] if node["id"] == "gateway")


def test_asset_service_can_require_current_fdb_and_arp_identity(monkeypatch, tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map
    from app.infrastructure_service_probes import apply_service_probes

    now = datetime.now(timezone.utc)
    observed = (now - timedelta(minutes=24)).isoformat()
    ip, mac = "192.0.2.22", "02:00:00:00:00:22"
    context = {"devices": [{"id": "recorder", "name": "Recorder", "kind": "video_recorder",
                            "management_ip": ip, "mac_addresses": [mac]}]}
    network = {"sources": [{"id": 1, "name": "switch", "driver": "snmp_switch", "enabled": True}],
               "ports": [{"source": "switch", "port_key": "ifindex:15", "name": "ge15", "oper_status": "up",
                          "last_seen_at": observed}],
               "arp": [{"ip": ip, "mac": mac, "last_seen_at": observed}],
               "asset_fdb": [{"source_id": 1, "mac": mac, "port_key": "ifindex:15", "vlan_id": 1,
                              "observed_at": observed}]}
    bindings = {"asset_fdb_paths": {"recorder": "switch"},
                "asset_services": {"recorder-web": {"asset": "recorder", "label": "Web", "require_network_identity": True}}}
    spec = {"type": "http", "ip": ip, "port": 80, "path": "/login", "body_contains": "login"}
    calls = []

    def probe(probe_spec):
        calls.append(probe_spec)
        return {"state": "reachable", "httpStatus": 200}

    monkeypatch.setattr("app.infrastructure_service_probes._http_probe", probe)
    snapshot = tmp_path / "map.json"

    def read(when=None):
        graph = build_graph(context, network, {}, {}, bindings, now)
        apply_service_probes(graph["nodes"], {"recorder-web": [spec]})
        snapshot.write_text(json.dumps(graph), encoding="utf-8")
        return next(node for node in load_infrastructure_map(snapshot, when)["nodes"] if node["id"] == "recorder-web")

    node = read()
    assert node["mapStatus"] == "ok" and node["serviceChecks"][0]["identityCheckedAt"] == observed
    assert read(now + timedelta(minutes=2))["mapStatus"] == "unknown"
    calls.clear()
    network["asset_fdb"].clear()
    node = read()
    assert calls == []
    assert node["mapStatus"] == "unknown" and node["serviceChecks"][0]["reason"] == "probe_target_unconfirmed"


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
        "sources": [{"name": "main", "driver": "mikrotik_api", "enabled": 1,
                     "driver_options": {"intent_stable_id": "rb"}}],
        "arp": [{"source": "main", "ip": address, "mac": mac, "interface": "bridge-lan", "last_seen_at": at}],
        "router_bridge_hosts": [learned],
        "router_interfaces": [{"source": "main", "name": "ether7", "type": "ether",
                               "running": 1, "disabled": 0, "last_seen_at": at},
                              {"source": "main", "name": "ether9", "type": "ether",
                               "running": 0, "disabled": 1, "last_seen_at": at},
                              {"source": "main", "name": "bridge-lan", "type": "bridge",
                               "running": 1, "disabled": 0, "last_seen_at": at}],
    }
    path = tmp_path / "graph.json"

    def lan(at=now, public_at=now):
        graph = build_graph(context, network, {}, {}, bindings, at)
        path.write_text(json.dumps(graph), encoding="utf-8")
        return [e for e in load_infrastructure_map(path, public_at)["links"] if e["a"] == "rb" and e["b"] == "coordinator"]

    link, = lan()
    assert link["kind"] == "Путь по MAC-таблице" and link["confirmed"]
    expected = {"name": "ether7", "source": "RouterOS", "state": "up",
                "speedBps": None, "checkedAt": at, "stale": False}
    assert link["portEvidence"] == [{"a": "ether7", "b": "", "source": "MikroTik · ARP + FDB", "at": at,
                                     "confirmed": True, "portStates": {"a": expected}}]
    ports = next(node["ports"] for node in load_infrastructure_map(path, now)["nodes"] if node["id"] == "rb")
    assert ports == [expected, {**expected, "name": "ether9", "state": "disabled"}]
    expired = lan(public_at=now + timedelta(hours=1))[0]
    assert not expired["confirmed"]
    assert "portStates" not in expired["portEvidence"][0]
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
    from app.infrastructure_map import _map_statuses, _public_node

    node["reachability"] = {"state": "reachable", "source": "ICMP", "checkedAt": at}
    public = _public_node(node, now)
    _map_statuses({"vpn": public}, [])
    assert public["mapStatus"] == "unknown"
    node["serviceChecks"][1].update(state="unreachable", checkedAt=at)
    public = _public_node(node, now)
    _map_statuses({"vpn": public}, [])
    assert public["mapStatus"] == "warn"


def test_service_availability_expires_using_its_own_probe_evidence():
    from app.infrastructure_map import _map_statuses, _public_node

    now = datetime.now(timezone.utc)
    stamp = now.isoformat()
    stale = (now - timedelta(minutes=6)).isoformat()
    current = (now - timedelta(minutes=1)).isoformat()

    def check(state, at, **extra):
        return {"state": state, "method": "HTTP", "source": "UI_VPN", "checkedAt": at, "required": True, **extra}

    def read(*checks):
        raw = {"id": "app", "kind": "Сервис", "serviceChecks": list(checks),
               "reachability": {"state": "reachable", "source": "Проверка сервиса", "checkedAt": stamp}}
        public = _public_node(raw, now)
        _map_statuses({"app": public}, [])
        return public["reachability"], public["mapStatus"]

    health, color = read(check("reachable", stale), check("unreachable", stamp), check("reachable", stamp, component=True))
    assert health["state"] == "unknown" and color == "unknown"
    health, color = read(check("reachable", current), check("unknown", stamp))
    assert health["state"] == "reachable" and health["checkedAt"] == current and color == "unknown"
    health, color = read(check("unreachable", current), check("unreachable", stamp))
    assert health["state"] == "unreachable" and health["checkedAt"] == current and color == "critical"


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


def test_icmp_via_expected_router_keeps_route_evidence_separate_from_echo(monkeypatch):
    from app import infrastructure_service_probes as probes
    from app.infrastructure_map import _public_service_check

    target, gateway = "192.0.2.19", "192.0.2.1"
    route = {"dst": target, "gateway": gateway, "dev": "ens18", "prefsrc": "192.0.2.30"}
    calls = []

    def route_output(command, **kwargs):
        assert command == ["/usr/sbin/ip", "-j", "-4", "route", "get", target]
        return json.dumps([route]).encode()

    def ping(address):
        calls.append(address)
        return {"state": "unknown", "reason": "icmp_no_echo_reply"}

    monkeypatch.setattr(probes.subprocess, "check_output", route_output)
    monkeypatch.setattr(probes, "_icmp_check", ping)

    def check():
        node = {"id": "vpn", "kind": "Сервис"}
        probes.apply_service_probes([node], {"vpn": [
            {"type": "icmp", "ip": target, "route_via": gateway, "supplemental": True},
        ]})
        return _public_service_check(node["serviceChecks"][0], datetime.now(timezone.utc))

    observed = check()
    assert observed["state"] == "unknown" and observed["reason"] == "icmp_no_echo_reply"
    assert observed["localRoute"] == {"state": "reachable", "gateway": gateway, "expectedGateway": gateway,
                                      "interface": "ens18", "sourceIP": "192.0.2.30"}
    route["gateway"] = "192.0.2.254"
    different = check()
    assert different["state"] == "unknown" and different["reason"] == "icmp_route_mismatch"
    assert different["localRoute"]["state"] == "unreachable"
    assert calls == [target]


def test_wireguard_policy_needs_fresh_kernel_route_mark_and_handshake(tmp_path, monkeypatch):
    from app import infrastructure_service_probes as probes
    from app.infrastructure_map import _public_service_check

    now = datetime.now(timezone.utc)
    report = tmp_path / "policy.json"
    facts = {"checkedAt": now.isoformat(), "markers": {"ens18.50": 1},
             "wireguard": {"wg0": {"peerCount": 1, "latestHandshake": int(now.timestamp()) - 15}}}
    route = {"dst": "192.0.2.1", "from": "172.16.50.1", "iif": "ens18.50",
             "dev": "wg0", "table": "123", "mark": 1, "flags": []}
    monkeypatch.setattr(probes.subprocess, "check_output", lambda *args, **kwargs: json.dumps([route]).encode())
    spec = {"type": "wireguard_policy", "interface": "wg0", "ingress": "ens18.50", "mark": 1, "table": 123,
            "peer": "172.16.50.1", "report": str(report)}

    def read():
        report.write_text(json.dumps(facts), encoding="utf-8")
        node = {"id": "policy", "kind": "Сервис"}
        probes.apply_service_probes([node], {"policy": [spec]})
        return _public_service_check(node["serviceChecks"][0], datetime.now(timezone.utc))

    check = read()
    assert check["state"] == "reachable" and check["wireguardPolicy"]["markerConfirmed"]
    assert check["wireguardPolicy"]["routeConfirmed"] and check["wireguardPolicy"]["peerCount"] == 1
    facts["wireguard"]["wg0"]["latestHandshake"] = int(now.timestamp()) - 310
    assert read()["reason"] == "wireguard_handshake_unconfirmed"
    facts["markers"]["ens18.50"] = 2
    assert read()["reason"] == "wireguard_mark_mismatch"
    route["dev"] = "ens18"
    assert read()["reason"] == "wireguard_route_mismatch"


def test_wireguard_report_rejects_ambiguous_marking_and_exports_only_handshake_metadata():
    import runpy
    from pathlib import Path

    report = runpy.run_path(str(Path(__file__).resolve().parents[1] / "deploy" / "openvpn-policy-report.py"))
    prerouting = ["-P PREROUTING ACCEPT", "-A PREROUTING -j VPN_POLICY_MARK"]
    rules = ["-N VPN_POLICY_MARK", "-A VPN_POLICY_MARK -i ens18.50 -j MARK --set-xmark 0x1/0xffffffff",
             "-A VPN_POLICY_MARK -s 192.0.2.9/32 -i tun0 -j QUEST_WG"]
    assert report["markers"](prerouting, rules) == {"ens18.50": 1}
    assert report["markers"](prerouting, [*rules, "-A VPN_POLICY_MARK -i ens+ -j DROP"]) is None
    assert report["markers"](prerouting, [*rules, "-A VPN_POLICY_MARK -i ens18.50 -j RETURN"]) == {}
    assert report["handshakes"](["wg0\tprivate-output-placeholder\t123"]) == {
        "wg0": {"peerCount": 1, "latestHandshake": 123},
    }


def test_local_vlan_probe_requires_expected_link_address_and_route(monkeypatch):
    from app import infrastructure_service_probes as probes
    from app.infrastructure_map import _public_service_check

    address = [{"ifname": "ens18.50", "flags": ["UP", "LOWER_UP"],
                "linkinfo": {"info_kind": "vlan", "info_data": {"id": 50}},
                "addr_info": [{"family": "inet", "local": "192.0.2.2", "prefixlen": 30}]}]
    route = [{"dst": "192.0.2.1", "from": "192.0.2.2", "dev": "ens18.50"}]
    pings = []
    monkeypatch.setattr(probes.subprocess, "check_output",
                        lambda args, **kwargs: json.dumps(address if "address" in args else route).encode())

    def ping(ip, *, source_ip=None, interface=None):
        pings.append((ip, source_ip, interface))
        return probes.subprocess.CompletedProcess([], 0, stdout=b"64 bytes from 192.0.2.1: icmp_seq=1 ttl=64 time=0.3 ms")

    monkeypatch.setattr(probes, "_ping", ping)
    spec = {"type": "vlan_transit", "interface": "ens18.50", "vlan": 50, "address": "192.0.2.2/30", "ip": "192.0.2.1"}

    def read():
        node = {"id": "transit", "kind": "Сервис"}
        probes.apply_service_probes([node], {"transit": [spec]})
        return _public_service_check(node["serviceChecks"][0], datetime.now(timezone.utc))

    check = read()
    assert (check["state"], check["roundTripMs"], check["vlanTransit"]) == (
        "reachable", 0.3, {"interface": "ens18.50", "id": 50, "localAddress": "192.0.2.2/30"},
    )
    assert pings == [("192.0.2.1", "192.0.2.2", "ens18.50")]
    route[0]["dev"] = "ens18"
    assert read()["reason"] == "vlan_route_mismatch"
    address[0]["linkinfo"]["info_data"]["id"] = 51
    assert read()["reason"] == "vlan_id_mismatch"
    assert len(pings) == 1


def test_tagged_transit_is_excluded_from_physical_topology_and_uses_canonical_endpoints(tmp_path):
    from app.infrastructure_collect import _local_vlan_probe_specs, build_graph
    from app.infrastructure_map import load_infrastructure_map, summarize_topology

    now = datetime.now(timezone.utc)
    transit = {"id": "policy", "relation": "connected_to", "state": {"verified": True},
               "endpoint_a": {"device": "remote", "interface": "vlan02", "address": "192.0.2.1/30"},
               "endpoint_b": {"device": "local", "interface": "ens18.50", "address": "192.0.2.2/30"},
               "vlan": {"id": 50, "mode": "tagged_transit"}}
    context = {"devices": [{"id": key, "name": key, "kind": "server"} for key in ("local", "remote")],
               "links": [transit]}
    specs = _local_vlan_probe_specs(context, {"policy": "local"})
    assert specs["transit:policy"]["ip"] == "192.0.2.1"
    graph = build_graph(context, {}, {}, {}, {}, now, local_vlan_probes=specs)
    path = tmp_path / "map.json"
    path.write_text(json.dumps(graph), encoding="utf-8")
    public = load_infrastructure_map(path, now)
    audit = summarize_topology(public)["topologyAudit"]
    assert not any(audit["directLinks"].values())
    link = next(edge for edge in public["links"] if edge["kind"] == "Транзитный сегмент")
    proof, = link["portEvidence"]
    assert (proof["a"], proof["b"], proof["vlan"]) == ("vlan02", "ens18.50", 50)
    assert "pairEvidence" not in proof
    transit["endpoint_b"]["address"] = "192.0.2.2/24"
    assert _local_vlan_probe_specs(context, {"policy": "local"}) == {}


def test_icmp_diagnostics_distinguish_echo_silence_and_probe_error(monkeypatch):
    from subprocess import CompletedProcess, TimeoutExpired
    from app import infrastructure_service_probes as probes
    from app.infrastructure_map import _public_service_check

    readings = {
        "192.0.2.1": (0, b"64 bytes from 192.0.2.1: icmp_seq=1 ttl=64 time=0.401 ms\n"),
        "192.0.2.2": (1, b""),
        "192.0.2.3": (1, b"From 192.0.2.254 icmp_seq=1 Destination Host Unreachable\n"),
        "192.0.2.4": (2, b"raw output must not be public"),
    }

    def run(command, **kwargs):
        assert kwargs["env"]["LC_ALL"] == "C"
        if command[-1] == "192.0.2.5":
            raise TimeoutExpired(command, 3)
        code, output = readings[command[-1]]
        return CompletedProcess(command, code, stdout=output)

    monkeypatch.setattr(probes.subprocess, "run", run)
    nodes = [{"id": key, "kind": "Сервис"} for key in (*readings, "192.0.2.5")]
    probes.apply_service_probes(nodes, {
        node["id"]: [{"type": "icmp", "ip": node["id"], "supplemental": True}] for node in nodes
    })
    now = datetime.now(timezone.utc)
    checks = [_public_service_check(node["serviceChecks"][0], now) for node in nodes]
    assert all("reachability" not in node for node in nodes)
    assert all(check["supplemental"] is True for check in checks)
    assert [(c["state"], c.get("reason")) for c in checks] == [
        ("reachable", None), ("unknown", "icmp_no_echo_reply"), ("unknown", "icmp_unreachable"),
        ("unknown", "icmp_probe_error"), ("unknown", "icmp_probe_error"),
    ]
    assert checks[0]["roundTripMs"] == 0.401
    assert checks[2]["errorSource"] == "192.0.2.254"
    assert "raw output" not in json.dumps(checks)


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
            self.headers = [line for line in request.split(b"\r\n") if line.startswith((b"Via:", b"Call-ID:", b"CSeq:"))]
            self.sent_final = False

        def recv(self, size):
            if len(self.requests) <= self.drop_count:
                raise TimeoutError
            if self.code == b"refused":
                raise ConnectionRefusedError
            if self.before_final:
                code, headers = self.before_final.pop(0)
                return b"\r\n".join([b"SIP/2.0 " + code, *headers(self.headers), b"", b""])
            if self.code is None or self.sent_final:
                raise TimeoutError
            self.sent_final = True
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
    wire.before_final = []
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
        assert public["attempts"] == len(wire.requests) == (3 if code is None or not match else 1)
    node["serviceChecks"][-1].update(reason="arbitrary output", responseCode=900, attempts=4)
    public = _public_node(node, datetime.now(timezone.utc))["serviceChecks"][-1]
    assert "reason" not in public and "responseCode" not in public and "attempts" not in public
    wire.requests, wire.drop_count = [], 1
    wire.code, wire.match, wire.offender = b"200 OK", True, None
    probes.apply_service_probes([node], {"pbx": [spec]})
    result = _public_node(node, datetime.now(timezone.utc))["serviceChecks"][-1]
    assert result["state"] == "reachable" and result["attempts"] == 2
    assert len(wire.requests) == 2 and wire.requests[0] == wire.requests[1]

    wire.requests, wire.drop_count = [], 0
    wire.before_final = [
        (b"200 OK", lambda headers: [b"v: SIP/2.0/UDP 192.0.2.14;branch=z9hG4bKunrelated", *headers[1:]]),
        (b"100 Trying", lambda headers: headers),
    ]
    wire.code = b"503 Service Unavailable"
    probes.apply_service_probes([node], {"pbx": [spec]})
    result = _public_node(node, datetime.now(timezone.utc))["serviceChecks"][-1]
    assert (result["state"], result["responseCode"], result["attempts"]) == ("unreachable", 503, 1)

    wire.requests = []
    wire.before_final = [(b"100 Trying", lambda headers: headers)]
    wire.code = None
    probes.apply_service_probes([node], {"pbx": [spec]})
    result = _public_node(node, datetime.now(timezone.utc))["serviceChecks"][-1]
    assert (result["state"], result["responseCode"], result["attempts"]) == ("unknown", 100, 3)


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


def test_service_audit_shares_map_status_and_reports_required_check_gaps(tmp_path, monkeypatch):
    path = tmp_path / "infrastructure.json"
    monkeypatch.setenv("INFRASTRUCTURE_MAP_SNAPSHOT_PATH", str(path))
    now = datetime.now(timezone.utc)
    stamp = now.isoformat()
    path.write_text(json.dumps({
        "schema": 1, "snapshotAt": stamp,
        "nodes": [
            {"id": "vm", "name": "VM", "kind": "Сервер"},
            {"id": "svc", "name": "Directum", "kind": "Сервис",
             "reachability": {"state": "reachable", "checkedAt": stamp},
             "sources": [{"name": "Server Observer", "at": stamp}],
             "requiredObserverChecks": ["c_disk_free", "iis_active"],
             "checks": [{"name": "c_disk_free", "status": "critical"}],
             "serviceChecks": [
                 {"method": "HTTP", "source": "UI_VPN", "state": "reachable", "required": True, "checkedAt": stamp},
                 {"method": "DNS", "source": "UI_VPN", "state": "unknown", "supplemental": True, "checkedAt": stamp},
                 {"method": "HTTPS", "source": "UI_VPN", "state": "reachable", "required": True,
                  "checkedAt": (now - timedelta(minutes=10)).isoformat()},
             ]},
            {"id": "vipnet", "name": "ViPNet", "kind": "Сервис",
             "serviceChecks": [
                 {"method": "Маршрут", "source": "UI_VPN", "state": "reachable", "required": True,
                  "component": True, "checkedAt": stamp},
                 {"method": "ICMP", "source": "UI_VPN", "state": "unknown", "supplemental": True,
                  "checkedAt": stamp, "reason": "icmp_no_echo_reply"},
             ]},
        ],
        "links": [{"a": "vm", "b": "svc", "kind": "Цель проверки", "confirmed": True}],
    }), encoding="utf-8")
    client, headers, _ = make_client(tmp_path, monkeypatch)
    url = "/api/v1/network/infrastructure"
    response = client.get(url + "?view=services", headers=headers)
    assert response.status_code == 200
    graph = response.json()["infrastructure"]
    assert "nodes" not in graph and "links" not in graph
    audit = graph["serviceAudit"]
    assert audit["total"] == 2 and audit["counts"] == {"critical": 0, "warn": 1, "unknown": 1, "ok": 0}
    row, vipnet = audit["services"]
    full = client.get(url, headers=headers).json()["infrastructure"]
    assert row["id"] == "svc" and row["status"] == full["nodes"][1]["mapStatus"] == "warn"
    assert row["hosts"] == ["vm"]
    assert row["requiredChecks"] == {"passed": 1, "failed": 1, "unconfirmed": 2}
    assert {(c["check"], c["status"], c["stale"]) for c in row["issues"]} == {
        ("c_disk_free", "critical", False), ("iis_active", "unknown", False), ("HTTPS", "unknown", True),
    }
    assert vipnet["requiredChecks"] == {"passed": 1, "failed": 0, "unconfirmed": 0}
    hint, = vipnet["issues"]
    assert hint["check"] == "ICMP" and hint["required"] is False and hint["reason"] == "icmp_no_echo_reply"
    assert response.headers["cache-control"] == "no-store"


def test_topology_audit_surfaces_pending_declared_ports_without_promoting_mac_paths(tmp_path, monkeypatch):
    path = tmp_path / "infrastructure.json"
    monkeypatch.setenv("INFRASTRUCTURE_MAP_SNAPSHOT_PATH", str(path))
    now = datetime.now(timezone.utc).isoformat()
    path.write_text(json.dumps({
        "schema": 1, "snapshotAt": now,
        "nodes": [{"id": "snr", "name": "SNR", "kind": "Коммутатор"},
                  {"id": "pve", "name": "pve1", "kind": "Гипервизор", "ports": [{"name": "enp2s0"}]}],
        "links": [
            {"a": "snr", "b": "pve", "kind": "Сетевое соединение", "confirmed": True, "portEvidence": [
                {"a": "xe3", "b": "vm_net_10g", "source": "GitHub", "confirmed": True},
                {"a": "xe3", "b": "ens7f1", "source": "netctl FDB + Proxmox", "confirmed": True, "at": now},
                {"a": "ge12", "b": "management_1g", "source": "GitHub", "confirmed": False},
                {"a": "xe3", "b": "enp2s0", "source": "GitHub", "confirmed": False},
            ]},
            {"a": "pve", "b": "snr", "kind": "Путь по MAC-таблице", "confirmed": True, "portEvidence": [
                {"a": "enp134s0", "b": "ge12", "source": "netctl FDB + Proxmox", "confirmed": True, "at": now},
            ]},
        ],
    }), encoding="utf-8")
    client, headers, _ = make_client(tmp_path, monkeypatch)
    response = client.get("/api/v1/network/infrastructure?view=topology", headers=headers)
    assert response.status_code == 200
    graph = response.json()["infrastructure"]
    assert "nodes" not in graph and "links" not in graph
    audit = graph["topologyAudit"]
    assert audit["directLinks"] == {"current": 1, "verifiedInventory": 0, "unconfirmed": 0}
    assert audit["pendingTotal"] == 2
    pending, mismatch = audit["pending"]
    assert (pending["a"], pending["b"], pending["portA"], pending["portB"]) == ("snr", "pve", "ge12", "management_1g")
    observed, = pending["observedPaths"]
    assert (observed["portA"], observed["portB"]) == ("ge12", "enp134s0")
    assert mismatch["portB"] == "enp2s0" and mismatch["observedPaths"] == []


def test_reciprocal_mac_path_shows_fresh_stp_evidence_without_confirming_cable(tmp_path):
    from app.infrastructure_map import RECIPROCAL_MAC_SOURCE, load_infrastructure_map, summarize_topology

    now = datetime.now(timezone.utc)
    stamp = now.isoformat()
    path = tmp_path / "infrastructure.json"
    stp = {"localPort": "Port13", "designatedBridgeMac": "2c:c8:1b:9c:31:ea",
           "designatedPortId": "80:03", "checkedAt": stamp, "bridgeDeviceId": "root"}
    switch = {"id": "css", "name": "CSS", "kind": "Коммутатор", "stpRootPath": stp,
              "ports": [{"name": "Port13", "state": "up", "checkedAt": stamp}]}
    declared = {"a": "Port13", "b": "Gi1/22", "source": "GitHub", "confirmed": False}
    observed = {**declared, "source": RECIPROCAL_MAC_SOURCE, "confirmed": True, "at": stamp}
    edges = [{"a": "css", "b": "tp", "kind": "Сетевое соединение", "portEvidence": [declared]},
             {"a": "css", "b": "tp", "kind": "Путь по MAC-таблице", "confirmed": True,
              "portEvidence": [observed]}]

    def read(at=now):
        path.write_text(json.dumps({"schema": 1, "snapshotAt": stamp, "links": edges, "nodes": [switch,
                                    {"id": "tp", "name": "TP", "kind": "Коммутатор"},
                                    {"id": "root", "name": "Root", "kind": "Маршрутизатор"}]}), encoding="utf-8")
        return load_infrastructure_map(path, at)

    graph = read()
    direct, learned = graph["links"]
    assert direct["confirmed"] is False
    proof, = learned["portEvidence"]
    assert "pairEvidence" not in proof
    assert proof["stpPaths"] == [{**stp, "deviceId": "css"}]
    pending, = summarize_topology(graph)["topologyAudit"]["pending"]
    assert pending["observedPaths"][0]["stpPaths"] == proof["stpPaths"]
    assert "stpPaths" not in read(now + timedelta(minutes=6))["links"][1]["portEvidence"][0]
    observed["a"] = "Port14"
    assert "stpPaths" not in read()["links"][1]["portEvidence"][0]


def test_agent_audit_keeps_unbound_mac_matches_diagnostic_and_redacts_identity(tmp_path, monkeypatch):
    from app import api

    path = tmp_path / "infrastructure.json"
    monkeypatch.setenv("INFRASTRUCTURE_MAP_SNAPSHOT_PATH", str(path))
    at = datetime.now(timezone.utc).isoformat()
    keys = ("mac-020000000001", "mac-020000000002")
    path.write_text(json.dumps({"schema": 1, "snapshotAt": at, "nodes": [
        {"id": f"vm:{index}", "name": f"VM {index}", "guest": True, "vmid": index,
         "kind": "Виртуальная машина", "agentMatchKeys": [key],
         "sources": [{"name": "Proxmox", "status": "ok", "at": at, "label": "Запущена"}]}
        for index, key in enumerate(keys, 1)
    ]}), encoding="utf-8")

    class Adapter:
        def list_agent_network_identities(self):
            return [{"id": str(index), "baseline_mac_keys": [key], "online": True,
                     "last_seen_at": at, "baseline_collected_at": at}
                    for index, key in enumerate([keys[0], keys[1], keys[1]])]

        def close(self):
            pass

    monkeypatch.setattr(api, "get_endpoint_context_adapter", Adapter)
    client, headers, _ = make_client(tmp_path, monkeypatch)
    regular = client.get("/api/v1/network/infrastructure", headers=headers).json()["infrastructure"]
    assert all(n["mapStatus"] == "unknown" and "agentMatchKeys" not in n for n in regular["nodes"])
    response = client.get("/api/v1/network/infrastructure?view=agents", headers=headers)
    assert response.status_code == 200
    assert all(key not in response.text for key in keys)
    result = response.json()["infrastructure"]["agentAudit"]
    assert (result["eligible"], result["matched"], result["ambiguous"]) == (2, 1, 1)
    matched, ambiguous = result["guests"]
    assert matched == {"id": "vm:1", "name": "VM 1", "vmid": 1, "state": "matched",
                       "registrations": 1, "presence": "online", "lastSeenAt": at}
    assert ambiguous["state"] == "ambiguous" and "lastSeenAt" not in ambiguous


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


def test_auto_guest_arp_checks_use_unique_local_ip_and_prefer_the_newer_result(monkeypatch):
    from app import infrastructure_collect as collector

    now = datetime.now(timezone.utc)
    earlier = (now - timedelta(minutes=1)).isoformat()
    ip, mac = "192.0.2.21", "02:00:00:00:00:03"
    pve = {"at": earlier, "cluster": [], "nodes": [],
           "guests": [{"vmid": 108, "node": "pve1", "type": "qemu", "status": "running"}],
           "configs": {"108": {"net0": f"virtio={mac},bridge=vmbr0"}}}
    arp = {"ip": ip, "mac": mac, "last_seen_at": earlier}
    host = {"ip": ip, "mac": mac, "availability": {"state": "online", "reason": "active_probe",
            "active_method": "icmp", "checked_at": earlier, "run_status": "success"}}
    network = {"arp": [arp], "hosts": [host]}
    calls = []
    monkeypatch.setattr(collector, "_probe_on_link_mac", lambda address, mac: calls.append((address, mac)) or True)

    def collect(configured=None):
        return collector._collect_guest_arp_probes(pve, network, configured or {}, now, auto_on_link=True)

    assert collector._collect_guest_arp_probes(pve, network, {}, now) == {}
    network["guest_arp_probes"] = collect()
    graph = collector.build_graph({}, network, {}, pve, {}, datetime.now(timezone.utc))
    node = next(row for row in graph["nodes"] if row.get("vmid") == 108)
    assert node["reachability"]["source"] == "UI_VPN"
    assert node["properties"]["IP проверки по ARP"] == ip
    assert calls == [(ip, mac)]
    assert collect({"108": "192.0.2.99"}) == {}
    network["arp"].append({**arp, "ip": "192.0.2.22"})
    assert collect() == {}
    network["arp"].pop()
    pve["at"] = (now - timedelta(hours=1)).isoformat()
    assert collect() == {}
    assert calls == [(ip, mac)]


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
    monkeypatch.setattr(collector, "_probe_on_link_mac", lambda *_: False)
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
