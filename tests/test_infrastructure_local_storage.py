from datetime import datetime, timedelta, timezone
from urllib.error import HTTPError

from app.infrastructure_collect import build_graph
from app.infrastructure_map import _map_statuses, _public_node


def test_local_storage_checks_distinguish_failures_disabled_and_missing():
    from app.infrastructure_storage import read_local_storage_checks

    stores = {"main-zfs": "zfspool", "local-lvm": "lvmthin"}
    inventory = [
        {"storage": "main-zfs", "type": "zfspool", "shared": 0, "enabled": 1, "active": 0},
        {"storage": "local-lvm", "type": "lvmthin", "shared": 0, "enabled": 1, "active": 1,
         "total": 500, "used": 350, "avail": 150},
        {"storage": "pbs", "type": "pbs", "enabled": 1, "active": 0, "shared": 1},
    ]

    def get(path):
        if path == "nodes/pve1/storage":
            return inventory
        if path == "nodes/pve2/storage":
            return [{**inventory[0], "enabled": 0}]
        if path == "nodes/pve3/storage":
            raise HTTPError(path, 403, "Forbidden", {}, None)
        raise AssertionError(path)

    checks = read_local_storage_checks(get, {"pve1", "pve2", "pve3"}, stores)
    now = datetime.now(timezone.utc)
    graph = build_graph({}, {}, {},
                        {"cluster": [], "nodes": [{"node": node, "status": "online"} for node in checks],
                         "guests": [], "at": now.isoformat(), "localStorageChecks": checks}, {}, now)
    nodes = {node["id"]: _public_node(node, now) for node in graph["nodes"]}
    _map_statuses(nodes, graph["links"])
    report = {key: {check["localStorage"]["id"]: check for check in nodes[key]["serviceChecks"]} for key in checks}
    assert set(report["pve1"]) == set(stores)
    assert report["pve1"]["main-zfs"]["state"] == "unreachable"
    assert report["pve1"]["local-lvm"]["localStorage"] == {
        "id": "local-lvm", "node": "pve1", "type": "lvmthin", "totalBytes": 500, "usedBytes": 350, "availableBytes": 150,
    }
    assert not report["pve2"]["main-zfs"].get("required")
    assert report["pve2"]["main-zfs"]["reason"] == "pve_storage_excluded"
    assert report["pve2"]["local-lvm"]["state"] == "unknown"
    assert report["pve3"]["local-lvm"]["reason"] == "pve_storage_permission"
    assert [nodes[node]["mapStatus"] for node in ("pve1", "pve2", "pve3")] == ["warn", "unknown", "unknown"]
    stale = _public_node(next(node for node in graph["nodes"] if node["id"] == "pve1"), now + timedelta(hours=1))
    assert all(check["stale"] and "availableBytes" not in check["localStorage"] for check in stale["serviceChecks"])
