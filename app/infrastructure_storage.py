"""Read the status of configured local VM datastores from each hypervisor."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.error import HTTPError
from urllib.parse import quote

from .infrastructure_map import INTERFACE_NAME, LOCAL_STORAGE_METHOD, LOCAL_STORAGE_TYPES, PVE_STORAGE_ID


def read_local_storage_checks(get, nodes: set[str], stores: object) -> dict[str, list[dict]]:
    if not isinstance(stores, dict) or not 1 <= len(stores) <= 6 or not all(
        isinstance(key, str) and PVE_STORAGE_ID.fullmatch(key) and kind in LOCAL_STORAGE_TYPES
        for key, kind in stores.items()
    ):
        return {}

    def read(node):
        rows, missing_reason = [], "pve_storage_unconfirmed"
        try:
            rows = get(f"nodes/{quote(node, safe='')}/storage")
        except HTTPError as exc:
            if exc.code == 403:
                missing_reason = "pve_storage_permission"
            exc.close()
        except (OSError, ValueError, KeyError):
            pass

        observed = {}
        for row in rows if isinstance(rows, list) else ():
            if isinstance(row, dict) and isinstance(key := row.get("storage"), str) and key in stores:
                observed.setdefault(key, []).append(row)
        checked_at = datetime.now(timezone.utc).isoformat()
        checks = []
        for key, kind in sorted(stores.items()):
            matches = observed.get(key, [])
            detail = {"id": key, "node": node, "type": kind}
            state, reason, required = "unknown", missing_reason, True
            if len(matches) == 1 and matches[0].get("type") == kind and matches[0].get("shared") in (0, False):
                row = matches[0]
                enabled, active = (row.get(field) if type(row.get(field)) in (bool, int) else None
                                   for field in ("enabled", "active"))
                if enabled == 0:
                    reason, required = "pve_storage_excluded", False
                elif enabled == 1 and active == 0:
                    state, reason = "unreachable", "pve_storage_inactive"
                elif enabled == active == 1:
                    state, reason = "reachable", ""
                    detail.update(totalBytes=row.get("total"), usedBytes=row.get("used"), availableBytes=row.get("avail"))
            checks.append({"source": "Proxmox", "method": LOCAL_STORAGE_METHOD, "state": state,
                           "reason": reason, "required": required, "component": True,
                           "checkedAt": checked_at, "localStorage": detail})
        return node, checks

    valid_nodes = sorted(node for node in nodes if isinstance(node, str) and INTERFACE_NAME.fullmatch(node))
    with ThreadPoolExecutor(max_workers=6) as pool:
        return dict(pool.map(read, valid_nodes))
