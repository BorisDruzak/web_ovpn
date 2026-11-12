"""Project bounded Proxmox vzdump results without publishing task logs."""

from __future__ import annotations

import re
import shlex
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from itertools import takewhile
from time import monotonic
from urllib.parse import quote

from .infrastructure_map import BACKUP_PROBE_METHOD, INTERFACE_NAME, PVE_STORAGE_ID

_JOB_HEADER = "INFO: starting new backup job: vzdump "
_RESULT = re.compile(r"^(INFO: Finished Backup of VM|ERROR: Backup of VM) ([1-9][0-9]{0,8})(?: |$)")


def backup_policy(spec: object) -> dict[int, int]:
    if (not isinstance(spec, dict) or not isinstance(spec.get("asset"), str)
            or not isinstance(spec.get("storage"), str) or not PVE_STORAGE_ID.fullmatch(spec["storage"])):
        return {}
    ages = spec.get("max_age_hours")
    if not isinstance(ages, dict) or not 1 <= len(ages) <= 15:
        return {}
    if not all(isinstance(key, str) and re.fullmatch(r"[1-9][0-9]{0,8}", key)
               and type(hours) is int and 1 <= hours <= 744 for key, hours in ages.items()):
        return {}
    return {int(key): hours for key, hours in ages.items()}


def _backup_log(rows: list) -> tuple[str, set[int], dict[int, bool]] | None:
    if not rows or not all(isinstance(row, dict) and isinstance(row.get("t"), str) for row in rows):
        return None
    lines = [row["t"] for row in rows]
    if lines[-1] != "TASK OK" and not lines[-1].startswith("TASK ERROR:"):
        return None
    headers = [line[len(_JOB_HEADER):] for line in lines if line.startswith(_JOB_HEADER)]
    if len(headers) != 1:
        return None
    try:
        arguments = shlex.split(headers[0])
        storage = arguments[arguments.index("--storage") + 1]
    except (ValueError, IndexError):
        return None
    if arguments.count("--storage") != 1 or not PVE_STORAGE_ID.fullmatch(storage):
        return None
    planned = set(map(int, takewhile(lambda arg: re.fullmatch(r"[1-9][0-9]{0,8}", arg), arguments)))
    results = {}
    for line in lines:
        if match := _RESULT.match(line):
            vmid = int(match[2])
            successful = match[1].startswith("INFO:")
            if vmid in results and results[vmid] != successful:
                return None
            results[vmid] = successful
    return storage, planned, results


def read_proxmox_backup(get, nodes: list[str], storage: str, now: datetime) -> dict:
    if not isinstance(storage, str) or not PVE_STORAGE_ID.fullmatch(storage):
        return {}

    def rows(path):
        try:
            data = get(path)
        except (OSError, ValueError, KeyError):
            return None
        return data if isinstance(data, list) and all(isinstance(row, dict) for row in data) else None

    jobs = rows("cluster/backup")
    if jobs is None:
        return {}
    guests = set()
    incomplete = False
    for job in jobs:
        if job.get("type") != "vzdump" or job.get("storage") != storage or job.get("enabled") != 1:
            continue
        vmids = job.get("vmid")
        if isinstance(vmids, str) and re.fullmatch(r"[1-9][0-9]{0,8}(?:,[1-9][0-9]{0,8})*", vmids):
            guests.update(map(int, vmids.split(",")))
        else:
            incomplete = True
    result = {"checkedAt": now.isoformat(), "guests": guests, "incomplete": incomplete, "results": {}}
    if not guests or not nodes or not all(isinstance(node, str) and INTERFACE_NAME.fullmatch(node) for node in nodes):
        return result
    with ThreadPoolExecutor(max_workers=6) as pool:
        history = list(pool.map(rows, (f"nodes/{node}/tasks?typefilter=vzdump&limit=12" for node in nodes)))
    if any(tasks is None for tasks in history):
        return result
    tasks = sorted(
        (task for node, node_tasks in zip(nodes, history) for task in node_tasks[:12]
         if task.get("node") == node and task.get("type") == "vzdump"
         and type(task.get("starttime")) is int and type(task.get("endtime")) is int
         and 0 < task["starttime"] <= task["endtime"] <= now.timestamp()),
        key=lambda task: (task["starttime"], task["endtime"]), reverse=True,
    )
    pending = guests.copy()
    deadline = monotonic() + 12
    for task in tasks[:12]:
        upid = task.get("upid")
        if (monotonic() >= deadline or not isinstance(upid, str) or len(upid) > 256
                or not upid.startswith(f"UPID:{task['node']}:")):
            break
        log = rows(f"nodes/{task['node']}/tasks/{quote(upid, safe='')}/log?limit=1024")
        report = _backup_log(log) if log is not None else None
        if report is None:
            break
        target, planned, outcomes = report
        if target != storage:
            continue
        for vmid in pending.intersection(outcomes):
            result["results"][vmid] = {
                "successful": outcomes[vmid],
                "completedAt": datetime.fromtimestamp(task["endtime"], timezone.utc),
            }
        pending.difference_update(planned, outcomes)
        if not pending:
            break
    return result


def backup_service_checks(observation: dict, max_age_hours: dict[int, int], now: datetime) -> list[dict]:
    checks = []
    common = {"source": "Proxmox", "method": BACKUP_PROBE_METHOD, "required": True,
              "checkedAt": observation.get("checkedAt", now.isoformat())}
    guests = observation.get("guests", set())
    for vmid, hours in sorted(max_age_hours.items()):
        state, reason = "unknown", "backup_no_result"
        check = {**common, "backupVmid": vmid, "backupMaxAgeHours": hours}
        outcome = observation.get("results", {}).get(vmid)
        if vmid not in guests and observation:
            reason = "backup_schedule_missing"
        elif outcome:
            completed = outcome["completedAt"]
            check["backupCompletedAt"] = completed.isoformat()
            if not outcome["successful"]:
                state, reason = "unreachable", "backup_task_failed"
            elif now - completed > timedelta(hours=hours):
                state, reason = "unreachable", "backup_overdue"
            else:
                state, reason = "reachable", ""
        checks.append({**check, "state": state, **({"reason": reason} if reason else {})})
    if observation.get("incomplete") or guests - max_age_hours.keys():
        checks.append({**common, "state": "unknown", "reason": "backup_untracked_schedule"})
    return checks
