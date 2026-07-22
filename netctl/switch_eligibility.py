from __future__ import annotations

import json
from typing import Any


_AUTHORITATIVE_FDB_OUTCOMES = frozenset({"success_with_rows", "success_empty"})


def has_authoritative_fdb(status: object, outcomes_json: object) -> bool:
    """Return whether a completed switch run authoritatively replaced current FDB."""
    if str(status) not in {"success", "partial"}:
        return False
    try:
        outcomes = json.loads(str(outcomes_json or "{}"))
    except (TypeError, json.JSONDecodeError):
        return False
    return isinstance(outcomes, dict) and str(outcomes.get("fdb") or "") in _AUTHORITATIVE_FDB_OUTCOMES


def authoritative_fdb_run(row: Any) -> bool:
    return has_authoritative_fdb(row["collector_status"], row["outcomes_json"])
