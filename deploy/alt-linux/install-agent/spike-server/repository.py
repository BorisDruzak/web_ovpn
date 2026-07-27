from __future__ import annotations

import json
import os
import secrets
import tempfile
from datetime import UTC, datetime
from pathlib import Path


class SpikeRepository:
    """Private, file-backed state for the non-production spike fixture."""

    _REQUIRED_MACHINE_FIELDS = frozenset(
        {"uuid", "manufacturer", "product_name", "memory_kib", "boot_id"}
    )
    _VALID_STATES = frozenset(
        {"agent_started", "inventory_ready", "waiting_for_approval", "spike_approved"}
    )

    def __init__(self, state_root: Path) -> None:
        self.state_root = state_root
        self.state_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.state_root, 0o700)

    def create_session(self, inventory: dict[str, object], peer_ip: str) -> str:
        self._validate_inventory(inventory)
        session_id = "spike-{}-{}".format(
            datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ"),
            secrets.token_hex(4),
        )
        session_dir = self.state_root / session_id
        session_dir.mkdir(mode=0o700)
        self._write(
            session_dir / "session.json",
            {
                "session_id": session_id,
                "decision": "waiting",
                "peer_ip": peer_ip,
                "inventory": inventory,
                "states": [],
            },
        )
        return session_id

    def decision(self, session_id: str) -> str:
        return str(self._read(session_id)["decision"])

    def approve(self, session_id: str) -> str:
        return self._transition(session_id, "approved")

    def cancel(self, session_id: str) -> str:
        return self._transition(session_id, "cancelled")

    def report_state(self, session_id: str, state: str) -> None:
        if state not in self._VALID_STATES:
            raise ValueError("unknown spike state")
        record = self._read(session_id)
        states = record.setdefault("states", [])
        if not isinstance(states, list) or len(states) >= 128:
            raise ValueError("invalid spike state history")
        states.append(state)
        self._write(self._path(session_id), record)

    def states(self, session_id: str) -> list[str]:
        states = self._read(session_id).get("states", [])
        if not isinstance(states, list) or not all(isinstance(state, str) for state in states):
            raise ValueError("invalid spike state history")
        return states

    def _transition(self, session_id: str, desired: str) -> str:
        record = self._read(session_id)
        current = str(record["decision"])
        if current == "waiting":
            record["decision"] = desired
            self._write(self._path(session_id), record)
            return desired
        return current

    def _path(self, session_id: str) -> Path:
        if not session_id.startswith("spike-") or "/" in session_id or "\\" in session_id:
            raise KeyError("unknown session")
        path = self.state_root / session_id / "session.json"
        if not path.is_file():
            raise KeyError("unknown session")
        return path

    def _read(self, session_id: str) -> dict[str, object]:
        return json.loads(self._path(session_id).read_text(encoding="utf-8"))

    def _validate_inventory(self, inventory: dict[str, object]) -> None:
        if set(inventory) != {"machine", "boot_media", "build_id"}:
            raise ValueError("invalid spike inventory fields")
        machine = inventory.get("machine")
        if not isinstance(machine, dict) or set(machine) != self._REQUIRED_MACHINE_FIELDS:
            raise ValueError("invalid spike machine fields")
        if not all(isinstance(value, str) and len(value) <= 128 for value in machine.values()):
            raise ValueError("invalid spike machine values")
        for key in ("boot_media", "build_id"):
            value = inventory.get(key)
            if not isinstance(value, str) or len(value) > 128:
                raise ValueError("invalid spike inventory values")

    @staticmethod
    def _write(path: Path, record: dict[str, object]) -> None:
        descriptor, temporary = tempfile.mkstemp(prefix=".session-", dir=path.parent)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                json.dump(record, output, ensure_ascii=True, separators=(",", ":"))
                output.write("\n")
            os.chmod(temporary, 0o600)
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
