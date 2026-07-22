from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import dataclass
from typing import Any

from .audit import AuditSigner, append_event
from .checkpoint import build_checkpoint, deliver_checkpoint
from .policy_resolver import create_asset_internet_access_plan
from .reconcile import apply_plan, rollback_plan, verify_plan
from .store import get_change_plan, plan_digest, transition_plan, upsert_desired_policy


@dataclass
class ControlService:
    conn: sqlite3.Connection
    netctl_db_url: str
    adapter: Any
    enforcement_sources_by_site: dict[str, str]
    source_sla_seconds: int
    audit_signer: AuditSigner
    writes_enabled: bool
    audit_sink: dict[str, str]

    def _audit(self, event_type: str, *, action: str, peer: str, subject: dict[str, str], outcome: str) -> None:
        append_event(self.conn, self.audit_signer, event_type, {
            "action": action, "authenticated_peer": peer, "authorized_subject": subject, "outcome": outcome,
        })

    def _checkpoint(self) -> None:
        if not self.writes_enabled:
            raise ValueError("production network writes are disabled")
        checkpoint = build_checkpoint(self.conn, self.audit_signer, instance_id=self.audit_sink["instance_id"])
        deliver_checkpoint(
            checkpoint, host=self.audit_sink["host"], identity_file=self.audit_sink["identity_file"],
            known_hosts=self.audit_sink["known_hosts"],
        )

    def dispatch(self, action: str, payload: dict[str, Any], *, peer: str, subject: dict[str, str]) -> dict[str, Any]:
        try:
            if action == "status":
                result = {"status": "ok", "service": "netopsctl", "writes_enabled": self.writes_enabled}
            elif action == "plan.create":
                plan = payload["plan"]
                common = {
                    "plan_key": f"plan-{uuid.uuid4()}", "actor": f"{subject['principal_type']}:{subject['principal_id']}",
                    "desired_state": plan["desired_state"], "reason": plan["reason"],
                    "enforcement_sources_by_site": self.enforcement_sources_by_site,
                    "source_sla_seconds": self.source_sla_seconds,
                    "anchor_check": lambda target: bool(self.adapter.inspect_internet_policy_anchor()["valid"])
                    and target == next(iter(self.enforcement_sources_by_site.values())),
                }
                if plan["subject_type"] == "asset":
                    result = create_asset_internet_access_plan(self.conn, self.netctl_db_url, asset_key=plan["subject_key"], **common)
                else:
                    from .policy_resolver import create_user_internet_access_plan

                    result = create_user_internet_access_plan(self.conn, self.netctl_db_url, user_key=plan["subject_key"], **common)
                result["plan_digest"] = plan_digest(self.conn, result["plan_key"])
            elif action == "plan.inspect":
                result = get_change_plan(self.conn, payload["plan_key"])
                result["plan_digest"] = plan_digest(self.conn, payload["plan_key"])
            elif action == "plan.approve":
                plan_key = payload["plan_key"]
                transition_plan(self.conn, plan_key, "validated")
                result = transition_plan(self.conn, plan_key, "approved")
                result["plan_digest"] = plan_digest(self.conn, plan_key)
            elif action == "plan.apply":
                self._checkpoint()
                result = apply_plan(self.conn, payload["plan_key"], self.adapter)
            elif action == "plan.verify":
                result = verify_plan(self.conn, payload["plan_key"], self.adapter)
                if result["status"] == "verified":
                    plan = self.conn.execute("SELECT * FROM change_plans WHERE plan_key = ?", (payload["plan_key"],)).fetchone()
                    desired = json.loads(plan["desired_state_json"])
                    upsert_desired_policy(
                        self.conn, payload["plan_key"], subject_type=str(plan["subject_type"]), subject_key=str(plan["subject_key"]),
                        desired_state=str(desired["internet_access"]), reason=str(plan["reason"]), enforcement_scope="all-sites",
                    )
            elif action == "plan.rollback":
                self._checkpoint()
                result = rollback_plan(self.conn, payload["plan_key"], self.adapter)
            else:
                raise ValueError("unsupported control action")
        except Exception:
            self._audit("network_control_failed", action=action, peer=peer, subject=subject, outcome="failed")
            raise
        self._audit("network_control_succeeded", action=action, peer=peer, subject=subject, outcome="ok")
        return result
