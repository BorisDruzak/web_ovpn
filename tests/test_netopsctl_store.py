from __future__ import annotations

import pytest


def test_change_plans_use_a_separate_database_and_freeze_after_approval(tmp_path) -> None:
    from netopsctl.store import add_plan_step, connect, create_change_plan, transition_plan, update_draft_plan

    conn = connect(f"sqlite:///{(tmp_path / 'netopsctl.sqlite').as_posix()}")
    try:
        plan = create_change_plan(
            conn,
            plan_key="plan-20260722-0001",
            actor="api:network-admin",
            reason="approved access request",
            subject_type="asset",
            subject_key="mac:AA:BB:CC:DD:EE:FF",
            operation_type="internet_access_set",
            desired_state={"internet_access": "deny"},
            resolved_targets=[{"source": "router-a", "target": "address-list:blocked"}],
            context_evidence_hash="a" * 64,
            precheck={"status": "ok"},
            rollback={"operation": "remove"},
        )
        add_plan_step(conn, plan["plan_key"], adapter="mikrotik", operation="address_list.add", target_key="router-a", request={"list": "blocked"})
        update_draft_plan(conn, plan["plan_key"], reason="approved access request #42")
        transition_plan(conn, plan["plan_key"], "validated")
        transition_plan(conn, plan["plan_key"], "approved")

        with pytest.raises(ValueError, match="immutable"):
            update_draft_plan(conn, plan["plan_key"], reason="changed after approval")
        with pytest.raises(ValueError, match="immutable"):
            add_plan_step(conn, plan["plan_key"], adapter="mikrotik", operation="address_list.remove", target_key="router-a", request={})
        assert transition_plan(conn, plan["plan_key"], "applying")["status"] == "applying"
    finally:
        conn.close()


def test_change_plan_state_machine_and_desired_policy_are_bounded(tmp_path) -> None:
    from netopsctl.store import connect, create_change_plan, transition_plan, upsert_desired_policy

    conn = connect(f"sqlite:///{(tmp_path / 'netopsctl.sqlite').as_posix()}")
    try:
        plan = create_change_plan(
            conn, plan_key="plan-2", actor="api:network-admin", reason="policy",
            subject_type="user", subject_key="employee:ivanov", operation_type="internet_access_set",
            desired_state={"internet_access": "allow"}, resolved_targets=[], context_evidence_hash="b" * 64,
            precheck={}, rollback={},
        )
        with pytest.raises(ValueError, match="invalid status transition"):
            transition_plan(conn, plan["plan_key"], "applied")
        transition_plan(conn, plan["plan_key"], "validated")
        transition_plan(conn, plan["plan_key"], "approved")
        transition_plan(conn, plan["plan_key"], "applying")
        transition_plan(conn, plan["plan_key"], "applied")
        transition_plan(conn, plan["plan_key"], "verified")
        policy = upsert_desired_policy(
            conn, plan["plan_key"], subject_type="user", subject_key="employee:ivanov",
            desired_state="allow", reason="policy", enforcement_scope="all-sites",
        )
        assert policy["status"] == "active"
        assert policy["source_plan_key"] == "plan-2"
    finally:
        conn.close()
