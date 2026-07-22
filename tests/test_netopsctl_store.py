from __future__ import annotations

import pytest


def _peer(service_principal: str):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from netopsctl.server import AuthenticatedPeer

    return AuthenticatedPeer(
        uid=1001, gid=1001, pid=1234, service_principal=service_principal,
        public_key=Ed25519PrivateKey.generate().public_key().public_bytes_raw(),
        allowed_actions=frozenset(),
    )


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
        assert {
            "plan_schema_version": 1,
            "authorization_version": 1,
            "operation_version": 1,
        }.items() <= plan.items()
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


def test_control_service_inspection_returns_persisted_plan_and_digest(tmp_path) -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from netopsctl.audit import AuditSigner
    from netopsctl.service import ControlService
    from netopsctl.store import connect, create_change_plan

    conn = connect(f"sqlite:///{(tmp_path / 'netopsctl.sqlite').as_posix()}")
    try:
        create_change_plan(
            conn, plan_key="plan-inspect", actor="api:network-admin", reason="policy",
            subject_type="asset", subject_key="mac:AA:BB:CC:DD:EE:FF", operation_type="internet_access_set",
            desired_state={"internet_access": "deny"}, resolved_targets=[], context_evidence_hash="c" * 64,
            precheck={}, rollback={},
        )
        service = ControlService(
            conn=conn, netctl_db_url="sqlite:///unused", adapter=object(), enforcement_sources_by_site={},
            source_sla_seconds=300, audit_signer=AuditSigner("test", Ed25519PrivateKey.generate()),
            writes_enabled=False, audit_sink={},
        )

        result = service.dispatch(
            "plan.inspect", {"plan_key": "plan-inspect"}, peer=_peer("openvpn-web"),
            subject={"principal_type": "api_principal", "principal_id": "api:netops", "principal_name": "api:netops", "session_id": "request-1", "authorization_id": "auth-1"},
        )

        assert result["plan_key"] == "plan-inspect"
        assert result["plan_digest"].startswith("sha256:")
    finally:
        conn.close()


def test_control_service_routes_the_dedicated_reconcile_action(tmp_path, monkeypatch) -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from netopsctl.audit import AuditSigner
    from netopsctl.service import ControlService
    from netopsctl.store import connect

    conn = connect(f"sqlite:///{(tmp_path / 'netopsctl.sqlite').as_posix()}")
    try:
        service = ControlService(
            conn=conn, netctl_db_url="sqlite:///context.sqlite", adapter=object(), enforcement_sources_by_site={},
            source_sla_seconds=300, audit_signer=AuditSigner("test", Ed25519PrivateKey.generate()),
            writes_enabled=True, audit_sink={},
        )
        monkeypatch.setattr(service, "_checkpoint", lambda: None)
        monkeypatch.setattr(
            "netopsctl.reconcile.reconcile_desired_policies",
            lambda *_args, **kwargs: {"reconciled": 1, "stale_identity": 0, "skipped": 0},
        )
        assert service.dispatch(
            "policy.reconcile", {"limit": 4}, peer=_peer("netopsctl-reconcile"),
            subject={"principal_type": "service", "principal_id": "reconciler", "principal_name": "reconciler", "session_id": "timer", "authorization_id": "reconcile-1"},
        ) == {"reconciled": 1, "stale_identity": 0, "skipped": 0}
    finally:
        conn.close()
