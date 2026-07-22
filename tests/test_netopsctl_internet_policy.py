from __future__ import annotations

from netctl.util import utc_now

import pytest


def test_asset_deny_plan_resolves_current_ipv4_to_one_bounded_step(tmp_path) -> None:
    from netctl.db import connect as connect_netctl
    from netopsctl.policy_resolver import create_asset_internet_access_plan
    from netopsctl.store import connect as connect_netops

    netctl_url = f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}"
    now = utc_now()
    context = connect_netctl(netctl_url)
    try:
        source = context.execute(
            """INSERT INTO network_sources (name, driver, host, port, username, secret_ref, tls, verify_tls, site, enabled, created_at, updated_at, last_collect_at, last_status)
               VALUES ('edge-a', 'mock', '127.0.0.1', 1, '', '', 0, 0, 'site-a', 1, ?, ?, ?, 'success')""", (now, now, now)
        ).lastrowid
        asset = context.execute(
            """INSERT INTO assets (asset_key, identity_method, identity_confidence, provisional, first_seen_at, last_seen_at, created_at, updated_at)
               VALUES ('mac:AA:BB:CC:DD:EE:FF', 'manual', 100, 0, ?, ?, ?, ?)""", (now, now, now, now)
        ).lastrowid
        context.execute(
            """INSERT INTO ip_observations (asset_id, site, source_id, source_key, ip, first_seen_at, last_seen_at, is_current, observation_source)
               VALUES (?, 'site-a', ?, 'edge-a', '192.0.2.10', ?, ?, 1, 'manual')""", (asset, source, now, now)
        )
        context.commit()
    finally:
        context.close()
    netops = connect_netops(f"sqlite:///{(tmp_path / 'netops.sqlite').as_posix()}")
    try:
        create_asset_internet_access_plan(
            netops, netctl_url, plan_key="plan-asset-deny", actor="api:network-admin", asset_key="mac:AA:BB:CC:DD:EE:FF",
            desired_state="deny", reason="approved", enforcement_sources_by_site={"site-a": "router-a"},
            source_sla_seconds=300, anchor_check=lambda source: source == "router-a",
        )
        step = netops.execute("SELECT operation, target_key, request_json FROM change_plan_steps").fetchone()
        assert tuple(step[:2]) == ("ensure_address_list_entry", "router-a")
        assert '192.0.2.10' in step[2]
    finally:
        netops.close()


def test_asset_policy_rejects_unknown_desired_state_and_provisional_identity(tmp_path) -> None:
    from netctl.db import connect as connect_netctl
    from netopsctl.policy_resolver import create_asset_internet_access_plan, resolve_asset_targets
    from netopsctl.store import connect as connect_netops

    netctl_url = f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}"
    now = utc_now()
    context = connect_netctl(netctl_url)
    try:
        context.execute(
            """INSERT INTO assets (asset_key, identity_method, identity_confidence, provisional, first_seen_at, last_seen_at, created_at, updated_at)
               VALUES ('provisional:192.0.2.10', 'provisional_legacy', 0, 1, ?, ?, ?, ?)""", (now, now, now, now)
        )
        context.commit()
        with pytest.raises(ValueError, match="provisional"):
            resolve_asset_targets(context, "provisional:192.0.2.10", enforcement_sources_by_site={}, source_sla_seconds=300, anchor_check=lambda _: True)
    finally:
        context.close()
    netops = connect_netops(f"sqlite:///{(tmp_path / 'netops.sqlite').as_posix()}")
    try:
        with pytest.raises(ValueError, match="unknown desired"):
            create_asset_internet_access_plan(
                netops, netctl_url, plan_key="plan-invalid", actor="api:network-admin", asset_key="provisional:192.0.2.10",
                desired_state="maybe", reason="invalid", enforcement_sources_by_site={}, source_sla_seconds=300, anchor_check=lambda _: True,
            )
    finally:
        netops.close()


def test_approved_plan_applies_idempotently_and_verifies(tmp_path) -> None:
    from netopsctl.reconcile import apply_plan, verify_plan
    from netopsctl.store import add_plan_step, connect, create_change_plan, transition_plan

    class Adapter:
        entries = []

        @staticmethod
        def ownership_comment(plan_key, asset_key):
            return f"web_ovpn:policy:{plan_key}:asset:{asset_key}"

        def ensure_address_list_entry(self, target, address, plan_key, asset_key):
            assert (target, address, plan_key, asset_key) == ("router-a", "192.0.2.10", "plan-apply", "mac:AA")
            self.entries.append({"address": address, "comment": self.ownership_comment(plan_key, asset_key)})
            return {"status": "added"}

        def list_managed_address_list_entries(self, target):
            assert target == "router-a"
            return self.entries

    conn = connect(f"sqlite:///{(tmp_path / 'netops.sqlite').as_posix()}")
    try:
        create_change_plan(conn, plan_key="plan-apply", actor="api", reason="approved", subject_type="asset", subject_key="mac:AA", operation_type="internet_access_set", desired_state={}, resolved_targets=[], context_evidence_hash="c" * 64, precheck={}, rollback={})
        add_plan_step(conn, "plan-apply", adapter="mikrotik", operation="ensure_address_list_entry", target_key="router-a", request={"address": "192.0.2.10", "asset_key": "mac:AA"})
        transition_plan(conn, "plan-apply", "validated")
        transition_plan(conn, "plan-apply", "approved")
        assert apply_plan(conn, "plan-apply", Adapter())["status"] == "applied"
        assert apply_plan(conn, "plan-apply", Adapter())["status"] == "already_applied"
        assert verify_plan(conn, "plan-apply", Adapter())["status"] == "verified"
    finally:
        conn.close()


def test_verify_mismatch_marks_plan_failed_without_another_device_mutation(tmp_path) -> None:
    from netopsctl.reconcile import apply_plan, verify_plan
    from netopsctl.store import add_plan_step, connect, create_change_plan, transition_plan

    class Adapter:
        @staticmethod
        def ownership_comment(plan_key, asset_key):
            return f"web_ovpn:policy:{plan_key}:asset:{asset_key}"

        def ensure_address_list_entry(self, *_args):
            return {"status": "added"}

        def list_managed_address_list_entries(self, _target):
            return []

    conn = connect(f"sqlite:///{(tmp_path / 'netops.sqlite').as_posix()}")
    try:
        create_change_plan(conn, plan_key="plan-mismatch", actor="api", reason="approved", subject_type="asset", subject_key="mac:AA", operation_type="internet_access_set", desired_state={}, resolved_targets=[], context_evidence_hash="c" * 64, precheck={}, rollback={})
        add_plan_step(conn, "plan-mismatch", adapter="mikrotik", operation="ensure_address_list_entry", target_key="router-a", request={"address": "192.0.2.10", "asset_key": "mac:AA"})
        transition_plan(conn, "plan-mismatch", "validated")
        transition_plan(conn, "plan-mismatch", "approved")
        apply_plan(conn, "plan-mismatch", Adapter())
        assert verify_plan(conn, "plan-mismatch", Adapter())["status"] == "failed"
        assert conn.execute("SELECT status FROM change_plans WHERE plan_key = 'plan-mismatch'").fetchone()[0] == "failed"
    finally:
        conn.close()


def test_rollback_removes_only_the_original_plan_asset_entry(tmp_path) -> None:
    from netopsctl.reconcile import apply_plan, rollback_plan
    from netopsctl.store import add_plan_step, connect, create_change_plan, transition_plan

    class Adapter:
        def __init__(self):
            self.removals = []

        def ensure_address_list_entry(self, *_args):
            return {"status": "added"}

        def remove_address_list_entry(self, target, address, plan_key, asset_key):
            self.removals.append((target, address, plan_key, asset_key))
            return {"status": "removed"}

    adapter = Adapter()
    conn = connect(f"sqlite:///{(tmp_path / 'netops.sqlite').as_posix()}")
    try:
        create_change_plan(conn, plan_key="plan-rollback", actor="api", reason="approved", subject_type="asset", subject_key="mac:AA", operation_type="internet_access_set", desired_state={}, resolved_targets=[], context_evidence_hash="c" * 64, precheck={}, rollback={"steps": [{"operation": "remove_address_list_entry", "target_key": "router-a", "request": {"address": "192.0.2.10", "asset_key": "mac:AA"}}]})
        add_plan_step(conn, "plan-rollback", adapter="mikrotik", operation="ensure_address_list_entry", target_key="router-a", request={"address": "192.0.2.10", "asset_key": "mac:AA"})
        transition_plan(conn, "plan-rollback", "validated")
        transition_plan(conn, "plan-rollback", "approved")
        apply_plan(conn, "plan-rollback", adapter)
        assert rollback_plan(conn, "plan-rollback", adapter)["status"] == "rolled_back"
        assert adapter.removals == [("router-a", "192.0.2.10", "plan-rollback", "mac:AA")]
    finally:
        conn.close()
