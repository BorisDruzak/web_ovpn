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


def test_asset_policy_plan_basis_binds_active_context_head_before_apply(tmp_path) -> None:
    """A changed intent head invalidates an approved plan before any device call."""
    from netctl.db import connect as connect_netctl
    from netopsctl.policy_resolver import (
        changed_plan_preconditions,
        create_asset_internet_access_plan,
    )
    from netopsctl.store import connect as connect_netops

    netctl_url = f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}"
    now = utc_now()
    context = connect_netctl(netctl_url)
    try:
        revision_one = context.execute(
            """INSERT INTO context_revisions
               (context_id, schema_version, sha256, source_path, validated_at, status)
               VALUES ('site-a', '1.0', 'a' || printf('%063d', 0), 'fixture', ?, 'ok')""",
            (now,),
        ).lastrowid
        import_one = context.execute(
            """INSERT INTO context_import_runs
               (context_id, context_revision_id, input_sha256, git_sha, source_path, started_at, status)
               VALUES ('site-a', ?, 'a', 'fixture', 'fixture', ?, 'success_imported')""",
            (revision_one, now),
        ).lastrowid
        context.execute(
            """INSERT INTO context_heads
               (context_id, context_revision_id, activated_by_import_run_id, activated_at)
               VALUES ('site-a', ?, ?, ?)""",
            (revision_one, import_one, now),
        )
        source = context.execute(
            """INSERT INTO network_sources (name, driver, host, port, username, secret_ref, tls, verify_tls, site, enabled, created_at, updated_at, last_collect_at, last_status)
               VALUES ('edge-a', 'mock', '127.0.0.1', 1, '', '', 0, 0, 'site-a', 1, ?, ?, ?, 'success')""",
            (now, now, now),
        ).lastrowid
        asset = context.execute(
            """INSERT INTO assets (asset_key, identity_method, identity_confidence, provisional, first_seen_at, last_seen_at, created_at, updated_at)
               VALUES ('mac:AA:BB:CC:DD:EE:FF', 'manual', 100, 0, ?, ?, ?, ?)""",
            (now, now, now, now),
        ).lastrowid
        context.execute(
            """INSERT INTO ip_observations (asset_id, site, source_id, source_key, ip, first_seen_at, last_seen_at, is_current, observation_source)
               VALUES (?, 'site-a', ?, 'edge-a', '192.0.2.10', ?, ?, 1, 'manual')""",
            (asset, source, now, now),
        )
        context.commit()
    finally:
        context.close()

    netops = connect_netops(f"sqlite:///{(tmp_path / 'netops.sqlite').as_posix()}")
    try:
        plan = create_asset_internet_access_plan(
            netops, netctl_url, plan_key="plan-basis", actor="api:network-admin",
            asset_key="mac:AA:BB:CC:DD:EE:FF", desired_state="deny", reason="approved",
            enforcement_sources_by_site={"site-a": "router-a"}, source_sla_seconds=300,
            anchor_check=lambda source: {"valid": source == "router-a", "fingerprint": "anchor-one"},
        )
        assert plan["plan_basis_hash"].startswith("sha256:")
        assert plan["plan_basis"]["context_heads"] == [{
            "context_id": "site-a", "context_revision_id": revision_one,
            "sha256": "a" + "0" * 63,
        }]

        context = connect_netctl(netctl_url)
        try:
            revision_two = context.execute(
                """INSERT INTO context_revisions
                   (context_id, schema_version, sha256, source_path, validated_at, status)
                   VALUES ('site-a', '1.0', 'b' || printf('%063d', 0), 'fixture', ?, 'ok')""",
                (now,),
            ).lastrowid
            import_two = context.execute(
                """INSERT INTO context_import_runs
                   (context_id, context_revision_id, input_sha256, git_sha, source_path, started_at, status)
                   VALUES ('site-a', ?, 'b', 'fixture', 'fixture', ?, 'success_imported')""",
                (revision_two, now),
            ).lastrowid
            context.execute(
                "UPDATE context_heads SET context_revision_id = ?, activated_by_import_run_id = ? WHERE context_id = 'site-a'",
                (revision_two, import_two),
            )
            context.commit()
        finally:
            context.close()

        stored = netops.execute("SELECT * FROM change_plans WHERE plan_key = 'plan-basis'").fetchone()
        assert changed_plan_preconditions(
            stored, netctl_url, enforcement_sources_by_site={"site-a": "router-a"},
            source_sla_seconds=300,
            anchor_check=lambda source: {"valid": source == "router-a", "fingerprint": "anchor-one"},
        ) == ["context_head"]
    finally:
        netops.close()


def test_policy_plan_ttl_cannot_exceed_the_fifteen_minute_security_bound(tmp_path) -> None:
    from netopsctl.policy_resolver import create_asset_internet_access_plan
    from netopsctl.store import connect

    conn = connect(f"sqlite:///{(tmp_path / 'netops.sqlite').as_posix()}")
    try:
        with pytest.raises(ValueError, match="fifteen minutes"):
            create_asset_internet_access_plan(
                conn, "sqlite:///missing.sqlite", plan_key="invalid-ttl", actor="api",
                asset_key="mac:AA", desired_state="deny", reason="test",
                enforcement_sources_by_site={}, source_sla_seconds=300, anchor_check=lambda _: True,
                plan_ttl_seconds=901,
            )
    finally:
        conn.close()


def test_plan_preflight_names_a_changed_firewall_anchor_fingerprint(tmp_path) -> None:
    from netctl.db import connect as connect_netctl
    from netopsctl.policy_resolver import (
        changed_plan_preconditions,
        create_asset_internet_access_plan,
    )
    from netopsctl.store import connect as connect_netops

    netctl_url = f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}"
    now = utc_now()
    context = connect_netctl(netctl_url)
    try:
        source = context.execute(
            """INSERT INTO network_sources (name, driver, host, port, username, secret_ref, tls, verify_tls, site, enabled, created_at, updated_at, last_collect_at, last_status)
               VALUES ('edge-a', 'mock', '127.0.0.1', 1, '', '', 0, 0, 'site-a', 1, ?, ?, ?, 'success')""",
            (now, now, now),
        ).lastrowid
        asset = context.execute(
            """INSERT INTO assets (asset_key, identity_method, identity_confidence, provisional, first_seen_at, last_seen_at, created_at, updated_at)
               VALUES ('mac:AA', 'manual', 100, 0, ?, ?, ?, ?)""",
            (now, now, now, now),
        ).lastrowid
        context.execute(
            """INSERT INTO ip_observations (asset_id, site, source_id, source_key, ip, first_seen_at, last_seen_at, is_current, observation_source)
               VALUES (?, 'site-a', ?, 'edge-a', '192.0.2.11', ?, ?, 1, 'manual')""",
            (asset, source, now, now),
        )
        context.commit()
    finally:
        context.close()
    netops = connect_netops(f"sqlite:///{(tmp_path / 'netops.sqlite').as_posix()}")
    try:
        create_asset_internet_access_plan(
            netops, netctl_url, plan_key="plan-anchor", actor="api", asset_key="mac:AA",
            desired_state="deny", reason="approved", enforcement_sources_by_site={"site-a": "router-a"},
            source_sla_seconds=300,
            anchor_check=lambda _: {"valid": True, "anchor": "WEBOVPN-INTERNET-DENY", "fingerprint": "before"},
        )
        stored = netops.execute("SELECT * FROM change_plans WHERE plan_key = 'plan-anchor'").fetchone()
        assert changed_plan_preconditions(
            stored, netctl_url, enforcement_sources_by_site={"site-a": "router-a"}, source_sla_seconds=300,
            anchor_check=lambda _: {"valid": True, "anchor": "WEBOVPN-INTERNET-DENY", "fingerprint": "after"},
        ) == ["firewall_anchor_fingerprint"]
    finally:
        netops.close()


def test_user_plan_becomes_stale_when_its_primary_binding_is_retired(tmp_path) -> None:
    from netctl.db import connect as connect_netctl
    from netctl.user_context import bind_user_asset, create_user, retire_user_asset_binding
    from netopsctl.policy_resolver import (
        changed_plan_preconditions,
        create_user_internet_access_plan,
    )
    from netopsctl.store import connect as connect_netops

    netctl_url = f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}"
    now = utc_now()
    context = connect_netctl(netctl_url)
    try:
        source = context.execute(
            """INSERT INTO network_sources (name, driver, host, port, username, secret_ref, tls, verify_tls, site, enabled, created_at, updated_at, last_collect_at, last_status)
               VALUES ('edge-a', 'mock', '127.0.0.1', 1, '', '', 0, 0, 'site-a', 1, ?, ?, ?, 'success')""",
            (now, now, now),
        ).lastrowid
        asset = context.execute(
            """INSERT INTO assets (asset_key, identity_method, identity_confidence, provisional, first_seen_at, last_seen_at, created_at, updated_at)
               VALUES ('mac:AA', 'manual', 100, 0, ?, ?, ?, ?)""",
            (now, now, now, now),
        ).lastrowid
        context.execute(
            """INSERT INTO ip_observations (asset_id, site, source_id, source_key, ip, first_seen_at, last_seen_at, is_current, observation_source)
               VALUES (?, 'site-a', ?, 'edge-a', '192.0.2.12', ?, ?, 1, 'manual')""",
            (asset, source, now, now),
        )
        context.commit()
        create_user(context, "employee:one", "Employee One")
        binding = bind_user_asset(
            context, "employee:one", "mac:AA", relation="primary_user", confidence=100,
            reason="assigned workstation",
        )
    finally:
        context.close()

    netops = connect_netops(f"sqlite:///{(tmp_path / 'netops.sqlite').as_posix()}")
    try:
        plan = create_user_internet_access_plan(
            netops, netctl_url, plan_key="plan-user-binding", actor="api", user_key="employee:one",
            desired_state="deny", reason="approved", enforcement_sources_by_site={"site-a": "router-a"},
            source_sla_seconds=300, anchor_check=lambda _: {"valid": True, "fingerprint": "anchor-one"},
        )
        assert plan["subject_key"] == "employee:one"
        assert plan["desired_state"]["resolved_enforcement_asset_key"] == "mac:AA"

        context = connect_netctl(netctl_url)
        try:
            retire_user_asset_binding(context, int(binding["id"]), "reassigned")
        finally:
            context.close()

        stored = netops.execute("SELECT * FROM change_plans WHERE plan_key = 'plan-user-binding'").fetchone()
        assert changed_plan_preconditions(
            stored, netctl_url, enforcement_sources_by_site={"site-a": "router-a"},
            source_sla_seconds=300, anchor_check=lambda _: {"valid": True, "fingerprint": "anchor-one"},
        ) == ["user_policy_binding"]
    finally:
        netops.close()


def test_reconciler_adds_new_deny_before_removing_a_superseded_dhcp_address(tmp_path) -> None:
    from netctl.db import connect as connect_netctl
    from netopsctl.reconcile import reconcile_desired_policies
    from netopsctl.store import connect as connect_netops
    from netopsctl.store import create_change_plan, transition_plan, upsert_desired_policy

    class Adapter:
        def __init__(self) -> None:
            self.calls: list[tuple[str, str]] = []
            self.entries = [{"address": "192.0.2.20", "comment": self.ownership_comment("policy-source", "mac:AA")}]

        @staticmethod
        def ownership_comment(plan_key, asset_key):
            return f"web_ovpn:policy:{plan_key}:asset:{asset_key}"

        def list_managed_address_list_entries(self, _target):
            self.calls.append(("list", ""))
            return list(self.entries)

        def ensure_address_list_entry(self, _target, address, plan_key, asset_key):
            self.calls.append(("ensure", address))
            self.entries.append({"address": address, "comment": self.ownership_comment(plan_key, asset_key)})
            return {"status": "added", "address": address}

        def remove_address_list_entry(self, _target, address, plan_key, asset_key):
            self.calls.append(("remove", address))
            comment = self.ownership_comment(plan_key, asset_key)
            self.entries = [entry for entry in self.entries if (entry["address"], entry["comment"]) != (address, comment)]
            return {"status": "removed", "address": address}

    netctl_url = f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}"
    now = utc_now()
    context = connect_netctl(netctl_url)
    try:
        source = context.execute(
            """INSERT INTO network_sources (name, driver, host, port, username, secret_ref, tls, verify_tls, site, enabled, created_at, updated_at, last_collect_at, last_status)
               VALUES ('edge-a', 'mock', '127.0.0.1', 1, '', '', 0, 0, 'site-a', 1, ?, ?, ?, 'success')""",
            (now, now, now),
        ).lastrowid
        asset = context.execute(
            """INSERT INTO assets (asset_key, identity_method, identity_confidence, provisional, first_seen_at, last_seen_at, created_at, updated_at)
               VALUES ('mac:AA', 'manual', 100, 0, ?, ?, ?, ?)""",
            (now, now, now, now),
        ).lastrowid
        context.execute(
            """INSERT INTO ip_observations (asset_id, site, source_id, source_key, ip, first_seen_at, last_seen_at, is_current, observation_source)
               VALUES (?, 'site-a', ?, 'edge-a', '192.0.2.21', ?, ?, 1, 'manual')""",
            (asset, source, now, now),
        )
        context.commit()
    finally:
        context.close()
    netops = connect_netops(f"sqlite:///{(tmp_path / 'netops.sqlite').as_posix()}")
    try:
        create_change_plan(
            netops, plan_key="policy-source", actor="api", reason="approved", subject_type="asset",
            subject_key="mac:AA", operation_type="internet_access_set", desired_state={"internet_access": "deny"},
            resolved_targets=[], context_evidence_hash="a" * 64, precheck={}, rollback={},
        )
        for status in ("validated", "approved", "applying", "applied", "verified"):
            transition_plan(netops, "policy-source", status)
        upsert_desired_policy(
            netops, "policy-source", subject_type="asset", subject_key="mac:AA", desired_state="deny",
            reason="approved", enforcement_scope="all-sites",
        )
        adapter = Adapter()
        result = reconcile_desired_policies(
            netops, netctl_url, adapter, enforcement_sources_by_site={"site-a": "router-a"},
            source_sla_seconds=300, anchor_check=lambda _: {"valid": True, "fingerprint": "anchor-one"},
        )
        assert result["reconciled"] == 1
        assert adapter.calls.index(("ensure", "192.0.2.21")) < adapter.calls.index(("remove", "192.0.2.20"))
        assert adapter.entries == [{"address": "192.0.2.21", "comment": "web_ovpn:policy:policy-source:asset:mac:AA"}]
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


def test_asset_policy_rejects_duplicate_current_ip_on_another_asset(tmp_path) -> None:
    from netctl.db import connect as connect_netctl
    from netopsctl.policy_resolver import resolve_asset_targets

    netctl_url = f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}"
    now = utc_now()
    context = connect_netctl(netctl_url)
    try:
        source = context.execute(
            """INSERT INTO network_sources (name, driver, host, port, username, secret_ref, tls, verify_tls, site, enabled, created_at, updated_at, last_collect_at, last_status)
               VALUES ('edge-a', 'mock', '127.0.0.1', 1, '', '', 0, 0, 'site-a', 1, ?, ?, ?, 'success')""", (now, now, now)
        ).lastrowid
        asset_ids = []
        for key in ("mac:AA", "mac:BB"):
            asset_ids.append(context.execute(
                """INSERT INTO assets (asset_key, identity_method, identity_confidence, provisional, first_seen_at, last_seen_at, created_at, updated_at)
                   VALUES (?, 'manual', 100, 0, ?, ?, ?, ?)""", (key, now, now, now, now)
            ).lastrowid)
        for asset_id in asset_ids:
            context.execute(
                """INSERT INTO ip_observations (asset_id, site, source_id, source_key, ip, first_seen_at, last_seen_at, is_current, observation_source)
                   VALUES (?, 'site-a', ?, 'edge-a', '192.0.2.10', ?, ?, 1, 'manual')""", (asset_id, source, now, now)
            )
        context.commit()
        with pytest.raises(ValueError, match="duplicate current IP"):
            resolve_asset_targets(context, "mac:AA", enforcement_sources_by_site={"site-a": "router-a"}, source_sla_seconds=300, anchor_check=lambda _: True)
    finally:
        context.close()


def test_asset_policy_rejects_ambiguous_attachment(tmp_path) -> None:
    from netctl.db import connect as connect_netctl
    from netopsctl.policy_resolver import resolve_asset_targets

    context = connect_netctl(f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}")
    now = utc_now()
    try:
        asset_id = context.execute(
            """INSERT INTO assets (asset_key, identity_method, identity_confidence, provisional, first_seen_at, last_seen_at, created_at, updated_at)
               VALUES ('mac:AA', 'manual', 100, 0, ?, ?, ?, ?)""", (now, now, now, now)
        ).lastrowid
        interface_id = context.execute(
            """INSERT INTO asset_interfaces (asset_id, interface_key, mac, first_seen_at, last_seen_at)
               VALUES (?, 'eth0', 'AA:BB:CC:DD:EE:FF', ?, ?)""", (asset_id, now, now)
        ).lastrowid
        run_id = context.execute(
            "INSERT INTO network_correlation_runs (run_type, started_at, status) VALUES ('attachments', ?, 'success')", (now,)
        ).lastrowid
        context.execute(
            """INSERT INTO asset_attachment_resolutions (asset_interface_id, asset_id, status, confidence, first_seen_at, last_seen_at, correlation_run_id)
               VALUES (?, ?, 'ambiguous', 0, ?, ?, ?)""", (interface_id, asset_id, now, now, run_id)
        )
        context.commit()
        with pytest.raises(ValueError, match="attachment"):
            resolve_asset_targets(context, "mac:AA", enforcement_sources_by_site={}, source_sla_seconds=300, anchor_check=lambda _: True)
    finally:
        context.close()


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
            self.entries.append({"address": address, "comment": self.ownership_comment(plan_key, asset_key), "disabled": "false"})
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


def test_apply_rejects_changed_preconditions_before_device_mutation(tmp_path) -> None:
    from netopsctl.reconcile import apply_plan
    from netopsctl.store import add_plan_step, connect, create_change_plan, transition_plan

    class Adapter:
        calls = 0

        def ensure_address_list_entry(self, *_args):
            self.calls += 1
            return {"status": "added"}

    adapter = Adapter()
    conn = connect(f"sqlite:///{(tmp_path / 'netops.sqlite').as_posix()}")
    try:
        create_change_plan(conn, plan_key="plan-stale", actor="api", reason="approved", subject_type="asset", subject_key="mac:AA", operation_type="internet_access_set", desired_state={}, resolved_targets=[], context_evidence_hash="d" * 64, precheck={}, rollback={})
        add_plan_step(conn, "plan-stale", adapter="mikrotik", operation="ensure_address_list_entry", target_key="router-a", request={"address": "192.0.2.10", "asset_key": "mac:AA"})
        transition_plan(conn, "plan-stale", "validated")
        transition_plan(conn, "plan-stale", "approved")

        result = apply_plan(conn, "plan-stale", adapter, preflight=lambda _plan: ["ip_observations"])

        assert result == {"status": "stale_precondition", "plan_key": "plan-stale", "replan_required": True, "changed_preconditions": ["ip_observations"]}
        assert adapter.calls == 0
    finally:
        conn.close()


def test_apply_rejects_when_enforcement_device_is_locked(tmp_path) -> None:
    from netopsctl.reconcile import apply_plan
    from netopsctl.store import add_plan_step, connect, create_change_plan, transition_plan

    class Adapter:
        calls = 0

        def ensure_address_list_entry(self, *_args):
            self.calls += 1
            return {"status": "added"}

    adapter = Adapter()
    conn = connect(f"sqlite:///{(tmp_path / 'netops.sqlite').as_posix()}")
    try:
        create_change_plan(conn, plan_key="plan-locked", actor="api", reason="approved", subject_type="asset", subject_key="mac:AA", operation_type="internet_access_set", desired_state={}, resolved_targets=[], context_evidence_hash="e" * 64, precheck={}, rollback={})
        add_plan_step(conn, "plan-locked", adapter="mikrotik", operation="ensure_address_list_entry", target_key="router-a", request={"address": "192.0.2.10", "asset_key": "mac:AA"})
        transition_plan(conn, "plan-locked", "validated")
        transition_plan(conn, "plan-locked", "approved")
        conn.execute("INSERT INTO device_operation_locks (device_key, holder, acquired_at) VALUES ('router-a', 'other', datetime('now'))")
        conn.commit()

        with pytest.raises(ValueError, match="device operation is already in progress"):
            apply_plan(conn, "plan-locked", adapter)

        assert adapter.calls == 0
    finally:
        conn.close()


def test_apply_recovers_a_lock_left_by_a_dead_broker_process(tmp_path) -> None:
    from netopsctl.reconcile import apply_plan
    from netopsctl.store import add_plan_step, connect, create_change_plan, transition_plan

    class Adapter:
        calls = 0

        def ensure_address_list_entry(self, *_args):
            self.calls += 1
            return {"status": "added"}

    adapter = Adapter()
    conn = connect(f"sqlite:///{(tmp_path / 'netops.sqlite').as_posix()}")
    try:
        create_change_plan(conn, plan_key="plan-recover-lock", actor="api", reason="approved", subject_type="asset", subject_key="mac:AA", operation_type="internet_access_set", desired_state={}, resolved_targets=[], context_evidence_hash="f" * 64, precheck={}, rollback={})
        add_plan_step(conn, "plan-recover-lock", adapter="mikrotik", operation="ensure_address_list_entry", target_key="router-a", request={"address": "192.0.2.10", "asset_key": "mac:AA"})
        transition_plan(conn, "plan-recover-lock", "validated")
        transition_plan(conn, "plan-recover-lock", "approved")
        conn.execute(
            """INSERT INTO device_operation_locks (device_key, holder, acquired_at, owner_pid)
               VALUES ('router-a', 'crashed', datetime('now'), 999999)"""
        )
        conn.commit()

        assert apply_plan(conn, "plan-recover-lock", adapter)["status"] == "applied"
        assert adapter.calls == 1
        assert conn.execute("SELECT count(*) FROM device_operation_locks").fetchone()[0] == 0
    finally:
        conn.close()


def test_preflight_rejects_expired_plan_without_reading_or_mutating_devices(tmp_path) -> None:
    from netopsctl.policy_resolver import changed_plan_preconditions
    from netopsctl.store import connect, create_change_plan

    conn = connect(f"sqlite:///{(tmp_path / 'netops.sqlite').as_posix()}")
    try:
        create_change_plan(conn, plan_key="plan-expired", actor="api", reason="approved", subject_type="asset", subject_key="mac:AA", operation_type="internet_access_set", desired_state={}, resolved_targets=[], context_evidence_hash="f" * 64, precheck={}, rollback={})
        conn.execute("UPDATE change_plans SET created_at = '2000-01-01T00:00:00Z' WHERE plan_key = 'plan-expired'")
        conn.commit()
        plan = conn.execute("SELECT * FROM change_plans WHERE plan_key = 'plan-expired'").fetchone()
        assert changed_plan_preconditions(plan, "sqlite:///missing.sqlite", enforcement_sources_by_site={}, source_sla_seconds=300, anchor_check=lambda _: True) == ["plan_expired"]
    finally:
        conn.close()
