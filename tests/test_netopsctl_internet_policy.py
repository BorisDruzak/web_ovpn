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
