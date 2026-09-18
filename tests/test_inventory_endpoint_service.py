from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.inventory.models import (
    InventoryAssetType,
    InventoryEndpointState,
    InventoryExternalBinding,
    InventoryExternalBindingStatus as Status,
    InventoryObservationSource,
)
from app.inventory.service import InventoryService, InventoryValidationError

NOW = datetime(2026, 9, 18, 8, tzinfo=timezone.utc)
DEVICE_A = "Opaque-Device-A"
DEVICE_B = "Opaque-Device-B"
MAC = "00:11:22:33:44:55"
UUID = "11111111-2222-3333-4444-555555555555"


@pytest.fixture
def session(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'endpoint.sqlite'}")
    from app.db import get_sessionmaker, init_db, reset_engine_cache

    reset_engine_cache()
    init_db()
    with get_sessionmaker()() as db:
        yield db


@pytest.fixture
def service():
    from app.inventory.endpoint import InventoryEndpointService

    return InventoryEndpointService()


def pc(db, *, mac=MAC, serial=None, asset_type=InventoryAssetType.PC):
    inventory = InventoryService()
    asset = inventory.create_asset(db, asset_type, serial_number=serial)
    if mac:
        inventory.sync_identifiers(
            db, asset, [{"identifier_type": "mac", "value": mac}]
        )
    return asset


def identity(device=DEVICE_A, *, mac=MAC, **extra):
    return {
        "id": device,
        "baseline_mac_keys": ["mac-" + mac.replace(":", "").lower()] if mac else [],
        "baseline_collected_at": NOW.isoformat(),
        **extra,
    }


def state(db, binding, **values):
    row = InventoryEndpointState(
        binding_id=binding.id,
        asset_id=binding.asset_id,
        endpoint_device_id=binding.external_id,
        safe_context_json=values,
        last_success_at=NOW,
        refreshed_at=NOW,
        last_checked_at=NOW,
    )
    db.add(row)
    db.flush()
    return row


def test_exact_one_to_one_mac_auto_confirms_and_uuid_becomes_stable(session, service):
    asset = pc(session)
    binding = service.reconcile_candidates(session, [identity()], NOW)[0]
    assert (
        binding.asset_id,
        binding.status,
        binding.binding_method,
        binding.external_id,
    ) == (asset.id, Status.CONFIRMED, "mac_exact", DEVICE_A)
    InventoryService().sync_identifiers(
        session, asset, [{"identifier_type": "mac", "value": "66:77:88:99:aa:bb"}]
    )
    assert (
        service.reconcile_candidates(
            session, [identity(DEVICE_B, mac="66:77:88:99:aa:bb")], NOW
        )
        == []
    )
    assert service.lookup_confirmed_endpoint(session, DEVICE_A).id == asset.id
    assert service.lookup_confirmed_endpoint(session, DEVICE_B) is None


@pytest.mark.parametrize("duplicate_side", ["inventory", "endpoint"])
def test_duplicate_mac_stays_candidate(session, service, duplicate_side):
    pc(session)
    identities = [identity()]
    if duplicate_side == "inventory":
        pc(session)
    else:
        identities.append(identity(DEVICE_B))
    bindings = service.reconcile_candidates(session, identities, NOW)
    assert len(bindings) == 2
    assert all(b.status == Status.CANDIDATE for b in bindings)
    assert len(service.reconcile_candidates(session, identities, NOW)) == 2
    assert len(session.scalars(select(InventoryExternalBinding)).all()) == 2


def test_multiple_interfaces_do_not_greedily_confirm_two_devices(session, service):
    asset = pc(session)
    InventoryService().sync_identifiers(
        session,
        asset,
        [
            {"identifier_type": "mac", "value": MAC},
            {"identifier_type": "mac", "value": "66:77:88:99:aa:bb"},
        ],
    )
    bindings = service.reconcile_candidates(
        session, [identity(), identity(DEVICE_B, mac="66:77:88:99:aa:bb")], NOW
    )
    assert len(bindings) == 2
    assert all(b.status == Status.CANDIDATE for b in bindings)


def test_ip_hostname_display_name_user_never_create_binding(session, service):
    asset = pc(session, mac=None)
    asset.custom_name = asset.assigned_person_name = "same-name"
    InventoryService().sync_identifiers(
        session,
        asset,
        [
            {"identifier_type": "ip", "value": "192.0.2.5"},
            {"identifier_type": "hostname", "value": "same-name"},
        ],
    )
    assert (
        service.reconcile_candidates(
            session,
            [
                identity(
                    mac=None,
                    ip="192.0.2.5",
                    hostname="same-name",
                    display_name="same-name",
                    current_user="same-name",
                )
            ],
            NOW,
        )
        == []
    )


@pytest.mark.parametrize("kind", ["serial", "product_uuid"])
def test_serial_and_explicit_product_uuid_are_candidates_only(session, service, kind):
    asset = pc(session, mac=None, serial=" SN-123 " if kind == "serial" else None)
    if kind == "product_uuid":
        InventoryService().sync_identifiers(
            session,
            asset,
            [{"identifier_type": "other", "value": "product_uuid:" + UUID}],
        )
    extra = {"serial_number": "sn-123"} if kind == "serial" else {"product_uuid": UUID}
    binding = service.reconcile_candidates(session, [identity(mac=None, **extra)], NOW)[
        0
    ]
    assert binding.status == Status.CANDIDATE
    assert binding.binding_method == (
        "serial_exact" if kind == "serial" else "product_uuid_exact"
    )
    service.confirm_binding(session, asset.id, binding.id, "operator", NOW)
    assert service.lookup_confirmed_endpoint(session, DEVICE_A).id == asset.id


def test_arbitrary_other_identifier_is_not_product_uuid(session, service):
    asset = pc(session, mac=None)
    InventoryService().sync_identifiers(
        session, asset, [{"identifier_type": "other", "value": UUID}]
    )
    assert (
        service.reconcile_candidates(
            session, [identity(mac=None, product_uuid=UUID)], NOW
        )
        == []
    )


def test_rejection_suppresses_same_evidence_but_new_evidence_can_propose(
    session, service
):
    asset = pc(session, mac=None, serial="serial-one")
    binding = service.reconcile_candidates(
        session, [identity(mac=None, serial_number="serial-one")], NOW
    )[0]
    service.reject_binding(session, asset.id, binding.id, "operator", NOW)
    assert (
        service.reconcile_candidates(
            session,
            [identity(mac=None, serial_number="serial-one")],
            NOW + timedelta(minutes=1),
        )
        == []
    )
    asset.serial_number = "serial-two"
    new = service.reconcile_candidates(
        session, [identity(mac=None, serial_number="serial-two")], NOW
    )[0]
    assert new.id != binding.id
    assert binding.status == Status.REJECTED and binding.ended_at == NOW


def test_stale_missing_and_changed_candidates_cannot_confirm(session, service):
    asset = pc(session, mac=None, serial="SN")
    binding = service.reconcile_candidates(
        session, [identity(mac=None, serial_number="SN")], NOW
    )[0]
    with pytest.raises(InventoryValidationError):
        service.confirm_binding(
            session, asset.id, binding.id, "operator", NOW + timedelta(days=2)
        )
    asset.serial_number = "changed"
    with pytest.raises(InventoryValidationError):
        service.confirm_binding(session, asset.id, binding.id, "operator", NOW)
    asset.serial_number = "SN"
    service.reconcile_candidates(session, [], NOW)
    with pytest.raises(InventoryValidationError):
        service.confirm_binding(session, asset.id, binding.id, "operator", NOW)


def test_old_or_future_identity_is_not_auto_confirmed(session, service):
    pc(session)
    for timestamp in (NOW - timedelta(days=3), NOW + timedelta(days=3)):
        assert (
            service.reconcile_candidates(
                session, [identity(baseline_collected_at=timestamp.isoformat())], NOW
            )
            == []
        )


def test_manual_confirmation_rechecks_both_uniqueness_conditions(session, service):
    first = pc(session, serial="SN")
    pc(session, serial="SN")
    candidates = service.reconcile_candidates(
        session, [identity(), identity(DEVICE_B)], NOW
    )
    a = next(
        b for b in candidates if b.asset_id == first.id and b.external_id == DEVICE_A
    )
    service.confirm_binding(session, first.id, a.id, "operator", NOW)
    for b in candidates:
        if b.id != a.id and (b.asset_id == first.id or b.external_id == DEVICE_A):
            with pytest.raises(InventoryValidationError):
                service.confirm_binding(session, b.asset_id, b.id, "operator", NOW)


def test_detach_preserves_manual_data_state_and_observations(session, service):
    asset = pc(session, serial="SN")
    binding = service.reconcile_candidates(session, [identity()], NOW)[0]
    cached = state(session, binding, ram_gb=16)
    service.detach_binding(session, asset.id, binding.id, "operator", NOW)
    assert binding.status == Status.ENDED and binding.ended_at == NOW
    assert session.get(InventoryEndpointState, cached.binding_id) is not None
    assert asset.serial_number == "SN"
    assert service.lookup_confirmed_endpoint(session, DEVICE_A) is None
    assert service.asset_context(session, asset.id, NOW)["sources"]["endpoint"] == {}


def test_manual_detach_blocks_rediscovery_even_when_mac_evidence_changes(
    session, service
):
    asset = pc(session)
    binding = service.reconcile_candidates(session, [identity()], NOW)[0]
    service.detach_binding(session, asset.id, binding.id, "operator", NOW)
    assert service.reconcile_candidates(session, [identity()], NOW) == []
    InventoryService().sync_identifiers(
        session, asset, [{"identifier_type": "mac", "value": "66:77:88:99:aa:bb"}]
    )
    assert (
        service.reconcile_candidates(session, [identity(mac="66:77:88:99:aa:bb")], NOW)
        == []
    )
    assert session.scalars(select(InventoryExternalBinding)).all() == [binding]
    assert service.lookup_confirmed_endpoint(session, DEVICE_A) is None


def test_new_uuid_after_detach_requires_explicit_confirmation(session, service):
    asset = pc(session)
    old = service.reconcile_candidates(session, [identity()], NOW)[0]
    service.detach_binding(session, asset.id, old.id, "operator", NOW)
    candidate = service.reconcile_candidates(session, [identity(DEVICE_B)], NOW)[0]
    assert candidate.status == Status.CANDIDATE
    assert service.lookup_confirmed_endpoint(session, DEVICE_B) is None
    service.confirm_binding(session, asset.id, candidate.id, "operator", NOW)
    assert service.lookup_confirmed_endpoint(session, DEVICE_B).id == asset.id


def test_replaced_uuid_does_not_return_after_new_binding_is_detached(session, service):
    asset = pc(session)
    old = service.reconcile_candidates(session, [identity()], NOW)[0]
    replacement = service.replace_binding(
        session, asset.id, old.id, DEVICE_B, "operator", NOW
    )
    service.detach_binding(session, asset.id, replacement.id, "operator", NOW)
    assert (
        service.reconcile_candidates(session, [identity(), identity(DEVICE_B)], NOW)
        == []
    )
    assert service.lookup_confirmed_endpoint(session, DEVICE_A) is None
    assert service.lookup_confirmed_endpoint(session, DEVICE_B) is None


def test_replacement_keeps_history_and_failed_replacement_is_atomic(session, service):
    asset = pc(session)
    old = service.reconcile_candidates(session, [identity()], NOW)[0]
    pc(session, mac="66:77:88:99:aa:bb")
    service.reconcile_candidates(
        session, [identity(DEVICE_B, mac="66:77:88:99:aa:bb")], NOW
    )
    with pytest.raises(InventoryValidationError):
        service.replace_binding(session, asset.id, old.id, DEVICE_B, "operator", NOW)
    assert old.status == Status.CONFIRMED and old.ended_at is None
    new = service.replace_binding(
        session, asset.id, old.id, "New-OPAQUE-UUID", "operator", NOW
    )
    assert old.status == Status.REPLACED and old.ended_at == NOW
    assert new.external_id == "New-OPAQUE-UUID" and new.binding_method == "manual"
    assert service.lookup_confirmed_endpoint(session, old.external_id) is None
    assert service.lookup_confirmed_endpoint(session, new.external_id).id == asset.id


def test_non_pc_cannot_bind_or_replace(session, service):
    asset = pc(session, asset_type=InventoryAssetType.MONITOR)
    assert service.reconcile_candidates(session, [identity()], NOW) == []
    with pytest.raises(InventoryValidationError, match="PC"):
        service.confirm_binding(session, asset.id, "unknown", "operator", NOW)


def test_context_uses_local_endpoint_technical_values_preserves_manual_and_authority(
    session, service
):
    inventory = InventoryService()
    asset = pc(session, serial="MANUAL-SERIAL")
    location = inventory.create_location(session, name="Room 1")
    asset.location_id = location.id
    asset.assigned_person_name = "Inventory owner"
    inventory.update_details(session, asset, {"ram_gb": 8, "ram_type": "DDR4"})
    child = inventory.create_asset(
        session, InventoryAssetType.MONITOR, location_id=location.id
    )
    inventory.attach_existing_asset(session, asset.id, child.id, actor="operator")
    binding = service.reconcile_candidates(session, [identity()], NOW)[0]
    state(
        session,
        binding,
        ram_gb=16,
        serial_number="ENDPOINT-SERIAL",
        current_user="OS user",
        location_id="WRONG",
        assigned_person_name="WRONG",
        token="SECRET",
    )
    context = inventory.asset_context(session, asset.id, NOW)
    assert context["effective"]["ram_gb"] == {
        "value": 16,
        "source": "endpoint",
        "observed_at": NOW.isoformat(),
    }
    assert context["sources"]["manual"]["details"]["ram_gb"] == 8
    assert context["effective"]["serial_number"]["value"] == "MANUAL-SERIAL"
    assert context["effective"]["assigned_person_name"]["value"] == "Inventory owner"
    assert context["effective"]["current_user"]["value"] == "OS user"
    assert context["location"]["id"] == location.id
    assert context["related_devices"][0]["id"] == child.id
    assert [d["field"] for d in context["discrepancies"]] == ["ram_gb", "serial_number"]
    assert "SECRET" not in str(context)


@pytest.mark.parametrize(
    "action,expected",
    [("accept_endpoint", 16), ("keep_manual", 8), ("mark_verified", 8)],
)
def test_disposition_records_actor_before_after_without_changing_authority(
    session, service, action, expected
):
    asset = pc(session, serial="SN")
    asset.assigned_person_name = "Assigned person"
    InventoryService().update_details(session, asset, {"ram_gb": 8, "ram_type": "DDR4"})
    binding = service.reconcile_candidates(session, [identity()], NOW)[0]
    state(session, binding, ram_gb=16)
    record = service.resolve_discrepancy(
        session, asset.id, "ram_gb", action, "operator", NOW
    )
    assert InventoryService().details_for(session, asset)["ram_gb"] == expected
    assert InventoryService().details_for(session, asset)["ram_type"] == "DDR4"
    assert record.source == InventoryObservationSource.MANUAL
    assert record.data_json["actor"] == "operator"
    assert record.data_json["old_value"] == 8
    assert record.data_json["new_value"] == expected
    assert record.data_json["endpoint_value"] == 16
    assert record.data_json["action"] == action
    assert asset.assigned_person_name == "Assigned person"
    assert (asset.last_verified_at == NOW) == (action == "mark_verified")
    if action != "accept_endpoint":
        assert (
            service.asset_context(session, asset.id, NOW)["discrepancies"][0][
                "disposition"
            ]["action"]
            == action
        )


def test_resolution_rejects_unsupported_fields_and_uses_persisted_value(
    session, service
):
    asset = pc(session)
    binding = service.reconcile_candidates(session, [identity()], NOW)[0]
    state(session, binding, ram_gb=16, serial_number="NEW")
    for field in ("location_id", "assigned_person_name", "cpu_model"):
        with pytest.raises(InventoryValidationError):
            service.resolve_discrepancy(
                session, asset.id, field, "accept_endpoint", "operator", NOW
            )
    asset.serial_number = "OLD"
    service.resolve_discrepancy(
        session, asset.id, "serial_number", "accept_endpoint", "operator", NOW
    )
    assert asset.serial_number == "NEW"


def test_outage_shows_last_good_value_and_stale_freshness(session, service):
    asset = pc(session)
    binding = service.reconcile_candidates(session, [identity()], NOW)[0]
    cached = state(session, binding, ram_gb=16)
    cached.unavailable_since = NOW + timedelta(minutes=1)
    context = service.asset_context(session, asset.id, NOW + timedelta(minutes=2))
    assert context["effective"]["ram_gb"]["value"] == 16
    assert context["freshness"]["endpoint"]["status"] == "unavailable"
    assert context["freshness"]["endpoint"]["last_success_at"] == NOW.isoformat()


def test_bound_endpoint_cannot_automatically_move_to_another_pc(session, service):
    first = pc(session)
    original = service.reconcile_candidates(session, [identity()], NOW)[0]
    InventoryService().sync_identifiers(session, first, [])
    second = pc(session)
    candidate = service.reconcile_candidates(session, [identity()], NOW)[0]
    assert candidate.asset_id == second.id and candidate.status == Status.CANDIDATE
    assert service.lookup_confirmed_endpoint(session, DEVICE_A).id == first.id
    assert original.status == Status.CONFIRMED


def test_replacement_database_failure_rolls_back_old_binding(session, service):
    from sqlalchemy import text
    from sqlalchemy.exc import IntegrityError

    asset = pc(session)
    old = service.reconcile_candidates(session, [identity()], NOW)[0]
    session.commit()
    session.execute(
        text(
            "CREATE TRIGGER test_reject_replacement BEFORE INSERT ON inventory_external_bindings "
            "WHEN NEW.external_id = 'reject-me' BEGIN SELECT RAISE(ABORT, 'test rejection'); END"
        )
    )
    with pytest.raises(IntegrityError):
        service.replace_binding(session, asset.id, old.id, "reject-me", "operator", NOW)
    assert old.status == Status.CONFIRMED and old.ended_at is None
    assert service.lookup_confirmed_endpoint(session, DEVICE_A).id == asset.id
    assert service.lookup_confirmed_endpoint(session, "reject-me") is None


def test_changed_endpoint_value_does_not_inherit_previous_manual_decision(
    session, service
):
    asset = pc(session)
    InventoryService().update_details(session, asset, {"ram_gb": 8})
    binding = service.reconcile_candidates(session, [identity()], NOW)[0]
    cached = state(session, binding, ram_gb=16)
    service.resolve_discrepancy(
        session, asset.id, "ram_gb", "keep_manual", "operator", NOW
    )
    cached.safe_context_json = {"ram_gb": 32}
    context = service.asset_context(session, asset.id, NOW)
    assert context["discrepancies"][0]["disposition"] is None


@pytest.mark.parametrize(
    "field,manual_value,endpoint_value",
    [("ram_gb", 8, 16), ("serial_number", "MANUAL", "ENDPOINT")],
)
def test_keep_manual_selects_manual_effective_value_and_retains_both_sources(
    session, service, field, manual_value, endpoint_value
):
    asset = pc(session, serial="MANUAL")
    InventoryService().update_details(session, asset, {"ram_gb": 8})
    binding = service.reconcile_candidates(session, [identity()], NOW)[0]
    state(session, binding, **{field: endpoint_value})
    service.resolve_discrepancy(
        session, asset.id, field, "keep_manual", "operator", NOW
    )
    context = service.asset_context(session, asset.id, NOW)
    assert context["effective"][field]["value"] == manual_value
    assert context["effective"][field]["source"] == "manual"
    assert context["sources"]["endpoint"][field] == endpoint_value
    assert context["discrepancies"][0]["manual"] == manual_value
    assert context["discrepancies"][0]["endpoint"] == endpoint_value


@pytest.mark.parametrize("change", ["endpoint_value", "manual_value", "binding"])
def test_keep_manual_effective_override_expires_when_comparison_changes(
    session, service, change
):
    asset = pc(session)
    inventory = InventoryService()
    inventory.update_details(session, asset, {"ram_gb": 8})
    binding = service.reconcile_candidates(session, [identity()], NOW)[0]
    cached = state(session, binding, ram_gb=16)
    service.resolve_discrepancy(
        session, asset.id, "ram_gb", "keep_manual", "operator", NOW
    )
    assert (
        service.asset_context(session, asset.id, NOW)["effective"]["ram_gb"]["source"]
        == "manual"
    )
    if change == "endpoint_value":
        cached.safe_context_json = {"ram_gb": 32}
    elif change == "manual_value":
        inventory.update_details(session, asset, {"ram_gb": 4})
    else:
        replacement = service.replace_binding(
            session, asset.id, binding.id, DEVICE_B, "operator", NOW
        )
        state(session, replacement, ram_gb=16)
    context = service.asset_context(session, asset.id, NOW)
    assert context["effective"]["ram_gb"]["source"] == "endpoint"
    assert context["effective"]["ram_gb"]["value"] == (
        32 if change == "endpoint_value" else 16
    )
    assert context["discrepancies"][0]["disposition"] is None


def test_replacement_closes_existing_candidate_for_replacement_uuid(session, service):
    asset = pc(session)
    candidates = service.reconcile_candidates(
        session, [identity(), identity(DEVICE_B)], NOW
    )
    old = next(b for b in candidates if b.external_id == DEVICE_A)
    candidate = next(b for b in candidates if b.external_id == DEVICE_B)
    service.confirm_binding(session, asset.id, old.id, "operator", NOW)
    new = service.replace_binding(session, asset.id, old.id, DEVICE_B, "operator", NOW)
    assert candidate.ended_at == NOW
    assert candidate.status == Status.REPLACED
    assert new.status == Status.CONFIRMED


def test_invalid_resolution_is_non_mutating_and_requires_actor(session, service):
    asset = pc(session)
    InventoryService().update_details(session, asset, {"ram_gb": 8})
    binding = service.reconcile_candidates(session, [identity()], NOW)[0]
    state(session, binding, ram_gb=-16)
    for actor, action in (
        ("operator", "accept_endpoint"),
        ("", "mark_verified"),
        ("operator", "delete"),
    ):
        with pytest.raises(InventoryValidationError):
            service.resolve_discrepancy(session, asset.id, "ram_gb", action, actor, NOW)
    assert InventoryService().details_for(session, asset)["ram_gb"] == 8
    assert asset.last_verified_at is None


def test_netctl_source_is_visible_and_endpoint_hostname_is_effective(session, service):
    asset = pc(session)
    InventoryService().sync_identifiers(
        session,
        asset,
        [
            {"identifier_type": "mac", "value": MAC},
            {
                "identifier_type": "hostname",
                "value": "network-name",
                "source": "netctl",
            },
            {"identifier_type": "ip", "value": "192.0.2.6", "source": "netctl"},
        ],
    )
    binding = service.reconcile_candidates(session, [identity()], NOW)[0]
    state(session, binding, hostname="endpoint-name")
    context = service.asset_context(session, asset.id, NOW + timedelta(hours=1))
    assert context["effective"]["hostname"]["value"] == "endpoint-name"
    assert context["effective"]["ip"]["source"] == "netctl"
    assert {r["value"] for r in context["sources"]["netctl"]["identifiers"]} == {
        "network-name",
        "192.0.2.6",
    }
    assert context["freshness"]["endpoint"]["status"] == "stale"
