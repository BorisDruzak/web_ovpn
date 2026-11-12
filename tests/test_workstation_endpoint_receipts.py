"""Authoritative installation receipts bind only the confirmed inventory target."""

import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.inventory.models import (
    InventoryAsset, InventoryAssetType, InventoryExternalBinding, InventoryExternalBindingStatus,
    InventoryObservation, InventoryPCDetails,
)
from app.workstations.endpoint_receipts import sync_installation_receipts
from app.workstations.journal import public_payload
from app.workstations.models import SourceSnapshot, WorkstationRequest
from test_workstations_reconcile import database


@pytest.fixture
def approved_installation(database, monkeypatch):
    from app.workstations import api

    now = datetime.now(timezone.utc)
    asset, machine, request, device = (str(uuid4()) for _ in range(4))
    installation_id = f"inventory-{asset}-{machine}-" + "a" * 32
    sha = "a" * 64
    plan_id = "setup-component-" + sha
    monkeypatch.setattr(api, "snapshot_state", lambda *_: {"stale": False})
    with database() as db:
        db.add(InventoryAsset(id=asset, asset_type=InventoryAssetType.PC, manual_revision=1))
        db.flush()
        db.add(InventoryPCDetails(asset_id=asset, os_name="ALT Workstation K 11"))
        db.add(SourceSnapshot(
            source="reconciliation", generation="fixture", batch_id=str(uuid4()), observed_at=now,
            data_json={"devices": [{
                "inventory_asset_id": asset, "inventory_revision": 1, "machine_uuid": machine,
                "registration_state": "ready", "identity_state": "observed",
            }]},
        ))
        db.add(WorkstationRequest(
            id=request, actor="user:fixture", action="plans.apply", permission="workstations:apply",
            intent_sha256=sha, status="succeeded", created_at=now - timedelta(seconds=30),
            parameters_json={"kind": "component", "plan_id": plan_id, "sha256": sha, "_endpoint_installation": {
                "asset_id": asset, "machine_uuid": machine, "asset_revision": 1, "installation_id": installation_id,
            }},
            data_json={"job_id": "job-20261112T010000Z-aaaaaaaa", "machine_uuid": machine,
                       "plan_id": plan_id, "plan_sha256": sha},
        ))
        db.commit()
    return SimpleNamespace(now=now, asset=asset, machine=machine, request=request, device=device, installation_id=installation_id)


class ReceiptClient:
    def __init__(self, receipt):
        self.receipt = receipt
        self.calls = []

    def lookup_inventory_installation(self, installation_id):
        self.calls.append(installation_id)
        return self.receipt


def test_windows_uncertain_issue_expires_after_the_provider_window_and_missing_receipt(database):
    from app.endpoint_platform_client import EndpointPlatformInstallationUnavailable
    from app.workstations.projection import fingerprint
    from app.workstations.windows_installation import ACTION, installation_id_for

    now = datetime.now(timezone.utc)
    asset, request_id = (str(uuid4()) for _ in range(2))
    secret = "fixture-only"
    with database() as db:
        db.add(InventoryAsset(id=asset, asset_type=InventoryAssetType.PC, manual_revision=1))
        row = WorkstationRequest(id=request_id, actor="user:former-operator", action=ACTION,
            permission="workstations:apply", intent_sha256="a" * 64, status="registered",
            data_json={"last_issue_started_at": (now - timedelta(minutes=33)).isoformat()})
        assignment_id = installation_id_for(secret, row, asset)
        row.parameters_json = {"_endpoint_installation": {
            "asset_id": asset, "machine_uuid": asset, "asset_revision": 1, "platform": "windows",
            "installation_digest": fingerprint(assignment_id),
        }}
        db.add(row)
        db.commit()

    class NoReceipt:
        def lookup_inventory_installation(self, value):
            assert value == assignment_id
            raise EndpointPlatformInstallationUnavailable()

    sync_installation_receipts(database, NoReceipt(), clock=lambda: now, windows_secret=secret)
    with database() as db:
        row = db.get(WorkstationRequest, request_id)
        assert row.data_json["installation_binding_state"] == "expired"


def connected(item):
    from uuid import UUID

    return SimpleNamespace(state="connected", device_id=UUID(item.device),
                           registered_at=item.now - timedelta(seconds=10), heartbeat_at=item.now)


def test_pending_receipt_then_heartbeat_creates_one_audited_binding(database, approved_installation):
    item = approved_installation
    client = ReceiptClient(SimpleNamespace(state="waiting_connection"))
    sync_installation_receipts(database, client, clock=lambda: item.now)
    with database() as db:
        assert db.scalar(select(InventoryExternalBinding)) is None
        assert db.get(WorkstationRequest, item.request).data_json["installation_binding_state"] == "waiting_connection"
    client.receipt = connected(item)
    sync_installation_receipts(database, client, clock=lambda: item.now)
    sync_installation_receipts(database, client, clock=lambda: item.now)
    with database() as db:
        binding = db.scalars(select(InventoryExternalBinding)).one()
        assert (binding.asset_id, binding.external_id, binding.status, binding.binding_method) == (
            item.asset, item.device, InventoryExternalBindingStatus.CONFIRMED, "installation_receipt",
        )
        audit = db.scalars(select(InventoryObservation)).one()
        assert audit.data_json["workstation_request_id"] == item.request
        row = db.get(WorkstationRequest, item.request)
        assert row.data_json["installation_binding_state"] == "connected"
        assert item.installation_id not in json.dumps([audit.data_json, public_payload(row.parameters_json), row.data_json])
    assert client.calls == [item.installation_id, item.installation_id]


@pytest.mark.parametrize("drift", ["asset_revision", "machine", "rejected", "bound_elsewhere"])
def test_receipt_respects_target_revision_machine_and_existing_binding(database, approved_installation, drift):
    item = approved_installation
    client = ReceiptClient(connected(item))
    with database() as db:
        if drift == "asset_revision":
            db.get(InventoryAsset, item.asset).manual_revision += 1
        elif drift == "machine":
            snapshot = db.get(SourceSnapshot, "reconciliation")
            snapshot.data_json = {"devices": [{**snapshot.data_json["devices"][0], "machine_uuid": str(uuid4())}]}
        else:
            other = item.asset
            if drift == "bound_elsewhere":
                other = str(uuid4())
                db.add(InventoryAsset(id=other, asset_type=InventoryAssetType.PC))
                db.flush()
            db.add(InventoryExternalBinding(
                asset_id=other, external_id=item.device, binding_method="manual", confidence=100, created_by="fixture-admin",
                status=InventoryExternalBindingStatus.REJECTED if drift == "rejected" else InventoryExternalBindingStatus.CONFIRMED,
            ))
        db.commit()
    sync_installation_receipts(database, client, clock=lambda: item.now)
    with database() as db:
        row = db.get(WorkstationRequest, item.request)
        assert row.data_json["installation_binding_state"] == "conflict"
        assert db.scalar(select(InventoryObservation)) is None
        binding = db.scalar(select(InventoryExternalBinding))
        assert binding is None or binding.status != InventoryExternalBindingStatus.CONFIRMED or binding.asset_id != item.asset


def test_directed_installation_keeps_mac_evidence_as_candidate_until_receipt(database, approved_installation):
    from app.inventory.endpoint import InventoryEndpointService
    from app.inventory.models import InventoryAssetIdentifier, InventoryIdentifierType, InventoryObservationSource
    from app.workstations.endpoint_receipts import installation_reservations

    item = approved_installation
    with database() as db:
        db.add(InventoryAssetIdentifier(
            asset_id=item.asset, identifier_type=InventoryIdentifierType.MAC, value="02:00:00:00:00:01",
            normalized_value="020000000001", source=InventoryObservationSource.MANUAL,
        ))
        db.flush()
        candidates = InventoryEndpointService().reconcile_candidates(db, [{
            "id": item.device, "baseline_collected_at": item.now.isoformat(),
            "baseline_mac_keys": ["mac-020000000001"],
        }], item.now, awaiting_installation=installation_reservations(db)[0])
        assert [candidate.status for candidate in candidates] == [InventoryExternalBindingStatus.CANDIDATE]
        db.commit()
    sync_installation_receipts(database, ReceiptClient(connected(item)), clock=lambda: item.now)
    with database() as db:
        binding = db.scalars(select(InventoryExternalBinding)).one()
        assert binding.status == InventoryExternalBindingStatus.CONFIRMED
        assert binding.binding_method == "installation_receipt"
        assert installation_reservations(db) == (frozenset(), frozenset())


def test_unavailable_older_receipts_do_not_starve_newer_assignment(database, approved_installation):
    from app.endpoint_platform_client import EndpointPlatformInstallationUnavailable
    from app.workstations.endpoint_receipts import MAX_PER_PASS

    item = approved_installation
    with database() as db:
        wanted = db.get(WorkstationRequest, item.request)
        for index in range(MAX_PER_PASS):
            asset_id, machine_id = str(uuid4()), str(uuid4())
            installation = f"inventory-{asset_id}-{machine_id}-" + "b" * 32
            params = {**wanted.parameters_json, "_endpoint_installation": {
                "asset_id": asset_id, "machine_uuid": machine_id, "asset_revision": 1,
                "installation_id": installation,
            }}
            db.add(WorkstationRequest(
                action="plans.apply", permission="workstations:apply", actor="user:fixture",
                intent_sha256="b" * 64, status="succeeded", created_at=wanted.created_at - timedelta(seconds=index + 1),
                parameters_json=params, data_json={**wanted.data_json, "machine_uuid": machine_id},
            ))
        db.commit()

    class Client(ReceiptClient):
        def lookup_inventory_installation(self, installation_id):
            super().lookup_inventory_installation(installation_id)
            if installation_id != item.installation_id:
                raise EndpointPlatformInstallationUnavailable()
            return self.receipt

    client = Client(connected(item))
    sync_installation_receipts(database, client, clock=lambda: item.now)
    assert item.installation_id not in client.calls
    sync_installation_receipts(database, client, clock=lambda: item.now)
    with database() as db:
        assert db.get(WorkstationRequest, item.request).data_json["installation_binding_state"] == "connected"


def test_unknown_native_admission_is_recovered_without_resubmitting(database, approved_installation, monkeypatch):
    from app.workstations import client as workstation_client

    item = approved_installation
    with database() as db:
        row = db.get(WorkstationRequest, item.request)
        data = row.data_json
        row.status, row.data_json = "unknown", None
        db.commit()
    calls = []

    class Controller:
        def with_deadline(self, deadline):
            return self

        def call(self, operation, parameters, *, request_id, scope):
            calls.append((operation, parameters, scope))
            return {"request_id": item.request, "state": "successful", "data": data}

    monkeypatch.setattr(workstation_client, "WorkstationsClient", Controller)
    sync_installation_receipts(database, ReceiptClient(connected(item)), clock=lambda: item.now)
    assert calls == [("receipts.status", {"request_id": item.request}, "read")]
    with database() as db:
        assert db.get(WorkstationRequest, item.request).data_json["installation_binding_state"] == "connected"


def test_apply_ignores_receipt_metadata_for_dedup_and_gateway_dispatch(database, approved_installation):
    from app.panel_operations import execution_future
    from app.workstations.service import WorkstationsService

    item = approved_installation
    with database() as db:
        recorded = db.get(WorkstationRequest, item.request)
        original, response = recorded.parameters_json, recorded.data_json
    calls = []

    class Controller:
        def call(self, operation, parameters, **kwargs):
            calls.append((operation, parameters))
            return response

    service = WorkstationsService(client=Controller(), session_factory=database)
    logical = {key: value for key, value in original.items() if key != "_endpoint_installation"}
    request_id = str(uuid4())
    issued = service.start("plans.apply", original, actor="user:fixture", request_id=request_id)
    execution_future(issued["operation_id"]).result(timeout=5)
    recovered = service.start("plans.apply", logical, actor="user:fixture", request_id=request_id)
    assert calls == [("plans.apply", logical)]
    assert recovered["operation_id"] == issued["operation_id"]
    assert item.installation_id not in json.dumps(recovered)


def test_reserved_network_key_blocks_mac_autoconfirm_on_other_card(database, approved_installation):
    from app.inventory.endpoint import InventoryEndpointService
    from app.inventory.models import InventoryAssetIdentifier, InventoryIdentifierType, InventoryObservationSource
    from app.workstations.endpoint_receipts import installation_reservations

    item = approved_installation
    other = str(uuid4())
    with database() as db:
        row = db.get(WorkstationRequest, item.request)
        target = {**row.parameters_json["_endpoint_installation"], "network_keys": ["mac:02:00:00:00:00:01"]}
        row.parameters_json = {**row.parameters_json, "_endpoint_installation": target}
        db.add(InventoryAsset(id=other, asset_type=InventoryAssetType.PC))
        db.flush()
        db.add(InventoryAssetIdentifier(
            asset_id=other, identifier_type=InventoryIdentifierType.MAC, value="02:00:00:00:00:01",
            normalized_value="020000000001", source=InventoryObservationSource.MANUAL,
        ))
        db.flush()
        assets, keys = installation_reservations(db)
        candidates = InventoryEndpointService().reconcile_candidates(db, [{
            "id": item.device, "baseline_collected_at": item.now.isoformat(),
            "baseline_mac_keys": ["mac-020000000001"],
        }], item.now, awaiting_installation=assets, reserved_mac_keys=keys)
        assert [(candidate.asset_id, candidate.status) for candidate in candidates] == [
            (other, InventoryExternalBindingStatus.CANDIDATE),
        ]


def test_slow_pending_response_preserves_completed_receipt(database, approved_installation):
    item = approved_installation

    class Slow(ReceiptClient):
        def lookup_inventory_installation(self, installation_id):
            sync_installation_receipts(database, ReceiptClient(connected(item)), clock=lambda: item.now)
            return SimpleNamespace(state="waiting_connection")

    sync_installation_receipts(database, Slow(None), clock=lambda: item.now)
    with database() as db:
        assert db.get(WorkstationRequest, item.request).data_json["installation_binding_state"] == "connected"
        assert db.scalars(select(InventoryExternalBinding)).one().external_id == item.device
