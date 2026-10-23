from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import uuid

import pytest

NOW = datetime(2026, 10, 23, 12, tzinfo=timezone.utc)
PC, PRINTER, OTHER, LOCATION, TARGET = [str(uuid.UUID(int=n)) for n in range(1, 6)]
MAC = "02:00:00:00:00:01"
PMAC = "02:00:00:00:00:02"


@pytest.fixture
def snapshot():
    return {
        "assets": [
            {"id": PC, "type": "PC", "location_id": LOCATION, "status": "in_use"},
            {
                "id": PRINTER,
                "type": "PRINTER",
                "location_id": LOCATION,
                "manufacturer": "Kyocera",
                "model": "ECOSYS M2030dn",
                "status": "in_use",
                "serial": "SERIAL1",
            },
        ],
        "locations": [LOCATION],
        "identifiers": [
            {"asset_id": PC, "type": "mac", "value": MAC},
            {"asset_id": PRINTER, "type": "ip", "value": "192.0.2.20"},
            {"asset_id": PRINTER, "type": "mac", "value": PMAC},
        ],
        "printer_details": [{"asset_id": PRINTER, "connection_type": "network"}],
    }


def probe(_args, _timeout):
    return {
        "status": "ok",
        "printer": {
            "status": "found",
            "snmp_version": "2c",
            "suggestions": {
                "model": "ECOSYS M2030dn",
                "description": "KYOCERA Printing System",
                "serial_number": "SERIAL1",
                "mac": PMAC,
            },
            "details": {"page_counter": 12},
        },
    }


def build(snapshot, call=probe):
    from app.inventory.printer_plan import build_plan

    return build_plan(snapshot, PC, TARGET, call, now=NOW)


def test_selects_only_exact_location_network_kyocera(snapshot):
    for n, changes in enumerate(
        [
            {"location_id": OTHER},
            {"manufacturer": "Pantum"},
            {"status": "broken"},
            {"type": "MONITOR"},
        ],
        20,
    ):
        row = dict(snapshot["assets"][1], id=str(uuid.UUID(int=n)), **changes)
        snapshot["assets"].append(row)
    calls = []
    plan = build(
        snapshot,
        lambda args, timeout: (calls.append((args, timeout)), probe(args, timeout))[1],
    )
    assert plan["ready"] is True
    assert [q["asset_id"] for q in plan["printers"]] == [PRINTER]
    assert plan["target"] == {"uuid": TARGET, "macs": [MAC], "pc_asset_id": PC}
    assert plan["location_id"] == LOCATION
    assert calls == [(["printer", "inspect-ip", "--target", "192.0.2.20"], 30)]
    assert plan["printers"][0]["queue"] == "inv_kyocera_" + PRINTER.replace("-", "")
    assert plan["expires_at"] == (NOW + timedelta(minutes=10)).isoformat()


@pytest.mark.parametrize(
    "case,reason",
    [
        ("multiple_ips", "printer_ip_ambiguous"),
        ("duplicate_ip", "printer_ip_conflict"),
        ("unknown_status", "printer_status_unknown"),
        ("unknown_connection", "printer_connection_unknown"),
        ("no_ip", "printer_ip_missing"),
        ("model_suffix", "printer_model_conflict"),
        ("snmp_timeout", "printer_snmp_unavailable"),
        ("snmp_partial", "printer_snmp_identity_missing"),
        ("serial_conflict", "printer_serial_conflict"),
        ("mac_conflict", "printer_mac_conflict"),
        ("unsupported", "printer_driver_unavailable"),
    ],
)
def test_unsafe_candidate_is_visible_and_makes_plan_nonready(snapshot, case, reason):
    reply = probe([], 30)
    if case == "multiple_ips":
        snapshot["identifiers"].append(
            {"asset_id": PRINTER, "type": "ip", "value": "192.0.2.21"}
        )
    if case == "duplicate_ip":
        snapshot["assets"].append({"id": OTHER, "type": "PC", "location_id": OTHER})
        snapshot["identifiers"].append(
            {"asset_id": OTHER, "type": "ip", "value": "192.0.2.20"}
        )
    if case == "unknown_status":
        snapshot["assets"][1]["status"] = None
    if case == "unknown_connection":
        snapshot["printer_details"] = []
    if case == "no_ip":
        snapshot["identifiers"] = [
            i for i in snapshot["identifiers"] if i["type"] != "ip"
        ]
    if case == "model_suffix":
        reply["printer"]["suggestions"]["model"] = "ECOSYS M2030dw"
    if case == "snmp_partial":
        reply["printer"]["suggestions"] = {}
    if case == "serial_conflict":
        reply["printer"]["suggestions"]["serial_number"] = "DIFFERENT"
    if case == "mac_conflict":
        reply["printer"]["suggestions"]["mac"] = "02:00:00:00:00:03"
    if case == "unsupported":
        snapshot["assets"][1]["model"] = "P6235cdn"
        reply["printer"]["suggestions"]["model"] = "ECOSYS P6235cdn"

    def call(*_):
        if case == "snmp_timeout":
            raise TimeoutError("private diagnostic must not leak")
        return reply

    plan = build(snapshot, call)
    assert plan["ready"] is False
    assert plan["printers"] == []
    assert plan["excluded"] == [{"asset_id": PRINTER, "reason": reason}]
    assert "private diagnostic" not in str(plan)


def test_duplicate_identical_identifier_rows_are_not_ambiguous(snapshot):
    snapshot["identifiers"].append(copy.deepcopy(snapshot["identifiers"][1]))
    assert build(snapshot)["ready"]


@pytest.mark.parametrize(
    "case", ["missing_pc", "not_pc", "no_location", "no_mac", "shared_mac"]
)
def test_invalid_pc_binding_is_rejected_before_any_probe(snapshot, case):
    from app.inventory.printer_plan import PrinterPlanError

    if case == "missing_pc":
        snapshot["assets"].pop(0)
    if case == "not_pc":
        snapshot["assets"][0]["type"] = "PRINTER"
    if case == "no_location":
        snapshot["assets"][0]["location_id"] = None
    if case == "no_mac":
        snapshot["identifiers"].pop(0)
    if case == "shared_mac":
        snapshot["assets"].append({"id": OTHER, "type": "PC"})
        snapshot["identifiers"].append({"asset_id": OTHER, "type": "mac", "value": MAC})
    with pytest.raises(PrinterPlanError):
        build(
            snapshot, lambda *_: pytest.fail("must validate PC before network lookup")
        )


def test_no_printers_is_explicit_nonready_without_probe(snapshot):
    snapshot["assets"].pop()
    plan = build(snapshot, lambda *_: pytest.fail("no candidate"))
    assert not plan["ready"] and plan["printers"] == []


def test_normalization_preserves_model_suffixes():
    from app.inventory.printer_plan import normalize_model

    assert normalize_model("Kyocera ECOSYS M2030dn KPDL") == "M2030DN"
    assert normalize_model("m5526") != normalize_model("ECOSYS M5526cdw")
    assert normalize_model("M5526cdn") != normalize_model("M5526cdw")


def test_export_revalidates_inventory_snmp_and_source_hash(snapshot, tmp_path):
    from app.inventory.printer_plan import export_plan, PrinterPlanError

    plan = build(snapshot)
    changed = copy.deepcopy(snapshot)
    changed["assets"][0]["location_id"] = OTHER
    with pytest.raises(PrinterPlanError):
        export_plan(plan, changed, probe, tmp_path, tmp_path / "bundle", now=NOW)
    with pytest.raises(PrinterPlanError):
        export_plan(
            plan, snapshot, lambda *_: {}, tmp_path, tmp_path / "bundle", now=NOW
        )
    with pytest.raises(PrinterPlanError):
        export_plan(
            plan,
            snapshot,
            probe,
            tmp_path,
            tmp_path / "bundle",
            now=NOW + timedelta(minutes=11),
        )
    plan["printers"][0]["ip"] = "192.0.2.99"
    with pytest.raises(PrinterPlanError):
        export_plan(plan, snapshot, probe, tmp_path, tmp_path / "bundle", now=NOW)
    assert not (tmp_path / "bundle").exists()


def test_export_verifies_exact_ppd_hash_before_creating_bundle(snapshot, tmp_path):
    from app.inventory.printer_plan import export_plan, PrinterPlanError, driver_catalog

    row = driver_catalog()["M2030DN"]
    (tmp_path / row["filename"]).write_text('*PPD-Adobe: "4.3"\n')
    with pytest.raises(PrinterPlanError, match="driver"):
        export_plan(
            build(snapshot), snapshot, probe, tmp_path, tmp_path / "bundle", now=NOW
        )
    assert not (tmp_path / "bundle").exists()


def test_inventory_reader_uses_existing_models_without_initializing_database(tmp_path):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session
    from app.db import Base
    from app.inventory.models import (
        InventoryAsset,
        InventoryAssetType,
        InventoryLocation,
    )
    from app.inventory.printer_inventory import read_inventory

    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add(InventoryLocation(id=LOCATION, name="private department name"))
        db.add(
            InventoryAsset(
                id=PC,
                asset_type=InventoryAssetType.PC,
                location_id=LOCATION,
                assigned_person_name="PRIVATE EMPLOYEE",
            )
        )
        db.commit()
        snapshot = read_inventory(db)
        assert snapshot["assets"][0]["id"] == PC
        assert snapshot["locations"] == [LOCATION]
        assert "PRIVATE" not in str(snapshot) and "private department" not in str(
            snapshot
        )


@pytest.mark.parametrize("model", ["M2040dn", "M2540dn", "M4125idn", "M5526cdw"])
def test_ppds_rejected_by_native_conformance_are_not_enabled(snapshot, model):
    snapshot["assets"][1]["model"] = model
    reply = probe([], 30)
    reply["printer"]["suggestions"]["model"] = model
    plan = build(snapshot, lambda *_: reply)
    assert not plan["ready"]
    assert plan["excluded"] == [
        {"asset_id": PRINTER, "reason": "printer_driver_unavailable"}
    ]


def test_successful_export_writes_only_verified_private_bundle(
    snapshot, tmp_path, monkeypatch
):
    from app.inventory import printer_plan
    import hashlib
    import json

    ppd = b'*PPD-Adobe: "4.3"\n*ModelName: "Kyocera ECOSYS M2030dn KPDL"\n'
    catalog = {
        "M2030DN": {
            "filename": "verified.ppd",
            "sha256": hashlib.sha256(ppd).hexdigest(),
            "provenance": "test",
        }
    }
    monkeypatch.setattr(printer_plan, "driver_catalog", lambda: catalog)
    (tmp_path / "verified.ppd").write_bytes(ppd)
    plan = build(snapshot)
    result = printer_plan.export_plan(
        plan, snapshot, probe, tmp_path, tmp_path / "bundle", now=NOW
    )
    assert result["queues"] == 1
    assert (tmp_path / "bundle/drivers/verified.ppd").read_bytes() == ppd
    assert json.loads((tmp_path / "bundle/request.json").read_text()) == plan
    assert (
        json.loads((tmp_path / "bundle/vars.json").read_text())[
            "inventory_printer_request"
        ]
        == plan
    )
