from __future__ import annotations

import base64
import copy
from datetime import timedelta
import hashlib
import importlib.util
from pathlib import Path

import pytest

from test_inventory_printer_plan import NOW, PC, PRINTER, LOCATION, TARGET, MAC, PMAC

SOURCE = (
    Path(__file__).resolve().parents[1]
    / "deploy/alt-linux/ansible/roles/inventory_printers/files/inventory_cups.py"
)


@pytest.fixture
def runtime():
    spec = importlib.util.spec_from_file_location("inventory_cups_test", SOURCE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def document():
    from app.inventory.printer_plan import digest

    ppd = b'*PPD-Adobe: "4.3"\n*ModelName: "Kyocera ECOSYS M2040dn KPDL"\n'
    driver = {
        "filename": "m2040.ppd",
        "sha256": hashlib.sha256(ppd).hexdigest(),
        "provenance": "test",
    }
    request = {
        "schema_version": 1,
        "created_at": NOW.isoformat(),
        "expires_at": (NOW + timedelta(minutes=10)).isoformat(),
        "target": {"uuid": TARGET, "macs": [MAC], "pc_asset_id": PC},
        "location_id": LOCATION,
        "source_sha256": "1" * 64,
        "ready": True,
        "excluded": [],
        "printers": [
            {
                "asset_id": PRINTER,
                "queue": "inv_kyocera_" + PRINTER.replace("-", ""),
                "ip": "192.0.2.20",
                "model": "M2040DN",
                "driver": driver,
                "snmp": {"version": "2c", "serial": "SERIAL1", "mac": PMAC},
            }
        ],
    }
    request["sha256"] = digest(request)
    return {
        "request": request,
        "drivers": {"m2040.ppd": base64.b64encode(ppd).decode()},
    }, {"M2040DN": driver}


class FakeCups:
    uuid = TARGET
    macs = [MAC]

    def __init__(self):
        self.queues = {}
        self.markers = {}
        self.writes = []

    def identity(self):
        return self.uuid, self.macs

    def inspect(self, name):
        return copy.deepcopy(self.queues.get(name))

    def marker(self, name):
        return copy.deepcopy(self.markers.get(name))

    def install(self, row, ppd):
        self.writes.append(row["queue"])
        self.queues[row["queue"]] = {
            "uri": "socket://" + row["ip"] + ":9100",
            "model": row["model"],
            "signature": hashlib.sha256(ppd).hexdigest(),
            "shared": False,
            "enabled": True,
            "accepting": True,
            "busy": False,
        }

    def save_marker(self, name, marker):
        self.markers[name] = copy.deepcopy(marker)


def run(runtime, document, system, **kwargs):
    return runtime.reconcile(document[0], document[1], system, now=NOW, **kwargs)


def test_first_install_then_noop_and_check_has_no_writes(runtime, document):
    system = FakeCups()
    assert run(runtime, document, system, mode="check")["changed"] is True
    assert system.writes == [] and system.markers == {}
    assert run(runtime, document, system, mode="apply")["changed"] is True
    assert len(system.writes) == 1
    assert run(runtime, document, system, mode="apply")["changed"] is False
    assert len(system.writes) == 1


@pytest.mark.parametrize(
    "case,code",
    [
        ("wrong_uuid", "printer_target_identity_mismatch"),
        ("wrong_mac", "printer_target_identity_mismatch"),
        ("expired", "printer_plan_expired"),
        ("tampered", "printer_plan_invalid"),
        ("driver", "printer_driver_invalid"),
        ("foreign", "printer_queue_not_owned"),
    ],
)
def test_rejects_before_any_change(runtime, document, case, code):
    system = FakeCups()
    request = document[0]["request"]
    if case == "wrong_uuid":
        system.uuid = PRINTER
    if case == "wrong_mac":
        system.macs = [PMAC]
    if case == "expired":
        from app.inventory.printer_plan import digest

        request["created_at"] = (NOW - timedelta(hours=1)).isoformat()
        request["expires_at"] = (NOW - timedelta(minutes=50)).isoformat()
        request["sha256"] = digest({k: v for k, v in request.items() if k != "sha256"})
    if case == "tampered":
        request["printers"][0]["ip"] = "192.0.2.21"
    if case == "driver":
        document[0]["drivers"]["m2040.ppd"] = base64.b64encode(b"BAD").decode()
    if case == "foreign":
        system.queues[request["printers"][0]["queue"]] = {
            "uri": "socket://192.0.2.20:9100"
        }
    with pytest.raises(runtime.Blocked, match=code):
        run(runtime, document, system, mode="apply")
    assert not system.writes and not system.markers


def test_owned_drift_is_repaired_but_pending_jobs_block_repair(runtime, document):
    system = FakeCups()
    run(runtime, document, system, mode="apply")
    queue = document[0]["request"]["printers"][0]["queue"]
    system.queues[queue]["shared"] = True
    system.queues[queue]["busy"] = True
    with pytest.raises(runtime.Blocked, match="printer_queue_busy"):
        run(runtime, document, system, mode="apply")
    assert len(system.writes) == 1
    system.queues[queue]["busy"] = False
    assert run(runtime, document, system, mode="apply")["changed"] is True
    assert run(runtime, document, system, mode="apply")["changed"] is False


def test_validate_mode_only_checks_inputs_and_target(runtime, document):
    class NoCups(FakeCups):
        def inspect(self, _):
            pytest.fail("validation must precede CUPS package/service changes")

    assert run(runtime, document, NoCups(), mode="validate")["changed"] is False


def test_foreign_later_queue_blocks_entire_batch_before_first_change(runtime, document):
    from app.inventory.printer_plan import digest

    other = copy.deepcopy(document[0]["request"]["printers"][0])
    other["asset_id"] = PC
    other["queue"] = "inv_kyocera_" + PC.replace("-", "")
    other["ip"] = "192.0.2.21"
    request = document[0]["request"]
    request["printers"].append(other)
    request["sha256"] = digest({k: v for k, v in request.items() if k != "sha256"})
    system = FakeCups()
    system.queues[other["queue"]] = {"uri": "socket://192.0.2.21:9100"}
    with pytest.raises(runtime.Blocked, match="printer_queue_not_owned"):
        run(runtime, document, system, mode="apply")
    assert system.writes == []


def test_external_ppd_filter_is_rejected_even_with_consistent_hashes(runtime, document):
    from app.inventory.printer_plan import digest

    ppd = b'*PPD-Adobe: "4.3"\n*ModelName: "Kyocera ECOSYS M2040dn KPDL"\n*cupsFilter: "application/postscript 0 dangerous"\n'
    document[1]["M2040DN"]["sha256"] = hashlib.sha256(ppd).hexdigest()
    document[0]["request"]["printers"][0]["driver"] = document[1]["M2040DN"]
    document[0]["drivers"]["m2040.ppd"] = base64.b64encode(ppd).decode()
    req = document[0]["request"]
    req["sha256"] = digest({k: v for k, v in req.items() if k != "sha256"})
    with pytest.raises(runtime.Blocked, match="printer_driver_invalid"):
        run(runtime, document, FakeCups(), mode="apply")


def test_check_defers_cups_observation_when_scheduler_is_unavailable(runtime, document):
    class StoppedCups(FakeCups):
        def scheduler_ready(self):
            return False

        def inspect(self, _):
            pytest.fail("dry-run must not query an unavailable scheduler")

    system = StoppedCups()
    result = run(runtime, document, system, mode="check")
    assert result["changed"] is True
    assert result["deferred"] == "cups_scheduler_unavailable"
    assert not system.writes and not system.markers


def test_all_ppds_are_conformance_checked_before_first_mutation(runtime, document):
    class BadConformance(FakeCups):
        def validate_driver(self, _row, _data):
            raise runtime.Blocked("printer_ppd_validation_failed")

    system = BadConformance()
    with pytest.raises(runtime.Blocked, match="printer_ppd_validation_failed"):
        run(runtime, document, system, mode="apply")
    assert system.writes == [] and system.markers == {}


def test_cups_commands_use_local_unix_socket_for_peer_authentication(
    runtime, monkeypatch
):
    from types import SimpleNamespace

    captured = []
    monkeypatch.setenv("CUPS_SERVER", "untrusted.example")

    def execute(argv, **kwargs):
        captured.append((argv, kwargs))
        return SimpleNamespace(returncode=0, stdout="ok")

    monkeypatch.setattr(runtime.subprocess, "run", execute)
    assert runtime.CupsSystem().call("/usr/sbin/lpadmin", "-p", "test") == "ok"
    argv, options = captured[0]
    assert argv[:3] == ["/usr/sbin/lpadmin", "-h", "/run/cups/cups.sock"]
    assert "CUPS_SERVER" not in options["env"]


def test_post_mutation_failure_remains_unknown(runtime, document):
    class ReceiptFailure(FakeCups):
        def save_marker(self, *_):
            raise OSError("private filesystem diagnostic")

    with pytest.raises(
        runtime.ApplyUnverified, match="printer_apply_outcome_unverified"
    ):
        run(runtime, document, ReceiptFailure(), mode="apply")
