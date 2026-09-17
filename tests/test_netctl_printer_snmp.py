from __future__ import annotations

SECRET = "docs-only-community-marker"


class FakeTransport:
    def __init__(self, *, responses, **options):
        self.responses = responses
        self.options = options

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    async def get(self, oid, *, capability=""):
        return self.responses[oid]


def _success(oid, value_type, value):
    from netctl.snmp.models import CapabilityResult, SnmpVarBind
    from netctl.snmp.outcomes import SnmpOutcome

    return CapabilityResult(
        capability="fixture",
        outcome=SnmpOutcome.SUCCESS_WITH_ROWS,
        rows=(SnmpVarBind(oid=oid, value_type=value_type, value=value),),
    )


def test_printer_snmp_prefers_v2c_and_returns_only_protocol_supplied_fields():
    """A printer probe may prefill its own SNMP data without exposing its community."""
    from netctl.printer_snmp import (
        PRINTER_NAME,
        PRINTER_PAGE_COUNTER,
        PRINTER_SERIAL,
        SYS_DESCR,
        inspect_printer_snmp,
    )

    calls = []
    responses = {
        SYS_DESCR: _success(SYS_DESCR, "octet_string", b"Kyocera ECOSYS"),
        PRINTER_NAME: _success(PRINTER_NAME, "octet_string", b"Kyocera M5526"),
        PRINTER_SERIAL: _success(PRINTER_SERIAL, "octet_string", b"SERIAL-150"),
        PRINTER_PAGE_COUNTER: _success(PRINTER_PAGE_COUNTER, "integer", 1234),
    }

    def factory(**options):
        calls.append(options)
        return FakeTransport(responses=responses, **options)

    result = inspect_printer_snmp(
        "192.168.100.150",
        secrets={"NETCTL_SECRET_PRINTER_SNMP_COMMUNITY": SECRET},
        transport_factory=factory,
    )

    assert result["status"] == "found"
    assert result["snmp_version"] == "2c"
    assert result["suggestions"] == {
        "custom_name": "Kyocera M5526",
        "serial_number": "SERIAL-150",
        "description": "Kyocera ECOSYS",
    }
    assert result["details"] == {"page_counter": 1234}
    assert [call["snmp_version"] for call in calls] == ["2c"]
    assert SECRET not in repr(result)


def test_printer_snmp_falls_back_to_v1_after_a_v2c_timeout():
    """Legacy printers must remain discoverable when they only implement SNMPv1."""
    from netctl.printer_snmp import PRINTER_NAME, PRINTER_PAGE_COUNTER, PRINTER_SERIAL, SYS_DESCR, inspect_printer_snmp
    from netctl.snmp.models import CapabilityResult
    from netctl.snmp.outcomes import SnmpOutcome

    calls = []
    timeout = CapabilityResult("fixture", SnmpOutcome.TIMEOUT, error_code="timeout")
    responses = {
        SYS_DESCR: _success(SYS_DESCR, "octet_string", b"Legacy printer"),
        PRINTER_NAME: _success(PRINTER_NAME, "octet_string", b"Legacy 1200"),
        PRINTER_SERIAL: timeout,
        PRINTER_PAGE_COUNTER: timeout,
    }

    def factory(**options):
        calls.append(options)
        if options["snmp_version"] == "2c":
            return FakeTransport(responses={oid: timeout for oid in responses}, **options)
        return FakeTransport(responses=responses, **options)

    result = inspect_printer_snmp(
        "192.168.100.150",
        secrets={"NETCTL_SECRET_PRINTER_SNMP_COMMUNITY": SECRET},
        transport_factory=factory,
    )

    assert result["status"] == "found"
    assert result["snmp_version"] == "1"
    assert [call["snmp_version"] for call in calls] == ["2c", "1"]


def test_printer_cli_accepts_only_one_canonical_ip_and_returns_public_fields(capsys, monkeypatch):
    """The CLI remains a one-printer read-only boundary for the inventory form."""
    import json
    import netctl.cli as cli

    monkeypatch.setattr(
        cli,
        "inspect_printer_snmp",
        lambda target: {"status": "found", "snmp_version": "2c", "suggestions": {"custom_name": "Printer"}, "details": {}},
    )

    rc = cli.main(["--json", "printer", "inspect-ip", "--target", "192.168.100.150"])
    payload = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert payload["printer"]["suggestions"] == {"custom_name": "Printer"}
