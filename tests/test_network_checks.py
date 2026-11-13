from ipaddress import IPv4Address
from subprocess import CompletedProcess, TimeoutExpired

from app import network_checks


def test_linux_route_only_returns_route_fields(monkeypatch):
    def run(argv, **kwargs):
        assert argv == ["/usr/sbin/ip", "-j", "-4", "route", "get", "192.0.2.20"]
        assert kwargs["timeout"] == 5
        return CompletedProcess(argv, 0, '[{"dev":"eth0","prefsrc":"192.0.2.1","extra":"hidden"}]', "")

    monkeypatch.setattr(network_checks.subprocess, "run", run)
    assert network_checks.lookup_linux_route(IPv4Address("192.0.2.20")) == {
        "status": "route_found", "result": {"dev": "eth0", "prefsrc": "192.0.2.1"},
    }


def test_trace_rejects_unmonitored_address_before_launch(monkeypatch):
    def netctl(args, **kwargs):
        assert args == ["hosts", "inspect", "192.0.2.20", "--availability-only"]
        return {"host": {"ip": "192.0.2.20", "availability": {"state": "not_monitored"}}}

    def unexpected_run(*args, **kwargs):
        raise AssertionError("probe was launched")

    monkeypatch.setattr(network_checks, "run_netctl", netctl)
    monkeypatch.setattr(network_checks.subprocess, "run", unexpected_run)
    assert network_checks.trace_linux_route(IPv4Address("192.0.2.20"))["status"] == "not_monitored"


def test_trace_retains_hops_on_timeout(monkeypatch):
    monkeypatch.setattr(network_checks, "run_netctl", lambda *args, **kwargs: {
        "host": {"ip": "192.0.2.20", "availability": {"state": "up"}},
    })

    def timeout(argv, **kwargs):
        assert argv == ["/usr/bin/stdbuf", "-oL", "/usr/bin/tracepath", "-4", "-n", "-m", "12", "192.0.2.20"]
        assert kwargs["timeout"] == 18
        raise TimeoutExpired(argv, 18, output=b"1?: [LOCALHOST] pmtu 1500\n1: 192.0.2.1 0.415ms\n2: no reply\n")

    monkeypatch.setattr(network_checks.subprocess, "run", timeout)
    result = network_checks.trace_linux_route(IPv4Address("192.0.2.20"))
    assert result["status"] == "partial"
    assert result["result"]["timed_out"] is True
    assert result["result"]["hops"] == [
        {"hop": 1, "address": "192.0.2.1", "rtt_ms": 0.415},
        {"hop": 2, "address": None, "rtt_ms": None},
    ]


def test_configured_source_test_hides_raw_driver_response(monkeypatch):
    calls = []

    def netctl(args, **kwargs):
        calls.append(args)
        if args == ["sources", "list"]:
            return {"sources": [{"name": "router", "enabled": 1}, {"name": "disabled", "enabled": 0}]}
        return {"status": "ok", "result": {"status": "ok", "private_field": "unused"}}

    monkeypatch.setattr(network_checks, "run_netctl", netctl)
    enabled = network_checks.SourceTestCheck(check="source_test", source="router")
    disabled = network_checks.SourceTestCheck(check="source_test", source="disabled")
    result = network_checks.execute_network_check(enabled)
    assert result["status"] == "ok" and result["result"] == {}
    assert network_checks.execute_network_check(disabled)["status"] == "not_found"
    assert calls == [["sources", "list"], ["sources", "test", "--no-update", "--", "router"], ["sources", "list"]]
