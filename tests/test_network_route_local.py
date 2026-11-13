import errno
import json
import socket
import ssl
import subprocess

import dns.message
import dns.query
import dns.rcode
import dns.rrset
import pytest

from app import network_route_local
from app.network_route_local import probe_local_route


TARGET = "192.0.2.10"
SOURCE = "192.0.2.20"


@pytest.fixture(autouse=True)
def linux_probe_backend(monkeypatch):
    monkeypatch.setattr(network_route_local, "_WINDOWS", False)


def _route_result(argv):
    return subprocess.CompletedProcess(
        argv,
        0,
        b'[{"dst":"192.0.2.10","dev":"eth0","prefsrc":"192.0.2.20","internal":"secret"}]',
        b"",
    )


@pytest.fixture
def routed(monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda argv, **kwargs: _route_result(argv))


@pytest.mark.parametrize("gateway", ["192.0.2.1", "0.0.0.0"])
def test_windows_kernel_route_uses_bound_ipv4_and_matching_interface(monkeypatch, gateway):
    rows = [
        {"IPAddress": SOURCE, "InterfaceIndex": 10},
        {"DestinationPrefix": "192.0.2.0/24", "InterfaceIndex": 10, "NextHop": gateway, "RouteMetric": 3},
    ]

    def run(argv, timeout):
        assert argv[0].endswith("powershell.exe")
        assert f"-RemoteIPAddress '{TARGET}' -LocalIPAddress '{SOURCE}'" in argv[-1]
        assert timeout == network_route_local.ROUTE_TIMEOUT
        return subprocess.CompletedProcess(argv, 0, json.dumps(rows).encode(), b"")

    monkeypatch.setattr(network_route_local, "_WINDOWS", True)
    monkeypatch.setattr(network_route_local, "_run_local", run)
    route = network_route_local._kernel_route(TARGET, SOURCE)
    expected = {"dst": TARGET, "from": SOURCE, "dev": "ifindex-10", "metric": 3}
    if gateway != "0.0.0.0":
        expected["gateway"] = gateway
    assert route == {"status": "route_found", "result": expected}
    rows[1]["InterfaceIndex"] = 11
    assert network_route_local._kernel_route(TARGET, SOURCE) == {"status": "failed", "result": {}}


def test_expected_kernel_interface_blocks_traffic_on_mismatch(monkeypatch, routed):
    def unexpected(*args, **kwargs):
        pytest.fail("must not send probe traffic on another interface")

    monkeypatch.setattr(network_route_local, "_tcp", unexpected)
    result = probe_local_route(target=TARGET, protocol="tcp", port=443, expected_kernel_interface="tun0")
    assert result["status"] == "unavailable"
    assert result["evidence"]["reason"] == "kernel_interface_mismatch"
    assert result["kernel_route"]["result"]["dev"] == "eth0"


def test_expected_kernel_interface_allows_probe_on_match(monkeypatch, routed):
    monkeypatch.setattr(network_route_local, "_tcp", lambda *args: "reachable")
    result = probe_local_route(target=TARGET, protocol="tcp", port=443, expected_kernel_interface="eth0")
    assert result["status"] == "reachable"
    assert result["kernel_route"]["result"]["dev"] == "eth0"


@pytest.mark.parametrize(
    "stdout, stderr, exit_code, status, reason",
    [
        (
            b"64 bytes from 192.0.2.10: icmp_seq=1 ttl=64 time=0.781 ms",
            b"",
            0,
            "reachable",
            None,
        ),
        (b"", b"", 1, "timeout", "icmp_no_echo_reply"),
        (
            b"From 192.0.2.1 icmp_seq=1 Destination Host Unreachable",
            b"",
            1,
            "unreachable",
            "icmp_unreachable",
        ),
        (
            b"",
            b"ping: local error: message too long, mtu=1450",
            2,
            "unreachable",
            "icmp_fragmentation_required",
        ),
        (
            b"",
            b"ping: bind: Cannot assign requested address",
            2,
            "unavailable",
            "source_unavailable",
        ),
        (b"", b"unexpected local error", 2, "failed", "icmp_probe_failed"),
    ],
)
def test_icmp_uses_configured_source_and_ipv4_df_payload(
    monkeypatch, stdout, stderr, exit_code, status, reason
):
    def run(argv, **kwargs):
        assert kwargs["timeout"] <= 3
        if "neigh" in argv:
            return subprocess.CompletedProcess(argv, 0, b"[]", b"")
        if argv[0] == "/usr/sbin/ip":
            assert argv[1:] == ["-j", "-4", "route", "get", TARGET, "from", SOURCE]
            return _route_result(argv)
        assert argv == [
            "/usr/bin/ping",
            "-4",
            "-n",
            "-c",
            "1",
            "-W",
            "2",
            "-I",
            SOURCE,
            "-M",
            "do",
            "-s",
            "1472",
            TARGET,
        ]
        return subprocess.CompletedProcess(argv, exit_code, stdout, stderr)

    monkeypatch.setattr(subprocess, "run", run)

    result = probe_local_route(
        target=TARGET, protocol="icmp", source_address=SOURCE, mtu=1500
    )

    assert result["status"] == status
    assert result["evidence"]["mtu"] == 1500
    assert result["evidence"]["duration_ms"] >= 0
    assert result["evidence"].get("reason") == reason
    if status == "reachable":
        assert result["evidence"]["round_trip_ms"] == 0.781
    assert result["kernel_route"] == {
        "status": "route_found",
        "result": {"dst": TARGET, "dev": "eth0", "prefsrc": SOURCE},
    }


@pytest.mark.parametrize("gateway", [None, "192.0.2.1"])
@pytest.mark.parametrize("state", ["FAILED", "STALE", None])
def test_failed_probe_reads_only_next_hop_arp_after_ping(monkeypatch, gateway, state):
    address = gateway or TARGET
    route = {"dst": TARGET, "dev": "eth0.20"}
    if gateway:
        route["gateway"] = gateway
    commands = []

    def run(argv, **kwargs):
        commands.append(argv)
        if "route" in argv:
            stdout = json.dumps([route]).encode()
        elif "neigh" in argv:
            assert argv == [
                "/usr/sbin/ip", "-j", "-4", "neigh", "show",
                "to", address, "dev", "eth0.20",
            ]
            rows = [{"dst": address, "state": [state]}] if state else []
            stdout = json.dumps(rows).encode()
        else:
            return subprocess.CompletedProcess(argv, 1, b"", b"")
        return subprocess.CompletedProcess(argv, 0, stdout, b"")

    monkeypatch.setattr(subprocess, "run", run)
    result = probe_local_route(target=TARGET, protocol="icmp", source_address=SOURCE)

    assert result["status"] == "timeout"
    assert result["evidence"]["linux_neighbor"] == {
        "address": address,
        "interface": "eth0.20",
        "state": state.lower() if state else "not_cached",
    }
    assert commands[1][0] == "/usr/bin/ping"


@pytest.mark.parametrize(
    "changes",
    [
        {"target": "router.example.test"},
        {"target": "224.0.0.1"},
        {"target": "192.0.2.10 "},
        {"source_address": "0.0.0.0"},
        {"protocol": "other"},
        {"mtu": 67},
        {"protocol": "tcp", "port": 65536},
        {"protocol": "tcp", "port": True},
        {
            "protocol": "https",
            "server_name": "service.test",
            "http_path": "//another-host",
        },
        {
            "protocol": "https",
            "server_name": "service.test",
            "http_path": "/ok\r\nX: y",
        },
        {"protocol": "http", "server_name": "service.test\r\nX: y"},
        {"protocol": "http", "http_path": "http://other.test/"},
        {"protocol": "tls", "server_name": "host:443"},
        {"protocol": "dns", "dns_type": "AXFR"},
        {
            "protocol": "dns",
            "dns_name": "example.test",
            "expected_dns_answers": ("2001:db8::1",),
        },
    ],
)
def test_invalid_configuration_never_runs_route_or_probe(monkeypatch, changes):
    monkeypatch.setattr(
        subprocess, "run", lambda *args, **kw: pytest.fail("unexpected route lookup")
    )
    profile = {"target": TARGET, "protocol": "icmp"}
    profile.update(changes)

    result = probe_local_route(**profile)

    assert result["status"] == "unavailable"
    assert result["evidence"]["reason"] == "invalid_configuration"
    assert result["kernel_route"]["status"] == "not_run"


@pytest.mark.parametrize(
    "error, status, reason",
    [
        (TimeoutError("internal timeout"), "timeout", "timeout"),
        (
            ConnectionRefusedError(errno.ECONNREFUSED, "internal refusal"),
            "unreachable",
            "connection_refused",
        ),
        (
            OSError(errno.EADDRNOTAVAIL, "internal bind"),
            "unavailable",
            "source_unavailable",
        ),
        (OSError(errno.EIO, "internal error"), "failed", "transport_error"),
    ],
)
def test_tcp_pins_destination_and_source_and_classifies_errors(
    monkeypatch, routed, error, status, reason
):
    def connect(address, *, timeout, source_address):
        assert address == (TARGET, 443)
        assert 0 < timeout <= 3
        assert source_address == (SOURCE, 0)
        raise error

    monkeypatch.setattr(socket, "create_connection", connect)

    result = probe_local_route(
        target=TARGET, protocol="tcp", source_address=SOURCE, port=443
    )

    assert result["status"] == status
    assert result["evidence"]["reason"] == reason
    assert "internal" not in str(result)
    assert result["kernel_route"]["status"] == "route_found"


class _Connection:
    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def settimeout(self, timeout):
        assert 0 < timeout <= 3


def test_route_lookup_unavailable_does_not_override_successful_tcp(monkeypatch):
    def missing(*args, **kwargs):
        raise FileNotFoundError

    monkeypatch.setattr(subprocess, "run", missing)
    monkeypatch.setattr(
        socket, "create_connection", lambda *args, **kwargs: _Connection()
    )

    result = probe_local_route(target=TARGET, protocol="tcp", port=80)

    assert result["status"] == "reachable"
    assert result["kernel_route"] == {"status": "unavailable", "result": {}}


@pytest.mark.parametrize(
    "configured, port, authority, path, response_status, result_status",
    [
        ({}, 80, TARGET, "/", 200, "reachable"),
        (
            {"server_name": "service.test", "http_path": "/health"},
            80,
            "service.test",
            "/health",
            302,
            "unreachable",
        ),
        (
            {"server_name": "service.test", "port": 8080, "expected_http_status": 302},
            8080,
            "service.test:8080",
            "/",
            302,
            "reachable",
        ),
    ],
)
def test_http_pins_connection_and_uses_configured_host_without_tls_or_redirect(
    monkeypatch,
    routed,
    configured,
    port,
    authority,
    path,
    response_status,
    result_status,
):
    class PlainHttp(_Connection):
        read = False

        def sendall(self, data):
            expected = (
                f"GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
            )
            assert data == expected.encode("ascii")

        def recv(self, size):
            assert not self.read, "status line is enough to finish the probe"
            self.read = True
            return f"HTTP/1.1 {response_status} Example\r\n".encode("ascii")

    connections = []

    def connect(address, *, timeout, source_address):
        assert address == (TARGET, port)
        assert source_address == (SOURCE, 0)
        connections.append(address)
        return PlainHttp()

    monkeypatch.setattr(socket, "create_connection", connect)
    monkeypatch.setattr(
        ssl,
        "create_default_context",
        lambda: pytest.fail("plain HTTP does not use TLS"),
    )

    result = probe_local_route(
        target=TARGET, protocol="http", source_address=SOURCE, **configured
    )

    assert result["status"] == result_status
    assert result["evidence"]["http_status"] == response_status
    assert result["evidence"]["expected_http_status"] == configured.get(
        "expected_http_status", 200
    )
    assert "tls_version" not in result["evidence"]
    assert connections == [(TARGET, port)]


@pytest.mark.parametrize(
    "expected, status", [(None, "unreachable"), (302, "reachable")]
)
def test_https_verifies_sni_and_reports_status_without_following_redirect(
    monkeypatch, routed, expected, status
):
    class Tls(_Connection):
        def getpeercert(self):
            return {"notAfter": "Nov 20 23:59:59 2030 GMT"}

        def version(self):
            return "TLSv1.3"

        def sendall(self, data):
            assert (
                data
                == b"GET /health HTTP/1.1\r\nHost: service.test:8443\r\nConnection: close\r\n\r\n"
            )

        def recv(self, size):
            return b"HTTP/1.1 302 Found\r\nLocation: https://private.example.test/token\r\n\r\nsecret"

    def connect(address, *, timeout, source_address):
        assert address == (TARGET, 8443)
        return _Connection()

    def wrap(context, connection, *, server_hostname):
        assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
        assert server_hostname == "service.test"
        return Tls()

    monkeypatch.setattr(socket, "create_connection", connect)
    monkeypatch.setattr(ssl.SSLContext, "wrap_socket", wrap)

    result = probe_local_route(
        target=TARGET,
        protocol="https",
        port=8443,
        server_name="service.test",
        http_path="/health",
        expected_http_status=expected,
    )

    assert result["status"] == status
    assert result["evidence"]["http_status"] == 302
    assert result["evidence"]["expected_http_status"] == (expected or 200)
    assert result["evidence"]["tls_version"] == "TLSv1.3"
    assert result["evidence"]["tls_expires_at"] == "2030-11-20T23:59:59+00:00"
    assert "private.example" not in str(result)
    assert "secret" not in str(result)


def test_tls_distinguishes_certificate_verification_failure(monkeypatch, routed):
    def wrap(*args, **kwargs):
        raise ssl.SSLCertVerificationError("sensitive TLS error")

    monkeypatch.setattr(
        socket, "create_connection", lambda *args, **kwargs: _Connection()
    )
    monkeypatch.setattr(ssl.SSLContext, "wrap_socket", wrap)

    result = probe_local_route(
        target=TARGET, protocol="tls", port=443, server_name="service.test"
    )

    assert result["status"] == "unreachable"
    assert result["evidence"]["reason"] == "tls_certificate_invalid"
    assert "sensitive" not in str(result)


@pytest.mark.parametrize("protocol", ["tls", "https"])
@pytest.mark.parametrize("custom_ca", [False, True])
def test_tls_preserves_certificate_and_hostname_validation_with_optional_ca(
    monkeypatch, routed, tmp_path, protocol, custom_ca
):
    class Tls(_Connection):
        def version(self):
            return "TLSv1.3"

        def getpeercert(self):
            return {}

        def sendall(self, data):
            assert data.startswith(b"GET / HTTP/1.1\r\n")

        def recv(self, size):
            return b"HTTP/1.1 200 OK\r\n"

    ca_file = tmp_path / "internal-ca.pem"
    ca_file.touch()
    context = ssl.create_default_context()

    def trust(**kwargs):
        assert kwargs == ({"cafile": str(ca_file)} if custom_ca else {})
        return context

    def wrap(actual_context, connection, *, server_hostname):
        assert actual_context is context
        assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
        assert server_hostname == "service.test"
        return Tls()

    monkeypatch.setattr(ssl, "create_default_context", trust)
    monkeypatch.setattr(ssl.SSLContext, "wrap_socket", wrap)
    monkeypatch.setattr(
        socket, "create_connection", lambda *args, **kwargs: _Connection()
    )
    result = probe_local_route(
        target=TARGET,
        protocol=protocol,
        server_name="service.test",
        **({"tls_ca_file": str(ca_file)} if custom_ca else {}),
    )

    assert result["status"] == "reachable"
    assert result["evidence"]["tls_version"] == "TLSv1.3"
    assert str(ca_file) not in str(result)


@pytest.mark.parametrize("kind", ["missing", "directory", "invalid", "unreadable"])
def test_tls_reports_unusable_ca_as_setup_failure(monkeypatch, routed, tmp_path, kind):
    ca_file = tmp_path / "private-ca.pem"
    if kind == "directory":
        ca_file.mkdir()
    elif kind in ("invalid", "unreadable"):
        ca_file.write_text("not a certificate")
    if kind == "unreadable":

        def trust(*, cafile):
            raise PermissionError(cafile)

        monkeypatch.setattr(ssl, "create_default_context", trust)
    monkeypatch.setattr(
        socket, "create_connection", lambda *args, **kw: pytest.fail("unexpected probe")
    )

    result = probe_local_route(
        target=TARGET,
        protocol="tls",
        server_name="service.test",
        tls_ca_file=str(ca_file),
    )

    assert result["status"] == "unavailable"
    assert result["evidence"]["reason"] == "tls_ca_unavailable"
    assert "private-ca" not in str(result)


@pytest.mark.parametrize(
    "protocol, absolute", [("tls", False), ("http", True), ("icmp", True)]
)
def test_ca_path_must_be_absolute_and_used_with_tls(
    monkeypatch, tmp_path, protocol, absolute
):
    monkeypatch.setattr(
        subprocess, "run", lambda *args, **kw: pytest.fail("unexpected route lookup")
    )
    ca_file = str(tmp_path / "ca.pem") if absolute else "relative/ca.pem"

    result = probe_local_route(target=TARGET, protocol=protocol, tls_ca_file=ca_file)

    assert result["status"] == "unavailable"
    assert result["evidence"]["reason"] == "invalid_configuration"


@pytest.mark.parametrize(
    "expectation, answers, rcode, status, reason",
    [
        (
            ("192.0.2.30", "192.0.2.31"),
            ("192.0.2.31", "192.0.2.30"),
            0,
            "reachable",
            None,
        ),
        (
            ("192.0.2.30",),
            ("192.0.2.30", "192.0.2.31"),
            0,
            "unreachable",
            "dns_answer_mismatch",
        ),
        ((), (), 0, "unreachable", "dns_no_answer"),
        ((), (), dns.rcode.NXDOMAIN, "unreachable", "dns_rcode"),
    ],
)
def test_dns_checks_only_terminal_answer_from_the_configured_resolver(
    monkeypatch, routed, expectation, answers, rcode, status, reason
):
    def udp(query, where, *, timeout, port, source, raise_on_truncation):
        assert where == TARGET and port == 53 and source == SOURCE
        assert raise_on_truncation and 0 < timeout <= 3
        assert query.question[0].name.to_text() == "alias.example.test."
        assert query.question[0].rdtype == dns.rdatatype.A
        response = dns.message.make_response(query)
        response.set_rcode(rcode)
        if answers:
            response.answer.append(
                dns.rrset.from_text(
                    "alias.example.test.", 30, "IN", "CNAME", "private.example.test."
                )
            )
            response.answer.append(
                dns.rrset.from_text("private.example.test.", 30, "IN", "A", *answers)
            )
        return dns.message.from_wire(response.to_wire())

    monkeypatch.setattr(dns.query, "udp", udp)

    result = probe_local_route(
        target=TARGET,
        protocol="dns",
        source_address=SOURCE,
        dns_name="alias.example.test",
        expected_dns_answers=expectation,
    )

    assert result["status"] == status
    assert result["evidence"]["dns_rcode"] == dns.rcode.to_text(rcode)
    assert result["evidence"].get("reason") == reason
    if answers:
        assert result["evidence"]["dns_answer_count"] == len(answers)
        assert result["evidence"]["dns_answers_match"] == (status == "reachable")
    assert "private.example" not in str(result)
    assert "192.0.2.30" not in str(result)


def test_dns_tcp_fallback_uses_remaining_budget_and_same_resolver(monkeypatch, routed):
    from app import network_route_local

    times = iter([100, 100, 100, 100, 102, 102.5])
    monkeypatch.setattr(network_route_local, "monotonic", lambda: next(times))

    def udp(query, where, *, timeout, port, source, raise_on_truncation):
        assert (where, port, source, timeout) == (TARGET, 5353, SOURCE, 3)
        raise dns.message.Truncated

    def tcp(query, where, *, timeout, port, source):
        assert (where, port, source, timeout) == (TARGET, 5353, SOURCE, 1)
        response = dns.message.make_response(query)
        response.answer.append(
            dns.rrset.from_text(
                "service.test.", 30, "IN", "CNAME", "Target.Example.test."
            )
        )
        return dns.message.from_wire(response.to_wire())

    monkeypatch.setattr(dns.query, "udp", udp)
    monkeypatch.setattr(dns.query, "tcp", tcp)

    result = probe_local_route(
        target=TARGET,
        protocol="dns",
        port=5353,
        source_address=SOURCE,
        dns_name="service.test",
        dns_type="CNAME",
        expected_dns_answers=("target.example.test.",),
    )

    assert result["status"] == "reachable"
    assert result["evidence"]["dns_transport"] == "TCP"
    assert result["evidence"]["duration_ms"] == 2500


@pytest.mark.parametrize("transport,status", [("tcp", "reachable"), ("udp", "unreachable")])
def test_dns_uses_only_the_configured_transport(monkeypatch, routed, transport, status):
    calls = []

    def udp(query, where, *, timeout, port, source, raise_on_truncation):
        calls.append("udp")
        assert (where, port, source, raise_on_truncation) == (TARGET, 5353, SOURCE, True)
        raise dns.message.Truncated

    def tcp(query, where, *, timeout, port, source):
        calls.append("tcp")
        assert (where, port, source) == (TARGET, 5353, SOURCE)
        response = dns.message.make_response(query)
        response.answer.append(dns.rrset.from_text("service.test.", 30, "IN", "A", "192.0.2.31"))
        return dns.message.from_wire(response.to_wire())

    monkeypatch.setattr(dns.query, "udp", udp)
    monkeypatch.setattr(dns.query, "tcp", tcp)
    result = probe_local_route(
        target=TARGET, protocol="dns", source_address=SOURCE, port=5353,
        dns_name="service.test", dns_transport=transport, expected_dns_answers=("192.0.2.31",),
    )
    assert calls == [transport]
    assert result["status"] == status
    assert result["evidence"]["dns_transport"] == transport.upper()
    if transport == "udp":
        assert result["evidence"]["reason"] == "dns_truncated"


def test_kernel_empty_evidence_and_https_no_reply_are_typed(monkeypatch):
    class Tls(_Connection):
        def version(self):
            return "TLSv1.3"

        def getpeercert(self):
            return {}

        def sendall(self, data):
            assert data.startswith(b"GET / HTTP/1.1\r\n")

        def recv(self, size):
            return b""

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda argv, **kw: subprocess.CompletedProcess(argv, 0, b"[{}]", b""),
    )
    monkeypatch.setattr(socket, "create_connection", lambda *args, **kw: _Connection())
    monkeypatch.setattr(ssl.SSLContext, "wrap_socket", lambda *args, **kw: Tls())

    result = probe_local_route(
        target=TARGET, protocol="https", server_name="service.test"
    )

    assert result["kernel_route"]["status"] == "failed"
    assert result["status"] == "failed"
    assert result["evidence"]["reason"] == "http_no_response"
    assert result["evidence"]["tls_version"] == "TLSv1.3"
