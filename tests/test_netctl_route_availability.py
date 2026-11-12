import subprocess
from io import BytesIO

import pytest

from netctl.drivers import mikrotik_api, mikrotik_ssh


TARGET = "192.0.2.50"
SOURCE = {
    "name": "router",
    "driver": "mikrotik_ssh",
    "enabled": True,
    "host": "192.0.2.1",
    "port": 22,
    "username": "observer",
    "ssh_connect_timeout": 90,
    "ssh_identity_file": "/private/test-key",
    "ssh_proxy_jump": "test-jump",
}
API_SOURCE = {**SOURCE, "driver": "mikrotik_api", "port": 8729, "secret_ref": "router-probe"}
API_SECRETS = {"NETCTL_SECRET_ROUTER_PROBE_PASSWORD": "test-only-credential"}


def run_probe(**kwargs):
    from netctl.route_availability import probe_router_route

    return probe_router_route(**{
        "source": "router", "target": TARGET, "sources": [SOURCE], "secrets": {}, **kwargs,
    })


def fake_ssh(monkeypatch, *, stdout="", stderr="", returncode=0):
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, returncode, stdout, stderr)

    monkeypatch.setattr(mikrotik_ssh.subprocess, "run", run)
    return calls


def fake_api(monkeypatch, reply, *, login=("!done", "")):
    class FakeSocket:
        def __init__(self):
            self.data = BytesIO(b"".join(bytes([len(word)]) + word.encode() for word in (*login, *reply)))
            self.words = []
            self.closed = False
            self.timeouts = []

        def recv(self, length):
            return self.data.read(length)

        def sendall(self, payload):
            self.words.append(payload[1:].decode())

        def settimeout(self, value):
            self.timeouts.append(value)

        def close(self):
            self.closed = True

    sock = FakeSocket()
    monkeypatch.setattr(mikrotik_api.socket, "create_connection", lambda *args, **kwargs: sock)
    return sock


def test_router_probe_passes_the_requested_bindings_and_reports_metrics_without_claiming_a_path(monkeypatch):
    calls = fake_ssh(
        monkeypatch,
        stdout=(
            "0 192.0.2.50 1492 64 1ms45us\n"
            "1 192.0.2.50 timeout\n"
            "2 192.0.2.50 1492 64 1ms163us\n"
            "    sent=3 received=2 packet-loss=33% min-rtt=1ms45us avg-rtt=1ms104us max-rtt=1ms163us\n"
        ),
    )

    result = run_probe(
        source_address="192.0.2.10", interface="wan-2.100", routing_table="rtab-WAN2", mtu=1492,
    )

    [call] = calls
    command, options = call
    assert command[-2] == "observer@192.0.2.1"
    assert command[-1].split() == [
        "/ping", "address=192.0.2.50", "count=3", "interval=1s", "src-address=192.0.2.10",
        "interface=wan-2.100", "routing-table=rtab-WAN2", "size=1492", "do-not-fragment",
    ]
    assert command[command.index("-i") + 1] == "/private/test-key"
    assert command[command.index("-J") + 1] == "test-jump"
    assert options["timeout"] <= 18
    assert options["shell"] is False
    assert result["status"] == "reachable"
    assert result["observed_path"] is None
    evidence = result["evidence"]
    assert evidence["requested"] == {
        "source_address": "192.0.2.10", "interface": "wan-2.100", "routing_table": "rtab-WAN2", "mtu": 1492,
    }
    assert (evidence["sent"], evidence["received"], evidence["packet_loss_pct"]) == (3, 2, 33.33)
    assert evidence["rtt_ms"] == {"min": 1.045, "avg": 1.104, "max": 1.163}
    assert "rtt_variation" not in evidence
    assert "/private/test-key" not in repr(result)


def test_ssh_rtt_variation_uses_only_adjacent_echo_replies(monkeypatch):
    fake_ssh(monkeypatch, stdout=(
        "0 192.0.2.50 56 64 2ms\n"
        "1 192.0.2.50 56 64 5ms\n"
        "2 192.0.2.5 56 63 40ms ttl exceeded\n"
        "sent=3 received=2 min-rtt=2ms avg-rtt=3ms500us max-rtt=5ms\n"
    ))
    assert run_probe()["evidence"]["rtt_variation"] == {"mean_abs_delta_ms": 3.0, "pairs": 1}


def test_api_rtt_variation_uses_sequence_order(monkeypatch):
    fake_api(monkeypatch, [
        "!re", "=seq=1", "=host=192.0.2.50", "=time=7ms", "",
        "!re", "=seq=0", "=host=192.0.2.50", "=time=2ms", "",
        "!re", "=seq=2", "=host=192.0.2.50", "=time=4ms", "=status=echo reply", "=sent=3", "=received=3", "",
        "!done", "",
    ])
    evidence = run_probe(sources=[API_SOURCE], secrets=API_SECRETS)["evidence"]
    assert evidence["rtt_variation"] == {"mean_abs_delta_ms": 4.0, "pairs": 2}


def test_no_icmp_replies_is_a_completed_probe_not_a_transport_timeout(monkeypatch):
    fake_ssh(monkeypatch, stdout="    sent=3 received=0 packet-loss=100%\n")

    result = run_probe()

    assert result["status"] == "unreachable"
    assert result["reason"] == "no_icmp_reply"
    assert result["evidence"]["packet_loss_pct"] == 100
    assert "rtt_ms" not in result["evidence"]


def test_mtu_error_reports_the_actual_icmp_error_responder(monkeypatch):
    fake_ssh(
        monkeypatch,
        stdout=(
            "0 192.0.2.5 576 63 893us fragmentation needed and DF set\n"
            "1 packet too large and cannot be fragmented\n"
            "2 packet too large and cannot be fragmented\n"
            "sent=3 received=0 packet-loss=100%\n"
        ),
    )

    result = run_probe(mtu=1500)

    assert result["status"] == "unreachable"
    assert result["reason"] == "mtu_exceeded"
    assert result["observed_path"] is None
    assert result["evidence"]["icmp_errors"] == [
        {"sequence": 0, "status": "fragmentation_needed", "responder": "192.0.2.5"},
        {"sequence": 1, "status": "packet_too_large", "responder": None},
        {"sequence": 2, "status": "packet_too_large", "responder": None},
    ]
    assert "path_mtu" not in result["evidence"]


def test_local_ping_error_with_target_in_host_column_has_no_observed_responder(monkeypatch):
    fake_ssh(monkeypatch, stdout="0 192.0.2.50 no route to host\nsent=3 received=0 packet-loss=100%")

    result = run_probe()

    assert result["evidence"]["icmp_errors"] == [{"sequence": 0, "status": "no_route", "responder": None}]


def test_router_api_uses_the_same_selectors_and_final_cumulative_counts(monkeypatch):
    sock = fake_api(monkeypatch, [
        "!re", "=seq=0", "=sent=1", "=received=1", "=packet-loss=0", "",
        "!re", "=seq=1", "=sent=2", "=received=1", "=packet-loss=50", "=status=timeout", "",
        "!re", "=seq=2", "=sent=3", "=received=2", "=packet-loss=33",
        "=min-rtt=551us", "=avg-rtt=725us", "=max-rtt=899us", "",
        "!done", "",
    ])

    result = run_probe(
        sources=[API_SOURCE], secrets=API_SECRETS, source_address="192.0.2.10",
        interface="ether9", routing_table="rtab-RTK", mtu=1492,
    )

    assert sock.closed
    assert sock.words == [
        "/login", "=name=observer", "=password=test-only-credential", "",
        "/ping", "=address=192.0.2.50", "=count=3", "=interval=1s", "=src-address=192.0.2.10",
        "=interface=ether9", "=routing-table=rtab-RTK", "=size=1492", "=do-not-fragment=", "",
    ]
    assert result["status"] == "reachable"
    assert result["observed_path"] is None
    assert result["evidence"]["method"] == "routeros_api_ping"
    assert result["evidence"]["sent"] == 3
    assert result["evidence"]["received"] == 2
    assert result["evidence"]["packet_loss_pct"] == 33.33
    assert result["evidence"]["rtt_ms"] == {"min": 0.551, "avg": 0.725, "max": 0.899}
    assert "test-only-credential" not in repr(result)


@pytest.mark.parametrize("reply, expected", [
    (["!re", "=address=192.0.2.50", "=interface=ether9", "=status=incomplete", "=complete=false", "",
      "!done", ""], {"status": "observed", "state": "incomplete", "resolved": False}),
    (["!re", "=address=192.0.2.50", "=interface=other", "=status=reachable", "=complete=true", "",
      "!done", ""], {"status": "missing"}),
    (["!trap", "=message=permission denied", ""], {"status": "unavailable"}),
])
def test_gateway_arp_preserves_ping_and_uses_exact_interface(monkeypatch, reply, expected):
    sock = fake_api(monkeypatch, ["!re", "=sent=3", "=received=0", "", "!done", "", *reply])
    result = run_probe(sources=[API_SOURCE], secrets=API_SECRETS, interface="ether9", observe_neighbor=True)
    assert result["status"] == "unreachable"
    assert result["observed_path"] is None
    assert result["evidence"]["gateway_arp"] == expected
    assert sock.words[-5:] == ["/ip/arp/print", "=.proplist=address,interface,status,complete,disabled",
                               "?address=192.0.2.50", "?interface=ether9", ""]


def test_router_api_reports_icmp_error_without_guessing_a_path(monkeypatch):
    fake_api(monkeypatch, [
        "!re", "=seq=0", "=host=192.0.2.5", "=size=576", "=ttl=63", "=time=893us",
        "=status=fragmentation needed and DF set", "=sent=1", "=received=0", "",
        "!re", "=seq=2", "=status=timeout", "=sent=3", "=received=0", "",
        "!done", "",
    ])

    result = run_probe(sources=[API_SOURCE], secrets=API_SECRETS, mtu=1500)

    assert result["status"] == "unreachable"
    assert result["reason"] == "mtu_exceeded"
    assert result["evidence"]["icmp_errors"] == [
        {"sequence": 0, "status": "fragmentation_needed", "responder": "192.0.2.5"},
    ]
    assert result["observed_path"] is None


@pytest.mark.parametrize("trap", ["input does not match any value of routing-table", "unknown parameter routing-table"])
def test_router_api_argument_trap_never_falls_back_to_another_probe(monkeypatch, trap):
    sock = fake_api(monkeypatch, [
        "!trap", "=category=1", f"=message={trap}", "",
        "!done", "",
    ])

    result = run_probe(sources=[API_SOURCE], secrets=API_SECRETS, routing_table="missing")

    assert result["status"] == "unavailable"
    assert result["reason"] == "routeros_rejected_probe"
    assert sock.words.count("/ping") == 1
    assert "received" not in result["evidence"]


def test_router_api_login_trap_closes_transport_and_sanitizes_error(monkeypatch):
    sock = fake_api(monkeypatch, [], login=["!trap", "=message=invalid credentials (test-only detail)", ""])

    result = run_probe(sources=[API_SOURCE], secrets=API_SECRETS)

    assert result["status"] == "failed"
    assert result["reason"] == "router_api_failed"
    assert sock.closed
    assert "/ping" not in sock.words
    assert "test-only detail" not in repr(result)


def test_api_observes_first_hop_on_completed_probe_without_changing_ping_outcome(monkeypatch):
    sock = fake_api(monkeypatch, [
        "!re", "=seq=2", "=status=timeout", "=sent=3", "=received=0", "",
        "!done", "",
        "!re", "=seq=0", "=status=TTL exceeded", "=host=192.0.2.2", "=time=831us", "",
        "!done", "",
    ])

    result = run_probe(
        sources=[API_SOURCE], secrets=API_SECRETS, interface="ether9", expected_first_hop="192.0.2.3",
    )

    assert sock.words[-7:] == ["/ping", "=address=192.0.2.50", "=count=1", "=interval=1s", "=interface=ether9", "=ttl=1", ""]
    assert sock.timeouts[0] == 8
    assert 0 < sock.timeouts[1] <= 4
    assert result["status"] == "unreachable"
    assert result["reason"] == "no_icmp_reply"
    assert result["observed_path"] == "192.0.2.2"
    assert result["evidence"]["first_hop"] == {
        "expected": "192.0.2.3", "status": "observed", "reason": "ttl_exceeded", "rtt_ms": 0.831,
    }


def test_ssh_uses_shorter_timeout_for_first_hop(monkeypatch):
    calls = []

    def run(command, **options):
        calls.append((command[-1], options["timeout"]))
        output = (
            "0 192.0.2.2 84 64 20ms894us TTL exceeded\nsent=1 received=0 packet-loss=100%\n"
            if " ttl=1" in command[-1] else "sent=3 received=3 packet-loss=0%\n"
        )
        return subprocess.CompletedProcess(command, 0, output, "")

    monkeypatch.setattr(mikrotik_ssh.subprocess, "run", run)

    result = run_probe(expected_first_hop="192.0.2.2")

    assert len(calls) == 2
    assert calls[1][0] == "/ping address=192.0.2.50 count=1 interval=1s ttl=1"
    assert 0 < calls[1][1] <= 4
    assert result["status"] == "reachable"
    assert result["observed_path"] == "192.0.2.2"
    assert result["evidence"]["first_hop"]["rtt_ms"] == 20.894


def test_ssh_first_hop_rejection_keeps_primary_reachability(monkeypatch):
    def run(command, **options):
        output = (
            "expected end of command (line 1 column 60)\n"
            if " ttl=1" in command[-1] else "sent=3 received=3 packet-loss=0%\n"
        )
        return subprocess.CompletedProcess(command, 0, output, "")

    monkeypatch.setattr(mikrotik_ssh.subprocess, "run", run)

    result = run_probe(expected_first_hop="192.0.2.2")

    assert result["status"] == "reachable"
    assert result["observed_path"] is None
    assert result["evidence"]["first_hop"]["status"] == "unavailable"


def test_api_echo_reply_without_ttl_exceeded_does_not_observe_first_hop(monkeypatch):
    fake_api(monkeypatch, [
        "!re", "=seq=2", "=sent=3", "=received=3", "",
        "!done", "",
        "!re", "=seq=0", "=host=192.0.2.50", "=time=831us", "=sent=1", "=received=1", "",
        "!done", "",
    ])

    result = run_probe(sources=[API_SOURCE], secrets=API_SECRETS, expected_first_hop="192.0.2.2")

    assert result["status"] == "reachable"
    assert result["observed_path"] is None
    assert result["evidence"]["first_hop"]["reason"] == "no_ttl_exceeded"


@pytest.mark.parametrize("returncode", [0, 1])
def test_router_that_rejects_routing_table_does_not_retry_without_binding(monkeypatch, returncode):
    calls = fake_ssh(monkeypatch, stdout="expected end of command (line 1 column 60)\n", returncode=returncode)

    result = run_probe(routing_table="rtab-WAN2")

    assert result["status"] == "unavailable"
    assert result["reason"] == "routeros_rejected_probe"
    assert len(calls) == 1
    assert "received" not in result["evidence"]


def test_ssh_failure_never_turns_a_partial_result_into_reachability_or_leaks_stderr(monkeypatch):
    fake_ssh(monkeypatch, returncode=255, stdout="sent=3 received=3 packet-loss=0%",
             stderr="observer@192.0.2.1: Permission denied (private details).")

    result = run_probe()

    assert result["status"] == "failed"
    assert result["reason"] == "ssh_failed"
    assert "received" not in result["evidence"]
    assert "private details" not in repr(result)


def test_ssh_command_timeout_has_no_icmp_counters(monkeypatch):
    def timed_out(command, **kwargs):
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    monkeypatch.setattr(mikrotik_ssh.subprocess, "run", timed_out)

    result = run_probe()

    assert result["status"] == "timeout"
    assert result["reason"] == "ssh_timeout"
    assert "sent" not in result["evidence"]


@pytest.mark.parametrize("stdout", ["sent=2 received=2", "sent=3 received=4", "arbitrary device output"])
def test_incomplete_or_impossible_summaries_fail_without_guessed_metrics(monkeypatch, stdout):
    fake_ssh(monkeypatch, stdout=stdout)

    result = run_probe()

    assert result["status"] == "failed"
    assert result["reason"] == "unexpected_ping_output"
    assert "received" not in result["evidence"]


@pytest.mark.parametrize(
    "overrides",
    [
        {"target": "router.example"}, {"target": "192.0.2.0/24"}, {"target": "239.0.0.1"},
        {"target": "255.255.255.255"}, {"target": "192.0.2.50; /system reboot"},
        {"target": "127.0.0.1"}, {"source_address": "0.0.0.0"}, {"source_address": "::1"},
        {"interface": "ether1\n/system reboot"}, {"routing_table": 'main"'},
        {"source": "bad name"}, {"mtu": True}, {"mtu": 67}, {"mtu": 9001},
        {"expected_first_hop": "192.0.2.1; /system reboot"},
    ],
)
def test_invalid_probe_inputs_never_run_ssh(monkeypatch, overrides):
    calls = fake_ssh(monkeypatch)

    with pytest.raises(ValueError):
        run_probe(**overrides)

    assert calls == []


@pytest.mark.parametrize(
    "sources",
    [
        [{**SOURCE, "enabled": False}],
        [{**SOURCE, "driver": "snmp_switch"}],
        [{**SOURCE, "name": "Router"}],
        [SOURCE, SOURCE],
    ],
)
def test_only_one_enabled_routeros_source_with_the_exact_name_is_accepted(monkeypatch, sources):
    calls = fake_ssh(monkeypatch)

    result = run_probe(sources=sources)

    assert result["status"] == "unavailable"
    assert result["reason"] == "router_source_unavailable"
    assert calls == []
