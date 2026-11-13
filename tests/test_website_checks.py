import ipaddress

import pytest

from app import website_checks as checks


@pytest.mark.parametrize("code,kind,body,status", [
    (200, "text/html", b"<!doctype html><html><title>Page</title></html>", "ok"),
    (200, "text/html", b"<html>Checking your browser</html>", "challenge"),
    (200, "text/html", b"plain text", "not_html"),
    (200, "application/json", b"<html></html>", "not_html"),
    (403, "text/html", b"<html></html>", "blocked"),
    (503, "text/html", b"<html></html>", "http_error"),
])
def test_page_status_checks_http_and_body(code, kind, body, status):
    assert checks.page_status(code, kind, body) == status


def test_redirect_to_unapproved_host_is_not_fetched(monkeypatch):
    calls = []

    def fetch(url, address):
        calls.append(url)
        return {"http_code": 302, "redirect_url": "https://example.org/"}, b"", 0

    monkeypatch.setattr(checks, "resolve_public", lambda _: [ipaddress.IPv4Address("8.8.8.8")])
    monkeypatch.setattr(checks, "fetch", fetch)
    monkeypatch.setattr(checks, "trace", lambda _: {"status": "partial", "hops": []})
    row = checks.check_site("https://www.gosuslugi.ru/")
    assert row["status"] == "redirect_outside_catalog"
    assert calls == ["https://www.gosuslugi.ru/"]


def test_fetch_uses_nspd_ca_only_for_https_nspd(tmp_path, monkeypatch):
    from subprocess import CompletedProcess

    ca = tmp_path / "nspd.pem"
    ca.touch()
    monkeypatch.setattr(checks, "NSPD_CA", ca, raising=False)
    commands = []

    def run(args, **kwargs):
        commands.append(args)
        return CompletedProcess(args, 0, stdout=b"{}")

    monkeypatch.setattr(checks.subprocess, "run", run)
    address = ipaddress.ip_address("2.63.246.71")
    checks.fetch("https://nspd.gov.ru/map", address)
    checks.fetch("https://pgs.gosuslugi.ru/", address)
    checks.fetch("http://nspd.gov.ru/", address)
    assert commands[0][commands[0].index("--cacert") + 1] == str(ca)
    assert all("--cacert" not in command for command in commands[1:])


def test_gost_configuration_is_limited_to_pgs_https(tmp_path, monkeypatch):
    from subprocess import CompletedProcess

    config = tmp_path / "openssl.cnf"
    ca = tmp_path / "ca.pem"
    config.touch()
    ca.touch()
    monkeypatch.setattr(checks, "PGS_OPENSSL_CONFIG", config, raising=False)
    monkeypatch.setattr(checks, "PGS_CA", ca, raising=False)
    monkeypatch.delenv("OPENSSL_CONF", raising=False)
    calls = []

    def run(args, **kwargs):
        calls.append((args, kwargs.get("env") or {}))
        return CompletedProcess(args, 0, stdout=b"{}")

    monkeypatch.setattr(checks.subprocess, "run", run)
    address = ipaddress.ip_address("82.202.191.39")
    for url in ("https://pgs.gosuslugi.ru/", checks.PGS_LOGIN,
                "http://pgs.gosuslugi.ru/", "https://example.org/"):
        checks.fetch(url, address)
    for args, env in calls[:2]:
        assert env["OPENSSL_CONF"] == str(config)
        assert args[args.index("--cacert") + 1] == str(ca)
    for args, env in calls[2:]:
        assert "OPENSSL_CONF" not in env
        assert "--ciphers" not in args


def test_https_failure_keeps_tcp_success_and_identifies_tls_stage(monkeypatch):
    address = ipaddress.ip_address("82.202.191.39")
    monkeypatch.setattr(checks, "resolve_public", lambda _: [address])
    monkeypatch.setattr(checks, "fetch", lambda url, ip: (
        {"time_connect": 0.042, "time_appconnect": 0, "ssl_verify_result": 1,
         "local_ip": "192.168.100.30"}, b"", 35))
    monkeypatch.setattr(checks, "probe_path", lambda ip, port: {
        "ping": {"status": "no_reply"}, "trace": {"status": "partial"}})
    result = checks.check_site("https://pgs.gosuslugi.ru/")
    assert result["status"] == "tls_error"
    assert result["failure_stage"] == "tls"
    assert result["tcp_ms"] == 42
    assert result["source_address"] == "192.168.100.30"
    assert result["ping"]["status"] == "no_reply"
    assert result["certificate"] is None


def test_pgs_login_does_not_store_oidc_state(monkeypatch):
    calls = []
    monkeypatch.setattr(checks, "resolve_public", lambda _: [ipaddress.ip_address("82.202.191.51")])
    monkeypatch.setattr(checks, "fetch", lambda url, ip: (calls.append(url) or {}, b"", 35))
    monkeypatch.setattr(checks, "probe_path", lambda ip, port: {})
    assert checks.check_site(checks.PGS_LOGIN)["url"] == checks.PGS_LOGIN
    assert checks.check_site(checks.PGS_LOGIN)["url"] == checks.PGS_LOGIN
    assert calls[0].startswith(checks.PGS_LOGIN + "?")
    assert "client_id=DigitalgovTorkndProd1Auth-Proxy" in calls[0]
    assert calls[0] != calls[1]


def test_history_retains_recent_runs(tmp_path, monkeypatch):
    monkeypatch.setattr(checks, "STATE", tmp_path / "checks.json")
    monkeypatch.setattr(checks, "check_site", lambda url: {"url": url, "status": "ok"})
    checks.run()
    checks.run()
    report = checks.report()
    assert [site["url"] for site in report["sites"]] == list(checks.SITES)
    assert len(report["history"]) == 2
    assert not report["stale"]


@pytest.mark.parametrize("url", [
    "file:///etc/hosts", "https://user:secret@example.org/", "http://example.org:22/",
    "http://localhost/", "http://127.1/", "http://2130706433/", "http://0x7f.0.0.1/",
    "http://example.org\\@127.0.0.1/", "http://[::ffff:127.0.0.1]/",
    "https://169.254.169.254/",
])
def test_manual_url_rejects_nonpublic_or_ambiguous_targets(url):
    with pytest.raises(ValueError):
        checks.public_url(url)


def test_manual_redirect_reresolves_and_rejects_internal_destination(monkeypatch):
    seen = []

    def fetch(url, address):
        seen.append((url, str(address)))
        return {"http_code": 302, "redirect_url": "https://internal.example.org/"}, b"", 0

    monkeypatch.setattr(checks, "resolve_public", lambda host:
                        [ipaddress.ip_address("8.8.8.8" if host == "example.org" else "10.0.0.1")])
    monkeypatch.setattr(checks, "fetch", fetch)
    monkeypatch.setattr(checks, "trace", lambda address: {"status": "partial"})
    row = checks.check_site("https://example.org/", manual=True)
    assert row["status"] == "non_public_address"
    assert seen == [("https://example.org/", "8.8.8.8")]


def test_windows_receipt_is_bounded_and_never_replaces_vpn_server_result(tmp_path, monkeypatch):
    import json
    from datetime import UTC, datetime, timedelta

    monkeypatch.setattr(checks, "STATE", tmp_path / "scheduled.json")
    monkeypatch.setattr(checks, "WINDOWS_STATE", tmp_path / "windows.json")
    now = datetime.now(UTC)
    payload = {
        "checked_at": now.isoformat(),
        "sites": [{"url": url, "status": "ok", "http_status": 200, "body_bytes": 42,
                   "content_type": "text/html", "tls": "verified", "total_ms": 10}
                  for url in checks.WINDOWS_SITES],
    }
    checks.store_windows_receipt(json.dumps(payload).encode(), now)
    report = checks.report()
    assert report["windows"]["sites"] == payload["sites"]
    assert report["sites"][0]["status"] == "pending"
    payload["checked_at"] = (now - timedelta(minutes=12)).isoformat()
    with pytest.raises(ValueError):
        checks.store_windows_receipt(json.dumps(payload).encode(), now)
    payload["checked_at"] = now.isoformat()
    payload["sites"][0]["raw_body"] = "private"
    with pytest.raises(ValueError):
        checks.store_windows_receipt(json.dumps(payload).encode(), now)
