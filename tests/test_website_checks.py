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


def test_history_retains_recent_runs(tmp_path, monkeypatch):
    monkeypatch.setattr(checks, "STATE", tmp_path / "checks.json")
    monkeypatch.setattr(checks, "check_site", lambda url: {"url": url, "status": "ok"})
    checks.run()
    checks.run()
    report = checks.report()
    assert len(report["sites"]) == 8 and len(report["history"]) == 2
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
