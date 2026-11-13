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
    assert len(report["sites"]) == 5 and len(report["history"]) == 2
    assert not report["stale"]
