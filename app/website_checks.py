"""Periodic GET and network diagnostics for an operator-owned HTTPS catalog."""

import ipaddress
import json
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import NamedTemporaryFile
from urllib.parse import urlsplit

SITES = (
    "https://www.gosuslugi.ru/",
    "https://frgu3.gosuslugi.ru/",
    "https://pos.gosuslugi.ru/admin/login",
    "https://pgs.gosuslugi.ru/",
    "https://digital.gov74.ru/",
)
HOSTS = {urlsplit(url).hostname for url in SITES}
STATE = Path("/var/lib/openvpn-web/website-checks.json")
INTERVAL_MINUTES = 5
BODY_LIMIT = 2 * 1024 * 1024
HISTORY_LIMIT = 288


def page_status(code: int, kind: str, body: bytes) -> str:
    if code in (401, 403, 429):
        return "blocked"
    if not 200 <= code < 300:
        return "http_error"
    if kind.split(";", 1)[0].strip().lower() not in {"text/html", "application/xhtml+xml"}:
        return "not_html"
    if not re.search(rb"<(?:!doctype\s+html\b|html\b)", body, re.I):
        return "not_html"
    if re.search(rb"checking your browser|cf-chl-|/cdn-cgi/challenge-platform|just a moment", body, re.I):
        return "challenge"
    if "госуслуги сейчас откроются" in body.decode("utf-8", "replace").lower():
        return "challenge"
    return "ok"


def resolve_public(host: str) -> list:
    addresses = {ipaddress.ip_address(row[4][0]) for row in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)}
    return sorted((ip for ip in addresses if ip.is_global and not ip.is_multicast
                   and getattr(ip, "ipv4_mapped", None) is None and getattr(ip, "scope_id", None) is None),
                  key=lambda ip: (ip.version, int(ip)))


def fetch(url: str, address) -> tuple[dict, bytes, int]:
    host = urlsplit(url).hostname
    ip = f"[{address}]" if address.version == 6 else str(address)
    with NamedTemporaryFile() as body:
        result = subprocess.run([
            "/usr/bin/curl", "--disable", "--globoff", "--noproxy", "*", "--proto", "=https",
            "--connect-timeout", "4", "--max-time", "10", "--max-filesize", str(BODY_LIMIT),
            "--silent", "--output", body.name, "--write-out", "%{json}",
            "--resolve", f"{host}:443:{ip}", "--url", url,
        ], capture_output=True, timeout=12, check=False)
        return json.loads(result.stdout or b"{}"), body.read(BODY_LIMIT), result.returncode


def trace(address) -> dict:
    from .network_checks import trace_address

    return trace_address(address)


def _approved_redirect(url: str) -> bool:
    try:
        parts = urlsplit(url)
        return (parts.scheme == "https" and parts.hostname in HOSTS and parts.port in (None, 443)
                and parts.username is None and parts.password is None and not parts.fragment
                and len(url) <= 2048 and not re.search(r"[\\\s\x00-\x1f\x7f]", url))
    except ValueError:
        return False


def check_site(url: str) -> dict:
    row = {"url": url, "checked_at": datetime.now(UTC).isoformat(), "redirects": []}
    current = url
    for _ in range(4):
        row["dns"] = []
        try:
            addresses = resolve_public(urlsplit(current).hostname)
        except OSError:
            addresses = []
        if not addresses:
            row.update(status="dns_error", address=None, http_status=None, tls="unconfirmed",
                       content_type=None, body_bytes=0, total_ms=None, first_byte_ms=None)
            break
        row["dns"] = [str(ip) for ip in addresses[:16]]
        for address in addresses[:3]:
            row["address"] = str(address)
            try:
                info, body, code = fetch(current, address)
            except (OSError, ValueError, subprocess.TimeoutExpired):
                info, body, code = {}, b"", 28
            if code not in (7, 28):
                break
        status = info.get("http_code") or None
        row.update(http_status=status, content_type=info.get("content_type"), body_bytes=len(body),
                   tls="verified" if status else ("failed" if code in (35, 51, 60, 77, 83, 90, 91) else "unconfirmed"),
                   total_ms=round(info["time_total"] * 1000) if isinstance(info.get("time_total"), (int, float)) else None,
                   first_byte_ms=round(info["time_starttransfer"] * 1000) if info.get("time_starttransfer") else None)
        if code:
            row["status"] = {28: "timeout", 63: "body_limit"}.get(code, "tls_error" if row["tls"] == "failed" else "connection_error")
            break
        redirect = info.get("redirect_url")
        if status and 300 <= status < 400 and redirect:
            if not _approved_redirect(redirect):
                row["status"] = "redirect_outside_catalog"
                break
            row["redirects"].append(urlsplit(redirect).hostname)
            current = redirect
            continue
        row["status"] = page_status(status or 0, row["content_type"] or "", body)
        break
    else:
        row["status"] = "redirect_limit"
    if row.get("address"):
        row["trace"] = trace(ipaddress.ip_address(row["address"]))
    return row


def report() -> dict:
    try:
        history = json.loads(STATE.read_bytes())
        latest = history[0]
        checked = datetime.fromisoformat(latest["checked_at"])
    except (OSError, ValueError, KeyError, IndexError, TypeError):
        history, latest, checked = [], {}, None
    rows = {row["url"]: row for row in latest.get("sites", [])}
    return {
        "origin": "vpn-server", "interval_minutes": INTERVAL_MINUTES,
        "checked_at": latest.get("checked_at"),
        "stale": checked is None or datetime.now(UTC) - checked > timedelta(minutes=2 * INTERVAL_MINUTES),
        "sites": [rows.get(url, {"url": url, "status": "pending"}) for url in SITES],
        "history": [
            {"checked_at": run["checked_at"],
             "sites": [{key: site.get(key) for key in ("url", "status", "http_status", "total_ms")}
                       for site in run["sites"]]}
            for run in history[:12]
        ],
    }


def run() -> None:
    with ThreadPoolExecutor(max_workers=5) as pool:
        sites = list(pool.map(check_site, SITES))
    try:
        history = json.loads(STATE.read_bytes())
    except (OSError, ValueError):
        history = []
    with NamedTemporaryFile(mode="w", encoding="utf-8", dir=STATE.parent, delete=False) as output:
        path = Path(output.name)
        try:
            json.dump([{"checked_at": datetime.now(UTC).isoformat(), "sites": sites}, *history[:HISTORY_LIMIT - 1]], output)
            output.close()
            path.replace(STATE)
        finally:
            path.unlink(missing_ok=True)


if __name__ == "__main__":
    run()
