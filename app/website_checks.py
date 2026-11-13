"""Periodic GET and network diagnostics for an operator-owned HTTPS catalog."""

import ipaddress
import json
import os
import re
import secrets
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import NamedTemporaryFile
from urllib.parse import urlencode, urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field
from .website_receipts import MAX_AGE as WINDOWS_MAX_AGE, WINDOWS_SITES, WINDOWS_STATE, store

PGS_LOGIN = "https://auth.pgs.gosuslugi.ru/auth/realms/DigitalgovTorkndProd1Auth/protocol/openid-connect/auth"
MON_PMO = "https://mon-pmo.gov74.ru/"
SITES = (
    "https://www.gosuslugi.ru/",
    "https://frgu3.gosuslugi.ru/",
    "https://pos.gosuslugi.ru/admin/login",
    "https://pgs.gosuslugi.ru/",
    PGS_LOGIN,
    "https://digital.gov74.ru/",
    "https://gisogd.gov74.ru/",
    MON_PMO,
    "https://e.mail.ru/inbox",
    "https://app.workspace.vk.ru/mail",
    "https://nspd.gov.ru/map?thematic=PKK&coordinate_x=7804891.637510094&coordinate_y=8181287.398947453&zoom=5&baseLayerId=235",
    "http://ssl.budgetplan.minfin.ru/",
    "https://reg-gp.minfin.ru/application/",
    "https://sobi.cert.roskazna.ru/",
)
HOSTS = {urlsplit(url).hostname for url in SITES}
LOGIN_HOSTS = {"account.mail.ru", "login.vk.com", "id.vk.com", "auth.pgs.gosuslugi.ru", "esia.gosuslugi.ru"}
STATE = Path("/var/lib/openvpn-web/website-checks.json")
NSPD_CA = Path("/etc/openvpn-web/nspd-website-ca.pem")
PGS_OPENSSL_CONFIG = Path("/etc/openvpn-web/pgs-gost-openssl.cnf")
PGS_CA = Path("/etc/openvpn-web/pgs-gost-ca.pem")
PGS_HOSTS = {"pgs.gosuslugi.ru", "auth.pgs.gosuslugi.ru"}
GOST_CLIENT_CERT_HOSTS = {"ssl.budgetplan.minfin.ru", "reg-gp.minfin.ru", "sobi.cert.roskazna.ru"}
CLIENT_CERT_HOSTS = GOST_CLIENT_CERT_HOSTS | {"pos.gosuslugi.ru"}
INTERVAL_MINUTES = 5
BODY_LIMIT = 2 * 1024 * 1024
HISTORY_LIMIT = 288


class WebsiteCheckInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str = Field(min_length=1, max_length=2048)


def is_public(ip) -> bool:
    return (ip.is_global and not ip.is_multicast and not ip.is_reserved
            and all(getattr(ip, field, None) is None for field in ("ipv4_mapped", "scope_id", "sixtofour", "teredo"))
            and not (ip.version == 6 and ip in ipaddress.IPv6Network("64:ff9b::/96")))


def public_url(url: str) -> str:
    url = url.strip()
    if not re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", url):
        url = "https://" + url
    if len(url) > 2048 or re.search(r"[\\\s\x00-\x1f\x7f]", url):
        raise ValueError("Invalid website URL")
    parts = urlsplit(url)
    default_port = {"http": 80, "https": 443}.get(parts.scheme)
    if (not default_port or not parts.hostname or parts.port not in (None, default_port)
            or parts.username is not None or parts.password is not None):
        raise ValueError("Expected a public HTTP or HTTPS URL")
    host = parts.hostname
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        host = host.encode("idna").decode("ascii").rstrip(".")
        if not re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}", host, re.I):
            raise ValueError("Invalid public hostname")
    else:
        if not is_public(ip):
            raise ValueError("Non-public address")
        host = f"[{ip}]" if ip.version == 6 else str(ip)
    return urlunsplit((parts.scheme, host, parts.path or "/", parts.query, ""))


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
    try:
        return [ipaddress.ip_address(host)]
    except ValueError:
        pass
    addresses = {ipaddress.ip_address(row[4][0]) for row in socket.getaddrinfo(host + ".", 443, type=socket.SOCK_STREAM)}
    return sorted(addresses, key=lambda ip: (ip.version, int(ip)))


def fetch(url: str, address) -> tuple[dict, bytes, int]:
    parts = urlsplit(url)
    host = parts.hostname
    port = 443 if parts.scheme == "https" else 80
    ip = f"[{address}]" if address.version == 6 else str(address)
    user_agent = ["--user-agent", "UI-VPN-Monitor/1.0"] if host == urlsplit(MON_PMO).hostname else []
    tls_args = []
    env = None
    if parts.scheme == "https":
        if host in PGS_HOSTS and PGS_OPENSSL_CONFIG.is_file() and PGS_CA.is_file():
            env = {**os.environ, "OPENSSL_CONF": str(PGS_OPENSSL_CONFIG)}
            tls_args = ["--cacert", str(PGS_CA), "--tlsv1.2", "--tls-max", "1.2",
                        "--ciphers", "GOST2012-KUZNYECHIK-KUZNYECHIKOMAC:GOST2012-MAGMA-MAGMAOMAC"]
        elif host == "nspd.gov.ru" and NSPD_CA.is_file():
            tls_args = ["--cacert", str(NSPD_CA)]
    with NamedTemporaryFile() as body:
        result = subprocess.run([
            "/usr/bin/curl", "--disable", "--globoff", "--noproxy", "*", "--proto", f"={parts.scheme}",
            "--connect-timeout", "4", "--max-time", "10", "--max-filesize", str(BODY_LIMIT),
            "--silent", "--output", body.name, "--write-out", "%{json}",
            *tls_args, *user_agent,
            *(["--resolve", f"{host}:{port}:{ip}"] if host != str(address) else []), "--url", url,
        ], capture_output=True, timeout=12, check=False, env=env)
        return json.loads(result.stdout or b"{}"), body.read(BODY_LIMIT), result.returncode


def trace(address) -> dict:
    from .network_checks import trace_address

    return trace_address(address)


def probe_client_certificate(host: str, address) -> str:
    """Observe the TLS request without sending a client certificate or an HTTP request."""
    endpoint = f"[{address}]:443" if address.version == 6 else f"{address}:443"
    args = ["/usr/bin/openssl", "s_client", "-connect", endpoint, "-servername", host,
            "-verify_hostname", host, "-msg", "-brief"]
    env = None
    if host in GOST_CLIENT_CERT_HOSTS:
        if not PGS_OPENSSL_CONFIG.is_file():
            return "unconfirmed"
        args.extend(("-tls1_2", "-cipher", "ALL"))
        env = {**os.environ, "OPENSSL_CONF": str(PGS_OPENSSL_CONFIG)}
    try:
        result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=6, check=False, env=env)
        transcript = result.stdout
    except subprocess.TimeoutExpired as exc:
        transcript = exc.stdout or b""
    except OSError:
        return "unconfirmed"
    if re.search(rb"^<<< .*Handshake .*\bCertificateRequest\s*$", transcript, re.MULTILINE):
        return "requested"
    return "not_requested" if b"CONNECTION ESTABLISHED" in transcript else "unconfirmed"


def ping(address) -> dict:
    try:
        result = subprocess.run(
            ["/usr/bin/ping", f"-{address.version}", "-n", "-c", "3", "-W", "1", str(address)],
            capture_output=True, text=True, timeout=5, check=False, env={**os.environ, "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired):
        return {"status": "unavailable"}
    stats = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received, ([\d.]+)% packet loss", result.stdout)
    if stats is None:
        return {"status": "unavailable"}
    sent, received, loss = stats.groups()
    rtt = re.search(r"= [\d.]+/([\d.]+)/[\d.]+/[\d.]+ ms", result.stdout)
    return {"status": "reply" if int(received) else "no_reply", "sent": int(sent), "received": int(received),
            "loss_percent": float(loss), "avg_ms": float(rtt[1]) if rtt else None}


def probe_path(address, port: int) -> dict:
    from .network_checks import lookup_linux_route

    route = lookup_linux_route(address, tcp_port=port)
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending_ping = pool.submit(ping, address)
        traced = trace(address)
    return {"route": route, "trace": traced, "ping": pending_ping.result()}


def certificate_summary(info: dict) -> dict | None:
    certs = info.get("certs")
    if not isinstance(certs, str):
        return None
    leaf = certs.split("-----END CERTIFICATE-----", 1)[0]
    fields = {"Subject": "subject", "Issuer": "issuer", "Start date": "not_before", "Expire date": "not_after"}
    summary = {}
    for line in leaf.splitlines():
        label, _, value = line.partition(":")
        if label in fields:
            summary[fields[label]] = value.strip()[:512]
    return summary or None


def elapsed_ms(seconds) -> int | None:
    return round(seconds * 1000) if isinstance(seconds, (int, float)) and seconds > 0 else None


def _approved_redirect(url: str) -> bool:
    try:
        parts = urlsplit(url)
        return (parts.scheme == "https" and parts.hostname in HOSTS and parts.port in (None, 443)
                and parts.username is None and parts.password is None and not parts.fragment
                and len(url) <= 2048 and not re.search(r"[\\\s\x00-\x1f\x7f]", url))
    except ValueError:
        return False


def manual_check(db, actor: str, url: str) -> dict:
    from fastapi import HTTPException

    from .network_actions import acquire_network_action

    try:
        url = public_url(url)
    except (ValueError, UnicodeError) as exc:
        raise HTTPException(status_code=422, detail="Укажите публичный HTTP или HTTPS адрес.") from exc
    permit = acquire_network_action(db, actor, "website-manual-check", datetime.now(UTC))
    if not permit.accepted:
        raise HTTPException(status_code=429, detail=permit.message,
                            headers={"Retry-After": str(permit.retry_after_seconds)})
    return check_site(url, manual=True)


def check_site(url: str, *, manual: bool = False) -> dict:
    url = public_url(url)
    row = {"url": url, "origin": "vpn-server", "checked_at": datetime.now(UTC).isoformat(), "redirects": []}
    current = MON_PMO + "pmo/" if url == MON_PMO else url
    if current == PGS_LOGIN:
        current += "?" + urlencode({
            "response_type": "code", "scope": "openid", "client_id": "DigitalgovTorkndProd1Auth-Proxy",
            "redirect_uri": "https://pgs.gosuslugi.ru/openid-connect-auth/redirect_uri",
            "state": secrets.token_hex(16), "nonce": secrets.token_hex(16),
        })
    for _ in range(3 if manual else 4):
        row["dns"] = []
        try:
            addresses = resolve_public(urlsplit(current).hostname)
        except OSError:
            addresses = []
        eligible = [ip for ip in addresses if is_public(ip)]
        if not eligible or (manual and len(eligible) != len(addresses)):
            row.update(status="non_public_address" if addresses else "dns_error", address=None, http_status=None, tls="unconfirmed",
                       failure_stage="dns", content_type=None, body_bytes=0, total_ms=None, first_byte_ms=None,
                       tcp_ms=None, tls_ms=None, certificate=None, certificate_verify_code=None, source_address=None)
            break
        row["dns"] = [str(ip) for ip in eligible[:16]]
        for address in eligible[:1 if manual else 3]:
            row["address"] = str(address)
            try:
                info, body, code = fetch(current, address)
            except (OSError, ValueError, subprocess.TimeoutExpired):
                info, body, code = {}, b"", 28
            if code not in (7, 28):
                break
        status = info.get("http_code") or None
        https = urlsplit(current).scheme == "https"
        tls_ms = elapsed_ms(info.get("time_appconnect"))
        tcp_ms = elapsed_ms(info.get("time_connect"))
        tls_error = code in (35, 51, 53, 54, 58, 59, 60, 77, 82, 83, 90, 91, 98)
        row.update(http_status=status, content_type=info.get("content_type"), body_bytes=len(body),
                   tls=("not_applicable" if not https else "failed" if tls_error else
                        "verified" if status or tls_ms is not None else "unconfirmed"),
                   certificate=certificate_summary(info) if https else None,
                   certificate_verify_code=info.get("ssl_verify_result") if https and (status or tls_ms is not None or code == 60) else None,
                   curl_exit_code=code,
                   source_address=info.get("local_ip") or None, tcp_ms=tcp_ms, tls_ms=tls_ms,
                   total_ms=elapsed_ms(info.get("time_total")), first_byte_ms=elapsed_ms(info.get("time_starttransfer")))
        if code:
            row["status"] = {28: "timeout", 63: "body_limit"}.get(code, "tls_error" if row["tls"] == "failed" else "connection_error")
            row["failure_stage"] = ("tls" if tls_error else "http" if status or tls_ms is not None else
                                    "tcp" if tcp_ms is None else "tls" if https else "http")
            break
        redirect = info.get("redirect_url")
        if status and 300 <= status < 400 and redirect:
            try:
                redirect = public_url(redirect)
            except (ValueError, UnicodeError):
                row["status"] = "redirect_outside_catalog"
                row["failure_stage"] = "http"
                break
            if urlsplit(redirect).hostname in LOGIN_HOSTS and urlsplit(redirect).scheme == "https":
                row["redirects"].append(urlsplit(redirect).hostname)
                row["status"] = "login_redirect"
                break
            if (manual and urlsplit(current).scheme == "https" and urlsplit(redirect).scheme != "https"
                    or not manual and not _approved_redirect(redirect)):
                row["status"] = "redirect_outside_catalog"
                row["failure_stage"] = "http"
                break
            row["redirects"].append(urlsplit(redirect).hostname)
            current = redirect
            continue
        row["status"] = page_status(status or 0, row["content_type"] or "", body)
        if row["status"] != "ok":
            row["failure_stage"] = "http"
        break
    else:
        row["status"] = "redirect_limit"
        row["failure_stage"] = "http"
    if row.get("address"):
        target = ipaddress.ip_address(row["address"])
        host = urlsplit(current).hostname
        if host in CLIENT_CERT_HOSTS:
            row["client_certificate"] = probe_client_certificate(host, target)
        row.update(probe_path(target, 443 if https else 80))
        if not row["source_address"]:
            row["source_address"] = row.get("route", {}).get("result", {}).get("prefsrc")
    return row


def report() -> dict:
    try:
        history = json.loads(STATE.read_bytes())
        latest = history[0]
        checked = datetime.fromisoformat(latest["checked_at"])
    except (OSError, ValueError, KeyError, IndexError, TypeError):
        history, latest, checked = [], {}, None
    rows = {row["url"]: row for row in latest.get("sites", [])}
    result = {
        "origin": "vpn-server", "interval_minutes": INTERVAL_MINUTES,
        "checked_at": latest.get("checked_at"),
        "stale": checked is None or datetime.now(UTC) - checked > timedelta(minutes=2 * INTERVAL_MINUTES),
        "sites": [rows.get(url, {"url": url, "status": "pending"}) for url in SITES],
        "history": [
            {"checked_at": run["checked_at"],
             "sites": [{key: site.get(key) for key in ("url", "status", "http_status", "total_ms", "failure_stage", "client_certificate")}
                       for site in run["sites"]]}
            for run in history[:12]
        ],
    }
    try:
        windows = json.loads(WINDOWS_STATE.read_bytes())
        when = datetime.fromisoformat(windows["checked_at"])
        result["windows"] = {**windows, "origin": "windows-vlan20",
                             "stale": not -timedelta(seconds=30) <= datetime.now(UTC) - when <= WINDOWS_MAX_AGE}
    except (OSError, ValueError, KeyError, TypeError):
        pass
    return result


def store_windows_receipt(payload: bytes, now: datetime) -> None:
    store(payload, now, WINDOWS_STATE)


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
