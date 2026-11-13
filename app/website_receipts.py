"""Accept bounded results from the fixed Windows VLAN20 website probe."""

import json
import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import NamedTemporaryFile

WINDOWS_SITES = (
    "https://pgs.gosuslugi.ru/",
    "https://nspd.gov.ru/map?thematic=PKK&coordinate_x=7804891.637510094&coordinate_y=8181287.398947453&zoom=5&baseLayerId=235",
)
WINDOWS_STATE = Path("/var/lib/openvpn-route-probes/windows-websites/websites.json")
MAX_BYTES = 4096
MAX_AGE = timedelta(minutes=10)


def store(payload: bytes, now: datetime, path: Path = WINDOWS_STATE) -> None:
    if len(payload) > MAX_BYTES:
        raise ValueError("Receipt too large")
    report = json.loads(payload)
    if not isinstance(report, dict) or set(report) != {"checked_at", "sites"}:
        raise ValueError("Invalid receipt")
    when = datetime.fromisoformat(report["checked_at"])
    if when.tzinfo is None or not -timedelta(seconds=30) <= now - when <= MAX_AGE:
        raise ValueError("Invalid receipt time")
    sites = report["sites"]
    if not isinstance(sites, list) or len(sites) != len(WINDOWS_SITES):
        raise ValueError("Invalid site list")
    for site, url in zip(sites, WINDOWS_SITES, strict=True):
        if (not isinstance(site, dict)
                or set(site) != {"url", "status", "http_status", "body_bytes", "content_type", "tls", "total_ms"}
                or site["url"] != url or site["status"] not in ("ok", "not_html", "challenge", "blocked", "http_error", "tls_error", "timeout", "connection_error")
                or site["tls"] not in ("verified", "failed", "unconfirmed")
                or site["content_type"] not in ("text/html", "application/xhtml+xml", "", None)
                or type(site["body_bytes"]) is not int or not 0 <= site["body_bytes"] <= 2097152
                or type(site["total_ms"]) is not int or not 0 <= site["total_ms"] <= 15000
                or (site["http_status"] is not None and
                    (type(site["http_status"]) is not int or not 100 <= site["http_status"] <= 599))):
            raise ValueError("Invalid site result")
        if site["status"] == "ok" and not (
            site["tls"] == "verified" and site["http_status"] == 200 and site["body_bytes"]
            and site["content_type"] in ("text/html", "application/xhtml+xml")
        ):
            raise ValueError("Inconsistent HTML result")
    with NamedTemporaryFile(mode="wb", dir=path.parent, delete=False) as out:
        tmp = Path(out.name)
        try:
            os.chmod(tmp, 0o640)
            out.write(payload)
            out.close()
            tmp.replace(path)
        finally:
            tmp.unlink(missing_ok=True)


if __name__ == "__main__":
    try:
        store(sys.stdin.buffer.read(MAX_BYTES + 1), datetime.now(UTC))
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        sys.exit("Website probe receipt rejected")
