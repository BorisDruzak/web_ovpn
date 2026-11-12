"""Single bounded HTTPS transfer against the Cloudflare speed-test endpoint."""

import ipaddress
import json
import os
import subprocess


SPEED_HOST = "speed.cloudflare.com"
SPEED_PORT = 443
MIN_BYTES = 100_000
MAX_DOWNLOAD_BYTES = 10_000_000
MAX_UPLOAD_BYTES = 5_000_000
TRANSFER_TIMEOUT = 12


def validate_speed_peer(value: str) -> str:
    peer = ipaddress.IPv4Address(value)
    if value != str(peer) or not peer.is_global or peer.is_multicast:
        raise ValueError("HTTPS speed peer must be a public unicast IPv4 address")
    return value


def run_https_speed(peer: str, direction: str, size: int) -> dict:
    validate_speed_peer(peer)
    if direction not in ("send", "receive"):
        raise ValueError("Invalid HTTPS transfer direction")
    upload = direction == "send"
    max_bytes = MAX_UPLOAD_BYTES if upload else MAX_DOWNLOAD_BYTES
    if type(size) is not int or not MIN_BYTES <= size <= max_bytes:
        raise ValueError("Invalid HTTPS transfer size")

    # Pin the configured IP while retaining TLS verification for the service name.
    argv = [
        "/usr/bin/curl", "--disable", "--ipv4", "--noproxy", "*",
        "--proto", "=https", "--resolve", f"{SPEED_HOST}:{SPEED_PORT}:{peer}",
        "--silent", "--fail", "--connect-timeout", "4",
        "--max-time", str(TRANSFER_TIMEOUT), "--output", os.devnull,
        "--write-out", (
            '{"http_status":%{http_code},"bytes_up":%{size_upload},'
            '"bytes_down":%{size_download},"duration":%{time_total},'
            '"peer":"%{remote_ip}","source":"%{local_ip}"}'
        ),
    ]
    if upload:
        argv.extend((
            "--header", "Content-Type: application/octet-stream", "--data-binary", "@-",
            "--max-filesize", str(MIN_BYTES), f"https://{SPEED_HOST}/__up",
        ))
    else:
        argv.extend(("--max-filesize", str(size), f"https://{SPEED_HOST}/__down?bytes={size}"))

    try:
        completed = subprocess.run(
            argv, input=bytes(size) if upload else b"", capture_output=True,
            check=False, timeout=TRANSFER_TIMEOUT + 1, env={"LC_ALL": "C"},
        )
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "result": {}}
    except OSError:
        return {"status": "unavailable", "result": {}}
    if completed.returncode:
        return {"status": "timeout" if completed.returncode == 28 else "failed", "result": {}}
    try:
        data = json.loads(completed.stdout)
        if not isinstance(data, dict):
            raise ValueError("Invalid transfer statistics")
        duration = data.get("duration")
        if (
            data.get("http_status") != 200
            or data.get("peer") != peer
            or data.get("bytes_up" if upload else "bytes_down") != size
            or type(duration) not in (int, float)
            or not 0 < duration <= TRANSFER_TIMEOUT + 1
        ):
            raise ValueError("Incomplete or mismatched HTTPS transfer")
        source = str(ipaddress.IPv4Address(data["source"]))
    except (KeyError, ValueError, RecursionError):
        return {"status": "failed", "result": {}}
    return {
        "status": "measured",
        "result": {
            "mbps": round(size * 8 / duration / 1_000_000, 2),
            "transferred_bytes": size,
            "duration_seconds": duration,
            "source_address": source,
        },
    }
