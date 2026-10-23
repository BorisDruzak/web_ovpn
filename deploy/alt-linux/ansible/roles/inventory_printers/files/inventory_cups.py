"""Standalone local CUPS reconciler; no network discovery or print submission."""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import uuid


class Blocked(ValueError):
    pass


class ApplyUnverified(Blocked):
    pass


def canonical(value):
    return json.dumps(
        value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":")
    ).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def model_name(value):
    return re.sub(
        "[^A-Z0-9]",
        "",
        re.sub(r"\b(KYOCERA|KYOSERA|ECOSYS|KPDL)\b", "", str(value).upper()),
    )


def ppd_signature(payload):
    # CUPS rewrites default choices; user defaults are not the driver identity.
    text = payload.decode("latin1")
    lines = [
        line.rstrip() for line in text.splitlines() if not line.startswith("*Default")
    ]
    return hashlib.sha256("\n".join(lines).encode("latin1")).hexdigest()


def valid_uuid(value):
    if (
        not isinstance(value, str)
        or str(uuid.UUID(value)) != value
        or uuid.UUID(value).int == 0
    ):
        raise ValueError


def valid_mac(value):
    return (
        isinstance(value, str)
        and re.fullmatch(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", value)
        and int(value[:2], 16) % 2 == 0
        and value != "00:00:00:00:00:00"
    )


def validate(document, catalog, *, now):
    try:
        if (
            set(document) != {"request", "drivers"}
            or len(canonical(document)) > 24 * 1024 * 1024
        ):
            raise ValueError
        request = document["request"]
        if (
            set(request)
            != {
                "schema_version",
                "created_at",
                "expires_at",
                "target",
                "location_id",
                "source_sha256",
                "printers",
                "excluded",
                "ready",
                "sha256",
            }
            or type(request["schema_version"]) is not int
            or request["schema_version"] != 1
            or request["ready"] is not True
            or request["excluded"] != []
            or request["sha256"]
            != digest({k: v for k, v in request.items() if k != "sha256"})
            or not re.fullmatch("[0-9a-f]{64}", request["source_sha256"])
        ):
            raise ValueError
        created, expires = (
            datetime.fromisoformat(request[k]) for k in ("created_at", "expires_at")
        )
        if (
            created.tzinfo is None
            or expires.tzinfo is None
            or expires - created != timedelta(minutes=10)
        ):
            raise ValueError
        if not created <= now < expires:
            raise Blocked("printer_plan_expired")
        target = request["target"]
        if set(target) != {"uuid", "pc_asset_id", "macs"}:
            raise ValueError
        valid_uuid(target["uuid"])
        valid_uuid(target["pc_asset_id"])
        valid_uuid(request["location_id"])
        if (
            not isinstance(target["macs"], list)
            or not 1 <= len(target["macs"]) <= 32
            or len(set(target["macs"])) != len(target["macs"])
            or not all(valid_mac(m) for m in target["macs"])
        ):
            raise ValueError
        if (
            not isinstance(request["printers"], list)
            or not 1 <= len(request["printers"]) <= 16
        ):
            raise ValueError
        names, ips, payloads = set(), set(), {}
        for row in request["printers"]:
            if set(row) != {"asset_id", "queue", "ip", "model", "driver", "snmp"}:
                raise ValueError
            valid_uuid(row["asset_id"])
            if (
                row["queue"] != "inv_kyocera_" + row["asset_id"].replace("-", "")
                or row["queue"] in names
            ):
                raise ValueError
            ip = ipaddress.IPv4Address(row["ip"])
            if (
                str(ip) != row["ip"]
                or ip.is_multicast
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_unspecified
                or int(ip) == 0xFFFFFFFF
                or row["ip"] in ips
            ):
                raise ValueError
            names.add(row["queue"])
            ips.add(row["ip"])
            driver = catalog.get(row["model"])
            if (
                not driver
                or row["driver"] != driver
                or Path(driver["filename"]).name != driver["filename"]
            ):
                raise ValueError
            evidence = row["snmp"]
            if (
                set(evidence) != {"version", "serial", "mac"}
                or evidence["version"] not in ("1", "2c")
                or not isinstance(evidence["serial"], str)
                or len(evidence["serial"]) > 512
                or not (evidence["serial"] or valid_mac(evidence["mac"]))
            ):
                raise ValueError
            try:
                data = base64.b64decode(
                    document["drivers"][driver["filename"]], validate=True
                )
                text = data.decode("latin1")
                if (
                    len(data) > 1048576
                    or hashlib.sha256(data).hexdigest() != driver["sha256"]
                    or not text.startswith("*PPD-Adobe:")
                    or "\x00" in text
                    or re.search(
                        r"^\*(?:cupsFilter2?|cupsPreFilter|cupsPortMonitor|FoomaticRIPCommandLine|APAutoSetupTool)\s*:",
                        text,
                        re.M,
                    )
                ):
                    raise ValueError
                matches = re.findall(r'^\*ModelName:\s*"([^"]+)"', text, re.M)
                if len(matches) != 1 or model_name(matches[0]) != row["model"]:
                    raise ValueError
            except (ValueError, KeyError, TypeError):
                raise Blocked("printer_driver_invalid") from None
            payloads[row["queue"]] = data
        if set(document["drivers"]) != {
            r["driver"]["filename"] for r in request["printers"]
        }:
            raise ValueError
        return request, payloads
    except Blocked:
        raise
    except (ValueError, KeyError, TypeError, AttributeError, OverflowError):
        raise Blocked("printer_plan_invalid") from None


def reconcile(document, catalog, system, *, mode, now=None):
    if mode not in ("validate", "check", "apply"):
        raise Blocked("printer_mode_invalid")
    request, ppds = validate(document, catalog, now=now or datetime.now(timezone.utc))
    actual_uuid, actual_macs = system.identity()
    if actual_uuid.lower() != request["target"]["uuid"] or not set(actual_macs) & set(
        request["target"]["macs"]
    ):
        raise Blocked("printer_target_identity_mismatch")
    if mode == "validate":
        return {
            "status": "ok",
            "changed": False,
            "queues": [],
            "scheduler_available": system.scheduler_ready()
            if hasattr(system, "scheduler_ready")
            else True,
        }
    if (
        mode == "check"
        and hasattr(system, "scheduler_ready")
        and not system.scheduler_ready()
    ):
        return {
            "status": "ok",
            "changed": True,
            "deferred": "cups_scheduler_unavailable",
            "queues": [
                {"name": r["queue"], "changed": True} for r in request["printers"]
            ],
        }
    if hasattr(system, "validate_driver"):
        for row in request["printers"]:
            system.validate_driver(row, ppds[row["queue"]])
    actions = []
    for row in request["printers"]:
        name = row["queue"]
        queue, marker = system.inspect(name), system.marker(name)
        if marker is not None and (
            marker.get("asset_id") != row["asset_id"]
            or marker.get("schema_version") != 1
        ):
            raise Blocked("printer_queue_not_owned")
        if queue is not None and marker is None:
            raise Blocked("printer_queue_not_owned")
        changed = (
            queue is None
            or marker is None
            or marker.get("driver_sha256") != row["driver"]["sha256"]
            or queue.get("uri") != "socket://" + row["ip"] + ":9100"
            or queue.get("model") != row["model"]
            or queue.get("signature") != marker.get("installed_signature")
            or queue.get("shared") is not False
            or queue.get("enabled") is not True
            or queue.get("accepting") is not True
        )
        if changed and queue and queue.get("busy") is not False:
            raise Blocked("printer_queue_busy")
        actions.append((row, changed))
    if mode == "apply":
        for row, changed in actions:
            if not changed:
                continue
            # Check again immediately before mutating an existing owned queue.
            current = system.inspect(row["queue"])
            if current is not None and current.get("busy") is not False:
                raise Blocked("printer_queue_busy")
            if current is not None and system.marker(row["queue"]) is None:
                raise Blocked("printer_queue_not_owned")
            try:
                system.install(row, ppds[row["queue"]])
                installed = system.inspect(row["queue"])
                if (
                    not installed
                    or installed.get("uri") != "socket://" + row["ip"] + ":9100"
                    or installed.get("model") != row["model"]
                    or installed.get("shared") is not False
                    or installed.get("enabled") is not True
                    or installed.get("accepting") is not True
                ):
                    raise ValueError
                system.save_marker(
                    row["queue"],
                    {
                        "schema_version": 1,
                        "asset_id": row["asset_id"],
                        "driver_sha256": row["driver"]["sha256"],
                        "installed_signature": installed["signature"],
                    },
                )
            except Exception:
                raise ApplyUnverified("printer_apply_outcome_unverified") from None
    return {
        "status": "ok",
        "changed": any(c for _, c in actions),
        "queues": [{"name": r["queue"], "changed": c} for r, c in actions],
    }


class CupsSystem:
    def __init__(self):
        self.state = Path("/var/lib/inventory-printers/queues")

    def identity(self):
        identity = Path("/sys/class/dmi/id/product_uuid").read_text().strip()
        macs = [
            p.read_text().strip().upper()
            for p in Path("/sys/class/net").glob("*/address")
        ]
        return identity, macs

    def scheduler_ready(self):
        try:
            return "scheduler is running" in self.call("/usr/bin/lpstat", "-r")
        except (Blocked, OSError):
            return False

    def call(self, executable, *args):
        env = {
            k: v
            for k, v in os.environ.items()
            if k
            not in ("CUPS_SERVER", "IPP_PORT", "LPDEST", "PRINTER", "CUPS_ENCRYPTION")
        }
        env.update(LC_ALL="C", LANG="C")
        result = subprocess.run(
            [executable, "-h", "/run/cups/cups.sock", *args],
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if result.returncode:
            raise Blocked("printer_cups_unavailable")
        return result.stdout

    def inspect(self, name):
        devices = self.call("/usr/bin/lpstat", "-v")
        line = next(
            (
                line
                for line in devices.splitlines()
                if line.startswith("device for " + name + ": ")
            ),
            None,
        )
        if line is None:
            return None
        uri = line.split(": ", 1)[1]
        state = self.call("/usr/bin/lpstat", "-p", name)
        accepting = self.call("/usr/bin/lpstat", "-a", name)
        options = self.call("/usr/bin/lpoptions", "-p", name)
        share = re.search(r"(?:^|\s)printer-is-shared=(true|false)(?:\s|$)", options)
        ppd = Path("/etc/cups/ppd") / (name + ".ppd")
        if not share or ppd.is_symlink() or not ppd.is_file():
            raise Blocked("printer_queue_observation_unverified")
        data = ppd.read_bytes()
        models = re.findall(r'^\*ModelName:\s*"([^"]+)"', data.decode("latin1"), re.M)
        if len(models) != 1:
            raise Blocked("printer_queue_observation_unverified")
        jobs = self.call("/usr/bin/lpstat", "-W", "not-completed", "-o", name)
        return {
            "uri": uri,
            "model": model_name(models[0]),
            "signature": ppd_signature(data),
            "shared": share[1] == "true",
            "enabled": " enabled since " in state,
            "accepting": " not accepting " not in accepting
            and " accepting requests since " in accepting,
            "busy": bool(jobs.strip()),
        }

    def marker(self, name):
        path = self.state / (name + ".json")
        if any(p.is_symlink() for p in (path, *path.parents)):
            raise Blocked("printer_marker_unsafe")
        if not path.exists():
            return None
        info = path.stat()
        if info.st_uid != 0 or info.st_mode & 0o077 or info.st_size > 4096:
            raise Blocked("printer_marker_unsafe")
        try:
            value = json.loads(path.read_text())
            if not isinstance(value, dict):
                raise ValueError
            return value
        except ValueError:
            raise Blocked("printer_marker_unsafe") from None

    def validate_driver(self, row, ppd):
        with tempfile.TemporaryDirectory(prefix="inventory-printer-") as temp:
            path = Path(temp) / "driver.ppd"
            path.write_bytes(ppd)
            path.chmod(0o600)
            validation = subprocess.run(
                ["/usr/bin/cupstestppd", "-q", str(path)],
                capture_output=True,
                timeout=20,
                check=False,
            )
            if validation.returncode:
                raise Blocked("printer_ppd_validation_failed")

    def install(self, row, ppd):
        with tempfile.TemporaryDirectory(prefix="inventory-printer-") as temp:
            path = Path(temp) / "driver.ppd"
            path.write_bytes(ppd)
            path.chmod(0o600)
            self.call(
                "/usr/sbin/lpadmin",
                "-p",
                row["queue"],
                "-E",
                "-v",
                "socket://" + row["ip"] + ":9100",
                "-P",
                str(path),
                "-D",
                "Inventory printer " + row["asset_id"],
                "-o",
                "printer-is-shared=false",
            )

    def save_marker(self, name, marker):
        if any(p.is_symlink() for p in (self.state, *self.state.parents)):
            raise Blocked("printer_marker_unsafe")
        self.state.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.state.chmod(0o700)
        with tempfile.NamedTemporaryFile(
            dir=self.state, prefix=".receipt-", delete=False
        ) as stream:
            path = Path(stream.name)
            os.fchmod(stream.fileno(), 0o600)
            stream.write(canonical(marker) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(path, self.state / (name + ".json"))


def main(catalog):
    try:
        raw = sys.stdin.buffer.read(24 * 1024 * 1024 + 1)
        if len(raw) > 24 * 1024 * 1024:
            raise Blocked("printer_plan_invalid")
        result = reconcile(json.loads(raw), catalog, CupsSystem(), mode=sys.argv[1])
        print(json.dumps(result))
        return 0
    except ApplyUnverified as exc:
        print(json.dumps({"status": "unknown", "code": str(exc), "changed": None}))
        return 3
    except Blocked as exc:
        print(json.dumps({"status": "blocked", "code": str(exc), "changed": False}))
        return 2
    except Exception:
        print(
            json.dumps(
                {
                    "status": "blocked",
                    "code": "printer_outcome_unverified",
                    "changed": False,
                }
            )
        )
        return 2
