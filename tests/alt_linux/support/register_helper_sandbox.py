from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from .lifecycle_fixtures import (
    TEST_MACHINE_MAC,
    TEST_MACHINE_UUID,
    TEST_REGISTRATION_ID,
)

HELPER = (
    Path(__file__).resolve().parents[3]
    / "deploy"
    / "alt-linux"
    / "bootstrap"
    / "alt-bootstrap-register"
)


@dataclass(frozen=True)
class HelperRun:
    result: subprocess.CompletedProcess[str]
    curl_calls: list[dict[str, object]]


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


def run_helper(
    tmp_path: Path,
    *,
    uid: int = 0,
    http_status: int = 201,
    response: dict[str, object] | str | None = None,
    curl_rc: int = 0,
    interface: str = "eth0",
    machine_uuid: str = TEST_MACHINE_UUID,
) -> HelperRun:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    curl_log = tmp_path / "curl.jsonl"

    _write_executable(
        fake_bin / "id",
        "#!/bin/sh\nprintf '%s\\n' \"${HELPER_TEST_UID}\"\n",
    )
    _write_executable(
        fake_bin / "ip",
        (
            "#!/bin/sh\n"
            "[ -n \"${HELPER_TEST_INTERFACE}\" ] && "
            "printf 'default via 192.168.100.1 dev %s\\n' "
            "\"${HELPER_TEST_INTERFACE}\"\n"
        ),
    )
    _write_executable(
        fake_bin / "hostname",
        "#!/bin/sh\nprintf 'alt-lifecycle-test\\n'\n",
    )
    _write_executable(
        fake_bin / "cat",
        (
            "#!/bin/sh\n"
            "case \"${1:-}\" in\n"
            "  /sys/class/net/*/address) printf '%s\\n' "
            "\"${HELPER_TEST_MAC}\" ;;\n"
            "  /sys/class/dmi/id/product_uuid) printf '%s\\n' "
            "\"${HELPER_TEST_UUID}\" ;;\n"
            "  *) exec /bin/cat \"$@\" ;;\n"
            "esac\n"
        ),
    )
    _write_executable(
        fake_bin / "curl",
        (
            f"#!{sys.executable}\n"
            "import json, os, pathlib, sys\n"
            "args = sys.argv[1:]\n"
            "def value(name): return args[args.index(name) + 1]\n"
            "pathlib.Path(value('--output')).write_text("
            "os.environ['HELPER_TEST_RESPONSE'], encoding='utf-8')\n"
            "body = value('--data')\n"
            "url = next(item for item in reversed(args) "
            "if item.startswith('http'))\n"
            "with open(os.environ['HELPER_TEST_CURL_LOG'], 'a', "
            "encoding='utf-8') as handle:\n"
            "    handle.write(json.dumps({'url': url, 'body': body}) + '\\n')\n"
            "print(os.environ['HELPER_TEST_HTTP_STATUS'], end='')\n"
            "raise SystemExit(int(os.environ['HELPER_TEST_CURL_RC']))\n"
        ),
    )

    if response is None:
        response = {
            "status": "registered",
            "machine_key": TEST_MACHINE_UUID,
            "registration_id": TEST_REGISTRATION_ID,
            "ip": "192.168.101.56",
        }
    response_text = (
        json.dumps(response, ensure_ascii=False)
        if isinstance(response, dict)
        else response
    )
    environment = os.environ.copy()
    environment.update(
        {
            "PATH": f"{fake_bin}:/usr/bin:/bin",
            "ALT_DEPLOY_REGISTER_URL": (
                "http://127.0.0.1:18088/register"
            ),
            "HELPER_TEST_UID": str(uid),
            "HELPER_TEST_INTERFACE": interface,
            "HELPER_TEST_MAC": TEST_MACHINE_MAC,
            "HELPER_TEST_UUID": machine_uuid,
            "HELPER_TEST_RESPONSE": response_text,
            "HELPER_TEST_HTTP_STATUS": str(http_status),
            "HELPER_TEST_CURL_RC": str(curl_rc),
            "HELPER_TEST_CURL_LOG": str(curl_log),
        }
    )
    result = subprocess.run(
        ["bash", str(HELPER)],
        text=True,
        capture_output=True,
        check=False,
        env=environment,
    )
    calls = (
        [
            json.loads(line)
            for line in curl_log.read_text(
                encoding="utf-8"
            ).splitlines()
        ]
        if curl_log.exists()
        else []
    )
    return HelperRun(result=result, curl_calls=calls)
