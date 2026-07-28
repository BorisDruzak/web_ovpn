from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
AGENT_ROOT = (
    REPO_ROOT / "deploy" / "alt-linux" / "install-agent" / "v1"
)
AGENT = AGENT_ROOT / "alt-install-agent"
STATE = AGENT_ROOT / "lib" / "state.sh"
TRANSPORT = AGENT_ROOT / "lib" / "transport.sh"
PROTOCOL = AGENT_ROOT / "lib" / "protocol.sh"
UI = AGENT_ROOT / "lib" / "ui.sh"
DHCP_HOOK = AGENT_ROOT / "lib" / "dhcp-hook.sh"
ISO_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "iso" / "agent-v1"
BUILDER = ISO_ROOT / "build-managed-iso.sh"
VERIFIER = ISO_ROOT / "verify-managed-iso.sh"
SOURCE_ISO = ISO_ROOT / "manifests" / "source_iso.json"
BUILD_INPUTS = ISO_ROOT / "lib" / "build-inputs.sh"
GATE = (
    ISO_ROOT
    / "initrd-overlay"
    / "lib"
    / "initrd"
    / "post"
    / "network-up"
    / "99-alt-install-agent-v1"
)
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "alt-managed-iso-spike.yml"


def _bash() -> Path:
    candidates = (
        shutil.which("bash"),
        r"C:\Program Files\Git\bin\bash.exe",
        r"C:\Program Files\Git\usr\bin\bash.exe",
    )
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return Path(candidate)
    pytest.skip("Bash is required for the initrd-agent contract")


def _run_bash(
    source: str,
    *,
    env: dict[str, str] | None = None,
    timeout: float = 10,
) -> subprocess.CompletedProcess[str]:
    command_env = os.environ.copy()
    if env:
        command_env.update(env)
    return subprocess.run(
        [str(_bash()), "-c", source],
        cwd=REPO_ROOT,
        env=command_env,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _public_key_document(raw: bytes) -> str:
    return (
        json.dumps(
            {
                "algorithm": "ed25519",
                "key_id": "sha256:" + hashlib.sha256(raw).hexdigest(),
                "public_key_b64": base64.b64encode(raw).decode("ascii"),
                "schema_version": 1,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )


def _write_fake_curl(path: Path, behavior: str) -> None:
    path.write_text(
        """#!/bin/bash
set -eu
output=
args=
while (($#)); do
    args="${args}${args:+ }$1"
    case "$1" in
        --output) output="$2"; shift 2 ;;
        --config|--write-out|--request|--header|--data-binary|--proto|--proto-redir|--max-redirs|--connect-timeout|--max-time|--max-filesize)
            args="${args} $2"
            shift 2
            ;;
        *) shift ;;
    esac
done
printf '%s\\n' "$args" >> "$FAKE_CURL_LOG"
attempt=0
[[ ! -f "$FAKE_CURL_ATTEMPTS" ]] || attempt=$(cat "$FAKE_CURL_ATTEMPTS")
attempt=$((attempt + 1))
printf '%s\\n' "$attempt" > "$FAKE_CURL_ATTEMPTS"
case "$FAKE_CURL_BEHAVIOR" in
    retry-create)
        if ((attempt < 3)); then exit 7; fi
        printf '%s' '{"credential":"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq","poll_after_seconds":3,"session_id":"install-20260727T120000Z-a1b2c3d4","state":"awaiting_approval"}' > "$output"
        printf '201'
        ;;
    redirect)
        printf '%s' '{"status":"redirect"}' > "$output"
        printf '302'
        ;;
    too-large)
        exit 63
        ;;
    transport-always)
        exit 7
        ;;
    status-and-plan)
        case "$args" in
            *'/status'*)
                if ((attempt == 1)); then
                    printf '%s' '{"state":"awaiting_approval"}' > "$output"
                else
                    printf '%s' '{"state":"plan_published"}' > "$output"
                fi
                printf '200'
                ;;
            *'/plan-signature'*)
                printf '%s' '{"signature":"exact-signature-bytes"}' > "$output"
                printf '200'
                ;;
            *'/plan'*)
                printf '%s' '{"plan":"exact-plan-bytes"}' > "$output"
                printf '200'
                ;;
            *) exit 98 ;;
        esac
        ;;
    create-and-heartbeat)
        case "$args" in
            *heartbeat*)
                printf '%s' '{"status":"ok"}' > "$output"
                printf '200'
                ;;
            *)
                printf '%s' '{"credential":"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq","poll_after_seconds":3,"session_id":"install-20260727T120000Z-a1b2c3d4","state":"awaiting_approval"}' > "$output"
                printf '201'
                ;;
        esac
        ;;
    *) exit 99 ;;
esac
""",
        encoding="utf-8",
        newline="\n",
    )
    path.chmod(0o755)


def _protocol_environment(tmp_path: Path, behavior: str) -> dict[str, str]:
    fake_curl = tmp_path / "curl"
    _write_fake_curl(fake_curl, behavior)
    fake_sleep = tmp_path / "sleep"
    fake_sleep.write_text(
        "#!/bin/bash\nprintf '%s\\n' \"$1\" >> \"$FAKE_SLEEP_LOG\"\n",
        encoding="utf-8",
        newline="\n",
    )
    fake_sleep.chmod(0o755)
    return {
        "ALT_INSTALL_STATE_ROOT": tmp_path.as_posix() + "/state",
        "ALT_INSTALL_CURL": fake_curl.as_posix(),
        "ALT_INSTALL_SLEEP": fake_sleep.as_posix(),
        "ALT_INSTALL_CONTROLLER": "http://192.168.100.17:18089",
        "FAKE_CURL_BEHAVIOR": behavior,
        "FAKE_CURL_LOG": (tmp_path / "curl.log").as_posix(),
        "FAKE_CURL_ATTEMPTS": (tmp_path / "attempts").as_posix(),
        "FAKE_SLEEP_LOG": (tmp_path / "sleep.log").as_posix(),
    }


def test_private_state_uses_atomic_mode_0600_files(tmp_path: Path) -> None:
    completed = _run_bash(
        """
set -euo pipefail
source deploy/alt-linux/install-agent/v1/lib/state.sh
state_init
state_write credential 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq'
stat -c '%a' "$ALT_INSTALL_STATE_ROOT"
stat -c '%a' "$ALT_INSTALL_STATE_ROOT/credential"
find "$ALT_INSTALL_STATE_ROOT" -maxdepth 1 -name '*.tmp.*' -print
""",
        env={"ALT_INSTALL_STATE_ROOT": tmp_path.as_posix() + "/state"},
    )

    assert completed.returncode == 0, completed.stderr
    if os.name == "nt":
        assert "chmod 0700" in STATE.read_text(encoding="utf-8")
        assert "chmod 0600" in STATE.read_text(encoding="utf-8")
    else:
        assert completed.stdout.splitlines() == ["700", "600"]
    assert (
        tmp_path / "state" / "credential"
    ).read_text(encoding="utf-8") == "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq"


def test_missing_controller_cmdline_uses_fixed_http_default(
    tmp_path: Path,
) -> None:
    cmdline = tmp_path / "cmdline"
    cmdline.write_text(
        "quiet sosnadmin.mode=agent-v1\n",
        encoding="utf-8",
    )
    completed = _run_bash(
        """
set -euo pipefail
source deploy/alt-linux/install-agent/v1/lib/config.sh
config_load
printf '%s\\n' "$ALT_INSTALL_CONTROLLER"
""",
        env={"ALT_INSTALL_CMDLINE_FILE": cmdline.as_posix()},
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "http://192.168.100.17:18089"


def test_create_nonce_is_32_bytes_in_url_safe_form(tmp_path: Path) -> None:
    completed = _run_bash(
        """
set -euo pipefail
base64() { return 97; }
od() {
    printf '%s ' {0..31}
    printf '\\n'
}
export ALT_INSTALL_AGENT_LIBRARY_ONLY=1
source deploy/alt-linux/install-agent/v1/alt-install-agent
state_init
generate_create_nonce
state_read create-nonce
""",
        env={"ALT_INSTALL_STATE_ROOT": tmp_path.as_posix() + "/state"},
    )

    assert completed.returncode == 0, completed.stderr
    nonce = completed.stdout.strip()
    expected = base64.urlsafe_b64encode(bytes(range(32))).rstrip(b"=").decode()
    assert nonce == expected


def test_transport_retries_only_failures_with_bounded_backoff(
    tmp_path: Path,
) -> None:
    inventory = tmp_path / "inventory.json"
    inventory.write_text('{"schema_version":1}', encoding="utf-8")
    environment = _protocol_environment(tmp_path, "retry-create")

    completed = _run_bash(
        f"""
set -euo pipefail
source deploy/alt-linux/install-agent/v1/lib/state.sh
source deploy/alt-linux/install-agent/v1/lib/transport.sh
source deploy/alt-linux/install-agent/v1/lib/protocol.sh
state_init
state_write create-nonce 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq'
protocol_create_session '{inventory.as_posix()}'
cat "$ALT_INSTALL_STATE_ROOT/session-id"
""",
        env=environment,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "install-20260727T120000Z-a1b2c3d4"
    assert (tmp_path / "attempts").read_text(encoding="utf-8").strip() == "3"
    assert (tmp_path / "sleep.log").read_text(
        encoding="utf-8"
    ).splitlines() == ["1", "2"]


def test_network_dhcp_uses_the_private_initrd_hook(tmp_path: Path) -> None:
    network_root = tmp_path / "net"
    (network_root / "eth0").mkdir(parents=True)
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    udhcpc = fake_bin / "udhcpc"
    udhcpc.write_text(
        "#!/bin/bash\nprintf '%s\\n' \"$*\" > \"$FAKE_UDHCPC_LOG\"\n",
        encoding="utf-8",
        newline="\n",
    )
    udhcpc.chmod(0o755)
    ip = fake_bin / "ip"
    ip.write_text(
        "#!/bin/bash\nprintf '%s\\n' \"$*\" >> \"$FAKE_IP_LOG\"\n",
        encoding="utf-8",
        newline="\n",
    )
    ip.chmod(0o755)

    completed = _run_bash(
        """
set -euo pipefail
source deploy/alt-linux/install-agent/v1/lib/network.sh
network_request_dhcp_once
""",
        env={
            "ALT_INSTALL_SYS_CLASS_NET": network_root.as_posix(),
            "ALT_INSTALL_DHCP_HOOK": DHCP_HOOK.as_posix(),
            "FAKE_UDHCPC_LOG": (tmp_path / "udhcpc.log").as_posix(),
            "FAKE_IP_LOG": (tmp_path / "ip.log").as_posix(),
            "PATH": fake_bin.as_posix() + os.pathsep + os.environ["PATH"],
        },
    )

    assert completed.returncode == 0, completed.stderr
    arguments = (tmp_path / "udhcpc.log").read_text(encoding="utf-8")
    assert "-i eth0" in arguments
    assert f"-s {DHCP_HOOK.as_posix()}" in arguments


def test_dhcp_hook_converts_contiguous_netmask() -> None:
    completed = _run_bash(
        """
set -euo pipefail
source deploy/alt-linux/install-agent/v1/lib/dhcp-hook.sh
mask_to_prefix 255.255.252.0
"""
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "22"


def test_redirect_is_rejected_without_retry(tmp_path: Path) -> None:
    inventory = tmp_path / "inventory.json"
    inventory.write_text('{"schema_version":1}', encoding="utf-8")
    environment = _protocol_environment(tmp_path, "redirect")

    completed = _run_bash(
        f"""
set -euo pipefail
source deploy/alt-linux/install-agent/v1/lib/state.sh
source deploy/alt-linux/install-agent/v1/lib/transport.sh
source deploy/alt-linux/install-agent/v1/lib/protocol.sh
state_init
state_write create-nonce 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq'
protocol_create_session '{inventory.as_posix()}'
""",
        env=environment,
    )

    assert completed.returncode != 0
    assert "redirect_rejected" in completed.stderr
    assert (tmp_path / "attempts").read_text(encoding="utf-8").strip() == "1"
    assert not (tmp_path / "sleep.log").exists()


def test_response_size_failure_is_not_retried(tmp_path: Path) -> None:
    inventory = tmp_path / "inventory.json"
    inventory.write_text('{"schema_version":1}', encoding="utf-8")
    environment = _protocol_environment(tmp_path, "too-large")

    completed = _run_bash(
        f"""
set -euo pipefail
source deploy/alt-linux/install-agent/v1/lib/state.sh
source deploy/alt-linux/install-agent/v1/lib/transport.sh
source deploy/alt-linux/install-agent/v1/lib/protocol.sh
state_init
state_write create-nonce 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq'
protocol_create_session '{inventory.as_posix()}'
""",
        env=environment,
    )

    assert completed.returncode != 0
    assert "response_too_large" in completed.stderr
    assert (tmp_path / "attempts").read_text(encoding="utf-8").strip() == "1"
    assert not (tmp_path / "sleep.log").exists()


def test_transport_retry_budget_is_five_attempts(tmp_path: Path) -> None:
    inventory = tmp_path / "inventory.json"
    inventory.write_text('{"schema_version":1}', encoding="utf-8")
    environment = _protocol_environment(tmp_path, "transport-always")

    completed = _run_bash(
        f"""
set -euo pipefail
source deploy/alt-linux/install-agent/v1/lib/state.sh
source deploy/alt-linux/install-agent/v1/lib/transport.sh
source deploy/alt-linux/install-agent/v1/lib/protocol.sh
state_init
state_write create-nonce 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq'
protocol_create_session '{inventory.as_posix()}'
""",
        env=environment,
    )

    assert completed.returncode != 0
    assert "transport_exhausted" in completed.stderr
    assert (tmp_path / "attempts").read_text(encoding="utf-8").strip() == "5"
    assert (tmp_path / "sleep.log").read_text(
        encoding="utf-8"
    ).splitlines() == ["1", "2", "4", "8"]


def test_bearer_credential_stays_out_of_logs_and_process_arguments(
    tmp_path: Path,
) -> None:
    inventory = tmp_path / "inventory.json"
    inventory.write_text('{"schema_version":1}', encoding="utf-8")
    environment = _protocol_environment(tmp_path, "create-and-heartbeat")
    secret = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq"

    completed = _run_bash(
        f"""
set -euo pipefail
source deploy/alt-linux/install-agent/v1/lib/state.sh
source deploy/alt-linux/install-agent/v1/lib/transport.sh
source deploy/alt-linux/install-agent/v1/lib/protocol.sh
state_init
state_write create-nonce 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq'
protocol_create_session '{inventory.as_posix()}'
protocol_heartbeat agent_started
stat -c '%a' "$ALT_INSTALL_STATE_ROOT/curl-auth.conf"
""",
        env=environment,
    )

    assert completed.returncode == 0, completed.stderr
    if os.name == "nt":
        assert completed.stdout.strip() == "644"
    else:
        assert completed.stdout.strip() == "600"
    assert secret not in completed.stdout
    assert secret not in completed.stderr
    assert secret not in (tmp_path / "curl.log").read_text(encoding="utf-8")
    assert secret in (
        tmp_path / "state" / "curl-auth.conf"
    ).read_text(encoding="utf-8")


def test_status_poll_and_download_preserve_exact_plan_bytes(
    tmp_path: Path,
) -> None:
    environment = _protocol_environment(tmp_path, "status-and-plan")
    secret = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq"

    completed = _run_bash(
        """
set -euo pipefail
source deploy/alt-linux/install-agent/v1/lib/state.sh
source deploy/alt-linux/install-agent/v1/lib/transport.sh
source deploy/alt-linux/install-agent/v1/lib/protocol.sh
state_init
state_write session-id 'install-20260727T120000Z-a1b2c3d4'
state_write poll-after '1'
state_write credential 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq'
state_write curl-auth.conf 'header = "Authorization: Bearer ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq"'
protocol_wait_for_plan
protocol_download_plan
cat "$ALT_INSTALL_STATE_ROOT/plan.json"
printf '\\n'
cat "$ALT_INSTALL_STATE_ROOT/plan-signature.json"
""",
        env=environment,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.splitlines() == [
        '{"plan":"exact-plan-bytes"}',
        '{"signature":"exact-signature-bytes"}',
    ]
    assert secret not in (tmp_path / "curl.log").read_text(encoding="utf-8")


def test_agent_invokes_all_helper_commands_before_ready_hold(
    tmp_path: Path,
) -> None:
    helper = tmp_path / "alt-install-helper"
    helper.write_text(
        """#!/bin/bash
set -eu
printf '%s\\n' "$1" >> "$FAKE_HELPER_LOG"
case "$1" in
    inventory)
        shift
        [[ "$1" == --output ]]
        printf '%s' '{"agent":{"boot_id":"boot-100"}}' > "$2"
        chmod 0600 "$2"
        printf '%s\\n' '{"command":"inventory","ok":true}'
        ;;
    verify-plan|disk-preflight)
        printf '{"command":"%s","ok":true}\\n' "$1"
        ;;
    *) exit 2 ;;
esac
""",
        encoding="utf-8",
        newline="\n",
    )
    helper.chmod(0o755)
    cmdline = tmp_path / "cmdline"
    cmdline.write_text(
        "quiet sosnadmin.mode=agent-v1 "
        "sosnadmin.controller=http://192.168.100.17:18089\n",
        encoding="utf-8",
    )
    boot_id = tmp_path / "boot-id"
    boot_id.write_text("boot-100\n", encoding="utf-8")
    stages = tmp_path / "stages"

    completed = _run_bash(
        f"""
set -euo pipefail
export ALT_INSTALL_AGENT_LIBRARY_ONLY=1
source deploy/alt-linux/install-agent/v1/alt-install-agent
network_prepare() {{ :; }}
protocol_create_session() {{
    state_write session-id 'install-20260727T120000Z-a1b2c3d4'
    state_write credential 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq'
    state_write curl-auth.conf 'header = "Authorization: Bearer ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq"'
}}
protocol_heartbeat() {{ printf '%s\\n' "$1" >> '{stages.as_posix()}'; }}
protocol_wait_for_plan() {{ :; }}
protocol_download_plan() {{
    state_write plan.json '{{"schema_version":1}}'
    state_write plan-signature.json '{{"schema_version":1}}'
}}
terminal_hold() {{ printf 'terminal=%s\\n' "$1"; }}
agent_run
""",
        env={
            "ALT_INSTALL_STATE_ROOT": tmp_path.as_posix() + "/state",
            "ALT_INSTALL_CMDLINE_FILE": cmdline.as_posix(),
            "ALT_INSTALL_BOOT_ID_FILE": boot_id.as_posix(),
            "ALT_INSTALL_HELPER": helper.as_posix(),
            "ALT_INSTALL_PUBLIC_KEY": tmp_path.as_posix() + "/public-key.json",
            "FAKE_HELPER_LOG": (tmp_path / "helper.log").as_posix(),
        },
    )

    assert completed.returncode == 0, completed.stderr
    assert (tmp_path / "helper.log").read_text(
        encoding="utf-8"
    ).splitlines() == ["inventory", "verify-plan", "disk-preflight"]
    assert stages.read_text(encoding="utf-8").splitlines() == [
        "agent_started",
        "inventory_validated",
        "waiting_for_approval",
        "plan_downloaded",
        "preflight_ready",
    ]
    assert completed.stdout.splitlines()[-1] == "terminal=preflight_ready"


def test_missing_boot_id_enters_terminal_hold(tmp_path: Path) -> None:
    cmdline = tmp_path / "cmdline"
    cmdline.write_text(
        "sosnadmin.mode=agent-v1 "
        "sosnadmin.controller=http://192.168.100.17:18089\n",
        encoding="utf-8",
    )

    completed = _run_bash(
        """
set -euo pipefail
export ALT_INSTALL_AGENT_LIBRARY_ONLY=1
source deploy/alt-linux/install-agent/v1/alt-install-agent
network_prepare() { :; }
generate_create_nonce() { :; }
helper_inventory() { :; }
terminal_hold() { printf 'terminal=%s\\n' "$1"; exit 97; }
agent_run
""",
        env={
            "ALT_INSTALL_STATE_ROOT": tmp_path.as_posix() + "/state",
            "ALT_INSTALL_CMDLINE_FILE": cmdline.as_posix(),
            "ALT_INSTALL_BOOT_ID_FILE": (
                tmp_path / "missing-boot-id"
            ).as_posix(),
        },
    )

    assert completed.returncode == 97
    assert completed.stdout.strip() == "terminal=boot_id_failed"


def test_ready_terminal_state_never_returns() -> None:
    completed = _run_bash(
        "timeout 0.4s bash -c '"
        "source deploy/alt-linux/install-agent/v1/lib/ui.sh; "
        "terminal_hold preflight_ready'",
        env={"ALT_INSTALL_SLEEP": "true"},
    )

    assert completed.returncode == 124
    assert completed.stderr == ""
    assert "READY FOR INSTALLATION" in completed.stdout
    assert "DRY RUN" in completed.stdout
    assert (
        "PASS: signed plan verified; disk preflight passed; no target writes"
        in completed.stdout
    )


def test_v1_payload_contains_no_destructive_handoff_tokens() -> None:
    files = [
        AGENT,
        *sorted((AGENT_ROOT / "lib").glob("*.sh")),
        GATE,
        BUILDER,
        BUILD_INPUTS,
        VERIFIER,
        *sorted((ISO_ROOT / "boot-menu").glob("*.patch")),
    ]
    forbidden = (
        "alterator",
        "install2.target",
        "sfdisk",
        "wipefs",
        "mkfs",
        "parted",
        "fdisk",
        "dd of=",
        "mount -o rw",
        "reboot",
        "poweroff",
    )

    for path in files:
        text = path.read_text(encoding="utf-8").lower()
        for token in forbidden:
            assert token not in text, f"{path} contains forbidden token {token}"


def test_iso_assets_pin_source_and_require_external_public_key() -> None:
    source = json.loads(SOURCE_ISO.read_text(encoding="utf-8"))
    assert source == {
        "schema_version": 1,
        "iso_id": "alt-kworkstation-11.4-install-x86_64",
        "iso_sha256": (
            "2529f98bca03a652709434a6a17cd4aac5df20c0793927abdf"
            "784e8f9388243a"
        ),
    }

    builder = BUILDER.read_text(encoding="utf-8")
    verifier = VERIFIER.read_text(encoding="utf-8")
    gate = GATE.read_text(encoding="utf-8")
    workflow = WORKFLOW.read_text(encoding="utf-8")
    assert "--public-key" in builder
    assert "public_key_sha256" in builder
    assert "public_key_id" in builder
    assert "payload.sha256" in builder
    assert "alt-install-helper" in builder
    assert "source_iso.json" in builder
    assert "stat -c '%a'" in verifier
    assert "sha256sum -c" in verifier
    assert "initrd_command" in verifier
    assert '[[ -f "$candidate" && -x "$candidate" ]]' in verifier
    for command in (
        "bash",
        "curl",
        "date",
        "grep",
        "head",
        "ip",
        "lsblk",
        "od",
        "tr",
        "udhcpc",
        "wc",
    ):
        assert f" {command}" in verifier
    assert "sosnadmin.mode=agent-v1" in gate
    assert "exec /usr/libexec/alt-install-agent" in gate
    assert "tests/test_alt_install_agent_v1.py" in workflow
    assert "find deploy/alt-linux/iso/agent-v1/lib" in workflow


def test_public_key_snapshot_survives_source_mutation_and_symlink_retarget(
    tmp_path: Path,
) -> None:
    first_document = _public_key_document(bytes(range(32)))
    second_document = _public_key_document(bytes(range(32, 64)))
    first_target = tmp_path / "key-a.json"
    second_target = tmp_path / "key-b.json"
    source_link = tmp_path / "public-key.json"
    stage = tmp_path / "stage"
    snapshot = stage / "public-key.snapshot.json"
    first_target.write_bytes(first_document.encode("utf-8"))
    second_target.write_bytes(second_document.encode("utf-8"))
    try:
        source_link.symlink_to(first_target)
    except OSError:
        pytest.skip("file symlink creation is unavailable")

    first = _run_bash(
        f"""
set -euo pipefail
source deploy/alt-linux/iso/agent-v1/lib/build-inputs.sh
mkdir -p '{stage.as_posix()}'
chmod 0700 '{stage.as_posix()}'
snapshot_public_key '{source_link.as_posix()}' '{snapshot.as_posix()}'
public_key_metadata '{snapshot.as_posix()}'
""",
        env={"ALT_INSTALL_PYTHON": Path(sys.executable).as_posix()},
    )
    assert first.returncode == 0, first.stderr

    first_target.write_bytes(second_document.encode("utf-8"))
    source_link.unlink()
    source_link.symlink_to(second_target)
    second = _run_bash(
        f"""
set -euo pipefail
source deploy/alt-linux/iso/agent-v1/lib/build-inputs.sh
public_key_metadata '{snapshot.as_posix()}'
""",
        env={"ALT_INSTALL_PYTHON": Path(sys.executable).as_posix()},
    )

    expected_key_id = "sha256:" + hashlib.sha256(bytes(range(32))).hexdigest()
    expected_document_sha256 = hashlib.sha256(
        first_document.encode("utf-8")
    ).hexdigest()
    assert second.returncode == 0, second.stderr
    assert first.stdout.strip().split() == [
        expected_key_id,
        expected_document_sha256,
    ]
    assert second.stdout == first.stdout
    assert snapshot.read_text(encoding="utf-8") == first_document
    if os.name == "nt":
        assert "chmod 0600" in BUILD_INPUTS.read_text(encoding="utf-8")
    else:
        assert snapshot.stat().st_mode & 0o777 == 0o600


def test_builder_never_reopens_mutable_public_key_after_snapshot() -> None:
    builder = BUILDER.read_text(encoding="utf-8")
    marker = (
        'snapshot_public_key "$public_key_resolved" '
        '"$public_key_snapshot"'
    )
    assert marker in builder
    after_snapshot = builder.split(marker, maxsplit=1)[1]

    assert '"$public_key"' not in after_snapshot
    assert 'public_key_metadata "$public_key_snapshot"' in after_snapshot
    assert 'install -D -m 0644 "$public_key_snapshot"' in after_snapshot
    assert '"$public_key_sha256"' in after_snapshot


def test_builder_refuses_to_run_without_public_key(tmp_path: Path) -> None:
    source = tmp_path / "source.iso"
    helper = tmp_path / "alt-install-helper"
    output = tmp_path / "managed.iso"
    source.write_bytes(b"source")
    helper.write_bytes(b"helper")
    helper.chmod(0o755)

    completed = _run_bash(
        f"""
bash deploy/alt-linux/iso/agent-v1/build-managed-iso.sh \
    --source '{source.as_posix()}' \
    --output '{output.as_posix()}' \
    --helper '{helper.as_posix()}' \
    --build-id test-build
"""
    )

    assert completed.returncode == 2
    assert "--public-key" in completed.stderr
    assert not output.exists()


def test_builder_applies_overwrite_policy_to_existing_sidecar(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.iso"
    helper = tmp_path / "alt-install-helper"
    public_key = tmp_path / "public-key.json"
    output = tmp_path / "managed.iso"
    sidecar = tmp_path / "managed.iso.build-manifest.json"
    source.write_bytes(b"source")
    helper.write_bytes(b"helper")
    public_key.write_text("{}", encoding="utf-8")
    sidecar.write_bytes(b"preserve-sidecar")

    completed = _run_bash(
        f"""
bash deploy/alt-linux/iso/agent-v1/build-managed-iso.sh \
    --source '{source.as_posix()}' \
    --output '{output.as_posix()}' \
    --helper '{helper.as_posix()}' \
    --public-key '{public_key.as_posix()}' \
    --build-id test-build
"""
    )

    assert completed.returncode == 1
    assert "Sidecar exists; use --force" in completed.stderr
    assert sidecar.read_bytes() == b"preserve-sidecar"
    assert not output.exists()


@pytest.mark.parametrize("input_name", ["source", "helper", "public_key"])
def test_builder_never_allows_sidecar_to_alias_an_input(
    tmp_path: Path,
    input_name: str,
) -> None:
    output = tmp_path / "managed.iso"
    sidecar = tmp_path / "managed.iso.build-manifest.json"
    source = tmp_path / "source.iso"
    helper = tmp_path / "alt-install-helper"
    public_key = tmp_path / "public-key.json"
    source.write_bytes(b"source")
    helper.write_bytes(b"helper")
    public_key.write_text("{}", encoding="utf-8")
    paths = {
        "source": source,
        "helper": helper,
        "public_key": public_key,
    }
    paths[input_name] = sidecar
    sidecar.write_bytes(b"protected-input")

    completed = _run_bash(
        f"""
bash deploy/alt-linux/iso/agent-v1/build-managed-iso.sh \
    --source '{paths["source"].as_posix()}' \
    --output '{output.as_posix()}' \
    --helper '{paths["helper"].as_posix()}' \
    --public-key '{paths["public_key"].as_posix()}' \
    --build-id test-build \
    --force
"""
    )

    assert completed.returncode == 1
    assert "Output artifacts conflict with an input asset" in completed.stderr
    assert sidecar.read_bytes() == b"protected-input"
    assert not output.exists()


def test_builder_never_accepts_source_as_forced_output(tmp_path: Path) -> None:
    source = tmp_path / "same.iso"
    helper = tmp_path / "alt-install-helper"
    public_key = tmp_path / "public-key.json"
    original = b"pinned-source-iso"
    source.write_bytes(original)
    helper.write_bytes(b"not-reached")
    public_key.write_text("{}", encoding="utf-8")

    completed = _run_bash(
        f"""
bash deploy/alt-linux/iso/agent-v1/build-managed-iso.sh \
    --source '{source.as_posix()}' \
    --output '{source.as_posix()}' \
    --helper '{helper.as_posix()}' \
    --public-key '{public_key.as_posix()}' \
    --build-id test-build \
    --force
"""
    )

    assert completed.returncode == 1
    assert "Source and output paths must differ" in completed.stderr
    assert source.read_bytes() == original


def test_builder_resolves_source_symlink_before_output_guard(
    tmp_path: Path,
) -> None:
    if os.name == "nt":
        pytest.skip("Git Bash cannot resolve native Windows file symlinks")
    source = tmp_path / "real.iso"
    source_alias = tmp_path / "alias.iso"
    helper = tmp_path / "alt-install-helper"
    public_key = tmp_path / "public-key.json"
    original = b"pinned-source-iso"
    source.write_bytes(original)
    try:
        source_alias.symlink_to(source)
    except OSError:
        pytest.skip("file symlink creation is unavailable")
    helper.write_bytes(b"not-reached")
    public_key.write_text("{}", encoding="utf-8")

    completed = _run_bash(
        f"""
bash deploy/alt-linux/iso/agent-v1/build-managed-iso.sh \
    --source '{source_alias.as_posix()}' \
    --output '{source.as_posix()}' \
    --helper '{helper.as_posix()}' \
    --public-key '{public_key.as_posix()}' \
    --build-id test-build \
    --force
"""
    )

    assert completed.returncode == 1
    assert "Source and output paths must differ" in completed.stderr
    assert source.read_bytes() == original
