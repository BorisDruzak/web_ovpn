from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
AGENT_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "install-agent" / "v2"
AGENT = AGENT_ROOT / "alt-install-execution-agent"
PROTOCOL = AGENT_ROOT / "lib" / "protocol.sh"
UI = AGENT_ROOT / "lib" / "ui.sh"


def _bash() -> Path:
    for candidate in (
        shutil.which("bash"),
        r"C:\Program Files\Git\bin\bash.exe",
        r"C:\Program Files\Git\usr\bin\bash.exe",
    ):
        if candidate and Path(candidate).is_file():
            return Path(candidate)
    pytest.skip("Bash is required for the V2 initrd-agent contract")


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
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def _library_agent_script(body: str) -> str:
    return f"""
set -euo pipefail
export ALT_INSTALL_AGENT_LIBRARY_ONLY=1
source '{AGENT.as_posix()}'
config_load() {{ :; }}
state_init() {{ :; }}
terminal_hold() {{ printf 'terminal=%s\\n' "$1"; exit 97; }}
{body}
"""


def test_agent_holds_without_execution_authorization(tmp_path: Path) -> None:
    actions = tmp_path / "actions"
    completed = _run_bash(
        _library_agent_script(
            f"""
protocol_download_execution_bundle() {{
    printf 'download-rejected\\n' >> '{actions.as_posix()}'
    return 1
}}
helper_verify_execution_bundle() {{
    printf 'verify-must-not-run\\n' >> '{actions.as_posix()}'
}}
protocol_claim_execution() {{
    printf 'claim-must-not-run\\n' >> '{actions.as_posix()}'
}}
helper_verify_plan() {{
    printf 'plan-must-not-run\\n' >> '{actions.as_posix()}'
}}
helper_disk_preflight() {{
    printf 'preflight-must-not-run\\n' >> '{actions.as_posix()}'
}}
protocol_handoff_started() {{
    printf 'handoff-must-not-run\\n' >> '{actions.as_posix()}'
}}
start_execution_relay() {{
    printf 'relay-must-not-run\\n' >> '{actions.as_posix()}'
}}
agent_run
"""
        )
    )

    assert completed.returncode == 97
    assert completed.stdout.strip() == "terminal=execution_pending"
    assert actions.read_text(encoding="utf-8").splitlines() == [
        "download-rejected"
    ]


def test_agent_repeats_preflight_then_starts_relay_before_handoff(
    tmp_path: Path,
) -> None:
    actions = tmp_path / "actions"
    completed = _run_bash(
        _library_agent_script(
            f"""
record() {{ printf '%s\\n' "$1" >> '{actions.as_posix()}'; }}
protocol_download_execution_bundle() {{ record download-execution-bundle; }}
helper_verify_execution_bundle() {{ record verify-execution-bundle; }}
protocol_claim_execution() {{ record claim; }}
helper_verify_plan() {{ record verify-plan; }}
helper_disk_preflight() {{ record disk-preflight; }}
protocol_handoff_started() {{ record handoff-started; }}
start_execution_relay() {{ record serve-execution-metadata; }}
agent_run
"""
        )
    )

    assert completed.returncode == 0, completed.stderr
    assert actions.read_text(encoding="utf-8").splitlines() == [
        "download-execution-bundle",
        "verify-execution-bundle",
        "claim",
        "verify-plan",
        "disk-preflight",
        "serve-execution-metadata",
        "handoff-started",
    ]


def _readiness_helper(
    tmp_path: Path,
    *,
    signal_ready: bool,
    startup_delay: float,
) -> tuple[Path, Path]:
    helper = tmp_path / "alt-install-helper"
    actions = tmp_path / "readiness-actions"
    ready_action = (
        f"""
sleep {startup_delay}
printf 'relay-bound\\n' >> '{actions.as_posix()}'
printf 'ALT_INSTALL_RELAY_READY_V1\\n' > "$ready_file"
sleep 1
"""
        if signal_ready
        else f"""
sleep {startup_delay}
printf 'relay-failed\\n' >> '{actions.as_posix()}'
exit 1
"""
    )
    helper.write_text(
        f"""#!/bin/bash
set -eu
[[ "$1" == serve-execution-metadata ]]
printf 'relay-started\\n' >> '{actions.as_posix()}'
shift
ready_file=
while (($#)); do
    if [[ "$1" == --ready-file ]]; then
        ready_file=$2
        shift 2
    else
        shift
    fi
done
[[ -n "$ready_file" ]]
{ready_action}
""",
        encoding="utf-8",
        newline="\n",
    )
    helper.chmod(0o755)
    return helper, actions


def test_agent_waits_for_delayed_post_bind_readiness_before_handoff(
    tmp_path: Path,
) -> None:
    helper, actions = _readiness_helper(
        tmp_path, signal_ready=True, startup_delay=0.35
    )
    state = tmp_path / "state"
    state.mkdir()
    (state / "execution-verification.json").write_text(
        '{"expires_at":"2099-01-01T00:00:00Z"}',
        encoding="utf-8",
    )
    completed = _run_bash(
        _library_agent_script(
            f"""
protocol_download_execution_bundle() {{ :; }}
helper_verify_execution_bundle() {{ :; }}
protocol_claim_execution() {{ :; }}
helper_verify_plan() {{ :; }}
helper_disk_preflight() {{ :; }}
protocol_handoff_started() {{
    printf 'handoff-started\\n' >> '{actions.as_posix()}'
}}
agent_run
printf 'agent-returned\\n' >> '{actions.as_posix()}'
"""
        ),
        env={
            "ALT_INSTALL_STATE_ROOT": state.as_posix(),
            "ALT_INSTALL_HELPER": helper.as_posix(),
            "ALT_INSTALL_RELAY_READY_TIMEOUT": "2",
            "ALT_INSTALL_RELAY_POLL_INTERVAL": "0.05",
        },
    )
    assert completed.returncode == 0, completed.stderr
    assert actions.read_text(encoding="utf-8").splitlines() == [
        "relay-started",
        "relay-bound",
        "handoff-started",
        "agent-returned",
    ]


def test_relay_exit_before_readiness_holds_without_handoff(
    tmp_path: Path,
) -> None:
    helper, actions = _readiness_helper(
        tmp_path, signal_ready=False, startup_delay=0.2
    )
    state = tmp_path / "state"
    state.mkdir()
    (state / "execution-verification.json").write_text(
        '{"expires_at":"2099-01-01T00:00:00Z"}',
        encoding="utf-8",
    )
    completed = _run_bash(
        _library_agent_script(
            f"""
protocol_download_execution_bundle() {{ :; }}
helper_verify_execution_bundle() {{ :; }}
protocol_claim_execution() {{ :; }}
helper_verify_plan() {{ :; }}
helper_disk_preflight() {{ :; }}
protocol_handoff_started() {{
    printf 'handoff-must-not-run\\n' >> '{actions.as_posix()}'
}}
agent_run
"""
        ),
        env={
            "ALT_INSTALL_STATE_ROOT": state.as_posix(),
            "ALT_INSTALL_HELPER": helper.as_posix(),
            "ALT_INSTALL_RELAY_READY_TIMEOUT": "2",
            "ALT_INSTALL_RELAY_POLL_INTERVAL": "0.05",
        },
    )

    assert completed.returncode == 97
    assert completed.stdout.strip() == "terminal=relay_failed"
    assert actions.read_text(encoding="utf-8").splitlines() == [
        "relay-started",
        "relay-failed",
    ]


@pytest.mark.parametrize(
    ("failing_action", "terminal"),
    [
        ("verify-execution-bundle", "execution_verification_failed"),
        ("claim", "execution_claim_failed"),
        ("verify-plan", "plan_verification_failed"),
        ("disk-preflight", "disk_preflight_failed"),
        ("handoff-started", "handoff_record_failed"),
        ("serve-execution-metadata", "relay_failed"),
    ],
)
def test_agent_failure_before_return_is_terminal_and_stops_progress(
    tmp_path: Path,
    failing_action: str,
    terminal: str,
) -> None:
    actions = tmp_path / "actions"
    completed = _run_bash(
        _library_agent_script(
            f"""
run_action() {{
    printf '%s\\n' "$1" >> '{actions.as_posix()}'
    [[ "$1" != '{failing_action}' ]]
}}
protocol_download_execution_bundle() {{ run_action download-execution-bundle; }}
helper_verify_execution_bundle() {{ run_action verify-execution-bundle; }}
protocol_claim_execution() {{ run_action claim; }}
helper_verify_plan() {{ run_action verify-plan; }}
helper_disk_preflight() {{ run_action disk-preflight; }}
protocol_handoff_started() {{ run_action handoff-started; }}
start_execution_relay() {{ run_action serve-execution-metadata; }}
agent_run
"""
        )
    )

    assert completed.returncode == 97
    assert completed.stdout.strip() == f"terminal={terminal}"
    observed = actions.read_text(encoding="utf-8").splitlines()
    assert observed[-1] == failing_action
    assert "sfdisk" not in observed
    assert "wipefs" not in observed
    assert "mkfs" not in observed


def test_protocol_posts_exact_single_use_routes_with_hardened_tls(
    tmp_path: Path,
) -> None:
    curl = tmp_path / "curl"
    arguments = tmp_path / "curl.arguments"
    curl.write_text(
        f"""#!/bin/bash
set -eu
printf '%s\\n' "$@" >> '{arguments.as_posix()}'
output=
previous=
for argument in "$@"; do
    if [[ "$previous" == --output ]]; then
        output=$argument
        break
    fi
    previous=$argument
done
[[ -n "$output" ]]
printf '%s' '{{"execution":{{"state":"claimed"}},"status":"ok"}}' > "$output"
printf '200'
""",
        encoding="utf-8",
        newline="\n",
    )
    curl.chmod(0o755)
    state = tmp_path / "state"
    state.mkdir()
    (state / "session-id").write_text(
        "install-20260729T120000Z-a1b2c3d4", encoding="utf-8"
    )
    (state / "curl-auth.conf").write_text(
        'header = "Authorization: Bearer AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"',
        encoding="utf-8",
    )
    ca = tmp_path / "execution-ca.pem"
    ca.write_text("test-ca", encoding="utf-8")

    completed = _run_bash(
        f"""
set -euo pipefail
source deploy/alt-linux/install-agent/v1/lib/state.sh
source '{PROTOCOL.as_posix()}'
protocol_claim_execution
""",
        env={
            "ALT_INSTALL_STATE_ROOT": state.as_posix(),
            "ALT_INSTALL_CURL": curl.as_posix(),
            "ALT_INSTALL_EXECUTION_CA": ca.as_posix(),
            "ALT_INSTALL_EXECUTION_CONTROLLER": "https://192.168.100.17:18092",
        },
    )

    assert completed.returncode == 0, completed.stderr
    captured = arguments.read_text(encoding="utf-8")
    assert "--proto\n=https\n" in captured
    assert "--proto-redir\n=https\n" in captured
    assert "--max-redirs\n0\n" in captured
    assert "--noproxy\n*\n" in captured
    assert "--proxy\n\n" in captured
    assert "--tlsv1.3\n" in captured
    assert "--config\n" in captured
    assert (
        "https://192.168.100.17:18092/v2/install-sessions/"
        "install-20260729T120000Z-a1b2c3d4/execution/claim\n"
    ) in captured
    assert "Bearer A" not in captured


def test_v2_terminal_hold_never_returns() -> None:
    completed = _run_bash(
        "timeout 0.4s bash -c '"
        f"source {UI.as_posix()}; "
        "terminal_hold execution_pending'",
        env={"ALT_INSTALL_SLEEP": "true"},
    )

    assert completed.returncode == 124
    assert completed.stderr == ""
    assert "terminal=execution_pending" in completed.stdout
