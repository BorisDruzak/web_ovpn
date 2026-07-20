from pathlib import Path
import re
import shutil
import subprocess

import pytest


QUEUE_DIR = "/var/lib/openvpn-web/server-drafts/queue"
RESULTS_DIR = "/var/lib/openvpn-web/server-drafts/results"
PRIVATE_DIR = "/var/lib/openvpn-web/server-drafts/private"
OBSERVER_KEY = "/etc/openvpn-web/server-observer.key"
OBSERVER_PUBLIC_KEY = "/etc/openvpn-web/server-observer.pub"
DRAFT_WORKER_INSTALLER = "deploy/install-server-draft-worker.sh"


def test_worker_service_is_key_isolated_and_retains_observer_hardening():
    service = Path("deploy/server-draft-worker.service").read_text(encoding="utf-8")

    for setting in (
        "User=openvpm",
        "Group=openvpn-web",
        "WorkingDirectory=/opt/openvpn-web",
        "TimeoutStartSec=3min",
        "NoNewPrivileges=true",
        "PrivateTmp=true",
        "ProtectHome=tmpfs",
        "ProtectSystem=strict",
        "ProtectControlGroups=true",
        "ProtectKernelLogs=true",
        "ProtectKernelModules=true",
        "ProtectKernelTunables=true",
        "ProtectClock=true",
        "ProtectHostname=true",
        "ProtectProc=invisible",
        "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
        "RestrictNamespaces=true",
        "RestrictRealtime=true",
        "LockPersonality=true",
        "MemoryDenyWriteExecute=true",
        "SystemCallArchitectures=native",
        "CapabilityBoundingSet=",
        f"BindReadOnlyPaths={OBSERVER_KEY}",
        "InaccessiblePaths=/etc/openvpn-web/openvpn-web.env",
        "InaccessiblePaths=/etc/openvpn/client-generator",
        "InaccessiblePaths=-/mnt/antares_soft/vpn_config",
        "InaccessiblePaths=-/var/lib/openvpn-web/openvpn-web.sqlite",
        "ReadWritePaths=/var/lib/openvpn-web/server-drafts",
        "ExecStart=/usr/local/sbin/server-draft-worker",
    ):
        assert setting in service


def test_worker_wrapper_runs_the_venv_module_once_with_only_draft_paths():
    wrapper = Path("deploy/server-draft-worker").read_text(encoding="utf-8")

    assert wrapper.startswith("#!/usr/bin/env bash\nset -euo pipefail\n")
    assert 'cd "$APP"' in wrapper
    assert "-m app.server_draft_worker" in wrapper
    assert f"--queue-dir {QUEUE_DIR}" in wrapper
    assert f"--results-dir {RESULTS_DIR}" in wrapper
    assert f"--private-dir {PRIVATE_DIR}" in wrapper
    assert "server-observer.key" not in wrapper


def test_path_unit_watches_only_the_public_request_queue():
    path_unit = Path("deploy/server-draft-worker.path").read_text(encoding="utf-8")

    assert f"PathChanged={QUEUE_DIR}" in path_unit
    assert "Unit=server-draft-worker.service" in path_unit
    assert "WantedBy=multi-user.target" in path_unit
    assert RESULTS_DIR not in path_unit
    assert PRIVATE_DIR not in path_unit


def test_installer_derives_public_key_and_enables_path_only():
    installer = Path("deploy/install-openvpn-web.sh").read_text(encoding="utf-8")

    assert "deploy/server-draft-worker\" /usr/local/sbin/server-draft-worker" in installer
    assert "server-draft-worker.service" in installer
    assert "server-draft-worker.path" in installer
    assert f"-d -m 0770 -o openvpn-web -g openvpn-web {QUEUE_DIR}" in installer
    assert f"-d -m 0770 -o openvpn-web -g openvpn-web {RESULTS_DIR}" in installer
    assert f"-d -m 0700 -o openvpm -g openvpm {PRIVATE_DIR}" in installer
    assert f"ssh-keygen -y -f {OBSERVER_KEY}" in installer
    assert OBSERVER_PUBLIC_KEY in installer
    assert f"-m 0644 -o root -g openvpn-web" in installer
    assert "systemctl daemon-reload" in installer
    assert "systemctl enable --now server-draft-worker.path" in installer
    assert "systemctl start server-draft-worker.service" not in installer
    assert "systemctl enable --now server-draft-worker.service" not in installer


def test_draft_worker_only_installer_has_a_strictly_limited_deployment_surface():
    installer = Path(DRAFT_WORKER_INSTALLER).read_text(encoding="utf-8")

    for required in (
        '"$SRC/deploy/server-draft-worker" /usr/local/sbin/server-draft-worker',
        "server-draft-worker.service",
        "server-draft-worker.path",
        f"-d -m 0770 -o openvpn-web -g openvpn-web {QUEUE_DIR}",
        f"-d -m 0770 -o openvpn-web -g openvpn-web {RESULTS_DIR}",
        f"-d -m 0700 -o openvpm -g openvpm {PRIVATE_DIR}",
        f"ssh-keygen -y -f {OBSERVER_KEY}",
        OBSERVER_PUBLIC_KEY,
        "systemctl daemon-reload",
        "systemctl enable --now server-draft-worker.path",
    ):
        assert required in installer

    for forbidden in (
        "netctl-collect",
        "/etc/netctl",
        "openvpn-web.service",
        "openvpn-server",
        "vpn-policy",
        "vpn-runtime-health",
        "systemctl restart",
        "systemctl enable --now server-draft-worker.service",
        '"$APP',
    ):
        assert forbidden not in installer


def test_scoped_installer_locks_and_validates_the_draft_namespace_before_mutation():
    installer = Path(DRAFT_WORKER_INSTALLER).read_text(encoding="utf-8")

    for required in (
        'DRAFT_PARENT="/var/lib/openvpn-web"',
        'DRAFT_ROOT="$DRAFT_PARENT/server-drafts"',
        'validate_root_component /var root root 755',
        'validate_root_component /var/lib root root 755',
        'validate_draft_parent "$DRAFT_PARENT"',
        'validate_existing_draft_component "$DRAFT_ROOT"',
        'validate_existing_draft_component "$DRAFT_ROOT/queue"',
        'validate_existing_draft_component "$DRAFT_ROOT/results"',
        'validate_existing_draft_component "$DRAFT_ROOT/private"',
        'sudo_cmd chown root:openvpn-web "$DRAFT_PARENT"',
        'sudo_cmd chmod 1750 "$DRAFT_PARENT"',
        'sudo_cmd chmod 1770 "$DRAFT_PARENT"',
        'sudo_cmd chown root:openvpn-web "$DRAFT_ROOT"',
        'sudo_cmd chmod 0750 "$DRAFT_ROOT"',
        'sudo_cmd mkdir --mode=0750 -- "$DRAFT_ROOT"',
        'readlink -e -- "$path"',
        'test -L "$path"',
        '"$metadata" == openvpn-web:openvpn-web:770',
        '"$metadata" == root:openvpn-web:750',
        'openvpn-web:openvpn-web:770',
        'openvpm:openvpm:700',
        'draft_root_action=create_exclusive',
        'draft_root_action=existing_hardened',
        'draft_root_action=legacy_locked',
        '[[ "$draft_root_metadata" == "root:openvpn-web:750" ]]',
        'case "$draft_root_action" in',
    ):
        assert required in installer

    cleanup = installer.split("cleanup() {", 1)[1].split("validate_root_component()", 1)[0]
    assert 'chown openvpn-web:openvpn-web "$DRAFT_PARENT"' not in cleanup
    assert 'install -d -m 0770 -o openvpn-web -g openvpn-web "$DRAFT_ROOT"' not in installer
    first_root_mutation = min(
        installer.index('sudo_cmd chown root:openvpn-web "$DRAFT_PARENT"'),
        installer.index('sudo_cmd chmod 1750 "$DRAFT_PARENT"'),
    )
    for validation in (
        'validate_root_component /var root root 755',
        'validate_root_component /var/lib root root 755',
        'validate_draft_parent "$DRAFT_PARENT"',
        'validate_existing_draft_component "$DRAFT_ROOT/private"',
    ):
        assert installer.index(validation) < first_root_mutation


def test_scoped_installer_legacy_parent_lock_executes_chmod_immediately_after_chown(
    tmp_path,
):
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is unavailable on this platform")

    installer = Path(DRAFT_WORKER_INSTALLER).read_text(encoding="utf-8")
    branch = installer.split(
        'if [[ "$draft_parent_metadata" == "openvpn-web:openvpn-web:755" ]]; then',
        1,
    )[1].split("# Recheck after the parent is locked.", 1)[0]
    trace = tmp_path / "legacy-lock.trace"
    script = f'''set -euo pipefail
TRACE="$1"
draft_parent_metadata=openvpn-web:openvpn-web:755
DRAFT_PARENT=/var/lib/openvpn-web
sudo_cmd() {{ printf '%s\\n' "$*" >> "$TRACE"; }}
if [[ "$draft_parent_metadata" == "openvpn-web:openvpn-web:755" ]]; then
{branch.split("else", 1)[0]}
fi
'''

    result = subprocess.run(
        [bash, "-c", script, "legacy-lock", trace.as_posix()],
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert trace.read_text(encoding="utf-8").splitlines() == [
        "chown root:openvpn-web /var/lib/openvpn-web",
        "chmod 1750 /var/lib/openvpn-web",
    ]


def test_worker_handoff_uses_the_scoped_installer_and_validates_rollback_sources():
    deployment = Path("docs/DEPLOYMENT.md").read_text(encoding="utf-8")
    handoff = deployment.split("## SSH Server Draft Worker Handoff and Rollback", 1)[1].split(
        "## Network Observer Setup", 1
    )[0]

    assert "bash deploy/install-server-draft-worker.sh" in handoff
    assert "bash deploy/install-openvpn-web.sh" not in handoff
    assert "server-draft-worker.path" in handoff
    assert "netctl-collect" in handoff
    assert "do **not** restart OpenVPN" in handoff

    for validation in (
        'backup_name="$(basename -- "$BACKUP_ROOT")"',
        "openvpn-web-server-drafts-backup-[0-9]{14}",
        'sudo test -L "$BACKUP_ROOT"',
        'sudo readlink -e -- "$BACKUP_ROOT"',
        'sudo test -d "$BACKUP_ROOT"',
        'sudo test -f "$rollback_manifest"',
        'asset_state server-draft-worker.service -f "$BACKUP_ROOT/server-draft-worker.service"',
        'asset_state server-draft-worker.path -f "$BACKUP_ROOT/server-draft-worker.path"',
        'asset_state server-drafts -d "$BACKUP_ROOT/server-drafts"',
    ):
        assert validation in handoff

    rollback = handoff.split("### Rollback", 1)[1]
    first_mutation = rollback.index("sudo systemctl stop server-draft-worker.path")
    for source_check in (
        'asset_state server-draft-worker.service -f "$BACKUP_ROOT/server-draft-worker.service"',
        'asset_state server-draft-worker.path -f "$BACKUP_ROOT/server-draft-worker.path"',
        'asset_state server-drafts -d "$BACKUP_ROOT/server-drafts"',
    ):
        assert rollback.index(source_check) < first_mutation

    assert "sudo systemctl disable server-draft-worker.path" in handoff
    assert "sudo systemctl stop server-draft-worker.service" in handoff
    assert "sudo rm -rf -- /var/lib/openvpn-web/server-drafts" in handoff


def test_worker_handoff_backup_and_rollback_fail_closed_for_every_mutated_asset():
    deployment = Path("docs/DEPLOYMENT.md").read_text(encoding="utf-8")
    handoff = deployment.split("## SSH Server Draft Worker Handoff and Rollback", 1)[1].split(
        "## Network Observer Setup", 1
    )[0]
    backup, rollback = handoff.split("### Rollback", 1)

    assert "set -euo pipefail" in backup
    assert "set -euo pipefail" in rollback
    assert 'rollback_manifest="$BACKUP_ROOT/rollback.assets"' in backup
    assert "printf 'Draft-worker rollback backup: %s\\n' \"$BACKUP_ROOT\"" in backup

    for source_name in (
        "server-draft-worker",
        "server-draft-worker.service",
        "server-draft-worker.path",
        "server-observer.pub",
        "server-drafts",
    ):
        assert source_name in backup
        assert f'"$BACKUP_ROOT/{source_name}"' in rollback
        assert f'"$rollback_manifest"' in rollback

    assert "present or absent" in backup
    assert "prior asset was absent" in rollback
    assert 'sudo test -L "$BACKUP_ROOT"' in rollback
    assert rollback.index('sudo test -L "$BACKUP_ROOT"') < rollback.index(
        'sudo readlink -e -- "$BACKUP_ROOT"'
    )
    assert 'backup_name="$(basename -- "$BACKUP_ROOT")"' in rollback
    assert '[[ "$backup_name" =~ ^openvpn-web-server-drafts-backup-[0-9]{14}$ ]]' in rollback
    assert '[[ "$BACKUP_ROOT" == "/root/$backup_name" ]]' in rollback
    assert '[[ "$resolved_backup_root" == "/root/$backup_name" ]]' in rollback

    first_mutation = rollback.index("sudo systemctl stop server-draft-worker.path")
    for validation in (
        'sudo test -f "$rollback_manifest"',
        'sudo test -L "$rollback_manifest"',
        'asset_state server-draft-worker -f "$BACKUP_ROOT/server-draft-worker"',
        'asset_state server-observer.pub -f "$BACKUP_ROOT/server-observer.pub"',
        'asset_state server-drafts -d "$BACKUP_ROOT/server-drafts"',
    ):
        assert rollback.index(validation) < first_mutation


def test_worker_handoff_backup_root_is_exclusive_and_validated_before_use():
    deployment = Path("docs/DEPLOYMENT.md").read_text(encoding="utf-8")
    handoff = deployment.split("## SSH Server Draft Worker Handoff and Rollback", 1)[1].split(
        "## Network Observer Setup", 1
    )[0]
    backup = handoff.split("### Rollback", 1)[0]

    assert 'sudo mkdir --mode=0700 -- "$BACKUP_ROOT"' in backup
    assert 'sudo install -d -m 0700 "$BACKUP_ROOT"' not in backup
    assert 'sudo test -L "$BACKUP_ROOT"' in backup
    assert 'sudo readlink -e -- "$BACKUP_ROOT"' in backup
    assert 'sudo stat -c \'%u:%g:%a\' -- "$BACKUP_ROOT"' in backup
    assert '[[ "$backup_root_metadata" == "0:0:700" ]]' in backup
    assert 'DRAFT_PARENT=/var/lib/openvpn-web' in backup
    assert 'sudo test -L "$DRAFT_PARENT"' in backup
    assert 'resolved_draft_parent="$(sudo readlink -e -- "$DRAFT_PARENT")"' in backup
    assert 'draft_parent_metadata="$(sudo stat -c \'%U:%G:%a\' -- "$DRAFT_PARENT")"' in backup
    assert 'openvpn-web:openvpn-web:755|root:openvpn-web:1770' in backup

    manifest_creation = backup.index('sudo install -m 0600 /dev/null "$rollback_manifest"')
    first_copy = backup.index('backup_asset server-draft-worker -f')
    for validation in (
        'sudo test -L "$BACKUP_ROOT"',
        'sudo readlink -e -- "$BACKUP_ROOT"',
        '[[ "$backup_root_metadata" == "0:0:700" ]]',
        'resolved_draft_parent="$(sudo readlink -e -- "$DRAFT_PARENT")"',
        'openvpn-web:openvpn-web:755|root:openvpn-web:1770',
    ):
        assert backup.index(validation) < manifest_creation
        assert backup.index(validation) < first_copy


def test_worker_handoff_backup_quiesces_trigger_and_restores_prior_state_on_failure(
    tmp_path,
):
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is unavailable on this platform")

    deployment = Path("docs/DEPLOYMENT.md").read_text(encoding="utf-8")
    handoff = deployment.split("## SSH Server Draft Worker Handoff and Rollback", 1)[1].split(
        "## Network Observer Setup", 1
    )[0]
    backup = handoff.split("### Rollback", 1)[0]
    state_management = backup.split("# BEGIN draft-worker backup quiescence", 1)[1].split(
        "# END draft-worker backup quiescence", 1
    )[0]
    assert backup.index("# END draft-worker backup quiescence") < backup.index(
        'rollback_manifest="$BACKUP_ROOT/rollback.assets"'
    )
    assert backup.index("# END draft-worker backup quiescence") < backup.index(
        "backup_asset server-draft-worker -f"
    )
    trace = tmp_path / "backup-state.trace"
    script = f'''set -euo pipefail
TRACE="$1"
sudo() {{
  printf '%s\\n' "$*" >> "$TRACE"
  case "$*" in
    "systemctl show --property=LoadState --value server-draft-worker.path") printf '%s\\n' loaded ;;
    "systemctl show --property=ActiveState --value server-draft-worker.path") printf '%s\\n' active ;;
    "systemctl show --property=LoadState --value server-draft-worker.service") printf '%s\\n' loaded ;;
    "systemctl show --property=ActiveState --value server-draft-worker.service") printf '%s\\n' inactive ;;
    "systemctl stop server-draft-worker.path"|"systemctl start server-draft-worker.path") ;;
    *) return 99 ;;
  esac
}}
sleep() {{ :; }}
{state_management}
exit 23
'''

    result = subprocess.run(
        [bash, "-c", script, "backup-state", trace.as_posix()],
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 23, result.stderr
    calls = trace.read_text(encoding="utf-8").splitlines()
    assert calls == [
        "systemctl show --property=LoadState --value server-draft-worker.path",
        "systemctl show --property=ActiveState --value server-draft-worker.path",
        "systemctl stop server-draft-worker.path",
        "systemctl show --property=LoadState --value server-draft-worker.service",
        "systemctl show --property=ActiveState --value server-draft-worker.service",
        "systemctl start server-draft-worker.path",
    ]


def test_worker_handoff_backup_waits_through_activating_until_terminal_inactive(
    tmp_path,
):
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is unavailable on this platform")

    deployment = Path("docs/DEPLOYMENT.md").read_text(encoding="utf-8")
    handoff = deployment.split("## SSH Server Draft Worker Handoff and Rollback", 1)[1].split(
        "## Network Observer Setup", 1
    )[0]
    backup = handoff.split("### Rollback", 1)[0]
    state_management = backup.split("# BEGIN draft-worker backup quiescence", 1)[1].split(
        "# END draft-worker backup quiescence", 1
    )[0]
    trace = tmp_path / "backup-activating.trace"
    active_calls = tmp_path / "service-active-calls"
    active_calls.write_text("0", encoding="utf-8")
    script = f'''set -euo pipefail
TRACE="$1"
ACTIVE_CALLS="$2"
sudo() {{
  printf '%s\n' "$*" >> "$TRACE"
  case "$*" in
    "systemctl show --property=LoadState --value server-draft-worker.path") printf '%s\n' loaded ;;
    "systemctl show --property=ActiveState --value server-draft-worker.path") printf '%s\n' active ;;
    "systemctl show --property=LoadState --value server-draft-worker.service") printf '%s\n' loaded ;;
    "systemctl show --property=ActiveState --value server-draft-worker.service")
      count="$(<"$ACTIVE_CALLS")"
      count=$((count + 1))
      printf '%s' "$count" > "$ACTIVE_CALLS"
      if (( count == 1 )); then printf '%s\n' activating; else printf '%s\n' inactive; fi
      ;;
    "systemctl stop server-draft-worker.path"|"systemctl start server-draft-worker.path") ;;
    *) return 99 ;;
  esac
}}
sleep() {{ printf 'sleep %s\n' "$*" >> "$TRACE"; }}
{state_management}
exit 23
'''

    result = subprocess.run(
        [bash, "-c", script, "backup-activating", trace.as_posix(), active_calls.as_posix()],
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 23, result.stderr
    calls = trace.read_text(encoding="utf-8").splitlines()
    assert calls.count(
        "systemctl show --property=ActiveState --value server-draft-worker.service"
    ) == 2
    assert "sleep 1" in calls
    assert calls.index("sleep 1") < len(calls) - 2
    assert calls[-1] == "systemctl start server-draft-worker.path"


def test_worker_handoff_backup_times_out_fail_closed_while_service_is_activating(
    tmp_path,
):
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is unavailable on this platform")

    deployment = Path("docs/DEPLOYMENT.md").read_text(encoding="utf-8")
    handoff = deployment.split("## SSH Server Draft Worker Handoff and Rollback", 1)[1].split(
        "## Network Observer Setup", 1
    )[0]
    backup = handoff.split("### Rollback", 1)[0]
    state_management = backup.split("# BEGIN draft-worker backup quiescence", 1)[1].split(
        "# END draft-worker backup quiescence", 1
    )[0]
    active_calls = tmp_path / "activating-timeout-calls"
    active_calls.write_text("0", encoding="utf-8")
    script = f'''set -euo pipefail
ACTIVE_CALLS="$1"
sudo() {{
  case "$*" in
    "systemctl show --property=LoadState --value server-draft-worker.path") printf '%s\n' not-found ;;
    "systemctl show --property=LoadState --value server-draft-worker.service") printf '%s\n' loaded ;;
    "systemctl show --property=ActiveState --value server-draft-worker.service")
      count="$(<"$ACTIVE_CALLS")"
      printf '%s' "$((count + 1))" > "$ACTIVE_CALLS"
      printf '%s\n' activating
      ;;
    *) return 99 ;;
  esac
}}
sleep() {{ :; }}
{state_management}
exit 19
'''

    result = subprocess.run(
        [bash, "-c", script, "backup-timeout", active_calls.as_posix()],
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 2
    assert "did not quiesce within 180 seconds" in result.stderr
    assert active_calls.read_text(encoding="utf-8") == "180"


def test_worker_handoff_backup_skips_absent_units_under_set_e(tmp_path):
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is unavailable on this platform")

    deployment = Path("docs/DEPLOYMENT.md").read_text(encoding="utf-8")
    handoff = deployment.split("## SSH Server Draft Worker Handoff and Rollback", 1)[1].split(
        "## Network Observer Setup", 1
    )[0]
    backup = handoff.split("### Rollback", 1)[0]
    state_management = backup.split("# BEGIN draft-worker backup quiescence", 1)[1].split(
        "# END draft-worker backup quiescence", 1
    )[0]
    trace = tmp_path / "backup-absent-units.trace"
    script = f'''set -euo pipefail
TRACE="$1"
sudo() {{
  printf '%s\n' "$*" >> "$TRACE"
  case "$*" in
    "systemctl show --property=LoadState --value server-draft-worker.path"|"systemctl show --property=LoadState --value server-draft-worker.service") printf '%s\n' not-found ;;
    *) return 99 ;;
  esac
}}
sleep() {{ return 99; }}
{state_management}
exit 17
'''

    result = subprocess.run(
        [bash, "-c", script, "backup-absent", trace.as_posix()],
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 17, result.stderr
    calls = trace.read_text(encoding="utf-8").splitlines()
    assert calls == [
        "systemctl show --property=LoadState --value server-draft-worker.path",
        "systemctl show --property=LoadState --value server-draft-worker.service",
    ]


def test_worker_handoff_rollback_skips_stop_and_disable_for_absent_units(tmp_path):
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is unavailable on this platform")

    deployment = Path("docs/DEPLOYMENT.md").read_text(encoding="utf-8")
    handoff = deployment.split("## SSH Server Draft Worker Handoff and Rollback", 1)[1].split(
        "## Network Observer Setup", 1
    )[0]
    rollback = handoff.split("### Rollback", 1)[1]
    unit_quiescence = rollback.split(
        "# BEGIN draft-worker rollback unit quiescence", 1
    )[1].split("# END draft-worker rollback unit quiescence", 1)[0]
    trace = tmp_path / "rollback-absent-units.trace"
    script = f'''set -euo pipefail
TRACE="$1"
sudo() {{
  printf '%s\n' "$*" >> "$TRACE"
  case "$*" in
    "systemctl show --property=LoadState --value server-draft-worker.path"|"systemctl show --property=LoadState --value server-draft-worker.service") printf '%s\n' not-found ;;
    *) return 99 ;;
  esac
}}
{unit_quiescence}
'''

    result = subprocess.run(
        [bash, "-c", script, "rollback-absent", trace.as_posix()],
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert trace.read_text(encoding="utf-8").splitlines() == [
        "systemctl show --property=LoadState --value server-draft-worker.path",
        "systemctl show --property=LoadState --value server-draft-worker.service",
    ]


def test_worker_handoff_rejects_nested_draft_symlinks_before_backup_and_restore(
    tmp_path,
):
    deployment = Path("docs/DEPLOYMENT.md").read_text(encoding="utf-8")
    handoff = deployment.split("## SSH Server Draft Worker Handoff and Rollback", 1)[1].split(
        "## Network Observer Setup", 1
    )[0]
    backup, rollback = handoff.split("### Rollback", 1)

    backup_lock = backup.index("lock_draft_parent_for_backup\n")
    backup_check = backup.index('reject_nested_symlinks "$DRAFT_ROOT"')
    backup_copy = backup.index("backup_asset server-drafts -d")
    assert backup_lock < backup_check < backup_copy
    assert 'sudo find -P "$root" -type l -print -quit' in backup

    restored_source_check = rollback.index(
        'reject_nested_symlinks "$BACKUP_ROOT/server-drafts"'
    )
    rollback_lock = rollback.index("lock_draft_parent_for_restore\n")
    live_check = rollback.index('reject_nested_symlinks "$DRAFT_PARENT/server-drafts"')
    draft_remove = rollback.index("sudo rm -rf -- /var/lib/openvpn-web/server-drafts")
    assert restored_source_check < rollback_lock < live_check < draft_remove

    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is unavailable on this platform")
    draft_root = tmp_path / "server-drafts"
    nested = draft_root / "queue" / "nested"
    nested.mkdir(parents=True)
    target = tmp_path / "outside"
    target.mkdir()
    symlink = nested / "escape"
    try:
        symlink.symlink_to(target, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlinks are unavailable on this platform: {exc}")

    function_text = backup.split("reject_nested_symlinks() {", 1)[1].split("\n}\n", 1)[0]
    script = f'''set -euo pipefail
sudo() {{ "$@"; }}
reject_nested_symlinks() {{
{function_text}
}}
reject_nested_symlinks "$1"
'''
    result = subprocess.run(
        [bash, "-c", script, "nested-symlink", draft_root.as_posix()],
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 2
    assert "nested symlink" in result.stderr


def test_worker_handoff_rollback_executes_parent_lock_before_draft_restore(tmp_path):
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is unavailable on this platform")

    deployment = Path("docs/DEPLOYMENT.md").read_text(encoding="utf-8")
    handoff = deployment.split("## SSH Server Draft Worker Handoff and Rollback", 1)[1].split(
        "## Network Observer Setup", 1
    )[0]
    rollback = handoff.split("### Rollback", 1)[1]
    function_text = rollback.split("lock_draft_parent_for_restore() {", 1)[1].split(
        "\n}\n", 1
    )[0]
    lock_call = rollback.index("lock_draft_parent_for_restore\n")
    for source_validation in (
        'worker_wrapper_state="$(asset_state server-draft-worker ',
        'worker_service_state="$(asset_state server-draft-worker.service ',
        'worker_path_state="$(asset_state server-draft-worker.path ',
        'worker_path_wants_state="$(asset_state server-draft-worker.path.wants ',
        'observer_public_key_state="$(asset_state server-observer.pub ',
        'draft_state="$(asset_state server-drafts',
        'parent_metadata_archive="$BACKUP_ROOT/openvpn-web-parent.tar"',
        "draft-worker parent metadata archive is incomplete or unsafe",
        "draft-worker rollback manifest lacks one prior path active state",
    ):
        assert rollback.index(source_validation) < lock_call
    assert lock_call < rollback.index("sudo systemctl stop server-draft-worker.path")
    assert lock_call < rollback.index("sudo rm -rf -- /var/lib/openvpn-web/server-drafts")

    trace = tmp_path / "rollback-parent-lock.trace"
    mode_state = tmp_path / "parent-mode"
    mode_state.write_text("1770", encoding="utf-8")
    script = f'''set -euo pipefail
TRACE="$1"
MODE_STATE="$2"
DRAFT_PARENT=/var/lib/openvpn-web
sudo() {{
  printf '%s\\n' "$*" >> "$TRACE"
  case "$*" in
    "test -L "*) return 1 ;;
    "test -d "*) return 0 ;;
    "readlink -e -- "*) printf '%s\\n' "${{*:4}}" ;;
    "stat -c %U:%G:%a -- /var"|"stat -c %U:%G:%a -- /var/lib") printf '%s\\n' root:root:755 ;;
    "stat -c %U:%G:%a -- /var/lib/openvpn-web") printf 'root:openvpn-web:%s\\n' "$(<"$MODE_STATE")" ;;
    "chown root:openvpn-web /var/lib/openvpn-web") ;;
    "chmod 1750 /var/lib/openvpn-web") printf 1750 > "$MODE_STATE" ;;
    *) return 99 ;;
  esac
}}
lock_draft_parent_for_restore() {{
{function_text}
}}
lock_draft_parent_for_restore
'''

    result = subprocess.run(
        [bash, "-c", script, "rollback-lock", trace.as_posix(), mode_state.as_posix()],
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    calls = trace.read_text(encoding="utf-8").splitlines()
    chown_index = calls.index("chown root:openvpn-web /var/lib/openvpn-web")
    for root_path in ("/var", "/var/lib"):
        assert calls.index(f"test -L {root_path}") < chown_index
        assert calls.index(f"readlink -e -- {root_path}") < chown_index
        assert calls.index(f"stat -c %U:%G:%a -- {root_path}") < chown_index
    assert calls[chown_index + 1] == "chmod 1750 /var/lib/openvpn-web"
    assert calls[-1] == "stat -c %U:%G:%a -- /var/lib/openvpn-web"
    assert mode_state.read_text(encoding="utf-8") == "1750"


def test_worker_handoff_rollback_restores_enablement_and_preserved_metadata():
    deployment = Path("docs/DEPLOYMENT.md").read_text(encoding="utf-8")
    handoff = deployment.split("## SSH Server Draft Worker Handoff and Rollback", 1)[1].split(
        "## Network Observer Setup", 1
    )[0]
    backup, rollback = handoff.split("### Rollback", 1)

    assert (
        "backup_asset server-draft-worker.path.wants -L "
        "/etc/systemd/system/multi-user.target.wants/server-draft-worker.path"
    ) in backup
    assert "draft_worker_path_was_active=inactive" in backup
    assert "draft_worker_path_was_active=active" in backup
    assert "printf 'server-draft-worker.path.active=%s\\n'" in backup
    assert 'sudo cp --archive --preserve=all --' in backup
    assert 'sudo cp --archive --preserve=all --' in rollback
    assert 'asset_state server-draft-worker.path.wants -L ' in rollback
    assert 'restore_asset "$worker_path_wants_state"' in rollback
    assert 'sudo systemctl start server-draft-worker.path' in rollback
    assert 'sudo install -m "$mode" "$source_path" "$target_path"' not in rollback

    for metadata_option in ("--acls", "--xattrs", "--selinux", "--numeric-owner", "--no-recursion"):
        assert metadata_option in backup
        assert metadata_option in rollback
    assert "var/lib/openvpn-web/" in rollback


def test_worker_handoff_constrains_the_prior_wants_symlink_target():
    deployment = Path("docs/DEPLOYMENT.md").read_text(encoding="utf-8")
    handoff = deployment.split("## SSH Server Draft Worker Handoff and Rollback", 1)[1].split(
        "## Network Observer Setup", 1
    )[0]

    assert 'readlink -- "$DRAFT_PATH_WANTS"' in handoff
    assert '"../server-draft-worker.path"' in handoff
    assert "refusing an unexpected draft-worker path enablement symlink" in handoff


def test_bash_test_l_detects_a_real_directory_symlink(tmp_path):
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is unavailable on this platform")

    backup_root = tmp_path / "openvpn-web-server-drafts-backup-20260720120000"
    target = tmp_path / "real-backup"
    target.mkdir()
    try:
        backup_root.symlink_to(target, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlinks are unavailable on this platform: {exc}")
    assert backup_root.is_symlink()

    result = subprocess.run(
        [bash, "-c", 'test -L "$1"', "test-L", backup_root.as_posix()],
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0


def test_bash_mkdir_without_p_rejects_reusing_an_existing_backup_root(tmp_path):
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is unavailable on this platform")

    backup_root = tmp_path / "openvpn-web-server-drafts-backup-20260720120000"
    result = subprocess.run(
        [
            bash,
            "-c",
            (
                'path="$1"; '
                'if command -v cygpath >/dev/null 2>&1 && [[ "$path" == ?:/* ]]; '
                'then path="$(cygpath -u "$path")"; fi; '
                'mkdir --mode=0700 -- "$path" || exit 77; '
                '! mkdir --mode=0700 -- "$path"'
            ),
            "exclusive-mkdir",
            backup_root.as_posix(),
        ],
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
    )

    if result.returncode == 77:
        pytest.skip("this platform cannot apply mode 0700 through bash mkdir")
    assert result.returncode == 0, result.stderr
    assert backup_root.is_dir()


def test_documented_draft_worker_shell_blocks_parse():
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is unavailable on this platform")

    deployment = Path("docs/DEPLOYMENT.md").read_text(encoding="utf-8")
    handoff = deployment.split("## SSH Server Draft Worker Handoff and Rollback", 1)[1].split(
        "## Network Observer Setup", 1
    )[0]
    blocks = re.findall(r"```bash\n(.*?)\n```", handoff, flags=re.DOTALL)
    assert len(blocks) == 4

    for block in blocks:
        result = subprocess.run(
            [bash, "-n"],
            input=block,
            text=True,
            capture_output=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
