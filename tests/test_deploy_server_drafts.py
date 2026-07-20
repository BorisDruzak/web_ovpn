from pathlib import Path


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
        'sudo test -L -- "$BACKUP_ROOT"',
        'sudo readlink -e -- "$BACKUP_ROOT"',
        'sudo test -d "$BACKUP_ROOT"',
        'sudo test -f "$rollback_manifest"',
        'asset_state server-draft-worker.service -f "$BACKUP_ROOT/server-draft-worker.service"',
        'asset_state server-draft-worker.path -f "$BACKUP_ROOT/server-draft-worker.path"',
        'asset_state server-drafts -d "$BACKUP_ROOT/server-drafts"',
    ):
        assert validation in handoff

    first_mutation = handoff.index("sudo systemctl stop server-draft-worker.path")
    for source_check in (
        'asset_state server-draft-worker.service -f "$BACKUP_ROOT/server-draft-worker.service"',
        'asset_state server-draft-worker.path -f "$BACKUP_ROOT/server-draft-worker.path"',
        'asset_state server-drafts -d "$BACKUP_ROOT/server-drafts"',
    ):
        assert handoff.index(source_check) < first_mutation

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
    assert 'sudo test -L -- "$BACKUP_ROOT"' in rollback
    assert rollback.index('sudo test -L -- "$BACKUP_ROOT"') < rollback.index(
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
