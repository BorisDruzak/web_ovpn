from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1] / "deploy" / "alt-linux"


def test_collector_waits_for_normal_browser_close_and_streams_full_profile() -> None:
    content = (ROOT / "migrations" / "collect-yandex-profile.sh").read_text(encoding="utf-8")

    assert "StrictHostKeyChecking=yes" in content
    assert "ControlMaster=auto" in content
    assert "trap cleanup EXIT" in content
    assert "Browser is running on source" in content
    assert "Press Enter to close it" in content
    assert "pkill -TERM" in content
    assert "-KILL" not in content
    assert "tar -C \"$home/.config\"" in content
    assert "SingletonLock" in content
    assert "zstd" in content
    assert "SHA256SUMS" in content
    assert "READY" in content
    assert "--transport-user" in content
    assert "sudo -n tar" in content
    assert "sha256sum profile.tar.zst > SHA256SUMS" in content


def test_restore_uses_fixed_playbook_and_atomic_profile_replacement() -> None:
    launcher = (ROOT / "migrations" / "restore-yandex-profile.py").read_text(encoding="utf-8")
    role = (ROOT / "ansible" / "roles" / "yandex_profile_restore" / "tasks" / "main.yml").read_text(encoding="utf-8")

    assert "yandex-profile-restore.yml" in launcher
    assert "READY" in launcher
    assert "migration_id" in launcher
    assert "target_user" in launcher
    assert '"-u", "ansible"' in launcher
    assert "/home/altserver/.ssh/id_ed25519" in launcher
    assert "known_hosts_autoinstall" in launcher
    assert "sha256sum" in role
    assert "pre-migration-" in role
    assert "ansible.builtin.tempfile" in role
    assert "mv" in role
    assert "SingletonLock" in role
    assert "pkill -TERM" in role
    assert "-KILL" not in role


def test_combined_launcher_collects_and_restores_without_manual_migration_id() -> None:
    launcher = (ROOT / "migrations" / "migrate-yandex-profile.py").read_text(encoding="utf-8")

    assert "collect-yandex-profile" in launcher
    assert "restore-yandex-profile" in launcher
    assert "Migration is ready:" in launcher
    assert "--migration-id" in launcher
    assert "--source-host" in launcher
    assert "--target-user" in launcher


def test_controller_installer_publishes_private_migration_tools() -> None:
    installer = (ROOT / "install-control-plane-lib.sh").read_text(encoding="utf-8")

    assert '"${ALT_ROOT}/migrations/collect-yandex-profile.sh"' in installer
    assert '"${ALT_ROOT}/migrations/restore-yandex-profile.py"' in installer
    assert '"${ALT_ROOT}/migrations/migrate-yandex-profile.py"' in installer
    assert '"${state_root}/migrations/yandex"' in installer
    assert "collect-yandex-profile" in installer
    assert "restore-yandex-profile" in installer
    assert "migrate-yandex-profile" in installer
