from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1] / "deploy" / "alt-linux"


def test_collector_waits_for_normal_browser_close_and_streams_full_profile() -> None:
    content = (ROOT / "migrations" / "collect-yandex-profile.sh").read_text(encoding="utf-8")

    assert "StrictHostKeyChecking=yes" in content
    assert "ControlMaster=auto" in content
    assert "trap cleanup EXIT" in content
    assert "Browser is still running" in content
    assert "sleep 2" in content
    assert "kill " not in content
    assert "tar -C \"$home/.config\"" in content
    assert "SingletonLock" in content
    assert "zstd" in content
    assert "SHA256SUMS" in content
    assert "READY" in content


def test_restore_uses_fixed_playbook_and_atomic_profile_replacement() -> None:
    launcher = (ROOT / "migrations" / "restore-yandex-profile.py").read_text(encoding="utf-8")
    role = (ROOT / "ansible" / "roles" / "yandex_profile_restore" / "tasks" / "main.yml").read_text(encoding="utf-8")

    assert "yandex-profile-restore.yml" in launcher
    assert "READY" in launcher
    assert "migration_id" in launcher
    assert "target_user" in launcher
    assert "sha256sum" in role
    assert "pre-migration-" in role
    assert "ansible.builtin.tempfile" in role
    assert "mv" in role
    assert "SingletonLock" in role
    assert "pkill" not in role


def test_controller_installer_publishes_private_migration_tools() -> None:
    installer = (ROOT / "install-control-plane-lib.sh").read_text(encoding="utf-8")

    assert '"${ALT_ROOT}/migrations/collect-yandex-profile.sh"' in installer
    assert '"${ALT_ROOT}/migrations/restore-yandex-profile.py"' in installer
    assert '"${state_root}/migrations/yandex"' in installer
    assert "collect-yandex-profile" in installer
    assert "restore-yandex-profile" in installer
