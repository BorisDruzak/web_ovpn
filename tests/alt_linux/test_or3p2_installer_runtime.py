from __future__ import annotations

import stat
from pathlib import Path

from support.installer_sandbox import (
    ALT_ROOT,
    InstallerSandbox,
)


def test_installer_publishes_helper_and_preserves_archives(
    tmp_path: Path,
) -> None:
    sandbox = InstallerSandbox.create(tmp_path)
    archive = sandbox.destination(
        "/var/lib/alt-deploy/machine-archives/"
        "archive-20260721T120000Z-11111111"
    )
    records = archive / "records"
    records.mkdir(parents=True)
    sentinels = {
        archive / "manifest.json": b'{"sentinel":"manifest"}\n',
        archive / "commit.json": b'{"sentinel":"commit"}\n',
        records / "ready.json": b"sentinel archived bytes\n",
    }
    for path, content in sentinels.items():
        path.write_bytes(content)
    before = {
        str(path.relative_to(archive)): path.read_bytes()
        for path in archive.rglob("*")
        if path.is_file()
    }

    result = sandbox.run_library()

    assert result.returncode == 0, result.stderr
    assert sandbox.destination(
        "/srv/alt-deploy/bootstrap/alt-bootstrap-register"
    ).read_bytes() == (
        ALT_ROOT / "bootstrap" / "alt-bootstrap-register"
    ).read_bytes()
    after = {
        str(path.relative_to(archive)): path.read_bytes()
        for path in archive.rglob("*")
        if path.is_file()
    }
    assert after == before


def test_installer_creates_private_archive_roots_and_lock(
    tmp_path: Path,
) -> None:
    sandbox = InstallerSandbox.create(tmp_path)

    result = sandbox.run_library()

    assert result.returncode == 0, result.stderr
    for absolute in (
        "/var/lib/alt-deploy/machine-archives",
        "/var/lib/alt-deploy/machine-archives/.transactions",
    ):
        path = sandbox.destination(absolute)
        assert path.is_dir()
        assert stat.S_IMODE(path.stat().st_mode) == 0o700
    lock_path = sandbox.destination(
        "/var/lib/alt-deploy/workstationctl.lock"
    )
    assert lock_path.is_file()
    assert stat.S_IMODE(lock_path.stat().st_mode) == 0o600


def test_installer_source_validates_and_publishes_helper() -> None:
    source = (
        ALT_ROOT / "install-control-plane-lib.sh"
    ).read_text(encoding="utf-8")

    assert '"${ALT_ROOT}/bootstrap/alt-bootstrap-register"' in source
    assert 'bash -n "${ALT_ROOT}/bootstrap/alt-bootstrap-register"' in source
    assert '"${bootstrap_root}/alt-bootstrap-register"' in source
    assert '"${state_root}/machine-archives/.transactions"' in source
    assert 'lock_file="${state_root}/workstationctl.lock"' in source


def test_installed_units_allow_only_required_lifecycle_roots(
    tmp_path: Path,
) -> None:
    sandbox = InstallerSandbox.create(tmp_path)

    result = sandbox.run_library()

    assert result.returncode == 0, result.stderr
    for unit in (
        "alt-deploy-register.service",
        "alt-deploy-process.service",
    ):
        text = sandbox.destination(
            f"/etc/systemd/system/{unit}"
        ).read_text(encoding="utf-8")
        assert "Environment=PYTHONPATH=/opt/alt-deploy-control" in text
        assert "ReadWritePaths=/var/lib/alt-deploy" in text
        assert "User=altserver" in text
        assert "Group=altserver" in text
        assert "ProtectSystem=strict" in text
