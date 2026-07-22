from __future__ import annotations

import io
import stat
import tarfile
from pathlib import Path

import pytest

from alt_deploy_backup.errors import BackupError
from support.backup_archive_sandbox import BackupSandbox


@pytest.mark.parametrize(
    ("member_name", "link_name", "member_type"),
    [
        ("/absolute", "", "regular"),
        ("runtime/../../escape", "", "regular"),
        ("runtime/link", "/etc/shadow", "symlink"),
        ("runtime/hard", "../../outside", "hardlink"),
        ("runtime/fifo", "", "fifo"),
    ],
)
def test_archive_inspection_rejects_unsafe_members(
    tmp_path: Path,
    member_name: str,
    link_name: str,
    member_type: str,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    archive = sandbox.make_tar_zst(
        member_name=member_name,
        link_name=link_name,
        member_type=member_type,
    )

    with pytest.raises(BackupError) as error:
        sandbox.archive_engine().inspect(
            sandbox.runtime_spec(),
            archive,
        )

    assert error.value.code == "backup_integrity_failed"


def test_archive_inspection_rejects_duplicate_member_names(
    tmp_path: Path,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    archive = sandbox.make_tar_zst(
        member_name="runtime/duplicate",
        duplicate=True,
    )

    with pytest.raises(BackupError) as error:
        sandbox.archive_engine().inspect(
            sandbox.runtime_spec(),
            archive,
        )

    assert error.value.code == "backup_integrity_failed"


def test_inspection_reaps_decompressor_after_unsafe_member(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    engine = sandbox.archive_engine()
    raw_tar = io.BytesIO()
    with tarfile.open(fileobj=raw_tar, mode="w") as archive:
        info = tarfile.TarInfo("/absolute")
        info.size = len(b"fixture\n")
        archive.addfile(info, io.BytesIO(b"fixture\n"))

    class FakeProcess:
        def __init__(self, raw: bytes) -> None:
            self.stdout = io.BytesIO(raw)
            self.waited = False
            self.killed = False

        def wait(self) -> int:
            self.waited = True
            return 0

        def poll(self) -> int | None:
            return None if not self.waited else 0

        def kill(self) -> None:
            self.killed = True

    process = FakeProcess(raw_tar.getvalue())
    monkeypatch.setattr(
        engine,
        "_open_decompressor",
        lambda archive_path: (archive_path.stat().st_size, process),
    )
    archive_path = sandbox.make_tar_zst(
        member_name="runtime/placeholder",
    )

    with pytest.raises(BackupError):
        engine.inspect(sandbox.runtime_spec(), archive_path)

    assert process.waited is True


def test_ansible_archive_excludes_vault(tmp_path: Path) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    vault_bytes = b"$ANSIBLE_VAULT;1.1;AES256\nnever-archive-this\n"
    sandbox.seed_ansible_tree(vault_bytes=vault_bytes)
    destination = sandbox.tmp_bundle / "ansible.tar.zst"

    record = sandbox.archive_engine().capture(
        sandbox.ansible_spec(),
        destination,
    )
    inspection = sandbox.archive_engine().inspect(
        sandbox.ansible_spec(),
        destination,
    )

    assert record.size_bytes > 0
    assert not any(
        "vault.yml" in member.name
        for member in inspection.members
    )
    assert vault_bytes not in sandbox.decompress_archive(destination)


def test_capture_records_canonical_paths_and_absence(
    tmp_path: Path,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    sandbox.seed_runtime_tree(include_api=False)
    destination = sandbox.tmp_bundle / "runtime.tar.zst"

    record = sandbox.archive_engine().capture(
        sandbox.runtime_spec(),
        destination,
    )

    paths = {item.absolute_path: item for item in record.paths}
    assert paths["/opt/alt-deploy-control"].present is True
    assert paths["/opt/alt-deploy-api"].present is False
    assert paths["/opt/alt-deploy-api"].kind == "absent"
    assert all(
        not item.absolute_path.startswith(str(sandbox.root))
        for item in record.paths
    )


def test_capture_failure_after_rename_removes_destination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    sandbox.seed_runtime_tree()
    destination = sandbox.tmp_bundle / "runtime.tar.zst"
    engine = sandbox.archive_engine()

    def fail_digest(path: Path) -> tuple[int, str]:
        raise BackupError(
            code="backup_component_failed",
            message="Injected digest failure",
            exit_code=4,
        )

    monkeypatch.setattr(engine, "_file_digest", fail_digest)

    with pytest.raises(BackupError):
        engine.capture(sandbox.runtime_spec(), destination)

    assert not destination.exists()


def test_rehearsal_extraction_clears_setuid_and_preserves_safe_link(
    tmp_path: Path,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    archive = sandbox.make_safe_runtime_archive(mode=0o6755)
    destination = sandbox.root / "rehearsal"

    sandbox.archive_engine().extract_for_rehearsal(
        sandbox.runtime_spec(),
        archive,
        destination,
    )

    executable = destination / "runtime" / "opt" / "tool"
    link = destination / "runtime" / "opt" / "tool-link"
    assert executable.read_bytes() == b"fixture-tool\n"
    assert stat.S_IMODE(executable.stat().st_mode) & 0o6000 == 0
    assert link.is_symlink()
    assert link.readlink() == Path("tool")


def test_capture_rejects_external_source_symlink(
    tmp_path: Path,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    sandbox.seed_runtime_tree()
    outside = tmp_path / "outside"
    outside.write_text("outside", encoding="utf-8")
    escape = sandbox.settings.runtime_control_root / "escape"
    escape.symlink_to(outside)

    with pytest.raises(BackupError) as error:
        sandbox.archive_engine().capture(
            sandbox.runtime_spec(),
            sandbox.tmp_bundle / "runtime.tar.zst",
        )

    assert error.value.code in {
        "backup_source_unsafe",
        "backup_component_failed",
    }
