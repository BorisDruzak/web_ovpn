from __future__ import annotations

import io
import os
import secrets
import shutil
import subprocess
import tarfile
from pathlib import Path

from alt_deploy_backup.archive import ArchiveEngine
from alt_deploy_backup.components import ComponentSpec, component_specs
from support.backup_sandbox import BackupSandbox as BaseBackupSandbox


class BackupSandbox(BaseBackupSandbox):
    @classmethod
    def create(cls, tmp_path: Path) -> "BackupSandbox":
        base = BaseBackupSandbox.create(tmp_path)
        sandbox = cls(
            root=base.root,
            fake_bin=base.fake_bin,
            command_log_path=base.command_log_path,
            systemd_state_path=base.systemd_state_path,
            settings=base.settings,
        )
        sandbox._install_archive_tools()
        sandbox.tmp_bundle.mkdir(mode=0o700)
        return sandbox

    @property
    def tmp_bundle(self) -> Path:
        return self.root / "tmp-bundle"

    def _install_archive_tools(self) -> None:
        for name in ("tar", "zstd"):
            executable = shutil.which(name)
            if executable is None:
                raise RuntimeError(f"Required test command is missing: {name}")
            wrapper = self.fake_bin / name
            wrapper.write_text(
                "#!/bin/sh\n"
                f"exec {executable} \"$@\"\n",
                encoding="utf-8",
            )
            wrapper.chmod(0o755)

    def archive_engine(self) -> ArchiveEngine:
        return ArchiveEngine(self.settings)

    def _spec(self, name: str) -> ComponentSpec:
        return next(
            spec
            for spec in component_specs(self.settings)
            if spec.name == name
        )

    def runtime_spec(self) -> ComponentSpec:
        return self._spec("runtime")

    def ansible_spec(self) -> ComponentSpec:
        return self._spec("ansible")

    def seed_ansible_tree(self, *, vault_bytes: bytes) -> None:
        playbook = self.settings.ansible_root / "playbooks" / "site.yml"
        role = self.settings.ansible_root / "roles" / "fixture" / "tasks" / "main.yml"
        for path, content in (
            (playbook, b"---\n- hosts: all\n"),
            (role, b"---\n- debug: msg=fixture\n"),
            (self.settings.vault_file, vault_bytes),
        ):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
            path.chmod(0o600 if path == self.settings.vault_file else 0o640)

    def seed_runtime_tree(self, *, include_api: bool = True) -> None:
        package = self.settings.runtime_control_root / "alt_deploy" / "__init__.py"
        package.parent.mkdir(parents=True, exist_ok=True)
        package.write_text("VERSION = 'fixture'\n", encoding="utf-8")
        package.chmod(0o644)
        if include_api:
            api = self.settings.runtime_api_root / "register_api.py"
            api.parent.mkdir(parents=True, exist_ok=True)
            api.write_text("print('fixture')\n", encoding="utf-8")
            api.chmod(0o755)
        for path in (
            self.settings.workstationctl_path,
            self.settings.worker_path,
            self.settings.stage_helper_path,
        ):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            path.chmod(0o755)

    @staticmethod
    def _add_member(
        archive: tarfile.TarFile,
        *,
        name: str,
        member_type: str,
        link_name: str,
        data: bytes,
        mode: int,
    ) -> None:
        info = tarfile.TarInfo(name)
        info.mode = mode
        info.uid = os.getuid()
        info.gid = os.getgid()
        if member_type == "regular":
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
            return
        if member_type == "symlink":
            info.type = tarfile.SYMTYPE
        elif member_type == "hardlink":
            info.type = tarfile.LNKTYPE
        elif member_type == "fifo":
            info.type = tarfile.FIFOTYPE
        elif member_type == "directory":
            info.type = tarfile.DIRTYPE
        else:
            raise ValueError(f"Unsupported member type: {member_type}")
        info.size = 0
        info.linkname = link_name
        archive.addfile(info)

    def _compress_tar(self, tar_path: Path) -> Path:
        destination = tar_path.with_suffix(tar_path.suffix + ".zst")
        result = subprocess.run(
            [
                str(self.settings.zstd_path),
                "-q",
                "-f",
                str(tar_path),
                "-o",
                str(destination),
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr)
        tar_path.unlink()
        destination.chmod(0o600)
        return destination

    def make_tar_zst(
        self,
        *,
        member_name: str,
        link_name: str = "",
        member_type: str = "regular",
        duplicate: bool = False,
    ) -> Path:
        tar_path = self.tmp_bundle / (
            f"malicious-{secrets.token_hex(4)}.tar"
        )
        with tarfile.open(tar_path, "w") as archive:
            self._add_member(
                archive,
                name=member_name,
                member_type=member_type,
                link_name=link_name,
                data=b"fixture\n",
                mode=0o644,
            )
            if duplicate:
                self._add_member(
                    archive,
                    name=member_name,
                    member_type=member_type,
                    link_name=link_name,
                    data=b"duplicate\n",
                    mode=0o644,
                )
        return self._compress_tar(tar_path)

    def make_safe_runtime_archive(self, *, mode: int) -> Path:
        tar_path = self.tmp_bundle / (
            f"safe-runtime-{secrets.token_hex(4)}.tar"
        )
        with tarfile.open(tar_path, "w") as archive:
            for directory in ("runtime", "runtime/opt"):
                self._add_member(
                    archive,
                    name=directory,
                    member_type="directory",
                    link_name="",
                    data=b"",
                    mode=0o755,
                )
            self._add_member(
                archive,
                name="runtime/opt/tool",
                member_type="regular",
                link_name="",
                data=b"fixture-tool\n",
                mode=mode,
            )
            self._add_member(
                archive,
                name="runtime/opt/tool-link",
                member_type="symlink",
                link_name="tool",
                data=b"",
                mode=0o777,
            )
        return self._compress_tar(tar_path)

    def decompress_archive(self, archive: Path) -> bytes:
        result = subprocess.run(
            [str(self.settings.zstd_path), "-d", "-q", "-c", str(archive)],
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError("Unable to decompress archive fixture")
        return result.stdout
