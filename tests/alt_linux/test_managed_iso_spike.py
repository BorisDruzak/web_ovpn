from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
ISO_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "iso"
INSPECTOR = ISO_ROOT / "inspect-upstream-iso.sh"
MANIFEST = ISO_ROOT / "manifests" / "alt-kworkstation-11.4-install-x86_64.json"
AGENT_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "install-agent"
AGENT = AGENT_ROOT / "spike-agent"
CMDLINE = AGENT_ROOT / "lib" / "cmdline.sh"
INVENTORY = AGENT_ROOT / "lib" / "inventory.sh"
SPIKE_SERVER_ROOT = AGENT_ROOT / "spike-server"
SPIKE_SERVER = SPIKE_SERVER_ROOT / "server.py"
SPIKE_CTL = SPIKE_SERVER_ROOT / "ctl.py"
BUILDER = ISO_ROOT / "build-spike-iso.sh"
GATE_PATCH = ISO_ROOT / "initrd-patches" / "early-agent-gate.patch"
GRUB_PATCH = ISO_ROOT / "boot-menu" / "grub.cfg.patch"
ISOLINUX_PATCH = ISO_ROOT / "boot-menu" / "isolinux.cfg.patch"


def test_inspector_pins_all_artifacts_and_uses_read_only_tools() -> None:
    text = INSPECTOR.read_text(encoding="utf-8")

    for token in (
        "boot/initrd.img",
        "boot/grub/grub.cfg",
        "syslinux/isolinux.cfg",
        "etc/rc.d/rc.sysexec",
        "xorriso",
        "sha256sum",
        "gzip -dc",
        "cpio",
    ):
        assert token in text

    assert "xorriso -osirrox on" in text
    assert "-extract" in text
    assert "-delete" not in text


def test_manifest_contains_exact_non_placeholder_source_contract() -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))

    assert manifest["iso_id"] == "alt-kworkstation-11.4-install-x86_64"
    assert manifest["source_filename"] == "alt-kworkstation-11.4-install-x86_64.iso"
    assert manifest["source_size_bytes"] == 10_710_822_912
    for key in (
        "source_sha256",
        "initrd_sha256",
        "grub_cfg_sha256",
        "isolinux_cfg_sha256",
        "handoff_sha256",
    ):
        assert re.fullmatch(r"[0-9a-f]{64}", manifest[key])

    assert manifest["initrd_path"] == "/boot/initrd.img"
    assert manifest["grub_cfg_path"] == "/boot/grub/grub.cfg"
    assert manifest["isolinux_cfg_path"] == "/syslinux/isolinux.cfg"
    assert manifest["handoff_path"] == "/etc/rc.d/rc.sysexec"


def test_agent_is_fail_closed_and_does_not_reference_installer_actions() -> None:
    text = AGENT.read_text(encoding="utf-8")

    assert "spike_hold" in text
    assert "while :; do" in text
    assert "sosnadmin.mode=spike" in text
    for forbidden in (
        "alterator-autoinstall",
        "alterator-wizard",
        "sfdisk",
        "wipefs",
        "mkfs",
        "systemctl",
        "reboot",
        "poweroff",
    ):
        assert forbidden not in text


def test_agent_libraries_bound_cmdline_and_inventory_data() -> None:
    cmdline = CMDLINE.read_text(encoding="utf-8")
    inventory = INVENTORY.read_text(encoding="utf-8")

    assert "http://192.168.100.17:18089" in cmdline
    assert "eval" not in cmdline
    assert "max_interfaces=16" in inventory
    assert "max_disks=16" in inventory
    assert "sanitize_json_string" in inventory
    assert "findmnt -n -o SOURCE,FSTYPE,OPTIONS /image" in inventory


def test_spike_repository_transitions_are_private_and_idempotent(
    tmp_path: Path,
) -> None:
    sys.path.insert(0, str(SPIKE_SERVER_ROOT))
    try:
        from repository import SpikeRepository
    finally:
        sys.path.pop(0)

    repository = SpikeRepository(tmp_path)
    session = repository.create_session({"machine": {"uuid": "test"}}, "192.0.2.1")

    assert session.startswith("spike-")
    assert repository.decision(session) == "waiting"
    assert repository.approve(session) == "approved"
    assert repository.approve(session) == "approved"
    assert repository.cancel(session) == "approved"
    if os.name == "nt":
        assert "os.chmod(temporary, 0o600)" in (
            SPIKE_SERVER_ROOT / "repository.py"
        ).read_text(encoding="utf-8")
    else:
        assert (tmp_path / session / "session.json").stat().st_mode & 0o777 == 0o600


def test_spike_fixture_exposes_only_bounded_plain_text_contract() -> None:
    server = SPIKE_SERVER.read_text(encoding="utf-8")
    ctl = SPIKE_CTL.read_text(encoding="utf-8")

    assert "/spike/v1/sessions" in server
    assert "32768" in server
    assert "Content-Type" in server
    assert "text/plain" in server
    assert "approve" in ctl and "cancel" in ctl and "list" in ctl


def test_initrd_gate_precedes_exact_vendor_handoff_and_builder_is_guarded() -> None:
    patch = GATE_PATCH.read_text(encoding="utf-8")
    builder = BUILDER.read_text(encoding="utf-8")

    assert "sosnadmin.mode=spike" in patch
    assert patch.index("sosnadmin-install-spike") < patch.index(
        "exec runas /sbin/init"
    )
    assert "--force" in builder
    assert "xorriso" in builder
    assert "gzip -n" in builder
    assert "patch --fuzz=0" in builder


def test_boot_menu_patches_default_to_disk_and_keep_spike_safe() -> None:
    grub = GRUB_PATCH.read_text(encoding="utf-8")
    isolinux = ISOLINUX_PATCH.read_text(encoding="utf-8")

    assert "set timeout=5" in grub
    assert "/EFI/altlinux/shimx64.efi" in grub
    assert "/EFI/Microsoft/Boot/bootmgfw.efi" in grub
    assert "/EFI/BOOT/BOOTX64.EFI" not in grub
    assert "sosnadmin.mode=spike" in grub
    assert " ai " not in grub
    assert "default harddisk" in isolinux
    assert "sosnadmin.mode=spike" in isolinux
    assert " ai " not in isolinux
