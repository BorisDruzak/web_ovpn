from __future__ import annotations

import json
import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
ISO_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "iso"
INSPECTOR = ISO_ROOT / "inspect-upstream-iso.sh"
MANIFEST = ISO_ROOT / "manifests" / "alt-kworkstation-11.4-install-x86_64.json"
AGENT_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "install-agent"
AGENT = AGENT_ROOT / "spike-agent"
CMDLINE = AGENT_ROOT / "lib" / "cmdline.sh"
INVENTORY = AGENT_ROOT / "lib" / "inventory.sh"


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
