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
NETWORK = AGENT_ROOT / "lib" / "network.sh"
DHCP_HOOK = AGENT_ROOT / "lib" / "dhcp-hook.sh"
UI = AGENT_ROOT / "lib" / "ui.sh"
SPIKE_SERVER_ROOT = AGENT_ROOT / "spike-server"
SPIKE_SERVER = SPIKE_SERVER_ROOT / "server.py"
SPIKE_CTL = SPIKE_SERVER_ROOT / "ctl.py"
BUILDER = ISO_ROOT / "build-spike-iso.sh"
VERIFIER = ISO_ROOT / "verify-spike-iso.sh"
NETWORK_GATE = (
    ISO_ROOT
    / "initrd-overlay"
    / "lib"
    / "initrd"
    / "post"
    / "network-up"
    / "99-sosnadmin-spike"
)
GRUB_PATCH = ISO_ROOT / "boot-menu" / "grub.cfg.patch"
ISOLINUX_PATCH = ISO_ROOT / "boot-menu" / "isolinux.cfg.patch"
INITRD_OVERLAY = ISO_ROOT / "initrd-overlay" / "usr" / "libexec" / "sosnadmin-install-spike"
QEMU_HARNESS = REPO_ROOT / "deploy" / "alt-linux" / "qemu" / "run-spike-readonly-acceptance.sh"
SPIKE_DOC = REPO_ROOT / "docs" / "ALT_MANAGED_ISO_TECHNICAL_SPIKE.md"


def test_inspector_pins_all_artifacts_and_uses_read_only_tools() -> None:
    text = INSPECTOR.read_text(encoding="utf-8")

    for token in (
        "boot/initrd.img",
        "boot/grub/grub.cfg",
        "syslinux/isolinux.cfg",
        "etc/rc.d/rc",
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
        "runlevel_dispatcher_sha256",
    ):
        assert re.fullmatch(r"[0-9a-f]{64}", manifest[key])

    assert manifest["initrd_path"] == "/boot/initrd.img"
    assert manifest["grub_cfg_path"] == "/boot/grub/grub.cfg"
    assert manifest["isolinux_cfg_path"] == "/syslinux/isolinux.cfg"
    assert manifest["runlevel_dispatcher_path"] == "/etc/rc.d/rc"


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
    network = NETWORK.read_text(encoding="utf-8")
    dhcp_hook = DHCP_HOOK.read_text(encoding="utf-8")

    assert "http://192.168.100.17:18089" in cmdline
    assert "eval" not in cmdline
    assert "sanitize_json_string" in inventory
    assert "findmnt -n -o SOURCE,FSTYPE,OPTIONS /image" in inventory
    assert '"limits"' not in inventory
    assert "udhcpc -n -q -T 3 -t 3" in network
    assert "dhcp_configure" in network
    assert '"$interface" != "lo"' in network
    assert "while :; do" in network
    assert 'dhcp-hook.sh' in network
    assert 'ip -4 addr replace' in dhcp_hook
    assert 'ip -4 route replace default via' in dhcp_hook
    assert "/usr/lib/network/udhcpc4.script" not in network


def test_status_ui_does_not_pause_the_early_agent() -> None:
    ui = UI.read_text(encoding="utf-8")

    assert "--infobox" in ui
    assert "--msgbox" not in ui


def test_spike_repository_transitions_are_private_and_idempotent(
    tmp_path: Path,
) -> None:
    sys.path.insert(0, str(SPIKE_SERVER_ROOT))
    try:
        from repository import SpikeRepository
    finally:
        sys.path.pop(0)

    repository = SpikeRepository(tmp_path)
    inventory = {
        "machine": {
            "uuid": "test",
            "manufacturer": "QEMU",
            "product_name": "Standard PC",
            "memory_kib": "1024",
            "boot_id": "boot",
        },
        "boot_media": "",
        "build_id": "pr1",
    }
    session = repository.create_session(inventory, "192.0.2.1")

    assert session.startswith("spike-")
    assert repository.decision(session) == "waiting"
    assert repository.approve(session) == "approved"
    assert repository.approve(session) == "approved"
    assert repository.cancel(session) == "approved"
    repository.report_state(session, "waiting_for_approval")
    repository.report_state(session, "spike_approved")
    repository.report_state(session, "spike_approved")
    assert repository.states(session) == [
        "waiting_for_approval",
        "spike_approved",
        "spike_approved",
    ]
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
    assert "self._empty(HTTPStatus.NO_CONTENT)" in server
    assert "approve" in ctl and "cancel" in ctl and "list" in ctl


def test_initrd_gate_runs_after_network_and_before_bootchain() -> None:
    gate = NETWORK_GATE.read_text(encoding="utf-8")
    builder = BUILDER.read_text(encoding="utf-8")

    assert "sosnadmin.mode=spike" in gate
    assert "exec /usr/libexec/sosnadmin-install-spike" in gate
    assert "post/network-up/99-sosnadmin-spike" in builder
    assert "--force" in builder
    assert "xorriso" in builder
    assert "gzip -n" in builder
    assert "--owner=0:0" in builder
    assert "patch --fuzz=0" in builder
    assert 'bash "$root/inspect-upstream-iso.sh"' in builder


def test_boot_menu_patches_default_to_disk_and_keep_spike_safe() -> None:
    grub = GRUB_PATCH.read_text(encoding="utf-8")
    isolinux = ISOLINUX_PATCH.read_text(encoding="utf-8")

    assert "set timeout=10" in grub
    assert "\n+set GRUB_TERMINAL=" not in grub
    assert "/EFI/altlinux/shimx64.efi" in grub
    assert "/EFI/Microsoft/Boot/bootmgfw.efi" in grub
    assert "/EFI/BOOT/BOOTX64.EFI" not in grub
    assert "sosnadmin.mode=spike" in grub
    assert "console=ttyS0,115200" in grub
    assert "--hotkey 's'" in grub
    assert " ai " not in grub
    assert "default harddisk" in isolinux
    assert "sosnadmin.mode=spike" not in isolinux
    assert "console=ttyS0,115200" not in isolinux
    assert " ai " not in isolinux


def test_boot_menu_patches_are_valid_unified_diffs() -> None:
    """The build must fail before ISO replay if a menu patch is malformed."""
    for patch_path in (
        GRUB_PATCH,
        ISOLINUX_PATCH,
    ):
        _synthetic_preimage(patch_path.read_text(encoding="utf-8"))

    assert (
        "     set color_highlight=black/white\n   fi\n fi\n+if [ \"$grub_platform\" = \"efi\" ]"
        in GRUB_PATCH.read_text(encoding="utf-8")
    )


def test_verifier_and_overlay_enforce_the_spike_contract() -> None:
    verifier = VERIFIER.read_text(encoding="utf-8")

    assert INITRD_OVERLAY.read_text(encoding="utf-8") == AGENT.read_text(
        encoding="utf-8"
    )
    for token in (
        "--iso",
        "set timeout=10",
        "Sosnadmin managed installation [SPIKE]",
        "default harddisk",
        "default harddisk",
    ):
        assert token in verifier
    for token in (
        "boot/initrd.img",
        "gzip -dc",
        "cpio -id",
        "99-sosnadmin-spike",
        "sosnadmin-install-spike",
        "runlevel_dispatcher_sha256",
        "build-manifest.json",
    ):
        assert token in verifier


def test_qemu_harness_keeps_target_read_only_and_records_safety_evidence() -> None:
    text = QEMU_HARNESS.read_text(encoding="utf-8")

    for token in (
        "readonly=on",
        "query-blockstats",
        "target.before.sha256",
        "target.after.sha256",
        "session.waiting.json",
        "session.approved.json",
        "send-key",
        "net=192.168.100.0/24",
        "host=192.168.100.17",
        "dhcpstart=192.168.100.50",
        "guest-console.log",
        '-vnc "unix:$vnc_socket"',
        "--fixture-state",
        "session.json",
        "two spike_approved heartbeats",
        "timeout after ten seconds",
        'block.get("device") != "target"',
    ):
        assert token in text


def test_builder_has_space_guard_and_writes_iso_integrity_record() -> None:
    builder = BUILDER.read_text(encoding="utf-8")

    assert "df -Pk" in builder
    assert "source_size + 512 * 1024 * 1024" in builder
    assert ".build-manifest.json" in builder


def test_technical_spike_documentation_states_manual_no_write_scope() -> None:
    text = SPIKE_DOC.read_text(encoding="utf-8")

    for phrase in ("no write I/O", "read-only", "18089", "does not start Alterator"):
        assert phrase in text


def _synthetic_preimage(diff: str) -> str:
    """Validate unified-diff hunk counts without requiring POSIX tools on Windows."""
    old_count = new_count = 0
    expected_old = expected_new = None
    in_hunk = False
    for line in diff.splitlines():
        match = re.match(r"@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@", line)
        if match:
            if expected_old is not None:
                assert (old_count, new_count) == (expected_old, expected_new)
            expected_old = int(match.group(1) or "1")
            expected_new = int(match.group(2) or "1")
            old_count = new_count = 0
            in_hunk = True
            continue
        if not in_hunk:
            continue
        if line.startswith(" "):
            old_count += 1
            new_count += 1
        elif line.startswith("-"):
            old_count += 1
        elif line.startswith("+"):
            new_count += 1
    assert expected_old is not None
    assert (old_count, new_count) == (expected_old, expected_new)
    return diff
