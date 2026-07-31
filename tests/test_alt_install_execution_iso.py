from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import sys

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
ISO_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "iso" / "agent-v2"
BUILDER = ISO_ROOT / "build-managed-iso.sh"
VERIFIER = ISO_ROOT / "verify-managed-iso.sh"
GRUB_PATCH = ISO_ROOT / "boot-menu" / "grub.cfg.patch"
ISOLINUX_PATCH = ISO_ROOT / "boot-menu" / "isolinux.cfg.patch"
VERIFY_CONTRACT = ISO_ROOT / "verify-contract.py"
PUBLISH_LIBRARY = ISO_ROOT / "lib" / "publish.sh"
GATE = (
    ISO_ROOT
    / "initrd-overlay"
    / "lib"
    / "initrd"
    / "post"
    / "network-up"
    / "99-alt-install-execution-v2"
)
V1_ISO_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "iso" / "agent-v1"
RELEASE_BUILDER = (
    REPO_ROOT
    / "deploy"
    / "alt-linux"
    / "release"
    / "build-managed-iso-release.sh"
)


def _bash() -> Path:
    candidates = (
        Path(r"C:\Program Files\Git\bin\bash.exe"),
        Path(r"C:\Program Files\Git\usr\bin\bash.exe"),
        Path("/bin/bash"),
    )
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise AssertionError("bash is required for the managed ISO contract tests")


def _original_file_from_patch(patch: Path) -> str:
    """Reconstruct the original hunk ranges so patch(1) exercises the diff."""
    lines = patch.read_text(encoding="utf-8").splitlines()
    original: dict[int, str] = {1: "set default=harddisk"}
    original_line = 0
    in_hunk = False
    for line in lines:
        match = re.match(r"^@@ -([0-9]+)(?:,[0-9]+)? \+", line)
        if match:
            original_line = int(match.group(1))
            in_hunk = True
            continue
        if not in_hunk or line.startswith("\\"):
            continue
        if line.startswith((" ", "-")):
            value = line[1:]
            previous = original.get(original_line)
            if previous is not None and previous != value:
                raise AssertionError(
                    f"overlapping patch hunks disagree at line {original_line}"
                )
            original[original_line] = value
            original_line += 1
        elif not line.startswith("+"):
            in_hunk = False
    if patch.name == "grub.cfg.patch" and 84 not in original:
        # The exact upstream file closes its BIOS-only hard-disk menu block
        # between the second and third diff hunks. Preserve that real scope in
        # the compact reconstructed fixture.
        original[84] = "fi"
    maximum = max(original)
    return "\n".join(
        original.get(number, f"# untouched upstream line {number}")
        for number in range(1, maximum + 1)
    ) + "\n"


def _apply_menu_patches(
    fixture: Path, grub_patch: Path, isolinux_patch: Path
) -> Path:
    grub = fixture / "boot" / "grub" / "grub.cfg"
    isolinux = fixture / "syslinux" / "isolinux.cfg"
    grub.parent.mkdir(parents=True)
    isolinux.parent.mkdir(parents=True)
    grub.write_text(_original_file_from_patch(grub_patch), encoding="utf-8")
    isolinux.write_text(
        _original_file_from_patch(isolinux_patch), encoding="utf-8"
    )
    for patch in (grub_patch, isolinux_patch):
        completed = subprocess.run(
            [
                str(_bash()),
                "-lc",
                f"patch --fuzz=0 -d '{fixture.as_posix()}' -p1 "
                f"< '{patch.as_posix()}'",
            ],
            cwd=REPO_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        assert completed.returncode == 0, completed.stderr
    return fixture


def build_v2_fixture(tmp_path: Path) -> Path:
    assert BUILDER.is_file()
    assert VERIFIER.is_file()
    assert GRUB_PATCH.is_file()
    assert ISOLINUX_PATCH.is_file()
    fixture = _apply_menu_patches(
        tmp_path / "iso", GRUB_PATCH, ISOLINUX_PATCH
    )
    grub = fixture / "boot" / "grub" / "grub.cfg"
    grub.write_text(
        'set default="${saved_entry}"\n'
        + grub.read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    return fixture


def extract(fixture: Path, iso_path: str) -> str:
    return (fixture / iso_path.lstrip("/")).read_text(encoding="utf-8")


def _menu_contract_fixture(tmp_path: Path) -> dict[str, Path]:
    fixture = build_v2_fixture(tmp_path)
    grub = fixture / "boot" / "grub" / "grub.cfg"
    build_id = "release-20260729T120000Z-deadbee"
    controller = "https://192.168.100.17:18092"
    grub.write_text(
        grub.read_text(encoding="utf-8")
        .replace("__ALT_INSTALL_BUILD_ID__", build_id)
        .replace("__ALT_INSTALL_EXECUTION_CONTROLLER_URL__", controller),
        encoding="utf-8",
    )
    grub.write_text(
        grub.read_text(encoding="utf-8")
        + '\nmenuentry "Upstream installer" {\n'
        + '  linux /boot/vmlinuz systemd.unit=install2.target\n}\n',
        encoding="utf-8",
    )
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "build_id": build_id,
                "controller_url": controller,
            }
        ),
        encoding="utf-8",
    )
    v1_controller = tmp_path / "controller-url"
    v2_controller = tmp_path / "execution-controller-url"
    v1_controller.write_text(
        "http://192.168.100.17:18090\n", encoding="ascii"
    )
    v2_controller.write_text(f"{controller}\n", encoding="ascii")
    isolinux = fixture / "syslinux" / "isolinux.cfg"
    isolinux.write_text(
        isolinux.read_text(encoding="utf-8")
        + "\nlabel upstream-installer\n"
        + "  append systemd.unit=install2.target\n",
        encoding="utf-8",
    )
    return {
        "manifest": manifest,
        "grub": grub,
        "isolinux": isolinux,
        "v1_controller": v1_controller,
        "v2_controller": v2_controller,
    }


def _run_menu_contract(
    tmp_path: Path, fixture: dict[str, Path]
) -> subprocess.CompletedProcess[str]:
    if VERIFY_CONTRACT.is_file():
        command = [
            sys.executable,
            str(VERIFY_CONTRACT),
            "menu",
            "--manifest",
            str(fixture["manifest"]),
            "--grub",
            str(fixture["grub"]),
            "--isolinux",
            str(fixture["isolinux"]),
            "--v1-controller",
            str(fixture["v1_controller"]),
            "--v2-controller",
            str(fixture["v2_controller"]),
        ]
    else:
        blocks = re.findall(
            r"<<'PY'\n(.*?)\nPY",
            VERIFIER.read_text(encoding="utf-8"),
            flags=re.DOTALL,
        )
        legacy = tmp_path / "legacy-menu-contract.py"
        legacy.write_text(blocks[-1], encoding="utf-8")
        command = [
            sys.executable,
            str(legacy),
            str(fixture["manifest"]),
            str(fixture["grub"]),
            str(fixture["isolinux"]),
            str(fixture["v1_controller"]),
            str(fixture["v2_controller"]),
        ]
    return subprocess.run(
        command,
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def _move_v2_entry_outside_uefi_guard(grub: str) -> str:
    title = 'menuentry "Signed-plan installation [ROOT APPROVAL REQUIRED]"'
    start = grub.index(title)
    end = grub.index("\n}", start) + 2
    entry = grub[start:end]
    without_entry = grub[:start] + grub[end:]
    return (
        without_entry
        + '\nif [ "fixture" = "fixture" ]; then\n'
        + entry
        + "\nfi\n"
    )


def _builder_inputs(tmp_path: Path) -> dict[str, Path]:
    source = tmp_path / "alt-kworkstation-11.4-install-x86_64.iso"
    helper = tmp_path / "alt-install-helper"
    public_key = tmp_path / "controller-public-key.json"
    ca_certificate = tmp_path / "execution-ca.pem"
    source.write_bytes(b"pinned-source-fixture")
    helper.write_bytes(b"static-helper-fixture")
    public_key.write_text("{}", encoding="utf-8")
    ca_certificate.write_text(
        "-----BEGIN CERTIFICATE-----\nMAA=\n"
        "-----END CERTIFICATE-----\n",
        encoding="ascii",
    )
    return {
        "source": source,
        "helper": helper,
        "public_key": public_key,
        "ca_certificate": ca_certificate,
        "output": tmp_path / "managed.iso",
    }


def _run_builder(paths: dict[str, Path], controller_url: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            str(_bash()),
            BUILDER.as_posix(),
            "--source",
            paths["source"].as_posix(),
            "--output",
            paths["output"].as_posix(),
            "--helper",
            paths["helper"].as_posix(),
            "--public-key",
            paths["public_key"].as_posix(),
            "--ca-certificate",
            paths["ca_certificate"].as_posix(),
            "--build-id",
            "release-20260729T120000Z-deadbee",
            "--controller-url",
            controller_url,
        ],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def test_v2_iso_has_opt_in_execution_menu_and_loopback_metadata(
    tmp_path: Path,
) -> None:
    grub = extract(build_v2_fixture(tmp_path), "/boot/grub/grub.cfg")
    assert (
        'menuentry "Signed-plan installation [ROOT APPROVAL REQUIRED]"'
        in grub
    )
    assert "ai curl=http://127.0.0.1:18192" in grub
    assert "set default=harddisk" in grub
    assert "curl=http://192.168.100.17" not in grub


def test_v2_menu_is_uefi_only_non_default_and_preserves_v1(
    tmp_path: Path,
) -> None:
    v2_fixture = build_v2_fixture(tmp_path / "v2")
    v1_fixture = _apply_menu_patches(
        tmp_path / "v1",
        V1_ISO_ROOT / "boot-menu" / "grub.cfg.patch",
        V1_ISO_ROOT / "boot-menu" / "isolinux.cfg.patch",
    )
    grub = extract(v2_fixture, "/boot/grub/grub.cfg")
    isolinux = extract(v2_fixture, "/syslinux/isolinux.cfg")
    v1_grub = extract(v1_fixture, "/boot/grub/grub.cfg").replace(
        "__ALT_INSTALL_CONTROLLER_URL__", "http://192.168.100.17:18090"
    )
    entry = 'menuentry "Signed-plan installation [ROOT APPROVAL REQUIRED]"'

    assert grub.count(entry) == 1
    entry_offset = grub.index(entry)
    efi_start = grub.rfind(
        'if [ "$grub_platform" = "efi" ]; then', 0, entry_offset
    )
    efi_end = grub.find("\nfi\n", entry_offset)
    assert 0 <= efi_start < entry_offset < efi_end
    assert "sosnadmin.mode=agent-v2" in grub[entry_offset:efi_end]
    assert "systemd.unit=install2.target" in grub[entry_offset:efi_end]
    assert "automatic=method:disk,uuid:$ROOT_UUID" in grub[entry_offset:efi_end]
    assert "ip=dhcp" in grub[entry_offset:efi_end]
    assert "console=ttyS0,115200" in grub[entry_offset:efi_end]
    assert "savedefault" not in grub[entry_offset:efi_end]
    assert "Normal ALT installation" in grub
    assert 'menuentry "Signed-plan preflight [DRY RUN]"' in grub
    assert (
        "sosnadmin.mode=agent-v1 "
        "sosnadmin.controller=http://192.168.100.17:18090"
    ) in grub
    assert "Normal ALT installation" in v1_grub
    assert 'menuentry "Signed-plan preflight [DRY RUN]"' in v1_grub
    assert isolinux == extract(
        v1_fixture, "/syslinux/isolinux.cfg"
    )
    assert "default harddisk" in isolinux


def test_verifier_rejects_appended_direct_controller_curl(
    tmp_path: Path,
) -> None:
    fixture = _menu_contract_fixture(tmp_path)
    valid = _run_menu_contract(tmp_path, fixture)
    assert valid.returncode == 0, valid.stderr
    grub = fixture["grub"]
    grub.write_text(
        grub.read_text(encoding="utf-8").replace(
            "ai curl=http://127.0.0.1:18192",
            "ai curl=http://127.0.0.1:18192 "
            "curl=https://192.168.100.17:18092",
        ),
        encoding="utf-8",
    )

    tampered = _run_menu_contract(tmp_path, fixture)

    assert tampered.returncode != 0
    assert "kernel command line" in tampered.stderr


@pytest.mark.parametrize(
    ("original", "tampered"),
    [
        ("lowmem quiet", "lowmem debug quiet"),
        ("ip=dhcp console=ttyS0,115200", "ip=dhcp ip=none console=ttyS0,115200"),
        ("ip=dhcp console=ttyS0,115200", "console=ttyS0,115200 ip=dhcp"),
    ],
)
def test_verifier_rejects_noncanonical_kernel_network_tokens(
    tmp_path: Path, original: str, tampered: str
) -> None:
    fixture = _menu_contract_fixture(tmp_path)
    fixture["grub"].write_text(
        fixture["grub"].read_text(encoding="utf-8").replace(
            original, tampered
        ),
        encoding="utf-8",
    )

    completed = _run_menu_contract(tmp_path, fixture)

    assert completed.returncode != 0
    assert "kernel command line" in completed.stderr


def test_verifier_rejects_v2_entry_moved_to_an_arbitrary_if_scope(
    tmp_path: Path,
) -> None:
    fixture = _menu_contract_fixture(tmp_path)
    fixture["grub"].write_text(
        _move_v2_entry_outside_uefi_guard(
            fixture["grub"].read_text(encoding="utf-8")
        ),
        encoding="utf-8",
    )

    completed = _run_menu_contract(tmp_path, fixture)

    assert completed.returncode != 0
    assert "UEFI" in completed.stderr


def test_verifier_rejects_v2_entry_without_matching_uefi_close(
    tmp_path: Path,
) -> None:
    fixture = _menu_contract_fixture(tmp_path)
    grub = fixture["grub"].read_text(encoding="utf-8")
    entry = grub.index(
        'menuentry "Signed-plan installation [ROOT APPROVAL REQUIRED]"'
    )
    closing = grub.index("\nfi\n", entry)
    fixture["grub"].write_text(
        grub[:closing] + "\n" + grub[closing + len("\nfi\n") :],
        encoding="utf-8",
    )

    completed = _run_menu_contract(tmp_path, fixture)

    assert completed.returncode != 0
    assert "UEFI" in completed.stderr


def test_verifier_rejects_v2_entry_in_uefi_else_branch(
    tmp_path: Path,
) -> None:
    fixture = _menu_contract_fixture(tmp_path)
    grub = fixture["grub"].read_text(encoding="utf-8")
    entry = grub.index(
        'menuentry "Signed-plan installation [ROOT APPROVAL REQUIRED]"'
    )
    fixture["grub"].write_text(
        grub[:entry] + "else\n" + grub[entry:],
        encoding="utf-8",
    )

    completed = _run_menu_contract(tmp_path, fixture)

    assert completed.returncode != 0
    assert "UEFI" in completed.stderr


@pytest.mark.parametrize(
    "selector",
    [
        "set default=alt-agent-v2",
        'set default="alt-agent-v2"',
        "set default=2",
        "set default=saved",
        "default=alt-agent-v2",
        "set saved_entry=alt-agent-v2",
    ],
)
def test_verifier_rejects_every_additional_default_selector(
    tmp_path: Path, selector: str
) -> None:
    fixture = _menu_contract_fixture(tmp_path)
    fixture["grub"].write_text(
        fixture["grub"].read_text(encoding="utf-8")
        + f"\n{selector}\n",
        encoding="utf-8",
    )

    completed = _run_menu_contract(tmp_path, fixture)

    assert completed.returncode != 0
    assert "default" in completed.stderr


def test_verifier_pins_source_digest_independently_of_embedded_pair(
    tmp_path: Path,
) -> None:
    pinned = (
        "2529f98bca03a652709434a6a17cd4aac5df20c0793927abdf"
        "784e8f9388243a"
    )
    manifest = tmp_path / "manifest.json"
    source = tmp_path / "source_iso.json"
    manifest.write_text(
        json.dumps({"source_iso_sha256": pinned}), encoding="utf-8"
    )
    source.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "iso_id": "alt-kworkstation-11.4-install-x86_64",
                "iso_sha256": pinned,
            }
        ),
        encoding="utf-8",
    )
    valid = subprocess.run(
        [
            sys.executable,
            str(VERIFY_CONTRACT),
            "source",
            "--manifest",
            str(manifest),
            "--source-identity",
            str(source),
        ],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert valid.returncode == 0, valid.stderr

    redefined = "1" * 64
    manifest.write_text(
        json.dumps({"source_iso_sha256": redefined}), encoding="utf-8"
    )
    source.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "iso_id": "alt-kworkstation-11.4-install-x86_64",
                "iso_sha256": redefined,
            }
        ),
        encoding="utf-8",
    )
    tampered = subprocess.run(
        [
            sys.executable,
            str(VERIFY_CONTRACT),
            "source",
            "--manifest",
            str(manifest),
            "--source-identity",
            str(source),
        ],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert tampered.returncode != 0
    assert "pinned" in tampered.stderr


def test_verifier_rejects_unpinned_source_iso_for_delta_comparison(
    tmp_path: Path,
) -> None:
    source_iso = tmp_path / "comparison.iso"
    source_iso.write_bytes(b"crafted-comparison-iso")

    completed = subprocess.run(
        [
            sys.executable,
            str(VERIFY_CONTRACT),
            "source-iso",
            "--source",
            str(source_iso),
        ],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode != 0
    assert "source ISO digest is not pinned" in completed.stderr


@pytest.mark.parametrize(
    ("relative", "content"),
    [
        ("opt/bootstrap/controller-private.key", "secret-key-material"),
        ("root/session-credential.json", "{}"),
        ("var/lib/install/install-secret", "secret"),
        ("tmp/execution-token", "token"),
        (
            "opt/bootstrap/material.pem",
            "-----BEGIN PRIVATE KEY-----\nAAAA\n"
            "-----END PRIVATE KEY-----\n",
        ),
    ],
)
def test_verifier_scans_for_secret_like_files_outside_managed_roots(
    tmp_path: Path, relative: str, content: str
) -> None:
    root = tmp_path / "initrd"
    root.mkdir()
    valid = subprocess.run(
        [
            sys.executable,
            str(VERIFY_CONTRACT),
            "scan",
            "--root",
            str(root),
        ],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert valid.returncode == 0, valid.stderr
    leaked = root / relative
    leaked.parent.mkdir(parents=True)
    leaked.write_text(content, encoding="utf-8")

    tampered = subprocess.run(
        [
            sys.executable,
            str(VERIFY_CONTRACT),
            "scan",
            "--root",
            str(root),
        ],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert tampered.returncode != 0
    assert "secret-like" in tampered.stderr


def test_verifier_ignores_private_key_marker_in_unchanged_source_file(
    tmp_path: Path,
) -> None:
    """Only V2 changes, not pinned upstream binaries, are secret-scanned."""
    root = tmp_path / "initrd"
    source_root = tmp_path / "source-initrd"
    relative = Path("usr/lib64/libgio-2.0.so.0.8400.4")
    content = b"binary\x00-----BEGIN PRIVATE KEY-----\x00data"
    for directory in (root, source_root):
        candidate = directory / relative
        candidate.parent.mkdir(parents=True)
        candidate.write_bytes(content)

    completed = subprocess.run(
        [
            sys.executable,
            str(VERIFY_CONTRACT),
            "scan",
            "--root",
            str(root),
            "--source-root",
            str(source_root),
        ],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr


@pytest.mark.skipif(
    not hasattr(os, "mkfifo"), reason="POSIX FIFO support is required"
)
def test_verifier_ignores_unchanged_source_fifo(tmp_path: Path) -> None:
    root = tmp_path / "initrd"
    source_root = tmp_path / "source-initrd"
    for directory in (root, source_root):
        entry = directory / ".initrd" / "rdshell"
        entry.parent.mkdir(parents=True)
        os.mkfifo(entry)

    completed = subprocess.run(
        [
            sys.executable,
            str(VERIFY_CONTRACT),
            "scan",
            "--root",
            str(root),
            "--source-root",
            str(source_root),
        ],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr


def test_verifier_allows_pinned_upstream_passwd_but_rejects_injected_secret(
    tmp_path: Path,
) -> None:
    """The pinned ALT initrd's account database is not V2 payload."""
    root = tmp_path / "initrd"
    source_root = tmp_path / "source-initrd"
    passwd = root / "etc" / "passwd"
    passwd.parent.mkdir(parents=True)
    passwd.write_text("root:x:0:0:root:/root:/bin/bash\n", encoding="utf-8")
    source_passwd = source_root / "etc" / "passwd"
    source_passwd.parent.mkdir(parents=True)
    source_passwd.write_text(
        "root:x:0:0:root:/root:/bin/bash\n", encoding="utf-8"
    )

    valid = subprocess.run(
        [
            sys.executable,
            str(VERIFY_CONTRACT),
            "scan",
            "--root",
            str(root),
            "--source-root",
            str(source_root),
        ],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert valid.returncode == 0, valid.stderr
    leaked = root / "opt" / "bootstrap" / "execution-token"
    leaked.parent.mkdir(parents=True)
    leaked.write_text("token", encoding="utf-8")
    tampered = subprocess.run(
        [
            sys.executable,
            str(VERIFY_CONTRACT),
            "scan",
            "--root",
            str(root),
            "--source-root",
            str(source_root),
        ],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert tampered.returncode != 0
    assert "secret-like" in tampered.stderr


def test_verifier_scans_pinned_upstream_passwd_content_for_private_key(
    tmp_path: Path,
) -> None:
    """The filename exception must not hide a replaced account database."""
    root = tmp_path / "initrd"
    source_root = tmp_path / "source-initrd"
    passwd = root / "etc" / "passwd"
    passwd.parent.mkdir(parents=True)
    passwd.write_text(
        "-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n",
        encoding="utf-8",
    )
    source_passwd = source_root / "etc" / "passwd"
    source_passwd.parent.mkdir(parents=True)
    source_passwd.write_text(
        "root:x:0:0:root:/root:/bin/bash\n", encoding="utf-8"
    )

    completed = subprocess.run(
        [
            sys.executable,
            str(VERIFY_CONTRACT),
            "scan",
            "--root",
            str(root),
            "--source-root",
            str(source_root),
        ],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode != 0
    assert "secret-like" in completed.stderr


def test_verifier_streams_large_files_and_detects_split_private_key_marker(
    tmp_path: Path,
) -> None:
    root = tmp_path / "initrd"
    leaked = root / "opt" / "bootstrap" / "archive.bin"
    leaked.parent.mkdir(parents=True)
    marker = b"-----BEGIN OPENSSH PRIVATE KEY-----"
    prefix = b"x" * (16 * 64 * 1024 - 10)
    leaked.write_bytes(prefix + marker + b"\nsecret\n")
    assert leaked.stat().st_size > 1024 * 1024

    completed = subprocess.run(
        [
            sys.executable,
            str(VERIFY_CONTRACT),
            "scan",
            "--root",
            str(root),
        ],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode != 0
    assert "secret-like" in completed.stderr


def test_verifier_detects_long_private_key_label_across_chunk_boundary(
    tmp_path: Path,
) -> None:
    root = tmp_path / "initrd"
    leaked = root / "opt" / "bootstrap" / "archive-long-label.bin"
    leaked.parent.mkdir(parents=True)
    chunk_boundary = 16 * 64 * 1024
    preamble = b"-----BEGIN " + (b"A" * 65) + b" "
    prefix = b"x" * (chunk_boundary - len(preamble) - 8)
    leaked.write_bytes(prefix + preamble + b"PRIVATE KEY-----\nsecret\n")
    assert leaked.stat().st_size > 1024 * 1024

    completed = subprocess.run(
        [
            sys.executable,
            str(VERIFY_CONTRACT),
            "scan",
            "--root",
            str(root),
        ],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode != 0
    assert "secret-like" in completed.stderr


def test_managed_iso_publication_never_leaves_iso_without_sidecar(
    tmp_path: Path,
) -> None:
    success = tmp_path / "success"
    success.mkdir()
    staged_iso = success / "staged.iso"
    staged_sidecar = success / "staged.json"
    output = success / "managed.iso"
    sidecar = success / "managed.iso.build-manifest.json"
    staged_iso.write_bytes(b"iso")
    staged_sidecar.write_bytes(b"manifest")
    published = subprocess.run(
        [
            str(_bash()),
            "-c",
            f"source '{PUBLISH_LIBRARY.as_posix()}'; "
            f"publish_managed_iso '{staged_iso.as_posix()}' "
            f"'{staged_sidecar.as_posix()}' '{output.as_posix()}' "
            f"'{sidecar.as_posix()}'",
        ],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert published.returncode == 0, published.stderr
    assert output.read_bytes() == b"iso"
    assert sidecar.read_bytes() == b"manifest"

    failure = tmp_path / "failure"
    failure.mkdir()
    staged_iso = failure / "staged.iso"
    staged_sidecar = failure / "staged.json"
    output = failure / "managed.iso"
    sidecar = failure / "managed.iso.build-manifest.json"
    staged_iso.write_bytes(b"iso")
    staged_sidecar.write_bytes(b"manifest")
    sidecar.write_bytes(b"injected-sidecar-conflict")
    rejected = subprocess.run(
        [
            str(_bash()),
            "-c",
            f"source '{PUBLISH_LIBRARY.as_posix()}'; "
            f"publish_managed_iso '{staged_iso.as_posix()}' "
            f"'{staged_sidecar.as_posix()}' '{output.as_posix()}' "
            f"'{sidecar.as_posix()}'",
        ],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert rejected.returncode != 0
    assert not output.exists()
    assert sidecar.read_bytes() == b"injected-sidecar-conflict"


def test_v2_builder_rejects_every_controller_except_fixed_tls_endpoint(
    tmp_path: Path,
) -> None:
    paths = _builder_inputs(tmp_path)
    completed = _run_builder(paths, "http://192.168.100.17:18092")

    assert completed.returncode == 1
    assert "Controller URL is invalid" in completed.stderr
    assert not paths["output"].exists()
    assert not Path(
        f"{paths['output']}.build-manifest.json"
    ).exists()


def test_v2_builder_never_replaces_an_existing_output(
    tmp_path: Path,
) -> None:
    paths = _builder_inputs(tmp_path)
    paths["output"].write_bytes(b"immutable-release")

    completed = _run_builder(paths, "https://192.168.100.17:18092")

    assert completed.returncode == 1
    assert "Output already exists" in completed.stderr
    assert paths["output"].read_bytes() == b"immutable-release"


def test_v2_builder_never_allows_source_as_output(tmp_path: Path) -> None:
    paths = _builder_inputs(tmp_path)
    original = paths["source"].read_bytes()
    paths["output"] = paths["source"]

    completed = _run_builder(paths, "https://192.168.100.17:18092")

    assert completed.returncode == 1
    assert "Source and output paths must differ" in completed.stderr
    assert paths["source"].read_bytes() == original


def test_v2_gate_runs_only_for_the_explicit_v2_mode(tmp_path: Path) -> None:
    assert GATE.is_file()
    cmdline = tmp_path / "cmdline"
    agent = tmp_path / "agent"
    log = tmp_path / "agent.log"
    agent.write_text(
        "#!/bin/bash\nprintf 'started\\n' > \"$ALT_INSTALL_TEST_LOG\"\n",
        encoding="utf-8",
        newline="\n",
    )
    agent.chmod(0o755)
    environment = {
        "ALT_INSTALL_CMDLINE_FILE": cmdline.as_posix(),
        "ALT_INSTALL_EXECUTION_AGENT": agent.as_posix(),
        "ALT_INSTALL_TEST_LOG": log.as_posix(),
    }
    cmdline.write_text("quiet sosnadmin.mode=agent-v1\n", encoding="utf-8")
    first = subprocess.run(
        [str(_bash()), GATE.as_posix()],
        cwd=REPO_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    assert first.returncode == 0, first.stderr
    assert not log.exists()

    cmdline.write_text(
        "quiet sosnadmin.mode=agent-v2 "
        "sosnadmin.controller=https://192.168.100.17:18092\n",
        encoding="utf-8",
    )
    second = subprocess.run(
        [str(_bash()), GATE.as_posix()],
        cwd=REPO_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    assert second.returncode == 0, second.stderr
    assert log.read_text(encoding="utf-8") == "started\n"


def test_v2_iso_contract_embeds_only_public_identity_material() -> None:
    builder = BUILDER.read_text(encoding="utf-8")
    verifier = VERIFIER.read_text(encoding="utf-8")
    expected_assets = (
        "execution-ca.pem",
        "public-key.json",
        "source_iso.json",
        "execution-controller-url",
        "managed_iso_size_bytes",
        "payload.sha256",
        "alt-install-helper",
        "alt-install-agent-v2/alt-install-execution-agent",
        "usr/libexec/alt-install-agent",
    )
    for asset in expected_assets:
        assert asset in builder
        assert asset in verifier
    for script in (builder, verifier):
        assert "PRIVATE KEY" in script
        assert "password" in script.lower()
        assert "credential" in script.lower()
        assert "secret" in script.lower()
    assert "alt-install-agent-managed-iso-v2" in builder
    assert "alt-install-agent-managed-iso-v2" in verifier
    assert "Managed ISO size fixed point did not converge" in builder
    assert "sha256sum -c" in verifier
    assert "stat -c '%a'" in verifier
    assert "verify-contract.py" in verifier
    assert "publish_managed_iso" in builder


def test_release_builder_adds_v2_only_by_explicit_opt_in() -> None:
    release = RELEASE_BUILDER.read_text(encoding="utf-8")

    assert "agent_version=agent-v1" in release
    assert "--agent-version" in release
    assert "--execution-ca" in release
    assert "alt-kworkstation-11.4-agent-v1-$release_id.iso" in release
    assert "alt-kworkstation-11.4-agent-v2-$release_id.iso" in release
    assert "https://192.168.100.17:18092" in release
    assert "http://192.168.100.17:18090" in release
    assert "publish_managed_iso" in release
