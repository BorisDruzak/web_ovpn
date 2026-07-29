#!/usr/bin/env python3
"""Independent safety contracts for the managed ALT execution ISO."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from typing import Any


PINNED_SOURCE_SHA256 = (
    "2529f98bca03a652709434a6a17cd4aac5df20c0793927abdf"
    "784e8f9388243a"
)
SOURCE_ID = "alt-kworkstation-11.4-install-x86_64"
V1_CONTROLLER = "http://192.168.100.17:18090"
V2_CONTROLLER = "https://192.168.100.17:18092"
V2_TITLE = 'menuentry "Signed-plan installation [ROOT APPROVAL REQUIRED]"'
V2_DECLARATION = (
    f"{V2_TITLE} --hotkey 'x' --id 'alt-agent-v2' {{"
)
UEFI_GUARD = 'if [ "$grub_platform" = "efi" ]; then'
SUSPICIOUS_NAME = re.compile(
    r"(^|[._-])"
    r"(credential|key|passwd|password|private|secret|token)"
    r"([._-]|$)"
)
ALLOWED_PUBLIC_MATERIAL = {
    "usr/share/alt-install/execution-ca.pem",
    "usr/share/alt-install/public-key.json",
}


class ContractError(ValueError):
    """A managed ISO safety contract was violated."""


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractError("JSON input is invalid") from exc
    if not isinstance(value, dict):
        raise ContractError("JSON input must be an object")
    return value


def _read_text(path: Path, encoding: str = "utf-8") -> str:
    try:
        return path.read_text(encoding=encoding)
    except (OSError, UnicodeDecodeError) as exc:
        raise ContractError(f"cannot read {path.name}") from exc


def validate_source(manifest_path: Path, source_identity_path: Path) -> None:
    manifest = _read_json(manifest_path)
    source = _read_json(source_identity_path)
    if manifest.get("source_iso_sha256") != PINNED_SOURCE_SHA256:
        raise ContractError("source ISO digest is not pinned")
    if set(source) != {"schema_version", "iso_id", "iso_sha256"}:
        raise ContractError("source ISO identity fields are invalid")
    if (
        source["schema_version"] != 1
        or source["iso_id"] != SOURCE_ID
        or source["iso_sha256"] != PINNED_SOURCE_SHA256
    ):
        raise ContractError("embedded source ISO identity is not pinned")


def _if_scope_at(
    lines: list[str], target_index: int
) -> tuple[list[tuple[str, int, str]], dict[int, int]]:
    stack: list[tuple[str, int, str]] = []
    matched_closes: dict[int, int] = {}
    target_scopes: list[tuple[str, int, str]] | None = None
    for index, raw_line in enumerate(lines):
        line = raw_line.strip()
        is_multiline_if = (
            line.startswith("if ")
            and "; then" in line
            and not line.endswith("; fi")
        )
        if is_multiline_if:
            stack.append((line, index, "then"))
        elif line == "else" or line.startswith("elif "):
            if stack:
                condition, start, _ = stack[-1]
                stack[-1] = (condition, start, "else")
        elif line == "fi":
            if stack:
                _, start, _ = stack.pop()
                matched_closes[start] = index
        if index == target_index:
            target_scopes = list(stack)
    if target_scopes is None:
        raise ContractError("V2 menu entry is missing")
    return target_scopes, matched_closes


def _entry_lines(lines: list[str], start: int) -> list[str]:
    rendered: list[str] = []
    for raw_line in lines[start:]:
        line = raw_line.strip()
        rendered.append(line)
        if line == "}":
            return rendered
    raise ContractError("V2 menu entry is unterminated")


def _default_assignments(lines: list[str]) -> list[str]:
    defaults: list[str] = []
    for raw_line in lines:
        line = raw_line.strip()
        if re.match(r"^(?:set\s+)?default(?:\s*=|\s+)", line):
            defaults.append(line)
        normalized = line.replace('"', "").replace("'", "")
        if (
            "saved_entry" in normalized
            and (
                "alt-agent-v2" in normalized
                or "Signed-plan installation" in normalized
            )
        ):
            defaults.append(line)
    return defaults


def validate_menu(
    manifest_path: Path,
    grub_path: Path,
    isolinux_path: Path,
    v1_controller_path: Path,
    v2_controller_path: Path,
) -> None:
    manifest = _read_json(manifest_path)
    build_id = manifest.get("build_id")
    controller = manifest.get("controller_url")
    if not isinstance(build_id, str) or not build_id:
        raise ContractError("build ID is invalid")
    if controller != V2_CONTROLLER:
        raise ContractError("controller URL is invalid")
    if _read_text(v1_controller_path, "ascii") != f"{V1_CONTROLLER}\n":
        raise ContractError("embedded V1 controller URL changed")
    if _read_text(v2_controller_path, "ascii") != f"{controller}\n":
        raise ContractError("embedded V2 controller URL does not match")

    grub = _read_text(grub_path)
    isolinux = _read_text(isolinux_path)
    lines = grub.splitlines()
    declarations = [
        index
        for index, line in enumerate(lines)
        if line.strip().startswith(V2_TITLE)
    ]
    if len(declarations) != 1:
        raise ContractError("V2 menu entry count is invalid")
    target_index = declarations[0]
    if lines[target_index].strip() != V2_DECLARATION:
        raise ContractError("V2 menu declaration is invalid")
    entry_lines = _entry_lines(lines, target_index)
    entry_end = target_index + len(entry_lines) - 1
    scopes, matched_closes = _if_scope_at(lines, target_index)
    if (
        len(scopes) != 1
        or scopes[0][0] != UEFI_GUARD
        or scopes[0][2] != "then"
        or matched_closes.get(scopes[0][1], -1) <= entry_end
    ):
        raise ContractError("V2 menu entry is not in its matching UEFI guard")

    expected_linux = (
        "linux /boot/vmlinuz$KFLAVOUR fastboot live $CONSOLE $SAFEMODE "
        "root=bootchain bootchain=fg,altboot stagename=live "
        "ramdisk_size=4497433 lowmem quiet splash lang=$lang "
        "ip=dhcp console=ttyS0,115200 sosnadmin.mode=agent-v2 "
        f"sosnadmin.controller={controller} "
        f"sosnadmin.build={build_id} "
        "systemd.unit=install2.target ai "
        "curl=http://127.0.0.1:18192"
    )
    expected_entry = [
        V2_DECLARATION,
        'echo "Loading root-authorized signed-plan installer ..."',
        expected_linux,
        "initrd /boot/initrd$KFLAVOUR.img",
        "}",
    ]
    if entry_lines != expected_entry:
        raise ContractError("V2 kernel command line or menu body is invalid")

    defaults = _default_assignments(lines)
    if defaults != ["set default=harddisk"]:
        raise ContractError("GRUB default selector is invalid")
    for required in (
        'menuentry "Normal ALT installation"',
        'menuentry "Signed-plan preflight [DRY RUN]"',
        "sosnadmin.mode=agent-v1 "
        f"sosnadmin.controller={V1_CONTROLLER}",
    ):
        if required not in grub:
            raise ContractError("normal or V1 menu contract changed")
    if (
        grub.count("sosnadmin.mode=agent-v2") != 1
        or grub.count("systemd.unit=install2.target") != 1
        or grub.count("curl=http://127.0.0.1:18192") != 1
        or re.search(r"(?<!ai )\bcurl=", grub)
    ):
        raise ContractError("V2 kernel command line is not canonical")
    if (
        "default harddisk" not in isolinux
        or "agent-v2" in isolinux
        or "install2.target" in isolinux
    ):
        raise ContractError("BIOS menu must remain non-execution")


def scan_secret_like_files(root: Path) -> None:
    if not root.is_dir() or root.is_symlink():
        raise ContractError("extracted initrd root is invalid")
    for path in root.rglob("*"):
        if path.is_dir() and not path.is_symlink():
            continue
        relative = path.relative_to(root).as_posix()
        if relative in ALLOWED_PUBLIC_MATERIAL:
            continue
        name = path.name.lower()
        if SUSPICIOUS_NAME.search(name):
            raise ContractError(
                f"secret-like payload filename is forbidden: {relative}"
            )
        if not path.is_file() or path.is_symlink():
            continue
        try:
            size = path.stat().st_size
        except OSError as exc:
            raise ContractError(
                f"cannot inspect extracted payload file: {relative}"
            ) from exc
        if size > 1024 * 1024:
            continue
        try:
            content = path.read_bytes().upper()
        except OSError as exc:
            raise ContractError(
                f"cannot inspect extracted payload file: {relative}"
            ) from exc
        if re.search(
            rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", content
        ):
            raise ContractError(
                f"secret-like payload content is forbidden: {relative}"
            )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    menu = commands.add_parser("menu")
    menu.add_argument("--manifest", type=Path, required=True)
    menu.add_argument("--grub", type=Path, required=True)
    menu.add_argument("--isolinux", type=Path, required=True)
    menu.add_argument("--v1-controller", type=Path, required=True)
    menu.add_argument("--v2-controller", type=Path, required=True)
    source = commands.add_parser("source")
    source.add_argument("--manifest", type=Path, required=True)
    source.add_argument("--source-identity", type=Path, required=True)
    scan = commands.add_parser("scan")
    scan.add_argument("--root", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "menu":
            validate_menu(
                args.manifest,
                args.grub,
                args.isolinux,
                args.v1_controller,
                args.v2_controller,
            )
        elif args.command == "source":
            validate_source(args.manifest, args.source_identity)
        else:
            scan_secret_like_files(args.root)
    except ContractError as exc:
        print(f"verify-contract: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
