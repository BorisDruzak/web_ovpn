#!/bin/bash
set -Eeuo pipefail

usage() { printf '%s\n' 'Usage: verify-spike-iso.sh --iso <ISO> --manifest <JSON>' >&2; exit 2; }
die() { printf 'verify-spike-iso: %s\n' "$*" >&2; exit 1; }

iso= manifest=
while (($#)); do
    case "$1" in
        --iso) iso="${2:-}"; shift 2 ;;
        --manifest) manifest="${2:-}"; shift 2 ;;
        *) usage ;;
    esac
done
[[ -n "$iso" && -n "$manifest" && -r "$iso" && -r "$manifest" ]] || usage
for command in xorriso grep mktemp gzip cpio sha256sum python3 stat; do command -v "$command" >/dev/null || die "Missing required command: $command"; done
python3 - "$manifest" <<'PY'
import json
import sys
manifest = json.load(open(sys.argv[1], encoding="utf-8"))
for key in ("iso_id", "source_sha256", "runlevel_dispatcher_sha256"):
    if not isinstance(manifest.get(key), str) or not manifest[key]:
        raise SystemExit(f"missing manifest field: {key}")
PY

workdir=$(mktemp -d "${TMPDIR:-/var/tmp}/alt-spike-verify.XXXXXX")
trap 'rm -rf -- "$workdir"' EXIT
xorriso -osirrox on -indev "$iso" \
    -extract /boot/initrd.img "$workdir/initrd.img" \
    -extract /boot/grub/grub.cfg "$workdir/grub.cfg" \
    -extract /syslinux/isolinux.cfg "$workdir/isolinux.cfg" >/dev/null
mkdir -p "$workdir/initrd"
( cd "$workdir/initrd"; gzip -dc "$workdir/initrd.img" | cpio -idmu --quiet )

build_manifest="$iso.build-manifest.json"
[[ -r "$build_manifest" ]] || die "Missing build manifest: $build_manifest"
python3 - "$manifest" "$build_manifest" "$iso" "$workdir/initrd.img" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

source_manifest, build_manifest, iso, initrd = map(Path, sys.argv[1:])

def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

source = json.loads(source_manifest.read_text(encoding="utf-8"))
build = json.loads(build_manifest.read_text(encoding="utf-8"))
expected = {
    "format": "sosnadmin-alt-spike-build-v1",
    "source_iso_sha256": source["source_sha256"],
    "spike_iso_sha256": sha256(iso),
    "spike_initrd_sha256": sha256(initrd),
}
if build != expected:
    raise SystemExit("build manifest does not match ISO payload")
PY

require() {
    local file="$1" token="$2"
    grep -Fqx -- "$token" "$file" >/dev/null || grep -F -- "$token" "$file" >/dev/null \
        || die "Missing menu contract: $token"
}
forbid() { grep -F -- "$2" "$1" >/dev/null && die "Forbidden menu token: $2" || true; }

require "$workdir/grub.cfg" 'set timeout=10'
require "$workdir/grub.cfg" 'set default=harddisk'
require "$workdir/grub.cfg" '/EFI/altlinux/shimx64.efi'
require "$workdir/grub.cfg" '/EFI/altlinux/grubx64.efi'
require "$workdir/grub.cfg" '/EFI/Microsoft/Boot/bootmgfw.efi'
forbid "$workdir/grub.cfg" '/EFI/BOOT/BOOTX64.EFI'
require "$workdir/grub.cfg" 'menuentry "Boot from local disk"'
require "$workdir/grub.cfg" 'menuentry "Sosnadmin managed installation [SPIKE]"'
require "$workdir/grub.cfg" 'menuentry "Normal ALT installation"'
require "$workdir/grub.cfg" 'menuentry "Diagnostics"'
require "$workdir/grub.cfg" 'sosnadmin.mode=spike'
require "$workdir/grub.cfg" 'ip=dhcp'
require "$workdir/grub.cfg" 'console=ttyS0,115200'
forbid "$workdir/grub.cfg" ' ai '
forbid "$workdir/grub.cfg" 'curl='
require "$workdir/isolinux.cfg" 'default harddisk'
forbid "$workdir/isolinux.cfg" 'sosnadmin.mode=spike'
forbid "$workdir/isolinux.cfg" ' ai '
forbid "$workdir/isolinux.cfg" 'curl='

hook="$workdir/initrd/lib/initrd/post/network-up/99-sosnadmin-spike"
agent="$workdir/initrd/usr/libexec/sosnadmin-install-spike"
[[ "$(stat -c %a "$hook")" == 755 && "$(stat -c %a "$agent")" == 755 ]] || die 'Spike hook or agent is not executable'
grep -Fqx "if grep -Fqw 'sosnadmin.mode=spike' /proc/cmdline; then" "$hook" >/dev/null || die 'Unexpected initrd hook condition'
grep -Fqx '    exec /usr/libexec/sosnadmin-install-spike' "$hook" >/dev/null || die 'Unexpected initrd hook action'
for library in cmdline.sh dhcp-hook.sh inventory.sh network.sh protocol.sh ui.sh; do
    [[ -f "$workdir/initrd/usr/libexec/sosnadmin/lib/$library" ]] || die "Missing agent library: $library"
done
forbid "$agent" 'alterator-autoinstall'
forbid "$agent" 'alterator-wizard'
forbid "$agent" 'sfdisk'
forbid "$agent" 'wipefs'
forbid "$agent" 'mkfs'

printf '%s\n' 'menu_default=harddisk' 'managed_entry=verified' 'uefi_loader_order=verified' 'initrd_payload=verified' 'spike_iso_verified=true'
