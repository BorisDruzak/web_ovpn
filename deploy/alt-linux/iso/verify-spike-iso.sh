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
for command in xorriso grep mktemp; do command -v "$command" >/dev/null || die "Missing required command: $command"; done

workdir=$(mktemp -d "${TMPDIR:-/var/tmp}/alt-spike-verify.XXXXXX")
trap 'rm -rf -- "$workdir"' EXIT
xorriso -osirrox on -indev "$iso" \
    -extract /boot/grub/grub.cfg "$workdir/grub.cfg" \
    -extract /syslinux/isolinux.cfg "$workdir/isolinux.cfg" >/dev/null

require() {
    local file="$1" token="$2"
    grep -Fqx -- "$token" "$file" >/dev/null || grep -F -- "$token" "$file" >/dev/null \
        || die "Missing menu contract: $token"
}
forbid() { grep -F -- "$2" "$1" >/dev/null && die "Forbidden menu token: $2" || true; }

require "$workdir/grub.cfg" 'set timeout=60'
require "$workdir/grub.cfg" 'set default=harddisk'
require "$workdir/grub.cfg" '/EFI/altlinux/shimx64.efi'
require "$workdir/grub.cfg" '/EFI/altlinux/grubx64.efi'
require "$workdir/grub.cfg" '/EFI/Microsoft/Boot/bootmgfw.efi'
forbid "$workdir/grub.cfg" '/EFI/BOOT/BOOTX64.EFI'
require "$workdir/grub.cfg" 'menuentry "Sosnadmin managed installation [SPIKE]"'
require "$workdir/grub.cfg" 'sosnadmin.mode=spike'
require "$workdir/grub.cfg" 'ip=dhcp'
require "$workdir/grub.cfg" 'console=ttyS0,115200'
forbid "$workdir/grub.cfg" ' ai '
forbid "$workdir/grub.cfg" 'curl='
require "$workdir/isolinux.cfg" 'default harddisk'
require "$workdir/isolinux.cfg" 'label sosnadmin-spike'
require "$workdir/isolinux.cfg" 'sosnadmin.mode=spike'
require "$workdir/isolinux.cfg" 'console=ttyS0,115200'
forbid "$workdir/isolinux.cfg" ' ai '
forbid "$workdir/isolinux.cfg" 'curl='

printf '%s\n' 'menu_default=harddisk' 'managed_entry=verified' 'uefi_loader_order=verified' 'spike_iso_verified=true'
