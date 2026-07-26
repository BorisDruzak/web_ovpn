#!/bin/bash
set -Eeuo pipefail

usage() { printf '%s\n' 'Usage: build-spike-iso.sh --source <ISO> --output <ISO> [--force]' >&2; exit 2; }
die() { printf 'build-spike-iso: %s\n' "$*" >&2; exit 1; }
source_iso= output_iso= force=0
while (($#)); do case "$1" in --source) source_iso="$2"; shift 2;; --output) output_iso="$2"; shift 2;; --force) force=1; shift;; *) usage;; esac; done
[[ -n "$source_iso" && -n "$output_iso" ]] || usage
[[ -r "$source_iso" ]] || die 'Source ISO is not readable'
[[ ! -e "$output_iso" || "$force" == 1 ]] || die 'Output exists; use --force'
for command in xorriso cpio gzip patch sha256sum mktemp python3; do command -v "$command" >/dev/null || die "Missing required command: $command"; done
root=$(cd -- "$(dirname -- "$0")" && pwd -P)
bash "$root/inspect-upstream-iso.sh" --source "$source_iso" --manifest "$root/manifests/alt-kworkstation-11.4-install-x86_64.json"
workdir=$(mktemp -d "${TMPDIR:-/var/tmp}/alt-spike-build.XXXXXX")
trap 'rm -rf -- "$workdir"' EXIT
xorriso -osirrox on -indev "$source_iso" -extract /boot/initrd.img "$workdir/initrd.img" >/dev/null
xorriso -osirrox on -indev "$source_iso" -extract /boot/grub/grub.cfg "$workdir/grub.cfg" >/dev/null
xorriso -osirrox on -indev "$source_iso" -extract /syslinux/isolinux.cfg "$workdir/isolinux.cfg" >/dev/null
mkdir "$workdir/initrd"
( cd "$workdir/initrd"; gzip -dc "$workdir/initrd.img" | cpio -idmu --quiet )
install -D -m 0755 "$root/initrd-overlay/usr/libexec/sosnadmin-install-spike" "$workdir/initrd/usr/libexec/sosnadmin-install-spike"
install -D -m 0755 "$root/initrd-overlay/lib/initrd/post/network-up/99-sosnadmin-spike" "$workdir/initrd/lib/initrd/post/network-up/99-sosnadmin-spike"
install -D -m 0644 "$root/../install-agent/lib/cmdline.sh" "$workdir/initrd/usr/libexec/sosnadmin/lib/cmdline.sh"
install -D -m 0755 "$root/../install-agent/lib/dhcp-hook.sh" "$workdir/initrd/usr/libexec/sosnadmin/lib/dhcp-hook.sh"
install -D -m 0644 "$root/../install-agent/lib/network.sh" "$workdir/initrd/usr/libexec/sosnadmin/lib/network.sh"
install -D -m 0644 "$root/../install-agent/lib/inventory.sh" "$workdir/initrd/usr/libexec/sosnadmin/lib/inventory.sh"
install -D -m 0644 "$root/../install-agent/lib/protocol.sh" "$workdir/initrd/usr/libexec/sosnadmin/lib/protocol.sh"
install -D -m 0644 "$root/../install-agent/lib/ui.sh" "$workdir/initrd/usr/libexec/sosnadmin/lib/ui.sh"
sed -i 's#AGENT_ROOT=.*#AGENT_ROOT="/usr/libexec/sosnadmin"#' "$workdir/initrd/usr/libexec/sosnadmin-install-spike"
( cd "$workdir/initrd"; find . -print0 | cpio --null -o -H newc --owner=0:0 --quiet | gzip -n > "$workdir/initrd-spike.img" )
mkdir -p "$workdir/menu/boot/grub" "$workdir/menu/syslinux"
mv "$workdir/grub.cfg" "$workdir/menu/boot/grub/grub.cfg"
mv "$workdir/isolinux.cfg" "$workdir/menu/syslinux/isolinux.cfg"
patch --fuzz=0 -d "$workdir/menu" -p1 < "$root/boot-menu/grub.cfg.patch"
patch --fuzz=0 -d "$workdir/menu" -p1 < "$root/boot-menu/isolinux.cfg.patch"
tmp_output="$output_iso.tmp.$$"
rm -f -- "$tmp_output"
xorriso -indev "$source_iso" -outdev "$tmp_output" -boot_image any replay \
    -map "$workdir/initrd-spike.img" /boot/initrd.img \
    -map "$workdir/menu/boot/grub/grub.cfg" /boot/grub/grub.cfg \
    -map "$workdir/menu/syslinux/isolinux.cfg" /syslinux/isolinux.cfg \
    -commit >/dev/null
mv -f -- "$tmp_output" "$output_iso"
printf 'spike_iso=%s\n' "$output_iso"
