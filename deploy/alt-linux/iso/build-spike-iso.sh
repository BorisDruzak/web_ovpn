#!/bin/bash
set -Eeuo pipefail

usage() { printf '%s\n' 'Usage: build-spike-iso.sh --source <ISO> --output <ISO> [--force]' >&2; exit 2; }
die() { printf 'build-spike-iso: %s\n' "$*" >&2; exit 1; }
source_iso= output_iso= force=0
while (($#)); do case "$1" in --source) source_iso="$2"; shift 2;; --output) output_iso="$2"; shift 2;; --force) force=1; shift;; *) usage;; esac; done
[[ -n "$source_iso" && -n "$output_iso" ]] || usage
[[ -r "$source_iso" ]] || die 'Source ISO is not readable'
[[ ! -e "$output_iso" || "$force" == 1 ]] || die 'Output exists; use --force'
for command in xorriso cpio gzip patch sha256sum mktemp python3 df stat; do command -v "$command" >/dev/null || die "Missing required command: $command"; done
output_dir=$(dirname -- "$output_iso")
source_size=$(stat -c '%s' "$source_iso")
required_bytes=$((source_size + 512 * 1024 * 1024))
required_kib=$(((required_bytes + 1023) / 1024))
available_kib=$(df -Pk "$output_dir" | awk 'NR == 2 {print $4}')
[[ "$available_kib" =~ ^[0-9]+$ && "$available_kib" -ge "$required_kib" ]] || die 'Insufficient free space for ISO build'
root=$(cd -- "$(dirname -- "$0")" && pwd -P)
bash "$root/inspect-upstream-iso.sh" --source "$source_iso" --manifest "$root/manifests/alt-kworkstation-11.4-install-x86_64.json"
workdir=$(mktemp -d "${TMPDIR:-/var/tmp}/alt-spike-build.XXXXXX")
tmp_output=
tmp_integrity=
cleanup() {
    rm -rf -- "$workdir"
    [[ -z "$tmp_output" ]] || rm -f -- "$tmp_output"
    [[ -z "$tmp_integrity" ]] || rm -f -- "$tmp_integrity"
}
trap cleanup EXIT
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
tmp_integrity="${output_iso}.build-manifest.json.tmp.$$"
python3 - "$source_iso" "$tmp_output" "$workdir/initrd-spike.img" "$tmp_integrity" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

source, output, initrd, manifest = map(Path, sys.argv[1:])

def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

manifest.write_text(
    json.dumps(
        {
            "format": "sosnadmin-alt-spike-build-v1",
            "source_iso_sha256": sha256(source),
            "spike_iso_sha256": sha256(output),
            "spike_initrd_sha256": sha256(initrd),
        },
        sort_keys=True,
    )
    + "\n",
    encoding="utf-8",
)
PY
mv -f -- "$tmp_output" "$output_iso"
tmp_output=
mv -f -- "$tmp_integrity" "${output_iso}.build-manifest.json"
tmp_integrity=
printf 'spike_iso=%s\n' "$output_iso"
