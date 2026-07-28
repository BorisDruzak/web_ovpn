#!/bin/bash
set -Eeuo pipefail

usage() {
    printf '%s\n' \
        'Usage: build-managed-iso.sh --source <ISO> --output <ISO> --helper <BINARY> --public-key <JSON> --build-id <ID> [--force]' >&2
    exit 2
}

die() {
    printf 'build-managed-iso: %s\n' "$*" >&2
    exit 1
}

source_iso=
output_iso=
helper=
public_key=
build_id=
force=0
while (($#)); do
    case "$1" in
        --source) (($# >= 2)) || usage; source_iso="$2"; shift 2 ;;
        --output) (($# >= 2)) || usage; output_iso="$2"; shift 2 ;;
        --helper) (($# >= 2)) || usage; helper="$2"; shift 2 ;;
        --public-key) (($# >= 2)) || usage; public_key="$2"; shift 2 ;;
        --build-id) (($# >= 2)) || usage; build_id="$2"; shift 2 ;;
        --force) force=1; shift ;;
        *) usage ;;
    esac
done
[[ -n "$source_iso" && -n "$output_iso" && -n "$helper" &&
    -n "$public_key" && -n "$build_id" ]] || usage
[[ "$build_id" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] ||
    die 'Build ID is invalid'
[[ -f "$source_iso" && -r "$source_iso" ]] ||
    die 'Source ISO is not readable'
[[ -f "$helper" && -r "$helper" ]] ||
    die 'Helper is not readable'
[[ -f "$public_key" && -r "$public_key" ]] ||
    die 'Public key is not readable'
root=$(cd -- "$(dirname -- "$0")" && pwd -P)
agent_root=$(cd -- "$root/../../install-agent/v1" && pwd -P)
source_contract="$root/../manifests/alt-kworkstation-11.4-install-x86_64.json"
source_identity="$root/manifests/source_iso.json"
output_manifest="${output_iso}.build-manifest.json"
command -v readlink >/dev/null ||
    die 'Missing required command: readlink'
output_resolved=$(readlink -f -- "$output_iso") ||
    die 'Cannot resolve output path'
manifest_resolved=$(readlink -f -- "$output_manifest") ||
    die 'Cannot resolve sidecar path'

input_assets=(
    "$source_iso"
    "$helper"
    "$public_key"
    "$source_contract"
    "$source_identity"
    "$root/build-managed-iso.sh"
    "$root/verify-managed-iso.sh"
    "$root/lib/build-inputs.sh"
    "$root/../inspect-upstream-iso.sh"
    "$root/boot-menu/grub.cfg.patch"
    "$root/boot-menu/isolinux.cfg.patch"
    "$root/initrd-overlay/lib/initrd/post/network-up/99-alt-install-agent-v1"
    "$agent_root/alt-install-agent"
    "$agent_root"/lib/*.sh
)
input_resolved=()
public_key_resolved=
for input_index in "${!input_assets[@]}"; do
    input_asset=${input_assets[$input_index]}
    resolved=$(readlink -f -- "$input_asset") ||
        die "Cannot resolve input asset: $input_asset"
    input_resolved+=("$resolved")
    [[ "$input_index" -ne 2 ]] || public_key_resolved=$resolved
    if [[ "$input_asset" == "$source_iso" &&
        "$resolved" == "$output_resolved" ]]; then
        die 'Source and output paths must differ'
    fi
    [[ "$resolved" != "$output_resolved" &&
        "$resolved" != "$manifest_resolved" ]] ||
        die 'Output artifacts conflict with an input asset'
done
[[ ! -e "$output_iso" || "$force" == 1 ]] ||
    die 'Output exists; use --force'
[[ ! -e "$output_manifest" || "$force" == 1 ]] ||
    die 'Sidecar exists; use --force'

for command in xorriso cpio gzip patch sha256sum mktemp python3 \
    df stat install find sort sed mv chmod awk grep mkdir rm cat wc; do
    command -v "$command" >/dev/null ||
        die "Missing required command: $command"
done
# shellcheck source=lib/build-inputs.sh
source "$root/lib/build-inputs.sh"

output_dir=$(cd -- "$(dirname -- "$output_iso")" && pwd -P)
source_size=$(stat -c '%s' "$source_iso")
required_bytes=$((source_size + 512 * 1024 * 1024))
required_kib=$(((required_bytes + 1023) / 1024))
available_kib=$(df -Pk "$output_dir" | awk 'NR == 2 {print $4}')
[[ "$available_kib" =~ ^[0-9]+$ &&
    "$available_kib" -ge "$required_kib" ]] ||
    die 'Insufficient free space for ISO build'

workdir=$(mktemp -d "$output_dir/.alt-agent-v1-build.XXXXXX")
chmod 0700 -- "$workdir"
workdir_resolved=$(readlink -f -- "$workdir") ||
    die 'Cannot resolve private staging directory'
tmp_output="$workdir/managed.iso.staging"
tmp_manifest="$workdir/build-manifest.json.staging"
for resolved in "${input_resolved[@]}"; do
    [[ "$resolved" != "$workdir_resolved" &&
        "$resolved" != "$workdir_resolved"/* ]] ||
        die 'Private staging artifacts conflict with an input asset'
done
cleanup() {
    case "$workdir" in
        "$output_dir"/.alt-agent-v1-build.*) rm -rf -- "$workdir" ;;
    esac
}
trap cleanup EXIT

public_key_snapshot="$workdir/public-key.snapshot.json"
snapshot_public_key "$public_key_resolved" "$public_key_snapshot" ||
    die 'Public key snapshot failed'
read -r public_key_id public_key_sha256 < <(
    public_key_metadata "$public_key_snapshot"
) || die 'Public key validation failed'
[[ "$public_key_id" =~ ^sha256:[0-9a-f]{64}$ &&
    "$public_key_sha256" =~ ^[0-9a-f]{64}$ ]] ||
    die 'Public key metadata output is invalid'

python3 - "$helper" <<'PY' || die 'Helper must be a static Linux amd64 ELF'
import struct
import sys
from pathlib import Path

raw = Path(sys.argv[1]).read_bytes()
if len(raw) < 64 or raw[:6] != b"\x7fELF\x02\x01":
    raise SystemExit(1)
if struct.unpack_from("<H", raw, 18)[0] != 62:
    raise SystemExit(1)
program_offset = struct.unpack_from("<Q", raw, 32)[0]
entry_size = struct.unpack_from("<H", raw, 54)[0]
entry_count = struct.unpack_from("<H", raw, 56)[0]
if entry_size < 56 or entry_count == 0:
    raise SystemExit(1)
for index in range(entry_count):
    offset = program_offset + index * entry_size
    if offset + 4 > len(raw):
        raise SystemExit(1)
    if struct.unpack_from("<I", raw, offset)[0] == 3:
        raise SystemExit(1)
PY

bash "$root/../inspect-upstream-iso.sh" \
    --source "$source_iso" \
    --manifest "$source_contract"

xorriso -osirrox on -indev "$source_iso" \
    -extract /boot/initrd.img "$workdir/initrd.img" \
    -extract /boot/grub/grub.cfg "$workdir/grub.cfg" \
    -extract /syslinux/isolinux.cfg "$workdir/isolinux.cfg" >/dev/null
mkdir -p "$workdir/initrd"
(
    cd "$workdir/initrd"
    gzip -dc "$workdir/initrd.img" | cpio -idmu --quiet
)

install -D -m 0755 "$agent_root/alt-install-agent" \
    "$workdir/initrd/usr/libexec/alt-install-agent"
for library in "$agent_root"/lib/*.sh; do
    library_mode=0644
    [[ "${library##*/}" != dhcp-hook.sh ]] || library_mode=0755
    install -D -m "$library_mode" "$library" \
        "$workdir/initrd/usr/libexec/alt-install-agent-lib/lib/${library##*/}"
done
install -D -m 0755 "$helper" \
    "$workdir/initrd/usr/libexec/alt-install-helper"
install -D -m 0755 \
    "$root/initrd-overlay/lib/initrd/post/network-up/99-alt-install-agent-v1" \
    "$workdir/initrd/lib/initrd/post/network-up/99-alt-install-agent-v1"
install -D -m 0644 "$source_identity" \
    "$workdir/initrd/usr/share/alt-install/source_iso.json"
install -D -m 0644 "$public_key_snapshot" \
    "$workdir/initrd/usr/share/alt-install/public-key.json"
printf '%s\n' "$build_id" > "$workdir/build-id"
chmod 0600 "$workdir/build-id"
install -D -m 0644 "$workdir/build-id" \
    "$workdir/initrd/usr/share/alt-install/build-id"
printf '%011d\n' 0 > "$workdir/initrd/usr/share/alt-install/managed_iso_size_bytes"
chmod 0644 "$workdir/initrd/usr/share/alt-install/managed_iso_size_bytes"

repack_initrd() {
(
    cd "$workdir/initrd"
    sha256sum \
        lib/initrd/post/network-up/99-alt-install-agent-v1 \
        usr/libexec/alt-install-agent \
        usr/libexec/alt-install-helper \
        usr/libexec/alt-install-agent-lib/lib/config.sh \
        usr/libexec/alt-install-agent-lib/lib/dhcp-hook.sh \
        usr/libexec/alt-install-agent-lib/lib/network.sh \
        usr/libexec/alt-install-agent-lib/lib/protocol.sh \
        usr/libexec/alt-install-agent-lib/lib/state.sh \
        usr/libexec/alt-install-agent-lib/lib/transport.sh \
        usr/libexec/alt-install-agent-lib/lib/ui.sh \
        usr/share/alt-install/build-id \
        usr/share/alt-install/managed_iso_size_bytes \
        usr/share/alt-install/public-key.json \
        usr/share/alt-install/source_iso.json \
        > usr/share/alt-install/payload.sha256
    chmod 0644 usr/share/alt-install/payload.sha256
    find . -print0 |
        sort -z |
        cpio --null -o -H newc --owner=0:0 --quiet |
        gzip -n > "$workdir/initrd-agent-v1.img"
)
}
repack_initrd

mkdir -p "$workdir/menu/boot/grub" "$workdir/menu/syslinux"
mv "$workdir/grub.cfg" "$workdir/menu/boot/grub/grub.cfg"
mv "$workdir/isolinux.cfg" "$workdir/menu/syslinux/isolinux.cfg"
patch --fuzz=0 -d "$workdir/menu" -p1 < "$root/boot-menu/grub.cfg.patch"
patch --fuzz=0 -d "$workdir/menu" -p1 < "$root/boot-menu/isolinux.cfg.patch"
sed -i "s/__ALT_INSTALL_BUILD_ID__/$build_id/g" \
    "$workdir/menu/boot/grub/grub.cfg"
grep -F '__ALT_INSTALL_BUILD_ID__' "$workdir/menu/boot/grub/grub.cfg" \
    >/dev/null && die 'Build ID substitution failed'

xorriso -indev "$source_iso" -outdev "$tmp_output" \
    -boot_image any replay \
    -map "$workdir/initrd-agent-v1.img" /boot/initrd.img \
    -map "$workdir/menu/boot/grub/grub.cfg" /boot/grub/grub.cfg \
    -map "$workdir/menu/syslinux/isolinux.cfg" /syslinux/isolinux.cfg \
    -commit >/dev/null

managed_iso_size=$(stat -c '%s' "$tmp_output")
[[ "$managed_iso_size" =~ ^[1-9][0-9]{10,}$ ]] ||
    die 'Managed ISO size is invalid'
printf '%011d\n' "$managed_iso_size" > \
    "$workdir/initrd/usr/share/alt-install/managed_iso_size_bytes"
repack_initrd
tmp_final_output="$workdir/managed.iso.final"
xorriso -indev "$source_iso" -outdev "$tmp_final_output" \
    -boot_image any replay \
    -map "$workdir/initrd-agent-v1.img" /boot/initrd.img \
    -map "$workdir/menu/boot/grub/grub.cfg" /boot/grub/grub.cfg \
    -map "$workdir/menu/syslinux/isolinux.cfg" /syslinux/isolinux.cfg \
    -commit >/dev/null
[[ "$(stat -c '%s' "$tmp_final_output")" == "$managed_iso_size" ]] ||
    die 'Managed ISO size fixed point did not converge'
mv -f -- "$tmp_final_output" "$tmp_output"

python3 - "$source_iso" "$tmp_output" "$workdir/initrd-agent-v1.img" \
    "$workdir/initrd" "$tmp_manifest" "$build_id" "$public_key_id" \
    "$public_key_sha256" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

source, output, initrd, root, manifest = map(Path, sys.argv[1:6])
build_id, public_key_id, public_key_sha256 = sys.argv[6:9]

def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

document = {
    "build_id": build_id,
    "format": "alt-install-agent-managed-iso-v1",
    "helper_sha256": sha256(root / "usr/libexec/alt-install-helper"),
    "managed_initrd_sha256": sha256(initrd),
    "managed_iso_sha256": sha256(output),
    "payload_manifest_sha256": sha256(
        root / "usr/share/alt-install/payload.sha256"
    ),
    "public_key_id": public_key_id,
    "public_key_sha256": public_key_sha256,
    "source_iso_sha256": sha256(source),
}
manifest.write_text(
    json.dumps(document, ensure_ascii=True, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY

mv -f -- "$tmp_output" "$output_iso"
mv -f -- "$tmp_manifest" "$output_manifest"
printf 'managed_iso=%s\n' "$output_iso"
