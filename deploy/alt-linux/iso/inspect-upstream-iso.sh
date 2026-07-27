#!/bin/bash
set -Eeuo pipefail

readonly EXPECTED_SOURCE_BASENAME="alt-kworkstation-11.4-install-x86_64.iso"

usage() {
    cat >&2 <<'EOF'
Usage: inspect-upstream-iso.sh --source <ISO> --manifest <JSON>

Read and verify the pinned ALT 11.4 upstream ISO. The source ISO is never
modified. A mismatch exits non-zero.
EOF
    exit 2
}

die() {
    printf 'inspect-upstream-iso: %s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"
}

manifest_value() {
    local key="$1"
    python3 -c '
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    value = json.load(source)[sys.argv[2]]
if not isinstance(value, (str, int)):
    raise SystemExit("manifest value must be a string or integer")
print(value)
' "$manifest" "$key"
}

sha256_file() {
    sha256sum "$1" | awk '{print $1}'
}

verify_equals() {
    local label="$1"
    local expected="$2"
    local actual="$3"

    [[ "$actual" == "$expected" ]] || die "$label SHA-256 mismatch"
    printf '%s=%s\n' "$label" "$actual"
}

source_iso=
manifest=
while (($#)); do
    case "$1" in
        --source)
            (($# >= 2)) || usage
            source_iso="$2"
            shift 2
            ;;
        --manifest)
            (($# >= 2)) || usage
            manifest="$2"
            shift 2
            ;;
        *) usage ;;
    esac
done

[[ -n "$source_iso" && -n "$manifest" ]] || usage
[[ -f "$source_iso" && -r "$source_iso" ]] || die "Source ISO is not readable: $source_iso"
[[ -f "$manifest" && -r "$manifest" ]] || die "Manifest is not readable: $manifest"
[[ "${source_iso##*/}" == "$EXPECTED_SOURCE_BASENAME" ]] || die "Unexpected source ISO basename"

for required in xorriso gzip cpio sha256sum mktemp python3; do
    require_command "$required"
done

[[ "$(manifest_value source_filename)" == "$EXPECTED_SOURCE_BASENAME" ]] || die "Manifest source filename is unexpected"
[[ "$(stat -c '%s' "$source_iso")" == "$(manifest_value source_size_bytes)" ]] || die "Source ISO size mismatch"

workdir=$(mktemp -d "${TMPDIR:-/var/tmp}/alt-iso-inspect.XXXXXX")
trap 'rm -rf -- "$workdir"' EXIT

extract_iso_file() {
    local iso_path="$1"
    local destination="$2"

    xorriso -osirrox on -indev "$source_iso" -extract "$iso_path" "$destination" >/dev/null
}

extract_iso_file /boot/initrd.img "$workdir/initrd.img"
extract_iso_file /boot/grub/grub.cfg "$workdir/grub.cfg"
extract_iso_file /syslinux/isolinux.cfg "$workdir/isolinux.cfg"
gzip -dc "$workdir/initrd.img" | cpio -i --to-stdout --quiet etc/rc.d/rc > "$workdir/rc"

verify_equals source_sha256 "$(manifest_value source_sha256)" "$(sha256_file "$source_iso")"
verify_equals initrd_sha256 "$(manifest_value initrd_sha256)" "$(sha256_file "$workdir/initrd.img")"
verify_equals grub_cfg_sha256 "$(manifest_value grub_cfg_sha256)" "$(sha256_file "$workdir/grub.cfg")"
verify_equals isolinux_cfg_sha256 "$(manifest_value isolinux_cfg_sha256)" "$(sha256_file "$workdir/isolinux.cfg")"
verify_equals runlevel_dispatcher_sha256 "$(manifest_value runlevel_dispatcher_sha256)" "$(sha256_file "$workdir/rc")"

grep -Fqx 'for i in "$rcd"/S*; do' "$workdir/rc" \
    || die "Expected runlevel start-loop anchor is absent"

printf 'upstream_iso_verified=true\n'
