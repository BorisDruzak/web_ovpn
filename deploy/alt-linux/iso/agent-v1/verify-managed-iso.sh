#!/bin/bash
set -Eeuo pipefail

usage() {
    printf '%s\n' \
        'Usage: verify-managed-iso.sh --iso <ISO> [--manifest <JSON>]' >&2
    exit 2
}

die() {
    printf 'verify-managed-iso: %s\n' "$*" >&2
    exit 1
}

iso=
manifest=
while (($#)); do
    case "$1" in
        --iso) (($# >= 2)) || usage; iso="$2"; shift 2 ;;
        --manifest) (($# >= 2)) || usage; manifest="$2"; shift 2 ;;
        *) usage ;;
    esac
done
[[ -n "$iso" && -r "$iso" ]] || usage
manifest=${manifest:-${iso}.build-manifest.json}
[[ -r "$manifest" ]] || die 'Build manifest is not readable'
for command in xorriso gzip cpio sha256sum mktemp python3 stat grep mkdir rm; do
    command -v "$command" >/dev/null ||
        die "Missing required command: $command"
done

temporary_root=${TMPDIR:-/var/tmp}
workdir=$(mktemp -d "$temporary_root/alt-agent-v1-verify.XXXXXX")
cleanup() {
    case "$workdir" in
        "$temporary_root"/alt-agent-v1-verify.*) rm -rf -- "$workdir" ;;
    esac
}
trap cleanup EXIT

xorriso -osirrox on -indev "$iso" \
    -extract /boot/initrd.img "$workdir/initrd.img" \
    -extract /boot/grub/grub.cfg "$workdir/grub.cfg" \
    -extract /syslinux/isolinux.cfg "$workdir/isolinux.cfg" >/dev/null
mkdir -p "$workdir/initrd"
(
    cd "$workdir/initrd"
    gzip -dc "$workdir/initrd.img" | cpio -idmu --quiet
)

payload="$workdir/initrd/usr/share/alt-install/payload.sha256"
[[ -f "$payload" && ! -L "$payload" ]] ||
    die 'Payload checksum manifest is missing'
(
    cd "$workdir/initrd"
    sha256sum -c usr/share/alt-install/payload.sha256 >/dev/null
) || die 'Payload checksum verification failed'

python3 - "$manifest" "$iso" "$workdir/initrd.img" "$workdir/initrd" <<'PY'
import base64
import hashlib
import json
import struct
import sys
from pathlib import Path

manifest_path, iso, initrd, root = map(Path, sys.argv[1:])
document = json.loads(manifest_path.read_text(encoding="utf-8"))
expected_fields = {
    "build_id", "format", "helper_sha256", "managed_initrd_sha256",
    "managed_iso_sha256", "payload_manifest_sha256", "public_key_id",
    "public_key_sha256", "source_iso_sha256",
}
if set(document) != expected_fields:
    raise SystemExit("build manifest fields are invalid")
if document["format"] != "alt-install-agent-managed-iso-v1":
    raise SystemExit("build manifest format is invalid")
build_id = document["build_id"]
if (
    not isinstance(build_id, str)
    or not 1 <= len(build_id) <= 64
    or not all(character.isalnum() or character in "._-" for character in build_id)
):
    raise SystemExit("build ID is invalid")

def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

helper = root / "usr/libexec/alt-install-helper"
public_key_path = root / "usr/share/alt-install/public-key.json"
source_path = root / "usr/share/alt-install/source_iso.json"
checks = {
    "helper_sha256": sha256(helper),
    "managed_initrd_sha256": sha256(initrd),
    "managed_iso_sha256": sha256(iso),
    "payload_manifest_sha256": sha256(
        root / "usr/share/alt-install/payload.sha256"
    ),
    "public_key_sha256": sha256(public_key_path),
}
for field, actual in checks.items():
    if document[field] != actual:
        raise SystemExit(f"{field} does not match")

source = json.loads(source_path.read_text(encoding="utf-8"))
if set(source) != {"schema_version", "iso_id", "iso_sha256"}:
    raise SystemExit("source ISO identity fields are invalid")
if (
    source["schema_version"] != 1
    or source["iso_id"] != "alt-kworkstation-11.4-install-x86_64"
    or source["iso_sha256"] != document["source_iso_sha256"]
):
    raise SystemExit("source ISO identity does not match")

public_key = json.loads(public_key_path.read_text(encoding="utf-8"))
if set(public_key) != {
    "schema_version", "algorithm", "key_id", "public_key_b64"
}:
    raise SystemExit("public key fields are invalid")
if public_key["schema_version"] != 1 or public_key["algorithm"] != "ed25519":
    raise SystemExit("public key metadata is invalid")
raw_key = base64.b64decode(public_key["public_key_b64"], validate=True)
if len(raw_key) != 32:
    raise SystemExit("public key length is invalid")
key_id = "sha256:" + hashlib.sha256(raw_key).hexdigest()
if public_key["key_id"] != key_id or document["public_key_id"] != key_id:
    raise SystemExit("public key ID does not match")

raw_helper = helper.read_bytes()
if len(raw_helper) < 64 or raw_helper[:6] != b"\x7fELF\x02\x01":
    raise SystemExit("helper is not a Linux amd64 ELF")
if struct.unpack_from("<H", raw_helper, 18)[0] != 62:
    raise SystemExit("helper architecture is invalid")
program_offset = struct.unpack_from("<Q", raw_helper, 32)[0]
entry_size = struct.unpack_from("<H", raw_helper, 54)[0]
entry_count = struct.unpack_from("<H", raw_helper, 56)[0]
for index in range(entry_count):
    offset = program_offset + index * entry_size
    if struct.unpack_from("<I", raw_helper, offset)[0] == 3:
        raise SystemExit("helper has a dynamic interpreter")
PY

mode_is() {
    local expected="$1" path="$2"
    [[ "$(stat -c '%a' "$path")" == "$expected" ]] ||
        die "Unexpected mode for ${path#$workdir/initrd/}"
}

mode_is 755 \
    "$workdir/initrd/lib/initrd/post/network-up/99-alt-install-agent-v1"
mode_is 755 "$workdir/initrd/usr/libexec/alt-install-agent"
mode_is 755 "$workdir/initrd/usr/libexec/alt-install-helper"
mode_is 755 \
    "$workdir/initrd/usr/libexec/alt-install-agent-lib/lib/dhcp-hook.sh"
for library in config.sh network.sh protocol.sh state.sh transport.sh ui.sh; do
    mode_is 644 \
        "$workdir/initrd/usr/libexec/alt-install-agent-lib/lib/$library"
done
for asset in build-id payload.sha256 public-key.json source_iso.json; do
    mode_is 644 "$workdir/initrd/usr/share/alt-install/$asset"
done

initrd_command() {
    local command="$1" directory candidate
    for directory in bin sbin usr/bin usr/sbin; do
        candidate="$workdir/initrd/$directory/$command"
        if [[ -f "$candidate" && -x "$candidate" ]]; then
            return 0
        fi
    done
    die "Required initrd command is missing: $command"
}

for command in bash blkid cat chmod curl date grep head ip mkdir mv od \
    rm sleep tr udhcpc wc; do
    initrd_command "$command"
done

grep -Fqx "if grep -Fqw 'sosnadmin.mode=agent-v1' /proc/cmdline; then" \
    "$workdir/initrd/lib/initrd/post/network-up/99-alt-install-agent-v1" ||
    die 'Initrd gate condition is invalid'
grep -Fqx '    exec /usr/libexec/alt-install-agent' \
    "$workdir/initrd/lib/initrd/post/network-up/99-alt-install-agent-v1" ||
    die 'Initrd gate action is invalid'

python3 - "$manifest" "$workdir/grub.cfg" "$workdir/isolinux.cfg" <<'PY'
import json
import sys
from pathlib import Path

manifest = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
grub = Path(sys.argv[2]).read_text(encoding="utf-8")
isolinux = Path(sys.argv[3]).read_text(encoding="utf-8")
start = grub.find('menuentry "Signed-plan preflight [DRY RUN]"')
end = grub.find("\n}", start)
if start < 0 or end < 0:
    raise SystemExit("managed menu entry is missing")
block = grub[start:end]
expected = (
    "sosnadmin.mode=agent-v1 "
    "sosnadmin.controller=http://192.168.100.17:18089 "
    f"sosnadmin.build={manifest['build_id']}"
)
if expected not in block:
    raise SystemExit("managed menu command line is invalid")
if "set timeout=10" not in grub:
    raise SystemExit("managed menu timeout is invalid")
if 'menuentry "Boot from local disk"' not in grub:
    raise SystemExit("local disk menu entry is missing")
if "/EFI/BOOT/BOOTX64.EFI" in grub:
    raise SystemExit("recursive EFI fallback is present")
if "default harddisk" not in isolinux:
    raise SystemExit("legacy boot default is invalid")
PY

printf '%s\n' \
    'managed_manifest=verified' \
    'payload_checksums=verified' \
    'payload_modes=verified' \
    'managed_iso_verified=true'
