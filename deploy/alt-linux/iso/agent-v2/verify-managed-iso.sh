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
root=$(cd -- "$(dirname -- "$0")" && pwd -P)
contract="$root/verify-contract.py"
[[ -f "$contract" && ! -L "$contract" ]] ||
    die 'Verification contract is unreadable'
for command in xorriso gzip cpio sha256sum mktemp python3 stat grep \
    find sort mkdir rm; do
    command -v "$command" >/dev/null ||
        die "Missing required command: $command"
done

temporary_root=${TMPDIR:-/var/tmp}
workdir=$(mktemp -d "$temporary_root/alt-agent-v2-verify.XXXXXX")
cleanup() {
    case "$workdir" in
        "$temporary_root"/alt-agent-v2-verify.*) rm -rf -- "$workdir" ;;
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
python3 "$contract" source \
    --manifest "$manifest" \
    --source-identity \
    "$workdir/initrd/usr/share/alt-install/source_iso.json" ||
    die 'Pinned source identity verification failed'
python3 "$contract" scan --root "$workdir/initrd" ||
    die 'Extracted payload secret scan failed'

python3 - "$manifest" "$iso" "$workdir/initrd.img" \
    "$workdir/initrd" "$workdir/managed-iso.sha256" <<'PY'
import base64
import hashlib
import json
import re
import ssl
import struct
import sys
from pathlib import Path

manifest_path, iso, initrd, root, verified_digest_path = map(
    Path, sys.argv[1:]
)
document = json.loads(manifest_path.read_text(encoding="utf-8"))
expected_fields = {
    "build_id",
    "controller_ca_sha256",
    "controller_url",
    "format",
    "helper_sha256",
    "managed_initrd_sha256",
    "managed_iso_sha256",
    "payload_manifest_sha256",
    "public_key_id",
    "public_key_sha256",
    "source_iso_sha256",
}
if set(document) != expected_fields:
    raise SystemExit("build manifest fields are invalid")
if document["format"] != "alt-install-agent-managed-iso-v2":
    raise SystemExit("build manifest format is invalid")
if document["controller_url"] != "https://192.168.100.17:18092":
    raise SystemExit("controller URL is invalid")
build_id = document["build_id"]
if (
    not isinstance(build_id, str)
    or not 1 <= len(build_id) <= 64
    or not build_id[0].isalnum()
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
ca_path = root / "usr/share/alt-install/execution-ca.pem"
source_path = root / "usr/share/alt-install/source_iso.json"
managed_size_path = root / "usr/share/alt-install/managed_iso_size_bytes"
payload_path = root / "usr/share/alt-install/payload.sha256"
checks = {
    "controller_ca_sha256": sha256(ca_path),
    "helper_sha256": sha256(helper),
    "managed_initrd_sha256": sha256(initrd),
    "managed_iso_sha256": sha256(iso),
    "payload_manifest_sha256": sha256(payload_path),
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

managed_size = managed_size_path.read_text(encoding="ascii")
if (
    not managed_size.endswith("\n")
    or not managed_size[:-1].isdigit()
    or managed_size[:-1].startswith("0")
):
    raise SystemExit("managed ISO size is invalid")
if int(managed_size) != iso.stat().st_size:
    raise SystemExit("managed ISO size does not match")

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

ca_text = ca_path.read_text(encoding="ascii")
ca_upper = ca_text.upper()
for forbidden in ("PRIVATE KEY", "PASSWORD", "CREDENTIAL", "SECRET"):
    if forbidden in ca_upper:
        raise SystemExit("CA certificate contains secret-like material")
ca_match = re.fullmatch(
    r"-----BEGIN CERTIFICATE-----\n"
    r"([A-Za-z0-9+/=\n]+)"
    r"-----END CERTIFICATE-----\n",
    ca_text,
)
if ca_match is None:
    raise SystemExit("CA certificate PEM is invalid")
ca_der = base64.b64decode(
    "".join(ca_match.group(1).splitlines()), validate=True
)
if len(ca_der) < 4 or ca_der[0] != 0x30:
    raise SystemExit("CA certificate DER is invalid")
try:
    ssl._ssl._test_decode_cert(str(ca_path))
except (OSError, ssl.SSLError, ValueError):
    raise SystemExit("CA certificate X.509 structure is invalid")

expected_payload = [
    "lib/initrd/post/network-up/99-alt-install-agent-v1",
    "lib/initrd/post/network-up/99-alt-install-execution-v2",
    "usr/libexec/alt-install-agent",
    "usr/libexec/alt-install-helper",
    "usr/libexec/alt-install-agent-lib/lib/config.sh",
    "usr/libexec/alt-install-agent-lib/lib/dhcp-hook.sh",
    "usr/libexec/alt-install-agent-lib/lib/network.sh",
    "usr/libexec/alt-install-agent-lib/lib/protocol.sh",
    "usr/libexec/alt-install-agent-lib/lib/state.sh",
    "usr/libexec/alt-install-agent-lib/lib/transport.sh",
    "usr/libexec/alt-install-agent-lib/lib/ui.sh",
    "usr/libexec/alt-install-agent-v2/alt-install-execution-agent",
    "usr/libexec/alt-install-agent-v2/lib/config.sh",
    "usr/libexec/alt-install-agent-v2/lib/protocol.sh",
    "usr/libexec/alt-install-agent-v2/lib/ui.sh",
    "usr/share/alt-install/build-id",
    "usr/share/alt-install/controller-url",
    "usr/share/alt-install/execution-ca.pem",
    "usr/share/alt-install/execution-controller-url",
    "usr/share/alt-install/managed_iso_size_bytes",
    "usr/share/alt-install/public-key.json",
    "usr/share/alt-install/source_iso.json",
]
observed_payload = []
for line in payload_path.read_text(encoding="ascii").splitlines():
    match = re.fullmatch(r"[0-9a-f]{64}  ([^\x00\r\n]+)", line)
    if match is None:
        raise SystemExit("payload checksum line is invalid")
    observed_payload.append(match.group(1))
if observed_payload != expected_payload:
    raise SystemExit("managed payload is not exact")
for relative in expected_payload:
    path = root / relative
    if not path.is_file() or path.is_symlink():
        raise SystemExit(f"managed payload file is unsafe: {relative}")

runtime_expected = {
    relative
    for relative in expected_payload
    if relative.startswith("usr/libexec/alt-install-agent")
}
runtime_observed = set()
for runtime_root in (
    root / "usr/libexec/alt-install-agent-lib",
    root / "usr/libexec/alt-install-agent-v2",
):
    for path in runtime_root.rglob("*"):
        if path.is_file() or path.is_symlink():
            runtime_observed.add(path.relative_to(root).as_posix())
runtime_observed.add("usr/libexec/alt-install-agent")
if runtime_observed != runtime_expected:
    raise SystemExit("managed runtime file set is not exact")

share_files = sorted(
    path.name
    for path in (root / "usr/share/alt-install").iterdir()
    if path.is_file() and not path.is_symlink()
)
if share_files != sorted(
    [
        "build-id",
        "controller-url",
        "execution-ca.pem",
        "execution-controller-url",
        "managed_iso_size_bytes",
        "payload.sha256",
        "public-key.json",
        "source_iso.json",
    ]
):
    raise SystemExit("managed identity payload files are not exact")
for relative in expected_payload:
    name = Path(relative).name.lower()
    if any(token in name for token in ("private", "password", "credential", "secret")):
        raise SystemExit("secret-like managed payload filename is forbidden")

raw_helper = helper.read_bytes()
if len(raw_helper) < 64 or raw_helper[:6] != b"\x7fELF\x02\x01":
    raise SystemExit("helper is not a Linux amd64 ELF")
if struct.unpack_from("<H", raw_helper, 18)[0] != 62:
    raise SystemExit("helper architecture is invalid")
program_offset = struct.unpack_from("<Q", raw_helper, 32)[0]
entry_size = struct.unpack_from("<H", raw_helper, 54)[0]
entry_count = struct.unpack_from("<H", raw_helper, 56)[0]
if entry_size < 56 or entry_count == 0:
    raise SystemExit("helper program headers are invalid")
for index in range(entry_count):
    offset = program_offset + index * entry_size
    if offset + 4 > len(raw_helper):
        raise SystemExit("helper program headers are truncated")
    if struct.unpack_from("<I", raw_helper, offset)[0] == 3:
        raise SystemExit("helper has a dynamic interpreter")
verified_digest_path.write_text(
    checks["managed_iso_sha256"] + "\n", encoding="ascii"
)
PY

mode_is() {
    local expected="$1" path="$2"
    [[ -f "$path" && ! -L "$path" ]] ||
        die "Managed payload file is unsafe: ${path#$workdir/initrd/}"
    [[ "$(stat -c '%a' "$path")" == "$expected" ]] ||
        die "Unexpected mode for ${path#$workdir/initrd/}"
}

mode_is 755 \
    "$workdir/initrd/lib/initrd/post/network-up/99-alt-install-agent-v1"
mode_is 755 \
    "$workdir/initrd/lib/initrd/post/network-up/99-alt-install-execution-v2"
mode_is 755 "$workdir/initrd/usr/libexec/alt-install-agent"
mode_is 755 "$workdir/initrd/usr/libexec/alt-install-helper"
mode_is 755 \
    "$workdir/initrd/usr/libexec/alt-install-agent-lib/lib/dhcp-hook.sh"
for library in config.sh network.sh protocol.sh state.sh transport.sh ui.sh; do
    mode_is 644 \
        "$workdir/initrd/usr/libexec/alt-install-agent-lib/lib/$library"
done
mode_is 755 \
    "$workdir/initrd/usr/libexec/alt-install-agent-v2/alt-install-execution-agent"
for library in config.sh protocol.sh ui.sh; do
    mode_is 644 \
        "$workdir/initrd/usr/libexec/alt-install-agent-v2/lib/$library"
done
for asset in build-id controller-url execution-ca.pem \
    execution-controller-url managed_iso_size_bytes payload.sha256 \
    public-key.json source_iso.json; do
    mode_is 644 "$workdir/initrd/usr/share/alt-install/$asset"
done

initrd_command() {
    local command="$1" directory candidate
    for directory in bin sbin usr/bin usr/sbin; do
        candidate="$workdir/initrd/$directory/$command"
        if [[ -f "$candidate" && ! -L "$candidate" &&
            -x "$candidate" ]]; then
            return 0
        fi
    done
    die "Required initrd command is missing: $command"
}

for command in bash blkid cat chmod curl date grep head ip kill mkdir \
    mv od rm sleep tr udhcpc wc; do
    initrd_command "$command"
done

v2_gate="$workdir/initrd/lib/initrd/post/network-up/99-alt-install-execution-v2"
grep -Fqx \
    "if grep -Fqw 'sosnadmin.mode=agent-v2' \"\$cmdline_file\"; then" \
    "$v2_gate" || die 'V2 initrd gate condition is invalid'
grep -Fqx \
    '    export ALT_INSTALL_V1_AGENT_ROOT=${ALT_INSTALL_V1_AGENT_ROOT:-/usr/libexec/alt-install-agent-lib}' \
    "$v2_gate" || die 'V2 V1-library binding is invalid'
grep -Fqx '    exec "$agent"' "$v2_gate" ||
    die 'V2 initrd execution target is invalid'

python3 "$contract" menu \
    --manifest "$manifest" \
    --grub "$workdir/grub.cfg" \
    --isolinux "$workdir/isolinux.cfg" \
    --v1-controller \
    "$workdir/initrd/usr/share/alt-install/controller-url" \
    --v2-controller \
    "$workdir/initrd/usr/share/alt-install/execution-controller-url" ||
    die 'Boot menu contract verification failed'

printf 'managed_iso_verified=true\n'
printf 'managed_iso_sha256=%s\n' "$(<"$workdir/managed-iso.sha256")"
