#!/bin/bash
set -Eeuo pipefail

usage() {
    printf '%s\n' 'Usage: run-spike-readonly-acceptance.sh --iso <ISO> --ovmf-code <OVMF_CODE.fd> --ovmf-vars <OVMF_VARS.fd> --target <disk.img> --fixture-url <http://192.168.100.17:18089> --fixture-state <DIR> [--evidence-dir <DIR>]' >&2
    exit 2
}
die() { printf 'qemu-spike-acceptance: %s\n' "$*" >&2; exit 1; }

iso= ovmf_code= ovmf_vars= target= fixture_url= fixture_state= evidence_root=
while (($#)); do
    case "$1" in
        --iso) iso="${2:-}"; shift 2 ;;
        --ovmf-code) ovmf_code="${2:-}"; shift 2 ;;
        --ovmf-vars) ovmf_vars="${2:-}"; shift 2 ;;
        --target) target="${2:-}"; shift 2 ;;
        --fixture-url) fixture_url="${2:-}"; shift 2 ;;
        --fixture-state) fixture_state="${2:-}"; shift 2 ;;
        --evidence-dir) evidence_root="${2:-}"; shift 2 ;;
        *) usage ;;
    esac
done
[[ -n "$iso" && -n "$ovmf_code" && -n "$ovmf_vars" && -n "$target" && -n "$fixture_url" && -n "$fixture_state" ]] || usage
[[ "$fixture_url" == 'http://192.168.100.17:18089' ]] || die 'PR1 accepts only the isolated fixture URL'
for path in "$iso" "$ovmf_code" "$ovmf_vars" "$target"; do [[ -r "$path" ]] || die "Unreadable path: $path"; done
[[ -d "$fixture_state" ]] || die "Fixture state directory is missing"
for command in qemu-system-x86_64 qemu-img socat sha256sum python3 grep mktemp; do command -v "$command" >/dev/null || die "Missing required command: $command"; done

evidence_root=${evidence_root:-"${PWD}/acceptance"}
run_id="spike-$(date -u +%Y%m%dT%H%M%SZ)-$$"
evidence="$evidence_root/$run_id"
mkdir -p "$evidence"
vnc_socket="$evidence/vnc.sock"
qmp="$evidence/qmp.sock"
qemu_pid=
hotkey_pid=

cleanup() {
    if [[ -n "$hotkey_pid" ]] && kill -0 "$hotkey_pid" 2>/dev/null; then
        kill "$hotkey_pid" 2>/dev/null || true
        wait "$hotkey_pid" 2>/dev/null || true
    fi
    if [[ -n "$qemu_pid" ]] && kill -0 "$qemu_pid" 2>/dev/null; then
        kill "$qemu_pid" 2>/dev/null || true
        wait "$qemu_pid" 2>/dev/null || true
    fi
}
trap cleanup EXIT

sha256sum "$target" > "$evidence/target.before.sha256"
cp -- "$ovmf_vars" "$evidence/OVMF_VARS.fd"

qemu-system-x86_64 \
    -machine q35,accel=kvm:tcg -m 4096 -no-reboot \
    -drive if=pflash,format=raw,readonly=on,file="$ovmf_code" \
    -drive if=pflash,format=raw,file="$evidence/OVMF_VARS.fd" \
    -drive id=target,if=none,format=raw,file="$target",readonly=on \
    -device virtio-blk-pci,drive=target \
    -drive media=cdrom,readonly=on,file="$iso" \
    -netdev user,id=spike-net,net=192.168.100.0/24,host=192.168.100.17,dhcpstart=192.168.100.50 \
    -device virtio-net-pci,netdev=spike-net \
    -vnc "unix:$vnc_socket" \
    -boot order=d -serial "file:$evidence/guest-console.log" \
    -qmp "unix:$qmp,server=on,wait=off" \
    >"$evidence/qemu.log" 2>&1 &
qemu_pid=$!

for _ in $(seq 1 60); do [[ -S "$qmp" ]] && break; sleep 1; done
[[ -S "$qmp" ]] || die 'QMP socket did not become available'
qmp_query() {
    local destination="$1"
    printf '%s\n' '{"execute":"qmp_capabilities"}' '{"execute":"query-blockstats"}' \
        | socat -T 3 - "UNIX-CONNECT:$qmp" > "$destination"
}
qmp_send_managed_hotkey() {
    python3 - "$qmp" <<'PY'
import json
import socket
import sys

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.settimeout(1)
sock.connect(sys.argv[1])
sock.recv(65536)
for request in (
    {"execute": "qmp_capabilities"},
    {"execute": "send-key", "arguments": {"keys": [{"type": "qcode", "data": "s"}]}},
):
    sock.sendall((json.dumps(request) + "\n").encode())
    sock.recv(65536)
PY
}
vnc_send_managed_hotkey() {
    python3 - "$vnc_socket" <<'PY'
import socket
import struct
import sys

def receive_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise RuntimeError("VNC server closed the connection")
        data.extend(chunk)
    return bytes(data)

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.settimeout(1)
sock.connect(sys.argv[1])
version = receive_exact(sock, 12)
if not version.startswith(b"RFB 003."):
    raise RuntimeError(f"unexpected VNC version: {version!r}")
sock.sendall(version)
security_count = receive_exact(sock, 1)[0]
security_types = receive_exact(sock, security_count)
if 1 not in security_types:
    raise RuntimeError(f"VNC None security is unavailable: {security_types!r}")
sock.sendall(b"\x01")
if receive_exact(sock, 4) != b"\x00\x00\x00\x00":
    raise RuntimeError("VNC security handshake failed")
sock.sendall(b"\x01")
header = receive_exact(sock, 24)
name_length = struct.unpack(">I", header[20:24])[0]
receive_exact(sock, name_length)
key = struct.pack(">BBHI", 4, 1, 0, ord("s"))
sock.sendall(key)
sock.sendall(struct.pack(">BBHI", 4, 0, 0, ord("s")))
PY
}
qmp_query "$evidence/before.json"

fixture_status() {
    python3 - "$fixture_state" <<'PY'
import json
import sys
from pathlib import Path

records = sorted(Path(sys.argv[1]).glob("spike-*/session.json"))
if not records:
    raise SystemExit(1)
record = json.loads(records[-1].read_text(encoding="utf-8"))
print(record["session_id"], record["decision"], record.get("states", []).count("spike_approved"))
PY
}
wait_for_fixture_decision() {
    local expected="$1" seconds="$2" status session decision approved_count
    for _ in $(seq 1 "$seconds"); do
        status=$(fixture_status 2>/dev/null || true)
        if [[ -n "$status" ]]; then
            read -r session decision approved_count <<< "$status"
            if [[ "$decision" == "$expected" ]]; then
                printf '%s\n' "$session"
                return 0
            fi
        fi
        sleep 1
    done
    return 1
}

# The ISO timeout after ten seconds deliberately returns to the local disk. Send
# the explicit GRUB hotkey throughout the firmware-to-GRUB hand-off; OVMF under
# TCG can take several minutes before the menu is ready to receive a key.
(
    for _ in $(seq 1 300); do
        vnc_send_managed_hotkey || qmp_send_managed_hotkey || true
        sleep 1
    done
) &
hotkey_pid=$!
session=$(wait_for_fixture_decision waiting 260) || die 'Guest did not create a waiting fixture session'
kill "$hotkey_pid" 2>/dev/null || true
wait "$hotkey_pid" 2>/dev/null || true
hotkey_pid=
cp -- "$fixture_state/$session/session.json" "$evidence/session.waiting.json"
printf '%s\n' "Guest session $session is waiting. Approve it, then this harness will require spike_approved." >&2
wait_for_fixture_decision approved 600 >/dev/null || die 'Fixture session did not become approved'
for _ in $(seq 1 30); do
    state_count=$(fixture_status 2>/dev/null | awk '{print $3}')
    [[ "${state_count:-0}" -ge 2 ]] && break
    sleep 1
done
[[ "${state_count:-0}" -ge 2 ]] || die 'Guest did not report two spike_approved heartbeats'
cp -- "$fixture_state/$session/session.json" "$evidence/session.approved.json"
qmp_query "$evidence/after.json"
sha256sum "$target" > "$evidence/target.after.sha256"
cmp -s "$evidence/target.before.sha256" "$evidence/target.after.sha256" || die 'Target disk hash changed'

python3 - "$evidence/before.json" "$evidence/after.json" <<'PY'
import json
import sys

for filename in sys.argv[1:]:
    writes = []
    for line in open(filename, encoding="utf-8"):
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        for block in message.get("return", []):
            if block.get("device") != "target":
                continue
            stats = block.get("stats", {})
            for key, value in stats.items():
                if key.startswith("wr_") and isinstance(value, int) and value != 0:
                    writes.append((key, value))
    if writes:
        raise SystemExit(f"non-zero QMP write statistics in {filename}: {writes}")
PY

printf '%s\n' "evidence_dir=$evidence" 'PASS: no target-disk write I/O'
