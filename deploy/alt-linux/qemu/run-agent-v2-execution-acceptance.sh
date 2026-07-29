#!/bin/bash
set -Eeuo pipefail

readonly target_virtual_size=64G
readonly sentinel_virtual_size=8M
readonly target_format=qcow2
readonly pass_line='PASS: root-authorized install wrote only the disposable target; authenticated postflight installed'

usage() {
    printf '%s\n' \
        'Usage: run-agent-v2-execution-acceptance.sh --iso <V2-ISO> --ovmf-code <OVMF_CODE.fd> --ovmf-vars <OVMF_VARS.fd> --timeline <ROOT-TIMELINE.json> --postflight <AUTHENTICATED-POSTFLIGHT.json> [--evidence-dir <DIR>]' \
        '       run-agent-v2-execution-acceptance.sh --check-prerequisites' \
        '       run-agent-v2-execution-acceptance.sh --exercise-storage-contract' \
        '       run-agent-v2-execution-acceptance.sh --describe-safety-contract' >&2
    exit 2
}

die() {
    printf 'agent-v2-qemu: %s\n' "$*" >&2
    exit 1
}

check_prerequisites() {
    local missing=0 command
    local required=(
        qemu-system-x86_64 qemu-img python3 bash xorriso cpio socat
        sha256sum mktemp readlink id ip dnsmasq grep cp chmod mkdir
        date sleep seq dirname rm stat sed tail kill
    )
    for command in "${required[@]}"; do
        if ! command -v "$command" >/dev/null 2>&1; then
            printf 'agent-v2-qemu: Missing required command: %s\n' \
                "$command" >&2
            missing=1
        fi
    done
    if command -v python3 >/dev/null 2>&1; then
        if ! python3 -c \
            'import cryptography, socket; raise SystemExit(0 if hasattr(socket, "AF_UNIX") else 1)' \
            >/dev/null 2>&1; then
            printf '%s\n' \
                'agent-v2-qemu: Required Python cryptography/AF_UNIX support is unavailable' >&2
            missing=1
        fi
    fi
    if ((EUID != 0)); then
        printf '%s\n' \
            'agent-v2-qemu: Real root execution is required for execution authorization and TAP ownership' >&2
        missing=1
    fi
    ((missing == 0))
}

describe_safety_contract() {
    printf '%s\n' \
        'target_input=none' \
        'firmware=generic-ovmf' \
        'target_device=/dev/vda' \
        "target_virtual_size=$target_virtual_size" \
        'target_drive=qcow2,writable' \
        "sentinel_virtual_size=$sentinel_virtual_size" \
        'sentinel_drive=qcow2,readonly=on' \
        'iso_first_boot=required' \
        'iso_postflight_boot=absent' \
        'network=tap,harness-created' \
        'cleanup=qemu,tap,temporary-directory;validated-harness-owned-only'
}

workdir=
target=
sentinel=
target_drive=
sentinel_drive=
contract_root=
contract_workdir=

prepare_storage() {
    target="$workdir/target.qcow2"
    sentinel="$workdir/sentinel.qcow2"
    case "$target:$sentinel" in
        "$workdir"/target.qcow2:"$workdir"/sentinel.qcow2) ;;
        *) die 'Disposable storage escaped the harness work directory' ;;
    esac
    case "$workdir" in
        *,*) die 'Disposable work paths containing commas are unsupported' ;;
    esac
    qemu-img create -f "$target_format" "$target" "$target_virtual_size" \
        >"$workdir/qemu-img.log" 2>&1 ||
        die 'Disposable target creation failed'
    qemu-img create -f "$target_format" "$sentinel" "$sentinel_virtual_size" \
        >>"$workdir/qemu-img.log" 2>&1 ||
        die 'Read-only sentinel creation failed'
    target_drive="id=target,if=none,format=$target_format,file=$target,cache=none"
    sentinel_drive="id=sentinel,if=none,format=$target_format,file=$sentinel,cache=none,readonly=on"
}

cleanup_storage_contract() {
    case "$contract_workdir" in
        "$contract_root"/.alt-agent-v2-storage-contract.*)
            rm -rf -- "$contract_workdir"
            ;;
    esac
}

exercise_storage_contract() {
    local command
    for command in qemu-img mktemp readlink mkdir chmod rm; do
        command -v "$command" >/dev/null 2>&1 ||
            die "Missing storage-contract command: $command"
    done
    contract_root=${TMPDIR:-/tmp}
    contract_root=$(readlink -f -- "$contract_root") ||
        die 'Cannot resolve storage-contract temporary root'
    [[ -d "$contract_root" ]] ||
        die 'Storage-contract temporary root is not a directory'
    workdir=$(mktemp -d \
        "$contract_root/.alt-agent-v2-storage-contract.XXXXXX")
    chmod 0700 -- "$workdir"
    workdir=$(readlink -f -- "$workdir") ||
        die 'Cannot resolve storage-contract work directory'
    contract_workdir=$workdir
    case "$workdir" in
        "$contract_root"/.alt-agent-v2-storage-contract.*) ;;
        *) die 'Storage-contract work directory escaped its temporary root' ;;
    esac
    trap cleanup_storage_contract EXIT
    prepare_storage
    printf '%s\n' \
        "workdir=$workdir" \
        "target=$target" \
        "sentinel=$sentinel" \
        "target_drive=$target_drive" \
        "sentinel_drive=$sentinel_drive"
    cleanup_storage_contract
    [[ ! -e "$workdir" ]] ||
        die 'Storage-contract work directory cleanup failed'
    trap - EXIT
    contract_workdir=
    printf '%s\n' 'cleanup=removed'
}

if (($# == 1)) && [[ "$1" == --check-prerequisites ]]; then
    check_prerequisites || exit 1
    printf '%s\n' 'QEMU execution acceptance prerequisites are available'
    exit 0
fi
if (($# == 1)) && [[ "$1" == --exercise-storage-contract ]]; then
    exercise_storage_contract
    exit 0
fi
if (($# == 1)) && [[ "$1" == --describe-safety-contract ]]; then
    describe_safety_contract
    exit 0
fi

iso=
ovmf_code=
ovmf_vars=
timeline=
postflight=
evidence_root=
while (($#)); do
    case "$1" in
        --iso)
            (($# >= 2)) || usage
            iso=$2
            shift 2
            ;;
        --ovmf-code)
            (($# >= 2)) || usage
            ovmf_code=$2
            shift 2
            ;;
        --ovmf-vars)
            (($# >= 2)) || usage
            ovmf_vars=$2
            shift 2
            ;;
        --timeline)
            (($# >= 2)) || usage
            timeline=$2
            shift 2
            ;;
        --postflight)
            (($# >= 2)) || usage
            postflight=$2
            shift 2
            ;;
        --evidence-dir)
            (($# >= 2)) || usage
            evidence_root=$2
            shift 2
            ;;
        *)
            usage
            ;;
    esac
done
[[ -n "$iso" && -n "$ovmf_code" && -n "$ovmf_vars" &&
    -n "$timeline" && -n "$postflight" ]] || usage
check_prerequisites || exit 1

script_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo_root=$(cd -- "$script_root/../../.." && pwd -P)
support="$script_root/agent_v2_test_api.py"
iso_verifier="$repo_root/deploy/alt-linux/iso/agent-v2/verify-managed-iso.sh"
for path in "$iso" "$ovmf_code" "$ovmf_vars" "$support" "$iso_verifier"; do
    [[ -f "$path" && -r "$path" && ! -L "$path" ]] ||
        die "Required regular file is unreadable: $path"
done
for path in "$iso" "$ovmf_code" "$ovmf_vars"; do
    case "$path" in
        *,*) die "Input paths containing commas are unsupported: $path" ;;
    esac
done
bash "$iso_verifier" --iso "$iso" >/dev/null ||
    die 'V2 managed ISO verification failed'

evidence_root=${evidence_root:-"$PWD/acceptance"}
mkdir -p -- "$evidence_root"
evidence_root=$(readlink -f -- "$evidence_root") ||
    die 'Cannot resolve evidence root'
case "$evidence_root" in
    /|/home|/root) die 'Evidence root is too broad' ;;
    *,*) die 'Evidence root paths containing commas are unsupported' ;;
esac
[[ -d "$evidence_root" ]] || die 'Evidence root is not a directory'
run_id="agent-v2-$(date -u +%Y%m%dT%H%M%SZ)-$$"
evidence="$evidence_root/$run_id"
mkdir -m 0755 -- "$evidence"
workdir=$(mktemp -d "$evidence_root/.alt-agent-v2-qemu-work.XXXXXX")
chmod 0700 -- "$workdir"
workdir=$(readlink -f -- "$workdir") ||
    die 'Cannot resolve QEMU work directory'
case "$workdir" in
    "$evidence_root"/.alt-agent-v2-qemu-work.*) ;;
    *) die 'QEMU work directory escaped its evidence root' ;;
esac

qemu_pid=
dnsmasq_pid=
tap_name="aiv2$(( $$ % 100000 ))"
tap_created=0

stop_qemu() {
    local qmp_socket=${1:-}
    if [[ -n "$qemu_pid" ]] && kill -0 "$qemu_pid" 2>/dev/null; then
        if [[ -n "$qmp_socket" && -S "$qmp_socket" ]]; then
            python3 "$support" qmp-command \
                --socket "$qmp_socket" --execute quit >/dev/null 2>&1 ||
                kill "$qemu_pid" 2>/dev/null || true
        else
            kill "$qemu_pid" 2>/dev/null || true
        fi
        wait "$qemu_pid" 2>/dev/null || true
    fi
    qemu_pid=
}

cleanup() {
    stop_qemu
    if [[ -n "$dnsmasq_pid" ]] &&
        kill -0 "$dnsmasq_pid" 2>/dev/null; then
        kill "$dnsmasq_pid" 2>/dev/null || true
        wait "$dnsmasq_pid" 2>/dev/null || true
    fi
    if ((tap_created == 1)) &&
        [[ "$tap_name" == aiv2+([0-9]) ]] &&
        [[ -e "/sys/class/net/$tap_name" ]]; then
        ip link set "$tap_name" down 2>/dev/null || true
        ip tuntap del dev "$tap_name" mode tap 2>/dev/null || true
    fi
    case "$workdir" in
        "$evidence_root"/.alt-agent-v2-qemu-work.*)
            rm -rf -- "$workdir"
            ;;
    esac
}
shopt -s extglob
trap cleanup EXIT

prepare_storage
(
    cd -- "$workdir"
    sha256sum target.qcow2
) >"$evidence/target.before.sha256"
(
    cd -- "$workdir"
    sha256sum sentinel.qcow2
) >"$evidence/sentinel.before.sha256"
cp -- "$ovmf_vars" "$workdir/OVMF_VARS.fd"

[[ ! -e "/sys/class/net/$tap_name" ]] ||
    die 'Selected harness TAP name is already in use'
ip tuntap add dev "$tap_name" mode tap user "$(id -u)" ||
    die 'Harness TAP creation failed'
tap_created=1
ip address add 192.168.100.17/24 dev "$tap_name" ||
    die 'Harness TAP address assignment failed'
ip link set "$tap_name" up || die 'Harness TAP activation failed'
dnsmasq \
    --keep-in-foreground \
    --bind-interfaces \
    --interface="$tap_name" \
    --except-interface=lo \
    --dhcp-range=192.168.100.50,192.168.100.60,255.255.255.0,10m \
    --dhcp-option=3 \
    --dhcp-option=6 \
    --pid-file= \
    --conf-file= \
    >"$workdir/dnsmasq.log" 2>&1 &
dnsmasq_pid=$!

wait_for_socket() {
    local socket_path=$1 seconds=$2 elapsed
    for ((elapsed = 0; elapsed < seconds; elapsed++)); do
        [[ -S "$socket_path" ]] && return 0
        [[ -n "$qemu_pid" ]] && kill -0 "$qemu_pid" 2>/dev/null ||
            return 1
        sleep 1
    done
    return 1
}

wait_for_line() {
    local log_path=$1 pattern=$2 seconds=$3 elapsed
    for ((elapsed = 0; elapsed < seconds; elapsed++)); do
        if [[ -f "$log_path" ]] && grep -Fq -- "$pattern" "$log_path"; then
            return 0
        fi
        [[ -n "$qemu_pid" ]] && kill -0 "$qemu_pid" 2>/dev/null ||
            return 1
        sleep 1
    done
    return 1
}

wait_for_private_root_evidence() {
    local path=$1 seconds=$2 elapsed mode owner
    for ((elapsed = 0; elapsed < seconds; elapsed++)); do
        if [[ -f "$path" && ! -L "$path" ]]; then
            mode=$(stat -c '%a' "$path") || return 1
            owner=$(stat -c '%u' "$path") || return 1
            [[ "$mode" == 600 && "$owner" == 0 ]] || return 1
            return 0
        fi
        sleep 1
    done
    return 1
}

launch_qemu() {
    local boot_iso=$1 phase=$2
    local qmp_socket="$workdir/$phase.qmp.sock"
    local console="$workdir/$phase.console.log"
    local -a media=()
    [[ -z "$boot_iso" ]] ||
        media=(-drive "media=cdrom,readonly=on,file=$boot_iso")
    qemu-system-x86_64 \
        -machine q35,accel=kvm:tcg \
        -m 4096 \
        -uuid 22222222-3333-4444-5555-666666666662 \
        -smbios type=1,manufacturer=QEMU,product=Standard-PC,serial=agent-v2-execution \
        -drive "if=pflash,format=raw,readonly=on,file=$ovmf_code" \
        -drive "if=pflash,format=raw,file=$workdir/OVMF_VARS.fd" \
        -drive "$target_drive" \
        -device virtio-blk-pci,drive=target,serial=ALT-QEMU-TARGET \
        -drive "$sentinel_drive" \
        -device virtio-blk-pci,drive=sentinel,serial=ALT-QEMU-SENTINEL \
        "${media[@]}" \
        -netdev tap,id=agent-net,ifname="$tap_name",script=no,downscript=no \
        -device virtio-net-pci,netdev=agent-net,mac=52:54:00:12:34:62 \
        -boot order="$([[ -n "$boot_iso" ]] && printf d || printf c)",menu=on \
        -serial "file:$console" \
        -qmp "unix:$qmp_socket,server=on,wait=off" \
        -display none \
        >"$workdir/$phase.qemu.log" 2>&1 &
    qemu_pid=$!
    wait_for_socket "$qmp_socket" 60 ||
        die "$phase QMP socket did not become available"
}

install_qmp="$workdir/install.qmp.sock"
launch_qemu "$iso" install
wait_for_line "$workdir/install.console.log" \
    'terminal=execution_pending' 1200 ||
    die 'Guest never proved its pre-authorization execution hold'
python3 "$support" qmp-query \
    --socket "$install_qmp" \
    --output "$evidence/before-authorization.qmp.jsonl" ||
    die 'Pre-authorization QMP capture failed'

wait_for_line "$workdir/install.console.log" \
    'ALT install execution: verified_handoff' 900 ||
    die 'Verified execution handoff was not observed'
wait_for_line "$workdir/install.console.log" \
    'ALT install execution: installer_completed' 7200 ||
    die 'Stock installer completion was not observed'
python3 "$support" qmp-query \
    --socket "$install_qmp" \
    --output "$evidence/after-install.qmp.jsonl" ||
    die 'Post-install QMP capture failed'
stop_qemu "$install_qmp"

postflight_qmp="$workdir/postflight.qmp.sock"
launch_qemu '' postflight
wait_for_private_root_evidence "$postflight" 1200 ||
    die 'Authenticated postflight evidence did not become available'
wait_for_private_root_evidence "$timeline" 60 ||
    die 'Completed root authorization timeline did not become available'
stop_qemu "$postflight_qmp"

(
    cd -- "$workdir"
    sha256sum target.qcow2
) >"$evidence/target.after.sha256"
(
    cd -- "$workdir"
    sha256sum sentinel.qcow2
) >"$evidence/sentinel.after.sha256"
cp -- "$timeline" "$evidence/authorization-timeline.json"
cp -- "$postflight" "$evidence/postflight.json"
printf 'evidence_dir=%s\n' "$evidence"
python3 "$support" finalize-evidence \
    --before-qmp "$evidence/before-authorization.qmp.jsonl" \
    --after-qmp "$evidence/after-install.qmp.jsonl" \
    --target-before-sha "$evidence/target.before.sha256" \
    --target-after-sha "$evidence/target.after.sha256" \
    --sentinel-before-sha "$evidence/sentinel.before.sha256" \
    --sentinel-after-sha "$evidence/sentinel.after.sha256" \
    --timeline "$evidence/authorization-timeline.json" \
    --postflight "$evidence/postflight.json" \
    --output "$evidence/acceptance-receipt.json"
