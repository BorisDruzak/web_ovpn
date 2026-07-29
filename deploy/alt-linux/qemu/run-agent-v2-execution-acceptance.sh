#!/bin/bash
set -Eeuo pipefail

readonly target_virtual_size=64G
readonly sentinel_virtual_size=8M
readonly target_format=qcow2
readonly pass_line='PASS: root-authorized install wrote only the disposable target; authenticated postflight installed'

usage() {
    printf '%s\n' \
        'Usage: run-agent-v2-execution-acceptance.sh --iso <V2-ISO> --ovmf-code <OVMF_CODE.fd> --ovmf-vars <OVMF_VARS.fd> --controller-credential-key <KEY> [--evidence-dir <DIR>]' \
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
        date sleep seq dirname rm stat sed tail kill awk
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
            rm -f -- \
                "$contract_workdir/target.qcow2" \
                "$contract_workdir/sentinel.qcow2" \
                "$contract_workdir/qemu-img.log"
            rmdir -- "$contract_workdir" 2>/dev/null || true
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
controller_credential_key=
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
        --controller-credential-key)
            (($# >= 2)) || usage
            controller_credential_key=$2
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
    -n "$controller_credential_key" ]] || usage
check_prerequisites || exit 1

script_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo_root=$(cd -- "$script_root/../../.." && pwd -P)
support="$script_root/agent_v2_test_api.py"
execution_server="$repo_root/deploy/alt-linux/api/install_execution_server.py"
iso_verifier="$repo_root/deploy/alt-linux/iso/agent-v2/verify-managed-iso.sh"
for path in "$iso" "$ovmf_code" "$ovmf_vars" "$support" "$iso_verifier" \
    "$execution_server" "$controller_credential_key"; do
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
iso=$(readlink -f -- "$iso") ||
    die 'Cannot resolve verified V2 ISO'

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
workdir_ownership_record="$evidence/workdir-ownership.json"
early_workdir_cleanup() {
    if [[ -n "$workdir" &&
        -f "$workdir_ownership_record" &&
        ! -L "$workdir_ownership_record" ]]; then
        python3 "$support" remove-owned-workdir \
            --record "$workdir_ownership_record" \
            --workdir "$workdir" >/dev/null 2>&1 || true
    fi
}
trap early_workdir_cleanup EXIT
workdir=$(mktemp -d "$evidence_root/.alt-agent-v2-qemu-work.XXXXXX")
python3 "$support" record-workdir-ownership \
    --record "$workdir_ownership_record" \
    --workdir "$workdir" ||
    die 'Harness work directory identity recording failed'
chmod 0700 -- "$workdir"
workdir=$(readlink -f -- "$workdir") ||
    die 'Cannot resolve QEMU work directory'
case "$workdir" in
    "$evidence_root"/.alt-agent-v2-qemu-work.*) ;;
    *) die 'QEMU work directory escaped its evidence root' ;;
esac

qemu_pid=
qemu_starttime=
dnsmasq_pid=
dnsmasq_starttime=
execution_server_pid=
execution_server_starttime=
tap_name="aiv2$(( $$ % 100000 ))"
tap_created=0
tap_ownership_record="$evidence/tap-ownership.json"

process_starttime() {
    local pid=$1
    [[ "$pid" =~ ^[1-9][0-9]*$ && -r "/proc/$pid/stat" ]] ||
        return 1
    awk '{print $22}' "/proc/$pid/stat"
}

owned_process_alive() {
    local pid=$1 expected=$2 observed
    observed=$(process_starttime "$pid") || return 1
    [[ "$observed" == "$expected" ]] || return 1
    kill -0 "$pid" 2>/dev/null
}

stop_qemu() {
    local qmp_socket=${1:-}
    if [[ -n "$qemu_pid" ]] &&
        owned_process_alive "$qemu_pid" "$qemu_starttime"; then
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
    qemu_starttime=
}

cleanup() {
    stop_qemu
    if [[ -n "$execution_server_pid" ]] &&
        owned_process_alive \
            "$execution_server_pid" "$execution_server_starttime"; then
        kill "$execution_server_pid" 2>/dev/null || true
        wait "$execution_server_pid" 2>/dev/null || true
    fi
    if [[ -n "$dnsmasq_pid" ]] &&
        owned_process_alive "$dnsmasq_pid" "$dnsmasq_starttime"; then
        kill "$dnsmasq_pid" 2>/dev/null || true
        wait "$dnsmasq_pid" 2>/dev/null || true
    fi
    if ((tap_created == 1)); then
        if [[ -f "$tap_ownership_record" && ! -L "$tap_ownership_record" ]]; then
            python3 "$support" delete-owned-tap \
                --record "$tap_ownership_record" >/dev/null 2>&1 || {
                printf '%s\n' \
                    'agent-v2-qemu: TAP identity changed; preserving TAP' >&2
            }
        else
            printf '%s\n' \
                'agent-v2-qemu: TAP identity absent; preserving TAP' >&2
        fi
    fi
    if [[ -f "$workdir_ownership_record" &&
        ! -L "$workdir_ownership_record" ]]; then
        python3 "$support" remove-owned-workdir \
            --record "$workdir_ownership_record" \
            --workdir "$workdir" >/dev/null 2>&1 || {
            printf '%s\n' \
                'agent-v2-qemu: workdir identity changed; preserving workdir' >&2
        }
    else
        printf '%s\n' \
            'agent-v2-qemu: workdir identity absent; preserving workdir' >&2
    fi
}
shopt -s extglob
trap cleanup EXIT

prepare_storage
state_dir="$workdir/run-state"
mkdir -m 0700 -- "$state_dir"
vm_instance_id=$(python3 -c 'import uuid; print(uuid.uuid4())')
python3 "$support" create-run \
    --state-dir "$state_dir" \
    --iso "$(readlink -f -- "$iso")" \
    --target "$target" \
    --sentinel "$sentinel" \
    --vm-instance-id "$vm_instance_id" >/dev/null ||
    die 'Run trust state creation failed'
cp -- "$ovmf_vars" "$workdir/OVMF_VARS.fd"

[[ ! -e "/sys/class/net/$tap_name" ]] ||
    die 'Selected harness TAP name is already in use'
ip tuntap add dev "$tap_name" mode tap user "$(id -u)" ||
    die 'Harness TAP creation failed'
tap_created=1
tap_ifindex=$(<"/sys/class/net/$tap_name/ifindex")
python3 "$support" record-tap-ownership \
    --record "$tap_ownership_record" \
    --tap-name "$tap_name" \
    --tap-ifindex "$tap_ifindex" ||
    die 'Harness TAP creation identity recording failed'
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
dnsmasq_starttime=$(process_starttime "$dnsmasq_pid") ||
    die 'Harness DHCP process identity recording failed'
python3 "$execution_server" \
    --listen-address 192.168.100.17 \
    --listen-port 18092 \
    --credential-key "$controller_credential_key" \
    --acceptance-state-dir "$state_dir" \
    >"$workdir/execution-server.log" 2>&1 &
execution_server_pid=$!
execution_server_starttime=$(process_starttime "$execution_server_pid") ||
    die 'Harness execution service identity recording failed'

wait_for_socket() {
    local socket_path=$1 seconds=$2 elapsed
    for ((elapsed = 0; elapsed < seconds; elapsed++)); do
        [[ -S "$socket_path" ]] && return 0
        [[ -n "$qemu_pid" ]] &&
            owned_process_alive "$qemu_pid" "$qemu_starttime" ||
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
        [[ -n "$qemu_pid" ]] &&
            owned_process_alive "$qemu_pid" "$qemu_starttime" ||
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
    local -a postflight_channel=()
    if [[ -n "$boot_iso" ]]; then
        python3 "$support" verify-run-iso \
            --state-dir "$state_dir" >/dev/null ||
            die 'Run ISO identity changed before QEMU launch'
        media=(
            -drive "id=install-iso,if=none,media=cdrom,format=raw,readonly=on,file=$boot_iso"
            -device "ide-cd,drive=install-iso"
        )
    fi
    [[ "$phase" != postflight ]] ||
        postflight_channel=(
            -device virtio-serial-pci
            -chardev "socket,id=postflight,path=$workdir/postflight.channel.sock,server=on,wait=off"
            -device "virtserialport,chardev=postflight,name=alt.install.postflight"
        )
    qemu-system-x86_64 \
        -machine q35,accel=kvm:tcg \
        -m 4096 \
        -uuid "$vm_instance_id" \
        -smbios type=1,manufacturer=QEMU,product=Standard-PC,serial=agent-v2-execution \
        -drive "if=pflash,format=raw,readonly=on,file=$ovmf_code" \
        -drive "if=pflash,format=raw,file=$workdir/OVMF_VARS.fd" \
        -drive "$target_drive" \
        -device virtio-blk-pci,drive=target,serial=ALT-QEMU-TARGET \
        -drive "$sentinel_drive" \
        -device virtio-blk-pci,drive=sentinel,serial=ALT-QEMU-SENTINEL \
        "${media[@]}" \
        "${postflight_channel[@]}" \
        -netdev tap,id=agent-net,ifname="$tap_name",script=no,downscript=no \
        -device virtio-net-pci,netdev=agent-net,mac=52:54:00:12:34:62 \
        -boot order="$([[ -n "$boot_iso" ]] && printf d || printf c)",menu=on \
        -serial "file:$console" \
        -qmp "unix:$qmp_socket,server=on,wait=off" \
        -display none \
        >"$workdir/$phase.qemu.log" 2>&1 &
    qemu_pid=$!
    qemu_starttime=$(process_starttime "$qemu_pid") ||
        die "$phase QEMU process identity recording failed"
    wait_for_socket "$qmp_socket" 60 ||
        die "$phase QMP socket did not become available"
}

install_qmp="$workdir/install.qmp.sock"
launch_qemu "$iso" install
wait_for_line "$workdir/install.console.log" \
    'terminal=execution_pending' 1200 ||
    die 'Guest never proved its pre-authorization execution hold'
python3 "$support" capture-authorization-boundary \
    --state-dir "$state_dir" \
    --socket "$install_qmp" \
    --evidence-dir "$evidence" \
    --phase pending ||
    die 'Pending authorization boundary capture failed'
python3 "$support" create-authorization-request \
    --state-dir "$state_dir" ||
    die 'Controller-owned authorization request was unavailable'
python3 "$support" capture-authorization-boundary \
    --state-dir "$state_dir" \
    --socket "$install_qmp" \
    --evidence-dir "$evidence" \
    --phase before-authorization ||
    die 'Immediate authorization boundary capture failed'
authorization_observed_at=$(date -u +%Y-%m-%dT%H:%M:%S+00:00)
python3 "$support" authorize-execution \
    --state-dir "$state_dir" \
    --pending-boundary "$evidence/pending-boundary.json" \
    --before-authorization-boundary "$evidence/before-authorization-boundary.json" \
    --observed-at "$authorization_observed_at" ||
    die 'Real root execution authorization failed'

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
python3 "$support" attest-controller-history \
    --state-dir "$state_dir" ||
    die 'Controller execution history attestation failed'
stop_qemu "$install_qmp"

postflight_qmp="$workdir/postflight.qmp.sock"
launch_qemu '' postflight
python3 "$support" qmp-boot-query \
    --socket "$postflight_qmp" \
    --output "$evidence/postflight-boot.qmp.jsonl" ||
    die 'Target-only postflight boot identity capture failed'
python3 "$support" issue-postflight-challenge \
    --state-dir "$state_dir" \
    --qmp "$evidence/postflight-boot.qmp.jsonl" ||
    die 'Fresh postflight boot challenge failed'
for _attempt in $(seq 1 120); do
    [[ -S "$workdir/postflight.channel.sock" ]] || {
        sleep 1
        continue
    }
    socat -u "FILE:$state_dir/postflight-delivery.json" \
        "UNIX-CONNECT:$workdir/postflight.channel.sock" &&
        break
    sleep 1
done
for _attempt in $(seq 1 1200); do
    if python3 "$support" attest-installed \
        --state-dir "$state_dir" >/dev/null 2>&1; then
        installed_attested=1
        break
    fi
    sleep 1
done
[[ "${installed_attested:-0}" == 1 ]] ||
    die 'Authenticated first-boot postflight was not installed'
stop_qemu "$postflight_qmp"

sha256sum "$target" >"$evidence/target.after.sha256"
sha256sum "$sentinel" >"$evidence/sentinel.after.sha256"
printf 'evidence_dir=%s\n' "$evidence"
python3 "$support" finalize-evidence \
    --state-dir "$state_dir" \
    --initial-qmp "$evidence/pending.qmp.jsonl" \
    --before-authorization-qmp "$evidence/before-authorization.qmp.jsonl" \
    --after-install-qmp "$evidence/after-install.qmp.jsonl" \
    --postflight-boot-qmp "$evidence/postflight-boot.qmp.jsonl" \
    --initial-target-sha "$evidence/pending.target.sha256" \
    --before-authorization-target-sha "$evidence/before-authorization.target.sha256" \
    --after-target-sha "$evidence/target.after.sha256" \
    --initial-sentinel-sha "$evidence/pending.sentinel.sha256" \
    --before-authorization-sentinel-sha "$evidence/before-authorization.sentinel.sha256" \
    --after-sentinel-sha "$evidence/sentinel.after.sha256" \
    --output "$evidence/acceptance-receipt.json"
python3 "$support" export-public-evidence \
    --state-dir "$state_dir" \
    --receipt "$evidence/acceptance-receipt.json" \
    --output "$evidence/public-evidence" \
    --evidence "pending-boundary.json=$evidence/pending-boundary.json" \
    --evidence "pending.qmp.jsonl=$evidence/pending.qmp.jsonl" \
    --evidence "pending.target.sha256=$evidence/pending.target.sha256" \
    --evidence "pending.sentinel.sha256=$evidence/pending.sentinel.sha256" \
    --evidence "before-authorization-boundary.json=$evidence/before-authorization-boundary.json" \
    --evidence "before-authorization.qmp.jsonl=$evidence/before-authorization.qmp.jsonl" \
    --evidence "before-authorization.target.sha256=$evidence/before-authorization.target.sha256" \
    --evidence "before-authorization.sentinel.sha256=$evidence/before-authorization.sentinel.sha256" \
    --evidence "after-install.qmp.jsonl=$evidence/after-install.qmp.jsonl" \
    --evidence "postflight-boot.qmp.jsonl=$evidence/postflight-boot.qmp.jsonl" \
    --evidence "target.after.sha256=$evidence/target.after.sha256" \
    --evidence "sentinel.after.sha256=$evidence/sentinel.after.sha256"
