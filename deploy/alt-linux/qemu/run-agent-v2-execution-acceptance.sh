#!/bin/bash
set -Eeuo pipefail

readonly target_virtual_size=64G
readonly sentinel_virtual_size=8M
readonly target_format=qcow2
readonly pass_line='PASS: root-authorized install wrote only the disposable target; authenticated postflight installed'

usage() {
    printf '%s\n' \
        'Usage: run-agent-v2-execution-acceptance.sh --iso <V2-ISO> --source-iso <ALT-ISO> --ovmf-code <OVMF_CODE.fd> --ovmf-vars <OVMF_VARS.fd> --controller-credential-key <KEY> [--evidence-dir <DIR>]' \
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
        date sleep seq dirname rm stat sed tail kill awk unshare
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
            'import cryptography, ctypes, os, signal, socket; raise SystemExit(0 if all((hasattr(socket, "AF_UNIX"), (hasattr(os, "setns") or hasattr(ctypes.CDLL(None), "setns")), hasattr(os, "pidfd_open"), hasattr(signal, "pidfd_send_signal"))) else 1)' \
            >/dev/null 2>&1; then
            printf '%s\n' \
                'agent-v2-qemu: Required Python cryptography/AF_UNIX/netns support is unavailable' >&2
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
        'network=tap,dedicated-harness-netns' \
        'cleanup=qemu,identity-bound-netns,temporary-directory;validated-harness-owned-only'
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
source_iso=
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
        --source-iso)
            (($# >= 2)) || usage
            source_iso=$2
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
[[ -n "$iso" && -n "$source_iso" && -n "$ovmf_code" && -n "$ovmf_vars" &&
    -n "$controller_credential_key" ]] || usage
check_prerequisites || exit 1

script_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo_root=$(cd -- "$script_root/../../.." && pwd -P)
support="$script_root/agent_v2_test_api.py"
execution_server="$repo_root/deploy/alt-linux/api/install_execution_server.py"
session_server="$repo_root/deploy/alt-linux/api/install_session_server.py"
iso_verifier="$repo_root/deploy/alt-linux/iso/agent-v2/verify-managed-iso.sh"
for path in "$iso" "$source_iso" "$ovmf_code" "$ovmf_vars" "$support" "$iso_verifier" \
    "$execution_server" "$session_server" "$controller_credential_key"; do
    [[ -f "$path" && -r "$path" && ! -L "$path" ]] ||
        die "Required regular file is unreadable: $path"
done
for path in "$iso" "$source_iso" "$ovmf_code" "$ovmf_vars"; do
    case "$path" in
        *,*) die "Input paths containing commas are unsupported: $path" ;;
    esac
done
iso_verification=$(bash "$iso_verifier" --iso "$iso" --source "$source_iso") ||
    die 'V2 managed ISO verification failed'
grep -Fxq 'managed_iso_verified=true' <<<"$iso_verification" ||
    die 'V2 managed ISO verifier result is invalid'
expected_iso_sha256=$(sed -n \
    's/^managed_iso_sha256=\([0-9a-f]\{64\}\)$/\1/p' \
    <<<"$iso_verification")
[[ "$expected_iso_sha256" =~ ^[0-9a-f]{64}$ ]] ||
    die 'V2 managed ISO verifier digest is invalid'
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
session_server_pid=
session_server_starttime=
tap_name="aiv2$(( $$ % 100000 ))"
netns_holder_pid=
netns_ownership_record="$evidence/network-namespace-ownership.json"
cleanup_failure_record="$evidence/cleanup-failures.log"
cleanup_failed=0

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

record_cleanup_failure() {
    cleanup_failed=1
    printf '%s\n' "$1" >>"$cleanup_failure_record" 2>/dev/null || true
    chmod 0600 -- "$cleanup_failure_record" 2>/dev/null || true
    printf 'agent-v2-qemu: %s; preserving live resources and workdir\n' \
        "$1" >&2
}

stop_recorded_process() {
    local pid=$1 starttime=$2 label=$3
    [[ -n "$pid" && -n "$starttime" ]] || return 0
    if python3 "$support" stop-owned-process \
        --pid "$pid" \
        --process-starttime "$starttime" >/dev/null 2>&1; then
        wait "$pid" 2>/dev/null || true
        return 0
    fi
    record_cleanup_failure "$label cleanup verification failed"
    return 1
}

stop_qemu() {
    [[ -n "$qemu_pid" ]] || return 0
    if stop_recorded_process \
        "$qemu_pid" "$qemu_starttime" "QEMU process"; then
        qemu_pid=
        qemu_starttime=
        return 0
    fi
    return 1
}

cleanup() {
    stop_qemu || true
    if stop_recorded_process \
        "$session_server_pid" "$session_server_starttime" \
        "install-session API process"; then
        session_server_pid=
        session_server_starttime=
    fi
    if stop_recorded_process \
        "$execution_server_pid" "$execution_server_starttime" \
        "execution API process"; then
        execution_server_pid=
        execution_server_starttime=
    fi
    if stop_recorded_process \
        "$dnsmasq_pid" "$dnsmasq_starttime" "dnsmasq process"; then
        dnsmasq_pid=
        dnsmasq_starttime=
    fi
    if [[ -f "$netns_ownership_record" &&
        ! -L "$netns_ownership_record" ]]; then
        if python3 "$support" stop-network-namespace \
            --record "$netns_ownership_record" >/dev/null 2>&1; then
            if [[ -n "$netns_holder_pid" ]]; then
                wait "$netns_holder_pid" 2>/dev/null || true
                netns_holder_pid=
            fi
        else
            record_cleanup_failure "network namespace"
        fi
    elif [[ -n "$netns_holder_pid" ]]; then
        record_cleanup_failure \
            "network namespace identity is absent"
    fi
    if ((cleanup_failed != 0)); then
        return 0
    fi
    if [[ -f "$workdir_ownership_record" &&
        ! -L "$workdir_ownership_record" ]]; then
        python3 "$support" remove-owned-workdir \
            --record "$workdir_ownership_record" \
            --workdir "$workdir" >/dev/null 2>&1 || {
            record_cleanup_failure \
                "workdir cleanup verification failed"
        }
    else
        record_cleanup_failure "workdir identity is absent"
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
    --expected-iso-sha256 "$expected_iso_sha256" \
    --target "$target" \
    --sentinel "$sentinel" \
    --vm-instance-id "$vm_instance_id" >/dev/null ||
    die 'Run trust state creation failed'
python3 "$support" capture-preflight-session-baseline \
    --state-dir "$state_dir" >/dev/null ||
    die 'Controller preflight baseline capture failed'
run_iso_output=$(python3 "$support" verify-run-iso \
    --state-dir "$state_dir") ||
    die 'Harness-owned run ISO verification failed'
case "$run_iso_output" in
    run_iso_path=*) iso=${run_iso_output#run_iso_path=} ;;
    *) die 'Harness-owned run ISO path is invalid' ;;
esac
[[ -f "$iso" && ! -L "$iso" ]] ||
    die 'Harness-owned run ISO is unavailable'
cp -- "$ovmf_vars" "$workdir/OVMF_VARS.fd"

unshare --net -- python3 "$support" hold-network-namespace \
    --record "$netns_ownership_record" \
    >"$workdir/netns-holder.log" 2>&1 &
netns_holder_pid=$!
for _attempt in $(seq 1 50); do
    [[ -f "$netns_ownership_record" &&
        ! -L "$netns_ownership_record" ]] && break
    kill -0 "$netns_holder_pid" 2>/dev/null || break
    sleep 0.1
done
[[ -f "$netns_ownership_record" &&
    ! -L "$netns_ownership_record" ]] ||
    die 'Harness network namespace identity recording failed'
python3 "$support" run-in-network-namespace \
    --record "$netns_ownership_record" -- \
    ip link set lo up ||
    die 'Harness network namespace loopback activation failed'
python3 "$support" run-in-network-namespace \
    --record "$netns_ownership_record" -- \
    ip tuntap add dev "$tap_name" mode tap user "$(id -u)" ||
    die 'Harness TAP creation failed'
python3 "$support" run-in-network-namespace \
    --record "$netns_ownership_record" -- \
    ip address add 192.168.100.17/24 dev "$tap_name" ||
    die 'Harness TAP address assignment failed'
python3 "$support" run-in-network-namespace \
    --record "$netns_ownership_record" -- \
    ip link set "$tap_name" up ||
    die 'Harness TAP activation failed'
python3 "$support" run-in-network-namespace \
    --record "$netns_ownership_record" -- \
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
PYTHONPATH="$repo_root/deploy/alt-linux/control" \
ALT_DEPLOY_INSTALL_PROFILE_ROOT="$repo_root/deploy/alt-linux/autoinstall/profiles" \
python3 "$support" run-in-network-namespace \
    --record "$netns_ownership_record" -- \
    python3 "$session_server" \
    --listen-address 192.168.100.17 \
    --listen-port 18090 \
    >"$workdir/session-server.log" 2>&1 &
session_server_pid=$!
session_server_starttime=$(process_starttime "$session_server_pid") ||
    die 'Harness install-session service identity recording failed'
PYTHONPATH="$repo_root/deploy/alt-linux/control" \
ALT_DEPLOY_INSTALL_PROFILE_ROOT="$repo_root/deploy/alt-linux/autoinstall/profiles" \
python3 "$support" run-in-network-namespace \
    --record "$netns_ownership_record" -- \
    python3 "$execution_server" \
    --listen-address 192.168.100.17 \
    --listen-port 18092 \
    --credential-key "$controller_credential_key" \
    --acceptance-state-dir "$state_dir" \
    >"$workdir/execution-server.log" 2>&1 &
execution_server_pid=$!
execution_server_starttime=$(process_starttime "$execution_server_pid") ||
    die 'Harness execution service identity recording failed'

wait_for_controller_port() {
    local port=$1 pid=$2 starttime=$3 seconds=$4 elapsed
    for ((elapsed = 0; elapsed < seconds; elapsed++)); do
        if python3 "$support" run-in-network-namespace \
            --record "$netns_ownership_record" -- \
            python3 -c \
            'import socket, sys; connection = socket.create_connection(("192.168.100.17", int(sys.argv[1])), 1); connection.close()' \
            "$port" >/dev/null 2>&1; then
            return 0
        fi
        owned_process_alive "$pid" "$starttime" || return 1
        sleep 1
    done
    return 1
}
wait_for_controller_port 18090 "$session_server_pid" \
    "$session_server_starttime" 30 ||
    die 'Harness install-session API did not become available'
wait_for_controller_port 18092 "$execution_server_pid" \
    "$execution_server_starttime" 30 ||
    die 'Harness execution API did not become available'

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
    python3 "$support" run-in-network-namespace \
        --record "$netns_ownership_record" -- \
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
preflight_ready=0
for _ in $(seq 1 1200); do
    python3 "$support" qmp-send-v2-execution-hotkey \
        --socket "$install_qmp" >/dev/null 2>&1 || true
    if [[ -f "$workdir/install.console.log" ]] &&
        grep -Fq 'ALT install agent: waiting_for_approval' \
            "$workdir/install.console.log"; then
        preflight_ready=1
        break
    fi
    owned_process_alive "$qemu_pid" "$qemu_starttime" || break
    sleep 1
done
((preflight_ready == 1)) ||
    die 'Guest never reached its V1 signed-plan approval hold'
python3 "$support" approve-disposable-preflight \
    --state-dir "$state_dir" >/dev/null ||
    die 'Real root disposable preflight approval failed'
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
authorization_observed_at=$(python3 -c \
    'from datetime import datetime, timezone; print(datetime.now(timezone.utc).isoformat(timespec="microseconds"))')
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
stop_qemu

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
stop_qemu

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
    --evidence "sentinel.after.sha256=$evidence/sentinel.after.sha256" \
    --evidence "postflight-delivery.json=$state_dir/postflight-delivery.json" \
    --evidence "authenticated-postflight.json=$state_dir/authenticated-postflight.json"
