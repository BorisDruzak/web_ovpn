#!/bin/bash
set -Eeuo pipefail

readonly target_virtual_size='64G'
readonly target_format='qcow2'
readonly readonly_drive_option='readonly=on'
readonly managed_iso_builder_relative='deploy/alt-linux/iso/agent-v1/build-managed-iso.sh'
readonly source_identity_manifest_relative='deploy/alt-linux/iso/agent-v1/manifests/source_iso.json'

usage() {
    printf '%s\n' \
        'Usage: run-agent-v1-dry-run-acceptance.sh --source-iso <ISO> --helper <STATIC-ELF> --ovmf-code <OVMF_CODE.fd> --ovmf-vars <OVMF_VARS.fd> [--evidence-dir <DIR>]' \
        '       run-agent-v1-dry-run-acceptance.sh --check-prerequisites' \
        '       run-agent-v1-dry-run-acceptance.sh --exercise-target-contract' \
        '       run-agent-v1-dry-run-acceptance.sh --describe-safety-contract' >&2
    exit 2
}

die() {
    printf 'agent-v1-qemu: %s\n' "$*" >&2
    exit 1
}

check_prerequisites() {
    local missing=0 command
    local required=(
        qemu-system-x86_64 qemu-img python3 bash xorriso cpio gzip patch
        sha256sum mktemp readlink id grep cp chmod mkdir date sleep seq
        dirname cmp rm df stat install find sort sed mv awk cat wc
    )
    for command in "${required[@]}"; do
        if ! command -v "$command" >/dev/null 2>&1; then
            printf 'agent-v1-qemu: Missing required command: %s\n' \
                "$command" >&2
            missing=1
        fi
    done
    ((missing == 0)) || return 1
    python3 -c 'import cryptography' >/dev/null 2>&1 || {
        printf '%s\n' \
            'agent-v1-qemu: Missing required Python module: cryptography' >&2
        return 1
    }
    python3 -c \
        'import socket; raise SystemExit(0 if hasattr(socket, "AF_UNIX") else 1)' \
        >/dev/null 2>&1 || {
        printf '%s\n' \
            'agent-v1-qemu: Python AF_UNIX socket support is required' >&2
        return 1
    }
    if [[ $(id -u) != 0 ]]; then
        printf '%s\n' \
            'agent-v1-qemu: Real root execution is required for the approval fixture' >&2
        return 1
    fi
}

describe_safety_contract() {
    printf '%s\n' \
        'target_input=none' \
        "target_virtual_size=$target_virtual_size" \
        'writable_target=qcow2-overlay-with-qcow2-backing' \
        "readonly_target=qcow2-backing,$readonly_drive_option" \
        "managed_iso_builder=$managed_iso_builder_relative" \
        "source_identity_manifest=$source_identity_manifest_relative"
}

prepared_variant_work=
prepared_variant_evidence=
prepared_target=
prepared_target_readonly=
target_drive_argument=

prepare_disposable_target() {
    local variant=$1
    local variant_work="$workdir/$variant"
    local variant_evidence="$evidence/$variant"
    local backing="$variant_work/backing.qcow2"
    local target="$backing"
    local target_readonly=on

    case "$variant" in
        writable|readonly) ;;
        *) die "Unsupported disposable target variant: $variant" ;;
    esac
    case "$variant_work" in
        "$workdir"/writable|"$workdir"/readonly) ;;
        *) die 'Disposable target escaped the harness work directory' ;;
    esac
    mkdir -- "$variant_work"
    chmod 0700 -- "$variant_work"
    mkdir -- "$variant_evidence"
    chmod 0755 -- "$variant_evidence"
    qemu-img create -f "$target_format" "$backing" "$target_virtual_size" \
        >"$variant_work/qemu-img.log" 2>&1 ||
        die "$variant qemu backing creation failed"
    (
        cd -- "$variant_work"
        sha256sum backing.qcow2
    ) >"$variant_evidence/backing.before.sha256"
    if [[ "$variant" == writable ]]; then
        target="$variant_work/target-overlay.qcow2"
        target_readonly=off
        qemu-img create -f "$target_format" -F "$target_format" \
            -b "$backing" "$target" \
            >>"$variant_work/qemu-img.log" 2>&1 ||
            die 'Writable qcow2 overlay creation failed'
        (
            cd -- "$variant_work"
            sha256sum target-overlay.qcow2
        ) >"$variant_evidence/target.before.sha256"
    fi

    prepared_variant_work=$variant_work
    prepared_variant_evidence=$variant_evidence
    prepared_target=$target
    prepared_target_readonly=$target_readonly
}

compose_target_drive() {
    local target=$1 target_readonly=$2

    case "$target" in
        "$workdir"/writable/*|"$workdir"/readonly/*) ;;
        *) die 'QEMU target drive escaped the harness work directory' ;;
    esac
    target_drive_argument="id=target,if=none,format=$target_format,file=$target,cache=none"
    [[ "$target_readonly" == off ]] ||
        target_drive_argument="${target_drive_argument},${readonly_drive_option}"
}

contract_cleanup_root=
contract_cleanup_workdir=
cleanup_contract_exercise() {
    case "$contract_cleanup_workdir" in
        "$contract_cleanup_root"/.alt-agent-v1-qemu-contract.*)
            rm -rf -- "$contract_cleanup_workdir"
            ;;
    esac
}

exercise_target_contract() {
    local command
    for command in qemu-img sha256sum mktemp readlink mkdir chmod rm; do
        command -v "$command" >/dev/null 2>&1 ||
            die "Missing target-contract command: $command"
    done

    contract_cleanup_root=${TMPDIR:-/tmp}
    contract_cleanup_root=$(readlink -f -- "$contract_cleanup_root") ||
        die 'Cannot resolve target-contract temporary root'
    [[ -d "$contract_cleanup_root" ]] ||
        die 'Target-contract temporary root is not a directory'
    workdir=$(mktemp -d \
        "$contract_cleanup_root/.alt-agent-v1-qemu-contract.XXXXXX")
    chmod 0700 -- "$workdir"
    workdir=$(readlink -f -- "$workdir") ||
        die 'Cannot resolve target-contract work directory'
    contract_cleanup_workdir=$workdir
    case "$workdir" in
        "$contract_cleanup_root"/.alt-agent-v1-qemu-contract.*) ;;
        *) die 'Target-contract work directory escaped its temporary root' ;;
    esac
    case "$workdir" in
        *,*) die 'Target-contract work paths containing commas are unsupported' ;;
    esac
    trap cleanup_contract_exercise EXIT

    evidence="$workdir/evidence"
    mkdir -- "$evidence"
    chmod 0755 -- "$evidence"

    local writable_variant_work writable_target writable_drive
    local readonly_variant_work readonly_target readonly_drive
    prepare_disposable_target writable
    compose_target_drive "$prepared_target" "$prepared_target_readonly"
    writable_variant_work=$prepared_variant_work
    writable_target=$prepared_target
    writable_drive=$target_drive_argument

    prepare_disposable_target readonly
    compose_target_drive "$prepared_target" "$prepared_target_readonly"
    readonly_variant_work=$prepared_variant_work
    readonly_target=$prepared_target
    readonly_drive=$target_drive_argument

    printf '%s\n' \
        "workdir=$workdir" \
        "writable_variant_work=$writable_variant_work" \
        "writable_target=$writable_target" \
        "writable_drive=$writable_drive" \
        "readonly_variant_work=$readonly_variant_work" \
        "readonly_target=$readonly_target" \
        "readonly_drive=$readonly_drive"
    cleanup_contract_exercise
    [[ ! -e "$workdir" ]] ||
        die 'Target-contract work directory cleanup failed'
    trap - EXIT
    contract_cleanup_workdir=
    printf '%s\n' 'cleanup=removed'
}

if (($# == 1)) && [[ "$1" == --check-prerequisites ]]; then
    check_prerequisites || exit 1
    printf '%s\n' 'QEMU acceptance prerequisites are available'
    exit 0
fi
if (($# == 1)) && [[ "$1" == --exercise-target-contract ]]; then
    exercise_target_contract
    exit 0
fi
if (($# == 1)) && [[ "$1" == --describe-safety-contract ]]; then
    describe_safety_contract
    exit 0
fi

source_iso=
helper=
ovmf_code=
ovmf_vars=
evidence_root=
while (($#)); do
    case "$1" in
        --source-iso)
            (($# >= 2)) || usage
            source_iso=$2
            shift 2
            ;;
        --helper)
            (($# >= 2)) || usage
            helper=$2
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
[[ -n "$source_iso" && -n "$helper" && -n "$ovmf_code" &&
    -n "$ovmf_vars" ]] || usage
check_prerequisites || exit 1

script_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo_root=$(cd -- "$script_root/../../.." && pwd -P)
support="$script_root/agent_v1_test_api.py"
builder="$repo_root/$managed_iso_builder_relative"
source_identity="$repo_root/$source_identity_manifest_relative"
verifier="$repo_root/deploy/alt-linux/iso/agent-v1/verify-managed-iso.sh"
for path in "$source_iso" "$helper" "$ovmf_code" "$ovmf_vars" \
    "$support" "$builder" "$source_identity" "$verifier"; do
    [[ -f "$path" && -r "$path" && ! -L "$path" ]] ||
        die "Required regular file is unreadable: $path"
done
for path in "$source_iso" "$helper" "$ovmf_code" "$ovmf_vars"; do
    case "$path" in
        *,*) die "Input paths containing commas are unsupported: $path" ;;
    esac
done

evidence_root=${evidence_root:-"$PWD/acceptance"}
mkdir -p -- "$evidence_root"
evidence_root=$(readlink -f -- "$evidence_root") ||
    die 'Cannot resolve evidence root'
[[ -d "$evidence_root" ]] || die 'Evidence root is not a directory'
case "$evidence_root" in
    /|/home|/root) die 'Evidence root is too broad' ;;
esac
case "$evidence_root" in
    *,*) die 'Evidence root paths containing commas are unsupported' ;;
esac

run_id="agent-v1-$(date -u +%Y%m%dT%H%M%SZ)-$$"
evidence="$evidence_root/$run_id"
mkdir -m 0755 -- "$evidence"
workdir=$(mktemp -d "$evidence_root/.alt-agent-v1-qemu-work.XXXXXX")
chmod 0700 -- "$workdir"
workdir=$(readlink -f -- "$workdir") || die 'Cannot resolve work directory'
case "$workdir" in
    "$evidence_root"/.alt-agent-v1-qemu-work.*) ;;
    *) die 'Temporary work directory escaped the evidence root' ;;
esac

api_pid=
qemu_pid=
cleanup() {
    if [[ -n "$qemu_pid" ]] && kill -0 "$qemu_pid" 2>/dev/null; then
        kill "$qemu_pid" 2>/dev/null || true
        wait "$qemu_pid" 2>/dev/null || true
    fi
    if [[ -n "$api_pid" ]] && kill -0 "$api_pid" 2>/dev/null; then
        kill "$api_pid" 2>/dev/null || true
        wait "$api_pid" 2>/dev/null || true
    fi
    case "$workdir" in
        "$evidence_root"/.alt-agent-v1-qemu-work.*)
            rm -rf -- "$workdir"
            ;;
    esac
}
trap cleanup EXIT

fixture_state="$workdir/fixture"
mkdir -m 0700 -- "$fixture_state"
python3 "$support" prepare --state-dir "$fixture_state" \
    >"$workdir/fixture-prepare.log" ||
    die 'Temporary signing-key fixture preparation failed'

managed_iso="$workdir/managed-agent-v1.iso"
build_id="qemu-acceptance-${run_id#agent-v1-}"
bash "$builder" \
    --source "$source_iso" \
    --output "$managed_iso" \
    --helper "$helper" \
    --public-key "$fixture_state/install-plan-ed25519.pub" \
    --build-id "$build_id" \
    >"$workdir/build.log" 2>&1 ||
    die 'Managed ISO build failed'
bash "$verifier" --iso "$managed_iso" \
    >"$workdir/verify.log" 2>&1 ||
    die 'Managed ISO verification failed'
cp -- "$managed_iso.build-manifest.json" \
    "$evidence/managed-iso.build-manifest.json"

python3 "$support" serve --state-dir "$fixture_state" \
    >"$workdir/fixture-server.log" 2>&1 &
api_pid=$!
for _ in $(seq 1 60); do
    [[ -f "$fixture_state/server.ready" ]] && break
    kill -0 "$api_pid" 2>/dev/null ||
        die 'Disposable test API exited before becoming ready'
    sleep 1
done
[[ -f "$fixture_state/server.ready" ]] ||
    die 'Disposable test API did not become ready'

wait_for_socket() {
    local socket_path=$1 seconds=$2
    local elapsed
    for ((elapsed = 0; elapsed < seconds; elapsed++)); do
        [[ -S "$socket_path" ]] && return 0
        [[ -n "$qemu_pid" ]] && kill -0 "$qemu_pid" 2>/dev/null ||
            return 1
        sleep 1
    done
    return 1
}

wait_for_exact_line() {
    local log_path=$1 line=$2 seconds=$3
    local elapsed
    for ((elapsed = 0; elapsed < seconds; elapsed++)); do
        if [[ -f "$log_path" ]] &&
            {
                grep -Fqx -- "$line" "$log_path" ||
                    grep -Fqx -- "${line}"$'\r' "$log_path"
            }; then
            return 0
        fi
        [[ -n "$qemu_pid" ]] && kill -0 "$qemu_pid" 2>/dev/null ||
            return 1
        sleep 1
    done
    return 1
}

stop_qemu() {
    local qmp_socket=$1
    if [[ -n "$qemu_pid" ]] && kill -0 "$qemu_pid" 2>/dev/null; then
        python3 "$support" qmp-command \
            --socket "$qmp_socket" --execute quit >/dev/null 2>&1 ||
            kill "$qemu_pid" 2>/dev/null || true
        wait "$qemu_pid" 2>/dev/null || true
    fi
    qemu_pid=
}

run_variant() {
    local variant=$1 uuid=$2
    local variant_work variant_evidence target target_readonly
    prepare_disposable_target "$variant"
    variant_work=$prepared_variant_work
    variant_evidence=$prepared_variant_evidence
    target=$prepared_target
    target_readonly=$prepared_target_readonly

    local qmp_socket="$variant_work/qmp.sock"
    local vnc_socket="$variant_work/vnc.sock"
    local console="$variant_work/guest-console.log"
    local qemu_log="$variant_work/qemu.log"
    local vars_copy="$variant_work/OVMF_VARS.fd"
    local drive

    cp -- "$ovmf_vars" "$vars_copy"

    compose_target_drive "$target" "$target_readonly"
    drive=$target_drive_argument
    qemu-system-x86_64 \
        -machine q35,accel=kvm:tcg \
        -m 4096 \
        -no-reboot \
        -S \
        -uuid "$uuid" \
        -smbios "type=1,manufacturer=QEMU,product=Standard PC,serial=agent-v1-$variant" \
        -drive "if=pflash,format=raw,readonly=on,file=$ovmf_code" \
        -drive "if=pflash,format=raw,file=$vars_copy" \
        -drive "$drive" \
        -device virtio-blk-pci,drive=target,serial=ALT-QEMU-DRYRUN \
        -drive "media=cdrom,readonly=on,file=$managed_iso" \
        -netdev user,id=agent-net,net=192.168.100.0/24,host=192.168.100.17,dhcpstart=192.168.100.50,ipv6=off \
        -device virtio-net-pci,netdev=agent-net,mac=52:54:00:12:34:57 \
        -boot order=d,menu=on \
        -serial "file:$console" \
        -qmp "unix:$qmp_socket,server=on,wait=off" \
        -vnc "unix:$vnc_socket" \
        >"$qemu_log" 2>&1 &
    qemu_pid=$!

    wait_for_socket "$qmp_socket" 60 ||
        die "$variant QMP socket did not become available"
    python3 "$support" qmp-query \
        --socket "$qmp_socket" \
        --output "$variant_evidence/qmp.before.jsonl" ||
        die "$variant initial QMP query failed"
    python3 "$support" qmp-command \
        --socket "$qmp_socket" --execute cont ||
        die "$variant QEMU continue failed"

    local booted=0
    # This host may fall back to TCG.  An ALT graphical initrd can legitimately
    # need more than ten minutes before it reaches the serial agent banner.
    for _ in $(seq 1 1200); do
        if [[ -f "$console" ]] &&
            {
                grep -Fqx 'ALT install agent: waiting_for_approval' "$console" ||
                    grep -Fqx \
                        $'ALT install agent: waiting_for_approval\r' "$console"
            }; then
            booted=1
            break
        fi
        kill -0 "$qemu_pid" 2>/dev/null ||
            die "$variant QEMU exited before the agent started"
        python3 "$support" vnc-send-s --socket "$vnc_socket" \
            >/dev/null 2>&1 ||
            python3 "$support" qmp-command \
                --socket "$qmp_socket" --execute send-key \
                >/dev/null 2>&1 ||
            true
        sleep 1
    done
    ((booted == 1)) ||
        die "$variant guest did not reach waiting_for_approval"
    wait_for_exact_line "$console" \
        'PASS: signed plan verified; disk preflight passed; no target writes' \
        600 ||
        die "$variant guest did not emit the exact PASS line"
    local pass_count pass_count_cr
    pass_count=$(
        grep -Fxc \
            'PASS: signed plan verified; disk preflight passed; no target writes' \
            "$console" || true
    )
    pass_count_cr=$(
        grep -Fxc \
            $'PASS: signed plan verified; disk preflight passed; no target writes\r' \
            "$console" || true
    )
    ((pass_count + pass_count_cr == 1)) ||
        die "$variant guest PASS line was not unique"

    python3 "$support" qmp-query \
        --socket "$qmp_socket" \
        --output "$variant_evidence/qmp.after.jsonl" ||
        die "$variant final QMP query failed"
    stop_qemu "$qmp_socket"
    (
        cd -- "$variant_work"
        sha256sum backing.qcow2
    ) >"$variant_evidence/backing.after.sha256"
    if [[ "$variant" == writable ]]; then
        (
            cd -- "$variant_work"
            sha256sum target-overlay.qcow2
        ) >"$variant_evidence/target.after.sha256"
        cmp -s "$variant_evidence/target.before.sha256" \
            "$variant_evidence/target.after.sha256" ||
            die 'Writable target qcow2 SHA-256 changed'
    fi
    grep -E \
        '^(ALT install agent:|READY FOR INSTALLATION|PASS:)' \
        "$console" |
        sed 's/\r$//' >"$variant_evidence/guest-console.log"
    cp -- "$qemu_log" "$variant_evidence/qemu.log"
    python3 "$support" verify-variant \
        --variant "$variant" \
        --before-qmp "$variant_evidence/qmp.before.jsonl" \
        --after-qmp "$variant_evidence/qmp.after.jsonl" \
        --before-sha "$variant_evidence/backing.before.sha256" \
        --after-sha "$variant_evidence/backing.after.sha256" \
        --output "$variant_evidence/summary.json" ||
        die "$variant zero-write evidence failed verification"
}

run_variant writable '11111111-2222-3333-4444-555555555551'
run_variant readonly '11111111-2222-3333-4444-555555555552'

kill "$api_pid" 2>/dev/null || true
wait "$api_pid" 2>/dev/null || true
api_pid=
python3 "$support" export-evidence \
    --state-dir "$fixture_state" \
    --expected-sessions 2 \
    --output "$evidence/fixture-report.json" ||
    die 'Root-approval fixture evidence is incomplete'

printf 'evidence_dir=%s\n' "$evidence"
python3 "$support" finalize-evidence \
    --variant-summary "$evidence/writable/summary.json" \
    --variant-summary "$evidence/readonly/summary.json" \
    --fixture-report "$evidence/fixture-report.json" \
    --output "$evidence/acceptance-summary.json"
