#!/bin/bash
set -Eeuo pipefail

readonly rollout_v2_unit='alt-install-execution.service'
readonly rollout_v2_listener='192.168.100.17:18092'
readonly rollout_v1_listener='192.168.100.17:18090'

rollout_v2_die() {
    printf 'alt-install-execution-v2-rollout: %s\n' "$*" >&2
    return 1
}

rollout_v2_usage() {
    printf '%s\n' \
        'Usage: rollout-install-execution-v2.sh --backup-id <ID> --source-commit <40-hex> --source-iso <ISO> --source-iso-sha256 <SHA256> --managed-iso-sha256 <SHA256> --release-id <ID> --iso-dir <DIR> --public-key <JSON> --execution-ca <PEM> --go <GO> --task6-evidence-dir <DIR> --pilot-record <JSON> --receipt <JSON>' >&2
    return 2
}

rollout_v2_path() {
    printf '%s%s' "$1" "$2"
}

rollout_v2_release_sessions_lock() {
    local failed=0
    [[ ${ROLLOUT_V2_SESSIONS_LOCK_HELD:-0} == 1 ]] || return 0
    if ! flock --unlock "$ROLLOUT_V2_SESSIONS_LOCK_FD"; then
        failed=1
    fi
    if ! exec {ROLLOUT_V2_SESSIONS_LOCK_FD}>&-; then
        failed=1
    fi
    ROLLOUT_V2_SESSIONS_LOCK_HELD=0
    return "$failed"
}

rollout_v2_acquire_sessions_lock() {
    local root_prefix=$1 lock_parent
    ROLLOUT_V2_SESSIONS_LOCK=$(rollout_v2_path "$root_prefix" \
        /var/lib/alt-deploy/install-sessions.lock)
    lock_parent=${ROLLOUT_V2_SESSIONS_LOCK%/*}
    [[ -d "$lock_parent" && ! -L "$lock_parent" ]] ||
        rollout_v2_die 'Install session lock parent is unsafe'
    if [[ ! -e "$ROLLOUT_V2_SESSIONS_LOCK" &&
          ! -L "$ROLLOUT_V2_SESSIONS_LOCK" ]]; then
        install -m 0600 /dev/null "$ROLLOUT_V2_SESSIONS_LOCK" ||
            rollout_v2_die 'Install session lock cannot be created'
    fi
    [[ -f "$ROLLOUT_V2_SESSIONS_LOCK" &&
       ! -L "$ROLLOUT_V2_SESSIONS_LOCK" ]] ||
        rollout_v2_die 'Install session lock is unsafe'
    chmod 0600 "$ROLLOUT_V2_SESSIONS_LOCK" ||
        rollout_v2_die 'Install session lock mode cannot be secured'
    exec {ROLLOUT_V2_SESSIONS_LOCK_FD}<>"$ROLLOUT_V2_SESSIONS_LOCK" ||
        rollout_v2_die 'Install session lock cannot be opened'
    if ! flock --exclusive "$ROLLOUT_V2_SESSIONS_LOCK_FD"; then
        exec {ROLLOUT_V2_SESSIONS_LOCK_FD}>&-
        rollout_v2_die 'Install session lock cannot be acquired'
    fi
    ROLLOUT_V2_SESSIONS_LOCK_HELD=1
}

rollout_v2_restore() {
    trap - ERR INT TERM
    [[ ${ROLLOUT_V2_TRANSACTION_ACTIVE:-0} == 1 ]] || return 0
    ROLLOUT_V2_TRANSACTION_ACTIVE=0
    local -a failures=()
    local stopped=1 pointer_restored=1 unit_restored=1
    local reload_succeeded=1 activation_restored=1

    if ! systemctl stop "$rollout_v2_unit" >/dev/null 2>&1; then
        failures+=(service_stop)
        stopped=0
    fi
    if ((stopped == 1)); then
        if [[ ${ROLLOUT_V2_HAD_CURRENT:-0} == 1 ]]; then
            if ! ln -sfn -- "$ROLLOUT_V2_OLD_CURRENT" \
                "$ROLLOUT_V2_CURRENT.new-$$" ||
               ! mv -Tf -- "$ROLLOUT_V2_CURRENT.new-$$" \
                "$ROLLOUT_V2_CURRENT"; then
                failures+=(runtime_pointer_restore)
                pointer_restored=0
            fi
        elif ! rm -f -- "$ROLLOUT_V2_CURRENT"; then
            failures+=(runtime_pointer_remove)
            pointer_restored=0
        fi
        if [[ ${ROLLOUT_V2_HAD_UNIT:-0} == 1 ]]; then
            if ! install -m 0644 -- "$ROLLOUT_V2_SNAPSHOT/unit" \
                "$ROLLOUT_V2_UNIT_PATH.new-$$" ||
               ! mv -Tf -- "$ROLLOUT_V2_UNIT_PATH.new-$$" \
                "$ROLLOUT_V2_UNIT_PATH"; then
                failures+=(unit_restore)
                unit_restored=0
            fi
        elif ! rm -f -- "$ROLLOUT_V2_UNIT_PATH"; then
            failures+=(unit_remove)
            unit_restored=0
        fi
    else
        failures+=(runtime_restore_skipped)
        pointer_restored=0
        unit_restored=0
    fi
    if ((stopped == 1 && unit_restored == 1)); then
        if ! systemctl daemon-reload >/dev/null 2>&1; then
            failures+=(daemon_reload)
            reload_succeeded=0
        fi
    else
        failures+=(daemon_reload_skipped)
        reload_succeeded=0
    fi
    if ((stopped == 1 && pointer_restored == 1 &&
         unit_restored == 1 && reload_succeeded == 1)); then
        if [[ ${ROLLOUT_V2_WAS_ENABLED:-0} == 1 ]]; then
            if ! systemctl enable "$rollout_v2_unit" >/dev/null 2>&1; then
                failures+=(enable_restore)
                activation_restored=0
            fi
        elif ! systemctl disable "$rollout_v2_unit" >/dev/null 2>&1; then
            failures+=(disable_restore)
            activation_restored=0
        fi
        if [[ ${ROLLOUT_V2_WAS_ACTIVE:-0} == 1 ]]; then
            if ((activation_restored == 1)); then
                if ! systemctl start "$rollout_v2_unit" \
                    >/dev/null 2>&1; then
                    failures+=(active_restore)
                    activation_restored=0
                fi
            else
                failures+=(active_restore_skipped)
            fi
        fi
    else
        failures+=(activation_restore_skipped)
        activation_restored=0
    fi
    if [[ -n ${ROLLOUT_V2_NEW_RELEASE:-} ]]; then
        case "$ROLLOUT_V2_NEW_RELEASE" in
            "$ROLLOUT_V2_RELEASES"/*)
                if [[ "$ROLLOUT_V2_NEW_RELEASE" != \
                    "${ROLLOUT_V2_OLD_CURRENT:-}" ]]; then
                    if ((stopped == 1 && pointer_restored == 1 &&
                         unit_restored == 1 && reload_succeeded == 1 &&
                         activation_restored == 1)); then
                        if ! rm -rf -- "$ROLLOUT_V2_NEW_RELEASE"; then
                            failures+=(staged_runtime_remove)
                        fi
                    else
                        failures+=(staged_runtime_remove_skipped)
                    fi
                fi
                ;;
        esac
    fi
    if ! rollout_v2_release_sessions_lock; then
        failures+=(session_lock_release)
    fi
    if ((${#failures[@]} == 0)); then
        if ! rm -rf -- "$ROLLOUT_V2_SNAPSHOT"; then
            failures+=(snapshot_remove)
        fi
    fi
    if ((${#failures[@]} != 0)); then
        local joined
        joined=$(IFS=,; printf '%s' "${failures[*]}")
        printf 'alt-install-execution-v2-rollout: V2 rollback failed: %s; recovery snapshot=%s\n' \
            "$joined" "$ROLLOUT_V2_SNAPSHOT" >&2
        return 1
    fi
}

rollout_v2_error_trap() {
    local status=$1
    if ! rollout_v2_restore; then
        exit 70
    fi
    exit "$status"
}

rollout_v2_snapshot_regular_input() {
    python3 - "$1" "$2" <<'PY'
import os
import stat
import sys

source, output = sys.argv[1:]
flags = os.O_RDONLY
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
descriptor = os.open(source, flags)
try:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= 1024 * 1024:
        raise SystemExit(1)
    chunks = []
    remaining = before.st_size
    while remaining:
        chunk = os.read(descriptor, min(remaining, 64 * 1024))
        if not chunk:
            raise SystemExit(1)
        chunks.append(chunk)
        remaining -= len(chunk)
    after = os.fstat(descriptor)
    identity = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, name) != getattr(after, name) for name in identity):
        raise SystemExit(1)
finally:
    os.close(descriptor)
output_descriptor = os.open(
    output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400
)
try:
    payload = b"".join(chunks)
    view = memoryview(payload)
    while view:
        written = os.write(output_descriptor, view)
        if written <= 0:
            raise SystemExit(1)
        view = view[written:]
    os.fsync(output_descriptor)
finally:
    os.close(output_descriptor)
PY
}

rollout_v2_snapshot_task6_evidence() {
    python3 - "$1" "$2" <<'PY'
import os
from pathlib import Path
import shutil
import stat
import sys

source = Path(sys.argv[1])
output = Path(sys.argv[2])
before = source.lstat()
if not stat.S_ISDIR(before.st_mode) or source.is_symlink():
    raise SystemExit(1)
shutil.copytree(source, output, symlinks=True)
after = source.lstat()
if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
    raise SystemExit(1)
for path in output.rglob("*"):
    metadata = path.lstat()
    if path.is_symlink() or not (
        stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)
    ):
        raise SystemExit(1)
os.chmod(output, 0o700)
PY
}

rollout_v2_validate_backup() {
    local backup_tool=$1 backup_id=$2 output=$3
    [[ "$backup_id" =~ ^backup-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$ ]] ||
        rollout_v2_die 'Named backup ID is invalid'
    [[ -f "$backup_tool" && -x "$backup_tool" && ! -L "$backup_tool" ]] ||
        rollout_v2_die 'Installed backup utility is unavailable'
    "$backup_tool" rehearse-status "$backup_id" >"$output" ||
        rollout_v2_die 'Named rehearsed backup is required'
    if ! python3 - "$output" "$backup_id" <<'PY'
import json, re, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
if not isinstance(value, dict) or set(value) != {
    "status", "result", "backup_id", "manifest_sha256",
    "verification_sha256",
}:
    raise SystemExit(1)
if value["status"] != "ok" or value["result"] != "backup_rehearsed":
    raise SystemExit(1)
if value["backup_id"] != sys.argv[2]:
    raise SystemExit(1)
if any(not isinstance(value[name], str) or
       re.fullmatch(r"[0-9a-f]{64}", value[name]) is None
       for name in ("manifest_sha256", "verification_sha256")):
    raise SystemExit(1)
PY
    then
        rollout_v2_die 'Rehearsed backup response is invalid'
    fi
}

rollout_v2_no_active_execution() {
    local status
    if python3 - "$1" <<'PY'
import json, sys
from pathlib import Path
root = Path(sys.argv[1])
if not root.exists():
    raise SystemExit(0)
if not root.is_dir() or root.is_symlink():
    raise SystemExit(2)
terminal = {"installed", "failed", "cancelled", "expired"}
active = {"authorized", "claimed", "handoff_started", "installer_started"}
for path in sorted(root.glob("*/status.json")):
    if not path.is_file() or path.is_symlink():
        raise SystemExit(2)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise SystemExit(2)
    execution = value.get("execution") if isinstance(value, dict) else None
    if execution is None:
        continue
    state = execution.get("state") if isinstance(execution, dict) else None
    if state in active:
        raise SystemExit(1)
    if state not in terminal:
        raise SystemExit(2)
PY
    then
        status=0
    else
        status=$?
    fi
    case "$status" in
        0) ;;
        1) rollout_v2_die 'Active execution session blocks rollout' ;;
        *) rollout_v2_die 'Execution session state cannot be verified' ;;
    esac
}

rollout_v2_snapshot() {
    local root_prefix=$1
    ROLLOUT_V2_RELEASES=$(rollout_v2_path "$root_prefix" \
        /opt/alt-install-execution-api/releases)
    ROLLOUT_V2_CURRENT=$(rollout_v2_path "$root_prefix" \
        /opt/alt-install-execution-api/current)
    ROLLOUT_V2_UNIT_PATH=$(rollout_v2_path "$root_prefix" \
        /etc/systemd/system/alt-install-execution.service)
    ROLLOUT_V2_SNAPSHOT=$(mktemp -d \
        "$(rollout_v2_path "$root_prefix" /run)/.alt-v2-rollout.XXXXXX")
    chmod 0700 "$ROLLOUT_V2_SNAPSHOT"
    ROLLOUT_V2_HAD_CURRENT=0
    ROLLOUT_V2_HAD_UNIT=0
    ROLLOUT_V2_WAS_ENABLED=0
    ROLLOUT_V2_WAS_ACTIVE=0
    ROLLOUT_V2_OLD_CURRENT=
    ROLLOUT_V2_NEW_RELEASE=
    if [[ -L "$ROLLOUT_V2_CURRENT" ]]; then
        ROLLOUT_V2_OLD_CURRENT=$(readlink -- "$ROLLOUT_V2_CURRENT")
        ROLLOUT_V2_HAD_CURRENT=1
    elif [[ -e "$ROLLOUT_V2_CURRENT" ]]; then
        rollout_v2_die 'V2 runtime pointer is unsafe'
    fi
    if [[ -f "$ROLLOUT_V2_UNIT_PATH" && ! -L "$ROLLOUT_V2_UNIT_PATH" ]]; then
        cp -- "$ROLLOUT_V2_UNIT_PATH" "$ROLLOUT_V2_SNAPSHOT/unit"
        ROLLOUT_V2_HAD_UNIT=1
    elif [[ -e "$ROLLOUT_V2_UNIT_PATH" || -L "$ROLLOUT_V2_UNIT_PATH" ]]; then
        rollout_v2_die 'V2 unit path is unsafe'
    fi
    local status rc
    if status=$(systemctl is-enabled "$rollout_v2_unit" 2>/dev/null); then
        [[ "$status" == enabled ]] ||
            rollout_v2_die 'V2 enabled state is ambiguous'
        ROLLOUT_V2_WAS_ENABLED=1
    else
        rc=$?
        [[ "$status:$rc" == disabled:1 ||
           "$status:$rc" == not-found:1 ||
           "$status:$rc" == not-found:4 ]] ||
            rollout_v2_die 'V2 enabled state cannot be inspected'
    fi
    if status=$(systemctl is-active "$rollout_v2_unit" 2>/dev/null); then
        [[ "$status" == active ]] ||
            rollout_v2_die 'V2 active state is ambiguous'
        ROLLOUT_V2_WAS_ACTIVE=1
    else
        rc=$?
        [[ "$status:$rc" == inactive:3 ||
           "$status:$rc" == inactive:4 ||
           "$status:$rc" == unknown:3 ||
           "$status:$rc" == unknown:4 ]] ||
            rollout_v2_die 'V2 active state cannot be inspected'
    fi
}

rollout_v2_health() {
    local root_prefix=$1 unit health
    unit=$(systemctl cat "$rollout_v2_unit") ||
        rollout_v2_die 'V2 unit cannot be inspected'
    [[ "$unit" == *'--listen-address 192.168.100.17 --listen-port 18092'* &&
       "$unit" != *18090* && "$unit" != *'0.0.0.0'* &&
       "$unit" != *'[::]'* ]] ||
        rollout_v2_die 'V2 unit is not bound only to 192.168.100.17:18092'
    [[ "$(systemctl is-enabled "$rollout_v2_unit")" == enabled ]] ||
        rollout_v2_die 'V2 unit is not enabled'
    [[ "$(systemctl is-active "$rollout_v2_unit")" == active ]] ||
        rollout_v2_die 'V2 unit is not active'
    health=$(curl --noproxy '*' --fail --silent --show-error \
        --proto '=https' --tlsv1.3 --max-time 5 \
        --cacert "$(rollout_v2_path "$root_prefix" \
            /etc/alt-deploy/install-execution-ca.pem)" \
        "https://$rollout_v2_listener/health") ||
        rollout_v2_die 'V2 TLS health request failed'
    printf '%s' "$health" | python3 -c '
import json, sys
expected = {"schema_version": 1, "service": "alt-install-execution",
            "status": "ok"}
raise SystemExit(json.load(sys.stdin) != expected)
' || rollout_v2_die 'V2 TLS health response is invalid'
}

rollout_install_execution_v2_main() {
    local root_prefix=$1 release_builder=$2 installer=$3
    local task6_support=$4 pilot_verifier=$5
    shift 5
    local backup_id= source_commit= source_iso= source_iso_sha256=
    local managed_iso_sha256= release_id= iso_dir= public_key=
    local execution_ca= go= task6_evidence= pilot_record= receipt=
    ROLLOUT_V2_SESSIONS_LOCK_HELD=0
    ROLLOUT_V2_TRANSACTION_ACTIVE=0
    while (($#)); do
        (($# >= 2)) || { rollout_v2_usage; return $?; }
        case "$1" in
            --backup-id) backup_id=$2 ;;
            --source-commit) source_commit=$2 ;;
            --source-iso) source_iso=$2 ;;
            --source-iso-sha256) source_iso_sha256=$2 ;;
            --managed-iso-sha256) managed_iso_sha256=$2 ;;
            --release-id) release_id=$2 ;;
            --iso-dir) iso_dir=$2 ;;
            --public-key) public_key=$2 ;;
            --execution-ca) execution_ca=$2 ;;
            --go) go=$2 ;;
            --task6-evidence-dir) task6_evidence=$2 ;;
            --pilot-record) pilot_record=$2 ;;
            --receipt) receipt=$2 ;;
            *) rollout_v2_usage; return $? ;;
        esac
        shift 2
    done
    [[ -n "$backup_id" && -n "$source_commit" && -n "$source_iso" &&
       -n "$source_iso_sha256" && -n "$managed_iso_sha256" &&
       -n "$release_id" && -n "$iso_dir" && -n "$public_key" &&
       -n "$execution_ca" && -n "$go" && -n "$task6_evidence" &&
       -n "$pilot_record" && -n "$receipt" ]] ||
        { rollout_v2_usage; return $?; }
    for command in awk bash chmod cp curl flock git install ln mktemp mv \
        python3 readlink rm sha256sum systemctl; do
        command -v "$command" >/dev/null ||
            rollout_v2_die "Missing required command: $command"
    done
    [[ "$source_commit" =~ ^[0-9a-f]{40}$ ]] ||
        rollout_v2_die 'Source commit is invalid'
    [[ "$source_iso_sha256" =~ ^[0-9a-f]{64}$ &&
       "$managed_iso_sha256" =~ ^[0-9a-f]{64}$ ]] ||
        rollout_v2_die 'ISO digest is invalid'
    [[ -f "$source_iso" && ! -L "$source_iso" &&
       -f "$public_key" && ! -L "$public_key" &&
       -f "$execution_ca" && ! -L "$execution_ca" &&
       -x "$go" && -d "$iso_dir" && ! -L "$iso_dir" &&
       -d "$task6_evidence" && ! -L "$task6_evidence" &&
       -f "$pilot_record" && ! -L "$pilot_record" ]] ||
        rollout_v2_die 'Rollout input is unsafe or unavailable'
    [[ ! -e "$receipt" && ! -L "$receipt" ]] ||
        rollout_v2_die 'Production receipt already exists'
    [[ "$(sha256sum "$source_iso" | awk '{print $1}')" == \
       "$source_iso_sha256" ]] ||
        rollout_v2_die 'Source ISO digest mismatch'

    local script_root repo_root head main_commit status
    script_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
    repo_root=$(cd -- "$script_root/../../.." && pwd -P)
    git -C "$repo_root" fetch origin main ||
        rollout_v2_die 'Authoritative main cannot be fetched'
    head=$(git -C "$repo_root" rev-parse --verify 'HEAD^{commit}') ||
        rollout_v2_die 'Exact HEAD cannot be resolved'
    [[ "$head" == "$source_commit" ]] ||
        rollout_v2_die 'Source commit does not match exact HEAD'
    main_commit=$(git -C "$repo_root" rev-parse --verify \
        'refs/remotes/origin/main^{commit}') ||
        rollout_v2_die 'Authoritative main cannot be resolved'
    git -C "$repo_root" merge-base --is-ancestor \
        "$source_commit" "$main_commit" ||
        rollout_v2_die 'Source commit is not merged to authoritative main'
    status=$(git -C "$repo_root" status --porcelain \
        --untracked-files=all -- deploy/alt-linux \
        docs/runbooks/alt-install-execution-v2.md \
        docs/verification/alt-install-execution-v2-pilot-template.md \
        tests/test_alt_install_execution_rollout.py) ||
        rollout_v2_die 'Relevant source status cannot be inspected'
    [[ -z "$status" ]] || rollout_v2_die 'Relevant source paths are not clean'

    local sessions backup_tool preflight_dir backup_json pilot_snapshot
    sessions=$(rollout_v2_path "$root_prefix" \
        /var/lib/alt-deploy/install-sessions)
    rollout_v2_no_active_execution "$sessions"
    preflight_dir=$(mktemp -d \
        "$(rollout_v2_path "$root_prefix" /run)/.alt-v2-preflight.XXXXXX")
    chmod 0700 "$preflight_dir"
    backup_json="$preflight_dir/backup.json"
    backup_tool=$(rollout_v2_path "$root_prefix" \
        /usr/local/sbin/alt-deploy-backup)
    rollout_v2_validate_backup "$backup_tool" "$backup_id" "$backup_json"
    pilot_snapshot="$preflight_dir/pilot.json"
    rollout_v2_snapshot_regular_input "$pilot_record" "$pilot_snapshot" ||
        rollout_v2_die 'Pilot record snapshot failed'
    python3 "$pilot_verifier" --record "$pilot_snapshot" \
        --expected-iso-sha256 "$managed_iso_sha256" \
        >"$preflight_dir/pilot-validation.json" ||
        rollout_v2_die 'Pilot record validation failed'

    rollout_v2_snapshot "$root_prefix"
    mv -- "$backup_json" "$ROLLOUT_V2_SNAPSHOT/backup.json"
    mv -- "$pilot_snapshot" "$ROLLOUT_V2_SNAPSHOT/pilot.json"
    mv -- "$preflight_dir/pilot-validation.json" \
        "$ROLLOUT_V2_SNAPSHOT/pilot-validation.json"
    rm -rf -- "$preflight_dir" ||
        rollout_v2_die 'Preflight snapshot cleanup failed'
    if ! rollout_v2_acquire_sessions_lock "$root_prefix"; then
        rm -rf -- "$ROLLOUT_V2_SNAPSHOT"
        return 1
    fi
    if ! rollout_v2_no_active_execution "$sessions"; then
        local final_scan_cleanup_failed=0
        rollout_v2_release_sessions_lock ||
            final_scan_cleanup_failed=1
        rm -rf -- "$ROLLOUT_V2_SNAPSHOT" ||
            final_scan_cleanup_failed=1
        if ((final_scan_cleanup_failed == 1)); then
            rollout_v2_die \
                'Final execution scan cleanup failed'
        fi
        return 1
    fi
    ROLLOUT_V2_TRANSACTION_ACTIVE=1
    trap 'rollout_v2_error_trap $?' ERR INT TERM

    bash "$installer"
    [[ -L "$ROLLOUT_V2_CURRENT" ]] ||
        rollout_v2_die 'V2 runtime was not staged'
    ROLLOUT_V2_NEW_RELEASE=$(python3 -c \
        'from pathlib import Path; import sys; print(Path(sys.argv[1]).resolve(strict=True).as_posix())' \
        "$ROLLOUT_V2_CURRENT")
    ROLLOUT_V2_RELEASES=$(python3 -c \
        'from pathlib import Path; import sys; print(Path(sys.argv[1]).resolve(strict=True).as_posix())' \
        "$ROLLOUT_V2_RELEASES")
    case "$ROLLOUT_V2_NEW_RELEASE" in
        "$ROLLOUT_V2_RELEASES"/*) ;;
        *) rollout_v2_die 'Staged V2 runtime escaped its release root' ;;
    esac
    rollout_v2_health "$root_prefix"
    rollout_v2_release_sessions_lock ||
        rollout_v2_die 'Install session lock release failed'

    bash "$release_builder" --source-commit "$source_commit" \
        --source-iso "$source_iso" --public-key "$public_key" \
        --release-id "$release_id" --iso-dir "$iso_dir" --go "$go" \
        --agent-version agent-v2 --execution-ca "$execution_ca"
    local published sidecar
    published="$iso_dir/alt-kworkstation-11.4-agent-v2-$release_id.iso"
    sidecar="$published.build-manifest.json"
    [[ -f "$published" && ! -L "$published" &&
       -f "$sidecar" && ! -L "$sidecar" &&
       "$(sha256sum "$published" | awk '{print $1}')" == \
       "$managed_iso_sha256" ]] ||
        rollout_v2_die 'Immutable V2 ISO publication is invalid'
    python3 - "$sidecar" "$source_iso_sha256" "$managed_iso_sha256" \
        "$release_id" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
if (value.get("format") != "alt-install-agent-managed-iso-v2" or
    value.get("controller_url") != "https://192.168.100.17:18092" or
    value.get("build_id") != "release-" + sys.argv[4] or
    value.get("source_iso_sha256") != sys.argv[2] or
    value.get("managed_iso_sha256") != sys.argv[3]):
    raise SystemExit(1)
PY

    local task6_snapshot="$ROLLOUT_V2_SNAPSHOT/task6-public-evidence"
    rollout_v2_snapshot_task6_evidence \
        "$task6_evidence" "$task6_snapshot" ||
        rollout_v2_die 'Task 6 evidence snapshot failed'
    python3 "$task6_support" verify-public-evidence \
        --evidence-dir "$task6_snapshot" ||
        rollout_v2_die 'Task 6 production receipt verification failed'
    local task6_receipt="$task6_snapshot/acceptance-receipt.json"
    local task6_index="$task6_snapshot/evidence-index.json"
    python3 - "$task6_receipt" "$task6_index" \
        "$managed_iso_sha256" <<'PY'
import hashlib, json, sys
receipt_raw = open(sys.argv[1], "rb").read()
value = json.loads(receipt_raw)
index = json.load(open(sys.argv[2], encoding="utf-8"))
writes = value.get("writes", {})
before = writes.get("before_authorization", {})
after = writes.get("after_install", {})
if (index.get("schema_version") != 1 or
    index.get("receipt_sha256") != hashlib.sha256(receipt_raw).hexdigest() or
    value.get("schema_version") != 2 or value.get("result") != "pass" or
    value.get("acceptance_scope") != "generic-ovmf-disposable" or
    value.get("target_disk") != "/dev/vda" or
    value.get("artifacts", {}).get("iso", {}).get("sha256") != sys.argv[3] or
    value.get("controller", {}).get("state") != "installed" or
    value.get("postflight", {}).get("iso_attached") is not False or
    before != {"target_write_bytes": 0, "sentinel_write_bytes": 0} or
    type(after.get("target_write_bytes")) is not int or
    after["target_write_bytes"] <= 0 or
    after.get("sentinel_write_bytes") != 0):
    raise SystemExit(1)
PY

    python3 - "$receipt" "$source_commit" \
        "$ROLLOUT_V2_SNAPSHOT/backup.json" "$sidecar" "$task6_receipt" \
        "$task6_index" "$task6_evidence" \
        "$ROLLOUT_V2_SNAPSHOT/pilot.json" <<'PY'
import hashlib, json, os, sys
(
    out, commit, backup_path, sidecar_path, task6_path, task6_index_path,
    evidence, pilot_path,
) = sys.argv[1:]
backup = json.load(open(backup_path, encoding="utf-8"))
sidecar = json.load(open(sidecar_path, encoding="utf-8"))
task6_raw = open(task6_path, "rb").read()
task6 = json.loads(task6_raw)
task6_index_raw = open(task6_index_path, "rb").read()
pilot_raw = open(pilot_path, "rb").read()
pilot = json.loads(pilot_raw)
document = {
    "backup": {
        "backup_id": backup["backup_id"],
        "manifest_sha256": backup["manifest_sha256"],
        "verification_sha256": backup["verification_sha256"],
    },
    "controller": {
        "health": {"schema_version": 1, "service": "alt-install-execution",
                   "status": "ok"},
        "listener": "192.168.100.17:18092",
        "transport": "tls",
        "unit": "alt-install-execution.service",
    },
    "iso": {
        "managed_iso_sha256": sidecar["managed_iso_sha256"],
        "payload_manifest_sha256": sidecar["payload_manifest_sha256"],
        "public_key_id": sidecar["public_key_id"],
        "source_iso_sha256": sidecar["source_iso_sha256"],
    },
    "pilot": {
        "asset_id": pilot["asset_id"],
        "disk": pilot["disk"],
        "dmi_uuid": pilot["dmi_uuid"],
        "iso_sha256": pilot["iso_sha256"],
        "maintenance_window": pilot["maintenance_window"],
        "record_sha256": hashlib.sha256(pilot_raw).hexdigest(),
        "rollback_owner": pilot["rollback_owner"],
        "validation_only": True,
    },
    "result": "pass",
    "schema_version": 1,
    "source_commit": commit,
    "task6": {
        "evidence_dir": evidence,
        "evidence_index_sha256": hashlib.sha256(
            task6_index_raw
        ).hexdigest(),
        "receipt_sha256": hashlib.sha256(task6_raw).hexdigest(),
        "result": task6["result"],
        "run_id": task6["run"]["run_id"],
        "writes": task6["writes"],
    },
    "v1": {"endpoint": "192.168.100.17:18090", "mode": "no-write",
           "status": "unchanged"},
}
payload = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "wb") as stream:
    stream.write(payload)
    stream.flush()
    os.fsync(stream.fileno())
PY
    ROLLOUT_V2_TRANSACTION_ACTIVE=0
    trap - ERR INT TERM
    rm -rf -- "$ROLLOUT_V2_SNAPSHOT"
    printf 'production_receipt=%s\n' "$receipt"
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    ((EUID == 0)) || { rollout_v2_die 'Run as root'; exit 1; }
    script_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
    rollout_install_execution_v2_main "" \
        "$script_root/build-managed-iso-release.sh" \
        "$script_root/../install-install-execution-api.sh" \
        "$script_root/../qemu/agent_v2_test_api.py" \
        "$script_root/verify-install-execution-pilot.py" "$@"
fi
