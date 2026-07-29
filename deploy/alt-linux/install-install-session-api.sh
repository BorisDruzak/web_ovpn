#!/bin/bash
set -Eeuo pipefail

INSTALL_SESSION_API_ADDRESS=192.168.100.17
INSTALL_SESSION_API_PORT=18090
INSTALL_SESSION_API_UNIT=alt-install-session.service
INSTALL_SESSION_API_HEALTH_ATTEMPTS=5
INSTALL_SESSION_API_HEALTH_RETRY_SECONDS=1

install_session_api_error() {
    printf '%s\n' "$*" >&2
}

install_session_api_require_safe_path() {
    local root_prefix=$1
    local absolute_path=$2
    local relative_path=${absolute_path#/}
    local current=${root_prefix}
    local component
    local -a components

    IFS=/ read -r -a components <<< "${relative_path}"
    for component in "${components[@]}"; do
        current="${current}/${component}"
        if [[ -L ${current} ]]; then
            install_session_api_error \
                "Symlinked destination parent rejected: ${absolute_path}"
            return 1
        fi
    done
}

install_session_api_validate_rehearsal() {
    local payload=$1
    local backup_id=$2

    printf '%s\n' "${payload}" | python3 -c '
import json
import re
import sys

expected_id = sys.argv[1]
try:
    value = json.load(sys.stdin)
except (json.JSONDecodeError, UnicodeError):
    raise SystemExit(1)
expected_keys = {
    "status",
    "result",
    "backup_id",
    "manifest_sha256",
    "verification_sha256",
}
if not isinstance(value, dict) or set(value) != expected_keys:
    raise SystemExit(1)
if value["status"] != "ok" or value["result"] != "backup_rehearsed":
    raise SystemExit(1)
if value["backup_id"] != expected_id:
    raise SystemExit(1)
for key in ("manifest_sha256", "verification_sha256"):
    if not isinstance(value[key], str) or not re.fullmatch(r"[0-9a-f]{64}", value[key]):
        raise SystemExit(1)
' "${backup_id}"
}

install_session_api_acquire_installer_lock() {
    local root_prefix=$1
    local lock_directory="${root_prefix}/run/lock"
    local lock_path="${lock_directory}/alt-install-session-installer.lock"
    local metadata

    install_session_api_require_safe_path \
        "${root_prefix}" "/run/lock/alt-install-session-installer.lock" ||
        return 1
    install -d -o root -g root -m 0755 "${lock_directory}"
    if [[ ! -e ${lock_path} ]]; then
        install -o root -g root -m 0600 /dev/null "${lock_path}"
    elif [[ ! -f ${lock_path} || -L ${lock_path} ]]; then
        install_session_api_error "Installer lock is not a regular file"
        return 1
    fi
    chown root:root "${lock_path}"
    chmod 0600 "${lock_path}"
    metadata=$(stat -c '%U %G %a' "${lock_path}") || {
        install_session_api_error "Installer lock metadata cannot be inspected"
        return 1
    }
    if [[ ${metadata} != "root root 600" ]]; then
        install_session_api_error "Installer lock metadata is unsafe"
        return 1
    fi
    exec {INSTALL_SESSION_INSTALLER_LOCK_FD}<>"${lock_path}"
    if ! flock --exclusive --nonblock \
        "${INSTALL_SESSION_INSTALLER_LOCK_FD}"; then
        install_session_api_error \
            "Another install session API installer is running"
        exec {INSTALL_SESSION_INSTALLER_LOCK_FD}>&-
        return 1
    fi
}

install_session_api_release_installer_lock() {
    if [[ -n ${INSTALL_SESSION_INSTALLER_LOCK_FD:-} ]]; then
        exec {INSTALL_SESSION_INSTALLER_LOCK_FD}>&-
    fi
}

install_session_api_exact_socket_status() {
    local listeners
    local awk_status

    if ! listeners=$(ss -H -ltn); then
        return 2
    fi
    if printf '%s\n' "${listeners}" | awk \
        -v endpoint="${INSTALL_SESSION_API_ADDRESS}:${INSTALL_SESSION_API_PORT}" \
        '$4 == endpoint { occupied = 1 } END { exit !occupied }'
    then
        return 0
    else
        awk_status=$?
    fi
    if (( awk_status == 1 )); then
        return 1
    fi
    return 2
}

install_session_api_atomic_pointer() {
    local link_path=$1
    local target=$2
    local temporary="${link_path}.new-$$"

    rm -f -- "${temporary}"
    ln -s -- "${target}" "${temporary}"
    mv -Tf -- "${temporary}" "${link_path}"
}

install_session_api_atomic_regular_file() {
    local source=$1
    local destination=$2
    local owner=$3
    local group=$4
    local mode=$5
    local temporary="${destination}.new-$$"

    rm -f -- "${temporary}"
    install -o "${owner}" -g "${group}" -m "${mode}" \
        "${source}" "${temporary}"
    if [[ ! -f ${temporary} || -L ${temporary} ]]; then
        install_session_api_error "Atomic file staging is not regular"
        rm -f -- "${temporary}"
        return 1
    fi
    mv -Tf -- "${temporary}" "${destination}"
}

install_session_api_capture_systemd_state() {
    local enabled_status
    local enabled_rc
    local active_status
    local active_rc

    if enabled_status=$(systemctl is-enabled \
        "${INSTALL_SESSION_API_UNIT}" 2>/dev/null)
    then
        enabled_rc=0
    else
        enabled_rc=$?
    fi
    case "${enabled_status}:${enabled_rc}" in
        enabled:0)
            INSTALL_SESSION_WAS_ENABLED=1
            ;;
        disabled:1|not-found:1|not-found:4)
            INSTALL_SESSION_WAS_ENABLED=0
            ;;
        *)
            install_session_api_error \
                "Install session API service state inspection failed"
            return 1
            ;;
    esac

    if active_status=$(systemctl is-active \
        "${INSTALL_SESSION_API_UNIT}" 2>/dev/null)
    then
        active_rc=0
    else
        active_rc=$?
    fi
    case "${active_status}:${active_rc}" in
        active:0)
            INSTALL_SESSION_WAS_ACTIVE=1
            ;;
        inactive:3|unknown:3|unknown:4)
            INSTALL_SESSION_WAS_ACTIVE=0
            ;;
        *)
            install_session_api_error \
                "Install session API service state inspection failed"
            return 1
            ;;
    esac
}

install_session_api_prepare_storage() {
    local root_prefix=$1
    local sessions="${root_prefix}/var/lib/alt-deploy/install-sessions"
    local sessions_lock="${root_prefix}/var/lib/alt-deploy/install-sessions.lock"
    local metadata

    install_session_api_require_safe_path \
        "${root_prefix}" "/var/lib/alt-deploy/install-sessions" ||
        return 1
    install_session_api_require_safe_path \
        "${root_prefix}" "/var/lib/alt-deploy/install-sessions.lock" ||
        return 1
    if [[ -e ${sessions} && ! -d ${sessions} ]]; then
        install_session_api_error "Install session storage is not a directory"
        return 1
    fi
    install -d -o altserver -g altserver -m 0700 "${sessions}"
    if [[ ! -e ${sessions_lock} ]]; then
        install -o altserver -g altserver -m 0600 \
            /dev/null "${sessions_lock}"
    elif [[ ! -f ${sessions_lock} || -L ${sessions_lock} ]]; then
        install_session_api_error "Install session lock is not a regular file"
        return 1
    fi
    chown altserver:altserver "${sessions}" "${sessions_lock}"
    chmod 0700 "${sessions}"
    chmod 0600 "${sessions_lock}"

    metadata=$(stat -c '%U %G %a' "${sessions}") || return 1
    if [[ ${metadata} != "altserver altserver 700" ]]; then
        install_session_api_error "Install session storage metadata is unsafe"
        return 1
    fi
    metadata=$(stat -c '%U %G %a' "${sessions_lock}") || return 1
    if [[ ${metadata} != "altserver altserver 600" ]]; then
        install_session_api_error "Install session lock metadata is unsafe"
        return 1
    fi
}

install_session_api_health_is_exact() {
    local health

    if ! health=$(curl --fail --silent --show-error \
        --noproxy '*' \
        --max-time 5 \
        "http://${INSTALL_SESSION_API_ADDRESS}:${INSTALL_SESSION_API_PORT}/health")
    then
        return 1
    fi
    printf '%s\n' "${health}" | python3 -c '
import json
import sys

expected = {
    "schema_version": 1,
    "service": "alt-install-session",
    "status": "ok",
}
try:
    value = json.load(sys.stdin)
except (json.JSONDecodeError, UnicodeError):
    raise SystemExit(1)
if value != expected:
    raise SystemExit(1)
'
}

install_session_api_wait_for_health() {
    local attempt

    for ((attempt = 1;
         attempt <= INSTALL_SESSION_API_HEALTH_ATTEMPTS;
         attempt++)); do
        if install_session_api_health_is_exact; then
            return 0
        fi
        if (( attempt < INSTALL_SESSION_API_HEALTH_ATTEMPTS )); then
            sleep "${INSTALL_SESSION_API_HEALTH_RETRY_SECONDS}"
        fi
    done
    return 1
}

install_session_api_restore_activation() {
    local exit_code=$1

    trap - ERR INT TERM
    if [[ ${INSTALL_SESSION_TRANSACTION_ACTIVE:-0} == 1 ]]; then
        if [[ -n ${INSTALL_SESSION_OLD_CURRENT_TARGET:-} ]]; then
            install_session_api_atomic_pointer \
                "${INSTALL_SESSION_CURRENT}" \
                "${INSTALL_SESSION_OLD_CURRENT_TARGET}" || true
        else
            rm -f -- "${INSTALL_SESSION_CURRENT}" || true
        fi
        if [[ -n ${INSTALL_SESSION_OLD_PREVIOUS_TARGET:-} ]]; then
            install_session_api_atomic_pointer \
                "${INSTALL_SESSION_PREVIOUS}" \
                "${INSTALL_SESSION_OLD_PREVIOUS_TARGET}" || true
        else
            rm -f -- "${INSTALL_SESSION_PREVIOUS}" || true
        fi

        if [[ ${INSTALL_SESSION_HAD_UNIT:-0} == 1 ]]; then
            install_session_api_atomic_regular_file \
                "${INSTALL_SESSION_UNIT_BACKUP}" \
                "${INSTALL_SESSION_UNIT_PATH}" \
                root root 0644 || true
        else
            rm -f -- "${INSTALL_SESSION_UNIT_PATH}" || true
        fi
        systemctl daemon-reload || true

        if [[ ${INSTALL_SESSION_WAS_ENABLED:-0} == 1 ]]; then
            systemctl enable "${INSTALL_SESSION_API_UNIT}" || true
        else
            systemctl disable "${INSTALL_SESSION_API_UNIT}" || true
        fi
        if [[ ${INSTALL_SESSION_WAS_ACTIVE:-0} == 1 ]]; then
            systemctl start "${INSTALL_SESSION_API_UNIT}" || true
        else
            systemctl stop "${INSTALL_SESSION_API_UNIT}" || true
        fi
    fi

    if [[ -n ${INSTALL_SESSION_RELEASE_PATH:-} ]]; then
        rm -rf -- "${INSTALL_SESSION_RELEASE_PATH}" || true
    fi
    if [[ -n ${INSTALL_SESSION_TRANSACTION_DIR:-} ]]; then
        rm -rf -- "${INSTALL_SESSION_TRANSACTION_DIR}" || true
    fi
    exit "${exit_code}"
}

install_session_api_abandon_stage() {
    trap - ERR INT TERM
    if [[ -n ${INSTALL_SESSION_RELEASE_PATH:-} ]]; then
        rm -rf -- "${INSTALL_SESSION_RELEASE_PATH}"
    fi
    if [[ -n ${INSTALL_SESSION_TRANSACTION_DIR:-} ]]; then
        rm -rf -- "${INSTALL_SESSION_TRANSACTION_DIR}"
    fi
}

install_session_api_rollback() {
    local root_prefix=$1
    local runtime_root="${root_prefix}/opt/alt-install-session-api"
    local current="${runtime_root}/current"
    local previous="${runtime_root}/previous"
    local old_current_target=
    local previous_target

    install_session_api_require_safe_path \
        "${root_prefix}" "/opt/alt-install-session-api" || return 1
    if [[ ! -L ${previous} ]]; then
        install_session_api_error "No previous install session API runtime"
        return 1
    fi
    previous_target=$(readlink -- "${previous}")
    if [[ ! -d ${previous_target} ]]; then
        install_session_api_error "Previous install session API runtime is invalid"
        return 1
    fi
    if [[ -L ${current} ]]; then
        old_current_target=$(readlink -- "${current}")
    elif [[ -e ${current} ]]; then
        install_session_api_error "Current runtime pointer is not a symlink"
        return 1
    fi

    systemctl disable --now "${INSTALL_SESSION_API_UNIT}"
    install_session_api_atomic_pointer "${current}" "${previous_target}"
    if [[ -n ${old_current_target} ]]; then
        install_session_api_atomic_pointer "${previous}" "${old_current_target}"
    else
        rm -f -- "${previous}"
    fi
}

install_session_api_install() {
    local root_prefix=$1
    local rollback_backup_id=$2
    local script_dir
    local alt_root
    local backup_tool="${root_prefix}/usr/local/sbin/alt-deploy-backup"
    local runtime_root="${root_prefix}/opt/alt-install-session-api"
    local releases="${runtime_root}/releases"
    local current="${runtime_root}/current"
    local previous="${runtime_root}/previous"
    local unit_path="${root_prefix}/etc/systemd/system/${INSTALL_SESSION_API_UNIT}"
    local release_id
    local stage
    local rehearsal
    local socket_status

    if [[ ! ${rollback_backup_id} =~ ^backup-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$ ]]; then
        install_session_api_error "Invalid rollback backup ID"
        return 2
    fi
    if [[ ! -x ${backup_tool} ]]; then
        install_session_api_error "Installed alt-deploy-backup is required"
        return 1
    fi
    if ! rehearsal=$("${backup_tool}" rehearse-status "${rollback_backup_id}"); then
        install_session_api_error "Rollback rehearsal status failed"
        return 1
    fi
    if ! install_session_api_validate_rehearsal \
        "${rehearsal}" "${rollback_backup_id}"; then
        install_session_api_error "Invalid rollback rehearsal status"
        return 1
    fi
    if install_session_api_exact_socket_status; then
        socket_status=0
    else
        socket_status=$?
    fi
    case ${socket_status} in
        0)
            install_session_api_error \
                "Listener already occupies ${INSTALL_SESSION_API_ADDRESS}:${INSTALL_SESSION_API_PORT}"
            return 1
            ;;
        1) ;;
        *)
            install_session_api_error \
                "Install session API socket inspection failed"
            return 1
            ;;
    esac

    install_session_api_require_safe_path \
        "${root_prefix}" "/opt/alt-install-session-api/releases" || return 1
    install_session_api_require_safe_path \
        "${root_prefix}" "/etc/systemd/system" || return 1
    if [[ -L ${unit_path} ]]; then
        install_session_api_error \
            "Service unit destination must not be a symlink"
        return 1
    fi
    install_session_api_require_safe_path \
        "${root_prefix}" \
        "/etc/systemd/system/${INSTALL_SESSION_API_UNIT}" || return 1

    script_dir=$(
        cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
        pwd -P
    )
    alt_root=${script_dir}
    release_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
    INSTALL_SESSION_TRANSACTION_DIR="${releases}/.transaction-${release_id}"
    stage="${INSTALL_SESSION_TRANSACTION_DIR}/stage"
    INSTALL_SESSION_RELEASE_PATH="${releases}/${release_id}"
    INSTALL_SESSION_UNIT_BACKUP="${INSTALL_SESSION_TRANSACTION_DIR}/unit.backup"
    INSTALL_SESSION_UNIT_PATH=${unit_path}
    INSTALL_SESSION_CURRENT=${current}
    INSTALL_SESSION_PREVIOUS=${previous}
    INSTALL_SESSION_TRANSACTION_ACTIVE=0
    INSTALL_SESSION_OLD_CURRENT_TARGET=
    INSTALL_SESSION_OLD_PREVIOUS_TARGET=
    INSTALL_SESSION_HAD_UNIT=0
    INSTALL_SESSION_WAS_ENABLED=0
    INSTALL_SESSION_WAS_ACTIVE=0

    trap 'install_session_api_restore_activation $?' ERR INT TERM

    install -d -o root -g root -m 0755 \
        "${releases}" \
        "${INSTALL_SESSION_TRANSACTION_DIR}" \
        "${stage}" \
        "${stage}/api" \
        "${stage}/control" \
        "${stage}/autoinstall" \
        "${stage}/autoinstall/profiles"
    cp -a -- "${alt_root}/api/." "${stage}/api/"
    cp -a -- "${alt_root}/control/." "${stage}/control/"
    cp -a -- \
        "${alt_root}/autoinstall/profiles/." \
        "${stage}/autoinstall/profiles/"

    if [[ -n $(find "${stage}" -type l -print -quit) ]]; then
        install_session_api_error "Staged runtime contains a symlink"
        install_session_api_abandon_stage
        return 1
    fi
    for required in \
        "${stage}/api/install_session_server.py" \
        "${stage}/api/install_session_key_init.py" \
        "${stage}/control/alt_deploy/install_session_keys.py"
    do
        if [[ ! -f ${required} ]]; then
            install_session_api_error "Staged runtime is incomplete"
            install_session_api_abandon_stage
            return 1
        fi
    done
    chown -R root:root "${stage}"
    chmod 0755 "${stage}" "${stage}/api" "${stage}/control"

    if ! PYTHONPATH="${stage}/control" \
        python3 "${stage}/api/install_session_key_init.py" >/dev/null; then
        install_session_api_error "Install signing key initialization failed"
        install_session_api_abandon_stage
        return 1
    fi

    mv -- "${stage}" "${INSTALL_SESSION_RELEASE_PATH}"

    if [[ -L ${current} ]]; then
        INSTALL_SESSION_OLD_CURRENT_TARGET=$(readlink -- "${current}")
    elif [[ -e ${current} ]]; then
        install_session_api_error "Current runtime pointer is not a symlink"
        install_session_api_abandon_stage
        return 1
    fi
    if [[ -L ${previous} ]]; then
        INSTALL_SESSION_OLD_PREVIOUS_TARGET=$(readlink -- "${previous}")
    elif [[ -e ${previous} ]]; then
        install_session_api_error "Previous runtime pointer is not a symlink"
        install_session_api_abandon_stage
        return 1
    fi
    if [[ -L ${unit_path} ]]; then
        install_session_api_error \
            "Service unit destination must not be a symlink"
        install_session_api_abandon_stage
        return 1
    elif [[ -f ${unit_path} ]]; then
        cp -- "${unit_path}" "${INSTALL_SESSION_UNIT_BACKUP}"
        INSTALL_SESSION_HAD_UNIT=1
    elif [[ -e ${unit_path} ]]; then
        install_session_api_error "Service unit destination is not a regular file"
        install_session_api_abandon_stage
        return 1
    fi
    if ! install_session_api_capture_systemd_state; then
        install_session_api_abandon_stage
        return 1
    fi
    if ! install_session_api_prepare_storage "${root_prefix}"; then
        install_session_api_abandon_stage
        return 1
    fi

    INSTALL_SESSION_TRANSACTION_ACTIVE=1
    if [[ -n ${INSTALL_SESSION_OLD_CURRENT_TARGET} ]]; then
        if ! install_session_api_atomic_pointer \
            "${previous}" "${INSTALL_SESSION_OLD_CURRENT_TARGET}"; then
            install_session_api_error \
                "Install session API previous pointer activation failed"
            install_session_api_restore_activation 1
        fi
    fi
    if ! install_session_api_atomic_pointer \
        "${current}" "${INSTALL_SESSION_RELEASE_PATH}"; then
        install_session_api_error \
            "Install session API current pointer activation failed"
        install_session_api_restore_activation 1
    fi
    if ! install_session_api_atomic_regular_file \
        "${alt_root}/systemd/${INSTALL_SESSION_API_UNIT}" \
        "${unit_path}" root root 0644; then
        install_session_api_error "Install session API unit installation failed"
        install_session_api_restore_activation 1
    fi
    if ! systemctl daemon-reload; then
        install_session_api_error "Install session API daemon reload failed"
        install_session_api_restore_activation 1
    fi
    if ! systemctl enable --now "${INSTALL_SESSION_API_UNIT}"; then
        install_session_api_error "Install session API activation failed"
        install_session_api_restore_activation 1
    fi

    if ! install_session_api_wait_for_health; then
        install_session_api_error "Install session API health validation failed"
        install_session_api_restore_activation 1
    fi

    INSTALL_SESSION_TRANSACTION_ACTIVE=0
    trap - ERR INT TERM
    rm -rf -- "${INSTALL_SESSION_TRANSACTION_DIR}"
}

install_session_api_main() {
    local root_prefix=$1
    local result
    shift

    case ${1:-} in
        --rollback)
            if (( $# != 1 )); then
                install_session_api_error \
                    "usage: install-install-session-api.sh --rollback"
                return 2
            fi
            if ! install_session_api_acquire_installer_lock \
                "${root_prefix}"; then
                return 1
            fi
            if install_session_api_rollback "${root_prefix}"; then
                result=0
            else
                result=$?
            fi
            install_session_api_release_installer_lock
            return "${result}"
            ;;
        --rollback-backup-id)
            if (( $# != 2 )) || [[ -z ${2:-} ]]; then
                install_session_api_error \
                    "usage: install-install-session-api.sh --rollback-backup-id BACKUP_ID"
                return 2
            fi
            if ! install_session_api_acquire_installer_lock \
                "${root_prefix}"; then
                return 1
            fi
            if install_session_api_install "${root_prefix}" "$2"; then
                result=0
            else
                result=$?
            fi
            install_session_api_release_installer_lock
            return "${result}"
            ;;
        *)
            install_session_api_error \
                "usage: install-install-session-api.sh --rollback-backup-id BACKUP_ID | --rollback"
            return 2
            ;;
    esac
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    if (( EUID != 0 )); then
        install_session_api_error "Run as root"
        exit 1
    fi
    install_session_api_main "" "$@"
fi
