#!/bin/bash
set -Eeuo pipefail

INSTALL_SESSION_API_ADDRESS=192.168.100.17
INSTALL_SESSION_API_PORT=18090
INSTALL_SESSION_API_UNIT=alt-install-session.service

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

install_session_api_exact_socket_is_occupied() {
    ss -H -ltn | awk \
        -v endpoint="${INSTALL_SESSION_API_ADDRESS}:${INSTALL_SESSION_API_PORT}" \
        '$4 == endpoint { occupied = 1 } END { exit !occupied }'
}

install_session_api_atomic_pointer() {
    local link_path=$1
    local target=$2
    local temporary="${link_path}.new-$$"

    rm -f -- "${temporary}"
    ln -s -- "${target}" "${temporary}"
    mv -Tf -- "${temporary}" "${link_path}"
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
            install -o root -g root -m 0644 \
                "${INSTALL_SESSION_UNIT_BACKUP}" \
                "${INSTALL_SESSION_UNIT_PATH}" || true
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
    local health

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
    if install_session_api_exact_socket_is_occupied; then
        install_session_api_error \
            "Listener already occupies ${INSTALL_SESSION_API_ADDRESS}:${INSTALL_SESSION_API_PORT}"
        return 1
    fi

    install_session_api_require_safe_path \
        "${root_prefix}" "/opt/alt-install-session-api/releases" || return 1
    install_session_api_require_safe_path \
        "${root_prefix}" "/etc/systemd/system" || return 1

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
    if [[ -f ${unit_path} ]]; then
        cp -- "${unit_path}" "${INSTALL_SESSION_UNIT_BACKUP}"
        INSTALL_SESSION_HAD_UNIT=1
    elif [[ -e ${unit_path} ]]; then
        install_session_api_error "Service unit destination is not a regular file"
        install_session_api_abandon_stage
        return 1
    fi
    if systemctl is-enabled --quiet "${INSTALL_SESSION_API_UNIT}"; then
        INSTALL_SESSION_WAS_ENABLED=1
    fi
    if systemctl is-active --quiet "${INSTALL_SESSION_API_UNIT}"; then
        INSTALL_SESSION_WAS_ACTIVE=1
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
    if ! install -o root -g root -m 0644 \
        "${alt_root}/systemd/${INSTALL_SESSION_API_UNIT}" \
        "${unit_path}"; then
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

    if ! health=$(curl --fail --silent --show-error \
        --max-time 5 \
        "http://${INSTALL_SESSION_API_ADDRESS}:${INSTALL_SESSION_API_PORT}/health")
    then
        install_session_api_error "Install session API health validation failed"
        install_session_api_restore_activation 1
    fi
    if ! printf '%s\n' "${health}" | python3 -c '
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
'; then
        install_session_api_error "Install session API health validation failed"
        install_session_api_restore_activation 1
    fi

    INSTALL_SESSION_TRANSACTION_ACTIVE=0
    trap - ERR INT TERM
    rm -rf -- "${INSTALL_SESSION_TRANSACTION_DIR}"
}

install_session_api_main() {
    local root_prefix=$1
    shift

    case ${1:-} in
        --rollback)
            if (( $# != 1 )); then
                install_session_api_error \
                    "usage: install-install-session-api.sh --rollback"
                return 2
            fi
            install_session_api_rollback "${root_prefix}"
            ;;
        --rollback-backup-id)
            if (( $# != 2 )) || [[ -z ${2:-} ]]; then
                install_session_api_error \
                    "usage: install-install-session-api.sh --rollback-backup-id BACKUP_ID"
                return 2
            fi
            install_session_api_install "${root_prefix}" "$2"
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
