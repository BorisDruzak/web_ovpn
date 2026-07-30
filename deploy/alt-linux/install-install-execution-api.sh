#!/bin/bash
set -Eeuo pipefail

INSTALL_EXECUTION_API_ADDRESS=192.168.100.17
INSTALL_EXECUTION_API_PORT=18092
INSTALL_EXECUTION_API_UNIT=alt-install-execution.service

install_execution_api_error() {
    printf '%s\n' "$*" >&2
}

install_execution_api_require_safe_path() {
    local root_prefix=$1
    local absolute_path=$2
    local current=${root_prefix}
    local component
    local -a components

    IFS=/ read -r -a components <<< "${absolute_path#/}"
    for component in "${components[@]}"; do
        current="${current}/${component}"
        if [[ -L ${current} ]]; then
            install_execution_api_error "Symlinked destination parent rejected: ${absolute_path}"
            return 1
        fi
    done
}

install_execution_api_exact_socket_status() {
    local listeners
    local awk_status

    if ! listeners=$(ss -H -ltnp); then
        return 2
    fi
    INSTALL_EXECUTION_SOCKET_SNAPSHOT=${listeners}
    if printf '%s\n' "${listeners}" | awk \
        -v endpoint="${INSTALL_EXECUTION_API_ADDRESS}:${INSTALL_EXECUTION_API_PORT}" \
        -v port="${INSTALL_EXECUTION_API_PORT}" \
        '$4 == endpoint || $4 == "*:" port || $4 == "0.0.0.0:" port ||
         $4 == "[::]:" port || $4 == ":::" port { occupied = 1 }
         END { exit !occupied }'
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

install_execution_api_unit_is_managed() {
    local unit_path=$1
    local script_dir
    local expected_unit
    local fragment_path
    local drop_in_paths
    local need_daemon_reload

    if [[ ! -f ${unit_path} || -L ${unit_path} ]]; then
        return 1
    fi
    if ! script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &&
        pwd -P); then
        return 1
    fi
    expected_unit="${script_dir}/systemd/${INSTALL_EXECUTION_API_UNIT}"
    if [[ ! -f ${expected_unit} || -L ${expected_unit} ]] ||
       ! cmp -s -- "${expected_unit}" "${unit_path}"; then
        return 1
    fi
    if ! fragment_path=$(systemctl show --property=FragmentPath --value \
        "${INSTALL_EXECUTION_API_UNIT}") ||
       [[ ${fragment_path} != "${unit_path}" ]]; then
        return 1
    fi
    if ! drop_in_paths=$(systemctl show --property=DropInPaths --value \
        "${INSTALL_EXECUTION_API_UNIT}") ||
       [[ -n ${drop_in_paths} ]]; then
        return 1
    fi
    if ! need_daemon_reload=$(systemctl show \
        --property=NeedDaemonReload --value \
        "${INSTALL_EXECUTION_API_UNIT}") ||
       [[ ${need_daemon_reload} != no ]]; then
        return 1
    fi
}

install_execution_api_owned_listener_is_healthy() {
    local root_prefix=$1
    local current=$2
    local unit_path=$3
    local runtime_root="${root_prefix}/opt/alt-install-execution-api"
    local releases="${runtime_root}/releases"
    local canonical_releases
    local current_target
    local main_pid
    local endpoint
    local line
    local pid_tokens
    local exact_count=0

    if [[ ! -L ${current} ]]; then
        install_execution_api_error \
            "Occupied V2 listener has no managed runtime pointer"
        return 1
    fi
    if ! current_target=$(readlink -f -- "${current}") ||
       [[ ! -d ${current_target} ]]; then
        install_execution_api_error \
            "Occupied V2 listener runtime pointer is invalid"
        return 1
    fi
    if ! canonical_releases=$(cd -- "${releases}" && pwd -P); then
        install_execution_api_error \
            "Occupied V2 listener release root is unavailable"
        return 1
    fi
    case ${current_target} in
        "${canonical_releases}/"*) ;;
        *)
            install_execution_api_error \
                "Occupied V2 listener runtime is outside managed releases"
            return 1
            ;;
    esac
    if ! install_execution_api_unit_is_managed "${unit_path}"; then
        install_execution_api_error \
            "Occupied V2 listener unit is not the managed V2 unit"
        return 1
    fi
    if ! systemctl is-active "${INSTALL_EXECUTION_API_UNIT}" \
        >/dev/null 2>&1; then
        install_execution_api_error \
            "Occupied V2 listener managed unit is not active"
        return 1
    fi
    if ! main_pid=$(systemctl show --property=MainPID --value \
        "${INSTALL_EXECUTION_API_UNIT}") ||
       [[ ! ${main_pid} =~ ^[0-9]+$ ]] ||
       (( main_pid <= 1 )); then
        install_execution_api_error \
            "Occupied V2 listener managed unit PID is invalid"
        return 1
    fi
    while IFS= read -r line; do
        [[ -n ${line} ]] || continue
        endpoint=$(awk '{print $4}' <<< "${line}")
        case ${endpoint} in
            "*:${INSTALL_EXECUTION_API_PORT}"|\
            "0.0.0.0:${INSTALL_EXECUTION_API_PORT}"|\
            "[::]:${INSTALL_EXECUTION_API_PORT}"|\
            ":::${INSTALL_EXECUTION_API_PORT}")
                install_execution_api_error \
                    "Wildcard V2 listener cannot be treated as managed"
                return 1
                ;;
            "${INSTALL_EXECUTION_API_ADDRESS}:${INSTALL_EXECUTION_API_PORT}")
                exact_count=$((exact_count + 1))
                if ! pid_tokens=$(grep -oE 'pid=[0-9]+' <<< "${line}" |
                    sort -u) ||
                   [[ ${pid_tokens} != "pid=${main_pid}" ]]; then
                    install_execution_api_error \
                        "Occupied V2 listener PID does not match the managed unit"
                    return 1
                fi
                ;;
        esac
    done <<< "${INSTALL_EXECUTION_SOCKET_SNAPSHOT:-}"
    if (( exact_count != 1 )); then
        install_execution_api_error \
            "Occupied V2 listener set is ambiguous"
        return 1
    fi
    if ! install_execution_api_health_is_exact "${root_prefix}"; then
        install_execution_api_error \
            "Occupied V2 listener failed exact TLS health verification"
        return 1
    fi
}

install_execution_api_listener_allows_install() {
    local root_prefix=$1
    local current=$2
    local unit_path=$3
    local socket_status

    if install_execution_api_exact_socket_status; then
        socket_status=0
    else
        socket_status=$?
    fi
    case ${socket_status} in
        0)
            if install_execution_api_owned_listener_is_healthy \
                "${root_prefix}" "${current}" "${unit_path}"; then
                return 0
            fi
            install_execution_api_error \
                "Listener already occupies ${INSTALL_EXECUTION_API_ADDRESS}:${INSTALL_EXECUTION_API_PORT} and is not the verified managed V2 service"
            return 1
            ;;
        1) return 0 ;;
        *)
            install_execution_api_error \
                "Execution API socket inspection failed"
            return 1
            ;;
    esac
}

install_execution_api_atomic_pointer() {
    local link_path=$1
    local target=$2
    local temporary="${link_path}.new-$$"

    rm -f -- "${temporary}"
    ln -s -- "${target}" "${temporary}"
    mv -Tf -- "${temporary}" "${link_path}"
}

install_execution_api_atomic_regular_file() {
    local source=$1
    local destination=$2
    local temporary="${destination}.new-$$"

    rm -f -- "${temporary}"
    install -o root -g root -m 0644 "${source}" "${temporary}"
    if [[ ! -f ${temporary} || -L ${temporary} ]]; then
        install_execution_api_error "Atomic file staging is not regular"
        rm -f -- "${temporary}"
        return 1
    fi
    mv -Tf -- "${temporary}" "${destination}"
}

install_execution_api_initialize_tls() {
    local root_prefix=$1
    local control_root=$2

    ALT_DEPLOY_INSTALL_EXECUTION_TLS_ROOT="${root_prefix}/var/lib/alt-deploy-secrets" \
    ALT_DEPLOY_INSTALL_EXECUTION_CA_PRIVATE_KEY="${root_prefix}/var/lib/alt-deploy-secrets/install-execution-ca.pem" \
    ALT_DEPLOY_INSTALL_EXECUTION_SERVER_PRIVATE_KEY="${root_prefix}/var/lib/alt-deploy-secrets/install-execution-server.pem" \
    ALT_DEPLOY_INSTALL_EXECUTION_CA_CERTIFICATE="${root_prefix}/etc/alt-deploy/install-execution-ca.pem" \
    ALT_DEPLOY_INSTALL_EXECUTION_SERVER_CERTIFICATE="${root_prefix}/etc/alt-deploy/install-execution-server.pem" \
    ALT_DEPLOY_INSTALL_EXECUTION_LISTEN_ADDRESS="${INSTALL_EXECUTION_API_ADDRESS}" \
    PYTHONPATH="${control_root}" \
    python3 -c '
from alt_deploy.config import Settings
from alt_deploy.install_tls import ensure_execution_tls_material
ensure_execution_tls_material(Settings.from_env())
'
}

install_execution_api_health_is_exact() {
    local root_prefix=$1
    local health

    if ! health=$(curl --fail --silent --show-error --noproxy '*' \
        --proto '=https' --tlsv1.3 --max-time 5 \
        --cacert "${root_prefix}/etc/alt-deploy/install-execution-ca.pem" \
        "https://${INSTALL_EXECUTION_API_ADDRESS}:${INSTALL_EXECUTION_API_PORT}/health"); then
        return 1
    fi
    printf '%s\n' "${health}" | python3 -c '
import json
import sys
expected = {"schema_version": 1, "service": "alt-install-execution", "status": "ok"}
try:
    value = json.load(sys.stdin)
except (json.JSONDecodeError, UnicodeError):
    raise SystemExit(1)
raise SystemExit(value != expected)
'
}

install_execution_api_capture_systemd_state() {
    local enabled_rc
    local active_rc

    if systemctl is-enabled "${INSTALL_EXECUTION_API_UNIT}" >/dev/null 2>&1; then
        INSTALL_EXECUTION_WAS_ENABLED=1
    else
        enabled_rc=$?
        case ${enabled_rc} in
            1|4) INSTALL_EXECUTION_WAS_ENABLED=0 ;;
            *)
                install_execution_api_error "Execution API service state inspection failed"
                return 1
                ;;
        esac
    fi
    if systemctl is-active "${INSTALL_EXECUTION_API_UNIT}" >/dev/null 2>&1; then
        INSTALL_EXECUTION_WAS_ACTIVE=1
    else
        active_rc=$?
        case ${active_rc} in
            1|3|4) INSTALL_EXECUTION_WAS_ACTIVE=0 ;;
            *)
                install_execution_api_error "Execution API service state inspection failed"
                return 1
                ;;
        esac
    fi
}

install_execution_api_restore_activation() {
    trap - ERR INT TERM
    if [[ ${INSTALL_EXECUTION_TRANSACTION_ACTIVE:-0} != 1 ]]; then
        return 0
    fi
    INSTALL_EXECUTION_TRANSACTION_ACTIVE=0
    local -a failures=()
    local stopped=1
    local pointer_restored=1
    local unit_restored=1
    local reload_succeeded=1
    local activation_restored=1
    local failed_release_removed=1
    local releases
    local joined

    releases="$(dirname -- "${INSTALL_EXECUTION_CURRENT}")/releases"
    if ! systemctl stop "${INSTALL_EXECUTION_API_UNIT}"; then
        failures+=(service_stop)
        stopped=0
    fi
    if (( stopped == 1 )); then
        if [[ -n ${INSTALL_EXECUTION_OLD_CURRENT_TARGET:-} ]]; then
            if ! install_execution_api_atomic_pointer \
                "${INSTALL_EXECUTION_CURRENT}" \
                "${INSTALL_EXECUTION_OLD_CURRENT_TARGET}"; then
                failures+=(runtime_pointer_restore)
                pointer_restored=0
            fi
        elif ! rm -f -- "${INSTALL_EXECUTION_CURRENT}"; then
            failures+=(runtime_pointer_remove)
            pointer_restored=0
        fi
        if [[ ${INSTALL_EXECUTION_HAD_UNIT:-0} == 1 ]]; then
            if ! install_execution_api_atomic_regular_file \
                "${INSTALL_EXECUTION_UNIT_BACKUP}" \
                "${INSTALL_EXECUTION_UNIT_PATH}"; then
                failures+=(unit_restore)
                unit_restored=0
            fi
        elif ! rm -f -- "${INSTALL_EXECUTION_UNIT_PATH}"; then
            failures+=(unit_remove)
            unit_restored=0
        fi
    else
        failures+=(runtime_restore_skipped)
        pointer_restored=0
        unit_restored=0
    fi
    if (( stopped == 1 && unit_restored == 1 )); then
        if ! systemctl daemon-reload; then
            failures+=(daemon_reload)
            reload_succeeded=0
        fi
    else
        failures+=(daemon_reload_skipped)
        reload_succeeded=0
    fi
    if (( stopped == 1 && pointer_restored == 1 &&
          unit_restored == 1 && reload_succeeded == 1 )); then
        if [[ ${INSTALL_EXECUTION_WAS_ENABLED:-0} == 1 ]]; then
            if ! systemctl enable "${INSTALL_EXECUTION_API_UNIT}"; then
                failures+=(enable_restore)
                activation_restored=0
            fi
        elif ! systemctl disable "${INSTALL_EXECUTION_API_UNIT}"; then
            failures+=(disable_restore)
            activation_restored=0
        fi
        if [[ ${INSTALL_EXECUTION_WAS_ACTIVE:-0} == 1 ]]; then
            if (( activation_restored == 1 )); then
                if ! systemctl start "${INSTALL_EXECUTION_API_UNIT}"; then
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
    case ${INSTALL_EXECUTION_RELEASE_PATH:-} in
        "${releases}/"*)
            if [[ ${INSTALL_EXECUTION_RELEASE_PATH} == \
                  "${INSTALL_EXECUTION_OLD_CURRENT_TARGET:-}" ]]; then
                failures+=(failed_release_matches_previous)
                failed_release_removed=0
            elif (( stopped == 1 && pointer_restored == 1 &&
                    unit_restored == 1 && reload_succeeded == 1 &&
                    activation_restored == 1 )); then
                if ! rm -rf -- "${INSTALL_EXECUTION_RELEASE_PATH}"; then
                    failures+=(failed_release_remove)
                    failed_release_removed=0
                fi
            else
                failures+=(failed_release_remove_skipped)
                failed_release_removed=0
            fi
            ;;
        *)
            failures+=(failed_release_path_invalid)
            failed_release_removed=0
            ;;
    esac
    if ((${#failures[@]} == 0 && failed_release_removed == 1)); then
        if ! rm -rf -- "${INSTALL_EXECUTION_TRANSACTION_DIR}"; then
            failures+=(transaction_remove)
        fi
    fi
    if ((${#failures[@]} != 0)); then
        joined=$(IFS=,; printf '%s' "${failures[*]}")
        install_execution_api_error \
            "Execution API rollback failed: ${joined}; recovery transaction=${INSTALL_EXECUTION_TRANSACTION_DIR}; failed release=${INSTALL_EXECUTION_RELEASE_PATH}"
        return 1
    fi
    return 0
}

install_execution_api_fail_activation() {
    local message=$1

    install_execution_api_error "${message}"
    if ! install_execution_api_restore_activation; then
        install_execution_api_error \
            "Execution API activation failed and rollback is incomplete"
        return 70
    fi
    return 1
}

install_execution_api_install() {
    local root_prefix=$1
    local script_dir
    local alt_root
    local runtime_root="${root_prefix}/opt/alt-install-execution-api"
    local releases="${runtime_root}/releases"
    local current="${runtime_root}/current"
    local release_id
    local transaction
    local stage
    local release
    local unit_path="${root_prefix}/etc/systemd/system/${INSTALL_EXECUTION_API_UNIT}"

    script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
    alt_root=${script_dir}
    if [[ ! -f ${alt_root}/api/install_execution_server.py ||
          ! -f ${alt_root}/control/alt_deploy/install_tls.py ||
          ! -f ${alt_root}/systemd/${INSTALL_EXECUTION_API_UNIT} ]]; then
        install_execution_api_error "Execution API source is incomplete"
        return 1
    fi
    if ! install_execution_api_listener_allows_install \
        "${root_prefix}" "${current}" "${unit_path}"; then
        return 1
    fi
    for path in /opt/alt-install-execution-api/releases /etc/systemd/system \
        /var/lib/alt-deploy-secrets /etc/alt-deploy; do
        install_execution_api_require_safe_path "${root_prefix}" "${path}" || return 1
    done
    if [[ -e ${current} && ! -L ${current} ]]; then
        install_execution_api_error "Current runtime pointer is not a symlink"
        return 1
    fi
    if [[ -L ${unit_path} || ( -e ${unit_path} && ! -f ${unit_path} ) ]]; then
        install_execution_api_error "Service unit destination must be a regular file"
        return 1
    fi

    release_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
    transaction="${releases}/.transaction-${release_id}"
    stage="${transaction}/stage"
    release="${releases}/${release_id}"
    install -d -o root -g root -m 0755 "${releases}" "${transaction}" \
        "${stage}" "${stage}/api" "${stage}/control" \
        "${root_prefix}/etc/systemd/system" "${root_prefix}/etc/alt-deploy"
    cp -a -- "${alt_root}/api/." "${stage}/api/"
    cp -a -- "${alt_root}/control/." "${stage}/control/"
    if [[ -n $(find "${stage}" -type l -print -quit) ]]; then
        install_execution_api_error "Staged runtime contains a symlink"
        rm -rf -- "${transaction}"
        return 1
    fi
    chown -R root:root "${stage}"
    chmod 0755 "${stage}" "${stage}/api" "${stage}/control"
    if ! install_execution_api_initialize_tls "${root_prefix}" "${stage}/control"; then
        install_execution_api_error "Execution TLS material initialization failed"
        rm -rf -- "${transaction}"
        return 1
    fi
    INSTALL_EXECUTION_CURRENT=${current}
    INSTALL_EXECUTION_UNIT_PATH=${unit_path}
    INSTALL_EXECUTION_TRANSACTION_DIR=${transaction}
    INSTALL_EXECUTION_RELEASE_PATH=${release}
    INSTALL_EXECUTION_UNIT_BACKUP="${transaction}/unit.backup"
    INSTALL_EXECUTION_OLD_CURRENT_TARGET=
    INSTALL_EXECUTION_HAD_UNIT=0
    INSTALL_EXECUTION_WAS_ENABLED=0
    INSTALL_EXECUTION_WAS_ACTIVE=0
    INSTALL_EXECUTION_TRANSACTION_ACTIVE=0
    if [[ -L ${current} ]]; then
        INSTALL_EXECUTION_OLD_CURRENT_TARGET=$(readlink -- "${current}")
    fi
    if [[ -f ${unit_path} ]]; then
        cp -- "${unit_path}" "${INSTALL_EXECUTION_UNIT_BACKUP}"
        INSTALL_EXECUTION_HAD_UNIT=1
    fi
    if ! install_execution_api_capture_systemd_state; then
        rm -rf -- "${transaction}"
        return 1
    fi
    mv -- "${stage}" "${release}"
    INSTALL_EXECUTION_TRANSACTION_ACTIVE=1
    if ! install_execution_api_atomic_pointer "${current}" "${release}"; then
        install_execution_api_fail_activation "Execution API current pointer activation failed"
        return $?
    fi
    if ! install_execution_api_atomic_regular_file \
        "${alt_root}/systemd/${INSTALL_EXECUTION_API_UNIT}" "${unit_path}"; then
        install_execution_api_fail_activation "Execution API unit installation failed"
        return $?
    fi
    if ! systemctl daemon-reload; then
        install_execution_api_fail_activation "Execution API daemon reload failed"
        return $?
    fi
    if ! systemctl enable "${INSTALL_EXECUTION_API_UNIT}"; then
        install_execution_api_fail_activation \
            "Execution API activation enablement failed"
        return $?
    fi
    if ! systemctl restart "${INSTALL_EXECUTION_API_UNIT}"; then
        install_execution_api_fail_activation "Execution API activation failed"
        return $?
    fi
    if ! install_execution_api_health_is_exact "${root_prefix}"; then
        install_execution_api_fail_activation "Execution API TLS health validation failed"
        return $?
    fi
    rm -rf -- "${transaction}"
    INSTALL_EXECUTION_TRANSACTION_ACTIVE=0
    printf 'Installed V2 execution API: %s\n' "${release_id}"
}

install_execution_api_main() {
    local root_prefix=$1
    shift
    if (( $# != 0 )); then
        install_execution_api_error "usage: install-install-execution-api.sh"
        return 2
    fi
    install_execution_api_install "${root_prefix}"
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    if (( EUID != 0 )); then
        install_execution_api_error "Run as root"
        exit 1
    fi
    install_execution_api_main "" "$@"
fi
