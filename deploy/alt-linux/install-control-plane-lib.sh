#!/bin/bash

install_destination() {
    local root_prefix=$1
    local absolute_path=$2
    printf '%s%s' "${root_prefix}" "${absolute_path}"
}

require_command() {
    local command_name=$1
    if ! command -v "${command_name}" >/dev/null 2>&1; then
        echo "Missing required command: ${command_name}" >&2
        return 1
    fi
}

require_regular_nonempty() {
    local path=$1
    if [[ ! -f "${path}" || -L "${path}" || ! -s "${path}" ]]; then
        echo "Unsafe or missing required runtime file: ${path}" >&2
        return 1
    fi
}

require_directory() {
    local path=$1
    if [[ ! -d "${path}" || -L "${path}" ]]; then
        echo "Unsafe or missing required directory: ${path}" >&2
        return 1
    fi
}

installer_python() {
    if [[ -x "${REPO_ROOT}/.venv/bin/python" ]]; then
        printf '%s' "${REPO_ROOT}/.venv/bin/python"
    else
        printf '%s' python3
    fi
}

rollback_backup_id_valid() {
    local backup_id=$1
    [[ ${backup_id} =~ ^backup-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$ ]]
}

installed_backup_tool() {
    local root_prefix=$1
    install_destination "${root_prefix}" /usr/local/sbin/alt-deploy-backup
}

run_installed_backup_tool() {
    local root_prefix=$1
    shift
    local executable
    executable=$(installed_backup_tool "${root_prefix}")
    if [[ ! -f "${executable}" || -L "${executable}" || ! -x "${executable}" ]]; then
        echo "Installed OR-3P3 backup utility is unavailable" >&2
        return 1
    fi
    local expected_uid=0
    local expected_gid=0
    if [[ -n "${root_prefix}" ]]; then
        expected_uid=${ALT_DEPLOY_BACKUP_EXPECTED_ROOT_UID:?}
        expected_gid=${ALT_DEPLOY_BACKUP_EXPECTED_ROOT_GID:?}
    fi
    local metadata
    metadata=$(stat -c '%u %g %a' "${executable}") || {
        echo "Installed OR-3P3 backup utility metadata is unavailable" >&2
        return 1
    }
    if [[ "${metadata}" != "${expected_uid} ${expected_gid} 750" ]]; then
        echo "Installed OR-3P3 backup utility metadata is unsafe" >&2
        return 1
    fi
    "${executable}" "$@"
}

validate_rollback_backup() {
    local root_prefix=$1
    local backup_id=$2
    if [[ -z "${backup_id}" ]]; then
        echo "An explicit rollback backup ID is required" >&2
        return 1
    fi
    if ! rollback_backup_id_valid "${backup_id}"; then
        echo "Invalid rollback backup ID" >&2
        return 1
    fi
    local response
    if ! response=$(run_installed_backup_tool \
        "${root_prefix}" rehearse-status "${backup_id}"); then
        echo "Rollback backup is not currently verified and rehearsed" >&2
        return 1
    fi
    if ! printf '%s' "${response}" | python3 -c '
import json
import re
import sys
backup_id = sys.argv[1]
payload = json.load(sys.stdin)
if not isinstance(payload, dict) or set(payload) != {
    "status",
    "result",
    "backup_id",
    "manifest_sha256",
    "verification_sha256",
}:
    raise SystemExit(1)
if payload["status"] != "ok":
    raise SystemExit(1)
if payload["result"] != "backup_rehearsed":
    raise SystemExit(1)
if payload["backup_id"] != backup_id:
    raise SystemExit(1)
for key in ("manifest_sha256", "verification_sha256"):
    value = payload[key]
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise SystemExit(1)
' "${backup_id}"; then
        echo "Rollback backup eligibility response is invalid" >&2
        return 1
    fi
}

stop_control_plane_after_failed_rollout() {
    stop_if_loaded alt-deploy-process.path || true
    stop_if_loaded alt-deploy-register.service || true
    stop_if_loaded alt-deploy-http.service || true
}

revoke_failed_rollout() {
    local root_prefix=$1
    local backup_id=$2
    run_installed_backup_tool \
        "${root_prefix}" rollout-revoke "${backup_id}" >/dev/null || true
    stop_control_plane_after_failed_rollout
}

validate_source_layout() {
    require_directory "${ALT_ROOT}/control/alt_deploy"
    require_directory "${ALT_ROOT}/ansible/playbooks"
    require_directory "${ALT_ROOT}/ansible/roles"

    local required_files=(
        "${ALT_ROOT}/control/workstationctl"
        "${ALT_ROOT}/control/alt-provision-worker"
        "${ALT_ROOT}/control/alt-job-stage"
        "${ALT_ROOT}/api/static_server.py"
        "${ALT_ROOT}/api/register_api.py"
        "${ALT_ROOT}/api/process_pending.py"
        "${ALT_ROOT}/systemd/alt-deploy-http.service"
        "${ALT_ROOT}/systemd/alt-deploy-register.service"
        "${ALT_ROOT}/systemd/alt-deploy-process.path"
        "${ALT_ROOT}/systemd/alt-deploy-process.service"
        "${ALT_ROOT}/ansible/ansible.cfg"
        "${ALT_ROOT}/ansible/group_vars/all.yml"
        "${ALT_ROOT}/ansible/playbooks/01-preflight.yml"
        "${ALT_ROOT}/ansible/playbooks/02-provision-account.yml"
        "${ALT_ROOT}/bootstrap/bootstrap.sh"
        "${ALT_ROOT}/bootstrap/alt-bootstrap-register"
        "${ALT_ROOT}/install-control-plane.sh"
        "${ALT_ROOT}/install-control-plane-args.sh"
        "${ALT_ROOT}/install-control-plane-lib.sh"
    )

    local required_file
    for required_file in "${required_files[@]}"; do
        require_regular_nonempty "${required_file}"
    done
}

run_source_cli() {
    local root_prefix=$1
    shift
    local python_bin
    python_bin=$(installer_python)

    sudo -u altserver env \
        PYTHONPATH="${ALT_ROOT}/control" \
        ALT_DEPLOY_REGISTRATION_ROOT="$(install_destination "${root_prefix}" /srv/alt-deploy/registration)" \
        ALT_DEPLOY_STATE_ROOT="$(install_destination "${root_prefix}" /var/lib/alt-deploy)" \
        ALT_DEPLOY_ANSIBLE_PROJECT="$(install_destination "${root_prefix}" /home/altserver/ansible)" \
        ALT_DEPLOY_KNOWN_HOSTS="$(install_destination "${root_prefix}" /home/altserver/.ssh/known_hosts_autoinstall)" \
        ALT_DEPLOY_PRIVATE_KEY="$(install_destination "${root_prefix}" /home/altserver/.ssh/id_ed25519)" \
        "${python_bin}" -m alt_deploy.cli --json "$@"
}

validate_active_jobs() {
    local root_prefix=$1
    local jobs_json
    local active_count

    if ! jobs_json=$(run_source_cli "${root_prefix}" jobs active); then
        echo "Unable to validate active provision jobs" >&2
        return 1
    fi

    if ! active_count=$(
        printf '%s' "${jobs_json}" | python3 -c '
import json
import sys
payload = json.load(sys.stdin)
count = payload.get("count")
jobs = payload.get("active_jobs")
if type(count) is not int or count < 0 or not isinstance(jobs, list):
    raise SystemExit(1)
if len(jobs) != count:
    raise SystemExit(1)
print(count)
'
    ); then
        echo "Active provision job response is invalid" >&2
        return 1
    fi

    if (( active_count != 0 )); then
        echo "Active provision jobs block controller installation" >&2
        return 1
    fi
}

validate_vault_and_permissions() {
    local root_prefix=$1

    if ! run_source_cli "${root_prefix}" vault check >/dev/null; then
        echo "Vault health check blocks controller installation" >&2
        return 1
    fi

    if ! run_source_cli "${root_prefix}" controller permissions >/dev/null; then
        echo "Controller permission check blocks installation" >&2
        return 1
    fi
}

validate_external_prerequisites() {
    local root_prefix=$1
    local private_key
    private_key=$(install_destination \
        "${root_prefix}" \
        /home/altserver/.ssh/id_ed25519)

    local required_files=(
        "${private_key}"
        "$(install_destination "${root_prefix}" /etc/systemd/system/alt-deploy-guard.service)"
        "$(install_destination "${root_prefix}" /srv/alt-deploy/bootstrap/ansible_authorized_keys)"
        "$(install_destination "${root_prefix}" /srv/alt-deploy/metadata/autoinstall.scm)"
        "$(install_destination "${root_prefix}" /srv/alt-deploy/metadata/vm-profile.scm)"
        "$(install_destination "${root_prefix}" /srv/alt-deploy/metadata/pkg-groups.tar)"
        "$(install_destination "${root_prefix}" /srv/alt-deploy/metadata/install-scripts.tar)"
    )

    local required_file
    for required_file in "${required_files[@]}"; do
        require_regular_nonempty "${required_file}"
    done

    local key_metadata
    key_metadata=$(stat -c '%a %U %G' "${private_key}") || {
        echo "Unable to inspect SSH private key" >&2
        return 1
    }
    if [[ "${key_metadata}" != "600 altserver altserver" ]]; then
        echo "SSH private key ownership or mode is unsafe" >&2
        return 1
    fi
}

require_pending_empty() {
    local root_prefix=$1
    local pending_dir
    pending_dir=$(install_destination \
        "${root_prefix}" \
        /srv/alt-deploy/registration/pending)

    if [[ ! -d "${pending_dir}" ]]; then
        return 0
    fi

    local pending_records
    shopt -s nullglob
    pending_records=("${pending_dir}"/*.json)
    shopt -u nullglob

    if (( ${#pending_records[@]} != 0 )); then
        echo "Pending workstation registrations block controller installation" >&2
        return 1
    fi
}

run_repository_verification() {
    local python_bin
    python_bin=$(installer_python)

    python3 -m py_compile \
        "${ALT_ROOT}/control/alt_deploy"/*.py \
        "${ALT_ROOT}/api/static_server.py" \
        "${ALT_ROOT}/api/register_api.py" \
        "${ALT_ROOT}/api/process_pending.py" \
        "${ALT_ROOT}/control/alt-job-stage"

    bash -n "${ALT_ROOT}/install-control-plane.sh"
    bash -n "${ALT_ROOT}/install-control-plane-args.sh"
    bash -n "${ALT_ROOT}/install-control-plane-lib.sh"
    bash -n "${ALT_ROOT}/bootstrap/bootstrap.sh"
    bash -n "${ALT_ROOT}/bootstrap/alt-bootstrap-register"

    (
        cd "${REPO_ROOT}"
        "${python_bin}" -m pytest -q tests/alt_linux
    )
}

install_control_plane_prechecks() {
    local root_prefix=$1
    local rollback_backup_id=${2:-}
    local required_commands=(
        python3
        ansible-playbook
        ansible-vault
        systemd-run
        systemctl
        sudo
        install
        cp
        ssh
        ssh-keyscan
        mkpasswd
        stat
        id
        bash
    )

    local command_name
    for command_name in "${required_commands[@]}"; do
        require_command "${command_name}"
    done

    if ! id altserver >/dev/null 2>&1; then
        echo "User altserver does not exist" >&2
        return 1
    fi

    validate_rollback_backup "${root_prefix}" "${rollback_backup_id}"
    validate_source_layout
    run_repository_verification
    validate_active_jobs "${root_prefix}"
    validate_vault_and_permissions "${root_prefix}"
    validate_external_prerequisites "${root_prefix}"
    require_pending_empty "${root_prefix}"

    if systemctl is-active --quiet alt-deploy-process.service; then
        echo "Pending-registration processor is active" >&2
        return 1
    fi
}

stop_if_loaded() {
    local unit=$1
    local load_state

    if ! load_state=$(systemctl show \
        "${unit}" \
        --property=LoadState \
        --value); then
        echo "Unable to inspect systemd unit: ${unit}" >&2
        return 1
    fi

    if [[ "${load_state}" != "not-found" ]]; then
        systemctl stop "${unit}"
    fi
}

enter_control_plane_maintenance() {
    stop_if_loaded alt-deploy-process.path
    stop_if_loaded alt-deploy-register.service
    stop_if_loaded alt-deploy-http.service

    if systemctl is-active --quiet alt-deploy-process.service; then
        echo "Pending-registration processor became active during maintenance" >&2
        return 1
    fi
}

install_controller_package() {
    local root_prefix=$1
    local control_root
    control_root=$(install_destination \
        "${root_prefix}" \
        /opt/alt-deploy-control)

    install -d -o root -g root -m 0755 "${control_root}"
    rm -rf "${control_root}/alt_deploy"
    cp -a "${ALT_ROOT}/control/alt_deploy" "${control_root}/alt_deploy"
    chown -R root:root "${control_root}"
    find "${control_root}" -type d -exec chmod 0755 {} +
    find "${control_root}" -type f -exec chmod 0644 {} +

    install -d -o root -g root -m 0755 \
        "$(install_destination "${root_prefix}" /usr/local/sbin)" \
        "$(install_destination "${root_prefix}" /usr/local/libexec)"

    install -o root -g root -m 0755 \
        "${ALT_ROOT}/control/workstationctl" \
        "$(install_destination "${root_prefix}" /usr/local/sbin/workstationctl)"
    install -o root -g root -m 0755 \
        "${ALT_ROOT}/control/alt-provision-worker" \
        "$(install_destination "${root_prefix}" /usr/local/libexec/alt-provision-worker)"
    install -o root -g root -m 0755 \
        "${ALT_ROOT}/control/alt-job-stage" \
        "$(install_destination "${root_prefix}" /usr/local/libexec/alt-job-stage)"
}

ensure_private_state_directories() {
    local root_prefix=$1
    local state_root
    local lock_file
    state_root=$(install_destination \
        "${root_prefix}" \
        /var/lib/alt-deploy)
    lock_file="${state_root}/workstationctl.lock"

    install -d -o altserver -g altserver -m 0700 \
        "${state_root}" \
        "${state_root}/jobs" \
        "${state_root}/assignments" \
        "${state_root}/machine-archives" \
        "${state_root}/machine-archives/.transactions" \
        "$(install_destination "${root_prefix}" /srv/alt-deploy/registration)" \
        "$(install_destination "${root_prefix}" /srv/alt-deploy/registration/pending)" \
        "$(install_destination "${root_prefix}" /srv/alt-deploy/registration/ready)" \
        "$(install_destination "${root_prefix}" /srv/alt-deploy/registration/failed)" \
        "$(install_destination "${root_prefix}" /home/altserver/.ssh)"

    if [[ -L "${lock_file}" ]] \
        || [[ -e "${lock_file}" && ! -f "${lock_file}" ]]; then
        echo "Unsafe controller lifecycle lock: ${lock_file}" >&2
        return 1
    fi

    if [[ ! -e "${lock_file}" ]]; then
        install -o altserver -g altserver -m 0600 \
            /dev/null \
            "${lock_file}"
    else
        chown altserver:altserver "${lock_file}"
        chmod 0600 "${lock_file}"
    fi
}

install_ansible_project() {
    local root_prefix=$1
    local ansible_root
    ansible_root=$(install_destination \
        "${root_prefix}" \
        /home/altserver/ansible)

    install -d -o altserver -g altserver -m 0750 \
        "${ansible_root}" \
        "${ansible_root}/playbooks" \
        "${ansible_root}/roles" \
        "${ansible_root}/group_vars"

    install -o altserver -g altserver -m 0644 \
        "${ALT_ROOT}/ansible/ansible.cfg" \
        "${ansible_root}/ansible.cfg"
    install -o altserver -g altserver -m 0644 \
        "${ALT_ROOT}/ansible/group_vars/all.yml" \
        "${ansible_root}/group_vars/all.yml"

    cp -a "${ALT_ROOT}/ansible/playbooks/." "${ansible_root}/playbooks/"
    cp -a "${ALT_ROOT}/ansible/roles/." "${ansible_root}/roles/"
    chown -R altserver:altserver \
        "${ansible_root}/playbooks" \
        "${ansible_root}/roles"
    find \
        "${ansible_root}/playbooks" \
        "${ansible_root}/roles" \
        -type d -exec chmod 0750 {} +
    find \
        "${ansible_root}/playbooks" \
        "${ansible_root}/roles" \
        -type f -exec chmod 0640 {} +
}

install_registration_runtime() {
    local root_prefix=$1
    local api_root
    local bootstrap_root
    api_root=$(install_destination "${root_prefix}" /opt/alt-deploy-api)
    bootstrap_root=$(install_destination "${root_prefix}" /srv/alt-deploy/bootstrap)

    install -d -o root -g root -m 0755 \
        "${api_root}" \
        "$(install_destination "${root_prefix}" /srv/alt-deploy)" \
        "$(install_destination "${root_prefix}" /srv/alt-deploy/metadata)" \
        "${bootstrap_root}"

    install -o root -g root -m 0755 \
        "${ALT_ROOT}/api/static_server.py" \
        "${api_root}/static_server.py"
    install -o root -g root -m 0755 \
        "${ALT_ROOT}/api/register_api.py" \
        "${api_root}/register_api.py"
    install -o root -g root -m 0755 \
        "${ALT_ROOT}/api/process_pending.py" \
        "${api_root}/process_pending.py"
    install -o root -g root -m 0644 \
        "${ALT_ROOT}/bootstrap/bootstrap.sh" \
        "${bootstrap_root}/bootstrap.sh"
    install -o root -g root -m 0644 \
        "${ALT_ROOT}/bootstrap/alt-bootstrap-register" \
        "${bootstrap_root}/alt-bootstrap-register"
}

install_systemd_units() {
    local root_prefix=$1
    local systemd_root
    systemd_root=$(install_destination \
        "${root_prefix}" \
        /etc/systemd/system)

    install -d -o root -g root -m 0755 "${systemd_root}"

    local unit
    for unit in \
        alt-deploy-http.service \
        alt-deploy-register.service \
        alt-deploy-process.path \
        alt-deploy-process.service; do
        install -o root -g root -m 0644 \
            "${ALT_ROOT}/systemd/${unit}" \
            "${systemd_root}/${unit}"
    done
}

activate_control_plane() {
    systemctl daemon-reload
    systemctl enable --now alt-deploy-http.service
    systemctl enable --now alt-deploy-register.service
    systemctl enable --now alt-deploy-process.path
}

run_installed_readiness() {
    local root_prefix=$1
    local workstationctl
    local attempt
    workstationctl=$(install_destination \
        "${root_prefix}" \
        /usr/local/sbin/workstationctl)

    for (( attempt = 1; attempt <= 15; attempt++ )); do
        if sudo -u altserver \
            "${workstationctl}" \
            --json \
            controller readiness >/dev/null; then
            return 0
        fi
        if (( attempt < 15 )); then
            sleep 1
        fi
    done

    echo "Controller readiness failed; restore the OR-3P3 backup before retrying" >&2
    return 1
}

run_post_maintenance_step() {
    local phase=$1
    shift

    if (
        set -Eeuo pipefail
        "$@"
    ); then
        return 0
    fi

    echo "ALT control-plane installation failed during ${phase}; restore the OR-3P3 backup before retrying" >&2
    return 1
}

install_control_plane_main() {
    local root_prefix=$1
    local rollback_backup_id=${2:-}

    install_control_plane_prechecks "${root_prefix}" "${rollback_backup_id}"
    if ! run_installed_backup_tool \
        "${root_prefix}" \
        rollout-begin \
        "${rollback_backup_id}" >/dev/null; then
        echo "Unable to start the guarded OR-3P4 rollout" >&2
        return 1
    fi

    if ! run_post_maintenance_step \
        maintenance \
        enter_control_plane_maintenance \
        || ! run_post_maintenance_step \
            controller_package \
            install_controller_package \
            "${root_prefix}" \
        || ! run_post_maintenance_step \
            private_state \
            ensure_private_state_directories \
            "${root_prefix}" \
        || ! run_post_maintenance_step \
            ansible_project \
            install_ansible_project \
            "${root_prefix}" \
        || ! run_post_maintenance_step \
            registration_runtime \
            install_registration_runtime \
            "${root_prefix}" \
        || ! run_post_maintenance_step \
            systemd_units \
            install_systemd_units \
            "${root_prefix}"; then
        revoke_failed_rollout "${root_prefix}" "${rollback_backup_id}"
        return 1
    fi

    if ! run_installed_backup_tool \
        "${root_prefix}" \
        rollout-authorize \
        "${rollback_backup_id}" >/dev/null; then
        echo "Unable to authorize the guarded OR-3P4 activation" >&2
        revoke_failed_rollout "${root_prefix}" "${rollback_backup_id}"
        return 1
    fi
    if ! run_post_maintenance_step activation activate_control_plane \
        || ! run_post_maintenance_step \
            readiness \
            run_installed_readiness \
            "${root_prefix}"; then
        revoke_failed_rollout "${root_prefix}" "${rollback_backup_id}"
        return 1
    fi
    if ! run_installed_backup_tool \
        "${root_prefix}" \
        rollout-complete \
        "${rollback_backup_id}" >/dev/null; then
        echo "Unable to complete guarded OR-3P4 rollout state" >&2
        revoke_failed_rollout "${root_prefix}" "${rollback_backup_id}"
        return 1
    fi

    echo "ALT deployment control plane installed successfully"
}
