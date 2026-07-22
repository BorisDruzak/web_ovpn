#!/bin/bash

backup_install_destination() {
    local root_prefix=$1
    local absolute_path=$2
    printf '%s%s' "${root_prefix}" "${absolute_path}"
}

backup_require_command() {
    local name=$1
    command -v "${name}" >/dev/null 2>&1 || {
        echo "Missing required backup command: ${name}" >&2
        return 1
    }
}

backup_require_regular_nonempty() {
    local path=$1
    if [[ ! -f "${path}" || -L "${path}" || ! -s "${path}" ]]; then
        echo "Unsafe or missing backup source: ${path}" >&2
        return 1
    fi
}

backup_require_directory() {
    local path=$1
    if [[ ! -d "${path}" || -L "${path}" ]]; then
        echo "Unsafe or missing backup directory: ${path}" >&2
        return 1
    fi
}

backup_validate_sources() {
    backup_require_directory "${ALT_ROOT}/backup/alt_deploy_backup"
    backup_require_regular_nonempty "${ALT_ROOT}/backup/alt-deploy-backup"
    backup_require_regular_nonempty "${ALT_ROOT}/backup/alt-deploy-guard.service"
    backup_require_regular_nonempty "${ALT_ROOT}/install-backup-tool.sh"
    backup_require_regular_nonempty "${ALT_ROOT}/install-backup-tool-lib.sh"
}

backup_expected_root_identity() {
    local root_prefix=$1
    if [[ -n "${root_prefix}" ]]; then
        printf '%s %s\n' \
            "${ALT_DEPLOY_BACKUP_EXPECTED_ROOT_UID:?}" \
            "${ALT_DEPLOY_BACKUP_EXPECTED_ROOT_GID:?}"
    else
        printf '0 0\n'
    fi
}

backup_validate_existing_directory() {
    local root_prefix=$1
    local absolute_path=$2
    local policy=${3:-repairable}
    local expected_mode=${4:-}
    local directory
    directory=$(backup_install_destination "${root_prefix}" "${absolute_path}")

    if [[ ! -e "${directory}" && ! -L "${directory}" ]]; then
        return 0
    fi
    if [[ -L "${directory}" || ! -d "${directory}" ]]; then
        echo "Backup installer directory is unsafe: ${absolute_path}" >&2
        return 1
    fi

    local expected_uid expected_gid
    read -r expected_uid expected_gid < <(
        backup_expected_root_identity "${root_prefix}"
    )
    local metadata uid gid mode
    metadata=$(stat -c '%u %g %a' "${directory}") || return 1
    read -r uid gid mode <<<"${metadata}"
    if [[ "${uid}" != "${expected_uid}" || "${gid}" != "${expected_gid}" ]]; then
        echo "Backup installer directory ownership is unsafe: ${absolute_path}" >&2
        return 1
    fi
    if [[ "${policy}" == public ]]; then
        if (( 8#${mode} & 8#022 )); then
            echo "Backup installer directory is writable by group or others: ${absolute_path}" >&2
            return 1
        fi
    elif [[ "${policy}" == exact && "${mode}" != "${expected_mode}" ]]; then
        echo "Backup installer directory mode is unsafe: ${absolute_path}" >&2
        return 1
    fi
}

backup_validate_existing_regular() {
    local root_prefix=$1
    local absolute_path=$2
    local expected_mode=${3:-}
    local expected_size=${4:-}
    local path
    path=$(backup_install_destination "${root_prefix}" "${absolute_path}")

    if [[ ! -e "${path}" && ! -L "${path}" ]]; then
        return 0
    fi
    if [[ -L "${path}" || ! -f "${path}" ]]; then
        echo "Backup installer file is unsafe: ${absolute_path}" >&2
        return 1
    fi

    local expected_uid expected_gid
    read -r expected_uid expected_gid < <(
        backup_expected_root_identity "${root_prefix}"
    )
    local metadata uid gid mode size
    metadata=$(stat -c '%u %g %a %s' "${path}") || return 1
    read -r uid gid mode size <<<"${metadata}"
    if [[ "${uid}" != "${expected_uid}" || "${gid}" != "${expected_gid}" ]]; then
        echo "Backup installer file ownership is unsafe: ${absolute_path}" >&2
        return 1
    fi
    if [[ -n "${expected_mode}" && "${mode}" != "${expected_mode}" ]]; then
        echo "Backup installer file mode is unsafe: ${absolute_path}" >&2
        return 1
    fi
    if [[ -n "${expected_size}" && "${size}" != "${expected_size}" ]]; then
        echo "Backup installer file size is unsafe: ${absolute_path}" >&2
        return 1
    fi
}

backup_validate_destination_layout() {
    local root_prefix=$1

    local public_directory
    for public_directory in \
        /opt \
        /usr/local \
        /usr/local/sbin \
        /etc/systemd \
        /etc/systemd/system \
        /var \
        /var/lib \
        /var/backups \
        /var/log; do
        backup_validate_existing_directory \
            "${root_prefix}" \
            "${public_directory}" \
            public
    done

    backup_validate_existing_directory \
        "${root_prefix}" \
        /opt/alt-deploy-backup
    backup_validate_existing_directory \
        "${root_prefix}" \
        /var/lib/alt-deploy-backup \
        exact \
        700
    backup_validate_existing_directory \
        "${root_prefix}" \
        /var/backups/alt-deploy \
        exact \
        700

    backup_validate_existing_regular \
        "${root_prefix}" \
        /usr/local/sbin/alt-deploy-backup
    backup_validate_existing_regular \
        "${root_prefix}" \
        /etc/systemd/system/alt-deploy-guard.service
    backup_validate_existing_regular \
        "${root_prefix}" \
        /var/log/alt-deploy-backup.log \
        600
    backup_validate_existing_regular \
        "${root_prefix}" \
        /var/lib/alt-deploy-backup/fingerprint.key \
        600 \
        32
}

backup_ensure_public_directory() {
    local root_prefix=$1
    local absolute_path=$2
    local directory
    directory=$(backup_install_destination "${root_prefix}" "${absolute_path}")

    backup_validate_existing_directory \
        "${root_prefix}" \
        "${absolute_path}" \
        public
    if [[ ! -e "${directory}" ]]; then
        install -d -o root -g root -m 0755 "${directory}"
    fi
}

backup_validate_log_parent() {
    backup_ensure_public_directory "$1" /var/log
}

backup_run_source_checks() {
    python3 -m py_compile \
        "${ALT_ROOT}/backup/alt_deploy_backup"/*.py \
        "${ALT_ROOT}/backup/alt-deploy-backup"
    bash -n "${ALT_ROOT}/install-backup-tool.sh"
    bash -n "${ALT_ROOT}/install-backup-tool-lib.sh"
}

backup_install_package() {
    local root_prefix=$1
    local package_root wrapper systemd_root
    package_root=$(backup_install_destination "${root_prefix}" /opt/alt-deploy-backup)
    wrapper=$(backup_install_destination "${root_prefix}" /usr/local/sbin/alt-deploy-backup)
    systemd_root=$(backup_install_destination "${root_prefix}" /etc/systemd/system)

    backup_ensure_public_directory "${root_prefix}" /usr/local/sbin
    backup_ensure_public_directory "${root_prefix}" /etc/systemd/system
    install -d -o root -g root -m 0750 "${package_root}"
    rm -rf "${package_root}/alt_deploy_backup"
    install -d -o root -g root -m 0750 \
        "${package_root}/alt_deploy_backup"
    local source_file
    for source_file in "${ALT_ROOT}/backup/alt_deploy_backup/"*.py; do
        backup_require_regular_nonempty "${source_file}"
        install -o root -g root -m 0640 \
            "${source_file}" \
            "${package_root}/alt_deploy_backup/${source_file##*/}"
    done

    install -o root -g root -m 0750 \
        "${ALT_ROOT}/backup/alt-deploy-backup" \
        "${wrapper}"
    install -o root -g root -m 0644 \
        "${ALT_ROOT}/backup/alt-deploy-guard.service" \
        "${systemd_root}/alt-deploy-guard.service"
}

backup_prepare_private_state() {
    local root_prefix=$1
    local state_root backup_root log_file
    state_root=$(backup_install_destination "${root_prefix}" /var/lib/alt-deploy-backup)
    backup_root=$(backup_install_destination "${root_prefix}" /var/backups/alt-deploy)
    log_file=$(backup_install_destination "${root_prefix}" /var/log/alt-deploy-backup.log)

    install -d -o root -g root -m 0700 "${state_root}" "${backup_root}"
    backup_validate_log_parent "${root_prefix}"
    if [[ -L "${log_file}" || ( -e "${log_file}" && ! -f "${log_file}" ) ]]; then
        echo "Backup operation log is unsafe" >&2
        return 1
    fi
    if [[ ! -e "${log_file}" ]]; then
        install -o root -g root -m 0600 /dev/null "${log_file}"
    else
        chown root:root "${log_file}"
        chmod 0600 "${log_file}"
    fi
}

backup_initialize_fingerprint_key() {
    local root_prefix=$1
    local package_root
    package_root=$(backup_install_destination "${root_prefix}" /opt/alt-deploy-backup)
    local environment=(
        PYTHONPATH="${package_root}"
        PYTHONDONTWRITEBYTECODE=1
    )
    if [[ -n "${root_prefix}" ]]; then
        local expected_root_uid=${ALT_DEPLOY_BACKUP_EXPECTED_ROOT_UID:-0}
        local expected_root_gid=${ALT_DEPLOY_BACKUP_EXPECTED_ROOT_GID:-0}
        local expected_service_uid=${ALT_DEPLOY_BACKUP_EXPECTED_SERVICE_UID:-${expected_root_uid}}
        local expected_service_gid=${ALT_DEPLOY_BACKUP_EXPECTED_SERVICE_GID:-${expected_root_gid}}
        environment+=(
            ALT_DEPLOY_BACKUP_TEST_MODE=1
            ALT_DEPLOY_BACKUP_TEST_ROOT="${root_prefix}"
            ALT_DEPLOY_BACKUP_EXPECTED_ROOT_UID="${expected_root_uid}"
            ALT_DEPLOY_BACKUP_EXPECTED_ROOT_GID="${expected_root_gid}"
            ALT_DEPLOY_BACKUP_EXPECTED_SERVICE_UID="${expected_service_uid}"
            ALT_DEPLOY_BACKUP_EXPECTED_SERVICE_GID="${expected_service_gid}"
            ALT_DEPLOY_BACKUP_EFFECTIVE_UID=0
        )
    fi
    env "${environment[@]}" \
        python3 -m alt_deploy_backup.cli install-check >/dev/null
}

install_backup_tool_main() {
    local root_prefix=$1
    local required=(
        python3
        install
        cp
        rm
        chmod
        chown
        stat
        bash
        env
        id
        sha256sum
        tar
        zstd
        systemctl
        systemd-analyze
        ansible-playbook
        ssh-keygen
    )
    local command_name
    for command_name in "${required[@]}"; do
        backup_require_command "${command_name}"
    done
    if ! id altserver >/dev/null 2>&1; then
        echo "User altserver does not exist" >&2
        return 1
    fi
    backup_validate_sources
    backup_run_source_checks
    backup_validate_destination_layout "${root_prefix}"
    backup_prepare_private_state "${root_prefix}"
    backup_install_package "${root_prefix}"
    backup_initialize_fingerprint_key "${root_prefix}"
    echo "ALT OR-3P3 backup tool installed successfully"
}
