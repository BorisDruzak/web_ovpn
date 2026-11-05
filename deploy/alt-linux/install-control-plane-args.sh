#!/bin/bash

parse_control_plane_args() {
    if (( $# < 2 )) || [[ ${1:-} != "--rollback-backup-id" ]]; then
        echo "Usage: install-control-plane.sh --rollback-backup-id <backup-id> [--maintenance-review SHA256] [--resume-verification]" >&2
        return 2
    fi
    local backup_id=$2
    if [[ ! ${backup_id} =~ ^backup-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$ ]]; then
        echo "Invalid rollback backup ID" >&2
        return 2
    fi
    CONTROL_PLANE_BACKUP_ID=${backup_id}
    CONTROL_PLANE_MAINTENANCE_REVIEW=
    CONTROL_PLANE_RESUME_VERIFICATION=0
    shift 2
    while (( $# )); do
        case "$1" in
            --maintenance-review)
                if (( $# < 2 )) || [[ -n ${CONTROL_PLANE_MAINTENANCE_REVIEW} || ! $2 =~ ^[0-9a-f]{64}$ ]]; then
                    echo "Invalid maintenance review SHA" >&2
                    return 2
                fi
                CONTROL_PLANE_MAINTENANCE_REVIEW=$2
                shift 2 ;;
            --resume-verification)
                if (( CONTROL_PLANE_RESUME_VERIFICATION )); then return 2; fi
                CONTROL_PLANE_RESUME_VERIFICATION=1
                shift ;;
            *) echo "Invalid installer option" >&2; return 2 ;;
        esac
    done
    printf '%s\n' "${backup_id}"
}
