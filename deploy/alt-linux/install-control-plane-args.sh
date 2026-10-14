#!/bin/bash

parse_control_plane_args() {
    if (( $# != 2 && $# != 4 )) || [[ ${1:-} != "--rollback-backup-id" ]]; then
        echo "Usage: install-control-plane.sh --rollback-backup-id <backup-id> [--maintenance-review SHA256]" >&2
        return 2
    fi
    if (( $# == 4 )) && { [[ ${3:-} != "--maintenance-review" ]] || [[ ! ${4:-} =~ ^[0-9a-f]{64}$ ]]; }; then
        echo "Invalid maintenance review SHA" >&2
        return 2
    fi

    local backup_id=$2
    if [[ ! ${backup_id} =~ ^backup-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$ ]]; then
        echo "Invalid rollback backup ID" >&2
        return 2
    fi

    printf '%s\n' "${backup_id}"
}
