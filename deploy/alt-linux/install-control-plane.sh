#!/bin/bash
set -Eeuo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "Run as root" >&2
    exit 1
fi

REPO_ROOT=$(
    cd "$(dirname "${BASH_SOURCE[0]}")/../.."
    pwd
)
ALT_ROOT="${REPO_ROOT}/deploy/alt-linux"

source "${ALT_ROOT}/install-control-plane-args.sh"
ROLLBACK_BACKUP_ID=$(parse_control_plane_args "$@")

source "${ALT_ROOT}/install-control-plane-lib.sh"
install_control_plane_main "" "${ROLLBACK_BACKUP_ID}"
