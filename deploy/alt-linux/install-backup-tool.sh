#!/bin/bash
set -Eeuo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "Run as root" >&2
    exit 1
fi
if (( $# != 0 )); then
    echo "install-backup-tool.sh accepts no arguments" >&2
    exit 2
fi

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
ALT_ROOT="${REPO_ROOT}/deploy/alt-linux"
source "${ALT_ROOT}/install-backup-tool-lib.sh"
install_backup_tool_main ""
