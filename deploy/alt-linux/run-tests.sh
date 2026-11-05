#!/bin/bash
set -Eeuo pipefail
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
python_bin=python3
if [[ -x "${REPO_ROOT}/.venv/bin/python" ]]; then
    python_bin="${REPO_ROOT}/.venv/bin/python"
fi
umask 022
if (( EUID == 0 )); then
    exec sudo -n -H -u altserver -- "${python_bin}" "${REPO_ROOT}/deploy/alt-linux/verify_repository.py" "$@"
fi
exec "${python_bin}" "${REPO_ROOT}/deploy/alt-linux/verify_repository.py" "$@"
