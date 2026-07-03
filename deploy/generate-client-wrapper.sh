#!/usr/bin/env bash
set -euo pipefail
exec /usr/local/sbin/vpnctl generate "$@"
