#!/bin/bash

set -Eeuo pipefail

OUTPUT=${1:-/srv/alt-deploy/metadata/install-scripts.tar}
TMPDIR_PATH=$(mktemp -d)
SCRIPT_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)

cleanup() {
    rm -rf "$TMPDIR_PATH"
}
trap cleanup EXIT

cp -a -- "$SCRIPT_ROOT/install-scripts/." "$TMPDIR_PATH/"
mkdir -p "$TMPDIR_PATH/preinstall.d"
install -m 0755 \
    "$SCRIPT_ROOT/../install-agent/v2/alt-install-execution-postflight" \
    "$TMPDIR_PATH/payload/alt-install-execution-postflight"

install -d -m 0755 "$(dirname "$OUTPUT")"
tar -C "$TMPDIR_PATH" \
    -cf "$OUTPUT" \
    preinstall.d \
    postinstall.d \
    payload

chmod 0644 "$OUTPUT"

echo "Created $OUTPUT"
