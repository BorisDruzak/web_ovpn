#!/bin/bash

set -Eeuo pipefail

OUTPUT=${1:-/srv/alt-deploy/metadata/install-scripts.tar}
TMPDIR_PATH=$(mktemp -d)

cleanup() {
    rm -rf "$TMPDIR_PATH"
}
trap cleanup EXIT

mkdir -p \
    "$TMPDIR_PATH/preinstall.d" \
    "$TMPDIR_PATH/postinstall.d"

install -d -m 0755 "$(dirname "$OUTPUT")"
tar -C "$TMPDIR_PATH" \
    -cf "$OUTPUT" \
    preinstall.d \
    postinstall.d

chmod 0644 "$OUTPUT"

echo "Created $OUTPUT"
