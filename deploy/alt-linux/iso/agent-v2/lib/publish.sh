#!/bin/bash

publish_managed_iso() {
    local staged_iso="$1"
    local staged_sidecar="$2"
    local output_iso="$3"
    local output_sidecar="$4"

    [[ -f "$staged_iso" && ! -L "$staged_iso" &&
        -f "$staged_sidecar" && ! -L "$staged_sidecar" ]] || return 1
    [[ ! -e "$output_iso" && ! -L "$output_iso" &&
        ! -e "$output_sidecar" && ! -L "$output_sidecar" ]] || return 1

    # Publish the sidecar first. An interrupted promotion may leave a harmless
    # orphan sidecar, but it must never expose an ISO without its manifest.
    mv -n -- "$staged_sidecar" "$output_sidecar" || return 1
    if [[ -e "$staged_sidecar" || ! -f "$output_sidecar" ]]; then
        return 1
    fi
    if ! mv -n -- "$staged_iso" "$output_iso" ||
        [[ -e "$staged_iso" || ! -f "$output_iso" ]]; then
        rm -f -- "$output_sidecar"
        return 1
    fi
}
