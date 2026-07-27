#!/bin/bash

ALT_INSTALL_STATE_ROOT=${ALT_INSTALL_STATE_ROOT:-/run/alt-install}

state_path() {
    local name="$1"
    [[ "$name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || return 1
    printf '%s/%s\n' "$ALT_INSTALL_STATE_ROOT" "$name"
}

state_init() {
    [[ ! -L "$ALT_INSTALL_STATE_ROOT" ]] || return 1
    mkdir -p -- "$ALT_INSTALL_STATE_ROOT"
    chmod 0700 -- "$ALT_INSTALL_STATE_ROOT"
    [[ -d "$ALT_INSTALL_STATE_ROOT" ]] || return 1
}

state_write_stream() {
    local name="$1" destination temporary
    destination=$(state_path "$name") || return 1
    [[ ! -L "$destination" ]] || return 1
    temporary="${destination}.tmp.$$"
    rm -f -- "$temporary"
    (
        umask 077
        : > "$temporary"
        chmod 0600 -- "$temporary"
        cat > "$temporary"
    ) || {
        rm -f -- "$temporary"
        return 1
    }
    mv -f -- "$temporary" "$destination"
    chmod 0600 -- "$destination"
}

state_write() {
    local name="$1" value="$2"
    printf '%s' "$value" | state_write_stream "$name"
}

state_read() {
    local path
    path=$(state_path "$1") || return 1
    [[ -f "$path" && ! -L "$path" ]] || return 1
    cat -- "$path"
}

state_remove() {
    local path
    path=$(state_path "$1") || return 1
    rm -f -- "$path"
}
