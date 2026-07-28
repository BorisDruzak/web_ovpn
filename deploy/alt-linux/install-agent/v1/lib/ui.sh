#!/bin/bash

ALT_INSTALL_SLEEP=${ALT_INSTALL_SLEEP:-sleep}

ui_status() {
    printf 'ALT install agent: %s\n' "$1"
}

terminal_hold() {
    local state="$1"
    if [[ "$state" == preflight_ready ]]; then
        printf '%s\n' 'READY FOR INSTALLATION — DRY RUN'
        printf '%s\n' \
            'PASS: signed plan verified; disk preflight passed; no target writes'
    else
        printf 'ALT install agent terminal state: %s\n' "$state" >&2
    fi
    while :; do
        "$ALT_INSTALL_SLEEP" 60
    done
}
