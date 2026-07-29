#!/bin/bash

ALT_INSTALL_SLEEP=${ALT_INSTALL_SLEEP:-sleep}

terminal_hold() {
    local state="$1"
    printf 'terminal=%s\n' "$state"
    while :; do
        "$ALT_INSTALL_SLEEP" 60
    done
}
