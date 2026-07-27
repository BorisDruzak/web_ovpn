#!/bin/bash

readonly SPIKE_CONTROLLER_URL="http://192.168.100.17:18089"
readonly SPIKE_CMDLINE_FILE="${SOSNADMIN_PROC_ROOT:-/proc}/cmdline"

cmdline_value() {
    local name="$1"
    local item
    for item in $(cat "$SPIKE_CMDLINE_FILE"); do
        case "$item" in
            "$name"=*) printf '%s\n' "${item#*=}"; return 0 ;;
        esac
    done
    return 1
}

load_spike_cmdline() {
    SPIKE_MODE=$(cmdline_value sosnadmin.mode) || return 1
    SPIKE_CONTROLLER=$(cmdline_value sosnadmin.controller) || return 1
    SPIKE_BUILD=$(cmdline_value sosnadmin.build) || return 1

    [[ "$SPIKE_MODE" == spike ]] || return 1
    [[ "$SPIKE_CONTROLLER" == "$SPIKE_CONTROLLER_URL" ]] || return 1
    [[ ${#SPIKE_BUILD} -le 64 && "$SPIKE_BUILD" =~ ^[A-Za-z0-9._-]+$ ]] || return 1
    export SPIKE_MODE SPIKE_CONTROLLER SPIKE_BUILD
}
