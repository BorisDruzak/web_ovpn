#!/bin/bash

create_spike_session() {
    local inventory="$1"
    local response
    response=$(printf '%s' "$inventory" | curl --fail --silent --show-error --connect-timeout 3 --max-time 10 \
        --request POST --header 'Content-Type: application/json' --data-binary @- \
        "$SPIKE_CONTROLLER/spike/v1/sessions") || return 1
    [[ "$response" =~ ^spike-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$ ]] || return 1
    printf '%s\n' "$response"
}

get_spike_decision() {
    local session="$1"
    local response
    response=$(curl --fail --silent --show-error --connect-timeout 3 --max-time 10 \
        "$SPIKE_CONTROLLER/spike/v1/sessions/$session/decision") || return 1
    case "$response" in
        waiting|approved|cancelled) printf '%s\n' "$response" ;;
        *) return 1 ;;
    esac
}

report_spike_state() {
    local session="$1" state="$2"
    printf '{"state":"%s"}\n' "$state" | curl --fail --silent --show-error --connect-timeout 3 --max-time 10 \
        --request POST --header 'Content-Type: application/json' --data-binary @- \
        "$SPIKE_CONTROLLER/spike/v1/sessions/$session/state" >/dev/null
}
