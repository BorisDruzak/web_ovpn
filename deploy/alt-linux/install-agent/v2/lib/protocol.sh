#!/bin/bash

ALT_INSTALL_CURL=${ALT_INSTALL_CURL:-curl}
readonly ALT_INSTALL_EXECUTION_RESPONSE_LIMIT=4096

execution_protocol_error() {
    printf 'ALT_INSTALL_ERROR %s\n' "$1" >&2
    return 1
}

execution_json_string() {
    local path="$1" field="$2" content expression
    [[ -f "$path" && ! -L "$path" ]] || return 1
    content=$(<"$path")
    expression="\"${field}\"[[:space:]]*:[[:space:]]*\"([^\"]*)\""
    [[ "$content" =~ $expression ]] || return 1
    printf '%s\n' "${BASH_REMATCH[1]}"
}

execution_session_id() {
    local session
    session=$(state_read session-id) || return 1
    [[ "$session" =~ ^install-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$ ]] ||
        return 1
    printf '%s\n' "$session"
}

protocol_download_execution_bundle() {
    local session credential auth manifest destination
    session=$(execution_session_id) || return 1
    credential=$(state_read credential) || return 1
    [[ "$credential" =~ ^[A-Za-z0-9_-]{43}$ ]] || return 1
    auth=$(state_path curl-auth.conf) || return 1
    [[ -f "$auth" && ! -L "$auth" ]] || return 1
    destination="$ALT_INSTALL_STATE_ROOT/execution-bundle"
    [[ ! -e "$destination" && ! -L "$destination" ]] || return 1
    manifest="${ALT_INSTALL_EXECUTION_CONTROLLER}/v2/install-sessions/${session}/execution/manifest"

    "$ALT_INSTALL_HELPER" download-execution-bundle \
        --manifest "$manifest" \
        --destination "$destination" \
        --ca-certificate "$ALT_INSTALL_EXECUTION_CA" \
        --credential-file "$(state_path credential)" >/dev/null
}

execution_protocol_post() {
    local action="$1" expected_state="$2"
    local session auth destination temporary status size observed
    local -a arguments

    case "$action:$expected_state" in
        claim:claimed|handoff-started:handoff_started) ;;
        *) return 1 ;;
    esac
    session=$(execution_session_id) || return 1
    auth=$(state_path curl-auth.conf) || return 1
    [[ -f "$auth" && ! -L "$auth" ]] || return 1
    destination=$(state_path "execution-${action}-response.json") ||
        return 1
    temporary="${destination}.tmp.$$"
    rm -f -- "$temporary"
    (
        umask 077
        : > "$temporary"
        chmod 0600 -- "$temporary"
    ) || return 1
    arguments=(
        --silent
        --show-error
        --proto '=https'
        --proto-redir '=https'
        --tlsv1.3
        --max-redirs 0
        --noproxy '*'
        --proxy ''
        --connect-timeout 3
        --max-time 10
        --max-filesize "$ALT_INSTALL_EXECUTION_RESPONSE_LIMIT"
        --cacert "$ALT_INSTALL_EXECUTION_CA"
        --request POST
        --config "$auth"
        --output "$temporary"
        --write-out '%{http_code}'
        "${ALT_INSTALL_EXECUTION_CONTROLLER}/v2/install-sessions/${session}/execution/${action}"
    )
    if ! status=$("$ALT_INSTALL_CURL" "${arguments[@]}"); then
        rm -f -- "$temporary"
        execution_protocol_error execution_transport_failed
        return 1
    fi
    [[ "$status" =~ ^[0-9]{3}$ ]] || {
        rm -f -- "$temporary"
        execution_protocol_error execution_status_invalid
        return 1
    }
    size=$(wc -c < "$temporary")
    if [[ "$status" == 3* ]]; then
        rm -f -- "$temporary"
        execution_protocol_error execution_redirect_rejected
        return 1
    fi
    if [[ "$status" != 200 ||
        "$size" -lt 1 ||
        "$size" -gt "$ALT_INSTALL_EXECUTION_RESPONSE_LIMIT" ]]; then
        rm -f -- "$temporary"
        execution_protocol_error execution_transition_rejected
        return 1
    fi
    mv -f -- "$temporary" "$destination"
    chmod 0600 -- "$destination"
    observed=$(execution_json_string "$destination" state) || {
        state_remove "execution-${action}-response.json"
        return 1
    }
    state_remove "execution-${action}-response.json"
    [[ "$observed" == "$expected_state" ]]
}

protocol_claim_execution() {
    execution_protocol_post claim claimed
}

protocol_handoff_started() {
    execution_protocol_post handoff-started handoff_started
}
