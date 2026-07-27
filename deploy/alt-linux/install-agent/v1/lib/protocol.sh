#!/bin/bash

protocol_json_string() {
    local path="$1" field="$2" content expression
    [[ -f "$path" && ! -L "$path" ]] || return 1
    content=$(<"$path")
    expression="\"${field}\"[[:space:]]*:[[:space:]]*\"([^\"]*)\""
    [[ "$content" =~ $expression ]] || return 1
    printf '%s\n' "${BASH_REMATCH[1]}"
}

protocol_json_integer() {
    local path="$1" field="$2" content expression
    content=$(<"$path")
    expression="\"${field}\"[[:space:]]*:[[:space:]]*([0-9]+)"
    [[ "$content" =~ $expression ]] || return 1
    printf '%s\n' "${BASH_REMATCH[1]}"
}

protocol_create_session() {
    local inventory="$1" nonce request response session credential poll_after
    [[ -f "$inventory" && ! -L "$inventory" ]] || return 1
    nonce=$(state_read create-nonce) || return 1
    [[ "$nonce" =~ ^[A-Za-z0-9_-]{43}$ ]] || return 1
    request=$(state_path create-request.json) || return 1
    {
        printf '{"create_nonce":"%s","inventory":' "$nonce"
        cat -- "$inventory"
        printf '}'
    } | state_write_stream create-request.json
    http_request POST /v1/install-sessions create-response.json \
        "$request" '' 201 || return 1
    response=$(state_path create-response.json) || return 1
    session=$(protocol_json_string "$response" session_id) || return 1
    credential=$(protocol_json_string "$response" credential) || return 1
    poll_after=$(protocol_json_integer "$response" poll_after_seconds) ||
        return 1
    [[ "$session" =~ ^install-[A-Za-z0-9-]{4,64}$ ]] || return 1
    [[ "$credential" =~ ^[A-Za-z0-9_-]{43}$ ]] || return 1
    [[ "$poll_after" =~ ^[0-9]+$ && "$poll_after" -ge 1 &&
        "$poll_after" -le 30 ]] || return 1
    state_write session-id "$session"
    state_write credential "$credential"
    state_write poll-after "$poll_after"
    state_write curl-auth.conf \
        "header = \"Authorization: Bearer ${credential}\""
    state_remove create-request.json
    state_remove create-response.json
}

protocol_heartbeat() {
    local stage="$1" session auth sequence=0 sent_at request response
    case "$stage" in
        agent_started|inventory_validated|waiting_for_approval|plan_downloaded|preflight_ready) ;;
        *) return 1 ;;
    esac
    session=$(state_read session-id) || return 1
    auth=$(state_path curl-auth.conf) || return 1
    if sequence=$(state_read heartbeat-sequence 2>/dev/null); then
        [[ "$sequence" =~ ^[0-9]+$ ]] || return 1
    else
        sequence=0
    fi
    sequence=$((sequence + 1))
    sent_at=$(date -u '+%Y-%m-%dT%H:%M:%S+00:00')
    request=$(state_path heartbeat-request.json) || return 1
    printf \
        '{"agent_version":"1.0.0","boot_id":"%s","reported_stage":"%s","schema_version":1,"sent_at":"%s","sequence":%s}' \
        "${ALT_INSTALL_BOOT_ID:-unknown}" "$stage" "$sent_at" "$sequence" |
        state_write_stream heartbeat-request.json
    http_request POST "/v1/install-sessions/${session}/heartbeat" \
        heartbeat-response.json "$request" "$auth" 200 || return 1
    response=$(state_path heartbeat-response.json) || return 1
    [[ "$(protocol_json_string "$response" status)" == ok ]] || return 1
    state_write heartbeat-sequence "$sequence"
    state_remove heartbeat-request.json
    state_remove heartbeat-response.json
}

protocol_wait_for_plan() {
    local session auth response state poll_after iteration
    session=$(state_read session-id) || return 1
    auth=$(state_path curl-auth.conf) || return 1
    poll_after=$(state_read poll-after) || return 1
    for ((iteration = 1; iteration <= 600; iteration++)); do
        http_request GET "/v1/install-sessions/${session}/status" \
            status-response.json '' "$auth" 200 || return 1
        response=$(state_path status-response.json) || return 1
        state=$(protocol_json_string "$response" state) || return 1
        state_remove status-response.json
        case "$state" in
            plan_published) return 0 ;;
            awaiting_approval|session_created) "$ALT_INSTALL_SLEEP" "$poll_after" ;;
            cancelled|expired)
                printf 'ALT_INSTALL_ERROR session_%s\n' "$state" >&2
                return 1
                ;;
            *)
                printf '%s\n' 'ALT_INSTALL_ERROR status_invalid' >&2
                return 1
                ;;
        esac
    done
    printf '%s\n' 'ALT_INSTALL_ERROR approval_timeout' >&2
    return 1
}

protocol_download_plan() {
    local session auth
    session=$(state_read session-id) || return 1
    auth=$(state_path curl-auth.conf) || return 1
    http_request GET "/v1/install-sessions/${session}/plan" \
        plan.json '' "$auth" 200 || return 1
    http_request GET "/v1/install-sessions/${session}/plan-signature" \
        plan-signature.json '' "$auth" 200
}
