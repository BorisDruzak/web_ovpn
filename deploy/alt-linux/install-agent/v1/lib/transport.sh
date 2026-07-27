#!/bin/bash

ALT_INSTALL_CURL=${ALT_INSTALL_CURL:-curl}
ALT_INSTALL_SLEEP=${ALT_INSTALL_SLEEP:-sleep}
readonly ALT_INSTALL_HTTP_ATTEMPTS=5
readonly ALT_INSTALL_HTTP_LIMIT=65536

transport_error() {
    printf 'ALT_INSTALL_ERROR %s\n' "$1" >&2
    return 1
}

http_request() {
    local method="$1" path="$2" output_name="$3" request_body="${4:-}"
    local auth_config="${5:-}" expected_status="$6"
    local destination temporary status attempt size curl_status
    local -a arguments

    [[ "$method" == GET || "$method" == POST ]] ||
        transport_error request_invalid || return 1
    [[ "$path" == /v1/install-sessions* && "$path" != *'?'* ]] ||
        transport_error request_invalid || return 1
    [[ "$expected_status" =~ ^[0-9]{3}$ ]] ||
        transport_error request_invalid || return 1
    destination=$(state_path "$output_name") ||
        transport_error request_invalid || return 1

    for ((attempt = 1; attempt <= ALT_INSTALL_HTTP_ATTEMPTS; attempt++)); do
        temporary="${destination}.tmp.$$"
        rm -f -- "$temporary"
        (
            umask 077
            : > "$temporary"
            chmod 0600 -- "$temporary"
        )
        arguments=(
            --silent
            --show-error
            --proto '=http'
            --proto-redir '=http'
            --max-redirs 0
            --connect-timeout 3
            --max-time 10
            --max-filesize "$ALT_INSTALL_HTTP_LIMIT"
            --request "$method"
            --output "$temporary"
            --write-out '%{http_code}'
        )
        [[ -z "$auth_config" ]] ||
            arguments+=(--config "$auth_config")
        if [[ -n "$request_body" ]]; then
            arguments+=(
                --header 'Content-Type: application/json'
                --data-binary "@$request_body"
            )
        fi
        arguments+=("${ALT_INSTALL_CONTROLLER}${path}")

        if status=$("$ALT_INSTALL_CURL" "${arguments[@]}"); then
            [[ "$status" =~ ^[0-9]{3}$ ]] || {
                rm -f -- "$temporary"
                transport_error response_status_invalid
                return 1
            }
            size=$(wc -c < "$temporary")
            [[ "$size" -le "$ALT_INSTALL_HTTP_LIMIT" ]] || {
                rm -f -- "$temporary"
                transport_error response_too_large
                return 1
            }
            if [[ "$status" == 3* ]]; then
                rm -f -- "$temporary"
                transport_error redirect_rejected
                return 1
            fi
            if [[ "$status" != "$expected_status" ]]; then
                rm -f -- "$temporary"
                transport_error semantic_rejection
                return 1
            fi
            mv -f -- "$temporary" "$destination"
            chmod 0600 -- "$destination"
            return 0
        else
            curl_status=$?
        fi

        rm -f -- "$temporary"
        case "$curl_status" in
            5|6|7|18|28|52|55|56) ;;
            63)
                transport_error response_too_large
                return 1
                ;;
            *)
                transport_error transport_local_failure
                return 1
                ;;
        esac
        if ((attempt == ALT_INSTALL_HTTP_ATTEMPTS)); then
            transport_error transport_exhausted
            return 1
        fi
        "$ALT_INSTALL_SLEEP" "$((1 << (attempt - 1)))"
    done
    return 1
}
