#!/bin/bash

wait_for_controller_route() {
    local attempt=0
    while (( attempt < 60 )); do
        if ip -4 route get 192.168.100.17 >/dev/null 2>&1; then
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 1
    done
    return 1
}
