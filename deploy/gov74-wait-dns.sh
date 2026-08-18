#!/usr/bin/env bash
set -euo pipefail

HOST="vpn-ra.gov74.ru"
attempt=0

while ! getent ahostsv4 "$HOST" >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if [[ "$attempt" -eq 1 || $((attempt % 10)) -eq 0 ]]; then
    logger -t gov74-wait-dns "waiting for DNS resolution of $HOST (attempt $attempt)"
  fi
  sleep 30
done

if [[ "$attempt" -gt 0 ]]; then
  logger -t gov74-wait-dns "DNS resolution restored for $HOST after $attempt wait attempt(s)"
fi
