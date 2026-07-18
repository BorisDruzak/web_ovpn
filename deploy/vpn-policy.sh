#!/usr/bin/env bash
set -euo pipefail

# Own only the policy-routing objects for VLAN50 egress through WireGuard.
# Keep wg-quick's main routing table untouched (`Table = off` in wg0.conf).
WG_IF="${WG_INTERFACE:-wg0}"
PBR_IN_IF="ens18.50"
PBR_TABLE="123"
PBR_MARK="0x1"
PBR_MASK="0xffffffff"
PBR_PRIORITY="1000"
MANGLE_CHAIN="VPN_POLICY_MARK"
NAT_CHAIN="VPN_POLICY_NAT"

usage() {
  echo "usage: $0 {start|stop|status}" >&2
  exit 2
}

delete_rule() {
  while ip rule del fwmark "$PBR_MARK/$PBR_MASK" lookup "$PBR_TABLE" priority "$PBR_PRIORITY" 2>/dev/null; do
    :
  done
}

delete_jump() {
  local table="$1"
  local parent="$2"
  local chain="$3"
  while iptables -w -t "$table" -D "$parent" -j "$chain" 2>/dev/null; do
    :
  done
}

clear_nat() {
  delete_jump nat POSTROUTING "$NAT_CHAIN"
  iptables -w -t nat -F "$NAT_CHAIN" 2>/dev/null || true
  iptables -w -t nat -X "$NAT_CHAIN" 2>/dev/null || true
}

ensure_marking() {
  delete_rule
  ip rule add fwmark "$PBR_MARK/$PBR_MASK" lookup "$PBR_TABLE" priority "$PBR_PRIORITY"

  delete_jump mangle PREROUTING "$MANGLE_CHAIN"
  iptables -w -t mangle -F "$MANGLE_CHAIN" 2>/dev/null || true
  iptables -w -t mangle -X "$MANGLE_CHAIN" 2>/dev/null || true
  iptables -w -t mangle -N "$MANGLE_CHAIN" 2>/dev/null || true
  iptables -w -t mangle -A "$MANGLE_CHAIN" -i "$PBR_IN_IF" -j MARK --set-xmark "$PBR_MARK/$PBR_MASK"
  iptables -w -t mangle -A PREROUTING -j "$MANGLE_CHAIN"
}

start() {
  if ! ip link show dev "$WG_IF" >/dev/null; then
    stop
    return 0
  fi
  clear_nat
  ensure_marking
  ip route replace default dev "$WG_IF" table "$PBR_TABLE"

  iptables -w -t nat -N "$NAT_CHAIN" 2>/dev/null || true
  iptables -w -t nat -A "$NAT_CHAIN" -o "$WG_IF" -m mark --mark "$PBR_MARK/$PBR_MASK" -j MASQUERADE
  iptables -w -t nat -A POSTROUTING -j "$NAT_CHAIN"
}

stop() {
  # Preserve the mark/rule and make its table explicitly unreachable. This
  # prevents VLAN50 traffic from falling through to the host's main table
  # while wg0 is down or still waiting for endpoint DNS at boot.
  ensure_marking
  clear_nat
  ip route replace unreachable default table "$PBR_TABLE"
}

status() {
  ip link show dev "$WG_IF" >/dev/null
  ip rule show | grep -Eq "^${PBR_PRIORITY}:.*fwmark ${PBR_MARK}.*lookup ${PBR_TABLE}"
  ip route show table "$PBR_TABLE" | grep -Eq "^default dev ${WG_IF}( |$)"
  iptables -w -t mangle -C PREROUTING -j "$MANGLE_CHAIN"
  iptables -w -t mangle -C "$MANGLE_CHAIN" -i "$PBR_IN_IF" -j MARK --set-xmark "$PBR_MARK/$PBR_MASK"
  iptables -w -t nat -C POSTROUTING -j "$NAT_CHAIN"
  iptables -w -t nat -C "$NAT_CHAIN" -o "$WG_IF" -m mark --mark "$PBR_MARK/$PBR_MASK" -j MASQUERADE
}

case "${1:-}" in
  start) start ;;
  stop) stop ;;
  status) status ;;
  *) usage ;;
esac
