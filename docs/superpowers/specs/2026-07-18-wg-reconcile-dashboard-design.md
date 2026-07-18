# WG reconciler and dashboard design

## Goal

Keep VLAN50 (`ens18.50`) fail-closed when `wg0` is absent, automatically
restore the existing table-123 policy when `wg0` returns, and show the
read-only runtime state in the existing web dashboard.

## Safety boundary

- The reconciler may modify only `fwmark 0x1/0xffffffff`, priority `1000`,
  table `123`, `VPN_POLICY_MARK`, and `VPN_POLICY_NAT`.
- It must never start, restart, stop, or reconfigure `wg-quick@wg0`, OpenVPN,
  OPNsense, MikroTik, DNS, client profiles, forwarding, MSS, or MTU.
- When `wg0` does not exist, it must preserve marking and make table `123`
  contain `unreachable default`; marked packets must not fall through to the
  main routing table.
- Runtime API and UI are read-only. They must not emit WireGuard private,
  preshared, or public key material.
- The reconciler shares `/run/lock/vpn-policy.lock` with `vpn-policy.service`;
  a timer invocation must serialize with controlled policy lifecycle work.

## Components

### Policy reconciler

`vpn-policy.sh` gains a `reconcile` command. It validates the existing
active or fail-closed state before writing: when `wg0` exists and the current
policy is healthy, it makes no changes; if that policy drifted, it installs
`default dev wg0`, the mark rule, the mangle chain and the NAT chain. When
`wg0` is absent and the fail-closed state is already healthy, it makes no
changes; if it drifted, it installs the mark rule/mangle chain and
`unreachable default`, with no WG NAT chain. This prevents the timer from
flushing and recreating healthy PBR/NAT objects every minute.

`vpn-policy-reconcile.service` runs that command as root. Its paired timer
starts one minute after boot and every minute thereafter. It has no dependency
that would start WG; each invocation exits successfully after making the
appropriate active or fail-closed state. The service invokes the script through
the shared `flock` lock, so this scoped repair cannot race `vpn-policy.service`.
The existing
`vpn-runtime-health.timer` remains a separate read-only alarm.

### Read-only web status

`GET /api/v1/runtime-health` calls `vpnctl --json runtime-health` without
`--strict`, under existing API authentication. It returns the structured
health response even when `overall=error`, so dashboard users can see the
failure rather than a generic HTTP error.

The existing `/network/dashboard` page gains a compact "VPN Runtime" card.
It shows OpenVPN service/management state, WG service/link/handshake age/MTU,
policy-rule/table/chain state, the legacy-51820 regression flag, and any
warnings/errors. The browser polls the new endpoint on page load and every
30 seconds. It never includes peer keys or packet addresses. Browser access is
session-authenticated rather than Bearer-authenticated: an unauthenticated
request to `/network/runtime-health` redirects with HTTP 303 to `/login`.

## Error handling

If `vpnctl` cannot run, the API uses the existing controlled `VpnctlError`
path. If a normal health response says `overall=error`, the API returns HTTP
200 with that response; the card uses an error state and displays only its
sanitized `warnings`/`errors` strings. Before rendering those messages, the
browser redacts key-like values, IP addresses, endpoint/host names, and ports;
all values are inserted with text nodes. A transient browser fetch failure
preserves an explicit "status unavailable" display until the next poll.

## Verification

- Shell tests execute `reconcile` against mocked `ip` and `iptables` commands
  and assert both the active-WG and missing-WG command sequences.
- Deployment asset tests assert reconciler timer installation and verify it
  does not invoke `systemctl restart`, `start`, or `stop` for WG/OpenVPN.
- API tests assert `runtime-health` calls the non-strict CLI and propagates an
  error-shaped health result with HTTP 200.
- Dashboard tests assert the card renders safe state fields and uses the
  polling endpoint.
- Production acceptance checks wait for one reconciler tick, confirm strict
  health, then verify the dashboard endpoint returns the same sanitized state.

## Out of scope

This iteration does not retry a failed WG peer, change its DNS endpoint, or
change any OpenVPN/MSS/MTU/device configuration. It also does not add alert
delivery beyond the existing systemd journal health record.
