# WG policy-routing resilience design

## Goal

Make the existing VLAN50-to-WireGuard policy route recover correctly after a
WireGuard restart, boot-time DNS delay or a missing netfilter chain, and expose
the complete read-only state through `vpnctl`.

## Scope

This stage covers only `wg0`, `vpn-policy.service` and a new read-only runtime
health command. It must not alter OpenVPN client profiles, OpenVPN forwarding,
MSS/MTU settings, OPNsense routing, MikroTik configuration, or the web UI.

## Required steady state

- `wg0.conf` retains `Table = off`.
- VLAN50 traffic enters through `ens18.50`, receives mark `0x1`, and is routed
  only by table `123`.
- Table `123` contains only `default dev wg0`.
- The policy rule is `fwmark 0x1/0xffffffff lookup 123` at priority `1000`.
- The packet-mark and NAT chains are `VPN_POLICY_MARK` and `VPN_POLICY_NAT`.
- No `awg0`, `vpn-routing.service`, table `51820`, or global WireGuard default
  route is accepted as healthy state.
- If `wg0` is unavailable, marked VLAN50 traffic remains unavailable rather
  than silently using the ordinary WAN route.

## Service design

The version-controlled `vpn-policy.service` will require, bind to and be part
of `wg-quick@wg0.service`. It runs a version-controlled script with explicit
`start`, `stop` and `status` operations:

- `start` first clears only its own marked rule, table-123 default and named
  chains, then creates exactly the required state.
- `stop` removes only those same managed objects. It does not flush global
  nftables state or alter OpenVPN rules.
- `status` reports whether each invariant is present; it makes no changes.

`PartOf=` ensures a deliberate `wg-quick@wg0` restart also restarts policy
setup. `BindsTo=` stops policy state when the device unit disappears. A
dedicated `vpn-runtime-health.timer` invokes health checking every minute so a
delayed endpoint DNS resolution or external ruleset flush becomes visible even
when systemd still shows a oneshot policy unit as active.

## Runtime health CLI

`vpnctl --json runtime-health` is read-only and returns structured sections:

- `openvpn`: service state, management socket availability and client count;
- `wireguard`: service/link state, handshake age, interface MTU and transfer
  counters, without keys or peer identifiers;
- `policy_routing`: expected rule, table default route, stale legacy rules and
  forbidden table `51820` state;
- `netfilter`: the expected mark and NAT chain rules and counters;
- `overall`: `ok`, `warn` or `error`, plus explicit failures.

`--strict` returns non-zero when `overall=error`; the timer uses it to record a
clear systemd failure in the journal. `WG_HANDSHAKE_MAX_AGE_SECONDS` defaults
to 180 seconds and remains configurable in the production environment.

## Safety and verification

- All health operations use read-only commands and redact private material.
- The installed systemd assets are generated from files tracked in this
  repository; ad-hoc remote scripts are not the source of truth.
- Automated tests cover healthy state, a missing `wg0`, stale handshake,
  missing table route, forbidden `51820` rule and no mutation during status.
- Deployment verification checks the service graph, then performs one planned
  `wg-quick@wg0` restart in a maintenance window and confirms policy recovery,
  OpenVPN management availability and unchanged OpenVPN client count.

## Explicitly deferred

- OpenVPN MSS/MTU remediation: it requires a real affected-client PMTU test.
- The web `VPN Runtime` page, API/MCP endpoint and retained health history.
- Changing the direct `openvpm` route from `10.10.10.0/24` to `/23`.
