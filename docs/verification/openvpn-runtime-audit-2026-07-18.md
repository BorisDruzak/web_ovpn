# OpenVPN runtime audit — 2026-07-18

## Scope and evidence

Read-only SSH diagnostics were run against `openvpm` (`192.168.100.30`). The
OpenVPN Control MCP endpoint was unavailable from the operator workstation:
its HTTP connection was refused. This audit therefore uses direct SSH output
for the OpenVPN host only; it does not change any network device.

## Observed OpenVPN host state

- `openvpn-server@server.service` was `active (running)`.
- The OpenVPN tunnel interface was `tun0` with `192.168.50.1/24`, consistent
  with the canonical `openvpn-pool` segment.
- The systemd unit starts OpenVPN with
  `--status /run/openvpn-server/status-server.log --status-version 2`. This
  command-line status path overrides the `status` directive in `server.conf`.
- IPv4 forwarding was enabled.
- `openvpn-web.service` was enabled but inactive. Its last journal entries show
  a clean systemd stop, not a crash; the local API listener on port 8088 was
  absent. This explains why the OpenVPN Control MCP endpoint was unavailable.
- `vpnctl validate-network-plan` returned no errors or warnings. It confirmed
  the current `/24` OpenVPN pool, management socket and no managed site routes.
  The management interface reported five current client connections at audit
  time; no client profile or CCD was changed.

## Observed routing and WireGuard state

- The host has `wg0` with address `10.196.194.246/32` and policy rule
  `fwmark 0x1 -> table 123`; table 123 has a default route through `wg0`.
- Only traffic arriving from `ens18.50` is marked for that policy table. The
  WireGuard peer has default allowed IPs and a current handshake; its
  configuration is therefore an egress path for this marked VLAN, not a
  replacement default route for all host traffic.
- The main table contains `10.10.10.0/24 via 192.168.100.1`.
- Netplan intentionally contains `10.10.10.0/24 via 192.168.100.1`. For an
  address in the adjacent `10.10.11.0/24`, the host follows its default route
  to MikroTik `192.168.100.250`; MikroTik returns an ICMP redirect to OPNsense.
  The last collected MikroTik table also contains `10.0.0.0/8 via
  192.168.100.1` (`Route to OPNsense VLANs`), explaining the redirect: the
  explicit `/24` bypasses the unnecessary first hop through MikroTik. The
  tested address `10.10.11.1` did not answer, so it is not currently identified
  as an active device or service.
- OPNsense LAN is now confirmed as `10.10.10.1/23`, so the canonical context
  and the `/23` route pushed by `vpnctl` are correct. The direct netplan route
  on `openvpm` remains narrower (`/24`) and is an optimization only for its
  lower half; widening that direct route is a separate live-network change.

## Fragility assessment

The current data path is working, but its recovery path is fragile.

- The correct current state is narrow and explicit: `Table = off` in
  `wg0.conf`, exactly one IPv4 rule (`fwmark 0x1 -> table 123`), a default
  route through `wg0` only in table `123`, and marking only ingress from
  `ens18.50`.
- Historical `wg-quick` logs show that an earlier configuration installed
  global rules and a default route in table `51820`. That could divert host
  traffic and explains the reported outages. Those rules are absent now, but
  must be treated as a regression condition.
- `vpn-policy.service` is enabled and active, but has only `After=` and
  `Wants=` for `wg-quick@wg0.service`. It has no `BindsTo=`, `PartOf=` or
  `ExecStop=`. A delayed WireGuard startup or a manual `wg-quick` restart can
  therefore leave table 123, packet marks and NAT chains absent or stale while
  systemd still reports the policy service active.
- `wg-quick` previously waited for DNS resolution of the WireGuard endpoint;
  the journal recorded a temporary DNS failure. The policy unit waits only 20
  seconds and does not retry, so this is a concrete boot-time failure mode.
- `nftables.service` is disabled while the active policy chains are created by
  `iptables-nft` through `vpn-policy.sh`. Any future nftables reload/flush can
  remove those chains without restarting the policy service.
- No MSS-clamp rule is active. Link counters show no current drops, so adding a
  global clamp would be speculative. The monitored policy path has MTU 1420
  on `wg0`; this path is not the reported MSS issue. Validate TCP PMTU on the
  real OpenVPN path before applying any OpenVPN-scoped `mssfix` or clamp.
- The existing web dashboard exposes OpenVPN state and RouterOS snapshots, but
  not the local `wg0`, table 123, packet mark, policy-chain or MTU state. Its
  latest MikroTik collection was stale at audit time, so it cannot provide a
  trustworthy live routing alarm by itself.
- The unused `vpn-routing.service` for a non-existent `awg0` was removed from
  `openvpm` after confirmation. `wg0`, policy table 123 and OpenVPN management
  were rechecked and remained healthy.

## Limits and follow-up

- The deploy account has no passwordless sudo. Protected OpenVPN, WireGuard
  and firewall state was read only after the sudo password was supplied; no
  private key material was recorded in this audit.
- Static nftables rules for the legacy `10.8.0.0/24` pool remain in INPUT,
  FORWARD and POSTROUTING, but their packet counters were zero. The legacy
  SNAT service is disabled and the dedicated `VIPNET_OPENVPN_SNAT` chain is
  absent, so `vpnctl nat-status` correctly reports the current
  `192.168.50.0/24` design as `disabled_expected`. Remove the zero-counter
  legacy rules only in a separately approved network-maintenance change.
- Authentication to `root@10.10.10.1` was rejected twice with the supplied
  password. WireGuard configuration on the OPNsense host remains unverified
  until its SSH authentication method or credentials are corrected.
- `vpnctl` defaults and its sample environment now use the active systemd
  status path. The deployed `/etc/openvpn/vpnctl.env` currently has no
  `STATUS_LOG` override, so it will use this corrected default when the local
  patch is deployed. `vpnctl server-config inspect` will continue to display
  `/var/log/openvpn/status.log` as the declared `server.conf` value; that is
  not the effective runtime value while systemd supplies `--status`.
