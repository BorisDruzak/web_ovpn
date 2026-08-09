# Task 10 — deployment and production verification

Date: 2026-08-09.

## Deployment

- Verified branch: `4963eb7` before this deployment record.
- Target: `ui-vpn-deploy` (`192.168.100.30`), application `/opt/openvpn-web`.
- The installer preflight correctly stopped before mutation because `/usr/bin/nmap`
  was absent. Installed the Ubuntu `nmap` package (and its distro dependencies),
  then reran the verified installer from an isolated `/tmp` source archive.
- Only the OpenVPN web application and Netctl timers were touched; no network-device
  configuration was changed.
- Migration head is `24`; `openvpn-web`, `netctl-collect.timer`,
  `netctl-reconcile.timer`, and `netctl-retention.timer` are active.
- `/usr/local/libexec/netctl-nmap-fingerprint` and
  `/etc/sudoers.d/netctl-nmap` are root-owned; `visudo -cf` passed.

## LLDP and SNMP canary

- The timer's fresh DGS collection produced the same four DGS core LLDP neighbours
  as the pre-deployment baseline. Optional subtype, descriptions, capabilities,
  and management-address fields were present where supplied.
- DGS reported timeout for `if_hc_in_octets` and aggregate counter samples, while
  FDB and LLDP remained available. This is an equipment capability limitation,
  not a loss of core inventory data.
- The full switch CLI matrix was executed. CSS FDB data remained populated.
  TP-Link sources still report their known optional-LLDP parse/timeout outcomes;
  their usable core data and FDB rows remained available.
- Telemetry rows are present and correctly report `insufficient_history` after the
  first post-deployment sample, avoiding fabricated rates.

## Nmap canary and safeguards

- Two confirmed runtime assets with exactly one current IPv4 completed the fixed
  `asset-fingerprint-v1` profile successfully. The first run completed in about
  two seconds; the second in about twenty-two seconds.
- Repeating the first asset inside TTL returned the same run id, demonstrating
  the no-second-scan/single-flight cache path.
- No Nmap process remained after completion. The runner is root-owned, uses the
  fixed no-NSE profile, and accepts only an asset key.
- An unauthenticated browser smoke reached the login boundary for both dashboard
  and asset card (HTTP 303). No authenticated browser session was available, and
  protected credentials were deliberately not read; the card POST lifecycle is
  covered by the verified local web test suite and backend canary above.

## Resource check

- Load average: 0.52 / 0.38 / 0.29; available memory about 1.5 GiB.
- No warning-priority entries for `openvpn-web` or `netctl-collect` in the final
  20-minute deployment window.
