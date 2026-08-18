# Gov74 DNS Self-Recovery Design

## Goal

Keep the Gov74 AnyConnect service recoverable after a transient DNS failure without changing VPN credentials, tunnel routes, or the OpenConnect invocation.

## Cause addressed

When Gov74 disconnects an idle session, `gov74-anyconnect.service` restarts. On 2026-08-15 its three restart attempts could not resolve `vpn-ra.gov74.ru`; systemd then applied its `StartLimitBurst=3` limit and left the service failed after DNS recovered.

## Design

Add a root-owned `gov74-wait-dns.sh` pre-start script. It waits for an IPv4 DNS result for `vpn-ra.gov74.ru`, logs that it is waiting at a bounded rate, and exits only when DNS is available. A `gov74-anyconnect.service.d/dns-wait.conf` drop-in runs the script before OpenConnect and permits that waiting phase to outlive systemd's default start timeout.

The existing OpenConnect command, credentials, `cisco0` interface, egress guard, output guard, and routes remain untouched. Once DNS recovers, the original service starts normally. Authentication or remote-rejection failures keep the existing bounded restart policy.

## Verification

Repository tests assert the script contract, systemd pre-start and timeout settings, and installer wiring. Deployment validates the unit with `systemd-analyze verify` and confirms that `gov74-anyconnect` remains active with `cisco0` present.
