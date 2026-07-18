# Server observability from OpenVPN gateway

## Goal

Add a read-only infrastructure health layer to the existing OpenVPN web panel.
The collector runs on the OpenVPN gateway and answers two distinct questions:

1. Is a target reachable from the gateway and from a VPN-client-like source?
2. Is the target's application, required service, DNS function, and storage healthy?

Network topology, host addresses, and target inventory remain in the canonical
network-configuration repository. This implementation stores only stable target
role identifiers and operational results. It stores no passwords, private keys,
or API tokens in the repository.

## Architecture

The OpenVPN gateway owns a dedicated SSH observer key. Its private half is kept
only in the gateway user's restricted `.ssh` directory. Each target authorizes
the public half for a least-privilege administrative observer account.

A systemd oneshot service invokes a collector every five minutes. The collector
uses read-only SSH commands, HTTPS loopback health endpoints, and source-bound
network probes. It writes the complete result atomically to a local snapshot and
appends operational errors to the system journal.

The web application reads the latest snapshot through a dedicated endpoint and
renders an Infrastructure Health section beside the existing VPN Runtime and
Network Observer state. The UI must always show the probe source: `gateway`,
`vpn_path`, or `target`.

## Target checks

| Target role | Gateway and VPN-path checks | Target-local checks |
| --- | --- | --- |
| file server | SSH reachability | SSH service and data disk free space |
| Directum | TCP/SSH reachability | system disk, RX log volume, Directum runner, database, queue, cache, web, DNS |
| Active Directory | TCP/SSH reachability | system disk, DNS, directory, AD Web Services, internal and external resolution |
| Nextcloud | HTTPS reachability | `status.php`, maintenance/database-upgrade state, application data disk, required services |
| OnlyOffice | HTTPS reachability | `/healthcheck` response `true`, container runtime, system disk |
| OPNsense DNS | SSH reachability | AdGuard DNS, Unbound, internal zone resolution, external resolution |

The collector performs client-like probes with the tunnel-side source address.
This validates reverse routing separately from ordinary gateway reachability.

## Result model and severity

Each check returns a timestamp, source, observed value, expected value, latency
where applicable, and one of:

- `ok` — expected result;
- `warn` — degraded but usable;
- `critical` — service unavailable or capacity at immediate risk;
- `error` — probe could not complete;
- `stale` — no completed collection for three intervals.

Disk thresholds are `warn` below 15% free and `critical` below 10% free. The
Directum RX log check is `warn` at 20 GiB and `critical` at 30 GiB. The collector
does not delete logs, restart services, or change any network configuration.

## Failure handling

A failed target never prevents collection of the remaining targets. SSH errors,
timeouts, parse failures, and unexpected endpoint responses are retained as
structured check errors. A collection is considered stale after fifteen minutes.
The UI distinguishes a failed target from an unavailable collector.

## Security boundaries

- Only the gateway holds observer private key material.
- The collector does not expose raw command output, secrets, or SSH keys through
  the web API.
- Commands are allow-listed per role; there is no web-triggered arbitrary shell
  execution.
- The implementation is read-only. Remediation workflows, retention cleanup,
  and service restarts are explicitly out of scope.

## Verification

Automated tests cover result parsing, threshold classification, stale-state
calculation, endpoint output handling, and web API/UI rendering. Deployment
verification confirms the timer, snapshot write, read-only target access from
the gateway, source-bound VPN-path probes, and the absence of target-side writes.
