# Availability Probe Capability Recovery Design

**Date:** 2026-08-11

## Goal

Restore active availability probes in the hardened Netctl systemd services
without weakening their sandboxing or exposing network details through the
web/API.

## Evidence

The Netctl services run with `NoNewPrivileges=true`. The host permits no
unprivileged ICMP ping sockets (`net.ipv4.ping_group_range = 1 0`), so the
file capability on `/usr/bin/ping` cannot take effect. Both services therefore
return `Operation not permitted`, which Netctl correctly sanitizes as
`executor_error`.

The observed `collection already running` is separate: the timer starts
`netctl-reconcile.service` after collection, and it intentionally holds the
shared collection lock for about 35 seconds. A manual collection during that
interval is rejected rather than run concurrently.

## Scope

Included:

- Add `AmbientCapabilities=CAP_NET_RAW` only to `netctl-collect.service` and
  `netctl-availability.service`.
- Retain `NoNewPrivileges=true`, `PrivateTmp=true`, and `ProtectHome=true`.
- Regression-test the hardening and capability contract.
- Deploy the unit updates, reload systemd, and run both services.

Excluded:

- Changes to network devices, network configuration, collection/reconcile
  locking, or UI semantics.
- Returning raw process output, targets, credentials, or socket errors.

## Acceptance Criteria

- Both active-probe unit files retain `NoNewPrivileges=true` and declare
  `AmbientCapabilities=CAP_NET_RAW`.
- The units reload successfully on the server.
- Manual availability and full Netctl collection services finish successfully.
