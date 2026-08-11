# Availability Probe Capability Recovery Implementation Plan

**Goal:** Restore ICMP availability probes in Netctl's hardened systemd
services with the minimum required capability.

**Architecture:** Keep the existing Netctl probe code and sandboxing. Give
only the two services that execute active probes an ambient `CAP_NET_RAW`,
because `NoNewPrivileges=true` prevents `/usr/bin/ping` from applying its file
capability on this host.

## Task 1: Add a failing unit contract

- [x] Add a test requiring `NoNewPrivileges=true` and
  `AmbientCapabilities=CAP_NET_RAW` in both active-probe services.
- [x] Verify it fails while the capability is absent.

## Task 2: Apply the least-privilege unit change

- [x] Add `AmbientCapabilities=CAP_NET_RAW` to `netctl-collect.service` and
  `netctl-availability.service`.
- [ ] Run deployment and Netctl focused tests.

## Task 3: Deploy and verify

- [ ] Offset reconciliation and availability timers after collection to avoid
  a shared-lock collision; add a regression test for the schedules.
- [ ] Back up and deploy the two unit files and both timers; reload systemd.
- [ ] Verify `netctl-availability.service`, manual collection, and the next
  automatic collection all exit successfully.
