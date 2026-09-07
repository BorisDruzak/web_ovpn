# Network Hosts Performance Design

**Status:** approved by the user on 2026-09-07.

## Goal

Make Network Hosts a fast, read-only UI/API over a persistent SQLite snapshot. Network collection, availability probes, SNMP, MikroTik access, and reconciliation remain background work; opening or filtering the host list never starts them.

## Constraints

- Preserve the semantics of `online`, `offline`, `seen`, `stale`, `connected`, `not_monitored`, passive evidence, active-probe origin, manual/scheduled runs, and force monitoring.
- Use the existing SQLite database only; do not introduce Redis, Celery, another service, or a larger timeout.
- Publish snapshots atomically and retain the latest complete snapshot after a refresh error.
- Keep the public `hosts` field while adding pagination and snapshot metadata.

## Design

`bulk_project_host_availability(conn, hosts, now)` loads rules, force-monitor state, manual results, latest runs/results, and passive ARP/DHCP/bridge/FDB evidence into bounded lookup maps. Per-host projection is then pure Python and functionally equivalent to `project_host_availability`.

`netctl.host_snapshot` builds this projection after collection/reconciliation and publishes it atomically to `network_host_current_state`, `network_host_current_sources`, and `network_host_snapshot_meta`. Snapshot rows include the complete public payload and indexed filtering/sorting columns. The builder applies a bounded OpenVPN overlay so `connected` belongs to the read model.

The host CLI, API, and HTML page read the prepared snapshot. The page polls lightweight metadata, and fetches a replacement for its current filtered page only after `snapshot_id` changes. Filters and page state are preserved; stale requests are cancelled or ignored.

## Validation

Tests prove legacy/bulk equivalence, bounded SQL statements for 1000+ hosts, migration/indexes, atomic publication/failure preservation, CLI/API filtering and pagination, and browser update race/error behavior. Production checks measure snapshot refresh and host reads and verify service/timer health.
