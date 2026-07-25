# Device Network Card and Bounded Collection History Design

**Date:** 2026-07-26

## Goal

Deliver a useful device card in the existing web UI. An operator can find a
device by IP address, hostname, MAC address, or known name, open it, and see
the best available network attachment: switch, port, VLAN, confidence, and
the path towards the core. The card must make uncertainty explicit.

The feature must use the existing read-only Network Observer and Netctl data
model. It must never change switch, router, DHCP, firewall, or OpenVPN
configuration.

The release also makes attachment data current after every completed
collection and bounds operational history to 30 days. Current state remains
available regardless of age.

## Current State

The application already has:

- `/network/hosts`: a web search/list for IP, MAC, hostname, and display name;
- `/network/hosts/{ip}`: a basic web device card;
- `GET /api/v1/context/search` and `GET /api/v1/context/assets/{asset_key}`:
  read-only asset context APIs;
- current switch ports, FDB, VLAN, LLDP, topology and attachment-resolution
  tables;
- attachment states: `confirmed`, `ambiguous`, `uplink_only`, and
  `unresolved`.

The context API has the attachment decision but does not return all display
fields needed by the web card, including the selected switch name and the
human-readable port details. The web card does not use the context API.

Collections run every five minutes, but the deployed `netctl-reconcile.timer`
is disabled. Consequently, collection data can be newer than the topology and
attachment decisions. The current storage code replaces current switch state,
but retains several append-only histories without a cleanup job. The deployed
SQLite database was 3.54 GB during the design review.

## Scope

### Included in release one

- Enrich the existing device-search and device-card flow.
- Show the resolved attachment, alternatives, confidence, and observation
  timestamp.
- Show a compact, textual path from the selected access switch towards the
  core; a graphical topology editor is not part of this release.
- Show the port state and a bounded list of known assets/MACs currently learned
  on that port.
- Reconcile topology and attachments only after a completed collection run.
- Enable and retain `netctl-reconcile.timer` as a boot/recovery safety net.
- Delete expired operational history daily using a 30-day policy.
- Supply deployment, rollback, and verification steps for the database change.

### Not included

- Device, switch, router, VLAN, firewall, DNS, DHCP, OpenVPN, or MikroTik
  configuration changes.
- A draggable topology map, a topology editor, or automated network writes.
- A claim that an FDB record always identifies a physical end device.
- Long-term archive storage beyond the defined 30-day operational window.

## User Experience

The existing `Устройства` page remains the entry point.

1. The operator enters an IP, hostname, MAC, or device name.
2. If the query matches several runtime assets, the result list presents each
   candidate with IP/MAC/site and opens only the selected asset.
3. The card shows identity and observations, then a new `Network attachment`
   panel.
4. A confirmed attachment shows switch name, management IP where available,
   port label/alias, VLAN, port status and speed, FDB observation time, and
   confidence.
5. An ambiguous attachment lists the best bounded alternatives and explains
   why no port is selected. `uplink_only` and `unresolved` show their distinct
   meanings and no invented port.
6. The card shows the bounded topology path to core when a confirmed
   attachment has one. It shows the explicit reason when it cannot build one.
7. The card shows a bounded, redacted list of other currently learned MACs and
   known assets on the selected port. It warns that an access point, IP phone,
   unmanaged switch, or trunk can make a port legitimately contain several
   devices.

All timestamps are displayed with their source and freshness. A card that
depends on a stale reconciliation must show that condition rather than present
the attachment as current.

## Attachment Semantics

An attachment is derived from an active asset interface MAC appearing in a
successful, authoritative switch FDB collection. Existing topology evidence
(intent, FDB management MAC, and LLDP) identifies backbone ports. Candidate
ports are ranked using the existing deterministic scoring rules.

- `confirmed`: one direct candidate meets the confidence threshold and leads
  competing candidates by the configured safety margin;
- `ambiguous`: two or more viable candidates cannot be safely distinguished;
- `uplink_only`: the MAC is observed only on verified backbone/uplink ports;
- `unresolved`: no eligible current FDB candidate exists.

The card exposes the status, confidence, selected attachment when present, and
bounded alternatives. It must not silently select the newest or highest-score
alternative for an ambiguous result.

## Data and API Design

Extend the read-only asset-context response with a presentation-safe
attachment object. It includes:

- `switch`: stable source id, source name, site, and management host;
- `port`: key, physical port, name, alias, administrative/operational state,
  and speed;
- `vlan`: key and numeric ID when known;
- `observed_at`, `confidence`, `status`, and bounded alternatives;
- `same_port_devices`: bounded current FDB entries linked to known runtime
  assets where possible, plus an unlinked-MAC count;
- `freshness`: collection time and reconciliation time used for the result.

Asset search remains exact in the context API for IP, hostname, MAC,
asset-key, and intent identity. The existing hosts-page substring search
continues to offer convenient discovery. The selected result supplies the
asset key for the context endpoint.

All new endpoints are authenticated and read-only. They return normalized
fields only; they must exclude credentials, raw SNMP values, full firewall
state, and internal database errors. Response lists remain bounded and
deterministically ordered.

## Collection and Reconciliation Design

One full `netctl collect all` is the collection boundary. On successful
completion, a single reconciliation sequence runs:

1. reconcile current switch topology;
2. reconcile asset attachments against that resulting topology;
3. publish the resulting common collection/reconciliation freshness markers.

The sequence is not triggered once per switch source. This avoids publishing
a card from a mixed collection cycle. A failed source must preserve its last
known authoritative current FDB; the reconciliation may use that retained
state and records source freshness for the operator.

Implement the primary trigger as a collection wrapper or collection-success
hook that invokes reconciliation only when `collect all` succeeds. Do not rely
on two independent five-minute timers for ordering. Keep
`netctl-reconcile.timer` enabled with its current five-minute/boot schedule as
a recovery mechanism; its executions use the same idempotent reconciliation
commands and must not contact network devices.

The deployment enables both timers only after backup, migration/compatibility
verification, and one manual read-only reconciliation proof. Any failure must
leave the last successful current topology and attachment resolutions intact.

## 30-Day Retention Design

Add an explicit Netctl retention command and a daily systemd timer. It
performs bounded, transactional deletion by cutoff timestamp and produces
aggregate counts only.

Rows eligible for deletion after 30 days include:

- `host_observations`;
- `network_events` and old collection-run records;
- `switch_fdb_events` and stale switch-collection runs;
- `asset_attachment_events` and superseded correlation-run records.

The job never deletes current state, including current FDB, current ports,
current VLAN/LLDP/STP state, current topology links, current attachment
resolutions, active assets/interfaces, or current IP/hostname observations.
It also retains each run referenced by current state and the most recent
successful run for every source and reconciliation type, even when older than
the cutoff. Deletion order removes dependent expired events before now-unused
run rows so foreign-key constraints remain valid.

Retention is separate from SQLite compaction. Daily deletion limits logical
growth and runs without a full database rewrite. To reclaim the existing disk
space, provide a one-time, operator-approved maintenance runbook: verify free
space, stop dependent services, create and verify a SQLite backup, compact
into a replacement database, validate integrity and aggregate counts, then
restore services. It has an explicit rollback to the backup.

## Error Handling and Observability

- Failed collection: do not run the collection-success reconciliation hook;
  preserve current switch state and surface freshness.
- Failed reconciliation: leave its prior current topology/attachment state
  unchanged; record a sanitized failure and show stale status on the card.
- Retention failure: make no partial deletion visible; leave the daily job
  failed and report aggregate failure metadata.
- Missing attachment fields or unknown port metadata: render `not available`,
  never fail the whole card.
- The dashboard and card expose last collection and last reconciliation times,
  along with source health.

## Verification

Automated tests cover:

- IP/hostname/MAC search, duplicate matches, and asset selection;
- confirmed, ambiguous, uplink-only, and unresolved card payloads;
- port/switch presentation data and bounded same-port device output;
- no secret or raw-collection fields in API responses;
- collection-success ordering and no reconciliation after failed collection;
- timer unit contracts and idempotent recovery reconciliation;
- 30-day retention cutoff, foreign-key protection of current-state runs,
  transactional rollback, and aggregate retention reporting;
- web rendering for all attachment states and stale freshness.

Deployment verification includes a database backup, integrity check, dry-run
retention counts, one manual collection/reconciliation cycle, source-health
review, card/API smoke tests, and confirmation that both collection and
reconciliation timers are active. No network-device write is part of
verification.

## Acceptance Criteria

- An operator can locate a known device by IP or hostname and open its card.
- A confirmed attachment displays the correct switch and port metadata from
  the current FDB-derived resolution.
- An ambiguous, uplink-only, or unresolved device clearly communicates why no
  definitive port is displayed.
- Card freshness comes from a completed collection/reconciliation boundary.
- Reconciliation runs automatically after successful collection and survives
  reboot through the enabled recovery timer.
- Historical operational records are limited to 30 days while current state
  remains queryable.
- The retention job has a dry run, audit summary, safety tests, deployment
  checks, and a documented database-compaction rollback path.
