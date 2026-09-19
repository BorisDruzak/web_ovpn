# Inventory ↔ Endpoint Platform Design

## Goal

Make the Inventory domain the canonical owner of the durable relation between a
physical `InventoryAsset` PC and an Endpoint Platform Device. It exposes one
local, provenance-aware asset context for Inventory, service consumers, and a
safe Network Observer compatibility projection.

This change is entirely in `web_ovpn`. Endpoint Platform remains an external
authoritative service. Its service client is provisioned administratively in
that service and is never created, modified, or stored by this repository.

## Hard boundaries

The only permitted integration is:

```text
Endpoint Agent -- WSS --> Endpoint Platform -- HTTPS published SDK --> web_ovpn
```

`EndpointPlatformServiceClient` and `EndpointContextAdapter` remain the sole
boundary. Inventory must not add an HTTP client or use `requests`/`httpx`
against Endpoint; open Agent WSS; import Endpoint server or Agent runtime;
read a device credential; or access an Endpoint database.

All new persistence uses the `inventory_` namespace. Existing OpenVPN,
Netctl, Network Observer, `network_hosts`, and runtime-asset semantics remain
unchanged. `EndpointAgentNetworkLink` becomes a derived read cache, not a
second authority.

## External contract and prerequisite

The published immutable `endpoint-platform-client` 0.2.0 SDK supplies the
provider contract: device listing, safe agent network identities, latest safe
context for `baseline_v1`, `health_v1`, `network_v1`, `inventory_v1`, and
`session_v1`, plus idempotent context collection requests. `inventory_v1`
contains bounded hardware, memory, physical storage and interface projections;
`session_v1` contains only the current login, interactive-session state and
collection time. The release lock fixes the exact wheel and SHA-256.
Endpoint Platform administration must create a distinct `web_ovpn` service
client with exactly:

```text
devices.read
context.read
context.collect
```

No `operations.*`, `modules.*`, `provisioning.*`, or other capability is
allowed. `context.collect` is required for the explicit agent-refresh action.

The administrative hand-off records the service-client identity, exact scopes,
an immutable released SDK wheel, its version/SHA-256, and a safe approved smoke
Device UUID. If a required scope, artifact, SDK call, or public API is absent,
the feature stays disabled. The repository records a precise
`endpoint_platform` follow-up naming that missing public contract; it never
uses a direct HTTP, database, or Agent workaround.

## Canonical data model

### Binding history

Add `inventory_external_bindings`:

| Field | Purpose |
| --- | --- |
| `id` | Inventory UUID. |
| `asset_id` | FK to `inventory_assets`; must be a PC. |
| `source` | Initially `endpoint_platform`. |
| `external_id` | Opaque Endpoint Device UUID stored as a string; never interpreted. |
| `status` | `candidate`, `confirmed`, `rejected`, `replaced`, or `ended`. |
| `binding_method` | `mac_exact`, `serial_exact`, `product_uuid_exact`, or `manual`. |
| `confidence` | Bounded matching score; manual confirmation is explicit rather than inferred. |
| `evidence_json` | Bounded allow-listed match explanation and timestamps. |
| `first_seen_at`, `last_verified_at`, `ended_at` | UTC lifecycle. |
| `created_by`, `created_at`, `updated_at` | Audit metadata. |

The table preserves history. Partial unique indexes enforce one active
confirmed binding for an Endpoint UUID and one for a PC:
`(source, external_id)` and `(asset_id, source)`, respectively, where
`status = 'confirmed' AND ended_at IS NULL`. An active-candidate
de-duplication index on `(asset_id, source, external_id)` prevents polling
spam. Service validation and a database constraint reject non-PC bindings.

Rebinding ends the old confirmed row as `replaced` or `ended`, then confirms
the new UUID in the same transaction. It never recreates the physical asset.
Detach ends only the relation; it never deletes source observations, an
Endpoint Device, Inventory relations, or manual data.

### Current Endpoint state and observations

Add `inventory_endpoint_state`, one row per binding, carrying the binding,
asset, and Endpoint Device UUID. It deliberately does not share a row with
binding history. Its allow-listed state is:

```text
online, last_seen_at, agent_version,
baseline_snapshot_id, health_snapshot_id, network_snapshot_id,
inventory_snapshot_id, session_snapshot_id,
baseline_semantic_hash, health_semantic_hash, network_semantic_hash,
inventory_semantic_hash, session_semantic_hash,
last_checked_at, refreshed_at, last_success_at, unavailable_since,
safe_context_json
```

`safe_context_json` is normalized, not a raw Endpoint payload. It contains
only display/fusion fields: OS/build, hostname, CPU, RAM, storage,
manufacturer/model, technical serial/product-UUID evidence, current OS user,
agent version, online/last-seen data, and card-safe network identifiers. It
excludes tokens, diagnostics, arbitrary payload fields, and Helpdesk data.

Extend `InventoryObservationSource` with `ENDPOINT`. An Endpoint observation
holds its binding/device reference, profile, snapshot ID, semantic hash,
collection time, and the same allow-listed projection. It is created only when
a profile semantic hash changes. Same-hash polling changes freshness fields,
not historical observations.

Add the singleton `inventory_endpoint_sync_control`, containing the worker
lease, last successful presence/full sync, last safe error code, and last
reconciliation request. A failed worker never clears a confirmed binding,
Endpoint state, or observation.

## Authority, effective view, and discrepancies

Manual Inventory remains authoritative for location, inventory number,
assigned person, asset status, photos, relations, notes, and a physically
verified serial. Endpoint is preferred for dynamic OS, CPU, RAM, storage,
hostname, current OS user, agent status/version, and last-seen data. Netctl
remains its existing network-derived source.

The local effective projection returns `value`, `source`, and
`observed_at` per field; it does not mutate manual data. It emits comparable
discrepancies initially for RAM and serial. Location and assigned person never
receive Endpoint replacement actions.

CSRF-protected, audited dispositions are:

- **Accept Endpoint**: copy an explicitly allowed resolved value into manual
  data only after user confirmation.
- **Keep manual**: retain both values and record the decision.
- **Mark verified**: record a physical verification without replacing either.

The UI always distinguishes Inventory's assigned person from Endpoint's
current OS user.

## Correlation and lifecycle

The existing `app/endpoint_agent_network.py` exact-MAC logic remains a
bootstrap input, but Inventory owns the durable outcome. The worker correlates
current Inventory PC identifiers and published Endpoint identities using exact
normalized MAC, exact physical serial, or exact product UUID. IP, hostname,
display name, and username cannot auto-bind; hostname is only explanatory
secondary evidence.

Only an exact one-PC/one-Endpoint/no-conflict MAC match may automatically
create a confirmed `mac_exact` binding. Duplicate MACs on either side remain
ambiguous candidates. Serial and product UUID exact matches are candidates for
manual confirmation in the first release. Rejected candidates are historical
and are not recreated until matching evidence changes materially.

After confirmation, the Endpoint UUID is the stable reference. Worker refreshes
read that UUID; it does not re-decide the relationship from MAC. Discovery
re-runs only for unbound PCs or ended/replaced bindings. Manual confirmation
revalidates PC type, candidate freshness, and both uniqueness conditions.
Replacement ends the old UUID before confirming the new UUID atomically.

## Worker and Network Observer projection

Add `inventory-endpoint-sync.service` and
`inventory-endpoint-sync.timer`. It runs once a minute for
presence/freshness, with a full bounded profile pass at most every five
minutes. Inventory renders and local context API reads never perform a remote
Endpoint sync.

The worker:

1. acquires the Inventory lease or exits successfully;
2. lists safe identities through `EndpointContextAdapter` and reconciles
   only unbound or changed candidates;
3. reads safe current profiles for confirmed bindings;
4. persists allow-listed current state and hash-deduplicated observations;
5. derives Network Observer's compatibility cache from confirmed binding/state
   and forwards only agent presence, OS family, and device type through the
   existing Netctl `fingerprint agent-evidence-sync` boundary;
6. persists redacted result/freshness and releases the lease.

All five published profiles are read on the bounded full pass. Missing optional
snapshots become a per-profile unavailable state, not a binding failure. The
rich inventory and session profiles enrich effective technical values and never
overwrite manual Inventory authority.

**Refresh agent data** calls the existing adapter's `request_collection` with
a server-generated idempotency key and safe profile. It returns request status;
only the worker writes the resulting state/observation.

`EndpointAgentNetworkLink` is rebuilt only from confirmed Inventory bindings
and safe state. Migration re-evaluates current PC MACs against current
published identities. A historical MAC-only cache row cannot alone auto-confirm
because it intentionally retains no MAC evidence. The exact current one-to-one
rule may confirm; every other case is candidate/ambiguous. Rollback disables
the new timer and leaves the old cache readable without deleting new history.

## Local API and UI

Use existing API authentication, session CSRF, and audit conventions.

| Endpoint | Local behavior |
| --- | --- |
| `GET /api/v1/inventory/assets/{id}/context` | Asset, location, related devices, manual/Netctl/Endpoint sources, effective values, discrepancies, provenance, and freshness; no upstream call. |
| `GET /api/v1/inventory/by-endpoint/{endpoint_device_uuid}` | Service lookup only for an active confirmed binding. |
| `GET /api/v1/inventory/assets/{id}/endpoint-candidates` | Persisted bounded candidates/evidence. |
| `POST .../endpoint-bindings/{binding_id}/confirm` | Confirm an eligible candidate. |
| `POST .../endpoint-bindings/{binding_id}/reject` | Reject candidate. |
| `POST .../endpoint-bindings/{binding_id}/detach` | End active binding without deletion. |
| `POST .../endpoint-refresh` | Request a safe SDK collection; worker later persists result. |
| `POST .../discrepancies/{field}/resolve` | Apply an explicit allowed disposition. |

The PC card reads local data and shows agent status, last successful Endpoint
refresh, agent version, OS/CPU/RAM/storage, hostname, network provenance,
current OS user, assigned person, related devices, and discrepancies. For an
outage it shows that Endpoint is temporarily unavailable plus the last
successful update. Other asset types expose no Endpoint binding actions.

## Deployment and smoke gate

Add to `.env.example` and protected production environment:

```text
ENDPOINT_PLATFORM_ENABLED=0
ENDPOINT_PLATFORM_BASE_URL=https://endpoint.sosnadmin.local
ENDPOINT_PLATFORM_TOKEN_FILE=/etc/openvpn-web/endpoint-platform.token
ENDPOINT_PLATFORM_CA_FILE=/etc/openvpn-web/endpoint-platform-ca.pem
ENDPOINT_PLATFORM_TIMEOUT_SECONDS=5
ENDPOINT_PLATFORM_SMOKE_DEVICE_ID=<approved UUID>
```

The smoke UUID is required when enabling production integration, because an
actual collection request is the only reliable proof of `context.collect`.
The token is provisioned outside Git as `root:openvpn-web`, mode `0640` (or
equivalent minimum ACL); the CA is root-managed and read-only. No secrets,
private CA material, or device credentials enter Git.

The installer consumes an immutable versioned SDK wheel and committed lock
manifest containing distribution version and SHA-256. It checks the digest,
installs via `pip --no-index --no-deps`, verifies installed version and
`import endpoint_platform_client`, and rejects moving branches, editable
installs, and source checkouts. A released wheel/digest is an external
prerequisite: no such artifact means feature disabled, never an unpinned
substitute.

Before enabling the flag or timer, a verifier running as `openvpn-web` checks
the lock/import, token and CA readability, TLS construction with CA validation,
`list_devices` for `devices.read`, safe identity/current-context reads for
`context.read`, and an idempotent approved-device `baseline_v1` collection
for `context.collect`. It reports only redacted errors. Bad TLS, redirect,
missing/mismatched SDK, missing files, or denied scope fails closed: timer
remains disabled while manual Inventory and Netctl remain usable.

The installer writes the systemd units, runs `daemon-reload`, and enables the
timer only after verifier exit zero. Rollback sets the flag to zero and disables
the timer while preserving local binding/state history; re-enable repeats the
smoke gate.

## Verification and acceptance

Tests must prove:

- no Agent WSS route/import, direct Endpoint HTTP, Endpoint DB access, Agent
  runtime import, or device credential handling;
- only existing client/adapter creates SDK calls, with CA verification, no
  redirects, bounded timeout, redacted errors, and fail-closed denied scopes;
- installer/verifier lock/hash/version/import/permission/API checks and timer
  refusal for every failed condition;
- binding one-to-one MAC auto-confirm, duplicate ambiguity, IP/hostname
  no-bind, serial/product UUID candidates, manual lifecycle, uniqueness, and
  replacement history;
- lease exclusion, local-only render, profile fallback, same-hash freshness,
  changed-hash observation, outage/scope-denial cache preservation, and safe
  Netctl projection;
- API/UI provenance, freshness, active-confirmed UUID lookup, mutation
  CSRF/audit, discrepancy actions, stale presentation, and non-PC exclusion;
- existing Inventory, Netctl, Network Observer, and compatibility tests.

Production deployment is separate. Its acceptance evidence includes the pinned
wheel manifest/SHA-256, redacted verifier result, service file permissions,
database backup before migration, active timer/journal, and live read-only card
verification. Browser acceptance is distinct from service or curl health.

External blockers are limited to no immutable SDK release, no exact-scope
service client, no approved smoke device, or a missing public SDK/API contract.
Each blocks feature enablement only: manual Inventory, Netctl, and last known
Endpoint state continue to work.
