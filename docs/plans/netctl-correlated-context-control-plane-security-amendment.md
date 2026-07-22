# Netctl Correlated Context and Safe Control Plane — Security Amendment

> This amendment is mandatory for [`netctl-correlated-context-control-plane.md`](netctl-correlated-context-control-plane.md). It refines the implementation requirements for PR 4A through PR 6C; it does not authorize any device write.

**Goal:** Make the proposed asset-level Internet policy safe against forged local requests, stale identity data, replay, audit tampering, and unsafe production migrations.

**Scope:** This document adds acceptance gates and implementation details. It does not change the plan's separation of observations, correlations, desired state, and executed changes.

## 1. Broker trust boundary

`netopsctld` must treat every field in its JSON payload as untrusted, including `actor`, user name, scope, plan ID, and RouterOS target. A Unix socket alone proves only the local process identity; it cannot establish which human initiated a web request.

### 1.1 Authenticate the local caller

The broker accepts requests only on Unix sockets and obtains `PID`, `UID`, and `GID` for every accepted connection with `SO_PEERCRED` before parsing the payload.

The normal web socket remains:

```text
/run/netopsctl/netopsctl.sock
owner: netopsctl
group: openvpn-web
mode: 0660
```

The broker maps the peer UID to an allow-listed service principal. At minimum it accepts the dedicated `openvpn-web` service UID; it rejects every other UID before JSON decoding. The reconciler uses a separate socket or a separate explicitly allow-listed service UID so that it has only its reconciliation scopes.

The audit record distinguishes the authenticated peer from the authorized subject:

```text
authenticated_peer:
  uid, gid, pid, service_principal

authorized_subject:
  principal_type, principal_id, principal_name, session_id, authorization_id
```

The broker must never record an unauthenticated `actor=...` value as an authorization fact.

### 1.2 Carry human authorization in a signed envelope

After session/RBAC validation, the web application creates and signs this canonical JSON envelope with its Ed25519 private key:

```json
{
  "authorization_version": 1,
  "action": "plan.apply",
  "principal_type": "web_user",
  "principal_id": "42",
  "principal_name": "admin-2",
  "session_id": "01J...",
  "authorization_id": "01J...",
  "scopes": ["network.plan.apply"],
  "plan_id": "01J...",
  "plan_digest": "sha256:...",
  "issued_at": "2026-07-22T08:00:00Z",
  "expires_at": "2026-07-22T08:02:00Z",
  "nonce": "..."
}
```

For `plan.create`, no plan exists yet: the envelope instead includes `action: "plan.create"` and `request_digest`, calculated from the canonical create request. The broker creates the plan and returns its immutable ID and digest. Every later approve/apply/verify/rollback envelope binds the exact `plan_id` and `plan_digest` shown above. The wire protocol carries the envelope and detached signature, not a trusted free-form `actor` field. The broker stores only the corresponding public key. Private keys for the web app and audit signer are loaded with `systemd LoadCredential=`; they must not be in JSON, SQLite, or an ordinary environment file.

At request time the broker validates, in this order:

1. Unix peer UID and its service-principal mapping.
2. The public key registered for that UID.
3. Envelope schema, canonical encoding, Ed25519 signature, and expiry.
4. Required scope for the exact action.
5. For `plan.create`, `request_digest` against the canonical request; otherwise `plan_id` and `plan_digest` against the persisted immutable plan.
6. A single-use nonce recorded transactionally before the action starts.

Replayed, expired, mismatched, malformed, or unknown-key envelopes are denied and audited. API-token callers use a registered `api_principal_id` and the same signed-envelope model; an arbitrary client header is never an identity.

### 1.3 Required broker tests

PR 6A must add tests that reject an unknown peer UID before payload parsing, a valid signature from the wrong UID, an expired envelope, a reused nonce, a wrong plan digest, an omitted scope, and a forged JSON `actor`. It must also prove that reconciler credentials cannot invoke web-only plan approval or apply actions.

## 2. Plan basis, TOCTOU, and IP reuse

The broker, not the web app, resolves an asset to current IP observations and enforcement points. It performs that resolution twice: at plan creation and immediately before apply.

### 2.1 Immutable plan basis

At creation, the broker reads `netctl.sqlite` read-only and canonicalizes the exact evidence used for a plan. The basis includes:

```text
active context head: ID, revision ID, SHA-256
asset: internal ID, stable key, retired/provisional state, update marker
interfaces: IDs and MACs
current IP observations: IDs, IPs, source IDs, first/last seen, current state
attachment: resolution ID, correlation run, state
enforcement: source ID, device identity, address-list name, anchor fingerprint
```

The broker stores `plan_basis_hash = SHA256(canonical_json(basis))` with the plan. Defaults are a five-minute plan TTL, a maximum fifteen-minute TTL, and a fifteen-minute maximum identity-observation age. The thresholds are configuration values and must be tested at their boundaries.

The web creation request contains only a stable subject and desired policy:

```json
{
  "subject_type": "asset",
  "subject_key": "mac:AA:BB:CC:DD:EE:FF",
  "policy": "internet_access",
  "desired_state": "deny",
  "reason": "approved support request"
}
```

It never sends an IP list, RouterOS path, or firewall command.

### 2.2 Revalidate before apply

Immediately before any RouterOS write, the broker rereads `netctl.sqlite` and the target RouterOS device. Apply is allowed only when all of these remain true:

- the plan is within TTL and the active context head is unchanged;
- the asset exists, is non-provisional and non-retired, with no open MAC identity collision;
- its MAC set is unchanged;
- every planned IP is still current, sufficiently fresh, uniquely bound to the same asset/interface, and not a duplicate current IP;
- attachment evidence is not ambiguous or conflicting;
- the enforcement source and address-list contract are unchanged;
- exactly one firewall anchor exists and its fingerprint matches the plan.

Any difference produces this terminal pre-write result; the old approved plan is never silently adapted to a new IP:

```json
{
  "status": "stale_precondition",
  "replan_required": true,
  "changed_preconditions": ["ip_observations", "firewall_anchor_fingerprint"]
}
```

The status transition and audit event are durable. The caller must create and approve a new plan.

### 2.3 RouterOS write boundary

There is one active apply or rollback per enforcement device. The firewall anchor is not identified by comment alone. Its fingerprint includes `chain`, `action`, `src-address-list`, `out-interface-list`, `disabled`, `log`, relative placement beside fixed anchors, and one unique managed comment:

```text
web_ovpn:internet-policy-anchor:v1
```

Every managed address-list member has an ownership comment:

```text
web_ovpn:policy:<policy-id>:asset:<asset-id>
```

Rollback may remove only entries with that exact ownership marker, never another entry merely because it has the same IP address.

After a successful deny, an IP change is handled only by the reconciler: retain the previous managed deny entry, add the new confirmed entry, verify it, and only then remove the old entry. Ambiguous identity opens `policy_stale_identity` and never restores Internet access automatically.

### 2.4 Required lifecycle tests

PR 6B must prove that changed context head, expired plan, stale observation, IP reassignment, duplicate current IP, ambiguous attachment, changed anchor, and concurrent writes all reject apply without RouterOS mutation. It must prove the new-IP reconciler order and ownership-scoped rollback.

## 3. Tamper-evident audit and production gate

Application-level immutability is insufficient for audit evidence. `netopsctl` must add an append-only `audit_events` table. The application cannot update or delete it; SQLite triggers abort `UPDATE` and `DELETE` attempts.

Every event contains a monotonically allocated sequence, event ID, event type, timestamp, canonical payload hash, previous hash, event hash, signer key ID, and Ed25519 signature. The event hash is calculated from the sequence, previous hash, payload hash, event type, and timestamp. Key rotation is itself an `audit_key_rotated` event.

`netopsctl audit verify` must reject sequence gaps, bad previous hashes, bad event hashes, invalid signatures, and invalid key transitions.

The service periodically sends a minimal signed checkpoint to an independent sink:

```json
{
  "instance_id": "sosn-netopsctl",
  "last_sequence": 1821,
  "chain_head": "sha256:...",
  "key_id": "audit-2026-01",
  "created_at": "...",
  "signature": "..."
}
```

Acceptable sinks are remote syslog over TLS, an append-only file on a separate server, PBS/NAS with separate credentials, or immutable object storage. GitHub is not an audit sink and must not receive a production token or operational audit data.

Until checkpoint delivery and verification are configured in production, create and dry-run may operate but production apply and rollback are disabled. Local signed chains are adequate for development only.

## 4. API contract before PR 4A

All new read endpoints use `/api/v1/context/...`; all control endpoints use `/api/v1/network-changes/...`. Adding optional fields or endpoints is compatible in v1. Removing/renaming fields, changing enum values, or changing field semantics requires v2. A deprecated version remains available for at least 90 days or two production release cycles, whichever is longer.

Read responses use a stable envelope:

```json
{
  "api_version": "1.0",
  "request_id": "01J...",
  "generated_at": "2026-07-22T08:00:00Z",
  "snapshot": {
    "context_revision_id": 7,
    "correlation_run_id": 91,
    "observation_cutoff": "2026-07-22T07:59:00Z"
  },
  "data": [],
  "pagination": {"limit": 100, "next_cursor": "...", "has_more": true},
  "errors": []
}
```

Collections use opaque, signed cursor pagination, never offsets. A cursor binds the snapshot/correlation run, sort timestamp, stable numeric ID, filters, and expiry. Default/max limits are 100/500; search is capped at 50. Asset contexts use ETags derived from context revision, correlation run, asset update marker, and finding update marker.

Topology queries are bounded rather than conventionally paginated: default/max depth is 3/8 and default/max node count is 250/1000. A bounded result reports `truncated: true` and a stable `truncation_reason`.

Every create, approve, apply, verify, and rollback request requires an `Idempotency-Key`. Plans include `plan_schema_version`, `authorization_version`, and `operation_version`. Apply accepts only `plan_id`, `plan_digest`, and a valid authorization envelope.

PR 4A must first add contract tests for version compatibility, response snapshots, cursor tampering/expiry/filter mismatch, topology bounds, ETags, and idempotency. PR 4C implements the read portion; PR 6A/6B implement the control portion.

## 5. Backup and rollback gate before migration 9

Before PR 4A is deployed, add `docs/runbooks/netctl-correlation-backup-rollback.md` and validate it against a copy of production data:

1. Create an online SQLite backup through the SQLite backup API.
2. Apply migration 9 to the copy and verify ledger `1..9` and `PRAGMA integrity_check`.
3. Compare existing runtime, intent, and switch counts.
4. Run topology reconciliation only against synthetic or copied data.
5. Restore the pre-migration copy and prove ledger `1..8` plus integrity.

The production runbook sequence is: disable `netctl-collect.timer`; wait for the collector and `CollectLock`; stop `openvpn-web.service`; record the deployed SHA; make and hash the SQLite backup; verify it; deploy the new application tree; apply migration 9; verify ledger, integrity, and old-table counts; run read-only topology smoke checks; start the web service; enable the timer; run API/CLI smoke checks. OpenVPN remains running.

Rollback disables the timer, stops the web service, restores both the previous application tree and the SQLite backup by atomic rename, verifies ledger `1..8` and integrity, then starts the service and timer and checks runtime assets, switches, and context status. Never delete migration ledger rows, drop new tables manually, or run old code with a partially changed database.

## 6. PR acceptance mapping

| Delivery | Additional non-negotiable acceptance |
| --- | --- |
| Pre-PR 4A | Versioned API contract tests and validated backup/rollback runbook exist. |
| PR 4A–4C | Read APIs return a pinned snapshot, signed cursors, bounds, and no control capability. |
| PR 6A | Peer UID mapping, signed envelopes, nonce replay protection, scope binding, and append-only signed audit work. |
| PR 6B | Basis hash and all stale-precondition checks run immediately before device writes; device mutex and ownership-scoped rollback work. |
| PR 6C | User policy resolution preserves the same signed subject-to-asset audit chain and cannot bypass asset eligibility. |
| Production enablement | Independent audit checkpoint is healthy; otherwise writes remain disabled. |
