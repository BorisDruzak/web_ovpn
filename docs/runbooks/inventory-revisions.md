# Inventory manual revision contract

Each inventory asset response contains an integer `manual_revision`.
PATCH `/api/v1/inventory/assets/{id}` requires `expected_revision` from the card
that the editor actually loaded. Missing revisions return 428; stale revisions
return 409. Fetch the current card and compare the submitted values before retrying.
Do not blindly fetch a new revision and retry an old payload.

POST `/api/v1/inventory/relations` requires `parent_revision` and `child_revision`
in JSON. DELETE `/api/v1/inventory/relations/{id}` requires those two query values.
Both claims are in one transaction, ordered by asset ID. Failure rolls back both.
HTML cards carry the same original revision, retain it after conflict and compare
submitted values against the current facts. Repeated stale submission cannot win.

Compatibility intentionally changes: existing writers must supply the revision.
There is no unguarded legacy PATCH fallback. Read and create-card shapes remain
compatible with an added response field. A revision is opaque: consumers must not
assume an exact increment of one per user action.

For the existing SQLite deployment, a repeatable additive migration supplies a
default revision of 1 to old cards. Database triggers advance it for changed manual
asset fields, detail tables, manual identifiers and workplace relationships.
Observation inserts and telemetry timestamps do not advance manual revisions.
These SQLite triggers have not been verified on other database engines.

Server-owned drafts retain their original revision throughout reload and conflict.
Attaching a newly created peripheral checks its parent's captured revision before
writing the card or relation. Remaining lifecycle integration is tracked in the
execution plan: soft delete/restore and external binding actions must use the same
boundary. The complete T09 acceptance remains open until those paths are verified.

Endpoint binding confirm/reject/detach/reconnect POSTs require the integer
`X-Inventory-Revision` header from the displayed physical card. Missing headers
return 428, malformed values 422, stale values 409. CSRF and permission gates
still apply. The atomic revision claim, binding decision and audit share one
transaction; an audit failure rolls everything back. A successful response adds
the resulting `manual_revision` alongside the existing binding `data`.
The browser sends its captured revision, preserves any input entered during the
request, and starts a fresh draft after a successful decision only when no manual
input needs preserving. It does not replace an old draft's original revision.
Discrepancy decisions still use their comparison hash; integration with the
physical-card manual revision remains an OPEN T09 gate.
