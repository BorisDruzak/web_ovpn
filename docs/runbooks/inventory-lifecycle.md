# Historical inventory deletion

Deleting a card moves it to «Удалённые». The operation keeps its ID, manual facts,
identifiers, photos, observations and checks. It records the author, time and reason.
Peripheral cards stay in their locations. Workplace relations and local external
bindings end in the same database transaction. No Netctl, Endpoint, agent or VPN
command is issued, and no external device is deleted.

Restoration returns the same card. Ended relationships remain historical; confirm
new relationships separately after checking conflicts. A missing location prevents
restoration with a clear error and leaves the deleted record intact. Repeated
delete/restore requests do not change attribution, facts or somebody else's binding.

Ordinary ORM reads and counts exclude deleted cards and their identifiers, including
direct card URLs and matching/sync consumers. Privileged history reads explicitly
opt in. Ordinary photo URLs cannot expose deleted-card files; the historical HTML
photo route requires `inventory:delete` and verifies the asset/photo pair. Historical
pages and APIs require the same permission. A reader or inventory editor receives
403 there. Historical access does not grant network/provider administration.

Individual photo deletion serializes with card lifecycle before changing its row.
It unlinks the file only after the row and audit commit, so database rollback keeps
the file. A late delete of a historical photo returns 409. If post-commit file
cleanup fails, the API reports `file_removed: false`; the unreferenced file remains
inaccessible. There is no automatic cleanup schedule in this change. Operators
must account for unreferenced files during authorized storage maintenance.

Browser deletion requires confirmation of the concrete card and a reason, CSRF and
the original manual revision. API DELETE `/api/v1/inventory/assets/{id}` now accepts
JSON `{ "expected_revision": REVISION, "reason": "Причина" }`. Missing revision is
428, stale revision 409. GET `/api/v1/inventory/deleted` lists at most 100 records
per page; GET `/api/v1/inventory/deleted/{id}` reads a deleted card. POST
`/api/v1/inventory/assets/{id}/restore` accepts `{ "expected_revision": REVISION }`.
Service credentials must explicitly include `inventory:delete`; legacy defaults do
not grant it. The capability remains separate from `inventory:write`.

SQLite initialization adds nullable lifecycle columns and a deletion-time index
without rebuilding cards. Default loader criteria protect asset/entity/column/count
reads. Database triggers reject late writes of deleted facts, identifiers, details,
observations, checks, photos and Endpoint cache, and active relations/bindings to
deleted assets. Conditional revision claims serialize deletion with edits. Ending
relations precedes marking the card deleted, within one transaction. No global
SQLite BEGIN hook is installed. Non-SQLite guard behavior has not been verified.

Before an authorized deployment, back up the database using SQLite's backup API
with a coherent snapshot and preserve the photo directory. Validate migration on a
copy, then deploy/restart all inventory readers and sync consumers together. Running
old code against this schema is unsafe: it does not understand tombstones and may
show or mutate deleted cards. A code-only downgrade is not a safe rollback; use a
coherent pre-migration database/photo backup under an explicit rollback procedure.
No production backup, migration or deployment has been performed in this work.

Synthetic tests verify a PC with two monitors and UPS, observation/detail retention,
same-ID restoration, ended relations, ordinary counts/URLs, ownership/capability and
CSRF gates, revision conflicts and idempotency, repeatable old-schema upgrade,
photo preservation and historical access, Netctl/Endpoint matching suppression,
reassigned Endpoint binding preservation, and simultaneous deletion/binding. Browser
script `tests/browser/inventory_lifecycle.js` exercises the actual delete/history/
restore flow against a loopback fixture. Export and future Netctl-specific bindings
must retain these lifecycle boundaries when their stages are implemented.
