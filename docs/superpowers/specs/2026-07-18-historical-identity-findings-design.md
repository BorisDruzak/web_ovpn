# Historical identity findings acknowledgement

## Purpose

Migration 3 preserved legacy identity conflicts as
`historical_identity_conflict` findings.  They are provenance for the
identity migration, not an operational incident queue.  The existing database
contains a large reviewed set of findings with keys beginning
`legacy-identity-conflict:`.

Migration 4 will remove that reviewed legacy set from the operational inbox
without deleting rows, evidence, or timestamps.

## Chosen policy

- Migration 4 changes `open` findings to `acknowledged` only when both
  conditions hold:
  - `finding_type = 'historical_identity_conflict'`; and
  - `finding_key` begins with `legacy-identity-conflict:`.
- It leaves `first_seen_at`, `last_seen_at`, `details_json`, asset and source
  references unchanged.  The schema-migration ledger is the auditable record
  of the bulk acknowledgement.
- The existing read-only findings command keeps its `open` default.  After
  migration its normal operational result contains current MAC collisions and
  unresolved IP-only observations, not legacy migration provenance.
- New IP-move findings use the `ip-moved:` prefix and remain `open` when they
  are first observed.  They are deliberately outside this migration's scope.
- `mac_identity_collision` and `unresolved_ip_only_runtime` are untouched.
- No finding or runtime observation is physically deleted or rewritten beyond
  the lifecycle status transition above.

## Alternatives rejected

1. A direct production SQL update is faster but is not reproducible on a
   restored database and gives no migration-ledger evidence.
2. Marking every historical conflict `resolved` makes reviewed provenance look
   automatically remediated and would also hide future IP-move signals.

## Implementation and verification

1. Add migration version 4 after migration 3.  It must use the current
   migration transaction/savepoint mechanism and be idempotent through the
   schema ledger.
2. Add migration tests proving the exact legacy subset is acknowledged,
   future `ip-moved:` historical conflicts remain open, other finding types
   remain open, and a failed migration rolls back atomically.
3. Update the readiness and backup/rollback documentation with before/after
   status queries.  The production operation takes a backup, applies the
   normal migration path, and verifies that acknowledged provenance remains
   queryable while the open inbox is small.
4. Run focused migration/runtime tests and the complete pytest suite before
   deployment.  A separate review verifies the migration predicate and the
   no-delete boundary.

## Non-goals

- Adding a generic operator acknowledgement UI or audit actor field.
- Paginating every historical findings query.
- Resolving MAC collisions or IP-only observations.
- Changing collection, intent import, network devices, or network topology.
