# Review — runtime asset identity implementation plan

Reviewed commit: `1375024546dfe2c9c7fd5eb631a90762f50e0d40`

Status: **design changes required before implementation**

The overall direction is correct: additive migration 2, separate runtime assets and Git intent, preservation of legacy reads, non-unique runtime IP observations, WAL/busy timeout, rollback testing, and no live-device changes.

The following contracts must be corrected before Task 1 starts.

## Critical 1 — multi-interface migration contradicts the identity rule

The plan defines:

```text
valid MAC -> asset_key = mac:<MAC>
```

Therefore two legacy rows with two different MAC addresses deterministically create two different assets. Task 3 nevertheless requires two distinct MAC-bearing legacy rows to become two interfaces of one asset. There is no reliable legacy grouping key that proves those MACs belong to one device.

Required decision for PR 2A:

```text
- migration creates one runtime asset per normalized MAC;
- the schema supports multiple interfaces per asset;
- migration does not infer that different MACs belong to one asset;
- multi-interface capability is tested by explicit runtime inserts/helpers;
- later correlation/merge work may join assets only from explicit evidence or operator confirmation.
```

Do not merge by hostname, display name, IP, or proximity during migration.

## Critical 2 — nullable source IDs defeat the proposed UNIQUE constraints

SQLite treats NULL values as distinct in UNIQUE constraints. These definitions permit duplicate rows when `source_id IS NULL`:

```sql
UNIQUE(asset_id, ip, source_id, observation_source)
UNIQUE(asset_id, hostname, source_id, source_type)
```

Required correction: add a non-null deterministic source identity, for example:

```sql
source_key TEXT NOT NULL
UNIQUE(asset_id, ip, source_key, observation_source)
UNIQUE(asset_id, hostname, source_key, source_type)
```

Suggested values:

```text
network-source:<id>
legacy-network-host:<host-id>
legacy-host-observation:<observation-id>
unknown
```

`source_id` may remain nullable as an optional FK, but must not be the sole deduplication component.

## Critical 3 — asset-intent binding points to a revision-scoped row

`intent_assets.id` identifies one row in one imported revision. A binding to that row becomes tied to an obsolete snapshot after the next context import.

Required correction: bind runtime assets to stable intent identity, not a revision row. Recommended PR 2A shape:

```sql
context_id TEXT NOT NULL,
intent_stable_id TEXT NOT NULL,
last_verified_context_revision_id INTEGER REFERENCES context_revisions(id),
UNIQUE(asset_id, context_id, intent_stable_id, binding_source)
```

Application validation can confirm that `(context_id, intent_stable_id)` exists in the active `intent_assets` snapshot. An alternative is a separate stable intent-identity registry, but that is more scope than PR 2A requires.

## Important 1 — deterministic conflict policy is missing

Several legacy rows may map to the same MAC asset but contain different:

```text
kind/category
status
site
display_name
comment
evidence
first_seen_at
last_seen_at
```

Define one deterministic policy. Recommended:

```text
first_seen_at = minimum non-empty legacy value
last_seen_at  = maximum non-empty legacy value
representative row = greatest (effective_last_seen, legacy id)
kind/status/site/display_name/comment = representative row with documented fallbacks
evidence = normalized union of all mapped rows
```

For NULL timestamps:

```text
first = first_seen_at or last_seen_at or migration_time
last  = last_seen_at or first_seen_at or migration_time
```

Without this contract, iteration order silently determines runtime data.

## Important 2 — manual tag mapping must cover both key types

Current tag keys are generated as either:

```text
mac:<NORMALIZED_MAC>
ip:<NORMALIZED_IP>
```

Migration rules must state:

```text
mac key -> asset_key mac:<MAC>
ip key  -> asset mapped from the matching legacy network_hosts.ip
unmatched key -> preserve in an unresolved_tag_keys_json report field
```

The current migration report only accounts for unresolved host IDs, so it cannot prove that all manual tags were preserved.

## Important 3 — historical source references may be orphaned

Historical `host_observations.source_id` values must be copied only when the referenced `network_sources` row exists; otherwise store `source_id = NULL` and retain a deterministic `source_key` derived from the observation ID/type.

Enabling foreign keys during migration can otherwise turn previously tolerated orphan data into a migration failure.

## Important 4 — `asset_key = mac:<MAC>` is a migration seed, not permanent ownership identity

Document that a MAC-derived asset key is the deterministic initial runtime key. NIC replacement, explicit asset merges, and multi-interface ownership will require later alias/merge semantics. PR 2A must not claim that MAC is a permanent organizational asset identity.

## Required test changes

Replace the contradictory migration test with:

```text
- same MAC + changed IP -> one asset, one MAC interface, multiple IP observations;
- different MACs -> separate migrated assets;
- schema/helper test proves one asset can hold multiple explicitly inserted interfaces;
- NULL source_id does not permit duplicate observations;
- binding survives context head changes because it uses stable intent ID;
- conflicting same-MAC legacy rows produce deterministic aggregate fields;
- mac: and ip: manual tags are both migrated or reported unresolved;
- orphan observation source_id is safely normalized.
```

Implementation should not start until the plan and Issue #7 acceptance criteria reflect these decisions.
