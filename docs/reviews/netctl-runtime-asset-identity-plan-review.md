# Review — runtime asset identity implementation plan

Original reviewed commit: `1375024546dfe2c9c7fd5eb631a90762f50e0d40`

Status: **resolved by approved plan revision**

The original direction was correct, but implementation was blocked until the identity and migration contracts below were decided. The operator approved the conservative model and the implementation plan was revised accordingly in:

```text
docs/plans/netctl-runtime-asset-identity.md
```

## Approved decisions

### Different MAC addresses

```text
same normalized MAC + changed IP -> one asset
different MACs -> different assets
no valid MAC -> provisional asset per legacy host row
```

Different MACs are not merged automatically by IP, hostname, display name, site, location, or observation timing. The schema supports multiple interfaces per asset, but migration does not infer multi-interface ownership.

A future correlation phase may propose a candidate merge. Confirmation requires stronger identity evidence such as agent/SMBIOS UUID, serial/inventory identity, or an operator decision.

### MAC asset keys

`mac:<MAC>` is an initial deterministic migration seed, not a permanent organizational identity. Future NIC replacement and asset merge require explicit alias/merge history.

### Observation source identity

Nullable `source_id` is insufficient for deduplication in SQLite. Runtime IP and hostname observations now require:

```sql
source_key TEXT NOT NULL
```

The unique constraints use `source_key`; `source_id` remains optional provenance.

### Stable intent binding

Runtime assets bind to:

```text
context_id + intent_stable_id
```

They do not bind directly to revision-scoped `intent_assets.id`. `last_verified_context_revision_id` may record the latest verified snapshot.

### Same-MAC aggregation

Multiple legacy rows with one normalized MAC are aggregated deterministically:

```text
first_seen_at = minimum effective timestamp
last_seen_at = maximum effective timestamp
representative row = greatest (effective_last_seen, legacy_host_id)
evidence = normalized union
conflicting values = migration-report records
```

### Legacy tags

Both current key forms are handled:

```text
mac:<MAC>
ip:<IP>
```

Unmatched or malformed tag records are preserved in the migration report rather than discarded.

### Orphaned observations

Historical observations copy `source_id` only when the referenced source exists. Otherwise they retain deterministic provenance through `source_key` and store `source_id = NULL`.

## Required test outcomes

```text
same MAC + changed IP -> one asset
different MACs -> separate assets
one explicitly created asset can contain multiple interfaces
NULL source_id cannot create duplicate observations
stable intent binding survives context head changes
same-MAC conflicts aggregate deterministically
mac: and ip: manual tags migrate or are reported unresolved
orphan observation sources are normalized safely
failed migration rolls back completely
```

## Implementation gate

The architecture gate is now cleared. Implementation may begin only from the revised plan and updated Issue #7 acceptance criteria. RouterOS route-table persistence is separately tracked in Issue #8 and is not part of PR 2A.
