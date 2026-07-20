# Context relation compatibility fix report

## Scope

Fix the `web_ovpn` context-import rejection of the canonical
`links[].relation: connected_to` value without changing production or the
`network_configuration` repository. Preserve rejection of relations outside
the explicit semantic allowlist.

## Root cause

The canonical schema accepts a non-empty relation string, and current
`network_configuration` content uses `connected_to`. The additional netctl
semantic contract still allowed only the original uppercase relation enum.
The queryable `intent_links.relation` SQLite column has the matching uppercase
`CHECK` constraint.

A real CLI reproduction against the checked-out canonical files returned five
deterministic semantic errors:

```text
links.0.relation: unsupported relation 'connected_to'
...
links.4.relation: unsupported relation 'connected_to'
```

The failure was therefore at the schema-to-semantic-contract boundary, before
intent snapshot materialisation.

## RED

Added
`test_canonical_connected_to_relation_validates_and_imports`. It changes both
fixture links to canonical `connected_to`, requires empty semantic errors,
imports the snapshot, checks the queryable relation column, and checks that the
active snapshot retains the canonical lowercase payload.

Before the implementation:

```text
FAILED tests/test_netctl_context_import.py::test_canonical_connected_to_relation_validates_and_imports
assert validate_import_semantics(document) == []
Left contains: unsupported relation 'connected_to'
```

## Minimal implementation

- Added the single explicit alias `connected_to -> CONNECTED_TO` to the
  semantic relation contract.
- Added `normalise_relation_type()` for the queryable SQLite relation column.
- Kept canonical JSON, canonical hash, and the active snapshot unchanged, so
  their relation remains `connected_to`.
- Did not broaden validation to arbitrary lowercase or unknown relations.
- Did not rebuild or alter the existing SQLite schema.

## GREEN and regression evidence

Focused relation and invalid-enum checks:

```text
11 passed in 0.55s
```

All context tests:

```text
71 passed in 2.21s
```

Full regression:

```text
212 passed, 1 skipped in 40.34s
```

The full run emitted only pre-existing deprecation warnings from pytest-asyncio,
FastAPI, Starlette routing, startup events, and templating.

## Independent observation

After the relation fix, a CLI probe against the older checked-out local
`network_configuration` worktree advanced past relation validation and then
reported `Object of type date is not JSON serializable` for unquoted YAML date
scalars. That is a separate canonicalisation concern and is intentionally not
changed by this scoped patch. The canonical repository and production were not
modified.
