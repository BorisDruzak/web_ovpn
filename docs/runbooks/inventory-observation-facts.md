# Inventory observation ownership (T09)

Manual edit operations own only MANUAL identifier rows. `sync_identifiers` defaults
to MANUAL ownership and rejects identifiers bearing another source. Explicit
create/workplace import paths accept the existing supported source payloads using
`owned_sources=set(InventoryObservationSource)`. Provider writers must explicitly
identify their owned sources; they must not use a manual edit to change ownership.
The source participates in the in-memory identity key. No schema migration is needed:
this table has no unique constraint excluding two sourced rows with the same value.

Netctl reconciliation matches distinct asset IDs by current MAC and rejects MACs
shared by multiple assets or duplicate snapshot hosts. It retires/replaces only
NETCTL IP/hostname rows. Equal-value observations update NETCTL last_seen_at and
never convert or change MANUAL rows, including their timestamps and current flags.
Missing snapshot fields retain prior NETCTL facts. MANUAL revision triggers remain
unchanged; telemetry does not cause false edit conflicts.

The HTML edit form and stale-form comparison use MANUAL-only defaults. Current
NETCTL identifiers appear separately as observed values. An unrelated save cannot
promote them to MANUAL. Existing Endpoint context keeps its explicit source/effective
precedence; all current sourced facts remain available to matching and projection.

## Synthetic verification

No production reads, network CLI commands, deployment, or external writes are used.
Regression coverage includes same-value source coexistence and timestamp refresh,
second changed IP, newer worker snapshot preserving manual IP99/revision, captured
HTML/API edit revision, preserving NMAP/NETCTL during manual save, provider-only
empty manual defaults, provider-source creation compatibility and manual update
rejection. Legacy tests expecting manual deactivation now require coexistence.

Executed locally on the isolated worktree (2026-09-26):

- `python -m pytest tests/test_inventory_revision.py tests/test_inventory_netctl_sync.py tests/test_inventory_endpoint_service.py -q --disable-warnings`: 75 passed; independently repeated by reviewer.
- `python -m pytest tests/test_inventory_api.py tests/test_inventory_web.py tests/test_inventory_service.py tests/test_inventory_netctl_bindings.py -q --disable-warnings`: 66 passed.
- `python -m pytest tests/test_inventory_network_projection.py tests/test_inventory_network_links_web.py tests/test_inventory_endpoint_regression.py tests/test_inventory_revision_migration.py -q --disable-warnings`: 14 passed.
- `python -m compileall -q app/inventory/service.py app/inventory/api.py app/inventory/web.py` and `git diff --check`: passed.

The new same-value test was run before the fix and failed because no separate NETCTL
row existed. All final checks use synthetic SQLite fixtures and injected collector
responses. Existing Python 3.14/FastAPI deprecation warnings remain unrelated.
