# Final review fixes: network host snapshot

## Scope and recovery

Recovered the uncommitted final-review changes in the isolated
`network-host-snapshot-20260907` worktree. No reset, deployment, push, SSH, or
production-network action was performed. GitNexus has no `ui_vpn` repository in
its available registry (only `endpoint_platform` and `helpdesk`), so the local
source, complete local diff, and automated tests were used for architecture and
impact verification.

## Implemented review fixes

1. Migration 27 creates `netctl_normalize_mac(mac)` expression indexes for
   `bridge_hosts` and `current_switch_fdb`. The SQLite function is the existing
   complete `normalize_mac` implementation, registered deterministic before
   migrations and on writable/read-only netctl connections. Raw MAC values and
   the existing raw indexes remain unchanged. The regression traces the real
   batched projection statements, runs `EXPLAIN QUERY PLAN` on each chunk, and
   proves seeks through both expression indexes. A legacy-row migration/reopen
   regression also proves the normalizer preserves whitespace/separator/case
   semantics and the index follows writes.
2. Snapshot metadata now contains `stale`, computed without writes from a
   generated timestamp older than 20 minutes, future, or invalid. The status
   and page read APIs accept an injected `now` for deterministic boundaries.
   The browser refresh script updates the freshness label even if the snapshot
   ID did not change, without fetching rows.
3. Successful `availability probe` and `availability force` publish a fresh
   host snapshot while the enclosing `CollectLock` is still held. Publication
   failures return `host_snapshot_failed` and leave the prior published
   snapshot intact.
4. The README records stale/pending behavior, expression-index registration
   requirements, manual-action publication, and operational limits.

## Verification evidence

Focused regressions:

```text
pytest -q tests/test_netctl_availability.py -k 'normalized_mac_index_migration or bulk_mac_queries_search_expression_indexes or manual_availability_action_publishes_snapshot_under_collection_lock'
4 passed, 65 deselected

pytest -q tests/test_netctl_host_snapshot.py
28 passed

pytest -q tests/test_web_network_observer.py -k snapshot_freshness_reaches_real_page_and_api_views
2 passed, 71 deselected

node tests/network_hosts_refresh.test.js
node --check app/static/network-hosts-refresh.js
```

Relevant suites:

```text
pytest -q tests/test_netctl_availability.py
69 passed

pytest -q tests/test_netctl_context_migrations.py
4 passed

python -m compileall -q app netctl
node --check app/static/network-hosts-refresh.js
node tests/network_hosts_refresh.test.js
git diff --check
```

The environment terminates individual terminal commands at approximately 30
seconds. The complete `test_web_network_observer.py` suite exceeded that limit;
the two directly affected end-to-end stale API/page cases above were run
successfully. Existing pytest-asyncio and FastAPI/Starlette deprecation warnings
remain outside this scope.

The compilation, Node syntax/behavior, and whitespace checks exited zero without
output. The full UI observer suite remains a recommended unrestricted-terminal
follow-up only because of the command-window limit; no affected test was left
unrun.
