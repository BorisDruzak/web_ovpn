# Network host snapshot verification — 2026-09-07

## Scope and release state

This record covers local verification in the isolated
`network-host-snapshot-20260907` checkout, starting from commit
`31c6d959ba6afae78c99ba116dc78e4ce63abaa2` plus the Task 6 observability change.
No push, deployment, production migration, production refresh or network-device
write was performed for this verification. Production measurements remain pending
a separate controller rollout and must be added from actual observations.

## Architecture and compatibility

Migration 25 adds availability projection indexes; migration 26 adds
`network_host_current_state`, `network_host_current_sources` and
`network_host_snapshot_meta`. Projection loads evidence in bounded batches and
per-host projection uses no SQL. Snapshot publication builds from a consistent
source read transaction, releases it, then replaces rows, sources and metadata
atomically under `BEGIN IMMEDIATE`. Failed writes preserve the previous complete
snapshot; tests cover concurrent readers and a competing host-comment writer.

`hosts list` and `snapshot-status` use read-only connections. The list applies
filters, numeric address ordering and pagination before decoding stored payloads.
Missing or unpublished snapshots return empty pending results without creating a
database or running migrations. Web/API list reads do not collect, probe,
reconcile, project availability or request live VPN clients. Single-host detail
keeps its existing separate behavior. Endpoint Agent stays neutral.

The browser polls metadata every 15 seconds and requests the current filtered
page when its snapshot ID changes. Existing rows survive failures and malformed
responses; generation guards reject late responses. The two host snapshot GET
API routes accept an authenticated browser session as well as bearer tokens;
other API routes keep their existing authorization boundary.

GitNexus was queried before local source review. Its configured registry returned
`Repository "ui_vpn" not found`, with only `endpoint_platform` and `helpdesk`
available. This is an index limitation; the local source and regression tests
provide the architecture evidence for this record.

## Local statement counts

Measured on Windows, Python 3.14.3, using the real `conn` and `seeded_hosts`
fixtures in `tests/test_netctl_availability.py` and a temporary SQLite database:
1,200 hosts, 2,000 current FDB rows and 300 bridge rows. Fixture preparation and
migrations are excluded from statement counts. Each measured operation installs
a SQLite trace callback and uses `time.monotonic()` for elapsed time; the callback
is removed after the operation. Only aggregate counts and durations were printed.

| Operation | Traced SQL statements | Elapsed milliseconds |
| --- | ---: | ---: |
| Legacy per-host projection of all 1,200 fixture hosts | 9,626 | 16,374 |
| Bulk projection of the same hosts | 25 | 66 |
| Persisted list read, page 1, limit 50, status all | 7 | 1 |

Legacy and bulk projected results were asserted equal. The snapshot contained
1,200 hosts and the page returned exactly 50. The full snapshot refresh recorded
140 ms in its metadata. The seven list statements include read savepoint control;
snapshot publication inserts are excluded from the list measurement. These are
single-run synthetic local measurements, not production latency or a service-level
guarantee. The legacy projector retained in the tree is the before reference.

The passing automated bounds independently assert fewer than 80 SQL statements
for the large fixture, zero SQL during `project_host_from_context`, and fewer
than 20 statements with 240 historical manual results and 240 historical runs.
The equivalence tests cover all five statuses and normalized passive evidence.

## Observability RED/GREEN

`pytest tests/test_netctl_host_snapshot.py -q -k logs_include` first exited 1:
two expected failures because completed list-read measurements were absent.
After adding the list completion log, the same command exited 0:
`2 passed, 23 deselected in 0.75s`.

The parametrized regression checks populated and out-of-range empty pages,
refresh completion, actual returned count, filtered total, snapshot ID, page,
limit and duration. Every event argument must be numeric and every field must
belong to the measurement allowlist. The fixture supplies private hostname,
source and query values to catch accidental inclusion. Existing refresh-error
coverage verifies that exception payloads do not reach logs.

Events use INFO for `host_snapshot.refresh.start`,
`host_snapshot.refresh.finish` and `host_snapshot.list.finish`, and ERROR for
`host_snapshot.refresh.error`. Fields are restricted to `id`, `count`, `total`,
`page`, `limit` and `duration_ms`; applicable subsets vary by event. No payloads,
addresses, hostnames, sources, credentials, filter values or configuration are
logged. The list completion event is emitted after decoding and releasing the
read savepoint, so failed reads are not reported as successful completion.

## Local verification commands

| Command | Result |
| --- | --- |
| `pytest tests/test_netctl_availability.py tests/test_netctl_cli.py tests/test_api_routes.py tests/test_web_network_observer.py tests/test_ui_snapshot_cache.py tests/test_netctl_host_snapshot.py -v` | Exit 0; 288 passed, 1 skipped, 26,860 warnings in 95.54 s |
| `pytest -q` (initial run) | Exit 1; 1 failed, 1,664 passed, 11 skipped, 44,588 warnings in 314.12 s |
| `pytest -q` (after deterministic fixture correction) | Exit 0; 1,665 passed, 11 skipped, 44,588 warnings in 311.98 s |
| `python -m compileall -q app netctl` | Exit 0 |
| `node --check app/static/network-hosts-refresh.js` | Exit 0 |
| `node tests/network_hosts_refresh.test.js` | Exit 0 |
| `git diff --check` | Exit 0 |

The targeted skip is the Linux-only separate-process collection-lock test on
Windows. Existing deprecation warnings concern pytest-asyncio fixture loop scope,
FastAPI/Starlette coroutine detection, startup hooks and template invocation.
The Node fixture exercises malformed-row preservation and metadata response races;
it is not a production browser smoke test.

The initial full-suite failure was
`tests/test_netctl_context_query.py::test_inspect_asset_context_returns_named_path_history_and_freshness`
at line 632: its fixed event timestamp, `2026-07-26T10:05:00Z`, is outside the
30-day history window on the verification date. The unchanged
`netctl/context_query.py::_attachment_events` correctly filters against current
UTC time. Neither this test nor its production module changed in Task 6.

The exact single-test command reproduced the failure (exit 1, one failed in
0.73 s). A diagnostic in-memory override of `context_query.utc_now` to
`2026-07-26T10:06:00Z`, followed by `pytest.main` for the same single test, passed
(exit 0, one passed in 0.41 s), confirming the date-dependent fixture assumption.
No source or test was altered by that diagnostic. The controller then authorized
a separate test-only correction: the one test now fixes `context_query.utc_now`
with pytest's `monkeypatch` to the fixture's timeline. Its July 26 event remains
inside the 30-day window and its June 25 event remains outside, preserving the
history-filter assertion. Production context behavior is unchanged. The exact
single-test pytest command now passes without diagnostic overrides (exit 0,
one passed in 0.48 s). The full-suite rerun then passed as recorded above.

## Production follow-up — pending

All deployment acceptance measurements below are unmeasured here:

- Installed commit, migration versions and active `openvpn-web` service.
- First published snapshot ID, generation time, total count and refresh duration.
- Authenticated host-list and metadata HTTP success and elapsed time, including
  the five-second response target.
- Browser rendering, current filter/page preservation and refresh behavior on
  the deployed site.
- Post-rollout logs confirming no new netctl timeout errors.

The controller must record actual sanitized results after final review and its
separate rollout. Back up the SQLite database before production migrations, use
the unprivileged collector identity for snapshot refresh, and preserve the last
good database/code backup for rollback. No network-device configuration changes
are needed for the host snapshot migration.
