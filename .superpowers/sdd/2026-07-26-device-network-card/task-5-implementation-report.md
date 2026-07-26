# Task 5 implementation report

## Scope delivered

- Added `netctl.retention` with a deterministic, non-mutating 30-day report and
  FK-safe apply operation.
- The apply operation uses exactly one `BEGIN IMMEDIATE` transaction, deletes
  event/history families before their parent runs, validates `foreign_key_check`
  and `integrity_check`, and never runs `VACUUM`.
- Protection sets retain current-state collector/correlation/path runs and the
  latest successful (or partial where supported) run per source/run type.
- Added `netctl --json retention cleanup [--days 30] [--apply]`; the default is
  a dry-run, and database failures are returned as `retention_failed` without
  underlying details.

## TDD evidence

1. `python -m pytest tests/test_netctl_retention.py -k dry_run -q` initially
   failed with `ModuleNotFoundError: No module named 'netctl.retention'`.
2. `python -m pytest tests/test_netctl_cli.py -k retention -q` initially
   failed because `retention` was not an accepted CLI command.
3. The failure-sanitization test initially propagated a SQLite error; the CLI
   now converts it to the stable `retention_failed` response.
4. Fix round 1: a fixture with an old successful generic `collection_runs`
   row (`status='ok'`) and a newer failed row initially reported two deletion
   candidates and removed the old successful run. Retention now uses the
   actual `store.py` generic-success status (`ok`) for both preview and apply.

## Verification

`python -m pytest tests/test_netctl_retention.py tests/test_netctl_cli.py -q`

Result: `66 passed, 1 skipped`. The existing pytest-asyncio configuration
warning remains outside this change.
