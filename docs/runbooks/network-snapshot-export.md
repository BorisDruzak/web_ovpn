# Network snapshot export source (T12)

## Contract

`netctl --json --db sqlite:///... hosts export` uses the same filters as `hosts list`, except page/limit are intentionally absent. Its successful JSON envelope is `{status: "ok", hosts, total, snapshot, inventory_projection_revision}`. Every matching interface appears in numeric IP order from a single published SQLite read snapshot. `inventory_projection_revision` is null without projection, otherwise echoes the validated stdin envelope revision. Inventory relation filtering uses the same bounded stdin projection and shared SQL predicates as the public list.

The internal export uses one SAVEPOINT spanning metadata, count, UTF-8 payload budget and rows. A concurrent WAL publication cannot mix metadata/count/rows. There is no page loop or external call. The CLI opens the existing database with mode=ro/query_only and never prepares/migrates/collects it. Public list pagination remains capped at 250.

Limits: 10,000 matching rows; final emitted ASCII-escaped JSON including status/worst-case CRLF newline <=16 MiB. Count is checked before row loading; aggregate payload bytes are checked in SQL before decoding; final envelope size is checked before success. Errors never include partial hosts:

- `host_snapshot_absent`: no existing published snapshot (missing database is not created).
- `host_export_row_budget`: narrow the selection.
- `host_export_byte_budget`: narrow the selection.
- `host_snapshot_failed`: malformed projection/filter/source or read failure; raw diagnostics are not emitted.

Published stale snapshots are permitted with explicit snapshot.stale=true. A valid empty selection returns total=0, not absent-snapshot failure.

## Workbook adapter / integration boundary

`app.network_xlsx.network_workbook(snapshot_result, enriched_hosts, *, filters, inventory_epoch, enriched_at) -> (bytes, counts)` uses the parent's common `app.xlsx_export.workbook_bytes`. The adapter writes `Снимок`, `Связи с инвентаризацией`, and `Параметры`. It projects an explicit source/enrichment field allowlist and preserves every interface, including unlinked/candidate/conflict states. Unknown arbitrary payload fields and arbitrary filter parameters are excluded. Row count/order/key mismatches and mismatched supplied inventory revisions fail explicitly. IDs/IP/MAC are text; UTC dates, booleans/counts retain types. Formula safety, bounded generation, style and private in-memory storage belong to the shared writer.

Callers own permissions, one consistent local Inventory enrichment read, local projection epoch rechecks, private owner-scoped artifacts, audit and offloading. This helper does not claim a distributed transaction, perform SDK requests, or authorize a user. The parameter sheet names the Netctl publication timestamp/id/freshness separately from local epoch/enrichment time. Parent owns routes/templates/rights/artifacts/dependency pinning; no edits to those are included here. A temporary local copy of the parent's uncommitted shared writer was used solely for isolated parser tests and is excluded from this commit.

## Verification

TDD RED: five source tests failed before hosts export existed; two adapter tests failed before network_workbook existed. A real-source nested passive-evidence regression subsequently failed and was fixed by explicit list-to-text projection.

`python -m pytest tests/test_network_xlsx.py tests/test_netctl_host_export.py tests/test_netctl_host_snapshot.py tests/test_netctl_cli.py -q --disable-warnings --tb=short -k 'not runtime_assets_status_reports_identity_operational_summary'`: **154 passed, 1 skipped, 1 deselected**. The excluded existing CLI assertion expects schema migrations through 26 while the committed baseline includes migration27; the full preceding run reproduced that mismatch separately (147 passed,1 skipped,1 failed). Source tests execute the actual CLI subprocess, retain the public250 cap, verify readonly SQL/file behavior, all list filters, stdin projection/revision, >one-page selection, empty/stale/absent outcomes, row/bytes/envelope limits and deterministic concurrent snapshot publication after metadata read. Actual CLI Unicode/emoji regression verifies portable ASCII-escaped JSON preserves values even on Windows cp1251; other CLI commands retain their existing emission. Parser tests verify full sheets, Cyrillic/leading zeros, no formulas/unknown fields, relation rows and epoch conflicts. Compileall and git diff --check passed.

Synthetic 300-row workbook available locally at `output/playwright/network-export/synthetic-devices.xlsx` (ignored QA artifact), 48,890 bytes, SHA256 `1a80011eaf18fc4c98cff711fb0bb0c22bb6bc28e340ccb064ff37adbe73edfd`. It was opened with openpyxl; manual Excel opening was not performed. No production reads/exports/network actions/deployment/push occurred.

GitNexus web_ovpn query preceded source exploration and located the committed host snapshot/list path. The remote index does not include local main20a49 source changes; shared dynamic CLI dispatch was verified against current source/tests. Context7 Python3.14 sqlite3 documentation confirmed URI mode=ro; no dependency changes belong to this branch.

Independent scoped review: no P1/P2; test_netctl_host_export + test_network_xlsx + test_netctl_host_snapshot + test_netctl_client independently passed 58 tests without deselections.
