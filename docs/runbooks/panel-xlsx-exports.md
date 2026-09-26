# Owned XLSX exports

Browser exports run in the existing bounded operation executor. POST requires a
session, CSRF and the export capability. The operation owns its worker Session;
the browser request does not perform workbook generation. A per-render intent
key makes a new submission read current facts while transport retries reuse one
result. History restoration rotates the displayed key even without bfcache;
already-sent request bodies retain their key. Pending equivalent intents share one operation.

## Routes and capabilities

| Route | Required capabilities | Scope |
| --- | --- | --- |
| POST /inventory/export, scope=all | inventory:read, inventory:export | All active cards |
| POST /inventory/export, scope=location | inventory:read, inventory:export | All active cards in explicit location_id |
| POST /inventory/export, scope=deleted | inventory:read, inventory:export, inventory:delete | Deleted cards only |
| POST /network/export | network:read, network:export | All matching interfaces in one published snapshot |
| GET /operations/{id}/files/{file_id} | Owner, original export capability, current read/export and delete for deleted exports | Owned unexpired artifact |

Existing VPN artifact capabilities remain unchanged. XLSX paths are never accepted
through VPN download roots or the raw-token download route. The operation result
route redirects file responses to durable artifacts, including after process restart.
No new service-account export endpoint or scope is introduced.

## Workbook scope

Inventory sheets: Устройства, Связи рабочего места, Сетевые привязки,
Идентификаторы, Проверки, Фото, Наблюдения, Параметры. Device rows include all six
asset types and their specialized fields. Relationships/identifiers include history;
related cards outside the chosen scope are labelled without silently expanding the
device sheet. Default selection excludes deleted cards. Photo metadata excludes
storage paths and image bytes. Source observations and operator decisions use
explicit safe fields, not arbitrary raw context or diagnostic dumps. Endpoint
network facts and per-profile freshness are separate from aggregate success dates.

Network sheets: Снимок, Связи с инвентаризацией, Параметры. Each selected interface
appears once, including explicit unlinked states. The source command is readonly
`netctl hosts export`, with the same selection filters and optional bounded stdin
projection as hosts list, and no pagination. Public list still caps pages at250.
Absent snapshots and exceeded budgets fail explicitly, never silently returning
an incomplete book. Metadata distinguishes source snapshot time from local
enrichment time/epoch; there is no distributed transaction claim.

Inventory uses one physical local read transaction; SQLite SELECT alone is not
sufficient under legacy sqlite3 control, so the owned reader issues BEGIN. Network
releases its first local projection read before CLI execution, uses another coherent
local read for enrichment, and checks the committed epoch before returning. A changed
epoch yields409 and no artifact. PostgreSQL readers use REPEATABLE READ READ ONLY.

## Resource and file boundaries

Source selection is bounded before ORM materialization: row limits plus a cumulative
16MiB byte budget for Text/JSON, using SQLite BLOB length (including NUL) or PostgreSQL
octet_length. Network source limits10000 rows/16MiB JSON output. Serialization limits
50000 total rows including headers,500000 cells,16MiB text,20MiB XLSX and20seconds.
Oversize cells and invalid XML Unicode fail explicitly. Strings remain text, including
leading-zero identifiers and formula-like values; numeric0 differs from an empty cell.
Dates are UTC. No formulas, links, macros or plaintext worksheet temporary files are
created. The in-memory worksheet adapter is verified against pinned openpyxl3.1.5;
dependency upgrades must rerun its tempfile-denial and parser regressions.

PANEL_EXPORT_ROOT selects a dedicated private directory. Default Linux path is
inventory_photo_root's parent/private-exports; Windows uses the current user's
LOCALAPPDATA/OpenVPNWeb/private-exports. Linux permissions are0700/0600; Windows
uses a protected owner+SYSTEM DACL. Generated names contain only random UUIDs.
Directory quota is64 files/200MiB, checked under an interprocess lock. download_ttl_minutes
controls validity and retention; startup and a60second worker remove expired generated
files. Cleanup preserves foreign files and skips symlinks. Quota/lock failures are
explicit. Files are private even if generation/audit fails before artifact registration.

## Release and rollback

No deployment has been performed. Back up the application database before the full
specification's schema initialization/migrations. Install requirements.txt, including
openpyxl3.1.5, and update the readonly Netctl CLI before enabling exports/selected
Inventory filters. Selected filters require SQLite JSON1 and SQLite>=3.35. Create the
private directory as the service account and keep it outside static/public roots.
Verify permissions, disk quota and download TTL in the target environment before use.
These exporter changes add no new database schema; earlier specification migrations
and their rollback constraints are documented in the revision/draft/lifecycle and
operation runbooks. Preserve the migrated database when rolling application code back;
do not erase card/history tables or republish obsolete relationships.

## Verification evidence

Synthetic tests cover whole selections beyond one page, two monitors/outside-scope
relationships, deleted/empty scope, source/change coherence, types, formulas, Unicode,
predecode NUL byte limits, owner/scopes/CSRF, revoked/expired artifacts, raw-token
rejection, new intents versus retries, background cleanup and four competing Windows
processes sharing a two-file quota. The first concurrency test exposed a Windows
read-before-lock race; the lock now acquires a byte beyond EOF without sentinel I/O.

`tests/browser/panel_xlsx_exports.js` uses loopback synthetic data, the explicit
operation-state refresh link, and downloads both books. Saved inventory_link applies
to the actual filter control. Parser checks inspect every cell for formulas and every
book for external links/macros. No manual desktop Excel acceptance, production exports,
Linux deployment permissions or real inventory data are claimed. Exact commands and
results are recorded in docs/plans/web-panel-reliability-2026-09-26.md.
