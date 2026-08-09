# Task 7 — Card-triggered Nmap integration — implementation report

## Status

Implemented and verified locally in the isolated worktree
`C:\Users\admin-2\Documents\ui_vpn\.worktrees\network-observer-enrichment-v2`.

Starting Git state:

```text
branch: codex/network-observer-enrichment-v2
HEAD before Task 7: d0b77b7
initial Task 7 commit: 7e9fa51
worktree: clean
```

No deployment, SSH session, live Nmap scan, package installation, remote-host
change, or production network/device write was performed.

## Implementation

### HTTP boundaries

- Kept `GET /network/assets/{asset_key}` authenticated, fast, and DB-only. It
  reads the existing bounded `netctl context-view asset` projection and never
  invokes `fingerprint ensure` or Nmap.
- Added authenticated, CSRF-protected
  `POST /network/assets/{asset_key}/fingerprint/ensure`.
- The POST validates the path asset key, ignores all browser-supplied target,
  port, profile, and script fields, returns HTTP 202, and queues one FastAPI
  background task containing only the validated asset key.
- The background task invokes only
  `netctl fingerprint ensure --asset-key <asset_key>` with a 45-second web
  client timeout. Target resolution and database single-flight remain in the
  existing netctl/Nmap policy and store layers.
- Background `NetctlError` failures are logged without raw stdout/stderr and do
  not fail the already-rendered device card.
- Added authenticated, read-only
  `GET /network/assets/{asset_key}/fingerprint/status`. It reads cached asset
  context and returns only the normalized fields used by the panel.

### Normalized public projection

The status/card projection is bounded to:

- state and freshness;
- an opaque run generation marker used only for polling coordination;
- device type, confidence, OUI vendor, OS name, Nmap accuracy, and last run
  time;
- at most 64 valid normalized open services;
- at most 16 concise evidence items from known provider labels.

The projection excludes target IP, raw XML, stderr, command lines, CPE data,
Nmap OS classes, error details, vulnerability structures, CVE claims, closed
ports, and unrecognized evidence providers. The generation marker is derived
only from the normalized stored run identity and is not rendered as card text.

### Card and browser lifecycle

- Added the Device fingerprint, Network services, and Evidence sections to
  `network_asset_detail.html` with server-rendered cached state.
- Added the four user-visible states: `Нет данных`, `Обновление...`,
  `Актуально`, and `Ошибка fingerprint`.
- Added `network-asset-fingerprint.js`, which POSTs ensure once, reads status,
  polls at 2-second intervals only while visible, prevents overlapping status
  requests, stops at a fresh success/new failure, and enforces a 30-second
  total deadline.
- DOM updates use `textContent` and created elements; no untrusted `innerHTML`
  rendering exists.
- Transport errors remain inside the poller and retry only within the same
  visibility/deadline bounds.

### Review-round generation fix

The first implementation correctly kept stale `success, fresh:false` results
non-terminal, but treated every `failed` status as terminal. A POST response is
sent before the FastAPI background task claims the database run, so the first
status request can still observe the previous failed run.

The fix carries the cached initial status plus an opaque run generation from
the server-rendered panel into the poller. The poller now:

1. ignores a failed result from the pre-ensure generation;
2. records a running generation when observed;
3. stops on failure of that new/active generation;
4. also stops when a fast new generation has already failed between polls;
5. stops on fresh success, including a valid TTL reuse;
6. continues only until the existing 30-second deadline if ensure cannot
   create a distinguishable new generation.

This is generation-aware without exposing scanner commands, raw scanner
output, target addresses, or failure internals.

## Files

Created:

- `app/static/network-asset-fingerprint.js`
- `tests/test_network_asset_fingerprint_js.py`
- `.superpowers/sdd/2026-08-09-network-observer-enrichment-v2/task-7-report.md`

Modified:

- `app/main.py`
- `app/templates/network_asset_detail.html`
- `tests/test_web_network_observer.py`

No netctl store, Nmap runner, scan policy, migration, deploy, or production
configuration file was changed by Task 7.

## TDD evidence

Initial Task 7 RED phases included:

- ensure endpoint: unauthenticated POST returned 404 rather than the required
  login redirect;
- scheduling contract: accepted response was missing and no background task
  existed;
- background command: the expected bounded netctl invocation marker was
  absent;
- background failure: `NetctlError` escaped the task;
- status endpoint: unauthenticated GET returned 404 and no normalized response
  existed;
- card panels: Device fingerprint content and lifecycle attributes were absent;
- JavaScript controller/adapter: the module, polling lifecycle, visibility
  behavior, deadline, safe DOM renderer, and transport containment were absent.

Each behavior was implemented only after its focused test failed for the
expected missing-feature reason. The initial completed Task 7 verification was
87 targeted tests passed and 1,580 full-suite tests passed with 11 skipped.

Review round 1 RED evidence:

```text
test_fingerprint_poller_ignores_stale_failure_until_new_run_generation_finishes
AssertionError: the pre-ensure failed generation is not terminal
actual timers: 0
expected timers: 1
```

The server-boundary RED then showed the normalized status response missing the
expected generation marker. GREEN verification confirmed the old failure is
ignored, a newly observed running/failed generation terminates, and a fast new
failed generation terminates without requiring an intermediate running poll.

## Verification

Expanded Task 7 and adjacent Nmap suite:

```powershell
python -m pytest tests/test_web_network_observer.py `
  tests/test_network_asset_fingerprint_js.py `
  tests/test_netctl_nmap_cli.py tests/test_netctl_nmap_store.py -q
```

Result: 88 passed, 0 failed in 48.48 seconds.

Fresh full suite after the review fix:

```powershell
python -m pytest -q
```

Result: 1,581 passed, 11 skipped, 0 failed in 271.77 seconds. Existing
FastAPI/Starlette/pytest-asyncio deprecation warnings remain.

Static verification before the review-round commit covers Python compilation,
JavaScript syntax, and `git diff --check`.

## Self-review

- Confirmed the only automatic Nmap trigger added by this phase is the card's
  authenticated POST; the card GET, hosts page, dashboard, collectors, and
  reconciliation paths remain non-triggering.
- Confirmed browser input cannot select an IP, port range, profile, script, or
  command argument.
- Confirmed duplicate browser opens may enqueue ensure calls, but netctl's
  database transaction/unique-running constraint remains the authoritative
  single-flight mechanism and fresh TTL reuse starts zero Nmap processes.
- Confirmed status and HTML render only the strict normalized projection.
- Confirmed old failures cannot suppress a new attempt and new failures still
  terminate promptly when their generation is identifiable.
- Confirmed no production/deploy files or remote systems were touched.

## Concerns and intentional limits

- Polling the read-only context endpoint starts a bounded local netctl process
  per status request. The 2-second interval, visibility pause, no-overlap gate,
  and 30-second deadline bound that cost.
- If ensure fails before it can create a new run generation, the browser cannot
  safely attribute the old failed snapshot to the new request. It therefore
  keeps the existing card usable and stops at the 30-second deadline rather
  than falsely reporting the old failure as the new attempt.
- Live Nmap behavior, TTL reuse, and process counts require the deferred Task 10
  production canary. This local task used only deterministic fakes and the
  existing netctl database/CLI tests.

Final local verdict: ready for parent integration and independent review.
