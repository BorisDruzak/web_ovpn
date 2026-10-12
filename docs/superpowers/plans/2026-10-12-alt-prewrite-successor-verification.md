# ALT prewrite successor implementation verification

Implementation admits one additive context only after the exact closed native
backup-preflight failure and fresh unchanged selected-machine evidence. Legacy
claims, receipts and four expired predecessor envelopes remain frozen. Planning
does not authorize password reset or make recovery/Setup acceptance claims.

## Executed verification

- Linux candidate snapshot: `python -B -m pytest -q -p no:cacheprovider --tb=short --disable-warnings --basetemp=PRIVATE_UNIQUE_DIRECTORY tests/alt_linux`: **2516 passed, 82 skipped**, 689.71 seconds.
- Final runtime workers: **29 passed**, including native operation-lock contention,
  pending backup mutations, exact hostname/FQDN and bounded large audit history.
- Genuine successor preparation/operator composition: **8 passed**. Original
  closed evidence remains byte-identical; legacy cannot consume successor plans.
- Existing recovery state/credential/composition checks: **177 passed**.
- `git diff --check`: passed before publication.
- Actual selected-machine candidate read-only probe: identity, absent recovery
  footprints and no active recovery passed. Protected predecessor validation:
  16 records and four envelopes passed. Controller native failure audit, guard,
  quiescence and capacity passed. No production admission or apply was executed
  during these checks; installed baseline still predates this implementation.

An earlier recovery-only run had one obsolete CLI mock failure; the mock now
targets protected operator composition. The final full ALT run above includes
that correction. Skips are retained as skips, not counted as acceptance.

## Independent review and architecture

A fresh-context reviewer found missing native backup concurrency observation.
RED/GREEN tests added a read-only nonblocking native operation lock and rejection
of pending mutating backup processes. Re-review found the issue resolved; final
hostname and large-audit compatibility changes were also reviewed without a
concrete blocker. The reviewer did not independently execute this test suite.

GitNexus upstream impact for `RecoveryAttemptStore` in `web_ovpn` reported
29 affected symbols (19 at depth one, 10 at depth two). Source and composition
tests verify dynamic credential/store selection across preparation, provider,
import, policy, terminal and Setup continuation. No HTTP contract changed.

## Required installed follow-up

Publish this exact revision, create/verify/rehearse a fresh guarded deployment
backup, run the native installer, compare installed bytes and readiness, and
prepare the installed successor plan. Verify all predecessor/history hashes and
the earliest child-plan expiry before requesting the specific reset approval.
Do not apply an expired plan, reuse the predecessor authority, or clear evidence.
