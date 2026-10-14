# ALT Setup maintenance review implementation plan

> **For agentic workers:** Use superpowers:executing-plans in this chat, as selected by the operator. Use focused TDD and one independent whole-change review before publication.

**Goal:** Allow separately confirmed native maintenance of one proven stopped full-Setup UNKNOWN without changing its history or target mutation gates.

**Architecture:** A canonical validator in the native backup package builds and checks protected plans/receipts. Thin controller CLI and explicit backup/installer scopes consume it; ordinary worker/admission behavior stays unchanged.

**Tech Stack:** Existing Python/file-state, Linux flock, native systemd/backup and read-only AD/SSH collectors; no new library, broker, database or HTTP contract.

**Spec:** `docs/superpowers/specs/2026-10-14-alt-setup-maintenance-review.md`

## Global constraints

- One full-Setup UNKNOWN and its two exact nested leases only; preserve all historical bytes.
- Plans expire after 30 minutes; confirmation creates an immutable 21600-second maintenance window, with fresh validation at each admission.
- 0700/0600 service-owned state, exact SHA, code/evidence/identity binding; no generic force flag.
- Prove lifecycle quiescence without requiring the idle worker daemon to die; default target gates remain blocked.
- No live metadata confirmation, deployment, reboot or target mutation before its separate operator gate.
- No cross-repository API or new account-reset/recovery mechanism.

## Review focus

- Finished UNKNOWN while its worker daemon still lives must use the real lock, not PID absence alone.
- Unrelated queued work or a foreign lease sharing a run ID must block maintenance.
- Root backup must read service-owned sealed records without changing ownership or metadata.
- A stale/changed/expired receipt must fail every native admission, including rollback/history checks.
- Bootstrap and installed consumers must validate the same canonical receipt with no path/code substitution.

### Task 1: Canonical private plan, evidence and confirmation

**Files:** create backup `setup_maintenance_review.py` and focused `test_setup_maintenance_review.py`; add a thin control import/CLI adapter and a read-only probe helper only as needed.

**Interfaces:** `MaintenanceReview(settings, observer=None, clock=None).plan(job_id)`;
`confirm(plan_id, sha)`; `exclusions(sha)` returns only validated job/lease sets.
Public projections expose IDs, SHA/deadlines, counts and maintenance-only purpose.

- [ ] Write a stopped full-Setup UNKNOWN fixture with exact failed run, execution, safe events and nested leases; preserve original bytes.
- [ ] Watch missing implementation/positive admission fail, then implement the smallest canonical service using existing validators and stores.
- [ ] Add and run negative evidence, identity/health, live lock, PID/daemon, owner/mode/symlink, expiry and duplicate-confirmation cases.
- [ ] Verify fresh proof and immutable history; commit the independently tested service and interface.

### Task 2: Explicit native backup/readiness/installer admission

**Files:** backup CLI/settings/repository/quiescence/setup_compat and restore health only as needed; control jobs/readiness adapters; installer argument/lib scripts; native sandbox and argument tests.

**Interfaces:** optional trailing `--maintenance-review SHA`, absent by default.
All native consumers invoke Task 1's canonical validator; no normal worker or target-admission exemption.

- [ ] Write native backup positive/negative and installer/default compatibility tests; watch them fail.
- [ ] Propagate the explicit scope, retain all other guards, and include new immutable directories in history fingerprint/ledger checks.
- [ ] Verify native capture/rehearsal/restore history preservation, unrelated-job denial, scoped readiness and unchanged ordinary target gates.
- [ ] Inspect full diff and commit the tested integration.

### Task 3: Operator contract, review and publication

**Files:** existing operator/engine docs and acceptance ledger.

- [ ] Document metadata confirmation, six-hour execution window, default denial, bootstrap path, immutable UNKNOWN and separate deployment/VM gates.
- [ ] Run applicable root/POSIX regression and exact final-SHA full CI; retain concrete receipts.
- [ ] Obtain one independent review of the complete maintenance delta, fix substantial findings with RED/GREEN, and publish through normal main fast-forward.
- [ ] Prepare a fresh read-only live maintenance plan and verified/rehearsed rollback proposal; ask for exact metadata/deployment approval only when concrete.
