# ALT Prewrite Successor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Prepare one separately confirmed recovery attempt after a verified controller-backup failure before workstation/AD mutation.

**Architecture:** A protected admission document freezes the predecessor and permits one explicit successor namespace. The attempt reference travels through internal Settings composition and the protected recovery snapshot; all controller stores and fixed request hashes bind the same context. Legacy records and execution exclusion remain unchanged.

**Tech Stack:** Existing Python standard library, pytest, fixed SSH source-stdin workers, native guarded controller backup/installer, existing Ansible Setup pipeline. No added dependency.

**Spec:** `docs/superpowers/specs/2026-10-12-alt-prewrite-failure-successor-design.md`.

## Global Constraints

- Original attempt paths and bytes remain unchanged; one successor per predecessor.
- Admission refuses all ambiguous/postwrite/import/service failures and active operations.
- One GUID-only machine-password write per confirmed successor; no replay, rollback, cleanup or second successor.
- No employee password/group/identity mutations; no arbitrary root/path/command/environment override.
- Old and new SHA/TTL authority are separate; a new concrete live reset requires human confirmation.
- Real topology/identities/credentials remain in protected runtime evidence.

## Review Focus

- Mixed attempt context must fail before a store mutation or fixed external process.
- Admission must freeze every predecessor record and refuse extra later-stage footprints.
- Incomplete admission/relationship persistence must not allocate another successor.
- Legacy status and Setup continuation must select the explicit context without global routing.
- Capacity/readiness proof must be current and informational errors must never expose secrets.

### Task 1: Protected attempt context and store isolation

**Files:** new `deploy/alt-linux/control/alt_deploy/setup_recovery_attempt_context.py`; modify `config.py`, `setup_recovery.py`, `setup_recovery_credential.py` and the six direct store constructors; new `tests/alt_linux/test_setup_recovery_attempt_context.py`.

**Interfaces:** `RecoveryAttemptStore.for_settings(settings, clock=None)`; `RecoveryAttemptStore(state_root, clock=None, context=None)`; optional internal `Settings.recovery_attempt_context`; `validate_context(state_root, reference, pair=None) -> dict`. Context references bind attempt ID, pair and admission SHA. Plans stay under the canonical state root.

- [x] Write tests for separate legacy/successor paths, protected descriptor replacement, wrong pair, malformed ID, missing relationship and mixed plan/context. Run and observe RED.
- [x] Implement fixed namespace selection and guard all path/reserve/credential boundaries. No environment accessor for the new Settings field.
- [x] Run namespace tests and existing recovery state/credential tests; verify both chains are immutable and legacy replay still fails.

### Task 2: Fixed read-only admission and absence evidence

**Files:** new `setup_recovery_successor.py`, `setup_recovery_successor_probe.py`, `setup_recovery_successor_runtime.py`; new `tests/alt_linux/test_setup_recovery_successor.py`, `test_setup_recovery_successor_runtime.py`.

**Interfaces:** `RecoverySuccessorService.prepare(failed_run_id, computer_guid, predecessor_sha) -> reference`; `RecoverySuccessorRuntime.inspect(machine, pair) -> bounded proof`. The runtime verifies fixed absent workstation footprints and no active children; controller checks native audit/readiness/capacity and exact protected predecessor chain.

- [x] Construct a real failed-preparation fixture and positive admission; negative tests mutate each required record, introduce each forbidden phase/footprint, change identity and simulate active/unknown process state. Observe RED.
- [x] Implement historical envelope integrity verification, frozen predecessor inventory and fixed absence/current-state proof. Persist the exclusive relationship and immutable descriptor without deleting any predecessor file.
- [x] Run negative admission/race/persistence tests, composed runtime and retained-source boundary tests; errors stay bounded and secret-free.

### Task 3: Native operator composition and continuation

**Files:** modify `setup_recovery_planning.py`, `setup_recovery_operator.py`, `setup_cli.py`, recovery composition stores, `setup_recovery_continuation.py`/resolution selection as needed; extend operator/execution/continuation/CLI tests and `docs/ALT_RECOVERY_OPERATOR.md`.

**Interfaces:** native `setup recovery successor-plan --failed-run ... --computer-guid ... --predecessor-sha256 ...`; normal `apply` reconstructs explicit context from the protected base snapshot. Status/continue use an explicit saved operator-plan selector for successor contexts. Normal Setup resolution loads the terminal execution plan to select the same context.

- [x] Write tests proving no execution during planning, exact SHA/TTL authority, wrong-context refusal, one successor application, permanent entered exclusion and unchanged original status/history. Observe RED.
- [x] Bind context reference in the snapshot and all canonical hashes; revalidate predecessor integrity before each fixed operation. Preserve genuine component lock ownership.
- [x] Test the production coordinator and final normal Setup continuation, including fresh verifier drift and partial persistence. Run all relevant recovery suites and source syntax checks.
- [x] Commit only task-related source/tests/docs after complete diff review and `git diff --check`.

### Task 4: Independent review, publication, installed preparation

**Files:** verification report and ignored progress ledger; verified tracked implementation from Tasks 1–3.

- [x] Request fresh-context whole-branch review with the approved spec and explicit dynamic store/worker chain. Fix substantiated findings with RED/GREEN tests.
- [ ] Run full relevant regression including protected root fixtures; inspect all output and exact source versions. Publish verified work to main using normal fast-forward flow; no force push.
- [ ] Confirm disk headroom for both deployment and runtime backups; retain the latest rollback bundle and predecessor evidence. Create/verify/rehearse fresh guarded deployment backup and install exact published bytes.
- [ ] Check installed byte equality, native readiness and actual selected-PC read-only successor admission/planning. Compare all predecessor and original history hashes before/after.
- [ ] Report the exact new operator SHA and effective earliest expiry. Request permission for the specific machine reset. Do not invoke apply in this task.

## Execution authorization

The human approved the written specification and explicitly requested implementation, all necessary verification and installed plan preparation, with the next permission request reserved for the concrete reset. Inline execution is selected for the tightly coupled composition; an independent whole-branch reviewer is required. No further routine implementation check-in is needed.
