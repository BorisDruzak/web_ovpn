# Faster guarded Setup implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans.

**Goal:** Detect unsupported future packages early and avoid repeating unchanged
controller verification after a transient pre-rollout refusal.

**Architecture:** Extend gpupdate_compat for read-only APT resolution. Share an
ALT runner between developer and installer tests. Bind successful full tests to
private verification evidence; reuse it only with fresh installation guards.

**Tech Stack:** Python 3.12 standard library, Bash, Ansible core 2.18.

**Spec:** docs/superpowers/specs/2026-11-05-setup-preflight-resume-design.md

## Global Constraints

- Preserve original UNKNOWN/jobs/claims/history and all target identity gates.
- No automatic package-transaction retries or workstation replay.
- Keep private credentials/vault out of source, logs and verification receipts.
- Verification evidence never authorizes rollout; no reuse after source/env drift.

## Review Focus

- The APT candidate can differ from the installed version: Task 1 future-version test.
- Missing gpoa-lib and removed packages: Task 1 missing/removal tests.
- Inherited root/Python/pytest variables: Task 2 environment tests.
- Tests passing while source changes: Task 3 before/after fingerprint test.
- A valid test receipt with unavailable target: Task 3 fresh-guard integration test.

### Task 1: Pre-upgrade compatibility

**Files:** gpupdate_compat.py; prejoin_upgrade/tasks/main.yml;
tests/alt_linux/test_prejoin_upgrade_compat.py.
**Interfaces:** check_upgrade(run) -> sanitized version proof using PATCH_SETS;
Ansible --upgrade-check runs after metadata and before dist-upgrade.

- [ ] Write and observe failing future-version/resolution/role-order tests.
- [ ] Implement bounded read-only simulation and pair validation.
- [ ] Run affected compatibility/package suites and commit the coherent change.

### Task 2: Unified ALT verification

**Files:** deploy/alt-linux/verify_repository.py; run-tests.sh;
tests/alt_linux/test_repository_verification.py; install-control-plane-lib.sh.
**Interfaces:** runner describe/run for fixed environment; full default suite and
focused developer paths use the same environment and syntax checks.

- [ ] Write and observe failing sanitized-environment and worker checks.
- [ ] Implement one service-account runner with private cache/temp and smoke checks.
- [ ] Route installer verification through it; run affected installer suites.

### Task 3: Native pre-rollout continuation

**Files:** deploy/alt-linux/verification_checkpoint.py; installer args/wrapper/lib;
tests/alt_linux/test_verification_checkpoint.py; installer integration tests;
docs/WORKSTATIONS_WEB_GUIDE.md and deployment runbook.
**Interfaces:** root-only checkpoint fingerprint/record/reuse, schema 1, six-hour
maximum age; --resume-verification reuses only full verification evidence.

- [ ] Write and observe failing source/env/tamper/expiry/failure/fresh-guard tests.
- [ ] Implement private atomic receipts, exact binding, fresh pre/post guards.
- [ ] Verify targeted regressions, one stabilized full suite and branch review.
- [ ] Commit/publish only task files; report exact deployed versus source state.
