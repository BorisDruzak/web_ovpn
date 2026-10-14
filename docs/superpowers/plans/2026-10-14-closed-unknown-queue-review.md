# Closed UNKNOWN Queue Review Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Admit one SHA-confirmed queued job on a different machine after fresh
closure checks, preserving the original UNKNOWN and serialized execution.

**Architecture:** Reuse native maintenance closure validation through a separate
queue-purpose validator. Bind each review to an already-admitted candidate, and
validate it immediately before the worker's existing single-use claim.

**Tech Stack:** Existing Python standard library, protected JSON state, Ansible,
systemd worker, native backup validator and pytest. No new dependency.

**Spec:** `docs/superpowers/specs/2026-10-14-closed-unknown-queue-review.md`.

## Global Constraints

- Purpose `queued_other_machine_only`; maintenance purpose remains separate.
- 30-minute protected-plan TTL; immutable review valid for at most six hours.
- One worker and lifecycle-before-queue lock ordering; FIFO remains strict.
- No original UNKNOWN/claim/assignment/reservation rewrite or domain replay.
- No network infrastructure changes, AD employee mutation or artificial home.
- Cancel only an exact unclaimed queued job; preserve the used plan claim.

## Review Focus

- Candidate state changes between review and claim deny admission.
- Registration/source or original evidence drift never authorizes target writes.
- An unrelated active provision job or extra legacy lease remains a blocker.
- Expired retained artifacts stay valid history but give no execution permission.
- Cancellation interrupted after claim retains ambiguity; it is never replayed.

## Task 1: Operator cancellation of an unstarted queued job

**Files:** Modify `deploy/alt-linux/control/alt_deploy/setup_jobs_view.py`,
`setup_cli.py`; test `tests/alt_linux/test_setup_jobs_cli.py` and
`tests/alt_linux/test_setup_jobs.py`.

**Interfaces:** `SetupJobsService.cancel(job_id, confirmed_plan_sha)` returns
the persisted safe cancellation result. It uses existing repository claim,
publish and transition methods; it adds no state enum or relaxed schema.

- [ ] Write failing tests for exact queued cancellation, wrong SHA, executing or
  UNKNOWN denial, repeated cancellation without a new claim, and interrupted
  claim without a terminal receipt. Assert the original blocker is unchanged.
- [ ] Run the new test cases and observe the missing command/service failures.
- [ ] Implement the CLI and service under the lifecycle lock. Bind current
  service process identity, persist the cancellation result before failed status,
  and preserve all admission artifacts. A partial cancellation fails closed.
- [ ] Run `python3 -m pytest -q tests/alt_linux/test_setup_jobs.py tests/alt_linux/test_setup_jobs_cli.py tests/alt_linux/test_setup_worker.py`.
- [ ] Inspect the complete diff, run `git diff --check`, stage only these files
  and commit `feat(alt-setup): cancel unstarted queued jobs safely`.

## Task 2: One-candidate queue review and serialized dispatch

**Files:** Create
`deploy/alt-linux/backup/alt_deploy_backup/setup_queue_review.py` and
`tests/alt_linux/test_setup_queue_review.py`. Modify
`deploy/alt-linux/backup/alt_deploy_backup/setup_maintenance_review.py`,
`setup_compat.py`, `deploy/alt-linux/control/alt_deploy/setup_worker.py`,
`setup_maintenance_review_bridge.py`, `setup_cli.py`,
`deploy/alt-linux/install-backup-tool-lib.sh`, and affected installer/CLI tests.
Update `docs/ALT_SETUP_ENGINE_V2.md`, `docs/ALT_SETUP_OPERATOR_GUIDE.md` and the
existing ALT Setup acceptance report with actual results.

**Interfaces:** `QueueAdmissionReview.plan(blocked_job_id, candidate_job_id)`;
`confirm(plan_id, sha)`; `for_candidate(candidate_job_id)` returning exact
`job_ids`/`lease_ids` exclusions only after fresh validation. A separate
`validate_artifacts(root)` validates retained records without fresh execution
authority. Bridge `queue_review_service(settings)` loads trusted installed code.

- [ ] Write failing tests using the closed-full fixture and a distinct queued
  candidate: no-review/wrong-purpose, exact valid review, UUID/hostname/GUID
  collision, stale request/status/source/history, expired Setup or review plan,
  expired receipt, unsafe file, live/unknown processes, unhealthy packages,
  extra leases/provision jobs, FIFO blockage, and unchanged original records.
- [ ] Add retention/restore tests for expired and consumed reviews; add CLI
  parser/dispatcher tests and public installer copy/origin tests.
- [ ] Run new tests and observe failures caused by missing queue-review APIs.
- [ ] Factor native closure snapshot helpers to accept only the exact candidate
  exemption and a closed-job-specific immutable history scope. Preserve default
  maintenance behavior and its existing tests.
- [ ] Implement the protected queue plans/receipts, exact candidate binding and
  current source checks. Bind the shared validator and queue module hashes;
  retain all sensitive snapshots privately. Validate stored artifacts separately
  from live admission, and include them in backup history comparison.
- [ ] Add CLI commands and trusted bridge/installer module support. In worker,
  select FIFO candidate, apply fresh queue exclusions only when ordinary guards
  block, then claim once under the existing lifecycle lock and execute normally.
- [ ] Run `python3 -m pytest -q tests/alt_linux/test_setup_queue_review.py tests/alt_linux/test_setup_maintenance_review.py tests/alt_linux/test_setup_worker.py tests/alt_linux/test_setup_jobs_cli.py tests/alt_linux/test_setup_backup_compatibility.py` plus changed installer tests identified from source.
- [ ] Run the applicable ALT suite, review GitNexus impact and dynamic paths,
  inspect the whole diff, run `git diff --check`, and commit
  `feat(alt-setup): review isolated queued machine admission`.

## Publication, deployment and live acceptance

- [ ] Perform one fresh whole-branch review and address substantive findings.
- [ ] Run one full repository regression and confirm its retained exit status.
- [ ] Publish verified commits to main using the normal non-forced workflow.
- [ ] Prepare a current native maintenance review and fresh backup; verify and
  rehearse it, check actual disk space and guarded deployment prerequisites.
- [ ] Obtain applicable concrete source/review approval and deploy the verified
  runtime through the stock guarded installer. Verify installed file digests.
- [ ] Create a fresh protected Setup plan/job for the approved disposable target.
  Confirm the exact one-job queue review and monitor that same worker job handle.
- [ ] Complete actual full Setup, independent component apply/verify/noop,
  controlled interruption/status reconciliation and permitted retry, authorized
  reboot and real selected-user first login. Record limitations honestly.
- [ ] Verify all original task requirements before marking the goal complete.

## Self-review

The spec's admission, identity, TTL, locking, persistence, CLI, cancellation and
history requirements map to the two tasks. The five Review Focus cases have
explicit tests. Existing Setup execution and recovery APIs remain unchanged.
Implementation is inline in the current chat, as previously selected by the user.
