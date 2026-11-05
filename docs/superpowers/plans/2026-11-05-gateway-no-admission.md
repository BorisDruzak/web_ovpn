# Gateway No-Admission Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans inline; request one
> fresh whole-branch code review before publishing or deployment.

**Goal:** Safely continue the selected workstation after a timed-out apply
which never received a native job admission.

**Architecture:** Align apply with the bounded planning transport budget. Add
an explicit operator review of expired unadmitted compatibility-successor
requests, retaining all UNKNOWN history and the ordinary fresh-plan gates.

**Tech Stack:** Existing Python 3.12, pytest, native locks/receipts, SSH gateway.

**Spec:** `docs/superpowers/specs/2026-11-05-gateway-no-admission-design.md`

## Global Constraints

- No callback replay, receipt/job relabelling, claim release, or target writes by review.
- Scope only terminal UNKNOWN V2 full-setup compatibility-successor requests.
- Require expired original plan, real ownership locks and positive live local proof.
- Keep the 300-second gateway alarm and 310-second client budget bounded.
- Preserve unrelated files, other backups, app data, credentials and operation leases.

## Review Focus

- A missing claim without terminal receipt/expired plan is not proof of no submission.
- Review must reject orphan jobs/reservations and a changed predecessor or target.
- A reviewed fact must not authorize reuse of the old plan or an automatic retry.
- Backup restore must retain old UNKNOWN receipts and review artifacts.
- Client timeouts must still preserve request identity and uncertainty after submission.

## Task 1: Bounded transport

- [ ] Add a timeout-selection regression test and observe RED for apply=30.
- [ ] Use 310 seconds for plans.apply; verify unchanged deadlines/SSH/uncertainty.
- [ ] Run client/API regression tests; inspect diff and commit independently.

## Task 2: Native no-admission fact

- [ ] Add native tests using real protected failed-prejoin fixture/receipt/locks;
  cover plan/confirm, immutable history, expiry, missing/orphan claims, tampering,
  live proof failures, and conservative restore; observe RED.
- [ ] Add focused backup-side review module, trusted CLI adapter and operator commands.
- [ ] Extend optional artifact/history validation and backup-tool public module copy.
- [ ] Run native/regression tests and fresh review; fix important findings with TDD.
- [ ] Publish verified source to main; preserve exact code and operation identifiers.

## Task 3: Guarded live continuation

- [ ] Stage exact trusted source, install compatible backup validators, review the
  original expired UNKNOWN request without replay and confirm the exact fact SHA.
- [ ] Refresh controller maintenance review and rollback backup, verify/rehearse,
  install the exact controller and panel change through normal procedures.
- [ ] Obtain a fresh same-identity plan, apply one retained new request after review,
  watch complete events to reboot/login and functional acceptance.
