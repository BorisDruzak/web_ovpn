# Selective ALT release verification implementation plan

> **For agentic workers:** Use superpowers:executing-plans inline, with one fresh whole-branch review.

**Goal:** Avoid the full test suite for isolated component releases.
**Architecture:** Explicit conservative change-to-test matrix, root-private verified snapshot baseline and exact-source proofs; unknown/shared inputs force full.
**Tech Stack:** Python3.12, existing PyYAML/pytest/Ansible worker and Bash installer.
**Spec:** docs/superpowers/specs/2026-11-05-selective-alt-verification.md

## Constraints and review focus

- Preserve all native live/backup/rollout admission and UNKNOWN history.
- No manually asserted/imported baseline and no arbitrary release test lists.
- Component test edits and helper additions select the entire coupled group; shared fixtures, removal, permissions and unknown paths force full.
- Revocation, corruption, stale resume, environment/policy drift and concurrent attempts must never reuse false evidence.
- Include standalone component integration tests in full coverage and audit role-to-test references.

## Task 1: Automatic scope and evidence

- [x] Write failing classifier and snapshot/receipt tests; run RED in the shared ALT environment.
- [x] Implement explicit policy, strict immutable proof persistence, auto/full/plan/resume and failure invalidation.
- [x] Wire CLI, same worker targets, forced-full installer option and sandbox regressions; run focused GREEN including all installer tests.
- [x] Update operator/runbook documentation and request one whole-branch review; fix important findings with RED/GREEN.
- [ ] Freeze exact source; run one full suite to bootstrap the new authority. Run real selective synthetic-candidate acceptance and global-change --plan fallback, then restore the real source through native full resume.
- [ ] Publish verified main, deploy via canonical backed-up installer, verify installed readiness/history/service state, export evidence and clean only this plan's scratch.

Final commands, source identity and delivery evidence are exported outside the
frozen source under Documents/ad-policy-audit/2026-11-05/Selective-ALT-verification-delivery.md.
