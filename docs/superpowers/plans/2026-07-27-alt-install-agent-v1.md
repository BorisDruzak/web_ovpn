# ALT install-agent V1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and validate a non-destructive signed-plan initrd agent, then deploy its controller API only after its integration gates pass.

**Architecture:** PR4a makes controller session lifecycle and Go verification deterministic with shared fixtures. PR4b consumes those contracts in an initrd overlay and proves zero writes in QEMU. PR5 deploys only the server-side API/control assets.

**Tech Stack:** Python 3.12, Go 1.22, POSIX shell, Go standard library, pytest, QEMU/QMP, GitHub Actions.

## Global Constraints

- No `install2.target`, Alterator, partitioning, target-disk write, reboot, secrets bundle, or first boot continuation.
- Source ALT ISO identity remains `2529f98bca03a652709434a6a17cd4aac5df20c0793927abdf784e8f9388243a`.
- The helper is CGO-free, amd64 Linux and standard-library-only.
- All bearer credentials and local plan state remain under `/run/alt-install` with private modes.
- PR5 deployment is blocked until PR4b CI and manual QEMU dry-run evidence pass.

---

### Task 1: PR4a session protocol lifecycle

**Files:** controller repository/service/API/session tests and PR3 documentation.

- [ ] Write failing API tests for `create_nonce` replay, nonce mismatch, expiration and `preflight_ready`.
- [ ] Add nonce digest persistence, safe idempotent create, expiry state and bounded heartbeat vocabulary.
- [ ] Run focused install-session tests and commit `feat: harden install session protocol v1`.

### Task 2: PR4a Go helper and shared vectors

**Files:** `deploy/alt-linux/install-agent/helper/`, Go tests, Python golden fixtures/tests and CI workflow.

- [ ] Write failing Go tests for exact inventory canonicalization, duplicate JSON rejection, signature mutation and disk preflight mismatch.
- [ ] Implement strict parser, inventory collector, verifier, preflight and deterministic build command.
- [ ] Generate shared fixtures from the checked-in PR3 contract; run `go test ./...` and Python vectors; commit `feat: add ALT install helper`.

### Task 3: PR4b initrd agent and ISO verification

**Files:** agent V1 shell modules, initrd overlay V1, ISO builder/verifier and contract tests.

- [ ] Write failing agent contract tests for private state, transport retry, redirect rejection and terminal hold.
- [ ] Implement Bash orchestration around helper commands and fixed endpoint configuration.
- [ ] Embed source ISO/public-key manifests and helper, verify modes/checksums, run static tests; commit `feat: add signed-plan initrd agent`.

### Task 4: PR4b QEMU dry-run evidence

**Files:** readonly acceptance harness, test API fixture and acceptance tests/docs.

- [ ] Write failing acceptance contract tests for writable target QMP zero-write evidence and final PASS line.
- [ ] Implement disposable writable and readonly QEMU variants, temporary keys/API and root approval sequence.
- [ ] Run manual QEMU acceptance; archive only non-secret evidence; commit `test: prove agent dry-run safety`.

### Task 5: PR5 deployment

**Files:** dedicated API launcher/systemd asset, installer/rollback runbook and deployment checks.

- [ ] Write failing static deployment contract tests for non-root service, private session ownership, binding and no private key in repository.
- [ ] Implement deployment assets without generating a production private key.
- [ ] After explicit key provisioning on `.17`, deploy, run health checks and record rollback evidence; commit `feat: deploy ALT session API`.
