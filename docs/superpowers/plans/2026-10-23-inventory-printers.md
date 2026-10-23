# Inventory network printers implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Export SNMP-verified same-location Kyocera queues from inventory and install them using an independent idempotent Ansible playbook.

**Architecture:** A read-only inventory adapter feeds a pure bounded planner. A CLI validates/rebuilds the plan before exporting private artifacts. A standalone target helper validates UUID/MAC/TTL/PPD and manages only owned local CUPS queues through the new role.

**Tech Stack:** Python standard library, existing SQLAlchemy 2.0 models and netctl CLI, ansible-core 2.18.6, ALT CUPS 2.4.20.

**Spec:** `docs/superpowers/specs/2026-10-23-inventory-printers-design.md`, explicitly approved by the user with “Подтверждаю, реализуй и проверь”. Execution is inline by the current agent.

## Global Constraints

- First increment only: standalone playbook; no general-Setup integration.
- Read inventory only; no AD/DNS/network/firewall/reboot or historical-job changes.
- Exact location IDs, Kyocera model suffixes, unique current IP and PC MAC.
- Exact independently verified target UUID plus inventory MAC membership.
- No physical print jobs, default changes, pruning or takeover of foreign queues.
- Private driver artifacts and acceptance data stay outside Git.
- Unknown/conflicting candidates make a plan non-ready; do not silently install a subset.

## Review Focus

- Duplicate current IPs on unrelated active cards block a candidate, even outside the selected location.
- Model suffixes and SNMP serial/MAC conflicts are never normalized away.
- Export after an inventory change or new SNMP conflict fails closed.
- Existing foreign queue/name or queued jobs prevent destructive drift repair.
- Second apply and check mode preserve queues, default, source artifacts and job state.

## Task 1: Inventory planner and validated export

**Files:** create `app/inventory/printer_inventory.py`, `printer_plan.py`, `printer_cli.py`, `deploy/alt-linux/ansible/roles/inventory_printers/files/driver_catalog.json`, `tests/test_inventory_printer_plan.py`.

**Interfaces:** `read_inventory(session) -> dict`; `build_plan(snapshot, pc_id, target_uuid, probe, *, now) -> dict`; `export_plan(plan, snapshot, probe, source_dir, destination, *, now) -> dict`.

- [x] Write tests for location isolation, identity binding, duplicate IP/MAC, exact supported models, unknown/status/network gates, SNMP conflict/timeout, changed/stale/tampered plan and PPD validation.
- [x] Run `python -m pytest tests/test_inventory_printer_plan.py -q`; observe missing implementation failures.
- [x] Implement pure bounded planner, versioned curated manifest and read-only SQLAlchemy adapter. Export rebuilds inventory/SNMP selection, verifies the approved fingerprint and driver hashes, and creates a new private bundle.
- [x] Run planner tests plus existing inventory/SNMP regressions; require all selected checks pass.

## Task 2: CUPS helper and standalone playbook

**Files:** create role `deploy/alt-linux/ansible/roles/inventory_printers/{tasks,defaults,files}`, playbook `07-inventory-printers.yml`, and `tests/test_inventory_printer_runtime.py`.

**Interfaces:** target helper mode `validate|check|apply` with a bounded structured document on stdin, JSON result `{status, changed, queues}`. Role consumes `inventory_printer_request`, `inventory_printer_driver_dir`, and fixed published helper bytes.

- [x] Write failing runtime tests for TTL, target UUID/MAC, malformed/foreign queues, unsafe PPDs, busy repair, exact URI/options, no-op second apply and read-only check.
- [x] Implement validation before queue mutation, local CUPS-only argv calls, private receipts/ownership markers, pending-job guard and semantic PPD comparison after CUPS normalization.
- [x] Implement role with validation before package/service changes and check-mode support. Keep all other Setup roles and controller state untouched.
- [x] Run both test files, Ansible syntax/check mode and relevant existing role regressions.

## Task 3: Native acceptance and delivery

**Files:** create `docs/runbooks/inventory-printers.md` and sanitized `docs/verification/INVENTORY_PRINTERS_2026-10-24.md`; update operator guide with standalone scope.

- [x] Verify VM 133 UUID/MAC/SSH public key through the trusted guest agent; pin a dedicated key file, save existing queues/default and create a pre-test snapshot.
- [x] Build a private temporary inventory fixture with VM PC identity and the copied selected printer/location; probe the real selected printer through netctl. Preserve provenance outside Git.
- [x] Export verified bundle, run syntax/check, first apply, second apply (`changed=0`), owned drift repair and identity/foreign/busy rejection cases. Compare original queues/default and verify no print submission.
- [x] Validate PPD syntax and available conversion chain; record physical output as untested. Record Pantum package/PPD/filter research without installing it.
- [x] Run exact final regression commands and `git diff --check`; obtain fresh whole-change review and fix material findings with tests.
- [ ] Commit only task files, publish verified work to main following repository policy, report commit SHA, included files, checks and native-test limits.

## Execution ledger

- Design approved. Ruling: implement inline without another routine approval stop because the user explicitly authorized implementation and test of this exact design.
- Worktree starts at `d9924d680182ee1796e1f3bfb40da13a9403e143`; unrelated screenshots remain in the original checkout.

- Task 1: complete; planner RED failures became GREEN. Final scoped suite: 92 passed, 1 Linux-only skip; the skipped test passed separately on ALT.
- Task 2: complete; native first apply changed=1, repeat changed=0, owned drift repaired, source driver conformance and PDF conversion passed.
- Task 3: acceptance and fresh code review complete; publication follows this recorded checkpoint. See the 2026-10-24 report for exact evidence and limits.
- Ruling: keep the catalog restricted to M2030dn after strict native rejection of four supplied PPDs; this limits automatic model coverage but avoids unverified driver installation.
- Ruling: keep existing scheduler enablement and use the peer-authenticated Unix socket; existing service policy remains intact.
- Ruling: send structured JSON directly to fixed helper code instead of persistent target staging files; all driver hashes and input are validated before queue writes.
- Final review: fixed unavailable-scheduler dry-run issue with a RED-to-GREEN regression; no deferred minor findings.
