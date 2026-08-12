# ALT Bootstrap Resilience Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Provide a rerunnable bootstrap that preserves valid DHCP configuration, restores technical Ansible access and automatically starts the controller-owned domain configuration for a pre-created UUID-bound request.

**Architecture:** bootstrap.sh owns technical access, local status and a bounded deferred registration unit. alt-bootstrap-register stays responsible only for the non-secret controller payload. A removable-media launcher downloads and executes the canonical script without containing credentials.

**Tech Stack:** POSIX shell/Bash, systemd, NetworkManager or etcnet, Ansible controller HTTP endpoint, pytest shell-contract tests.

## Global Constraints

- Support only ALT Workstation K 11.x based on major version 11.
- Preserve existing DHCP, DNS, routes and hostname; do not invent network policy.
- Do not log or persist passwords, AD credentials, Vault values or private keys.
- Use controller IP for bootstrap reachability; HTTPS migration is outside the MVP contract.
- Never execute domain join from bootstrap.

---

### Task 1: Bootstrap state contract

**Files:**
- Create: tests/alt_linux/test_bootstrap_resilience_contract.py
- Modify: deploy/alt-linux/bootstrap/bootstrap.sh

**Interfaces:**
- Consumes: bootstrap.sh
- Produces: root-only status, a run lock and staged sudo validation.

- [ ] Step 1: Write failing tests asserting that bootstrap.sh contains /var/lib/alt-bootstrap/status, pending_registration, flock, and validates a temporary sudoers file with visudo before installing the managed sudoers file.
- [ ] Step 2: Run pytest tests/alt_linux/test_bootstrap_resilience_contract.py -q and confirm the assertions fail against the current script.
- [ ] Step 3: Add the smallest state helpers, file lock and install_validated_sudoers function satisfying the tests.
- [ ] Step 4: Re-run the focused test and bash -n deploy/alt-linux/bootstrap/bootstrap.sh.
- [ ] Step 5: Commit the test and implementation with message feat(alt): add resilient bootstrap state contract.

### Task 2: Existing DHCP recovery

**Files:**
- Modify: deploy/alt-linux/bootstrap/bootstrap.sh
- Modify: tests/alt_linux/test_bootstrap_resilience_contract.py

**Interfaces:**
- Consumes: current default route, NetworkManager connection data or /etc/net/ifaces/<iface>.
- Produces: ensure_network_ready, returning success only after a route, global IPv4 and controller TCP check.

- [ ] Step 1: Write a failing test asserting the bootstrap can use nmcli connection up and systemctl restart network, but contains no resolver-writing operation.
- [ ] Step 2: Run the focused test and confirm it fails.
- [ ] Step 3: Implement ensure_network_ready: check first; re-activate only the known NetworkManager connection or etcnet service if missing; then re-check with bounded retry.
- [ ] Step 4: Run bash -n and the focused test.
- [ ] Step 5: Commit with message feat(alt): recover existing bootstrap network.

### Task 3: Deferred registration

**Files:**
- Create: deploy/alt-linux/bootstrap/alt-bootstrap-registration-retry.service
- Create: deploy/alt-linux/bootstrap/alt-bootstrap-registration-retry.timer
- Modify: deploy/alt-linux/bootstrap/bootstrap.sh
- Modify: tests/alt_linux/test_bootstrap_resilience_contract.py

**Interfaces:**
- Consumes: /usr/local/sbin/alt-bootstrap-register and root-only bootstrap status.
- Produces: a systemd timer with a finite retry limit and no credential input.

- [ ] Step 1: Write failing tests that require network-online.target and reject secret ALT environment values in the retry unit.
- [ ] Step 2: Run the focused test and confirm missing unit files fail.
- [ ] Step 3: Install root-owned units, set pending_registration after exhausted immediate attempts, and clear timer plus status when registration succeeds.
- [ ] Step 4: Run bash -n for both shell files and the focused test.
- [ ] Step 5: Commit with message feat(alt): defer bootstrap registration safely.

### Task 4: Automatic controller handoff

**Files:**
- Modify: deploy/alt-linux/api/process_pending.py
- Modify: deploy/alt-linux/control/alt_deploy/config.py
- Modify: deploy/alt-linux/install-control-plane-lib.sh
- Modify: deploy/alt-linux/systemd/alt-deploy-process.service
- Modify: tests/alt_linux/test_process_pending.py

**Interfaces:**
- Consumes: /srv/alt-deploy/configure-requests/<machine-uuid>.json and ConfigureRequest.
- Produces: configured or configure_failed registration records with the ConfigurePlanner run ID.

- [ ] Step 1: Write failing tests for a ready registration with a UUID-bound valid request, absent request, invalid request and planner failure.
- [ ] Step 2: Run the focused process-pending tests and confirm failure because the worker stops at awaiting_assignment.
- [ ] Step 3: Add a private configure-request directory, validate only the matching UUID request, run preview then start, and write a typed result without secrets.
- [ ] Step 4: Permit the systemd worker to read the request directory and add installation checks for its ownership and mode.
- [ ] Step 5: Run focused controller tests and commit with message feat(alt): auto-configure registered workstations.

### Task 5: Controller-served launcher

**Files:**
- Create: deploy/alt-linux/bootstrap/start-alt-bootstrap.sh
- Modify: docs/runbooks/alt-manual-bootstrap-mvp.md
- Modify: tests/alt_linux/test_bootstrap_resilience_contract.py

**Interfaces:**
- Consumes: ALT_DEPLOY_HOST and the canonical bootstrap HTTP URL.
- Produces: start-alt-bootstrap.sh downloaded from the controller.

- [ ] Step 1: Write a failing test requiring mktemp, mode 0700, bash -n and cleanup in the launcher.
- [ ] Step 2: Run the focused test and confirm it fails because the launcher is absent.
- [ ] Step 3: Implement a root-only launcher that downloads, syntax-checks, invokes and removes the temporary bootstrap.
- [ ] Step 4: Run bash -n on the launcher plus bootstrap tests on Linux.
- [ ] Step 5: Commit with message docs(alt): add removable media bootstrap launcher.

## Self-Review

- The five tasks cover state, DHCP recovery, deferred registration, automatic controller handoff and a short controller-served command.
- No task changes AD, application provisioning, hostname or controller secrets.
- Every implementation task begins with a failing test and has a Linux verification command.
