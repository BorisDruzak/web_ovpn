# ALT Manual Ansible MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Provision a manually installed ALT Workstation through one verified bootstrap and one fixed, safe domain-configuration Ansible scenario.

**Architecture:** Preserve the legacy autoinstall and local-account flows. Add a synchronous `workstationctl configure` path which resolves a registered UUID to an IP, validates a closed request schema, executes only the new playbook with strict SSH, and records a private bounded run log.

**Tech Stack:** Python 3, pytest, Bash, Ansible, Ansible Vault, ALT Linux K 11.x, OpenSSH.

## Global Constraints

- Base the branch on `origin/main` commit `1d2f9995ffc5fd9a9ff67ff30fa6584d4dc7288e`.
- Preserve managed ISO/install-agent/install-session and existing `provision` semantics.
- Never modify an existing assignment, active job, registration, known-host entry, or `test-user`.
- Never accept arbitrary playbooks, inventories, shell commands, IPs or Ansible extra vars.
- Use `MachineRepository` UUID-to-IP lookup, `ansible` target user, strict host-key checking and the existing controller identity.
- Vault values and credentials must not reach CLI arguments, request JSON, environment, output or logs.
- Do not execute a live mutation without a specific operator approval.

---

### Task 1: Bootstrap trust and readiness contract

**Files:**
- Modify: `deploy/alt-linux/bootstrap/bootstrap.sh`
- Test: `tests/alt_linux/test_manual_bootstrap.py`

**Interfaces:**
- Consumes: `ALT_DEPLOY_HOST`, `ALT_ANSIBLE_AUTHORIZED_KEY_SHA256`.
- Produces: idempotent `ansible` SSH/sudo readiness and registration.

- [ ] Write tests that assert root validation precedes network access, `ALT_DEPLOY_HOST` has the documented default, an SHA-256 fingerprint is required for manual key download, and the sudoers file is checked with `visudo` and `sudo -n true`.
- [ ] Run the test and confirm RED because the bootstrap has no configurable host or key fingerprint check.
- [ ] Add the smallest script helpers for release/network/controller validation, key fingerprint validation, and registration-only rerun.
- [ ] Run `bash -n deploy/alt-linux/bootstrap/bootstrap.sh` and the focused test.
- [ ] Commit: `feat(alt): harden manual bootstrap`.

### Task 2: Closed configure-request model

**Files:**
- Create: `deploy/alt-linux/control/alt_deploy/configure.py`
- Modify: `deploy/alt-linux/control/alt_deploy/config.py`
- Test: `tests/alt_linux/test_configure_request.py`

**Interfaces:**
- Consumes: JSON object from `--vars-file` and UUID positional argument.
- Produces: `ConfigureRequest.from_payload(machine_uuid, payload)` and public plan mapping.

- [ ] Write tests for the valid request and each rejection: unknown field, secret field, wrong domain constants, invalid hostname, missing OU/workgroup/test user, and UUID mismatch.
- [ ] Run the focused test and confirm RED because `alt_deploy.configure` does not exist.
- [ ] Implement an immutable request model and explicit allowlist validation; preserve only safe values.
- [ ] Run the focused test and controller compilation.
- [ ] Commit: `feat(alt): validate domain configure requests`.

### Task 3: Controller configure preview and synchronous runner

**Files:**
- Modify: `deploy/alt-linux/control/alt_deploy/ansible.py`
- Modify: `deploy/alt-linux/control/alt_deploy/cli.py`
- Modify: `deploy/alt-linux/control/alt_deploy/config.py`
- Create: `deploy/alt-linux/control/alt_deploy/configure.py`
- Test: `tests/alt_linux/test_configure_controller.py`

**Interfaces:**
- Consumes: `ConfigureRequest`, `MachineRepository`, `VaultHealthChecker`, fixed playbook path.
- Produces: JSON preview/start result and per-run `0600` log under a `0700` directory.

- [ ] Write RED tests proving UUID resolves to registered IP, the runner has `-i <ip>,`, `-u ansible`, strict SSH arguments and exactly `03-configure-domain-workstation.yml`.
- [ ] Add RED tests proving preview has no runner call or persistent run record, and a pre-existing assignment is neither read as a conflict nor changed.
- [ ] Implement the configure controller with a generated run ID, safe request file, bounded log reader, fixed Ansible command and error-code mapping.
- [ ] Add CLI parsers for `configure preview` and `configure start`; do not alter `provision` commands.
- [ ] Run focused tests, `py_compile deploy/alt-linux/control/alt_deploy/*.py`, and commit: `feat(alt): add fixed domain configure command`.

### Task 4: Domain playbook assets and preflight

**Files:**
- Create: `deploy/alt-linux/ansible/playbooks/03-configure-domain-workstation.yml`
- Create: `deploy/alt-linux/ansible/roles/manual_preflight/tasks/main.yml`
- Create: `deploy/alt-linux/ansible/roles/workstation_base/tasks/main.yml`
- Create: `deploy/alt-linux/ansible/roles/workstation_network/tasks/main.yml`
- Modify: `deploy/alt-linux/ansible/group_vars/all.yml`
- Test: `tests/alt_linux/test_domain_ansible_assets.py`

**Interfaces:**
- Consumes: safe configure request and non-secret group vars.
- Produces: controlled preflight facts and `manual_preflight_failed`, DNS/time gates.

- [ ] Write RED tests for exact role order, explicit Vault loading, no `local_employee`/`lightdm_accounts`, variable package lists and no unsafe shell patterns.
- [ ] Write RED tests requiring ALT 11.x/UUID/ansible sudo/route/free-space/DNS/time checks while forbidding `osn-admin` and LightDM prerequisites.
- [ ] Implement the playbook and roles with command `argv` lists and package variables initially empty pending live package discovery.
- [ ] Run focused tests and `ansible-playbook --syntax-check` with the project configuration.
- [ ] Commit: `feat(alt): add manual domain preflight assets`.

### Task 5: Network, domain join, packages and verification roles

**Files:**
- Create: `deploy/alt-linux/ansible/roles/domain_join/tasks/main.yml`
- Create: `deploy/alt-linux/ansible/roles/standard_software/tasks/main.yml`
- Create: `deploy/alt-linux/ansible/roles/domain_verify/tasks/main.yml`
- Modify: `deploy/alt-linux/ansible/group_vars/all.yml`
- Modify: `deploy/alt-linux/ansible/group_vars/vault.yml.example`
- Test: `tests/alt_linux/test_domain_ansible_assets.py`

- [ ] Write RED tests requiring `no_log: true` on credential tasks, no password in command arguments, `kdestroy`, idempotent joined-domain detection, different-domain conflict and public verification fields.
- [ ] Implement only the ALT-native mechanism confirmed by the preceding read-only audit; do not infer package names or enable repositories.
- [ ] Implement package installation from `domain_prerequisite_packages`, `standard_packages` and `organization_packages` variables.
- [ ] Run focused tests, all three Ansible syntax checks, and commit: `feat(alt): configure standard domain workstation`.

### Task 6: Operator documentation and verification gates

**Files:**
- Create: `docs/ALT_MANUAL_ANSIBLE_MVP.md`
- Modify: `deploy/alt-linux/README.md`
- Test: `tests/alt_linux/test_provisioning_docs.py`

- [ ] Document manual installation, SHA-256 key verification, registration, runtime Vault setup, request JSON, preview/start, reboot, diagnostics, retry, rollback and explicit non-goals.
- [ ] State that this is an additional path, not a replacement for managed ISO.
- [ ] Run `python -m pytest -q tests/alt_linux`, compilation, Bash syntax, three Ansible syntax checks, `git diff --check`, and record Windows POSIX-only skips exactly.
- [ ] Before live mutation, present a read-only audit of `alt-auto-test`; require a separate approval for bootstrap, preview and join.
- [ ] Commit: `docs(alt): document manual Ansible MVP`.
