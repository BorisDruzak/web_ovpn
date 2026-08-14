# ALT First-Login Orchestrator Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn one root invocation of `start-bootstrap.sh` into an auditable, automatic workstation flow ending in user-profile finalization after the selected employee's first AD login.

**Architecture:** Bootstrap carries a syntactically validated UPN as non-secret registration metadata. The controller validates that identity through an Ansible localhost AD query, runs a device-only configure playbook, performs one final reboot, and persists an orchestration record. A timer-driven reconciler observes durable `pam_mkhomedir` evidence and starts an idempotent post-login playbook for only the selected account.

**Tech Stack:** Bash, Python 3 standard library, Ansible, systemd service/timer/path units, existing Ansible Vault and SSSD.

## Global Constraints

- Do not store, log, or transmit an employee password.
- Keep managed ISO and existing registration-only bootstrap compatibility unchanged.
- Do not create an AD user or delete/reuse a computer object.
- Do not create an AD home before a successful AD login.
- One reboot maximum for a normal fresh workstation: after the device/domain stage.
- All public errors are bounded safe codes; Vault values and KRFB passwords remain `no_log`.

---

### Task 1: Capture the selected AD identity without changing bootstrap trust boundaries

**Files:**
- Modify: `deploy/alt-linux/bootstrap/start-bootstrap.sh`
- Modify: `deploy/alt-linux/bootstrap/bootstrap.sh`
- Modify: `deploy/alt-linux/bootstrap/alt-bootstrap-register`
- Modify: `deploy/alt-linux/control/alt_deploy/registration_admission.py`
- Test: `tests/alt_linux/test_start_bootstrap_launcher.py`
- Test: `tests/alt_linux/test_alt_bootstrap_register.py`
- Test: `tests/alt_linux/test_registration_admission.py`

**Interfaces:**
- Produces registration field `assigned_domain_user: str | null`, normalized lowercase UPN.
- `start-bootstrap.sh` exports `ALT_ASSIGNED_DOMAIN_USER`; only `bootstrap.sh` passes it to its registration helper.

- [ ] Write failing tests that require a UPN prompt, reject malformed values before download, and assert the registration JSON includes a normalized UPN but no password-like field.
- [ ] Run the selected Linux tests and confirm the prompt/field assertions fail against current sources.
- [ ] Add `read -r -p` UPN capture with the existing `sosnadmin.local` validation expression; pass it only through environment to the helper.
- [ ] Extend `RegistrationRequest` and its persisted record with an optional normalized UPN; preserve legacy requests that omit it.
- [ ] Run `pytest -q tests/alt_linux/test_start_bootstrap_launcher.py tests/alt_linux/test_alt_bootstrap_register.py tests/alt_linux/test_registration_admission.py` and commit `feat(alt): capture assigned domain user at bootstrap`.

### Task 2: Validate the AD user on the controller before domain join

**Files:**
- Create: `deploy/alt-linux/ansible/playbooks/00-validate-assigned-domain-user.yml`
- Create: `deploy/alt-linux/ansible/roles/ad_assigned_user_validation/tasks/main.yml`
- Modify: `deploy/alt-linux/api/process_pending.py`
- Test: `tests/alt_linux/test_pending_auto_configure.py`
- Test: `tests/alt_linux/test_ansible_resilience_contract.py`

**Interfaces:**
- Consumes `assigned_domain_user` and existing Vault join credentials.
- Produces exactly one of `assigned_domain_user_valid` or `assigned_domain_user_not_found`.

- [ ] Write failing tests requiring the validation playbook to use `kinit` plus GSSAPI `ldapsearch` under `no_log`, and requiring `process_pending` to stop before `configure start` on an invalid user.
- [ ] Run the targeted tests and verify the missing validator/state assertion fails.
- [ ] Implement the localhost Ansible playbook: query `(&(objectClass=user)(userPrincipalName=<UPN>))`, write only a boolean result file, and always destroy the Kerberos ticket.
- [ ] Invoke it from `process_pending`; reject unknown or malformed UPNs with `assigned_domain_user_not_found` and preserve technical registration.
- [ ] Run the targeted tests and commit `feat(alt): validate assigned AD user before join`.

### Task 3: Generate the standard configure request from approved controller defaults

**Files:**
- Modify: `deploy/alt-linux/api/process_pending.py`
- Modify: `deploy/alt-linux/control/alt_deploy/configure.py`
- Modify: `deploy/alt-linux/ansible/group_vars/all.yml`
- Test: `tests/alt_linux/test_pending_auto_configure.py`
- Test: `tests/alt_linux/test_configure_resilience.py`

**Interfaces:**
- `build_auto_configure_request(record) -> dict[str, object]` uses registered hostname, UUID, selected UPN, and fixed domain policy.
- Existing `/srv/alt-deploy/configure-requests/<uuid>.json` remains supported and takes precedence.

- [ ] Write failing tests for a registration with UPN and no request file producing an exact validated standard-domain request; assert a legacy registration still ends `awaiting_assignment`.
- [ ] Run targeted tests and confirm auto construction is absent.
- [ ] Add policy constants for OU Pilot, GPO domain, `core-apps`, and `krfb`; build and validate the request through `ConfigureRequest.from_mapping`.
- [ ] Keep arbitrary request fields rejected and retain explicit request-file precedence.
- [ ] Run targeted tests and commit `feat(alt): auto-build configure request from registration`.

### Task 4: Split device setup from user-profile setup and defer reboot

**Files:**
- Modify: `deploy/alt-linux/ansible/playbooks/03-configure-domain-workstation.yml`
- Create: `deploy/alt-linux/ansible/playbooks/04-configure-domain-user-profile.yml`
- Modify: `deploy/alt-linux/ansible/roles/prejoin_upgrade/tasks/main.yml`
- Modify: `deploy/alt-linux/ansible/roles/desktop_shortcuts/tasks/main.yml`
- Modify: `deploy/alt-linux/ansible/roles/remote_access_krfb/tasks/main.yml`
- Create: `deploy/alt-linux/ansible/roles/desktop_shortcuts_user/tasks/main.yml`
- Create: `deploy/alt-linux/ansible/roles/remote_access_krfb_user/tasks/main.yml`
- Test: `tests/alt_linux/test_ansible_resilience_contract.py`

**Interfaces:**
- Device stage writes `/etc/skel` only and reports `system_reboot_required: bool`.
- User stage requires an existing selected home and returns structured profile verification.

- [ ] Write failing asset tests proving `prejoin_upgrade` does not call `ansible.builtin.reboot`, that skeleton work stays in stage 03, and user-home/KRFB writes occur only in stage 04.
- [ ] Run the test and confirm it fails against the present combined roles.
- [ ] Move current-user shortcut/KRFB tasks into user-only roles; do not create a home in either stage.
- [ ] Add a final device-stage reboot task conditioned on `prejoin_upgrade_reboot_required or domain_join_changed`; preserve result persistence before any terminal error.
- [ ] Run Ansible syntax checks plus contract tests and commit `feat(alt): split device and first-login profile stages`.

### Task 5: Add durable orchestration records and a post-login reconciliation worker

**Files:**
- Create: `deploy/alt-linux/control/alt_deploy/first_login_orchestrator.py`
- Create: `deploy/alt-linux/api/reconcile_first_login.py`
- Create: `deploy/alt-linux/systemd/alt-deploy-first-login.service`
- Create: `deploy/alt-linux/systemd/alt-deploy-first-login.timer`
- Modify: `deploy/alt-linux/install-control-plane-lib.sh`
- Modify: `deploy/alt-linux/control/alt_deploy/config.py`
- Test: `tests/alt_linux/test_first_login_orchestrator.py`
- Test: `tests/alt_linux/test_install_assets.py`

**Interfaces:**
- `FirstLoginOrchestrator.reconcile() -> dict[str, object]` scans private records.
- Record states: `awaiting_first_domain_login`, `configuring_user_profile`, `ready`, `degraded`, `failed`.

- [ ] Write failing unit tests for first matching home detection, UID/GID mismatch rejection, no-op after `profile-finalized`, and recovery of a stale `configuring_user_profile` record.
- [ ] Run the new unit test and verify collection/import fails because the module is absent.
- [ ] Implement safe record reads/writes under a per-machine lock; use SSH `getent passwd` and `stat` through the existing restricted Ansible connection, then launch stage 04 only once.
- [ ] Add service/timer sandboxing and install/enable them through the guarded installer; grant only required state, SSH, and Ansible paths.
- [ ] Run unit/install tests and commit `feat(alt): reconcile first domain login profiles`.

### Task 6: Persist automatic system-stage outcome and document operator flow

**Files:**
- Modify: `deploy/alt-linux/api/process_pending.py`
- Modify: `deploy/alt-linux/README.md`
- Modify: `docs/runbooks/alt-manual-bootstrap-mvp.md`
- Test: `tests/alt_linux/test_pending_auto_configure.py`
- Test: `tests/alt_linux/test_manual_bootstrap_mvp_docs.py`

**Interfaces:**
- Successful device configure with an assigned user writes `awaiting_first_domain_login` rather than terminal `configured`.
- Failed AD validation, system configure, and user profile stages retain their distinct safe error code.

- [ ] Write failing tests for state progression from registration through `awaiting_first_domain_login` and for docs containing the one-command/no-password contract.
- [ ] Run the tests and confirm current `configured` terminal behavior fails them.
- [ ] Persist the initial configure result and orchestration record atomically; trigger the reconciler after reboot recovery and never rerun domain join from it.
- [ ] Update README and runbook with exact root command, expected reboot, sign-in instruction, machine status commands, and recovery semantics.
- [ ] Run focused tests and commit `feat(alt): complete automatic post-login workflow`.

### Task 7: Verify and canary rollout

**Files:**
- Modify: `docs/ALT_WORKSTATION_OPERATIONAL_RELIABILITY_HANDOFF.md`
- Test: `tests/alt_linux`

- [ ] Run `python3 -m pytest -q tests/alt_linux` on the Linux controller and `ansible-playbook --syntax-check` for stages 03 and 04.
- [ ] Deploy via `install-control-plane.sh` using an already rehearsed rollback backup; confirm controller readiness and timer status.
- [ ] On a fresh test device run only the root launcher, supply an existing AD UPN, confirm one reboot, first domain login, profile completion, and `ready` record.
- [ ] Record the canary evidence and rollback command in the handoff document, then commit `docs(alt): record first-login orchestrator canary`.
