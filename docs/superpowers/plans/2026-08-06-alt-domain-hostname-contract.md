# ALT manual domain hostname contract Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make manual ALT domain configuration enforce the approved ALT 11.x, hostname-mode, AD-computer-conflict and domain-login contract.

**Architecture:** The controller validates public request data and invokes only the existing fixed playbook. Ansible owns target-state checks and mutations: it reads modern ALT identity metadata, verifies or explicitly changes the hostname, detects an existing AD computer through Kerberos, then uses the delegated join path. Stable Ansible markers are mapped to public controller codes without exposing logs or secrets.

**Tech Stack:** Python 3, pytest, Ansible YAML, ALT system-auth, Samba/Kerberos/SSSD, Markdown.

## Global Constraints

- Accept ALT Workstation K from `/etc/os-release` with `VERSION_ID` beginning `11.`; do not gate on minor version or legacy `/etc/altlinux-release`.
- Hostname grammar: `^(lin|alt|win|deb)-[a-z][0-9]?-(pc[1-9][0-9]*)$`.
- The only modes are `verify` and `change_confirmed`; implicit renames are forbidden.
- Never accept an arbitrary playbook, inventory, command, target IP or credential.
- Never delete, reset, move or reuse an AD computer object.
- Do not run a mutating controller command or alter AD while verifying this change.

---

### Task 1: Request schema and public failure mapping

**Files:**
- Modify: `deploy/alt-linux/control/alt_deploy/configure.py`
- Modify: `tests/test_alt_manual_configure_request.py`

**Interfaces:**
- Consumes: the JSON passed to `ConfigureRequest.from_mapping`.
- Produces: `ConfigureRequest.hostname_mode: str`, `hostname_invalid` for malformed names, and mapped `hostname_mismatch` / `domain_computer_conflict` target markers.

- [ ] **Step 1: Write failing request tests**

```python
payload = valid_request()
payload["final_hostname"] = "alt-a1-pc3"
payload["hostname_mode"] = "verify"
assert ConfigureRequest.from_mapping(payload, expected_uuid=MACHINE_UUID).hostname_mode == "verify"
```

Add invalid names `alt_ws_001`, `alt-a11-pc3`, `ubuntu-a1-pc3`, and `alt-a1-pc0`; assert `hostname_invalid`. Add a mocked failed Ansible run whose private log contains `ALT_PREFLIGHT_FAILURE:hostname_mismatch` and assert the public error code has that exact value and exposes only the run ID.

- [ ] **Step 2: Run the test to verify it fails**

Run: `python -m pytest -q tests/test_alt_manual_configure_request.py`

Expected: FAIL because `hostname_mode` is currently unknown and the generic hostname pattern accepts/rejects the wrong set.

- [ ] **Step 3: Implement the minimal controller change**

Add `hostname_mode` to the exact request schema and dataclass. Validate the approved hostname grammar before target access with a dedicated `hostname_invalid` error. On a failed playbook, inspect its bounded private log and map only exact `ALT_PREFLIGHT_FAILURE:` markers; retain `domain_join_failed` for all unknown failures.

- [ ] **Step 4: Run the test to verify it passes**

Run: `python -m pytest -q tests/test_alt_manual_configure_request.py`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add deploy/alt-linux/control/alt_deploy/configure.py tests/test_alt_manual_configure_request.py
git commit -m "feat(alt): validate explicit hostname modes"
```

### Task 2: ALT 11.x and two-mode hostname role

**Files:**
- Modify: `deploy/alt-linux/ansible/roles/manual_preflight/tasks/main.yml`
- Modify: `deploy/alt-linux/ansible/roles/workstation_identity/tasks/main.yml`
- Modify: `tests/test_alt_domain_ansible_assets.py`

**Interfaces:**
- Consumes: `hostname_mode`, `final_hostname`, `/etc/os-release`, target static hostname.
- Produces: an ALT Workstation K 11.x gate and a no-op verified hostname or explicitly approved rename.

- [ ] **Step 1: Write failing asset tests**

Assert the preflight reads `/etc/os-release`, requires ALT Workstation K and matches `VERSION_ID` against `^11\\.`. Assert the identity role branches on `hostname_mode`, invokes `hostnamectl` only under `change_confirmed`, and uses `ALT_PREFLIGHT_FAILURE:hostname_mismatch`.

- [ ] **Step 2: Run the test to verify it fails**

Run: `python -m pytest -q tests/test_alt_domain_ansible_assets.py`

Expected: FAIL because the current role reads `/etc/altlinux-release` and always applies the name.

- [ ] **Step 3: Implement the minimal roles**

Read `/etc/os-release`, assert the ALT Workstation K product and a major version beginning `11.`. Read the static hostname before mutation. In `verify`, compare it to `final_hostname`; in `change_confirmed`, set it then compare. Assert allowed modes defensively in Ansible.

- [ ] **Step 4: Run the test to verify it passes**

Run: `python -m pytest -q tests/test_alt_domain_ansible_assets.py`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add deploy/alt-linux/ansible/roles/manual_preflight/tasks/main.yml deploy/alt-linux/ansible/roles/workstation_identity/tasks/main.yml tests/test_alt_domain_ansible_assets.py
git commit -m "fix(alt): verify ALT 11.x and hostname modes"
```

### Task 3: Safe AD computer-account conflict check

**Files:**
- Modify: `deploy/alt-linux/ansible/group_vars/all.yml`
- Modify: `deploy/alt-linux/ansible/roles/workstation_base/tasks/main.yml`
- Modify: `deploy/alt-linux/ansible/roles/domain_join/tasks/main.yml`
- Modify: `tests/test_alt_domain_ansible_assets.py`

**Interfaces:**
- Consumes: Vault join credentials, `computer_ou`, `final_hostname`, `net ads testjoin`.
- Produces: `ALT_PREFLIGHT_FAILURE:domain_computer_conflict` before a join write when an untrusted matching AD account exists.

- [ ] **Step 1: Write failing asset test**

Assert `ldapsearch -Y GSSAPI` filters exactly `(sAMAccountName={{ final_hostname }}$)`, scopes to `computer_ou`, runs after `kinit`, and uses the conflict marker. Assert role text contains no AD delete, reset or leave command.

- [ ] **Step 2: Run the test to verify it fails**

Run: `python -m pytest -q tests/test_alt_domain_ansible_assets.py`

Expected: FAIL because the existing role has no AD-object lookup.

- [ ] **Step 3: Implement the conflict guard**

Install the package that supplies `ldapsearch`. After acquiring a temporary Kerberos ticket, query only the target OU. If an entry exists and the idempotent trust predicate is false, stop with the stable conflict marker. Invoke `system-auth write ad` only after that guard. Keep ticket, query and join under `no_log: true` and always run `kdestroy`.

- [ ] **Step 4: Run the test to verify it passes**

Run: `python -m pytest -q tests/test_alt_domain_ansible_assets.py`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add deploy/alt-linux/ansible/group_vars/all.yml deploy/alt-linux/ansible/roles/workstation_base/tasks/main.yml deploy/alt-linux/ansible/roles/domain_join/tasks/main.yml tests/test_alt_domain_ansible_assets.py
git commit -m "feat(alt): reject untrusted AD computer conflicts"
```

### Task 4: Domain-home verification and operator documentation

**Files:**
- Modify: `deploy/alt-linux/ansible/roles/domain_verify/tasks/main.yml`
- Modify: `docs/ALT_MANUAL_ANSIBLE_MVP.md`
- Modify: `docs/runbooks/alt-manual-bootstrap-mvp.md`
- Modify: `tests/alt_linux/test_manual_bootstrap_mvp_docs.py`
- Modify: `tests/test_alt_domain_ansible_assets.py`

**Interfaces:**
- Consumes: `domain_test_user`, ALT auth configuration, controller-only execution policy.
- Produces: explicit verification of automatic-home configuration and current instructions for both hostname modes.

- [ ] **Step 1: Write failing documentation and asset tests**

Require the documents to contain `hostname_mode`, both modes, `OU=Pilot,OU=Linux,OU=Устройства,DC=sosnadmin,DC=local`, the curl bootstrap path and the non-mutating preview boundary. Require a read-only test of effective automatic home creation configuration, not merely `getent`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest -q tests/alt_linux/test_manual_bootstrap_mvp_docs.py tests/test_alt_domain_ansible_assets.py`

Expected: FAIL because the documents use the old request/OU and the role only performs lookup.

- [ ] **Step 3: Implement the verification and documentation**

Use ALT `system-auth` status/configuration as a read-only assertion that home creation is enabled; do not create a local account or synthetic domain login. Document the first real domain login after reboot as the acceptance check that creates the home. Replace old bootstrap text and OU with non-secret requests for both modes.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m pytest -q tests/alt_linux/test_manual_bootstrap_mvp_docs.py tests/test_alt_domain_ansible_assets.py`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add deploy/alt-linux/ansible/roles/domain_verify/tasks/main.yml docs/ALT_MANUAL_ANSIBLE_MVP.md docs/runbooks/alt-manual-bootstrap-mvp.md tests/alt_linux/test_manual_bootstrap_mvp_docs.py tests/test_alt_domain_ansible_assets.py
git commit -m "docs(alt): document verified manual domain workflow"
```

### Task 5: Full regression and safety review

**Files:** Verify only the files from Tasks 1-4.

- [ ] **Step 1: Run focused regression tests**

Run: `python -m pytest -q tests/test_alt_manual_configure_request.py tests/test_alt_domain_ansible_assets.py tests/alt_linux/test_manual_bootstrap_mvp_docs.py tests/alt_linux/test_bootstrap_register_integration.py`

Expected: PASS.

- [ ] **Step 2: Run syntax and style checks**

Run: `python -m compileall -q deploy/alt-linux/control/alt_deploy && python -m ruff check deploy/alt-linux/control/alt_deploy/configure.py tests/test_alt_manual_configure_request.py tests/test_alt_domain_ansible_assets.py`

Expected: PASS.

- [ ] **Step 3: Review the final diff for safety boundaries**

Run: `git diff main...HEAD -- deploy/alt-linux docs tests`

Expected: no password, Vault value, raw Ansible command interface, AD delete/reset/move operation, or managed-ISO change.

- [ ] **Step 4: Confirm a clean worktree**

Run: `git status --short`

Expected: empty output after commits; do not create an empty commit.

