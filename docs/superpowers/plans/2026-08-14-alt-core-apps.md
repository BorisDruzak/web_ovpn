# ALT core-apps Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Provide resilient, verified ONLYOFFICE and Nextcloud deployment through the existing `core-apps` ALT workstation profile.

**Architecture:** Add three independent Ansible components after the existing browser component. A controller catalog pins the ONLYOFFICE RPM; Nextcloud derives only from ALT repositories. A desktop role uses `/etc/skel` for future users and applies entries only to the explicit assigned UPN for an existing session.

**Tech Stack:** Python configure contract tests, Ansible roles, ALT APT/RPM, existing `alt_resilience` package retry tasks.

## Global Constraints

- `base` must remain free of ONLYOFFICE and Nextcloud.
- Only `core-apps` enables the three new components.
- ONLYOFFICE uses the exact controller RPM and SHA-256 from the approved catalog.
- Nextcloud uses `nextcloud-client` and `nextcloud-client-kde` from configured ALT repositories.
- No user homes may be enumerated; write an existing home only for `assigned_domain_user`.
- Temp RPM copies are `root:root`, `0600` and are removed in `always`.

---

### Task 1: Express the core-apps contract in tests

**Files:**
- Modify: `tests/test_alt_manual_configure_request.py`
- Modify: `tests/test_alt_domain_ansible_assets.py`
- Modify: `tests/alt_linux/test_ansible_resilience_contract.py`

**Interfaces:**
- Consumes: `ConfigureRequest.actions()` and `03-configure-domain-workstation.yml`.
- Produces: regression requirements for gated components and approved software roles.

- [ ] **Step 1: Write failing tests**

```python
assert ConfigureRequest.from_mapping(core_apps, expected_uuid=MACHINE_UUID).actions()[-1] == "install_core_apps"
assert {item["name"] for item in core_components} == {"onlyoffice", "nextcloud_desktop", "desktop_shortcuts"}
assert all(item["enabled"] == "{{ software_profile == 'core-apps' }}" for item in core_components)
```

- [ ] **Step 2: Run the focused tests and confirm they fail because components are absent.**

Run: `pytest tests/test_alt_manual_configure_request.py tests/test_alt_domain_ansible_assets.py tests/alt_linux/test_ansible_resilience_contract.py -q`

- [ ] **Step 3: Add only the minimal role and playbook code required by the assertions.**

- [ ] **Step 4: Re-run the focused tests and confirm they pass.**

- [ ] **Step 5: Commit the contract layer.**

### Task 2: Add verified application roles

**Files:**
- Modify: `deploy/alt-linux/ansible/group_vars/all.yml`
- Create: `deploy/alt-linux/ansible/roles/software_onlyoffice/defaults/main.yml`
- Create: `deploy/alt-linux/ansible/roles/software_onlyoffice/tasks/main.yml`
- Create: `deploy/alt-linux/ansible/roles/software_nextcloud_desktop/defaults/main.yml`
- Create: `deploy/alt-linux/ansible/roles/software_nextcloud_desktop/tasks/main.yml`

**Interfaces:**
- Consumes: `software_catalog` and shared package retry parameters.
- Produces: `onlyoffice_ok`, `onlyoffice_version`, `nextcloud_desktop_ok`, `nextcloud_desktop_version`.

- [ ] **Step 1: Write failing role-asset tests for checksum/RPM identity, retry include, package verification and temporary-file cleanup.**
- [ ] **Step 2: Run focused tests and confirm the role files are absent.**
- [ ] **Step 3: Implement roles with only the specified catalog and checks.**
- [ ] **Step 4: Re-run tests and Ansible syntax check.**
- [ ] **Step 5: Commit the application roles.**

### Task 3: Add desktop and autostart delivery

**Files:**
- Create: `deploy/alt-linux/ansible/roles/desktop_shortcuts/defaults/main.yml`
- Create: `deploy/alt-linux/ansible/roles/desktop_shortcuts/tasks/main.yml`
- Modify: `deploy/alt-linux/ansible/playbooks/03-configure-domain-workstation.yml`

**Interfaces:**
- Consumes: installed `/usr/share/applications/*.desktop` files and `assigned_domain_user`.
- Produces: links in `/etc/skel/Рабочий стол`, `/etc/skel/.config/autostart/nextcloud-client.desktop`, and parallel files only in the selected existing user home.

- [ ] **Step 1: Write failing asset tests requiring `/etc/skel`, `getent passwd`, no enumeration, and Nextcloud autostart.**
- [ ] **Step 2: Run the tests and confirm the desktop role is absent.**
- [ ] **Step 3: Implement the role and enable all core components only for `core-apps`.**
- [ ] **Step 4: Re-run focused tests and syntax check.**
- [ ] **Step 5: Commit the desktop role.**

### Task 4: Deploy and verify a core-apps canary

**Files:**
- No repository files required beyond Tasks 1–3.

- [ ] **Step 1: Run the ALT contract test suite and controller Ansible syntax check.**
- [ ] **Step 2: Deploy through the guarded controller installer; do not overwrite the active release directly.**
- [ ] **Step 3: Run preview then configure `core-apps` for `alt-a1-pc77` with the explicit domain user.**
- [ ] **Step 4: Verify result JSON, RPM versions, binaries, launcher files, `/etc/skel`, user autostart, and a running Nextcloud process after user login.**
- [ ] **Step 5: Commit/push the verified changes.**
