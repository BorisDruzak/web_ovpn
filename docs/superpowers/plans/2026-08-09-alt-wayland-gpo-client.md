# ALT Wayland Default and Group Policy Client Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Set Plasma Wayland as the managed login default and complete the existing ALT GPO client installation.

**Architecture:** `workstation_base` already maps `wayland` to LightDM `plasma`; change only the shared variable. The GPO prerequisite role installs `alterator-gpupdate`; the post-join client role checks for its `gpupdate-setup` command before enabling policy.

**Tech Stack:** Ansible, ALT Workstation K 11.x, LightDM, Plasma, gpupdate, alterator-gpupdate, pytest, Windows AD GPO.

## Global Constraints

- Keep `03-configure-domain-workstation.yml` as the sole controller-managed configure playbook.
- Keep order: base → GPO prerequisites → AD join with `--gpo` → GPO enable and update.
- Browser settings are delivered only by AD GPO; do not write Yandex policy JSON from Ansible.
- Do not change AD GPOs or automate screen timeout or keyboard layout.
- Never expose Vault values or passwords.

---

### Task 1: Declare and test Wayland and the complete GPO package set

**Files:**
- Modify: `tests/test_alt_domain_ansible_assets.py`
- Modify: `deploy/alt-linux/ansible/group_vars/all.yml`

- [ ] **Step 1: Write failing expectations**

```python
assert variables["workstation_desktop_session"] == "wayland"
assert variables["alt_group_policy_prerequisite_packages"] == [
    "gpupdate", "alterator-gpupdate"
]
```

- [ ] **Step 2: Verify RED**

```powershell
python -m pytest tests/test_alt_domain_ansible_assets.py -q
```

Expected: failure because the project still declares X11 and omits `alterator-gpupdate`.

- [ ] **Step 3: Make the minimal declaration**

```yaml
workstation_desktop_session: wayland
alt_group_policy_prerequisite_packages:
  - gpupdate
  - alterator-gpupdate
```

- [ ] **Step 4: Verify GREEN**

```powershell
python -m pytest tests/test_alt_domain_ansible_assets.py -q
```

### Task 2: Reject an incomplete GPO installation before enablement

**Files:**
- Modify: `tests/test_alt_domain_ansible_assets.py`
- Modify: `deploy/alt-linux/ansible/roles/alt_group_policy_client/tasks/main.yml`

- [ ] **Step 1: Write failing role expectations**

```python
assert "Check ALT Group Policy setup command" in client
assert "path: /usr/bin/gpupdate-setup" in client
```

- [ ] **Step 2: Verify RED**

```powershell
python -m pytest tests/test_alt_domain_ansible_assets.py -q
```

- [ ] **Step 3: Add the minimal Ansible preflight before `gpupdate-setup enable`**

```yaml
- name: Check ALT Group Policy setup command
  ansible.builtin.stat:
    path: /usr/bin/gpupdate-setup
  register: alt_group_policy_setup_command
- name: Require ALT Group Policy setup command
  ansible.builtin.assert:
    that: alt_group_policy_setup_command.stat.exists
    fail_msg: ALT_PREFLIGHT_FAILURE:group_policy_setup_unavailable
```

- [ ] **Step 4: Verify GREEN and syntax**

```powershell
python -m pytest tests/test_alt_domain_ansible_assets.py -q
ansible-playbook --syntax-check deploy/alt-linux/ansible/playbooks/03-configure-domain-workstation.yml
```

### Task 3: Deploy and verify the registered pilot

**Files:** No source changes.

- [ ] Deploy only committed Ansible source to `/home/altserver/ansible`, excluding Vault and runtime data.
- [ ] On the controller, syntax-check `playbooks/03-configure-domain-workstation.yml`.
- [ ] Run normal `workstationctl configure` for registered pilot `192.168.101.56`; do not run a caller-selected playbook.
- [ ] Verify by SSH: `user-session=plasma`, installed `gpupdate`/`alterator-gpupdate`/browser package, executable `gpupdate-setup`, a successful machine `gpupdate`, and non-empty `/etc/opt/yandex/browser/policies/managed/policies.json`.
- [ ] In the domain user's browser, confirm the same value through `browser://policy`.
- [ ] Run the full local test suite, review the diff, and commit source/test changes only.
