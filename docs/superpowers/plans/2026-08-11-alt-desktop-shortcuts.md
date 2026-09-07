# ALT desktop shortcuts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create consistent desktop shortcuts for standard ALT domain profiles.

**Architecture:** A dedicated Ansible role writes package-owned application launchers and relative folder links into `/etc/skel/Рабочий стол`, then mirrors them only to the existing `domain_test_user` profile. The role is positioned after software installation and before final verification.

**Tech Stack:** Ansible built-in `file`, `copy`, `command`, `stat`, and `assert` modules; KDE/Plasma `.desktop` entries.

## Global Constraints

- Do not create or alter SMB, Nextcloud or AD credentials.
- Do not alter GPO, autofs or existing domain-join behavior.
- Do not create missing user homes; all future user profiles come from `/etc/skel`.
- Use only vendor `.desktop` entries installed by approved packages.

---

### Task 1: Specify the role contract with a failing asset test

**Files:**
- Modify: `tests/test_alt_domain_ansible_assets.py`
- Create: `deploy/alt-linux/ansible/roles/desktop_shortcuts/defaults/main.yml`
- Create: `deploy/alt-linux/ansible/roles/desktop_shortcuts/tasks/main.yml`

- [ ] **Step 1: Write a failing test**

```python
def test_desktop_shortcuts_use_skel_and_existing_domain_test_profile() -> None:
    role = ANSIBLE_ROOT / "roles" / "desktop_shortcuts" / "tasks" / "main.yml"
    content = role.read_text(encoding="utf-8")
    assert "/etc/skel/Рабочий стол" in content
    assert "cptools.desktop" in content
    assert "yandex-browser.desktop" in content
    assert "onlyoffice-desktopeditors.desktop" in content
    assert "../net.drives/Public" in content
    assert "state: link" in content
```

- [ ] **Step 2: Run the focused test and confirm RED**

Run: `pytest -q tests/test_alt_domain_ansible_assets.py -k desktop_shortcuts`

- [ ] **Step 3: Add the minimal role**

Use `getent passwd {{ domain_test_user }}` only to identify the existing test
profile. Copy the three vendor entries, create the two relative links, and
assert their existence. Keep ownership of skeleton files root and mirror files
to the user profile only if its home already exists.

- [ ] **Step 4: Run the focused test and confirm GREEN**

Run: `pytest -q tests/test_alt_domain_ansible_assets.py -k desktop_shortcuts`

### Task 2: Integrate and accept the role

**Files:**
- Modify: `deploy/alt-linux/ansible/playbooks/03-configure-domain-workstation.yml`
- Modify: `tests/test_alt_domain_ansible_assets.py`

- [ ] **Step 1: Add a failing role-order assertion**

Require `desktop_shortcuts` after `standard_software` and before
`domain_verify`.

- [ ] **Step 2: Integrate the role**

Add `desktop_shortcuts` after `standard_software`.

- [ ] **Step 3: Verify locally and on the pilot**

Run focused tests, Ansible syntax check, configure the pilot again, and verify
the five visible entries in the user desktop directory.
