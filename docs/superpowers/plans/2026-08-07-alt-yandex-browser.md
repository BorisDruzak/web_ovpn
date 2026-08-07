# Yandex Browser for ALT Workstations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (- [ ]) syntax for tracking.

**Goal:** Install the approved Yandex Browser RPM through the existing controller-managed standard-domain configure playbook, while delivering browser settings only through AD GPO.

**Architecture:** A root-owned controller artifact remains outside Git. A fixed Ansible catalog identifies its path, SHA-256, name and EVR. standard_software dispatches only browser to software_browser; the role validates the artifact, installs the local RPM, verifies the exact EVR, removes the temporary file and exports a boolean.

**Tech Stack:** Ansible, ALT apt-get and RPM, Python pytest with PyYAML, Bash/SSH artifact staging.

## Global Constraints

- Package name: yandex-browser-stable; EVR: 26.4.4.968-1; architecture: x86_64.
- SHA-256: 7fbce78e9799ae36ebfcf750d5880f27d829d5546e9ac77f1868afb9657d9a89.
- Controller artifact: /opt/alt-deploy-control/artifacts/yandex-browser/Yandex.rpm, root:root, mode 0644. The RPM never enters Git.
- Policies come only from GPO ALT - Yandex Browser - Pilot. No Ansible role writes browser JSON policies, preferences, extensions or user profiles.
- 03-configure-domain-workstation.yml remains the only configure entry point and domain_verify remains the last role.
- A configure request supplies no URL, artifact path, checksum, package name or role name.
- The public configure result exposes only verification.browser: true or false.

## File Structure

- Modify: deploy/alt-linux/ansible/group_vars/all.yml — fixed catalog and component list.
- Modify: deploy/alt-linux/ansible/roles/standard_software/tasks/main.yml — literal allow-listed dispatcher.
- Create: deploy/alt-linux/ansible/roles/software_browser/defaults/main.yml — private temporary target and catalog reference.
- Create: deploy/alt-linux/ansible/roles/software_browser/tasks/main.yml — validation, install, verification and cleanup.
- Modify: deploy/alt-linux/ansible/roles/domain_verify/tasks/main.yml — public boolean only.
- Modify: tests/test_alt_domain_ansible_assets.py — static safety regression coverage.
- Create: docs/ALT_AD_GROUP_POLICY_PILOT.md — policy/install ownership boundary.

---

### Task 1: Add the fixed catalog and browser dispatcher

**Files:**
- Modify: deploy/alt-linux/ansible/group_vars/all.yml
- Modify: deploy/alt-linux/ansible/roles/standard_software/tasks/main.yml
- Test: tests/test_alt_domain_ansible_assets.py

**Interfaces:**
- Consumes: the root-owned RPM at the Global Constraints path.
- Produces: approved_software_components: [browser] and software_catalog.browser.

- [ ] **Step 1: Write a failing static contract test**

~~~python
def test_browser_catalog_and_dispatcher_are_fixed_and_allow_listed() -> None:
    variables = yaml.safe_load(
        (ANSIBLE_ROOT / "group_vars" / "all.yml").read_text(encoding="utf-8")
    )
    content = (
        ANSIBLE_ROOT / "roles" / "standard_software" / "tasks" / "main.yml"
    ).read_text(encoding="utf-8")

    assert variables["approved_software_components"] == ["browser"]
    assert variables["software_catalog"]["browser"]["artifact_path"] == (
        "/opt/alt-deploy-control/artifacts/yandex-browser/Yandex.rpm"
    )
    assert variables["software_catalog"]["browser"]["sha256"] == (
        "7fbce78e9799ae36ebfcf750d5880f27d829d5546e9ac77f1868afb9657d9a89"
    )
    assert variables["software_catalog"]["browser"]["package_name"] == "yandex-browser-stable"
    assert variables["software_catalog"]["browser"]["package_evr"] == "26.4.4.968-1"
    assert "browser: software_browser" in content
    assert "include_role" in content
~~~

- [ ] **Step 2: Confirm the test fails**

Run:

~~~powershell
pytest tests/test_alt_domain_ansible_assets.py::test_browser_catalog_and_dispatcher_are_fixed_and_allow_listed -q
~~~

Expected: FAIL because no browser catalog or dispatcher exists.

- [ ] **Step 3: Add fixed controller variables**

Append to all.yml:

~~~yaml
approved_software_components:
  - browser
software_catalog:
  browser:
    artifact_path: /opt/alt-deploy-control/artifacts/yandex-browser/Yandex.rpm
    sha256: 7fbce78e9799ae36ebfcf750d5880f27d829d5546e9ac77f1868afb9657d9a89
    package_name: yandex-browser-stable
    package_evr: 26.4.4.968-1
    architecture: x86_64
~~~

- [ ] **Step 4: Make the component dispatcher explicit**

Keep the current package-list task. Add these tasks below it:

~~~yaml
- name: Resolve fixed workstation software roles
  ansible.builtin.set_fact:
    standard_software_role_map:
      browser: software_browser

- name: Require only approved workstation software components
  ansible.builtin.assert:
    that:
      - approved_software_components | difference(standard_software_role_map.keys() | list) | length == 0
    fail_msg: ALT_PREFLIGHT_FAILURE:software_component_unsupported

- name: Install selected approved workstation software components
  ansible.builtin.include_role:
    name: "{{ standard_software_role_map[item] }}"
  loop: "{{ approved_software_components }}"
~~~

- [ ] **Step 5: Run the test and commit**

~~~powershell
pytest tests/test_alt_domain_ansible_assets.py -q
git add deploy/alt-linux/ansible/group_vars/all.yml deploy/alt-linux/ansible/roles/standard_software/tasks/main.yml tests/test_alt_domain_ansible_assets.py
git commit -m "feat(alt): select approved browser software"
~~~

Expected: test passes; only intended files are committed.

### Task 2: Create the verified local-RPM browser role

**Files:**
- Create: deploy/alt-linux/ansible/roles/software_browser/defaults/main.yml
- Create: deploy/alt-linux/ansible/roles/software_browser/tasks/main.yml
- Test: tests/test_alt_domain_ansible_assets.py

**Interfaces:**
- Consumes: software_catalog.browser.
- Produces: software_browser_verified: true only after the exact EVR is installed.

- [ ] **Step 1: Write a failing safety-order test**

~~~python
def test_browser_role_checks_controller_artifact_before_install_and_never_writes_policy() -> None:
    content = (
        ANSIBLE_ROOT / "roles" / "software_browser" / "tasks" / "main.yml"
    ).read_text(encoding="utf-8")

    assert "delegate_to: localhost" in content
    assert "get_checksum: true" in content
    assert "software_browser_catalog.sha256" in content
    assert content.index("Validate approved Yandex Browser artifact") < content.index("Install approved Yandex Browser RPM")
    assert "apt-get, -y, install" in content
    assert "rpm, -q" in content
    assert "state: absent" in content
    assert "software_browser_verified: true" in content
    assert "/etc/opt/yandex/browser/policies" not in content
~~~

- [ ] **Step 2: Confirm the test fails**

~~~powershell
pytest tests/test_alt_domain_ansible_assets.py::test_browser_role_checks_controller_artifact_before_install_and_never_writes_policy -q
~~~

Expected: FAIL because software_browser does not exist.

- [ ] **Step 3: Add role defaults**

~~~yaml
---
software_browser_temp_rpm: /var/tmp/approved-yandex-browser.rpm
software_browser_catalog: "{{ software_catalog.browser }}"
~~~

- [ ] **Step 4: Implement validation, install, verification and always-cleanup**

The source validation runs on the controller; package operations run on the managed workstation.

~~~yaml
- name: Inspect approved Yandex Browser artifact on controller
  ansible.builtin.stat:
    path: "{{ software_browser_catalog.artifact_path }}"
    get_checksum: true
    checksum_algorithm: sha256
  delegate_to: localhost
  become: false
  register: software_browser_artifact
  no_log: true

- name: Validate approved Yandex Browser artifact
  ansible.builtin.assert:
    that:
      - software_browser_artifact.stat.exists
      - software_browser_artifact.stat.isreg
      - software_browser_artifact.stat.checksum == software_browser_catalog.sha256
    fail_msg: ALT_PREFLIGHT_FAILURE:browser_artifact_invalid
  no_log: true

- name: Inspect approved Yandex Browser RPM architecture
  ansible.builtin.command:
    argv: [rpm, -qp, --qf, "%{ARCH}", "{{ software_browser_catalog.artifact_path }}"]
  delegate_to: localhost
  become: false
  register: software_browser_artifact_architecture
  changed_when: false
  no_log: true

- name: Require x86_64 approved Yandex Browser RPM
  ansible.builtin.assert:
    that:
      - software_browser_artifact_architecture.stdout | trim == software_browser_catalog.architecture
    fail_msg: ALT_PREFLIGHT_FAILURE:browser_architecture_invalid
  no_log: true
~~~

Add the remaining tasks exactly as follows:

~~~yaml
- name: Inspect installed Yandex Browser package
  ansible.builtin.command:
    argv: [rpm, -q, --qf, "%{VERSION}-%{RELEASE}", "{{ software_browser_catalog.package_name }}"]
  register: software_browser_installed_evr
  changed_when: false
  failed_when: false

- name: Install and verify approved Yandex Browser RPM
  block:
    - name: Copy approved Yandex Browser RPM
      ansible.builtin.copy:
        src: "{{ software_browser_catalog.artifact_path }}"
        dest: "{{ software_browser_temp_rpm }}"
        owner: root
        group: root
        mode: "0600"
      when: software_browser_installed_evr.stdout | trim != software_browser_catalog.package_evr
      no_log: true

    - name: Install approved Yandex Browser RPM
      ansible.builtin.command:
        argv: [apt-get, -y, install, "{{ software_browser_temp_rpm }}"]
      when: software_browser_installed_evr.stdout | trim != software_browser_catalog.package_evr
      register: software_browser_install
      changed_when: software_browser_install.rc == 0
      no_log: true

    - name: Verify approved Yandex Browser package EVR
      ansible.builtin.command:
        argv: [rpm, -q, --qf, "%{VERSION}-%{RELEASE}", "{{ software_browser_catalog.package_name }}"]
      register: software_browser_verified_evr
      changed_when: false

    - name: Require approved Yandex Browser package EVR
      ansible.builtin.assert:
        that:
          - software_browser_verified_evr.rc == 0
          - software_browser_verified_evr.stdout | trim == software_browser_catalog.package_evr
        fail_msg: ALT_PREFLIGHT_FAILURE:browser_install_verification_failed
  always:
    - name: Remove temporary Yandex Browser RPM
      ansible.builtin.file:
        path: "{{ software_browser_temp_rpm }}"
        state: absent
      no_log: true

- name: Publish Yandex Browser verification fact
  ansible.builtin.set_fact:
    software_browser_verified: true
~~~

- [ ] **Step 5: Run static tests and commit**

~~~powershell
pytest tests/test_alt_domain_ansible_assets.py -q
git add deploy/alt-linux/ansible/roles/software_browser tests/test_alt_domain_ansible_assets.py
git commit -m "feat(alt): install verified yandex browser rpm"
~~~

Expected: tests pass and the role contains no browser policy path.

### Task 3: Publish the non-secret browser result and document the GPO boundary

**Files:**
- Modify: deploy/alt-linux/ansible/roles/domain_verify/tasks/main.yml
- Create: docs/ALT_AD_GROUP_POLICY_PILOT.md
- Test: tests/test_alt_domain_ansible_assets.py

**Interfaces:**
- Consumes: software_browser_verified.
- Produces: verification.browser in the public configure result.

- [ ] **Step 1: Write a failing public-result test**

~~~python
def test_domain_verify_publishes_only_a_boolean_browser_result() -> None:
    content = (
        ANSIBLE_ROOT / "roles" / "domain_verify" / "tasks" / "main.yml"
    ).read_text(encoding="utf-8")

    assert "'browser': software_browser_verified | default(false)" in content
    assert "Yandex.rpm" not in content
    assert "/opt/alt-deploy-control/artifacts" not in content
~~~

- [ ] **Step 2: Confirm it fails, implement it, and confirm it passes**

Add only this key inside the existing public verification mapping:

~~~yaml
'browser': software_browser_verified | default(false),
~~~

Create docs/ALT_AD_GROUP_POLICY_PILOT.md with these exact rules:

~~~markdown
- Ansible installs the approved Yandex Browser RPM only.
- ALT - Yandex Browser - Pilot is linked only to the Pilot OU.
- Browser settings are changed in that GPO, never in Ansible files.
- Acceptance separately checks rpm -q yandex-browser-stable and browser://policy after a domain-user login.
~~~

Run:

~~~powershell
pytest tests/test_alt_domain_ansible_assets.py -q
git diff --check
git add deploy/alt-linux/ansible/roles/domain_verify/tasks/main.yml docs/ALT_AD_GROUP_POLICY_PILOT.md tests/test_alt_domain_ansible_assets.py
git commit -m "docs(alt): separate browser installation from gpo policy"
~~~

Expected: tests pass and no whitespace errors occur.

### Task 4: Stage the RPM, deploy the controller, and run a pilot acceptance check

**Files:**
- Modify: no Git-tracked binary files.
- Test: controller readiness and one Pilot workstation configure result.

**Interfaces:**
- Consumes: C:\Users\admin-2\Downloads\Yandex.rpm and the catalog constants from Task 1.
- Produces: the root-owned controller artifact and verification.browser: true on a pilot workstation.

- [ ] **Step 1: Verify the local source RPM**

~~~powershell
Get-FileHash 'C:\Users\admin-2\Downloads\Yandex.rpm' -Algorithm SHA256
~~~

Expected: 7FBCE78E9799AE36EBFCF750D5880F27D829D5546E9AC77F1868AFB9657D9A89.

- [ ] **Step 2: Copy to the controller and protect it outside Git**

Transfer to /tmp/Yandex.rpm, then execute:

~~~bash
sudo install -d -o root -g root -m 0755 /opt/alt-deploy-control/artifacts/yandex-browser
sudo install -o root -g root -m 0644 /tmp/Yandex.rpm /opt/alt-deploy-control/artifacts/yandex-browser/Yandex.rpm
sha256sum /opt/alt-deploy-control/artifacts/yandex-browser/Yandex.rpm
rpm -qp --qf '%{NAME} %{VERSION}-%{RELEASE} %{ARCH}\n' /opt/alt-deploy-control/artifacts/yandex-browser/Yandex.rpm
rm -f /tmp/Yandex.rpm
~~~

Expected: the exact Global Constraints hash and yandex-browser-stable 26.4.4.968-1 x86_64.

- [ ] **Step 3: Deploy through the rollback-gated installer**

~~~bash
sudo bash deploy/alt-linux/install-control-plane.sh --rollback-backup-id backup-20260805T144523Z-484f5259
sudo -u altserver /usr/local/sbin/workstationctl --json controller readiness
~~~

Expected: repository verification passes and readiness has no failed checks.

- [ ] **Step 4: Use the existing fixed standard-domain configure request on one Pilot workstation**

Confirm the public result includes:

~~~json
{"verification":{"browser":true}}
~~~

Then run:

~~~bash
rpm -q yandex-browser-stable
rpm -q --qf '%{VERSION}-%{RELEASE}\n' yandex-browser-stable
~~~

Expected: installed package EVR is 26.4.4.968-1.

- [ ] **Step 5: Verify the separate GPO path**

Log in with a domain user, open browser://policy, and confirm that only deliberately configured policies from ALT - Yandex Browser - Pilot appear. Ansible must not create local browser policy files.

- [ ] **Step 6: Final tracked-code commit**

~~~powershell
git status --short
git add deploy/alt-linux/ansible tests/test_alt_domain_ansible_assets.py docs/ALT_AD_GROUP_POLICY_PILOT.md
git commit -m "feat(alt): provision yandex browser from approved rpm"
~~~

Do not stage the RPM, controller artifacts, passwords, backups or transfer files.

## Plan Self-Review

- **Spec coverage:** Tasks 1-2 cover artifact identity, checksum, architecture, idempotent local installation, exact verification and cleanup. Task 3 covers public-result and GPO-only boundaries. Task 4 covers protected staging, rollback-gated deployment and pilot acceptance.
- **Placeholder scan:** Every action names exact files, variables, fail codes, commands and expected values.
- **Interface consistency:** Task 1 defines software_catalog.browser; Task 2 consumes it and emits software_browser_verified; Task 3 publishes it; Task 4 verifies verification.browser.
