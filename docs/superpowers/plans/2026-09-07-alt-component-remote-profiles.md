# ALT component and remote-profile implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add fail-closed software and per-user KRFB profile support to the
controller-managed configuration of an already installed ALT workstation.

**Architecture:** Keep stage 03's critical domain flow unchanged. Before any
selected optional component can mutate a workstation, validate its non-secret
catalog record and controller artifact. Fixed component roles produce only
boolean verification facts. KRFB is independently opt-in and uses a controller
Vault presence gate plus one explicitly supplied AD user.

**Tech Stack:** Python 3, pytest, Ansible, Ansible Vault, ALT Workstation K
11.x, SSSD/Samba, Plasma X11 and KDE KRFB.

**Spec:** `docs/superpowers/specs/2026-09-07-alt-component-remote-profiles.md`

## Global Constraints

- Do not modify `netctl`, NetworkManager DNS, routing, firewall policy, the
  managed-ISO path, or bootstrap registration.
- Preserve `ad_dns_servers` and the existing stage-03 critical-role order.
- Use only `03-configure-domain-workstation.yml` through `workstationctl`.
- Never commit an artifact, a password, Vault data, or an obscured KRFB value.
- Do not deploy or run against a controller/workstation without separate
  approval; Windows static tests are not an ALT runtime validation.

---

### Task 1: Record a fail-closed software catalog and legacy scope

**Files:**
- Create: `deploy/alt-linux/ansible/group_vars/software_catalog.yml`
- Create: `tests/test_alt_software_catalog.py`
- Create: `docs/ALT_LEGACY_PLAYBOOKS_INVENTORY.md`

**Interfaces:**
- Produces `software_catalog` entries for `browser`, `onlyoffice`, and
  `nextcloud_desktop`; all begin with `enabled: false`.
- An enabled entry must declare `source: rpm` or `source: alt-repository`.
  RPM entries require `artifact_path`, `sha256`, `package_name`, `package_evr`,
  `architecture`, and `executable`; repository entries require non-empty fixed
  `packages` and `executable` fields.

- [ ] **Step 1: Write the catalog schema test**

```python
def test_catalog_components_are_disabled_or_complete() -> None:
    catalog = yaml.safe_load(CATALOG.read_text(encoding="utf-8"))["software_catalog"]
    assert set(catalog) == {"browser", "onlyoffice", "nextcloud_desktop"}
    for name, item in catalog.items():
        if item["enabled"]:
            assert item["source"] in {"rpm", "alt-repository"}, name
            assert {"enabled", "source", "executable"} <= set(item), name
            if item["source"] == "rpm":
                assert {"artifact_path", "sha256", "package_name", "package_evr", "architecture"} <= set(item), name
            else:
                assert isinstance(item.get("packages"), list) and item["packages"], name
```

- [ ] **Step 2: Run the focused test and confirm it fails because the catalog is absent**

Run: `python -m pytest -q --noconftest tests/test_alt_software_catalog.py`

Expected: FAIL with a missing catalog path.

- [ ] **Step 3: Add the exact disabled catalog**

```yaml
---
software_catalog:
  browser: {enabled: false}
  onlyoffice: {enabled: false}
  nextcloud_desktop: {enabled: false}
```

Do not copy values from the historical branch until the controller artifacts
and their RPM metadata are read and approved on the intended controller.

- [ ] **Step 4: Write the legacy inventory**

List `ctipro_pro.yml`, `spravki.yml`, `ya.yml`, `setup_rdp.yml`,
`start_x11vnc.sh`, `force_dns_nm.yml`, `net-work.yml` and legacy printer/
monitoring playbooks. Mark the first three as pending checked catalog records;
mark RDP/X11VNC, forced DNS and network scripts as out of the new workstation
path; do not delete any historical file.

- [ ] **Step 5: Verify and commit**

Run: `python -m pytest -q --noconftest tests/test_alt_software_catalog.py`

Run: `git diff --check`

Commit: `docs(alt): define fail-closed software catalog`

### Task 2: Add aggregate component preflight before optional mutation

**Files:**
- Modify: `deploy/alt-linux/ansible/playbooks/03-configure-domain-workstation.yml`
- Create: `deploy/alt-linux/ansible/playbooks/tasks/configure_component_preflight.yml`
- Modify: `deploy/alt-linux/ansible/playbooks/tasks/configure_critical_phase.yml`
- Modify: `tests/test_alt_domain_ansible_assets.py`

**Interfaces:**
- Consumes `software_profile`, `remote_access_profile`, and `software_catalog`.
- Produces `configure_component_preflight_passed: bool` only after every
  selected catalog entry is enabled, structurally complete, present on the
  controller and checksum-valid.

- [ ] **Step 1: Write failing static tests**

```python
def test_selected_components_are_preflighted_before_component_roles() -> None:
    text = (PLAYBOOKS / "tasks/configure_critical_phase.yml").read_text()
    assert "configure_component_preflight.yml" in text
    assert text.index("configure_component_preflight.yml") < text.index("Run manual preflight")

def test_stage03_loads_the_nonsecret_component_catalog() -> None:
    text = (PLAYBOOKS / "03-configure-domain-workstation.yml").read_text()
    assert "../group_vars/software_catalog.yml" in text

def test_component_preflight_rejects_disabled_catalog_entries() -> None:
    text = (PLAYBOOKS / "tasks/configure_component_preflight.yml").read_text()
    assert "software_component_catalog_invalid" in text
    assert "checksum_algorithm: sha256" in text
    assert "delegate_to: localhost" in text
```

- [ ] **Step 2: Run the selected tests and confirm they fail**

Run: `python -m pytest -q --noconftest tests/test_alt_domain_ansible_assets.py`

Expected: FAIL because the component preflight task is absent.

- [ ] **Step 3: Implement deterministic selection and aggregate validation**

For `base`, set `selected_software_components: []`. For `core-apps`, set
`["browser", "onlyoffice", "nextcloud_desktop"]`; do not derive role names
from request input. Assert every selected entry is enabled and schema-complete.
For every RPM source, run localhost `stat` with `checksum_algorithm: sha256`
and require a regular file whose checksum exactly matches the catalog. For an
`alt-repository` source, require only its fixed non-empty package list and
executable schema; repository availability is verified by that component role.
Include this task immediately after the structured result is initialized and
before `Run manual preflight`; set the success fact only after all assertions
pass.

- [ ] **Step 4: Preserve stage-03 result semantics**

The preflight failure must use the existing structured failed result path and
must not add a false `components` success record. `base/none` must execute the
existing critical path unchanged.

- [ ] **Step 5: Verify and commit**

Run: `python -m pytest -q --noconftest tests/test_alt_domain_ansible_assets.py tests/test_alt_software_catalog.py`

Run: `git diff --check`

Commit: `feat(alt): preflight selected software components`

### Task 3: Implement only approved component roles

**Files:**
- Modify: `deploy/alt-linux/ansible/roles/standard_software/tasks/main.yml`
- Create: `deploy/alt-linux/ansible/roles/software_browser/tasks/main.yml`
- Create: `deploy/alt-linux/ansible/roles/software_onlyoffice/tasks/main.yml`
- Create: `deploy/alt-linux/ansible/roles/software_nextcloud_desktop/tasks/main.yml`
- Modify: `deploy/alt-linux/ansible/playbooks/tasks/configure_critical_phase.yml`
- Modify: `tests/test_alt_domain_ansible_assets.py`

**Interfaces:**
- Consumes the Task 2 validated `selected_software_components` and catalog.
- Produces `software_browser_verified`, `software_onlyoffice_verified`, and
  `software_nextcloud_desktop_verified` booleans plus matching structured
  component result fields.

- [ ] **Step 1: Use the read-only verified controller artifact record**

The ALT controller at `altserver-100-17` was inspected read-only on 2026-09-07.
Enable exactly these catalog entries; their artifacts are under the controlled
`/opt/alt-deploy-control/artifacts` root, never a user home:

```yaml
software_catalog:
  browser:
    enabled: true
    source: rpm
    artifact_path: /opt/alt-deploy-control/artifacts/yandex-browser/Yandex.rpm
    sha256: 7fbce78e9799ae36ebfcf750d5880f27d829d5546e9ac77f1868afb9657d9a89
    package_name: yandex-browser-stable
    package_evr: 26.4.4.968-1
    architecture: x86_64
    executable: /usr/bin/yandex-browser-stable
  onlyoffice:
    enabled: true
    source: rpm
    artifact_path: /opt/alt-deploy-control/artifacts/onlyoffice/onlyoffice-desktopeditors-9.4.0-epm1.repacked.130.x86_64.rpm
    sha256: b8dd26405b5cd79da8a80afc7089007de608a53e7e90ea6a247379bebfe54c9f
    package_name: onlyoffice-desktopeditors
    package_evr: 9.4.0-epm1.repacked.130
    architecture: x86_64
    executable: /usr/bin/onlyoffice-desktopeditors
  nextcloud_desktop:
    enabled: true
    source: alt-repository
    packages: [nextcloud-client, nextcloud-client-kde]
    executable: /usr/bin/nextcloud
```

The checked RPM metadata is respectively
`yandex-browser-stable|26.4.4.968-1|x86_64` and
`onlyoffice-desktopeditors|9.4.0-epm1.repacked.130|x86_64`. Do not download a
package, add a repository, or use a file under a user home directory.

- [ ] **Step 2: Write failing tests for fixed role selection and redaction**

```python
def test_standard_software_uses_a_fixed_role_map() -> None:
    text = (ROLES / "standard_software/tasks/main.yml").read_text()
    assert "software_component_role_map" in text
    assert "include_role" in text
    assert "{{ item }}" not in text

def test_component_roles_verify_rpm_metadata_without_policy_files() -> None:
    text = (ROLES / "software_browser/tasks/main.yml").read_text()
    assert "rpm, -qp" in text
    assert "/policies/managed/" not in text
```

- [ ] **Step 3: Implement the fixed roles**

Each role verifies the preflighted catalog entry again before installation,
copies any RPM to a private mode-0600 temporary path, installs exactly that
path through `apt-get -y install`, removes the temporary copy in `always`, and
verifies exact package EVR plus executable. Do not write browser policy files.
`standard_software` maps known component IDs to fixed role names and has no
free package-list input. Execute `standard_software` after
`domain_login_baseline` and immediately before `domain_verify`, then append an
`ok` component record only after each selected role verifies successfully. A
component failure is terminal and follows the existing result-write before fail
path; it must not claim the failed component succeeded.

- [ ] **Step 4: Verify and commit each approved component group**

Run: `python -m pytest -q --noconftest tests/test_alt_domain_ansible_assets.py tests/test_alt_software_catalog.py`

Run: `git diff --check`

Commit: `feat(alt): add verified core software roles`

### Task 4: Add KRFB only after the remote-access security inputs exist

**Files:**
- Modify: `deploy/alt-linux/control/alt_deploy/vault.py`
- Modify: `deploy/alt-linux/control/alt_deploy/configure.py`
- Create: `deploy/alt-linux/ansible/roles/remote_access_krfb/defaults/main.yml`
- Create: `deploy/alt-linux/ansible/roles/remote_access_krfb/tasks/main.yml`
- Create: `deploy/alt-linux/ansible/roles/remote_access_krfb/templates/krfbrc.j2`
- Create: `deploy/alt-linux/ansible/roles/remote_access_krfb/templates/org.sosn.krfb.desktop.j2`
- Modify: `deploy/alt-linux/ansible/playbooks/tasks/configure_critical_phase.yml`
- Modify: `tests/test_alt_manual_configure_request.py`
- Modify: `tests/test_alt_domain_ansible_assets.py`

**Interfaces:**
- Consumes `assigned_domain_user`, pre-existing user home, `krfb` RPM and two
  existing Vault fields `vault_krfb_desktop_password_obscured` and
  `vault_krfb_unattended_password_obscured`.
- Produces mode-0600 `~/.config/krfbrc`, mode-0644 Plasma autostart entry and
  non-secret `krfb_configured` verification fact.

- [ ] **Step 1: Require a confirmed existing VPN/firewall restriction for TCP 5900 and both Vault fields**

Do not introduce a firewall task. `VaultHealthChecker.check_krfb()` returns
only booleans for the two fields and raises
`remote_access_credentials_unavailable` when either is absent. `start()` calls
it only for `remote_access_profile == "krfb"`.

- [ ] **Step 2: Write failing safety tests**

```python
def test_krfb_role_targets_one_explicit_user_and_never_starts_a_process() -> None:
    text = (ROLES / "remote_access_krfb/tasks/main.yml").read_text()
    assert "assigned_domain_user" in text and "getent" in text
    assert "no_log: true" in text
    assert "systemctl --user" not in text and "loginctl" not in text

def test_krfb_template_has_vault_placeholders_not_password_literals() -> None:
    text = (ROLES / "remote_access_krfb/templates/krfbrc.j2").read_text()
    assert "{{ vault_krfb_desktop_password_obscured }}" in text
    assert "{{ vault_krfb_unattended_password_obscured }}" in text
```

- [ ] **Step 3: Implement the per-user role**

Resolve only `assigned_domain_user` through `getent passwd`, assert its home
exists, belongs to the resolved UID/GID and starts with `/home/`. Install or
verify the `krfb` package through a fixed package name. Create only that
user's `.config` and `.config/autostart`. Render `krfbrc` mode `0600` and the
autostart entry mode `0644`, both `no_log: true`; never launch KRFB or inspect
password keys.

- [ ] **Step 4: Verify and commit**

Run: `python -m pytest -q --noconftest tests/test_alt_manual_configure_request.py tests/test_alt_domain_ansible_assets.py`

Run: `git diff --check`

Commit: `feat(alt): configure assigned-user krfb profile`

### Task 5: Document and validate a controller canary

**Files:**
- Modify: `docs/ALT_MANUAL_ANSIBLE_MVP.md`
- Modify: `docs/runbooks/alt-stage03-base-canary.md`
- Create: `docs/verification/ALT_WORKSTATION_PROFILE_ACCEPTANCE.md`

**Interfaces:**
- Consumes approved artifact records, a registered test machine, a domain test
  user and the controller run result.
- Produces a non-secret acceptance record for base, core-apps and, if approved,
  KRFB.

- [ ] **Step 1: Document the fixed operator route**

Require `workstationctl --json configure preview` before `start`; state that
`core-apps` is unavailable until every catalog entry is enabled and that KRFB
requires the Vault gate, an explicit user and a separately approved restricted
port-5900 path.

- [ ] **Step 2: Validate on ALT after separately approved deployment**

Run the controller readiness command and its stage-03 syntax check, then canary
one already installed workstation. Capture only run ID, status, hostname,
boolean verification facts and reboot flag. Confirm Samba trust, SSSD lookup,
GPO processing and a single reboot only when requested.

- [ ] **Step 3: Final local verification and commit**

Run: `python -m pytest -q --noconftest tests/test_alt_domain_resilience_assets.py tests/test_alt_domain_ansible_assets.py tests/test_alt_manual_configure_request.py tests/test_alt_manual_bootstrap_contract.py tests/alt_linux/test_ansible_base_resilience_assets.py tests/test_alt_software_catalog.py`

Run: `git diff --check`

Commit: `docs(alt): document managed component profiles`

## Self-review

- The specification's five completion items map respectively to Tasks 1, 2,
  3, 4 and 5.
- The plan introduces no topology, DNS, firewall, `netctl`, installer or
  browser-policy changes.
- Search the final plan for `TODO`, `TBD`, `implement later`, and `similar to`
  before execution; no such placeholders are permitted.
