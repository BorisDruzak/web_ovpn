# ALT Workstation: Shares, OnlyOffice and Nextcloud Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give every domain workstation the approved OnlyOffice and Nextcloud Desktop clients, and map `\\antares\Public` for every domain user using supported ALT Group Policy.

**Architecture:** OnlyOffice is a pinned controller artifact with a SHA-256 and strict RPM metadata checks. Nextcloud Desktop is installed when absent from the approved ALT 11.x repository; no user credentials, URL or sync folder are configured. The shared folder is a User GPO at the domain root applied to `Authenticated Users`; it has only user-side settings, so its scope follows users rather than the Pilot computer OU.

**Tech Stack:** Ansible, APT/RPM, ALT `gpupdate`/autofs, Windows AD GPMC, pytest.

## Global Constraints

- Do not change bootstrap, managed ISO, ai curl, AD join, SMB ACLs, `/etc/fstab`, or user credentials.
- OnlyOffice source: `/opt/alt-deploy-control/artifacts/onlyoffice/onlyoffice-desktopeditors-9.4.0-epm1.repacked.130.x86_64.rpm`.
- OnlyOffice SHA-256: `b8dd26405b5cd79da8a80afc7089007de608a53e7e90ea6a247379bebfe54c9f`.
- OnlyOffice identity: `onlyoffice-desktopeditors|9.4.0-epm1.repacked.130|x86_64`.
- Nextcloud source is the active ALT 11.x repository package `nextcloud-client`; it is installed when absent and updated only by the established planned system-upgrade process.
- Shared resource is exactly `\\antares\Public`; DNS and Kerberos SMB read access have been verified from the pilot as `alt-test-2`.
- GPO name is `Network Drive - Public`, link target `sosnadmin.local`, security filter `Authenticated Users`, action `Update`, label `Public`, visible to the user, persistent.
- Keep changes local; do not commit, push, or merge.

---

### Task 1: Contract and regression tests

**Files:**
- Modify: `deploy/alt-linux/ansible/group_vars/all.yml`
- Modify: `tests/test_alt_domain_ansible_assets.py`
- Modify: `tests/test_alt_manual_configure_request.py`

**Interfaces:**
- Produces `software_catalog.onlyoffice` and `software_catalog.nextcloud_desktop` for roles.
- Produces preview actions `install_onlyoffice` and `install_nextcloud_desktop`.

- [ ] **Step 1: Add failing asset-contract tests**

```python
assert variables["software_catalog"]["onlyoffice"]["sha256"] == (
    "b8dd26405b5cd79da8a80afc7089007de608a53e7e90ea6a247379bebfe54c9f"
)
assert variables["software_catalog"]["nextcloud_desktop"] == {"package_name": "nextcloud-client", "executable": "/usr/bin/nextcloud"}
assert "software_onlyoffice" in role_names
assert "software_nextcloud_desktop" in role_names
assert "install_onlyoffice" in ConfigurePlanner(...).preview(...)["actions"]
```

- [ ] **Step 2: Run the focused tests and observe the expected failure**

Run: `pytest -q tests/test_alt_domain_ansible_assets.py tests/test_alt_manual_configure_request.py`

Expected: failure because the two catalog records, roles and preview actions do not yet exist.

- [ ] **Step 3: Add the fixed catalogs and preview actions**

Add exact OnlyOffice artifact metadata above. Add Nextcloud package name and expected executable `nextcloud`. Add two actions after `install_gosuslugi_plugin`.

- [ ] **Step 4: Re-run the focused tests**

Run: `pytest -q tests/test_alt_domain_ansible_assets.py tests/test_alt_manual_configure_request.py`

Expected: PASS.

### Task 2: OnlyOffice role

**Files:**
- Create: `deploy/alt-linux/ansible/roles/software_onlyoffice/defaults/main.yml`
- Create: `deploy/alt-linux/ansible/roles/software_onlyoffice/tasks/main.yml`
- Modify: `deploy/alt-linux/ansible/playbooks/03-configure-domain-workstation.yml`
- Modify: `tests/test_alt_domain_ansible_assets.py`

**Interfaces:**
- Consumes `software_catalog.onlyoffice`.
- Produces `onlyoffice_ok: true` and `onlyoffice_version` after verified installation.

- [ ] **Step 1: Add a failing role-safety test**

```python
assert "software_onlyoffice_catalog" in role_text
assert "delegate_to: localhost" in role_text
assert "onlyoffice_artifact_invalid" in role_text
assert "onlyoffice_rpm_metadata_invalid" in role_text
assert "no_log: true" in role_text
```

- [ ] **Step 2: Run the focused test and observe it fail**

Run: `pytest -q tests/test_alt_domain_ansible_assets.py -k onlyoffice`

Expected: failure because the role does not exist.

- [ ] **Step 3: Implement the minimal idempotent role**

Use controller-side `stat` with SHA-256, inspect the installed EVR, copy only when missing or mismatched, use a root-owned `0700` temporary directory, validate `rpm -qp` against fixed name/EVR/architecture, install via `apt-get -y install`, verify `rpm -q`, verify `/usr/bin/desktopeditors`, and remove the directory in `always`.

- [ ] **Step 4: Include the role in the fixed configure order**

Place it directly after `software_gosuslugi_plugin` and before `software_nextcloud_desktop`.

- [ ] **Step 5: Run focused tests**

Run: `pytest -q tests/test_alt_domain_ansible_assets.py -k onlyoffice`

Expected: PASS.

### Task 3: Nextcloud Desktop role

**Files:**
- Create: `deploy/alt-linux/ansible/roles/software_nextcloud_desktop/defaults/main.yml`
- Create: `deploy/alt-linux/ansible/roles/software_nextcloud_desktop/tasks/main.yml`
- Modify: `deploy/alt-linux/ansible/playbooks/03-configure-domain-workstation.yml`
- Modify: `tests/test_alt_domain_ansible_assets.py`

**Interfaces:**
- Consumes `software_catalog.nextcloud_desktop`.
- Produces `nextcloud_desktop_ok: true` and `nextcloud_desktop_version`.

- [ ] **Step 1: Add a failing repository-role test**

```python
assert "nextcloud-client" in role_text
assert "apt-get, update" in role_text
assert "nextcloud_desktop_install_verification_failed" in role_text
assert "/etc/xdg/autostart" not in role_text
assert "overrideserverurl" not in role_text
```

- [ ] **Step 2: Run the focused test and observe it fail**

Run: `pytest -q tests/test_alt_domain_ansible_assets.py -k nextcloud`

Expected: failure because the role does not exist.

- [ ] **Step 3: Implement the repository-only role**

Run `apt-get update`, inspect installed EVR using RPM, install `nextcloud-client` only when absent, verify the resulting EVR and `/usr/bin/nextcloud`. Do not create autostart entries, first-run helpers, URLs, tokens or directories in user homes.

- [ ] **Step 4: Include it after OnlyOffice**

Use the role order defined in Task 2.

- [ ] **Step 5: Run focused tests**

Run: `pytest -q tests/test_alt_domain_ansible_assets.py -k nextcloud`

Expected: PASS.

### Task 4: Result contract and operator documentation

**Files:**
- Modify: `deploy/alt-linux/ansible/roles/domain_verify/tasks/main.yml`
- Modify: `docs/ALT_MANUAL_ANSIBLE_MVP.md`
- Modify: `tests/test_alt_domain_ansible_assets.py`

**Interfaces:**
- Adds public booleans `onlyoffice_ok` and `nextcloud_desktop_ok` to `verification`.

- [ ] **Step 1: Add failing result-contract tests**

```python
assert "onlyoffice_ok" in domain_verify_text
assert "nextcloud_desktop_ok" in domain_verify_text
assert "vault_" not in domain_verify_text
```

- [ ] **Step 2: Run the focused tests and observe failure**

Run: `pytest -q tests/test_alt_domain_ansible_assets.py -k safe_software_results`

Expected: failure because result keys and documentation are absent.

- [ ] **Step 3: Implement result fields and documentation**

Publish only fact booleans. Document the pinned OnlyOffice artifact workflow and that Nextcloud login is performed by the user after first sign-in.

- [ ] **Step 4: Run focused tests**

Run: `pytest -q tests/test_alt_domain_ansible_assets.py`

Expected: PASS.

### Task 5: Controller deployment and pilot verification

**Files:**
- Modify on controller: `/home/altserver/ansible/group_vars/all.yml`, role and playbook files corresponding to Tasks 1–4.
- Create on controller: `/opt/alt-deploy-control/artifacts/onlyoffice/onlyoffice-desktopeditors-9.4.0-epm1.repacked.130.x86_64.rpm` mode `0600`, owner `altserver:altserver`.

**Interfaces:**
- Consumes the exact local implementation and approved existing OnlyOffice RPM.
- Produces a configure result with the new software verification booleans.

- [ ] **Step 1: Back up each changed controller path and stage files outside the live tree**

Verify source hashes before copying. Do not copy Vault files.

- [ ] **Step 2: Stage the OnlyOffice RPM and verify its checksum and metadata on the controller**

Run:

```bash
sha256sum /opt/alt-deploy-control/artifacts/onlyoffice/onlyoffice-desktopeditors-9.4.0-epm1.repacked.130.x86_64.rpm
rpm -qp --qf '%{NAME}|%{VERSION}-%{RELEASE}|%{ARCH}\n' /opt/alt-deploy-control/artifacts/onlyoffice/onlyoffice-desktopeditors-9.4.0-epm1.repacked.130.x86_64.rpm
```

Expected: the exact global-constraint values.

- [ ] **Step 3: Run syntax and preview checks**

Run controller `ansible-playbook --syntax-check` and `workstationctl --json configure preview` for `alt-a1-pc2`.

Expected: preview contains both new actions.

- [ ] **Step 4: Run configure on `alt-a1-pc2` and verify runtime state**

Verify `rpm -q onlyoffice-desktopeditors nextcloud-client`, `command -v nextcloud`, OnlyOffice executable path determined from the approved RPM, domain trust and SSSD.

- [ ] **Step 5: Repeat configure**

Expected: both software roles skip installation and keep verified versions.

### Task 6: AD GPO for Public share and user-session verification

**Systems:**
- Modify on AD: GPMC on `AD-MAIN`.
- Verify on pilot: `alt-a1-pc2` as `alt-test-2@sosnadmin.local`.

**Interfaces:**
- Consumes working AD GPO client and the verified SMB service `\\antares\Public`.
- Produces user mount `~/net.drives/Public` backed by ALT autofs.

- [ ] **Step 1: Back up the current GPO inventory and create the isolated GPO**

Create `Network Drive - Public`; do not edit Default Domain Policy or existing browser GPOs. Link it to `sosnadmin.local`. The GPO contains only user-side settings and is applied to `Authenticated Users`, which covers all domain users without restricting the location of their AD accounts.

- [ ] **Step 2: Configure user Drive Maps**

In `User Configuration → Preferences → Control Panel Settings → Drive Maps`, create one item with action `Update`, path `\\antares\Public`, label `Public`, reconnect enabled and `Show this drive` enabled. Enable the ALT user policy that exposes mounted drives in the home directory.

- [ ] **Step 3: Update policies in a real domain session**

From the Plasma session of `alt-test-2`, run `gpupdate --target User`, then verify `~/net.drives`, `/run/media/<username>/drives`, and an `ls` of the Public mount.

- [ ] **Step 4: Verify no credentials are stored by the workstation configuration**

Inspect the generated autofs configuration only for the UNC path and supported mount options; do not expose or create `cpassword`, SMB password files, or user tokens.

## Final verification

- [ ] Run `pytest -q`.
- [ ] Run `python -m compileall -q deploy/alt-linux/control/alt_deploy`.
- [ ] Run `git diff --check`.
- [ ] Remove temporary controller staging data and local askpass helper.
- [ ] Report versions, GPO name/link/filter, share access and the exact verification evidence. Do not commit or push.
