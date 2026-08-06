# ALT Playbook Modernization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the dormant, direct-run workstation playbooks with one controller-managed, testable ALT profile that preserves the proven manual bootstrap and AD-join flow, installs the approved Plasma baseline, CryptoPro, Справки БК, browser, and KRFB remote access, and applies browser configuration solely through AD Group Policy.

**Architecture:** `03-configure-domain-workstation.yml` remains the sole workstation configure entry point invoked by `workstationctl`; it does not accept a caller-selected playbook. The existing domain roles stay authoritative for hostname, DNS, X11/LightDM, AD join, SSSD, and Group Policy enablement. New focused roles are selected only through a strict configure request, use an approved local software catalog with SHA-256 checks, and return non-secret verification facts through the existing configure result. Browser installation is an Ansible responsibility; browser settings are AD GPO data delivered by ALT `gpupdate`, never an Ansible browser-policy file.

**Tech Stack:** ALT Workstation K 11.x, Ansible, Ansible Vault, Python controller (`alt_deploy`), LightDM + Plasma X11, SSSD/Samba/Kerberos, KDE KRFB, pytest.

## Global Constraints

- Keep both the managed ISO and `ai curl` installation paths unchanged; this plan covers only the temporary manual-install MVP after bootstrap registration.
- The only controller-managed workstation playbook is `deploy/alt-linux/ansible/playbooks/03-configure-domain-workstation.yml`.
- **Approved first-install ordering:** `bootstrap → full pre-join dist-upgrade → reboot → workstation_base → install gpupdate → domain join (--gpo) → gpupdate-setup enable → machine gpupdate`. The full upgrade is deliberately completed and rebooted before domain join; GPO activation and policy application are deliberately post-join.
- **Approved maintenance ordering:** a full `dist-upgrade` for an already joined workstation is a separately scheduled Ansible maintenance stage. It must not be bundled into domain join, bootstrap, or ordinary application provisioning.
- Preserve the current hostname contract and two modes: `verify` and `change_confirmed`. The current grammar `^(lin|alt|win|deb)-[a-z][0-9]?-(pc[1-9][0-9]*)$` remains valid; `alt-a1-pc1` is accepted.
- ALT Workstation K `11.x` is accepted. A minor release change, for example 11.2 to 11.4, must not block provisioning or require reinstallation.
- Preserve Plasma X11 as the managed LightDM default. Do not add, select, or configure GNOME, GDM, SDDM, XFCE, XRDP, X11VNC, or a Wayland default.
- Bootstrap creates only `ansible`; it neither creates AD users nor joins the domain. AD users already exist, and domain join remains controller-only.
- Do not create local employee accounts. The technical local accounts remain `osn-admin` and `ansible`; employees sign in through AD.
- Do not use or reintroduce MyChat, Zabbix, printers, ConsultantPlus, static routes, legacy forced DNS, GNOME GUI, or legacy RDP automation.
- `workstation_network` remains the only domain DNS policy. No new role may modify NetworkManager DNS, routes, or firewall rules.
- Browser policy is managed only through the separate AD GPO `ALT - Yandex Browser - Pilot`, linked only to `OU=Pilot,OU=Linux,OU=Устройства,DC=sosnadmin,DC=local`. No Ansible role may create `/etc/opt/yandex/browser/policies/managed/*.json`, edit browser preferences, or embed a browser policy value.
- The AD Central Store path is `\\sosnadmin.local\SYSVOL\sosnadmin.local\Policies\PolicyDefinitions`; its `ru-RU` and recommended `en-US` language directories carry the matching ADML files.
- Group Policy has two explicit stages: install `gpupdate` and its dependencies before domain join, then enable the workstation profile and request a machine policy update only after a successful join. `alterator-gpupdate` is optional UI support and must not make provisioning fail when unavailable in the ALT repository.
- Secrets, passwords, password hashes, Vault contents, and KRFB obscured passwords must never be stored in Git, request JSON, Ansible output, result JSON, or controller logs. Vault and its password file remain mode `0600` and readable only by the controller service account.
- A KRFB configuration is always assigned to an explicitly named existing AD user. Never infer a user from `/home`, a graphical session, `getent` enumeration, or “the first real user”.
- KRFB starts only from the assigned user’s Plasma autostart after graphical login. Ansible must not launch it, kill it, or perform a VNC authentication probe.
- Enabling KRFB is allowed only after an operator confirms that port 5900 is restricted by the existing VPN/firewall policy. This plan does not open ports or modify firewall configuration.
- Legacy scripts are retained unchanged and read-only until a separately approved archival/removal action. They are not invoked by the new path.

---

## Execution inputs required before the software roles are enabled

The playbook structure and validation can be implemented without external installers. Enabling each of `cryptopro`, `spravki-bk`, or `browser` additionally requires an approved controller-side artifact record containing: component ID, vendor/version, immutable file path under the controlled artifact root, SHA-256, and the exact package list or unattended installer arguments. No artifact is copied from `/home/altserver` into Git, and no role may fetch an installer from an arbitrary URL.

The KRFB role requires two already-obscured values in the existing Ansible Vault:

```yaml
vault_krfb_desktop_password_obscured: <secret>
vault_krfb_unattended_password_obscured: <secret>
```

The literal values must be entered only on the controller with `ansible-vault edit`; they must not appear in this plan, a template fixture, a request, or a commit.

## File structure

| Path | Change | Responsibility |
| --- | --- | --- |
| `deploy/alt-linux/control/alt_deploy/configure.py` | Modify | Strictly validate new profile selection fields, expose selected actions in preview, and invoke the additional Vault health gate only for KRFB. |
| `deploy/alt-linux/control/alt_deploy/vault.py` | Modify | Check KRFB Vault variable presence without returning secret values. |
| `deploy/alt-linux/ansible/playbooks/03-configure-domain-workstation.yml` | Modify | Keep the fixed domain sequence and insert the new roles before final verification. |
| `deploy/alt-linux/ansible/group_vars/all.yml` | Modify | Declare non-secret, versioned defaults for the approved profile and Plasma baseline. |
| `deploy/alt-linux/ansible/group_vars/software_catalog.yml` | Create | Non-secret component catalog; only SHA-256-pinned controller artifacts may be enabled. |
| `deploy/alt-linux/ansible/roles/standard_software/tasks/main.yml` | Modify | Select only the permitted component roles from the validated request. |
| `deploy/alt-linux/ansible/roles/software_cryptopro/*` | Create | Install and verify the SHA-256-pinned CryptoPro artifact. |
| `deploy/alt-linux/ansible/roles/software_spravki_bk/*` | Create | Install and verify the SHA-256-pinned Справки БК artifact. |
| `deploy/alt-linux/ansible/roles/software_browser/*` | Create | Install and verify the approved browser artifact and its declared package set. |
| `deploy/alt-linux/ansible/roles/alt_group_policy_prerequisites/{defaults,tasks}/*` | Create | Install ALT `gpupdate` and its dependencies before domain join; optional Alterator UI support must not block provisioning. |
| `deploy/alt-linux/ansible/roles/alt_group_policy_client/{defaults,tasks}/*` | Create | Enable the already-installed ALT GPO client after a new or existing domain join and apply machine GPOs; it contains no browser policy values. |
| `deploy/alt-linux/ansible/roles/domain_join/tasks/main.yml` | Modify | Add `--gpo` to the first domain join without weakening trust/conflict checks. |
| `deploy/alt-linux/ansible/roles/plasma_baseline/{defaults,tasks,templates}/*` | Create | Manage only the approved non-secret Plasma settings; never copy an entire user `.config`. |
| `deploy/alt-linux/ansible/roles/remote_access_krfb/{defaults,tasks,templates}/*` | Create | Write a protected per-user `krfbrc`, Plasma autostart entry, and non-secret verification facts; never start KRFB. |
| `deploy/alt-linux/ansible/roles/domain_verify/tasks/main.yml` | Modify | Include selected-profile verification fields in the public configure result without exposing secrets. |
| `tests/test_alt_manual_configure_request.py` | Modify | Cover request validation, preview actions, Vault gates, and redaction behavior. |
| `tests/test_alt_domain_ansible_assets.py` | Modify | Assert exact role order, X11 invariants, non-secret template properties, and no forbidden legacy technology. |
| `tests/test_alt_software_catalog.py` | Create | Validate catalog shape, SHA-256 format, component allowlist, and disabled-by-default behavior. |
| `docs/ALT_LEGACY_PLAYBOOKS_INVENTORY.md` | Create | State the disposition and successor for every audited legacy playbook; this is an inventory, not an instruction to delete files. |
| `docs/ALT_MANUAL_ANSIBLE_MVP.md` | Modify | Document the expanded request contract, profile order, first-login behavior, KRFB network gate, and acceptance checks. |

## Target configure request contract

The existing immutable fields remain. Add the following three fields and reject every other field:

```json
{
  "software_profile": "base",
  "remote_access_profile": "none",
  "assigned_domain_user": null
}
```

Allowed values:

| Field | Type | Allowed values | Rule |
| --- | --- | --- | --- |
| `software_profile` | string | `base`, `core-apps` | `base` applies the Plasma baseline only. `core-apps` requests the three catalog components after all are enabled and validated. |
| `remote_access_profile` | string | `none`, `krfb` | `krfb` adds only the KRFB role. |
| `assigned_domain_user` | string or `null` | lowercase short AD login or `@sosnadmin.local` UPN | Required for `krfb`; must resolve through SSSD before its home is prepared. It is independent of `domain_test_user`. |

For a normal domain workstation without remote access:

```json
{
  "machine_uuid": "<registered UUID>",
  "final_hostname": "alt-a1-pc1",
  "hostname_mode": "verify",
  "profile": "standard-domain",
  "domain": "sosnadmin.local",
  "realm": "SOSNADMIN.LOCAL",
  "workgroup": "SOSNADM",
  "computer_ou": "OU=Pilot,OU=Linux,OU=Устройства,DC=sosnadmin,DC=local",
  "domain_test_user": "alt-test-2@sosnadmin.local",
  "software_profile": "base",
  "remote_access_profile": "none",
  "assigned_domain_user": null
}
```

The same request with `remote_access_profile: "krfb"` must include the exact assigned UPN in `assigned_domain_user`. The controller still invokes the fixed playbook and still takes AD join credentials only from Vault.

## Planned role order

```text
manual_preflight
→ workstation_identity
→ workstation_base                 (LightDM Plasma X11)
→ alt_group_policy_prerequisites  (install gpupdate before join)
→ workstation_network              (domain DNS only)
→ domain_join                      (first join includes system-auth --gpo)
→ alt_group_policy_client          (every configure run)
→ plasma_baseline                  (non-secret /etc/skel defaults)
→ standard_software                (base or three catalog roles)
→ remote_access_krfb               (only when requested, never starts it)
→ domain_verify                    (writes final public result)
```

### Task 1: Extend the fixed configure contract and secret gates

**Files:**
- Modify: `deploy/alt-linux/control/alt_deploy/configure.py`
- Modify: `deploy/alt-linux/control/alt_deploy/vault.py`
- Modify: `tests/test_alt_manual_configure_request.py`

**Interfaces:**
- Consumes: the registered machine UUID, the existing fixed `standard-domain` request, and `VaultHealthChecker.check_ad_join()`.
- Produces: `ConfigureRequest.software_profile: str`, `ConfigureRequest.remote_access_profile: str`, `ConfigureRequest.assigned_domain_user: str | None`, and `VaultHealthChecker.check_krfb() -> dict[str, object]`.

- [ ] **Step 1: Write failing request-validation tests**

```python
def test_configure_request_accepts_base_profile_without_remote_user() -> None:
    payload = valid_request() | {
        "software_profile": "base",
        "remote_access_profile": "none",
        "assigned_domain_user": None,
    }
    request = ConfigureRequest.from_mapping(payload, expected_uuid=MACHINE_UUID)
    assert request.assigned_domain_user is None


def test_configure_request_requires_explicit_ad_user_for_krfb() -> None:
    payload = valid_request() | {
        "software_profile": "base",
        "remote_access_profile": "krfb",
        "assigned_domain_user": None,
    }
    with pytest.raises(ControlError, match="assigned domain user"):
        ConfigureRequest.from_mapping(payload, expected_uuid=MACHINE_UUID)
```

- [ ] **Step 2: Run the focused tests and confirm they fail because the new fields are rejected**

Run: `pytest tests/test_alt_manual_configure_request.py -q`

Expected: failure in the new tests with `configure_request_invalid` until the strict field set and dataclass are extended.

- [ ] **Step 3: Implement the exact request rules**

Extend `REQUEST_FIELDS`, `ConfigureRequest`, and `to_dict()` with the three fields above. Add constants:

```python
SOFTWARE_PROFILES = frozenset({"base", "core-apps"})
REMOTE_ACCESS_PROFILES = frozenset({"none", "krfb"})
```

Normalize `software_profile` and `remote_access_profile` to lowercase. Permit `assigned_domain_user is None` only when `remote_access_profile == "none"`; otherwise normalize it to lowercase and validate against the existing short-login/UPN regular expressions. Keep the current exact-field rejection so passwords, artifact paths, playbook names, and arbitrary Ansible variables cannot enter request JSON.

- [ ] **Step 4: Make preview accurately describe selected non-secret work**

Replace the constant action list with `ConfigureRequest.actions() -> list[str]`. It must return the existing six domain actions, plus `apply_plasma_baseline` for every request, `install_core_apps` only for `core-apps`, and `configure_krfb` only for `krfb`. `preview()` returns this list without reading Vault or contacting the target.

- [ ] **Step 5: Add the KRFB-only Vault health gate**

Add constants for the two KRFB variable names in `vault.py` and implement `check_krfb()` by decrypting the already-private Vault file and returning only:

```python
{
    "status": "ok",
    "checks": {
        "krfb_desktop_password_present": True,
        "krfb_unattended_password_present": True,
    },
}
```

On missing or empty values it raises `ControlError(code="remote_access_credentials_unavailable", ...)` with the same two boolean names and no values. In `ConfigurePlanner.start()`, call `check_ad_join()` for all requests and `check_krfb()` only when `request.remote_access_profile == "krfb"`.

- [ ] **Step 6: Add redaction and preview tests**

```python
def test_configure_preview_adds_krfb_without_secret_fields() -> None:
    request = ConfigureRequest.from_mapping(krfb_request(), expected_uuid=MACHINE_UUID)
    preview = ConfigurePlanner(SimpleNamespace(), machines=machine_repo).preview(MACHINE_UUID, request)
    assert "configure_krfb" in preview["actions"]
    assert "password" not in repr(preview).lower()


def test_krfb_vault_gate_reports_booleans_only() -> None:
    checker = VaultHealthChecker(SimpleNamespace())
    checker._build_checks = lambda: {"decryptable": True}  # type: ignore[method-assign]
    checker._decrypt = lambda: "vault_krfb_desktop_password_obscured: secret\nvault_krfb_unattended_password_obscured: secret\n"  # type: ignore[method-assign]
    assert checker.check_krfb()["checks"] == {
        "krfb_desktop_password_present": True,
        "krfb_unattended_password_present": True,
    }
```

- [ ] **Step 7: Run controller tests**

Run: `pytest tests/test_alt_manual_configure_request.py -q`

Expected: PASS; all request variants retain the fixed playbook and no test assertion contains a real secret.

- [ ] **Step 8: Commit the isolated controller contract**

```bash
git add deploy/alt-linux/control/alt_deploy/configure.py deploy/alt-linux/control/alt_deploy/vault.py tests/test_alt_manual_configure_request.py
git commit -m "feat(alt): add controlled workstation profile options"
```

### Task 1A: Enable ALT Group Policy and prepare the AD Central Store

**Files:**
- Modify: `deploy/alt-linux/ansible/roles/domain_join/tasks/main.yml`
- Create: `deploy/alt-linux/ansible/roles/alt_group_policy_client/defaults/main.yml`
- Create: `deploy/alt-linux/ansible/roles/alt_group_policy_client/tasks/main.yml`
- Modify: `deploy/alt-linux/ansible/playbooks/03-configure-domain-workstation.yml`
- Modify: `deploy/alt-linux/ansible/roles/domain_verify/tasks/main.yml`
- Modify: `tests/test_alt_domain_ansible_assets.py`
- Create: `docs/ALT_AD_GROUP_POLICY_PILOT.md`

**Interfaces:**
- Consumes: a valid Samba trust from `domain_join`, the AD Central Store at `\\sosnadmin.local\SYSVOL\sosnadmin.local\Policies\PolicyDefinitions`, and GPO `ALT - Yandex Browser - Pilot` linked only to `OU=Pilot,OU=Linux,OU=Устройства,DC=sosnadmin,DC=local`.
- Produces: `alt_group_policy_enabled: bool`, `alt_group_policy_machine_updated: bool`, and a workstation where `system-auth write ad … --gpo` is used only during the initial join.

- [ ] **Step 1: Write failing asset tests for the group-policy client**

```python
def test_domain_join_enables_gpo_on_the_first_join_only() -> None:
    content = (ANSIBLE_ROOT / "roles" / "domain_join" / "tasks" / "main.yml").read_text(encoding="utf-8")
    assert '"--createcomputer={{ alt_createcomputer_path }}"' in content
    assert '"--gpo"' in content
    assert "when: not domain_join_already_joined" in content


def test_group_policy_client_is_independent_of_rejoin() -> None:
    content = (ANSIBLE_ROOT / "roles" / "alt_group_policy_client" / "tasks" / "main.yml").read_text(encoding="utf-8")
    assert "gpupdate" in content
    assert "alterator-gpupdate" in content
    assert "gpupdate-setup, enable" in content
    assert "gpupdate, --target, Computer, --system, --force" in content
    assert "domain_join_already_joined" not in content
```

- [ ] **Step 2: Run the tests and confirm the current playbook lacks the GPO client role and `--gpo`**

Run: `pytest tests/test_alt_domain_ansible_assets.py -q`

Expected: FAIL because the current `system-auth` command has no `--gpo` argument and no `alt_group_policy_client` role exists.

- [ ] **Step 3: Add `--gpo` without changing the join security model**

Append a literal `--gpo` argument to the existing `system-auth write ad` `argv` list, immediately after `--createcomputer={{ alt_createcomputer_path }}`. Keep the Kerberos ticket, LDAP conflict check, `no_log: true`, and `when: not domain_join_already_joined` exactly as they are. A valid existing trust remains a no-rejoin path; Group Policy enablement is supplied by the new role instead.

- [ ] **Step 4: Implement the two-stage workstation GPO roles**

Set the role defaults to:

```yaml
---
alt_group_policy_profile: workstation
```

`alt_group_policy_prerequisites` runs before `domain_join` and contains:

```yaml
- ansible.builtin.package:
    name: gpupdate
    state: present
```

It must not require `alterator-gpupdate`; install that package only when an explicitly approved repository check confirms it is resolvable.

`alt_group_policy_client` runs after `domain_join` and contains:

```yaml
- ansible.builtin.command:
    argv: [gpupdate-setup, enable]
  register: alt_group_policy_enable
  changed_when: "'Created symlink' in alt_group_policy_enable.stdout"

- ansible.builtin.command:
    argv: [gpupdate, --target, Computer, --system, --force]
  register: alt_group_policy_machine_update
  changed_when: false

- ansible.builtin.assert:
    that:
      - alt_group_policy_machine_update.rc == 0
    fail_msg: ALT_PREFLIGHT_FAILURE:group_policy_update_failed

- ansible.builtin.set_fact:
    alt_group_policy_enabled: true
    alt_group_policy_machine_updated: true
```

Do not set a hard-coded DC in `/etc/gpupdate/gpupdate.ini`; the domain client selects the Samba backend. Do not call a user-target policy update as `ansible`, because browser user policy is applied at the domain user’s login. Do not create a browser JSON policy file.

- [ ] **Step 5: Integrate the role and public verification**

Place `alt_group_policy_prerequisites` immediately after `workstation_base` and before `domain_join`; place `alt_group_policy_client` immediately after `domain_join`. In `domain_verify`, append only these booleans to the public `verification` object:

```yaml
group_policy: "{{ alt_group_policy_enabled | default(false) and alt_group_policy_machine_updated | default(false) }}"
```

Keep `domain_verify` last and preserve all existing result fields.

- [ ] **Step 6: Prepare AD Central Store safely on Windows Server**

Perform this once in a maintenance window from an elevated Windows PowerShell session on an AD administration host. It is a Windows Server operation, not an Ansible task and not a workstation bootstrap action.

```powershell
dcdiag /test:Advertising /test:SysVolCheck /test:DFSREvent
repadmin /replsummary
repadmin /showrepl *

$domain = (Get-ADDomain).DNSRoot
$centralStore = "\\$domain\SYSVOL\$domain\Policies\PolicyDefinitions"
New-Item -ItemType Directory -Path $centralStore -Force
New-Item -ItemType Directory -Path (Join-Path $centralStore 'ru-RU') -Force
New-Item -ItemType Directory -Path (Join-Path $centralStore 'en-US') -Force
```

Take a System State/SYSVOL backup according to the organization’s existing Windows Server backup procedure before this command. Continue only when `dcdiag` and `repadmin` report healthy SYSVOL/replication; otherwise stop without creating or copying Central Store content.

- [ ] **Step 7: Install and copy the ADMX/ADML templates**

On an administrative ALT system, install exactly:

```bash
sudo apt-get update
sudo apt-get install admx-basealt admx-yandex-browser
find /usr/share/PolicyDefinitions -maxdepth 2 -type f \( -name '*.admx' -o -name '*.adml' \) -print | sort
```

Copy the resulting `.admx` files, `ru-RU/*.adml`, and available `en-US/*.adml` from `/usr/share/PolicyDefinitions` to the matching Central Store directories. Use a staging directory and copy only files supplied by `admx-basealt` and `admx-yandex-browser`; do not replace unrelated Microsoft or third-party templates. On Windows, after copying to a staging drive, use:

```powershell
robocopy 'D:\ALT-ADMX\PolicyDefinitions' $centralStore *.admx /R:2 /W:2 /COPY:DAT
robocopy 'D:\ALT-ADMX\PolicyDefinitions\ru-RU' (Join-Path $centralStore 'ru-RU') *.adml /R:2 /W:2 /COPY:DAT
robocopy 'D:\ALT-ADMX\PolicyDefinitions\en-US' (Join-Path $centralStore 'en-US') *.adml /R:2 /W:2 /COPY:DAT
```

Record package versions and hashes of the copied files in the change record. Re-open GPMC after replication and confirm that the ALT and Yandex policy categories load without an ADMX parsing error.

- [ ] **Step 8: Create and scope the browser GPO**

Create `ALT - Yandex Browser - Pilot` in `gpmc.msc` and link it only to `sosnadmin.local/Устройства/Linux/Pilot`. Do not link it to the domain root and do not modify `Default Domain Policy`. The initial GPO may be empty: policy values such as home page, SSO allowlists, extension rules, or update behaviour must be approved in a separate browser-policy change, because none are defined by this project specification.

Validate the scope with:

```powershell
Get-GPInheritance -Target 'OU=Pilot,OU=Linux,OU=Устройства,DC=sosnadmin,DC=local'
Get-GPO -Name 'ALT - Yandex Browser - Pilot'
```

- [ ] **Step 9: Write the AD and client acceptance procedure**

Document the following non-secret evidence in `docs/ALT_AD_GROUP_POLICY_PILOT.md`:

```text
Central Store exists with required ADMX and matching ru-RU/en-US ADML files
→ GPMC displays ALT and Yandex Browser templates
→ ALT - Yandex Browser - Pilot is linked only to the Pilot OU
→ workstation net ads testjoin is successful
→ gpupdate-setup status is enabled
→ gpupdate --target Computer --system --force exits 0
→ a domain user signs in and user GPO processing completes
→ gpresult confirms the Pilot GPO scope
→ browser://policy displays only the deliberately configured browser policies
```

- [ ] **Step 10: Run regression tests and commit**

Run: `pytest tests/test_alt_domain_ansible_assets.py -q`

Expected: PASS; a GPO client role is present after domain join, first join uses `--gpo`, the existing safe rejoin test remains intact, and browser-policy paths do not occur in any Ansible role.

```bash
git add deploy/alt-linux/ansible/playbooks/03-configure-domain-workstation.yml deploy/alt-linux/ansible/roles/domain_join/tasks/main.yml deploy/alt-linux/ansible/roles/alt_group_policy_client deploy/alt-linux/ansible/roles/domain_verify/tasks/main.yml tests/test_alt_domain_ansible_assets.py docs/ALT_AD_GROUP_POLICY_PILOT.md
git commit -m "feat(alt): enable domain group policy client"
```

### Task 2: Record legacy scope and establish a fail-closed software catalog

**Files:**
- Create: `deploy/alt-linux/ansible/group_vars/software_catalog.yml`
- Create: `tests/test_alt_software_catalog.py`
- Create: `docs/ALT_LEGACY_PLAYBOOKS_INVENTORY.md`

**Interfaces:**
- Consumes: `software_profile` from Task 1.
- Produces: `software_catalog: dict[str, dict[str, object]]` with exactly the component IDs `cryptopro`, `spravki-bk`, and `browser`.

- [ ] **Step 1: Write failing catalog tests**

```python
def test_catalog_contains_only_the_approved_component_ids() -> None:
    catalog = yaml.safe_load(CATALOG_PATH.read_text(encoding="utf-8"))["software_catalog"]
    assert set(catalog) == {"cryptopro", "spravki-bk", "browser"}
    assert all(item["enabled"] is False for item in catalog.values())


def test_enabled_catalog_entry_requires_pinned_artifact_metadata() -> None:
    entry = {"enabled": True, "artifact_path": "/srv/alt-deploy/artifacts/x.rpm", "sha256": "0" * 64, "packages": ["x"]}
    assert validate_catalog_entry("browser", entry) is None
```

`validate_catalog_entry()` is a small test helper in the test module; it asserts a boolean `enabled`, an absolute artifact path under `/srv/alt-deploy/artifacts/`, a lowercase 64-character hexadecimal SHA-256, and a non-empty list of package names when `enabled` is true.

- [ ] **Step 2: Run the catalog tests and confirm the catalog file is absent**

Run: `pytest tests/test_alt_software_catalog.py -q`

Expected: FAIL with a missing catalog file.

- [ ] **Step 3: Add the disabled-by-default catalog**

Create this non-secret structure. Disabled components have no executable installation data, which makes `core-apps` fail closed until an approved artifact record is committed in a separate reviewed change.

```yaml
---
software_catalog:
  cryptopro:
    enabled: false
  spravki-bk:
    enabled: false
  browser:
    enabled: false
```

When a component is approved, its entry must become:

```yaml
enabled: true
artifact_path: /srv/alt-deploy/artifacts/<approved-file>
sha256: <64 lowercase hexadecimal characters>
packages:
  - <exact package name>
```

The artifact itself lives only in `/srv/alt-deploy/artifacts/` on the controller with root-owned immutable release storage; the repository stores metadata, not binary installers.

- [ ] **Step 4: Add the legacy inventory**

Create a table with these exact rows and disposition:

| Legacy controller item | Disposition | Successor / reason |
| --- | --- | --- |
| `ctipro_pro.yml` | Replace | `software_cryptopro` after SHA-256-pinned artifact approval. |
| `spravki.yml` | Replace | `software_spravki_bk` after SHA-256-pinned artifact approval. |
| `ya.yml` | Replace | `software_browser` after browser package/version approval. |
| `setup_rdp.yml`, `start_x11vnc.sh` | Retire from workstation scope | `remote_access_krfb`; do not delete yet. |
| `desktop_icon.yml`, `/home/altserver/gui/gui.yml` | Retire from workstation scope | Obsolete GNOME/DING configuration; Plasma baseline is separate and minimal. |
| `force_dns_nm.yml` | Retire from workstation scope | `workstation_network` owns domain DNS. |
| `net-work.yml` | Retire from workstation scope | Static routes are out of scope. |
| `zabbix_in.yml` | Retire from workstation scope | Zabbix is out of scope. |
| `add_single_printer.yml`, `printers.yml`, `printers_config.yml`, `printers_new.yml` | Retire from workstation scope | Printers are out of scope. |
| `cons.yml` | Retire from workstation scope | ConsultantPlus is installed by another method. |
| `share.yml` | Deferred, unchanged | No approved replacement requirements; do not invoke or alter it. |
| `icon.yml`, `generate-client.sh`, `vault.yml`, `vk_team.yaml` | Preserve, no workstation invocation | Require separate ownership review before any action. |

State that these `/home/altserver` files are not called by the current control plane and must not be deleted as part of this work.

- [ ] **Step 5: Run catalog and documentation tests**

Run: `pytest tests/test_alt_software_catalog.py -q`

Expected: PASS; all three catalog entries are disabled and no unexpected component can be selected.

- [ ] **Step 6: Commit the inventory and catalog contract**

```bash
git add deploy/alt-linux/ansible/group_vars/software_catalog.yml tests/test_alt_software_catalog.py docs/ALT_LEGACY_PLAYBOOKS_INVENTORY.md
git commit -m "docs(alt): inventory legacy workstation automation"
```

### Task 3: Add minimal, user-safe Plasma baseline management

**Files:**
- Create: `deploy/alt-linux/ansible/roles/plasma_baseline/defaults/main.yml`
- Create: `deploy/alt-linux/ansible/roles/plasma_baseline/tasks/main.yml`
- Create: `deploy/alt-linux/ansible/roles/plasma_baseline/templates/powerdevilrc.j2`
- Create: `deploy/alt-linux/ansible/roles/plasma_baseline/templates/kscreenlockerrc.j2`
- Create: `deploy/alt-linux/ansible/roles/plasma_baseline/templates/kxkbrc.j2`
- Modify: `deploy/alt-linux/ansible/group_vars/all.yml`
- Modify: `tests/test_alt_domain_ansible_assets.py`

**Interfaces:**
- Consumes: managed `/etc/skel` used by `pam_mkhomedir.so` and `workstation_desktop_session: x11`.
- Produces: three non-secret default files in `/etc/skel/.config/`, copied when an AD home is first created; it never discovers or rewrites an existing employee’s complete `.config` tree.

- [ ] **Step 1: Write failing structural tests for baseline scope**

```python
def test_plasma_baseline_manages_only_approved_nonsecret_files() -> None:
    rendered = (ANSIBLE_ROOT / "roles" / "plasma_baseline" / "tasks" / "main.yml").read_text(encoding="utf-8")
    assert "/etc/skel/.config/powerdevilrc" in rendered
    assert "/etc/skel/.config/kscreenlockerrc" in rendered
    assert "/etc/skel/.config/kxkbrc" in rendered
    assert "/home/" not in rendered
    assert "find" not in rendered
```

- [ ] **Step 2: Run the structural tests and confirm the new role is missing**

Run: `pytest tests/test_alt_domain_ansible_assets.py -q`

Expected: FAIL because `plasma_baseline` and its templates do not exist.

- [ ] **Step 3: Implement the exact baseline templates**

Use `ansible.builtin.file` to create `/etc/skel/.config` as `root:root`, mode `0755`, then use `ansible.builtin.template` with `root:root`, mode `0644` for these exact non-secret contents:

```ini
# powerdevilrc
[AC][Display]
TurnOffDisplayIdleTimeoutSec=-1
TurnOffDisplayWhenIdle=false

[AC][SuspendAndShutdown]
AutoSuspendAction=0

# kscreenlockerrc
[Daemon]
Timeout=0

# kxkbrc
[Layout]
SwitchMode=Global
```

Do not copy `kcminputrc` or any whole `.config` directory: mouse acceleration has not been approved as a standard policy. Do not add autostart entries in this role.

- [ ] **Step 4: Insert the baseline role in the fixed sequence**

Modify `03-configure-domain-workstation.yml` to place `plasma_baseline` after `domain_join` and before `standard_software`. Keep `domain_verify` last.

- [ ] **Step 5: Run regression tests**

Run: `pytest tests/test_alt_domain_ansible_assets.py -q`

Expected: PASS; X11 remains the default, the old GNOME/RDP terms do not appear in the new role, and only the three approved files are managed.

- [ ] **Step 6: Commit the Plasma baseline**

```bash
git add deploy/alt-linux/ansible/group_vars/all.yml deploy/alt-linux/ansible/playbooks/03-configure-domain-workstation.yml deploy/alt-linux/ansible/roles/plasma_baseline tests/test_alt_domain_ansible_assets.py
git commit -m "feat(alt): add minimal plasma baseline role"
```

### Task 4: Make `standard_software` a strict component selector

**Files:**
- Modify: `deploy/alt-linux/ansible/roles/standard_software/tasks/main.yml`
- Create: `deploy/alt-linux/ansible/roles/software_cryptopro/defaults/main.yml`
- Create: `deploy/alt-linux/ansible/roles/software_cryptopro/tasks/main.yml`
- Create: `deploy/alt-linux/ansible/roles/software_spravki_bk/defaults/main.yml`
- Create: `deploy/alt-linux/ansible/roles/software_spravki_bk/tasks/main.yml`
- Create: `deploy/alt-linux/ansible/roles/software_browser/defaults/main.yml`
- Create: `deploy/alt-linux/ansible/roles/software_browser/tasks/main.yml`
- Modify: `tests/test_alt_domain_ansible_assets.py`

**Interfaces:**
- Consumes: `software_profile` from Task 1 and `software_catalog` from Task 2.
- Produces: `selected_software_components: list[str]`, containing `[]` for `base` and exactly `["cryptopro", "spravki-bk", "browser"]` for `core-apps`.

- [ ] **Step 1: Write failing selector tests**

```python
def test_standard_software_allows_only_base_or_the_three_component_profile() -> None:
    content = (ANSIBLE_ROOT / "roles" / "standard_software" / "tasks" / "main.yml").read_text(encoding="utf-8")
    assert "software_profile == 'base'" in content
    assert "software_profile == 'core-apps'" in content
    assert "software_component_catalog_invalid" in content
    assert "include_role" in content
```

- [ ] **Step 2: Run the test and confirm the current package-list role does not satisfy it**

Run: `pytest tests/test_alt_domain_ansible_assets.py -q`

Expected: FAIL because the role currently only applies `standard_packages + organization_packages`.

- [ ] **Step 3: Implement deterministic selection and catalog assertions**

Replace the free package-list behavior with these facts:

```yaml
- ansible.builtin.set_fact:
    selected_software_components: >-
      {{ [] if software_profile == 'base'
         else ['cryptopro', 'spravki-bk', 'browser'] }}

- ansible.builtin.assert:
    that:
      - software_profile in ['base', 'core-apps']
      - selected_software_components | difference(software_catalog.keys() | list) | length == 0
      - selected_software_components | map('extract', software_catalog) | map(attribute='enabled') | select('equalto', true) | list | length == selected_software_components | length
    fail_msg: ALT_PREFLIGHT_FAILURE:software_component_catalog_invalid
```

For each selected component, use `ansible.builtin.include_role` with the mapping `cryptopro → software_cryptopro`, `spravki-bk → software_spravki_bk`, and `browser → software_browser`. Do not interpolate a role name from input.

- [ ] **Step 4: Implement the identical safe installer contract in each component role**

Each role reads only its fixed `software_catalog.<component>` entry, asserts the approved artifact exists on the controller-defined path and its `sha256sum` equals the catalog value, then installs only the catalog’s declared packages using `ansible.builtin.package` or `ansible.builtin.apt_rpm` as appropriate for the confirmed artifact format. The verification task records a boolean `software_<component>_verified`; it must never emit the installer payload or a password. `software_browser` installs and verifies the browser only: it must not write `/etc/opt/yandex/browser/policies/managed/`, browser preference files, or any policy JSON because policy delivery belongs to Task 1A.

The concrete module is selected by the approved artifact record: a repository package uses `ansible.builtin.package`; a signed RPM uses `ansible.builtin.apt_rpm` with its fixed artifact path. A role rejects any other `artifact_format` with `ALT_PREFLIGHT_FAILURE:software_component_catalog_invalid`.

- [ ] **Step 5: Run structural and catalog tests**

Run: `pytest tests/test_alt_domain_ansible_assets.py tests/test_alt_software_catalog.py -q`

Expected: PASS; `core-apps` cannot run while any catalog component remains disabled.

- [ ] **Step 6: Commit the selector and component roles**

```bash
git add deploy/alt-linux/ansible/roles/standard_software deploy/alt-linux/ansible/roles/software_cryptopro deploy/alt-linux/ansible/roles/software_spravki_bk deploy/alt-linux/ansible/roles/software_browser tests/test_alt_domain_ansible_assets.py
git commit -m "feat(alt): add pinned core software roles"
```

### Task 5: Add per-user KRFB configuration and Plasma autostart

**Files:**
- Create: `deploy/alt-linux/ansible/roles/remote_access_krfb/defaults/main.yml`
- Create: `deploy/alt-linux/ansible/roles/remote_access_krfb/tasks/main.yml`
- Create: `deploy/alt-linux/ansible/roles/remote_access_krfb/templates/krfbrc.j2`
- Create: `deploy/alt-linux/ansible/roles/remote_access_krfb/templates/org.sosn.krfb.desktop.j2`
- Modify: `deploy/alt-linux/ansible/playbooks/03-configure-domain-workstation.yml`
- Modify: `deploy/alt-linux/ansible/roles/domain_verify/tasks/main.yml`
- Modify: `tests/test_alt_domain_ansible_assets.py`

**Interfaces:**
- Consumes: `remote_access_profile`, `assigned_domain_user`, and the two Vault variables from Task 1; SSSD is available after `domain_join`.
- Produces: the assigned user’s `~/.config/krfbrc` (mode `0600`), `~/.config/autostart/org.sosn.krfb.desktop` (mode `0644`), and public facts `krfb_configured` and `krfb_autostart_configured`.

- [ ] **Step 1: Write failing tests for user targeting and secret handling**

```python
def test_krfb_role_requires_explicit_user_and_never_launches_krfb() -> None:
    content = (ANSIBLE_ROOT / "roles" / "remote_access_krfb" / "tasks" / "main.yml").read_text(encoding="utf-8")
    assert "assigned_domain_user" in content
    assert "getent" in content
    assert "krfb_config_home" in content
    assert "/usr/bin/krfb" not in content
    assert "no_log: true" in content


def test_krfb_template_uses_vault_variables_and_has_no_literal_password() -> None:
    content = (ANSIBLE_ROOT / "roles" / "remote_access_krfb" / "templates" / "krfbrc.j2").read_text(encoding="utf-8")
    assert "{{ vault_krfb_desktop_password_obscured }}" in content
    assert "{{ vault_krfb_unattended_password_obscured }}" in content
```

- [ ] **Step 2: Run the test and confirm the role is absent**

Run: `pytest tests/test_alt_domain_ansible_assets.py -q`

Expected: FAIL because the KRFB role and templates do not yet exist.

- [ ] **Step 3: Resolve the explicit AD user and prepare only that home**

Run `getent passwd` with `ansible.builtin.command` and an `argv` list containing the validated `assigned_domain_user`; parse the passwd entry into UID, primary GID, and home directory. Assert that it resolves, that the home directory is absolute and starts with `/home/`, and that `remote_access_profile == 'krfb'` before creating anything.

When that specific domain home does not yet exist, create it with its resolved UID/GID, mode `0700`, then copy only the non-secret `/etc/skel/.config` defaults into it. This intentional pre-creation is required to configure KRFB before the user’s first graphical login; it does not create an AD account and remains compatible with the existing `pam_mkhomedir.so` first-login policy. Do not enumerate users and do not change any other home.

- [ ] **Step 4: Render the protected KRFB configuration**

Use this exact template and mark the task `no_log: true`:

```ini
[MainWindow]
startMinimized=true

[FrameBuffer]
preferredFrameBufferPlugin=pw

[Security]
allowDesktopControl=true
allowUnattendedAccess=true
desktopPassword={{ vault_krfb_desktop_password_obscured }}
noWallet=true
unattendedPassword={{ vault_krfb_unattended_password_obscured }}
```

Write it to `{{ krfb_config_home }}/.config/krfbrc` with the resolved user UID/GID and mode `0600`. The role must not read, print, copy, or commit the manually created configuration from the pilot PC.

- [ ] **Step 5: Render the assigned user’s Plasma autostart entry**

Create `{{ krfb_config_home }}/.config/autostart/org.sosn.krfb.desktop`, owned by the resolved UID/GID and mode `0644`:

```ini
[Desktop Entry]
Type=Application
Name=KDE Remote Desktop
Exec=/usr/bin/krfb
OnlyShowIn=KDE;
X-KDE-autostart-after=panel
X-KDE-StartupNotify=false
```

The role must only place this file. It must not call `systemctl --user`, `krfb`, `pkill`, `killall`, or `loginctl` to change a user session.

- [ ] **Step 6: Add non-secret role verification and final result fields**

Verify owner/mode for `krfbrc` and the autostart file, then read only `allowDesktopControl`, `allowUnattendedAccess`, and `noWallet` using `kreadconfig6` as the assigned user. Do not read either password key. Set `krfb_configured` and `krfb_autostart_configured` only after those checks pass.

Place `remote_access_krfb` after `standard_software` and before `domain_verify`, with `when: remote_access_profile == 'krfb'`. Extend `domain_verify` result JSON with:

```yaml
remote_access:
  profile: "{{ remote_access_profile }}"
  configured: "{{ remote_access_profile == 'none' or krfb_configured | default(false) }}"
```

No KRFB password field is included in the result.

- [ ] **Step 7: Run the role-asset regression tests**

Run: `pytest tests/test_alt_domain_ansible_assets.py tests/test_alt_manual_configure_request.py -q`

Expected: PASS; the playbook still ends in `domain_verify`, KRFB has no process-launch task, and the generated public result contains no secret field.

- [ ] **Step 8: Commit the KRFB role**

```bash
git add deploy/alt-linux/ansible/playbooks/03-configure-domain-workstation.yml deploy/alt-linux/ansible/roles/remote_access_krfb deploy/alt-linux/ansible/roles/domain_verify/tasks/main.yml tests/test_alt_domain_ansible_assets.py
git commit -m "feat(alt): configure per-user krfb remote access"
```

### Task 6: Update operational documentation and run controller-level tests

**Files:**
- Modify: `docs/ALT_MANUAL_ANSIBLE_MVP.md`
- Modify: `deploy/alt-linux/README.md`
- Modify: `tests/test_alt_domain_ansible_assets.py`
- Modify: `tests/test_alt_manual_configure_request.py`

**Interfaces:**
- Consumes: the request contract, catalog, role order, and verification keys from Tasks 1–5.
- Produces: a single operator procedure that uses `configure preview` followed by `configure start`, never a direct legacy `ansible-playbook` command.

- [ ] **Step 1: Write failing documentation assertions**

```python
def test_manual_mvp_docs_describe_fixed_playbook_and_krfb_network_gate() -> None:
    text = (REPO_ROOT / "docs" / "ALT_MANUAL_ANSIBLE_MVP.md").read_text(encoding="utf-8")
    assert "03-configure-domain-workstation.yml" in text
    assert "remote_access_profile" in text
    assert "5900" in text
    assert "firewall" in text.lower()
    assert "ansible-playbook -i" not in text
```

- [ ] **Step 2: Run the documentation assertion and confirm it fails until the procedure is updated**

Run: `pytest tests/test_alt_domain_ansible_assets.py -q`

Expected: FAIL on the new documentation assertions.

- [ ] **Step 3: Document the exact operator flow**

Document this sequence:

```text
manual ALT K 11.x installation
→ final hostname and local osn-admin
→ bootstrap registration
→ create non-secret configure request file with the fixed schema
→ workstationctl configure preview <uuid> --vars-file <request.json>
→ inspect fixed playbook, target IP, and actions
→ workstationctl configure start <uuid> --vars-file <request.json>
→ reboot only when result.reboot_required is true
→ first Plasma X11 domain login
→ KRFB acceptance check when requested
```

The documentation must state that `core-apps` is unavailable until all three catalog entries are enabled and their artifacts have been verified, and that `remote_access_profile: krfb` requires an existing AD user, Vault values, and an approved VPN/firewall path to 5900.

- [ ] **Step 4: Run all ALT structural/controller tests**

Run: `pytest tests/test_alt_manual_configure_request.py tests/test_alt_domain_ansible_assets.py tests/test_alt_software_catalog.py -q`

Expected: PASS.

- [ ] **Step 5: Run the repository test suite before deployment**

Run: `pytest -q`

Expected: PASS with the repository’s normal skips only. Do not deploy if any unrelated test regresses.

- [ ] **Step 6: Commit documentation and final test coverage**

```bash
git add docs/ALT_MANUAL_ANSIBLE_MVP.md deploy/alt-linux/README.md tests/test_alt_domain_ansible_assets.py tests/test_alt_manual_configure_request.py
git commit -m "docs(alt): document managed workstation profiles"
```

### Task 7: Controlled rollout and acceptance on a pilot workstation

**Files:**
- Modify: `docs/ALT_MANUAL_ANSIBLE_MVP.md`
- Create: `docs/verification/ALT_WORKSTATION_PROFILE_ACCEPTANCE.md`

**Interfaces:**
- Consumes: deployed controller release, one registered pilot workstation, a valid existing AD test user, and the non-secret configure request from Task 6.
- Produces: a dated acceptance record containing command exit statuses and non-secret observations.

- [ ] **Step 1: Write the acceptance checklist before deployment**

Create a checklist with these exact assertions:

```text
[ ] controller preview names only 03-configure-domain-workstation.yml
[ ] hostname is accepted without rename when it already matches the grammar
[ ] ALT release is 11.x; minor release is recorded but not rejected
[ ] net ads testjoin exits 0
[ ] systemctl is-active sssd returns active
[ ] getent passwd <test-user-upn> resolves
[ ] default Plasma session is X11 after graphical login
[ ] powerdevilrc, kscreenlockerrc, and kxkbrc have the approved values
[ ] base profile installs no unapproved component
[ ] browser configuration is absent from Ansible and is visible only after AD GPO processing
[ ] KRFB profile writes krfbrc mode 0600 for only the assigned user
[ ] KRFB autostart exists and KRFB starts only after that user’s Plasma login
[ ] port 5900 is reachable only through the pre-approved VPN/firewall path
[ ] no password or Vault value appears in configure result or Ansible log
```

- [ ] **Step 2: Deploy through the existing guarded controller installer**

Run the project’s established controller installer from the reviewed local source. Preserve its backup ID and validate the staged source before activation. Do not manually copy a playbook into `/home/altserver/ansible`, and do not modify the managed ISO or `ai curl` services.

- [ ] **Step 3: Execute base-profile pilot acceptance**

Use `workstationctl configure preview` then `workstationctl configure start` with `software_profile: "base"` and `remote_access_profile: "none"`. Record only the run ID, exit status, hostname, boolean verification values, package names, and test timestamps. Re-run the same request once; it must remain idempotent and report the valid existing Samba trust without rejoining.

- [ ] **Step 4: Execute KRFB pilot acceptance after firewall/VPN confirmation**

Use a request with `remote_access_profile: "krfb"` and an explicitly assigned existing AD test user. Confirm config ownership/mode and the three safe `kreadconfig6` values before login. After that user signs into Plasma X11, confirm `krfb` is running and port 5900 is listening. Perform one operator-controlled remote connection through the approved path; do not place remote-access credentials in the acceptance record.

- [ ] **Step 5: Execute core-apps acceptance only after catalog approval**

Before selecting `core-apps`, verify on the controller that all three catalog entries are enabled, their artifact SHA-256 values match the stored files, and their vendor versions are accepted. Run the profile on a disposable or explicitly approved pilot only; record installed package versions and application launch checks without copying installer binaries or secrets into Git.

- [ ] **Step 6: Commit the completed non-secret acceptance record**

```bash
git add docs/verification/ALT_WORKSTATION_PROFILE_ACCEPTANCE.md docs/ALT_MANUAL_ANSIBLE_MVP.md
git commit -m "docs(alt): record workstation profile acceptance"
```

## Plan self-review

- **Spec coverage:** The plan preserves the manual bootstrap → registration → controller-only AD join contract, keeps hostname verification/change modes and ALT 11.x compatibility, retains Plasma X11, excludes every named obsolete subsystem, and introduces each approved new item through a separate role. Task 1A creates the AD Central Store procedure, copies `admx-basealt` and `admx-yandex-browser`, scopes the browser GPO to Pilot, adds `--gpo` on first join, and enables `gpupdate` on both new and existing machines. KRFB is included as Task 5 with an explicit assigned user, Vault-only credentials, mode `0600`, Plasma autostart, no prelaunch, and a port-5900 network gate.
- **Safety coverage:** No task accepts a caller-selected playbook, arbitrary package name, URL, password, or route/DNS/firewall setting. Software remains disabled until artifact metadata is approved. Legacy files are inventoried but never deleted or silently invoked.
- **Sequence coverage:** The role order keeps `domain_verify` last, so its public result is produced only after profile roles complete. The rollout begins with `base`, then KRFB, and finally the externally supplied software artifacts.
- **Placeholder and interface check:** `software_profile`, `remote_access_profile`, `assigned_domain_user`, catalog component names, Vault gate method, public verification keys, and target files have one spelling throughout. The only runtime inputs not represented by a literal value are vendor installer artifacts and secret Vault values; both are deliberately external, governed inputs and are fail-closed by Tasks 2 and 4.
