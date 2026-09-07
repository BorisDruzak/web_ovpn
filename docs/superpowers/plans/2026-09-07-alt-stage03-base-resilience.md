# ALT Linux stage 03 — base workstation resilience plan

**Goal:** Upgrade the Ansible path for an already installed ALT Workstation K
11.x from a linear role list to a resilient, structured stage 03 flow. This
stage covers only base workstation configuration: preflight, hostname,
upgrade, base packages, DNS, Active Directory, Group Policy, the domain-login
baseline and verification. It does not install browser/core-apps/security
artifacts, configure KRFB, change the bootstrap trust model, or touch netctl.

## Binding decisions

- Preserve the configured `ad_dns_servers` value. The historical integration
  branch contains a different address, but this plan does not change network
  topology or DNS policy.
- Keep the current manual `workstationctl configure` request and the phase-0
  profile contract. No automatic registration or first-login worker is added.
- Stage 03 must emit the controller's structured result schema: all required
  fields, boolean flags, a `null` error for successful/degraded outcomes, and
  `{code, class, safe_message}` only for failed outcomes. The error `class`
  uses the stable hyphenated form `fatal-invariant`.
- Persist the result before returning a terminal Ansible failure.
- A package upgrade may request exactly one controlled reboot only after the
  system/domain phase has completed; it must not reboot inside
  `prejoin_upgrade`.
- Existing AD computer objects stay protected: retries must prove an absent
  object before another join write. Credentials and Kerberos output remain
  `no_log`.

## Task 1: Establish stage-03 structured result and critical phase contract

**Files:** `03-configure-domain-workstation.yml`, task includes under
`playbooks/tasks/`, `tests/test_alt_domain_ansible_assets.py`, and focused
Ansible asset tests.

1. Write failing static tests for the initial critical order: preflight,
   identity, upgrade, base prerequisites, DNS, domain join, GPO, and
   verification. Task 3 adds the domain-login baseline together with its
   actual `pam_mkhomedir` logic and verifies the final order.
2. Test that the playbook writes the phase-0 structured JSON schema, uses a
   `null` success error, persists a failed result before `ansible.builtin.fail`,
   and performs no component/application role.
3. Implement `configure_critical_phase.yml` and a minimal finalizer that
   matches the controller's strict schema. Do not copy the historical
   component loop because its software roles are intentionally out of scope.
4. Run the focused asset tests, YAML parse tests, and `git diff --check`.

## Task 2: Make the base OS, DNS and Group Policy phases recoverable

**Files:** `group_vars/all.yml`, `manual_preflight`, `prejoin_upgrade`,
`workstation_base`, `workstation_network`, Group Policy roles, and Ansible
asset tests.

1. Add failing contract tests for bounded retry variables, no nested reboot in
   `prejoin_upgrade`, retryable time/DNS checks, validated resolver write with
   rollback, and explicit Group Policy setup/update verification.
2. Add bounded retry policy variables without changing `ad_dns_servers`.
3. Move the reboot decision into the stage-03 final path. The upgrade role
   sets only `prejoin_upgrade_reboot_required`.
4. Preserve resolver ownership checks and restore a pre-existing resolver
   backup if the new DNS fails validation; remove only a newly created file.
5. Run focused asset tests and syntax parsing.

## Task 3: Make domain join and verification safe under transient failure

**Files:** `domain_join`, `domain_verify`, `domain_login_baseline`, stage-03
finalizer/playbook ordering, and related tests.

1. Write failing tests for retrying only recognized KDC/LDAP failures,
   reconciling Samba trust after an ambiguous join result, and never joining
   over a pre-existing computer object.
2. Implement no-log ticket acquisition and LDAP lookup retries. If a join
   command fails ambiguously, verify existing trust; retry once only when the
   computer account is proved absent.
3. Move `pam_mkhomedir` configuration to `domain_login_baseline` and let
   `domain_verify` report facts instead of writing an incompatible legacy
   result.
4. Add `domain_login_baseline` immediately before `domain_verify` and make
   the finalizer report a single `reboot_required` flag from the upgrade/join
   facts. It must not reboot inside any role.
5. Test static contracts and exact role ordering.

## Task 4: Validate on ALT before deployment

1. On an ALT controller, run `ansible-playbook --syntax-check` for stage 03
   and the targeted ALT asset suite.
2. Canary one already installed workstation with `software_profile=base` and
   `remote_access_profile=none`; verify the structured result, DNS/KDC,
   `net ads testjoin`, SSSD, `gpupdate`, and a single reboot only if needed.
3. Do not deploy or change the controller unless separately requested.
