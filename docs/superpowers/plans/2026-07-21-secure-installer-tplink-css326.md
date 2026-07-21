# Secure installer, TP-Link and CSS326 implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prevent installer credential disclosure, add an exact TP-Link JetStream identity, rotate the web administrator credential, and stage the CSS326 as a disabled discovery-only SNMP source.

**Architecture:** The installer uses only the protected environment file and never uses /tmp as a credential channel. Profile selection remains in netctl.snmp.profiles and accepts the TP-Link only when both system scalars match. Production validation uses the existing system-only discovery command while all SNMP sources and the collection timer stay disabled.

**Tech Stack:** Bash, systemd, FastAPI, Python 3.12, pytest, PySNMP 7.1.27, existing netctl CLI.

## Global Constraints

- Never commit, print, test with, or log the supplied administrator password, SNMP community, API token, endpoint, or raw SNMP response.
- Do not restart OpenVPN or WireGuard; only openvpn-web.service may restart for credential rotation.
- Keep netctl-collect.timer disabled and inactive, and every SNMP source enabled: false.
- Discovery may read only sysDescr, sysObjectID, sysUpTime, sysName and sysLocation. Never run collect.
- CSS326 discovery is expected to return known/css326; it is not an unknown-profile test.

---

### Task 1: Remove installer credential disclosure

**Files:**
- Modify: deploy/install-openvpn-web.sh:122-247
- Create: tests/test_deploy_credential_safety.py

**Interfaces:**
- Consumes: /etc/openvpn-web/openvpn-web.env as the only persistent credential store.
- Produces: an installer that preserves protected environment values without temporary credential files or secret stdout.

- [ ] **Step 1: Write the failing installer-safety test**

    from pathlib import Path

    ROOT = Path(__file__).resolve().parents[1]

    def test_installer_never_uses_or_prints_temporary_credentials() -> None:
        text = (ROOT / "deploy" / "install-openvpn-web.sh").read_text(encoding="utf-8")
        assert "/tmp/openvpn-web-admin-password.txt" not in text
        assert "/tmp/openvpn-web-api-token.txt" not in text
        assert "cat /tmp/openvpn-web-admin-password.txt" not in text
        assert "ADMIN_PASSWORD=%s" not in text
        assert "OPENVPN_WEB_API_TOKEN=%s" not in text

- [ ] **Step 2: Run the test to verify RED**

Run: python -m pytest -q tests/test_deploy_credential_safety.py

Expected: FAIL because the current installer creates and prints both temporary credential files.

- [ ] **Step 3: Make the smallest safe installer change**

Remove all reads, writes and final output for the two /tmp credential files. On a new protected environment, generate an administrator password only when no deployment-provided ADMIN_PASSWORD is present, write it directly into the 0640 root:openvpn-web environment file, and print only a generic completion message. On an existing environment, preserve ADMIN_PASSWORD without reading it into a temporary file. Preserve the token hash logic without writing a raw token anywhere.

- [ ] **Step 4: Run focused tests to verify GREEN**

Run: python -m pytest -q tests/test_deploy_credential_safety.py tests/test_netctl_deploy_security.py tests/test_deploy_vpn_runtime_health_timer.py

Expected: PASS.

- [ ] **Step 5: Commit Task 1**

    git add deploy/install-openvpn-web.sh tests/test_deploy_credential_safety.py
    git commit -m "fix: prevent installer credential disclosure"

### Task 2: Accept the exact TP-Link JetStream identity

**Files:**
- Modify: netctl/snmp/profiles.py:19,376-385
- Modify: tests/test_netctl_snmp_profiles.py:1100-1145

**Interfaces:**
- Consumes: SwitchSystem(sys_descr, sys_object_id, sys_name, sys_location, sys_uptime_ticks).
- Produces: TplinkProfile.matches(system) -> bool that retains the existing T1600G pattern and adds one exact JetStream identity.

- [ ] **Step 1: Write failing positive and negative identity tests**

    def test_tplink_hint_accepts_only_the_observed_jetstream_identity() -> None:
        from netctl.snmp.models import SwitchSystem
        from netctl.snmp.profiles import detect_profile

        exact = SwitchSystem(
            "JetStream 48-Port Gigabit Smart Switch with 4 SFP Slots",
            "1.3.6.1.4.1.11863.5.29", "", "", None,
        )
        wrong_oid = SwitchSystem(exact.sys_descr, "1.3.6.1.4.1.11863.5.30", "", "", None)

        assert detect_profile(exact, profile_hint="tplink").profile_id == "tplink"
        with pytest.raises(ValueError, match="profile_hint"):
            detect_profile(wrong_oid, profile_hint="tplink")

Add the complementary wrong-description assertion with the exact object ID.

- [ ] **Step 2: Run the test to verify RED**

Run: python -m pytest -q tests/test_netctl_snmp_profiles.py -k jetstream

Expected: FAIL because the current matcher accepts only T1600G descriptions.

- [ ] **Step 3: Add the bounded identity branch**

    _TPLINK_JETSTREAM_SYSTEM_OBJECT_ID = "1.3.6.1.4.1.11863.5.29"
    _TPLINK_JETSTREAM_SYSTEM_DESCRIPTION = "JetStream 48-Port Gigabit Smart Switch with 4 SFP Slots"

    return (
        _TPLINK_T1600G_SYSTEM_DESCRIPTION.search(system.sys_descr) is not None
        or (
            system.sys_object_id == _TPLINK_JETSTREAM_SYSTEM_OBJECT_ID
            and system.sys_descr == _TPLINK_JETSTREAM_SYSTEM_DESCRIPTION
        )
    )

- [ ] **Step 4: Run profile and discovery regressions**

Run: python -m pytest -q tests/test_netctl_snmp_profiles.py tests/test_netctl_switch_cli.py tests/test_netctl_switch_discovery_store.py

Expected: PASS.

- [ ] **Step 5: Commit Task 2**

    git add netctl/snmp/profiles.py tests/test_netctl_snmp_profiles.py
    git commit -m "feat: match exact TP-Link JetStream identity"

### Task 3: Document protected credential rotation and disabled-source gate

**Files:**
- Create: docs/runbooks/secure-installer-switch-discovery-rollout.md
- Modify: tests/test_deploy_credential_safety.py

**Interfaces:**
- Consumes: protected environment files, netctl sources inspect, and a named disabled source.
- Produces: a command sequence that does not echo credentials and validates enabled is False before and after discovery.

- [ ] **Step 1: Write the failing runbook-presence assertion**

    def test_credential_rotation_runbook_uses_protected_files_only() -> None:
        text = (ROOT / "docs/runbooks/secure-installer-switch-discovery-rollout.md").read_text(encoding="utf-8")
        assert "/etc/openvpn-web/openvpn-web.env" in text
        assert "/etc/netctl/secrets.env" in text
        assert "sources discover" in text
        assert "netctl-collect.timer" in text
        assert "collect " not in text
        assert "ADMIN_PASSWORD=" not in text

- [ ] **Step 2: Run the assertion to verify RED**

Run: python -m pytest -q tests/test_deploy_credential_safety.py -k runbook

Expected: FAIL because the runbook does not exist.

- [ ] **Step 3: Write the safe runbook**

Document a validated backup on /var/lib/netctl/backups; an atomic protected-env update supplied through an operator secret channel; removal of legacy temporary files after the update; restart of only openvpn-web.service; and an assert_disabled_snmp_source helper that validates name, snmp_switch driver and JSON boolean enabled is False before and after discovery. Use only placeholder source names and secret references.

- [ ] **Step 4: Run documentation and installer-safety tests**

Run: python -m pytest -q tests/test_deploy_credential_safety.py

Expected: PASS.

- [ ] **Step 5: Commit Task 3**

    git add docs/runbooks/secure-installer-switch-discovery-rollout.md tests/test_deploy_credential_safety.py
    git commit -m "docs: add secure installer discovery rollout"

### Task 4: Release and validate one TP-Link and one CSS326 source

**Files:**
- Deploy: reviewed release archive from the final commit.
- Modify on production only: protected web and netctl environment files plus the CSS326 source YAML.

**Interfaces:**
- Consumes: the operator-provided administrator password and CSS326 community through protected server-side input, never command output.
- Produces: a rotated web administrator credential; disabled TP-Link and CSS326 sources; known/tplink and known/css326 discovery responses.

- [ ] **Step 1: Verify the reviewed local release**

Run: python -m pytest -q --ignore=tests/alt_linux

Expected: PASS. If Windows cannot import Linux-only ALT tests, record that platform limitation separately and run the targeted suite on the Linux host.

- [ ] **Step 2: Create and validate the production rollback set**

Create the SQLite copy under /var/lib/netctl/backups, application/configuration archives under /var/backups/netctl, validate PRAGMA integrity_check, and verify all backup hashes. Capture timer state without printing protected environment contents.

- [ ] **Step 3: Deploy and rotate only the web credential**

Deploy the exact reviewed archive. Update the administrator password atomically in the protected environment through standard input or an operator secret channel, remove old temporary credential files, and restart only openvpn-web.service. Verify /login returns HTTP 200 and OpenVPN remains active.

- [ ] **Step 4: Keep collection disabled and validate TP-Link discovery**

    sudo -u netctl /usr/local/sbin/netctl --json sources discover tplink-ito-15

Expected: known/tplink. Run the disabled-source assertion before and after. Do not run sources test or collect.

- [ ] **Step 5: Stage CSS326 without exposing its community**

Use privileged protected-file input to add only the CSS326 secret value to /etc/netctl/secrets.env with root:netctl 0640. Create the source through netctl --json sources add-snmp-switch with the reviewed source name, management address, dedicated secret reference and --profile-hint css326. Verify it is disabled and do not print inspect output.

- [ ] **Step 6: Validate CSS326 discovery and final service state**

    sudo -u netctl /usr/local/sbin/netctl --json sources discover css326-24g-26

Expected: known/css326; no unknown fingerprint is created. Verify timer disabled/inactive, both SNMP sources disabled, OpenVPN and web service active, and the Linux targeted suite passes.

- [ ] **Step 7: Commit production evidence only if sanitized**

    git add docs/runbooks/secure-installer-switch-discovery-rollout.md
    git commit -m "docs: record secure switch discovery validation"

Never commit source YAML, protected environment files, backup manifests, communities, passwords, endpoints, raw output, or database artifacts.

