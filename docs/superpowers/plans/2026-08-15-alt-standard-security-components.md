# ALT Standard Security Components Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add mandatory Endpoint, CryptoPro, CAdES, Госуслуги Plugin and CA
components to `standard-domain`, with post-login shortcuts.

**Architecture:** System roles use verified controller artifacts and write
structured component results.  A separate user-profile role creates shortcuts
only after the selected AD home exists.  Endpoint enrollment uses the canonical
RPM helper and creates/revokes a per-host campaign in one protected block.

**Tech Stack:** Ansible, ALT RPM/apt, Ansible Vault, systemd, Endpoint Gateway
HTTPS API, SSSD domain profiles.

## Global Constraints

- TLS uses only `https://endpoint.sosnadmin.local` with CA verification.
- Claims, service tokens, credentials and CryptoPro license never enter Git or logs.
- Госуслуги Plugin version is `1.3.19.0-1`; IFCPlugin is excluded.
- The public share shortcut is `smb://antares/Public` and is not an SMB mount.

### Task 1: Add catalog and role contracts

**Files:** `ansible/group_vars/all.yml`, role defaults, Ansible asset tests.

- [ ] Write failing static tests for the required component order, exact
  artifact catalog and non-secret role contracts.
- [ ] Add controller artifact paths, SHA-256 values and exact package metadata.
- [ ] Run the focused asset tests.

### Task 2: Implement system security roles

**Files:** roles for organization CA, CryptoPro, CAdES, Госуслуги Plugin and
Endpoint; `03-configure-domain-workstation.yml`.

- [ ] Write failing tests for required dispatch and Endpoint cleanup semantics.
- [ ] Implement checksum/metadata checks, idempotent installation and
  verification facts.
- [ ] Implement canonical Endpoint claim lifecycle with `no_log` secret paths.
- [ ] Add the roles after domain join and run syntax/asset tests.

### Task 3: Add post-login desktop launchers

**Files:** desktop skeleton and user-profile roles, launcher templates, tests.

- [ ] Write a failing test for CryptoPro/Home/Public launcher coverage.
- [ ] Add safe `.desktop` templates to `/etc/skel` and selected user home.
- [ ] Verify owner/mode and no SMB credential persistence.

### Task 4: Deploy and canary verify

**Files:** controller artifact store and deployment runbook.

- [ ] Copy only reviewed public artifacts to the controller artifact store.
- [ ] Run controller syntax/readiness tests and guarded control-plane deployment.
- [ ] Execute on `.81`, verify token-redacted enrollment, component facts and
  user shortcuts, then record the result.
