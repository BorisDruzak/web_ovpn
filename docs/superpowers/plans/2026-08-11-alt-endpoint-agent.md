# ALT Endpoint Agent Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Install and enroll the approved Endpoint Agent RPM through the existing manual ALT configure workflow without storing a one-time claim.

**Architecture:** The configure controller validates that the dedicated provisioning token is present in Ansible Vault. The Ansible role verifies the controller-side RPM, derives the exact pre-install hardware fingerprint from the RPM payload, requests one claim from Gateway immediately before installation, and writes it only to the target's root-only bootstrap directory. The RPM performs enrollment and its own root finalizer removes the one-time claim after durable credential proof.

**Tech Stack:** Python 3 control service, Ansible, ALT RPM/rpm2cpio/cpio, systemd, HTTPS Gateway with the organization CA.

## Global Constraints

- Artifact: `endpoint-agent-0.1.0-6.x86_64.rpm`, SHA-256 `c7e3a1476ae831611cfb593f34ac4b7c43ff6c6602a6d7717c2032049cb752ac`.
- Gateway origin is only `https://endpoint.sosnadmin.local`; TLS validation uses `sosnadmin-local-ca.crt`.
- `vault_endpoint_provisioning_token` must have only `provisioning.install-claims.issue`; no administrator credential is used.
- `endpoint_enrollment_campaign_id` is non-secret and must be a valid UUID before a configure run can issue a claim.
- Claims use `no_log: true`, are never written to Git, Ansible result JSON, Vault, request JSON, or durable controller logs.
- Do not issue another claim when `endpoint-agent` is installed but enrollment is incomplete; return `endpoint_agent_recovery_required`.
- Package updates remain Gateway-controlled; Ansible performs first installation only.

---

### Task 1: Add controller safety gates and configure action

**Files:**
- Modify: `deploy/alt-linux/control/alt_deploy/vault.py`
- Modify: `deploy/alt-linux/control/alt_deploy/configure.py`
- Modify: `tests/test_alt_manual_configure_request.py`

**Interfaces:**
- Consumes: encrypted `vault_endpoint_provisioning_token`.
- Produces: `VaultHealthChecker.check_endpoint_provisioning() -> dict[str, object]` and configure action `install_endpoint_agent`.

- [ ] **Step 1: Write failing tests**

```python
assert checker.check_endpoint_provisioning() == {
    "status": "ok",
    "checks": {"endpoint_provisioning_token_present": True},
}
assert "install_endpoint_agent" in preview["actions"]
```

- [ ] **Step 2: Run the focused tests and verify they fail**

Run: `python -m pytest tests/test_alt_manual_configure_request.py -q`

- [ ] **Step 3: Implement the minimal gate and action**

```python
ENDPOINT_PROVISIONING_TOKEN_VARIABLE = "vault_endpoint_provisioning_token"
vault_checker.check_endpoint_provisioning()
```

- [ ] **Step 4: Run focused tests and verify they pass**

Run: `python -m pytest tests/test_alt_manual_configure_request.py -q`

### Task 2: Add the first-install Ansible role

**Files:**
- Modify: `deploy/alt-linux/ansible/group_vars/all.yml`
- Create: `deploy/alt-linux/ansible/roles/software_endpoint_agent/defaults/main.yml`
- Create: `deploy/alt-linux/ansible/roles/software_endpoint_agent/tasks/main.yml`
- Modify: `deploy/alt-linux/ansible/playbooks/03-configure-domain-workstation.yml`
- Modify: `tests/test_alt_domain_ansible_assets.py`

**Interfaces:**
- Consumes: catalog entry, `endpoint_enrollment_campaign_id`, Vault token, and the organization CA file.
- Produces: `software_endpoint_agent_verified: bool` only after package, durable credential, and three units are valid.

- [ ] **Step 1: Write failing asset tests**

```python
assert variables["software_catalog"]["endpoint_agent"]["package_evr"] == "0.1.0-6"
assert "software_endpoint_agent" in playbook[0]["roles"]
assert "no_log: true" in role_text
```

- [ ] **Step 2: Run the asset tests and verify they fail**

Run: `python -m pytest tests/test_alt_domain_ansible_assets.py -q`

- [ ] **Step 3: Implement minimal secure role**

```yaml
- name: Issue one-time Endpoint enrollment claim
  ansible.builtin.uri:
    url: https://endpoint.sosnadmin.local/api/v1/provisioning/install-claims
  no_log: true
  delegate_to: localhost
```

The role must validate artifact checksum/NEVRA before copying it, use its own payload only to obtain the exact fingerprint, enforce root-only bootstrap permissions, run `rpm -Uvh` once, wait for credential finalization, and remove all non-secret staging files.

- [ ] **Step 4: Run asset tests and verify they pass**

Run: `python -m pytest tests/test_alt_domain_ansible_assets.py -q`

### Task 3: Publish safe verification and document operation

**Files:**
- Modify: `deploy/alt-linux/ansible/roles/domain_verify/tasks/main.yml`
- Modify: `docs/ALT_MANUAL_ANSIBLE_MVP.md`
- Modify: `tests/test_alt_domain_ansible_assets.py`

**Interfaces:**
- Produces: non-secret endpoint verification booleans and documented prerequisite for campaign creation.

- [ ] **Step 1: Write a failing test**

```python
assert "endpoint_agent_ok" in domain_verify_text
assert "vault_endpoint_provisioning_token" not in domain_verify_text
```

- [ ] **Step 2: Run the focused test and verify it fails**

Run: `python -m pytest tests/test_alt_domain_ansible_assets.py -q`

- [ ] **Step 3: Add verification result and operational documentation**

```yaml
endpoint_agent_ok: "{{ software_endpoint_agent_verified | default(false) }}"
```

- [ ] **Step 4: Run focused tests and the full suite**

Run: `python -m pytest tests/test_alt_domain_ansible_assets.py tests/test_alt_manual_configure_request.py -q`

Run: `python -m pytest -q`

## Verification checklist

- The controller resolves `endpoint.sosnadmin.local` and verifies its TLS certificate with the organization CA.
- No configure run starts if the Vault token is absent.
- No role task prints or persists the claim or service token.
- Fresh install yields `endpoint-agent.service`, `endpoint-agent-update.path`, `endpoint-agent-finalize.path`, and a durable device credential.
- A repeated configure run neither receives a new claim nor changes the agent package.
- An incomplete existing enrollment fails with `endpoint_agent_recovery_required`.
