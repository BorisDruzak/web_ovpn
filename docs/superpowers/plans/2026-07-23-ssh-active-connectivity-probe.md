# SSH Active Connectivity Probe Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Verify Internet-policy enforcement from the selected asset over SSH, proving external blocking and preserved internal access.

**Architecture:** A bounded SSH probe accepts only a per-asset allowlist and executes a fixed Python TCP probe. `ControlService` passes it to verify and rollback. A systemd credential provides the key; no password or arbitrary command is accepted.

**Tech Stack:** Python standard library, OpenSSH client, systemd credentials, pytest.

## Global Constraints

- Probe configuration and private keys remain outside Git.
- Deny requires `internet=blocked` and `internal=reachable`; allow and rollback require both reachable.
- Web requests cannot select a host, command, credential, or TCP endpoint.
- This implementation does not change RouterOS configuration.

---

### Task 1: Bounded SSH probe

**Files:**
- Create: `netopsctl/connectivity_probe.py`
- Test: `tests/test_netopsctl_connectivity_probe.py`

**Interfaces:** `SSHConnectivityProbe.from_json(raw, identity_file)` and `verify(asset_key, expected_internet)` return `asset_key`, `internet`, and `internal` states.

- [ ] **Step 1: Write failing tests**

```python
probe = SSHConnectivityProbe.from_json(valid_json, "/run/credentials/netopsctl-active-probe-ssh-key")
monkeypatch.setattr(subprocess, "run", fake_ssh("internet=blocked\ninternal=reachable\n"))
assert probe.verify("mac:AA", expected_internet=False)["internet"] == "blocked"
with pytest.raises(ValueError, match="not configured"):
    probe.verify("mac:BB", expected_internet=False)
with pytest.raises(ValueError, match="invalid active connectivity probe configuration"):
    SSHConnectivityProbe.from_json('{"mac:AA":{"password":"x"}}', "/credential")
```

- [ ] **Step 2: Run RED**

Run: `pytest tests/test_netopsctl_connectivity_probe.py -q`

Expected: FAIL because the module is absent.

- [ ] **Step 3: Implement the minimal probe**

```python
def verify(self, asset_key: str, expected_internet: bool) -> dict[str, object]:
    config = self._assets.get(asset_key)
    if config is None:
        raise ValueError("active connectivity probe is not configured for this asset")
    completed = subprocess.run(self._ssh_command(config), input=FIXED_TCP_PROBE, text=True, capture_output=True, timeout=15, check=False)
    result = parse_probe_output(completed)
    if result["internet"] != ("reachable" if expected_internet else "blocked") or result["internal"] != "reachable":
        raise ValueError("active connectivity verification failed")
    return {"asset_key": asset_key, **result}
```

Use only `ssh -i <credential> -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=8 <configured-user>@<configured-host> python3 -`; validate every JSON field before command construction.

- [ ] **Step 4: Run GREEN and commit**

Run: `pytest tests/test_netopsctl_connectivity_probe.py -q`

Expected: PASS.

Commit: `git add netopsctl/connectivity_probe.py tests/test_netopsctl_connectivity_probe.py && git commit -m "feat: add bounded SSH connectivity probe"`

### Task 2: Active evidence for verify and rollback

**Files:**
- Modify: `netopsctl/reconcile.py`
- Modify: `netopsctl/service.py`
- Test: `tests/test_netopsctl_internet_policy.py`

**Interfaces:** `verify_plan(..., connectivity_probe=None)` and `rollback_plan(..., connectivity_probe=None)` fail closed when an Internet-policy plan has no probe.

- [ ] **Step 1: Write failing tests**

```python
assert verify_plan(conn, "deny-plan", adapter, connectivity_probe=Probe({"internet": "blocked", "internal": "reachable"}))["status"] == "verified"
with pytest.raises(ValueError, match="active connectivity probe"):
    verify_plan(conn, "allow-plan", adapter)
assert rollback_plan(conn, "deny-plan", adapter, connectivity_probe=Probe({"internet": "reachable", "internal": "reachable"}))["status"] == "rolled_back"
```

- [ ] **Step 2: Run RED**

Run: `pytest tests/test_netopsctl_internet_policy.py -q -k 'active_probe or rollback_requires'`

Expected: FAIL because reconciliation has no probe argument.

- [ ] **Step 3: Implement fail-closed invocation**

```python
desired = json.loads(str(plan["desired_state_json"]))
asset_key = str(desired.get("resolved_enforcement_asset_key") or plan["subject_key"])
if connectivity_probe is None:
    raise ValueError("active connectivity probe is required for Internet-policy verification")
probe_result = connectivity_probe.verify(asset_key, expected_internet=desired["internet_access"] == "allow")
```

Store `active_connectivity` beside `anchor_after`; after rollback run the same probe with `expected_internet=True` and reject failed connectivity.

- [ ] **Step 4: Run GREEN and commit**

Run: `pytest tests/test_netopsctl_internet_policy.py -q -k 'active_probe or rollback_requires'`

Expected: PASS.

Commit: `git add netopsctl/reconcile.py netopsctl/service.py tests/test_netopsctl_internet_policy.py && git commit -m "fix: require active policy connectivity checks"`

### Task 3: Protected runtime configuration

**Files:**
- Modify: `netopsctl/server.py`
- Modify: `deploy/netopsctl.service`
- Modify: `deploy/netopsctl`
- Test: `tests/test_netopsctl_server_security.py`
- Test: `tests/test_deploy_netopsctl.py`

**Interfaces:** configuration is `NETOPSCTL_ACTIVE_PROBES_JSON`; key credential is `netopsctl-active-probe-ssh-key` sourced at `/etc/netopsctl/credentials/active_probe_ssh_ed25519`.

- [ ] **Step 1: Write failing tests**

```python
monkeypatch.setenv("NETOPSCTL_ACTIVE_PROBES_JSON", '{"mac:AA":{"password":"x"}}')
with pytest.raises(RuntimeError, match="invalid netopsctl runtime configuration"):
    _build_service(conn)
assert "LoadCredential=netopsctl-active-probe-ssh-key:/etc/netopsctl/credentials/active_probe_ssh_ed25519" in Path("deploy/netopsctl.service").read_text()
```

- [ ] **Step 2: Run RED**

Run: `pytest tests/test_netopsctl_server_security.py tests/test_deploy_netopsctl.py -q -k probe`

Expected: FAIL because runtime and unit support are absent.

- [ ] **Step 3: Implement protected loading**

```python
raw = os.environ.get("NETOPSCTL_ACTIVE_PROBES_JSON", "{}")
probe = SSHConnectivityProbe.from_json(raw, str(Path(os.environ["CREDENTIALS_DIRECTORY"]) / "netopsctl-active-probe-ssh-key")) if raw != "{}" else None
```

Require the credential in the installer. Reject malformed JSON, passwords, unsupported fields, missing credential directory, and relative identity paths.

- [ ] **Step 4: Run GREEN and commit**

Run: `pytest tests/test_netopsctl_server_security.py tests/test_deploy_netopsctl.py -q -k probe`

Expected: PASS.

Commit: `git add netopsctl/server.py deploy/netopsctl.service deploy/netopsctl tests/test_netopsctl_server_security.py tests/test_deploy_netopsctl.py && git commit -m "feat: load protected active probe credentials"`

### Task 4: Sanitized rollout and final verification

**Files:**
- Modify: `docs/runbooks/netopsctl-internet-policy-rollout.md`
- Modify: `docs/verification/netopsctl-internet-policy-readiness.md`

- [ ] **Step 1: Document one-time public-key installation**

Document the selected asset key, protected credential source, and JSON allowlist. A temporary password may install a public key but must never appear in command history, Git, an environment file, a unit, or a verification record.

- [ ] **Step 2: Document controlled lifecycle**

Document baseline, deny/apply/verify, rollback, and post-rollback expected states. Record only the asset key, result states, and audit checkpoint status.

- [ ] **Step 3: Verify hygiene and local suite**

Run the credential-literal hygiene scan, then `pytest -q`,
`python -m compileall -q app netctl netopsctl`, and `git diff --check`.

Expected: no credential literal; tests and compilation pass; diff is clean.

- [ ] **Step 4: Commit**

Commit: `git add docs/runbooks/netopsctl-internet-policy-rollout.md docs/verification/netopsctl-internet-policy-readiness.md && git commit -m "docs: define active Internet policy verification"`
