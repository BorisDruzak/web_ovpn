# ALT install-session control plane (PR3)

PR3 adds a server-only, repository-complete control plane for ALT 11.4 installation planning. It does not deploy a service, modify the PR1 initrd agent, render secrets, start Alterator, alter an ISO, or mutate a target disk.

## Operator workflow

The agent-facing HTTP API creates a private install session after strict `InstallInventoryV1` and `standard-office` policy validation. It returns a one-time Bearer credential; only its SHA-256 is stored.

An operator may inspect a bounded preview:

```text
sudo -u altserver workstationctl --json install-sessions preview <session-id>
```

Root approval must bind the displayed inventory hash and disk fingerprint:

```text
sudo workstationctl --json install-sessions approve <session-id> \
  --inventory-sha256 <sha256> \
  --disk-fingerprint sha256:<sha256> \
  --reason "Approved disposable ALT installation target"
```

Approval re-evaluates the inventory and policy, builds `InstallPlanV1` revision 1, signs canonical `plan.json` with Ed25519, and atomically publishes the plan, checksum, and signature. A cancellation is terminal; already published revision files are retained as immutable audit artefacts, while plan downloads return `409 session_cancelled`.

## Files and keys

Sessions use `${ALT_DEPLOY_INSTALL_SESSIONS:-/var/lib/alt-deploy/install-sessions}`. Each session directory and revision directory is private (`0700`); inventory, authorization, status, approval, plan, checksum and signature files are private (`0600`). The session store belongs to `altserver:altserver`. Root-only approval explicitly transfers its newly created revision and approval files to that account before publication, so the API can serve a published plan without root access.

The production private key is deliberately not created by PR3. Before a later deployment, it must be a regular root-owned Ed25519 PKCS#8 PEM with mode `0600`; the accompanying JSON public key must be regular, root-owned and mode `0644`. Approval reads both through no-follow descriptors and refuses mismatched key identities.

## HTTP boundary

The API factory is test-only in PR3; no systemd unit or listener is installed. Session creation is limited to loopback and `192.168.100.0/23`; every per-session endpoint requires `Authorization: Bearer <credential>`. The server rejects chunked bodies, query strings, oversized targets/bodies and unknown routes, and sends `Cache-Control: no-store`.
