# ALT Bootstrap Resilience Design

## Goal

Make the manual ALT Workstation K 11.x bootstrap safe to rerun and resilient to transient DHCP, controller and registration failures, while preserving the existing network profile and the manual-install contract.

## Scope

The implementation changes bootstrap.sh, alt-bootstrap-register, a controller-served start-bootstrap.sh launcher, the controller pending-registration worker, Linux-runnable tests and operator documentation. It does not change managed ISO or AI Curl paths, create AD users, configure arbitrary DNS or routes, or disable SSH password access.

## Design

Bootstrap is a state machine with root-only state under /var/lib/alt-bootstrap/:

1. Validate root, ALT Workstation K major version 11, final hostname, and a unique process lock.
2. Inspect the current DHCP-backed route and IPv4 address.
3. When either is missing, re-activate only the currently known NetworkManager connection or existing etcnet interface, then re-check it; it never writes DNS, route or addressing policy.
4. Wait with bounded backoff for controller TCP reachability by the configured IP address.
5. Install and validate Python, OpenSSH, sudo and curl; create or reuse the technical ansible account; install the pinned controller key; install a sudoers drop-in atomically after visudo validation; enable SSH.
6. Register with bounded retries. If registration cannot reach the controller after technical preparation has succeeded, persist only non-secret registration state and enable a root-owned retry service and timer triggered after network-online.
7. Record ready, pending_registration, or a typed failure code in a root-only status file.

The bootstrap marker is written only after the technical access checks pass. A rerun reconciles every owned artifact and retries registration; it does not merely return because a marker exists.

The controller-served start-bootstrap.sh launcher is a short shell file. It checks root, downloads the canonical bootstrap into a private temporary path, syntax-checks it, then invokes it. The user-facing command downloads the launcher from the controller:

    curl --noproxy '*' -fsS http://192.168.100.17:8087/bootstrap/start-bootstrap.sh -o /tmp/start-alt-bootstrap.sh && sudo bash /tmp/start-alt-bootstrap.sh

## Controller Handoff

Before the local command, an operator creates a strict configure request at /srv/alt-deploy/configure-requests/<machine-uuid>.json. It contains final_hostname, hostname_mode, profile, domain, realm, workgroup, computer_ou and domain_test_user. It contains no password or Vault secret.

After registration and technical preflight succeed, the controller pending-registration worker loads only the request whose filename equals the registered UUID. It validates it using ConfigureRequest, runs ConfigurePlanner.preview and then ConfigurePlanner.start. The controller has the Vault and runs Ansible as altserver; the workstation never receives controller credentials.

If the request is absent, the worker leaves the station in awaiting_assignment and never starts domain join. If the matching request is invalid or preview fails, it writes a typed terminal status and never starts domain join. If configuration starts and a later role fails, the recorded result contains the run ID and failure; a retry uses the same request and idempotent configure playbook.

## Failure Policy

- Unsupported OS, bad hostname, no default interface, unrecoverable DHCP, key fingerprint mismatch and invalid sudoers are hard failures with a typed status.
- A missing controller is not a hard failure after SSH and sudo are validated: it results in pending_registration and bounded deferred retries.
- Network recovery only reactivates an existing DHCP connection; no new profile is created and no configured resolver is overwritten.
- All registration payloads remain UUID, MAC and hostname only. Passwords, private keys, Vault data and AD credentials are never logged or persisted.

## Verification

Tests run on Linux verify shell syntax, the presence of the lock/status/deferred retry contract, atomic sudoers validation before installation, and the launcher private download-and-exec contract. Integration verification on a clean ALT host checks idempotent rerun, temporary controller outage and registration recovery.
