# ALT component and remote-profile specification

## Goal

Extend the controller-managed configuration of an already installed ALT
Workstation K 11.x with opt-in software and remote-access profiles, without
changing the installation path, network topology, DNS policy, or `netctl`.

## Fixed boundaries

- `03-configure-domain-workstation.yml` remains the only controller-managed
  workstation playbook; a caller cannot select an arbitrary playbook.
- The manual bootstrap and managed-ISO paths are unchanged. The workstation
  never receives Ansible Vault material or runs the playbook locally.
- The current `ad_dns_servers` value remains unchanged. A historical branch
  that uses `192.168.100.1` is not a source of network configuration.
- Plasma X11 remains the managed desktop default. Do not add GNOME, XRDP,
  X11VNC, static routes, firewall mutations, or browser policy files.
- `software_profile=base` and `remote_access_profile=none` retain the stage-03
  base path. `core-apps` and `krfb` are explicit opt-in profiles.
- An enabled software component requires a controller-side immutable artifact
  path, a lower-case 64-character SHA-256, exact package metadata, and a
  successful preflight before any target-side installation begins. Components
  without such a record fail closed.
- Request JSON, public results, logs and Git contain no secrets. KRFB secrets
  stay in the existing controller Vault; its two required values are checked
  only by presence, never returned.
- KRFB targets exactly the request's already existing AD user. It creates no
  AD account, does not discover a user from a home directory/session, starts
  no process, and opens no port. The operator must separately confirm the
  existing VPN/firewall restriction for port 5900.

## Completion evidence

1. A non-secret, disabled-by-default component catalog has schema tests and
   documents every external artifact field required before enablement.
2. `core-apps` cannot start a partially specified component set; its aggregate
   controller/Ansible preflight fails before target package mutation.
3. Each enabled component is installed only through a fixed role after checksum
   and package metadata checks, with a non-secret verification fact.
4. `krfb` passes a controller Vault-presence gate, verifies the exact AD user,
   writes only that user's protected configuration and Plasma autostart file,
   and records no password in the result.
5. The runbook covers preview, fixed playbook, canary acceptance, and stopped
   failure handling. ALT runtime syntax and canary are executed only after a
   separately approved deployment.
