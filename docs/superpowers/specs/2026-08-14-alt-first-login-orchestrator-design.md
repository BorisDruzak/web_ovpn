# ALT first-login orchestrator design

## Goal

After one invocation of `start-bootstrap.sh`, prepare and register an ALT
workstation, validate the selected Active Directory user, configure and join
the computer, perform exactly one controlled reboot, and complete
user-scoped configuration automatically after that user's first domain login.

## Operator contract

1. The operator runs `start-bootstrap.sh` as root on the new workstation.
2. The script prompts once for the employee's AD login or UPN. It accepts no
   password and does not write a password to disk, a request, or logs.
3. Bootstrap records the requested user in the machine registration along
   with the existing UUID, MAC, IP, and hostname facts.
4. The controller validates the user against AD before starting the domain
   configuration. An unknown user produces `assigned_domain_user_not_found`;
   the workstation remains registered and technically manageable, but is not
   joined to the domain.
5. A successful system stage reboots the workstation once. The operator then
   signs in as the selected domain user. No additional command is required.
6. The controller detects the durable first-login evidence and completes the
   user-profile stage. The final state is `ready`, `degraded`, or `failed`
   with a stage-specific public error.

## Security boundary

`start-bootstrap.sh` validates only the UPN syntax locally. AD user lookup is
controller-owned: bootstrap deliberately has no AD credential. The controller
uses its existing privileged management boundary and records only the selected
UPN and safe outcome code. It never receives or stores an employee password.

## State model

The controller persists a root-owned-or-`altserver`-private orchestration
record keyed by machine UUID. State transitions are monotonic and idempotent:

```text
registered
  -> validating_assigned_user
  -> configuring_system
  -> rebooting_for_domain_login
  -> awaiting_first_domain_login
  -> configuring_user_profile
  -> ready | degraded | failed
```

The record contains the normal configure request, target IP, selected UPN,
stage results, timestamps, and safe error metadata. It contains no Vault
value, password, claim, or browser credential. A restart of the controller or
the polling worker reconciles a nonterminal record instead of starting a
second domain join.

## System stage and reboot policy

The existing `03-configure-domain-workstation.yml` becomes the system stage.
It retains preflight, package update, DNS, domain join, GPO, device-wide
software, certificates, and `/etc/skel` preparation. `prejoin_upgrade` must
no longer call `reboot` itself: it records that a reboot is required. A single
final controlled reboot is performed after the system stage, including when
`dist-upgrade` installed a kernel. There is no bootstrap reboot.

## User-profile stage

User-specific work is separated from device configuration:

- `/etc/skel` shortcuts and defaults are installed before reboot for future
  domain homes;
- per-user desktop shortcuts and Nextcloud autostart are applied after first
  domain login;
- KRFB user configuration is applied after first domain login, so the
  controller does not create a domain home prematurely;
- future profile migration can use the same post-login stage after confirming
  the browser is stopped.

First-login evidence is the expected AD account's home directory created by
`pam_mkhomedir`, with ownership matching `getent passwd <selected UPN>`. The
orchestrator records the state before reboot and accepts only a matching home
that appears afterwards. For a previously configured/reused station, a
successful durable `profile-finalized` marker is authoritative and makes the
stage a no-op.

## Worker and failure handling

A dedicated controller systemd timer invokes a narrow reconciliation worker.
It scans only nonterminal orchestration records. It verifies SSH reachability,
checks the first-login predicate, starts the post-login Ansible playbook only
once under a per-machine lock, and writes a structured result. Transient SSH
or SSSD convergence failures retain `awaiting_first_domain_login`; invalid
identity, failed Ansible result, or an unexpected existing home record a
specific terminal error. The existing pending-registration processor and
managed ISO routes remain unchanged.

## Verification

Tests cover UPN capture/redaction, AD-user rejection before configure,
one-reboot upgrade behavior, state transitions and reconciliation after a
worker restart, valid first-login detection, rejection of mismatched homes,
and idempotent post-login execution. Integration validation uses a new ALT
test machine and confirms exactly one reboot, computer object creation in OU
Pilot, first domain login, user shortcuts/KRFB, and a terminal `ready` state.
