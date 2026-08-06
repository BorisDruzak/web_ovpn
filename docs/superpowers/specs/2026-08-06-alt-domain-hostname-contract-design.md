# ALT manual domain join: hostname and safety contract

## Purpose

Bring the manual ALT Workstation domain-join path into line with the approved
operational contract.  A workstation is installed manually with its final
hostname and an `osn-admin` account, bootstrapped, registered, then configured
only through the controller's fixed `workstationctl configure` interface.

The controller never accepts an arbitrary Ansible command, inventory, playbook,
IP address, or AD credential from an operator.

## Version gate

`manual_preflight` must identify the operating system from `/etc/os-release`,
not the legacy `/etc/altlinux-release` text.  It accepts **ALT Workstation K**
whose `VERSION_ID` starts with `11.`.  Thus K 11.2, K 11.4 and future 11.x
updates are accepted without reinstallation; a different ALT product or a
non-11 major version is rejected.

## Hostname contract

The canonical hostname grammar is:

```text
^(lin|alt|win|deb)-[a-z][0-9]?-(pc[1-9][0-9]*)$
```

Examples: `alt-a1-pc3`, `lin-b-pc2`, `win-k3-pc1`, `deb-a2-pc12`.

`ConfigureRequest` retains `final_hostname` and adds the required field
`hostname_mode`, with exactly one of these values:

| Mode | Behaviour |
| --- | --- |
| `verify` | Assert that the target's static hostname exactly equals `final_hostname` and complies with the grammar. Do not change it. |
| `change_confirmed` | Treat `final_hostname` as an explicitly approved rename, set it through `hostnamectl`, then verify it. |

The controller rejects a malformed requested hostname before any target action
with `hostname_invalid`.  A target whose actual hostname is malformed or differs
from the requested value in `verify` mode stops with `hostname_mismatch`.
Hostnames are normalized to lower case before comparison and use.  This is
consistent with DNS/Linux hostnames; the AD computer account is case-insensitive.

## Domain join and conflict contract

The fixed playbook continues to create a missing computer account using the
delegated Vault account and the parent-first target OU path.  Before it does so,
it must query the target OU for `sAMAccountName=<hostname>$` using Kerberos/GSSAPI.

- No result: joining is permitted; AD creates the computer account.
- The station is already joined to the requested domain and `net ads testjoin`
  succeeds: it is an idempotent success, without an AD write.
- A matching AD account exists but the station cannot prove that trust: stop
  with `domain_computer_conflict`.

The playbook must never delete, reset, move or reuse an existing computer
account.  Lookup and join credentials originate only in the existing Ansible
Vault and are kept out of the request, command line and public result.

## Domain user login

The domain configuration must explicitly enable automatic home-directory
creation for AD users through the ALT-supported `system-auth`/PAM mechanism and
verify its effective configuration.  The acceptance check after reboot uses the
existing AD test account: `getent` must resolve it and its first successful
login must create the expected home directory.  No local employee account is
created by this path; `osn-admin` and `ansible` remain the technical accounts.

## Operator flow

1. The operator supplies the approved JSON request to the controller operator.
2. `workstationctl configure preview <uuid> --vars-file request.json` validates
   only the request and registration, then displays the immutable fixed plan.
3. `workstationctl configure start <uuid> --vars-file request.json` runs the
   fixed playbook as `altserver` with strict host-key checking.
4. A new join reports `reboot_required: true`; reboot is a separate explicit
   operator action.  The AD user then performs the first login.

`preview` is non-mutating and does not prove target DNS, NTP, hostname or AD
reachability.  Those checks happen at `start`.

## Documentation and tests

The manual runbook and MVP document must use the approved curl bootstrap path,
the Pilot OU, the two hostname modes, and the controller-only execution model.
Automated tests cover request validation, both hostname modes, ALT 11.x version
acceptance/rejection, computer-account conflicts, and public error mapping.
