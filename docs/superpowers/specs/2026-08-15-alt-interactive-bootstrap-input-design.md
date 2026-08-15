# ALT interactive bootstrap input design

## Goal

Move collection of deployment identity from the ALT installer into the first
interactive invocation of `start-bootstrap.sh`. The operator supplies only
the final workstation hostname and the employee's AD login; the controller
continues to own all domain configuration and validation.

## Operator interaction

The prompts appear in the terminal on the newly installed user workstation,
where the operator invokes the script as root. The controller never attempts
to present an interactive prompt.

1. The script reads the current static hostname and evaluates it locally.
2. A valid hostname is displayed and requires an explicit confirmation before
   it is used. An invalid hostname causes the script to request a replacement.
3. A supplied replacement is lower-cased, validated, displayed, and requires
   explicit confirmation before `hostnamectl set-hostname` is called.
4. The script re-reads the static hostname and refuses to continue unless it
   equals the confirmed value.
5. The script prompts for the employee's short login or UPN and normalizes a
   short login to `@sosnadmin.local`.
6. The bootstrap registers the hostname and UPN. The controller validates the
   UPN in AD before any domain join.

The only normal prompts are hostname confirmation/input and the AD login. No
domain name, realm, workgroup, OU, AD password, Vault value, or local
administrator password is requested.

## Hostname contract

The local validation rule must equal the controller rule:

```text
^(lin|alt|win|deb)-[a-z][0-9]?-(pc[1-9][0-9]*)$
```

Examples: `alt-a1-pc3`, `lin-b-pc12`, `win-k3-pc1`.

The rule is validated again by the controller before Ansible and by the
workstation identity role before domain join. A controller-side mismatch or
duplicate AD computer remains a terminal safe failure; it is never silently
renamed or reused.

## Data flow and failure handling

```text
start-bootstrap on user workstation
  -> local facts + hostname confirmation
  -> local hostname mutation and read-back verification (if needed)
  -> UPN capture
  -> technical bootstrap and registration
  -> controller AD UPN validation
  -> system/domain stage -> one reboot -> first-login user stage
```

If the controller is temporarily unavailable after local confirmation, the
existing technical registration retry is retained. A failed AD user lookup
does not request credentials again and does not perform a domain join; it
returns the safe `assigned_domain_user_not_found` outcome. The operator can
re-run the script with the corrected UPN without re-installing ALT.

## Compatibility and verification

Direct `bootstrap.sh` remains a noninteractive technical bootstrap for legacy
and managed-install paths. Only `start-bootstrap.sh` gains the new interaction.

Tests must prove valid-name confirmation, invalid-name retry, rejected
confirmation without mutation, lowercase normalization, `hostnamectl`
read-back failure, UPN normalization, no password prompt or log, and that the
controller-generated request retains `hostname_mode=verify` after the local
identity is set.
