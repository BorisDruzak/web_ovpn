# ALT Manual Ansible MVP Design

## Purpose

Add a safe, operator-driven provisioning path for a manually installed ALT
Workstation K 11.x. The path is deliberately separate from the existing
managed-ISO, install-agent, install-session and local-account provisioning
flows.

## Scope and safety boundary

The MVP performs this sequence:

```text
manual ALT installation -> bootstrap -> registration -> configure preview/start
-> hostname and domain DNS -> AD join -> standard packages -> verification
```

It does not add PXE, ISO building, initrd agents, OS installation automation,
web UI, arbitrary Ansible execution, employee-account provisioning, printer
or share setup, endpoint agents, CryptoPro, certificates, or a final office
software catalogue. It never edits existing provision assignments or jobs.

`host-111` is never contacted for tests. `alt-auto-test` is a compatibility
pilot only: its registration, assignment, known-host entry and `test-user`
must remain intact. A clean installation or restored snapshot is required for
final clean-install acceptance.

## Architecture

The existing bootstrap script remains the single bootstrap implementation. It
prepares the `ansible` account, SSH and registration, and is safe to rerun.
For a manual install it accepts `ALT_DEPLOY_HOST` and requires an operator
supplied SHA-256 SSH public-key fingerprint before replacing
`authorized_keys`. The fingerprint is public configuration, never a secret.

The controller gets a separate `workstationctl configure` command family. It
uses the registered UUID to resolve the target IP through `MachineRepository`,
uses the existing controller private key and strict known-host verification,
and invokes only `03-configure-domain-workstation.yml`. It does not reuse
`ProvisionPlanner`, assignments, the old worker, or `02-provision-account.yml`.

`preview` validates controller assets, the UUID, the request schema and Vault
health, then returns an entirely deterministic plan without target mutation.
`start` is synchronous, runs as `altserver`, writes a bounded `0600` log under
a dedicated `0700` configure-run directory, and returns a public JSON result.

## Configure request and result

The request is an object with exactly these fields:

```json
{
  "final_hostname": "alt-ws-001",
  "profile": "standard-domain",
  "domain": "sosnadmin.local",
  "realm": "SOSNADMIN.LOCAL",
  "workgroup": "SOSNADM",
  "computer_ou": "OU=Workstations,DC=sosnadmin,DC=local",
  "domain_test_user": "pilot.user"
}
```

`profile`, `domain`, and `realm` have the literal values shown above.
`workgroup`, `computer_ou`, and `domain_test_user` are required but supplied by
the operator only after AD delegation is ready. Any unknown field, secret-like
field, invalid UUID, or attempt to select a playbook, inventory, command, IP,
or arbitrary extra variables fails with `configure_request_invalid`.

The public result contains `machine_uuid`, `hostname`, `profile`, `domain`,
`already_joined`, `reboot_required`, `run_id`, and boolean verification fields
for SSH, sudo, DNS, time, domain join, SSSD, domain-user lookup and packages.
It contains no Vault values, passwords, key material, or decrypted Vault data.

## Ansible boundary

`03-configure-domain-workstation.yml` loads the runtime Vault explicitly and
runs these independent roles in order:

1. `manual_preflight`
2. `workstation_identity`
3. `workstation_base`
4. `workstation_network`
5. `domain_join`
6. `standard_software`
7. `domain_verify`

`manual_preflight` validates ALT release, UUID, Python, `ansible`, noninteractive
sudo, free space, route, DNS, time and current domain state. It does not
require `osn-admin`, LightDM, AccountsService, or domain packages.

Package names are variables. The first live step discovers the ALT-native
packages and supported join mechanism read-only; code must not guess package
names. The preferred join sequence is `kinit` through stdin, an ALT-native
SSSD/domain mechanism, then `kdestroy`. Credential tasks use `no_log: true`.
If the machine is already joined to `sosnadmin.local`, the join is skipped. A
different joined domain produces `domain_conflict`.

## Failure contract

Stable codes include `manual_preflight_failed`, `domain_dns_unhealthy`,
`domain_time_unhealthy`, `domain_join_credentials_unavailable`,
`domain_join_failed`, `domain_conflict`, `domain_verification_failed`,
`standard_packages_failed`, `configure_request_invalid`, and
`configure_not_configured`. Controlled Ansible failure markers are mapped by
the controller; raw output is bounded and never used to expose secrets.

## Live-test gates

First run a read-only audit of `192.168.101.56` through `osn-admin`: release,
identity, route, DNS/SRV, time, installed components and domain state. Show
that report before mutation. Bootstrap rerun, `configure preview`, and domain
join each require a separate explicit operator approval. Actual AD join also
requires the delegated account, runtime Vault value, workgroup, OU and a test
domain user. Graphical domain sign-in remains an operator manual check.
