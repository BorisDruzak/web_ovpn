# ALT Workstation: manual bootstrap and Ansible MVP

This is an additional operator path for a manually installed ALT Workstation
K 11.x. It does not replace the managed-ISO/install-agent path.

## Prerequisites

The controller is `192.168.100.17`; its bootstrap SSH public key fingerprint
is `SHA256:60+ctiToYXkwE+H5LfV2hD/MZqRFiato7Q1RcQRlTmM`. The controller needs
the existing `altserver` account, SSH identity, known-hosts file and runtime
Ansible Vault. AD DNS is `192.168.100.11`; the domain is `sosnadmin.local`,
realm `SOSNADMIN.LOCAL`, workgroup `SOSNADM`.

Install ALT manually, obtain an IP address and run as root:

```bash
sudo ALT_DEPLOY_HOST=192.168.100.17 \
  ALT_ANSIBLE_AUTHORIZED_KEY_SHA256='SHA256:60+ctiToYXkwE+H5LfV2hD/MZqRFiato7Q1RcQRlTmM' \
  bash bootstrap.sh
```

The script must not be fetched through `curl | bash`. It checks ALT release,
route, IPv4, controller reachability, the public-key fingerprint, sudoers and
passwordless sudo for `ansible`; it then registers the machine.

## Vault and request

Create/edit the runtime encrypted Vault only on the controller. It must include
`vault_ad_join_user` and `vault_ad_join_password`; never place those values in
the request file, command line, logs or Git.

```json
{
  "machine_uuid": "53b03180-5d78-11f0-bd95-f027db877a00",
  "final_hostname": "alt-ws-001",
  "profile": "standard-domain",
  "domain": "sosnadmin.local",
  "realm": "SOSNADMIN.LOCAL",
  "workgroup": "SOSNADM",
  "computer_ou": "OU=Workstations,DC=sosnadmin,DC=local",
  "domain_test_user": "pilot.user"
}
```

Run preview before any mutation:

```bash
sudo -u altserver /usr/local/sbin/workstationctl --json configure preview <uuid> \
  --vars-file /path/to/request.json
```

After preview review and explicit approval, start the fixed playbook:

```bash
sudo -u altserver /usr/local/sbin/workstationctl --json configure start <uuid> \
  --vars-file /path/to/request.json
```

`start` uses only `03-configure-domain-workstation.yml`, resolves the target
through its registration, uses strict SSH host-key checks and writes a private
per-run log. It installs ALT's `task-auth-ad-sssd`, configures domain DNS,
acquires a temporary Kerberos ticket through stdin, invokes `system-auth`, then
destroys the ticket. Reboot when `reboot_required` is true.

## Limits and recovery

Do not use this flow to remove assignments, release/reassign local employees,
install non-approved software, configure printers/shares/certificates, or run
arbitrary Ansible. A different existing domain stops with `domain_conflict`.
For failed joins, retain the private run log, correct DNS/time/OU/delegation,
then rerun preview; restore a VM snapshot or reinstall ALT for clean recovery.
Graphical domain login is verified manually by the operator.
