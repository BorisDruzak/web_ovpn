# ALT Workstation: manual bootstrap and domain join MVP

> **Scope/status:** This document is a local/static operator procedure. It does
> not prove that a deployed controller canary has run; runtime acceptance is a
> Task 6 activity after separately authorized deployment and successful
> controller readiness. Nothing here authorizes machine selection, `netctl`,
> bootstrap modification, network-policy changes, or Vault changes.

This is a temporary, controller-managed path for a manually installed ALT
Workstation K 11.x. It does not replace managed ISO or legacy ai curl=
installation.

## Execution path

The path begins only after ALT Workstation K 11.x is installed manually. The
sequence is fixed; the workstation never runs Ansible itself and the operator
never supplies a domain password to it.

1. The operator creates the local `osn-admin` recovery account, configures
   DHCP and sets the approved final hostname during the manual installation.
2. `osn-admin` starts `bootstrap.sh` as root. It validates the installed ALT
   release and network, installs the minimal SSH/Ansible dependencies, creates
   the restricted `ansible` technical account and registers the station.
3. The controller processes the registration: it waits for SSH, records the
   initial host key in its isolated known-hosts file, runs an Ansible ping and
   the fixed `workstationctl preflight`. Only a station that passes all three
   checks advances to `awaiting_assignment`; the controller then becomes the
   only side that can start configuration.
4. The controller operator runs `configure preview`. This validates the
   request, registered UUID and target IP without contacting or changing the
   workstation.
5. The controller operator runs `configure start`. It validates the Ansible
   assets, SSH identity, known-hosts file and AD join Vault values; then it
   creates a private run directory and invokes only
   `03-configure-domain-workstation.yml`.
6. The playbook runs these roles in order:
   `manual_preflight` → `workstation_identity` → `prejoin_upgrade` →
   `workstation_base` → `alt_group_policy_prerequisites` →
   `workstation_network` → `domain_join` → `alt_group_policy_client` →
   `domain_login_baseline` → selected software components → selected remote
   profile → `domain_verify`.
7. `manual_preflight` verifies release, DMI UUID, passwordless sudo, default
   route, NTP and AD DNS. `workstation_identity` either verifies the approved
   hostname or changes it only in `change_confirmed` mode.
8. Before a first domain join, `prejoin_upgrade` performs the configured full
   ALT upgrade when selected and records whether a reboot is required. Neither
   the role nor the controller reboots the workstation automatically; a
   previously joined machine skips this step.
9. The remaining roles install domain and Group Policy prerequisites, set AD
   DNS for the active interface, obtain a temporary Kerberos ticket, create a
   new computer account only when no account with the requested name exists in
   the target OU, join through `system-auth`, enable and apply machine Group
   Policy, then verify Samba trust, SSSD and a specified domain-user lookup.
10. `domain_verify` writes the public result on the controller. A newly joined
    workstation can report `reboot_required: true`; the controller does not
    reboot it automatically. The operator reboots it and the domain user signs
    in.

The controller readiness check syntax-checks this manual playbook alongside
the older preflight and local-account playbooks. A configuration run that
exceeds 90 minutes returns `domain_join_timeout` together with its `run_id`;
use that identifier to inspect the private controller log.

## Operator preparation

The employee's domain account must already exist in sosnadmin.local; this flow
does not create AD users. During manual installation the operator creates the
local recovery administrator osn-admin, uses DHCP, and sets the final unique
hostname.

The hostname is lower-case and must follow:

~~~text
^(lin|alt|win|deb)-[a-z][0-9]?-(pc[1-9][0-9]*)$
~~~

For example: alt-a1-pc3, lin-b-pc2, win-k3-pc1.

## Bootstrap

Log in as osn-admin and run:

~~~bash
curl --noproxy '*' -fsS --connect-timeout 5 --max-time 30 \
  http://192.168.100.17:8087/bootstrap/bootstrap.sh \
  -o /tmp/alt-bootstrap.sh && \
sudo env no_proxy=192.168.100.17 NO_PROXY=192.168.100.17 \
  bash /tmp/alt-bootstrap.sh
~~~

The local sudo prompt is the only place the local administrator password is
entered. Bootstrap prepares ansible, SSH, sudo and registration only. It does
not create an AD user or join the domain.

## Controller request

The workstation operator does not run Ansible or system-auth. An authorized
controller operator creates a non-secret JSON request and runs the fixed
controller command. The request does not contain a password, SSH key or Vault
value.

To verify the hostname set during installation without changing it:

~~~json
{
  "machine_uuid": "<registered-uuid>",
  "final_hostname": "alt-a1-pc3",
  "hostname_mode": "verify",
  "profile": "standard-domain",
  "domain": "sosnadmin.local",
  "realm": "SOSNADMIN.LOCAL",
  "workgroup": "SOSNADM",
  "computer_ou": "OU=Pilot,OU=Linux,OU=Устройства,DC=sosnadmin,DC=local",
  "domain_test_user": "alt-test-user@sosnadmin.local"
}
~~~

To rename a station only after explicit approval, change exactly these two
fields:

~~~json
{
  "final_hostname": "alt-a1-pc3",
  "hostname_mode": "change_confirmed"
}
~~~

verify stops with hostname_mismatch when the installed hostname differs.
change_confirmed is the only mode that permits a rename. A name outside the
approved grammar is rejected as hostname_invalid before the controller contacts
the workstation.

## Controller execution

The controller operator uses the fixed `workstationctl` route. Always run the
non-mutating preview before any start or other mutation:

~~~bash
sudo -u altserver /usr/local/sbin/workstationctl --json configure preview <uuid> \
  --vars-file /path/to/request.json
~~~

preview is non-mutating: it validates the request and registration and shows the
fixed plan, but does not test DNS, NTP, hostname or AD connectivity on the
station.

After review and approval, start the fixed playbook:

~~~bash
sudo -u altserver /usr/local/sbin/workstationctl --json configure start <uuid> \
  --vars-file /path/to/request.json
~~~

The controller resolves the registered target IP, uses strict SSH host-key
checking and runs only 03-configure-domain-workstation.yml. It configures AD
DNS, obtains the delegated join credential from the existing Ansible Vault,
creates a missing computer account in
OU=Pilot,OU=Linux,OU=Устройства,DC=sosnadmin,DC=local, and verifies Samba,
SSSD and the supplied AD user lookup.

If an existing computer account cannot be proven to belong to this station, the
run stops with domain_computer_conflict. It never deletes, resets, moves or
reuses that account. A station already joined to the requested domain with a
valid trust is unchanged.

### Optional managed profiles

The request's `software_profile` and `remote_access_profile` are fixed profile
selectors; they are not a place for paths, package metadata, Vault values or
arbitrary playbook options. `base`/`none` keeps the base path above.

For `software_profile: core-apps`, the controller and stage-03 playbook select
the approved browser, OnlyOffice and Nextcloud Desktop components. Every
selected component must pass its controller-side artifact preflight (including
the approved identity and package metadata) before any selected component can
run. A missing or invalid artifact fails closed; it never falls back to a
download or a caller-supplied artifact.

For `remote_access_profile: krfb`, the controller first requires both
presence-only checks for the existing Vault fields
`vault_krfb_desktop_password_obscured` and
`vault_krfb_unattended_password_obscured`. It also requires one explicit,
already-existing domain user in the request and the exact controller setting
`ALT_DEPLOY_KRFB_TCP_5900_RESTRICTED_CONFIRMED=true`. That setting records a
separate operator confirmation that the pre-existing VPN/firewall policy
restricts TCP port 5900; it does not open or change the port. KRFB writes only
the assigned user's protected configuration and autostart file. The controller
does not start KRFB, discover a user, or return a secret.

For every profile, review `configure preview` first and run `configure start`
only through the fixed controller command above. Stop on any preflight or
profile-gate failure.

## After a successful join

For a new join the public result reports reboot_required: true. The controller
does not reboot the station automatically. Reboot it, then sign in using the
existing AD account. PAM creates the domain user's home directory at that first
successful login; no local employee account is created.

The same fixed playbook selects Plasma X11 in LightDM before the domain-join
step. Wayland is not removed; X11 is the MVP default for reliable graphical UPN
login on ALT Workstation K 11.x. The selection takes effect after the required
reboot. On an already joined workstation it takes effect after the next normal
reboot or a deliberate LightDM restart; the controller never restarts LightDM
and interrupts an active user session on its own.
