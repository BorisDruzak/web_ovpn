# ALT Workstation: manual bootstrap and domain join MVP

This is a temporary, controller-managed path for a manually installed ALT
Workstation K 11.x. It does not replace managed ISO or legacy ai curl=
installation.

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

Run preview before any mutation:

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
