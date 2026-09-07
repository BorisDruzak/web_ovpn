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
  "domain_test_user": "alt-test-user@sosnadmin.local",
  "remote_access_profile": "none",
  "assigned_domain_user": null
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

## Plasma baseline and KRFB remote access

Every configure request writes the approved non-secret Plasma defaults only to
`/etc/skel/.config/`. They apply when a new domain home is created; Ansible does
not rewrite the complete configuration or power settings of an existing user.
The baseline disables display dimming, display power-off and automatic suspend
on AC power, selects the `performance` power profile, and keeps the Plasma
layout switch mode global.

KRFB is disabled by default. To configure it for one existing domain user, the
operator sets `"remote_access_profile": "krfb"` and supplies that exact login
or UPN in `assigned_domain_user`. The request remains non-secret. Before a
KRFB run, the controller verifies that the two obscured KRFB password values
exist in its private Ansible Vault.

The KRFB role resolves only the explicitly assigned user, writes
`~/.config/krfbrc` mode `0600`, and adds a Plasma autostart entry mode `0644`.
It never launches, restarts or stops KRFB, and it does not alter firewall or
VPN configuration. KRFB starts only at that user's next Plasma login. Use this
profile only where access to port 5900 is already restricted by the approved
network policy.

## After a successful join

For a new join the public result reports reboot_required: true. The controller
does not reboot the station automatically. Reboot it, then sign in using the
existing AD account. PAM creates the domain user's home directory at that first
successful login; no local employee account is created.

The fixed playbook selects the supported Plasma Wayland session in LightDM.
X11 remains installed and is not removed. The selection takes effect after the
required reboot. On an already joined workstation it takes effect after the
next normal reboot or a deliberate LightDM restart; the controller never
restarts LightDM or interrupts an active user session on its own.

## Mandatory CA, CryptoPro and ГосПлагин

The fixed workstation profile installs the public Sosnadmin Local CA anchor,
CryptoPro CSP, CAdES 2.0.15700-1 and ГосПлагин 1.3.42. The controller accepts only the fixed
artifact paths and SHA-256 values declared in Ansible group variables. Before
the first run, the controller operator places the approved CryptoPro archive
and ГосПлагин RPM in those paths with owner altserver:altserver and mode 0600,
then adds vault_cryptopro_license to the private Ansible Vault.

The profile validates artifact SHA-256 and RPM name/version/architecture before
installation, verifies both browser native-messaging hosts afterwards, and
uses PC/SC socket activation. The ГосПлагин ZIP is unpacked to its pinned RPM
payload without running the vendor self-extracting installer. The public configure result contains only boolean verification
values and package versions; it never contains the license or Vault material.

IFCPlugin is intentionally not installed. Yandex Browser extensions are
assigned centrally through AD Group Policy: Ansible installs native hosts only
and does not add local extension policies.

## Endpoint Agent first installation

The fixed profile also supports the one-time installation of the approved
Endpoint Agent RPM. Before rollout, the controller operator places
`endpoint-agent-0.1.0-6.x86_64.rpm` in the fixed Endpoint artifact directory,
with the SHA-256 declared in `group_vars/all.yml`.

The operator creates an active Gateway enrollment campaign for the approved
CIDR/group, lifetime and use limit, then stores only its UUID in the non-secret
`endpoint_enrollment_campaign_id` variable. The separate scoped Gateway
service token is stored only as `vault_endpoint_provisioning_token` in the
existing Ansible Vault. It has `provisioning.install-claims.issue` only; a
Gateway administrator credential is not used.

For a new workstation the role checks Gateway DNS and the RPM checksum and
metadata, derives the exact hardware fingerprint from that RPM payload, then
requests one short-lived claim immediately before `rpm -Uvh`. The claim is
root-only on the workstation, is hidden from Ansible output, is not placed in
Vault or the configure result, and is removed by the RPM finalizer only after
the durable device credential is verified. A repeated configure run never
issues a new claim or updates an enrolled Endpoint Agent; Gateway owns normal
agent updates. An installed but incomplete enrollment stops with
`endpoint_agent_recovery_required` and requires a controlled recovery rather
than an automatic claim replacement.

## OnlyOffice, Nextcloud Desktop and Public share

The fixed profile installs OnlyOffice Desktop Editors from the controller's
approved RPM. The controller validates its SHA-256, package name, version and
architecture before the package is copied to the workstation. A configure
request cannot select a different RPM or alter the expected package version.

The fixed profile also installs `nextcloud-client` from the approved ALT 11.x
repository when the client is absent. It does not configure a Nextcloud server
URL, a local sync directory, autostart, a password or a token. The domain user
starts Nextcloud and performs their own interactive sign-in after their first
Plasma login.

The shared resource `\\antares\Public` is not mounted by Ansible and no SMB
credential is stored on a workstation. It is connected by the separate user
GPO `Network Drive - Public`, linked to `sosnadmin.local` and security-filtered
to `Authenticated Users` (there are user-side settings only, so computer
accounts do not receive a drive map). On ALT, `gpupdate` manages the autofs mount; after the user
policy has applied, the visible user path is `~/net.drives/Public`.

## Desktop shortcuts

After the approved browser, CryptoPro and OnlyOffice packages are present, the
fixed profile copies their vendor launchers to `/etc/skel/Рабочий стол`:
CryptoPro Tools, Yandex Browser, ONLYOFFICE and Nextcloud. It also adds relative folder
links named `Сетевая папка` (`../net.drives/Public`) and `Домашняя папка`
(`..`). Consequently no desktop file contains a user-specific home path, SMB
credential or password.

New domain homes inherit all six entries during their first sign-in. The role
also copies the vendor `nextcloud-client.desktop` entry to `.config/autostart`, so the
client starts at Plasma login without a preconfigured account. A configure run
updates the already existing profile selected by `domain_test_user`; it does
not create a missing home just to place icons.
