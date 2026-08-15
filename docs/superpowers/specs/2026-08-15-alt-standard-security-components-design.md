# Standard ALT Security Components Design

## Goal

Make Endpoint Agent, CryptoPro CSP, CryptoPro CAdES, Госуслуги Plugin 1.3.19
and the Sosnadmin CA mandatory parts of the controller-managed `standard-domain`
workstation profile.  Create the related desktop entries after the first
successful domain login.

## Ordering

The critical domain phases remain unchanged.  Mandatory independent system
components run after successful domain join in this order: organization CA,
CryptoPro CSP, CAdES, Госуслуги Plugin, Endpoint Agent, then the desktop
skeleton.  The first-login stage creates user-owned shortcuts only after
`pam_mkhomedir` has created the selected domain home.

## Endpoint Agent boundary

The role installs only the reviewed RPM
`endpoint-agent-3.2.21-alt2.x86_64.rpm` from the controller artifact store.
It validates its SHA-256 and obtains the canonical binding only through the
RPM-provided fingerprint helper.  It creates one single-use Gateway campaign,
requests one host-bound claim immediately before installation, writes the
claim only as root-owned `0600` `/etc/credstore/endpoint-enrollment-claim`,
waits for durable enrollment, removes the claim, verifies a restart without it,
and always revokes the campaign.  Service token, claim and device credential
are never written to Git, inventory, result JSON or logs.

## Crypto and browser integration

The controller artifact store is the sole source for the approved CryptoPro
and CAdES archives, the direct Госуслуги Plugin 1.3.19 RPM, and the public CA.
The CryptoPro license and Endpoint service token remain existing Vault values.
The browser extension enablement remains an AD GPO responsibility; Ansible
installs only the native hosts and their RPMs.

## User shortcuts

`/etc/skel` and the selected existing domain profile receive only user-owned
desktop launchers: CryptoPro (`/opt/cprocsp/sbin/amd64/xcpui_app`), Home
(`file://$HOME`), and Public share (`smb://antares/Public`).  The role does not
mount the SMB share or store user credentials.

## Failure behavior and acceptance

All five system components are required.  A component failure yields a
structured failed provisioning result while cleanup of temporary artifacts,
one-time claim, and campaign still runs.  Acceptance requires domain join,
the exact installed RPM/package versions, trusted CA, native hosts, endpoint
durable credential and restart-without-claim, plus user-owned shortcut files.
