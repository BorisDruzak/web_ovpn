# ALT core-apps profile design

## Goal

Extend the existing `core-apps` configure profile so a domain workstation receives
ONLYOFFICE Desktop Editors, Nextcloud Desktop with KDE integration, and the
operator-approved desktop shortcuts without weakening the `base` profile.

## Scope and behaviour

- `base` remains the minimal managed profile: it must not install ONLYOFFICE or
  Nextcloud.
- `core-apps` installs both applications after the domain-critical phases have
  completed. A failure is recorded as an independent component failure in the
  existing structured configure result.
- ONLYOFFICE is installed only from the controller-held approved RPM:
  `/opt/alt-deploy-control/artifacts/onlyoffice/onlyoffice-desktopeditors-9.4.0-epm1.repacked.130.x86_64.rpm`.
  The role requires SHA-256
  `b8dd26405b5cd79da8a80afc7089007de608a53e7e90ea6a247379bebfe54c9f`
  and the RPM identity `onlyoffice-desktopeditors|9.4.0-epm1.repacked.130|x86_64`
  before a copy to a workstation. It verifies the installed EVR and
  `/usr/bin/onlyoffice-desktopeditors` afterwards.
- Nextcloud is installed only from the configured ALT repository. The role
  installs `nextcloud-client` and `nextcloud-client-kde`, then verifies package
  presence and `/usr/bin/nextcloud`.
- The desktop role is enabled only with `core-apps`. It copies the launchers for
  ONLYOFFICE, Yandex Browser and Nextcloud into `/etc/skel/Рабочий стол` and
  places `nextcloud-client.desktop` into `/etc/skel/.config/autostart`.
- For the explicitly supplied `assigned_domain_user`, the desktop role applies
  the same application links and Nextcloud autostart to the existing home. It
  does not enumerate or alter other user homes. The `base` request therefore
  continues to use `assigned_domain_user: null`; a `core-apps` request used for
  a present user must carry a valid UPN.

## Failure handling and safety

- Package-manager metadata refresh and package installation use the shared
  `alt_resilience` retry policy; signature, dependency and metadata validation
  errors remain fatal and visible as a component error.
- ONLYOFFICE uses a root-only temporary directory and an `always` cleanup block.
  No RPM is copied if its checksum or RPM metadata differs from the catalog.
- Nextcloud DNS is not preconfigured or automatically authenticated. First-run
  account setup remains an interactive action for the user; autostart merely
  opens the installed client.
- Existing user desktop changes are intentionally limited to the caller's
  `assigned_domain_user`; defaults for future domain users are delivered through
  `/etc/skel`.

## Verification

Tests must assert that `core-apps` preview exposes `install_core_apps`, that
the playbook enables these components only for `core-apps`, and that the roles
contain the catalog, retry, verification, cleanup and explicit-user constraints.
On the test workstation, verify the package EVRs, binaries, desktop entries,
`/etc/skel` launchers, and the selected user's Nextcloud autostart file. A
successful configure result must report the independent component statuses.
