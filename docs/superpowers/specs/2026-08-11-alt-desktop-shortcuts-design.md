# ALT Workstation: desktop shortcuts

## Goal

Provide the standard desktop shortcuts for every new domain profile and place
the same shortcuts in the already existing pilot profile.

## Design

`desktop_shortcuts` runs after the browser, CryptoPro and OnlyOffice are
installed. It creates `/etc/skel/Рабочий стол` and copies the vendor desktop
entries already installed by their packages:

- `cptools.desktop` — CryptoPro Tools;
- `yandex-browser.desktop` — Yandex Browser;
- `onlyoffice-desktopeditors.desktop` — ONLYOFFICE.

It also creates two relative links that have no user-specific absolute path:

- `Сетевая папка` -> `../net.drives/Public`;
- `Домашняя папка` -> `..`.

The role obtains `domain_test_user` through NSS and updates that profile only
when its home directory already exists. It never creates a new user home,
changes SMB credentials, or replaces GPO mapping. Future homes inherit the
files through `/etc/skel`.

## Verification

The role checks source entries, skeleton files and links. The pilot check runs
as the domain test user and confirms all entries are present, executable where
applicable, owned by that user, and resolve to the expected relative targets.
