# ALT Linux Workstation Deployment Context

This document is the canonical context for the ALT Linux workstation deployment work. It exists so a future maintainer, Codex session, or ChatGPT conversation can continue without reconstructing the design from chat history.

## Goal

Build a repeatable workstation provisioning chain for ALT Workstation K 11.2:

```text
USB installer
  -> ALT autoinstall configuration over HTTP
  -> unattended ALT installation
  -> first-boot bootstrap over HTTP
  -> create Ansible service account and SSH access
  -> register machine with deployment API
  -> refresh isolated SSH known_hosts data
  -> automatic ansible.builtin.ping verification
  -> later: apply workstation roles and software
```

The current target is ALT Workstation K 11.2 (Nemorosa), KDE/Plasma, UEFI, DHCP and Btrfs.

## Verified state

The full chain was tested successfully on 2026-07-16.

### Deployment server

- Host IP: `192.168.100.17`
- File server: `http://192.168.100.17:8087/`
- Registration API: `http://192.168.100.17:8088/register`
- Health endpoint: `http://192.168.100.17:8088/health`
- Ansible user on the server: `altserver`
- Ansible project: `/home/altserver/ansible`
- SSH private key: `/home/altserver/.ssh/id_ed25519`
- Isolated host-key file: `/home/altserver/.ssh/known_hosts_autoinstall`

### Verified target

- Hostname: `alt-auto-test`
- DHCP address during test: `192.168.101.56/23`
- MAC: `c0:9b:f4:62:54:e5`
- DMI UUID: `53b03180-5d78-11f0-bd95-f027db877a00`
- Interface during test: `enp3s0`

The IP remained the same after reinstall because DHCP saw the same MAC and reused the lease. The IP is not the durable machine identity. The API uses DMI UUID when available and falls back to MAC.

## Server paths

```text
/srv/alt-deploy/
├── index.txt
├── metadata/
│   ├── autoinstall.scm
│   ├── vm-profile.scm
│   ├── pkg-groups.tar
│   └── install-scripts.tar
├── bootstrap/
│   ├── bootstrap.sh
│   └── ansible_authorized_keys
├── packages/
├── logs/
└── registration/
    ├── pending/
    ├── ready/
    └── failed/

/opt/alt-deploy-api/
├── register_api.py
└── process_pending.py
```

`pkg-groups.tar` is copied from `/Metadata/pkg-groups.tar` on the exact ALT ISO used for installation. Do not replace it with a file from another release. It is intentionally not committed to Git.

`install-scripts.tar` is currently an empty archive with `preinstall.d/` and `postinstall.d/`; first-boot work is handled by `bootstrap.sh`.

## systemd units

- `alt-deploy-http.service`: Python static HTTP server on port 8087.
- `alt-deploy-register.service`: registration API on port 8088.
- `alt-deploy-process.path`: watches `registration/pending`.
- `alt-deploy-process.service`: one-shot SSH and Ansible verification.

Useful checks:

```bash
systemctl is-active \
  alt-deploy-http \
  alt-deploy-register \
  alt-deploy-process.path

curl -fsS http://127.0.0.1:8088/health
journalctl -u alt-deploy-http -f
journalctl -u alt-deploy-process.service -f
```

## Autoinstall boot

The current stock USB image is not modified. At the ALT boot menu, edit the Linux kernel command line and append:

```text
ai curl=http://192.168.100.17:8087/metadata/
```

This is temporary. Planned options:

1. Add a custom boot-menu entry to a rebuilt ISO/USB image.
2. Later move to PXE/iPXE.

The current autoinstall is destructive and clears the first detected disk. Test with one system disk only.

## Disk layout

The tested profile uses:

- UEFI system partition created by the installer.
- 4 GiB swap.
- Btrfs on the remaining space, minimum 40 GiB.
- Btrfs subvolume `@` mounted at `/`.
- Btrfs subvolume `@home` mounted at `/home`.

The installer profile is named `timeshiftstation` to match the working installation flow captured from `/root/.install-log/wizard.log`.

## Bootstrap behavior

`bootstrap.sh` performs only initial machine management:

1. Wait for the deployment file server.
2. Install/update `python3`, `openssh-server`, `sudo` and `curl`.
3. Create the technical account `ansible`.
4. Add `ansible` to `wheel`.
5. Download the Ansible public key.
6. Install passwordless sudo for this technical account.
7. Enable and start `sshd`.
8. Register hostname, source IP, MAC and UUID with the deployment API.
9. Create markers:
   - `/var/lib/alt-bootstrap-completed`
   - `/var/lib/alt-bootstrap-registered`
10. Log to `/var/log/alt-bootstrap.log`.

The bootstrap is designed so that a repeated run does not reinstall packages. If base bootstrap is complete but registration is missing, it retries registration only.

## Registration and Ansible verification

The API accepts internal clients from:

- `127.0.0.0/8`
- `192.168.100.0/23`

A registration creates a JSON record in `registration/pending`. The path unit starts `process_pending.py`, which:

1. Validates the registered IP is inside the deployment network.
2. Waits for TCP/22.
3. Removes old entries only from `known_hosts_autoinstall`.
4. Runs `ssh-keyscan` and writes current host keys to that isolated file.
5. Runs `ansible.builtin.ping` using the `ansible` account and `/usr/bin/python3`.
6. Moves the record to `ready` or `failed`.

A successful record resembles:

```json
{
  "machine_key": "53b03180-5d78-11f0-bd95-f027db877a00",
  "hostname": "alt-auto-test",
  "ip": "192.168.101.56",
  "mac": "c0:9b:f4:62:54:e5",
  "uuid": "53b03180-5d78-11f0-bd95-f027db877a00",
  "status": "ready",
  "verified_at": "2026-07-16T07:38:57+00:00",
  "ansible_output": "... ping ... pong ..."
}
```

## SSH host-key handling

A reinstall generates new SSH host keys. The automatic pipeline intentionally does not modify the operator's normal `~/.ssh/known_hosts`. It maintains:

```text
/home/altserver/.ssh/known_hosts_autoinstall
```

Ansible verification uses this file with strict host-key checking. The helper `deploy/alt-linux/ssh/ssh-alt` uses the same file for manual access to newly deployed machines.

A normal command such as `ssh ansible@192.168.101.56` can still report `REMOTE HOST IDENTIFICATION HAS CHANGED` because it uses the normal `known_hosts`. Use `ssh-alt` for deployment-managed machines, or remove the single stale normal entry manually.

A future stronger design is an internal OpenSSH host CA.

## Existing Ansible work to refactor

There is an older Ansible package originally written for ALT Linux 10 with GNOME. It was reported to work previously, but GUI-dependent parts are obsolete for ALT K 11.2.

The desired system-level software scope is:

- Yandex Browser.
- Managed browser policies, extensions and plugins.
- CryptoPro CSP and browser plugin.
- Organization root CA certificate.
- ONLYOFFICE Desktop Editors.
- Nextcloud desktop client.
- Certificates required for internal Nextcloud and ONLYOFFICE web access.
- Network shares, including the scan share.
- Later: helpdesk agent, monitoring and other common organization software.

Exclude from the initial workstation baseline:

- Per-user Plasma/KDE layout.
- Desktop icons and cosmetic GUI changes.
- Personal Nextcloud account binding.
- Personal CryptoPro certificates.
- User-specific shortcuts and autostart.
- Logic that selects the first directory in `/home`.

Recommended role order:

```text
01_base_system
02_local_accounts
03_workstation_software
04_organization_services
05_user_profile
```

The next role should establish the system baseline and account invariants before installing application software.

## Security rules

Never commit:

- yescrypt password hashes from the active `autoinstall.scm`;
- private SSH keys;
- Ansible Vault password files;
- CryptoPro license data;
- application passwords or API tokens;
- internal personal certificates;
- generated registration JSON containing data that should remain private;
- `pkg-groups.tar` copied from the ISO.

The committed autoinstall file is a template with placeholders only.

The current registration API is restricted by source network but has no authentication token. Before deployment outside a trusted provisioning VLAN, add a one-time registration token, HTTPS/mTLS, or both.

## Known limitations

1. `autoinstall.scm` currently names `enp3s0`; this is model-specific.
2. The installer clears the first disk.
3. The stock USB still requires manual `ai curl=...` entry.
4. Static file delivery uses Python `http.server`, not nginx.
5. The API uses plain HTTP on the trusted LAN.
6. Ready registrations are not yet exposed as a dynamic Ansible inventory.
7. No Ansible workstation roles have been migrated to ALT K 11.2 yet.
8. No web UI is connected to this deployment subsystem.

## Next implementation order

1. Generate dynamic Ansible inventory from `registration/ready`.
2. Add a safe base-system role and run it only against the test host.
3. Add local-account management and hide technical users from the display manager only after SSH/sudo validation.
4. Migrate organization CA, ONLYOFFICE and Nextcloud client roles.
5. Migrate Yandex Browser policies and mandatory extensions.
6. Migrate CryptoPro using Ansible Vault for licenses and secrets.
7. Add network-share roles without `0777` and without choosing an arbitrary home directory.
8. Make NIC selection independent of `enp3s0`.
9. Add a custom USB boot entry, then consider PXE/iPXE.
10. Replace Python static HTTP with nginx and harden registration transport.

## Quick recovery commands

Inspect records:

```bash
find /srv/alt-deploy/registration/pending -maxdepth 1 -type f -exec cat {} \;
find /srv/alt-deploy/registration/ready   -maxdepth 1 -type f -exec cat {} \;
find /srv/alt-deploy/registration/failed  -maxdepth 1 -type f -exec cat {} \;
```

Retry one failed request:

```bash
sudo -u altserver mv \
  /srv/alt-deploy/registration/failed/<machine-key>.json \
  /srv/alt-deploy/registration/pending/

sudo systemctl start alt-deploy-process.service
```

Validate bootstrap and Python:

```bash
bash -n /srv/alt-deploy/bootstrap/bootstrap.sh
python3 -m py_compile /opt/alt-deploy-api/register_api.py
python3 -m py_compile /opt/alt-deploy-api/process_pending.py
```

Verify a target through the isolated SSH database:

```bash
/usr/local/bin/ssh-alt 192.168.101.56 \
  'sudo -n true && echo SSH_OK'
```
