# MikroTik-to-VPN path visibility verification — 2026-07-21

## Scope

This verification covers the read-only path-visibility feature only. Its local
configuration is `/etc/openvpn-web/network-paths.json`; repository material is
limited to the role-only `deploy/network-paths.json.sample` and contains no
production addresses, credentials, or keys.

## Installer boundary

`deploy/install-openvpn-web.sh` installs the sample only when the operational
configuration path is absent. It preserves any existing file or dangling
symlink, so local, approved topology is never replaced during installation.

## Operator boundary

The installer and verification do not enable `netctl-collect.timer`, invoke
`netctl collect`, change a RouterOS device, or alter OpenVPN. Enabling the
timer, collecting RouterOS data, and any RouterOS change are separate,
explicitly approved operator actions governed by their respective maintenance
and network-change procedures.

## Local checks

Run from the repository root:

```powershell
python -m pytest tests/test_deploy_network_paths.py -v
python -m pytest -q
```

These tests inspect only repository files and do not contact the OpenVPN host
or any network device.
