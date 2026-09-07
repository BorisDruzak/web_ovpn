# ALT Linux legacy playbooks inventory

This inventory records historical workstation-related automation while the
controller-managed software catalog is introduced. Historical files are not
deleted or enabled by this change.

## Pending software catalog records

The following legacy application playbooks remain pending checked catalog
records. They must not be used to infer package metadata or enable a component
until the intended controller's artifacts and RPM metadata have been reviewed:

- `ctipro_pro.yml`
- `spravki.yml`
- `ya.yml`

## Out of the new workstation path

These legacy automation paths are explicitly outside the new controller-managed
workstation configuration path:

- `setup_rdp.yml` — RDP setup
- `start_x11vnc.sh` — X11VNC startup
- `force_dns_nm.yml` — forced DNS configuration
- `net-work.yml` — network scripting
- legacy printer playbooks
- legacy monitoring playbooks

The out-of-path entries are retained for historical reference only. This
inventory does not authorize their execution or any network/DNS policy change.
