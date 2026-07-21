# OR-3P1 Plan Amendment — Pending Registration Safety

This amendment is normative for `2026-07-21-alt-or3p1-pilot-installer-readiness.md`.

## Reason

Enabling `alt-deploy-process.path` while `/srv/alt-deploy/registration/pending` already contains a registration can start `process_pending.py`, which performs SSH and Ansible operations against a workstation. OR-3P1 requires installer verification itself to contact no target.

## Required Task 3 change

After active-job, Vault, permission, SSH-key, and static-asset checks—but before the first service stop or destination write—require an empty pending queue:

```bash
require_pending_empty() {
    local root_prefix=$1
    local pending_dir
    local pending_records

    pending_dir=$(install_destination \
        "${root_prefix}" \
        /srv/alt-deploy/registration/pending)

    shopt -s nullglob
    pending_records=("${pending_dir}"/*.json)
    shopt -u nullglob

    if (( ${#pending_records[@]} != 0 )); then
        echo "Pending workstation registrations block controller installation" >&2
        return 1
    fi
}
```

Call:

```bash
require_pending_empty "${root_prefix}"
```

before checking `alt-deploy-process.service` and before maintenance entry.

## Required tests

- The normal successful sandbox contains registration records only in `ready` and `failed`; `pending` is empty.
- A dedicated test seeds one pending JSON record, runs the installer library, and proves:
  - non-zero exit;
  - no service stop;
  - no destination mutation;
  - the pending record remains byte-identical;
  - no fake `ssh`, Ansible target command, or processor invocation occurs.
- The pre-mutation failure matrix includes `pending_registration_exists`.

This does not delete, move, retry, or reconcile pending registrations. The operator must resolve them explicitly before installation.
