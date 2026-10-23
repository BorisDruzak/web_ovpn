# Standalone inventory-selected Kyocera printers

This first increment is an explicit CLI plan/export plus an independent Ansible
playbook. It is not enabled in general workstation Setup, the web UI, a timer or
fleet policy. It never submits a print job or changes the default printer.

## Validated driver scope

The approved catalog currently enables **ECOSYS M2030dn only**. Its English KPDL
PPD from the operator's directory passes strict `cupstestppd` on CUPS 2.4.20.
`driver_catalog.json` pins its exact filename and SHA256; PPD bytes stay outside
Git. Read `roles/inventory_printers/files/rejected_drivers.json` for source hashes
rejected during native validation. The supplied M2040dn/M2540dn/M4125idn/M5526cdw
PPDs fail strict conformance and are not automatically installed. Do not bypass
this gate with relaxed validation or edit a vendor PPD to suppress its errors.

The official Kyocera Linux 10.1 package was inspected, not installed. Its PPDs
require `kyofilter_X` and `kyofilter_pre_X`; deploying that package and proving its
ALT dependencies is separate work. A model name alone does not prove a driver.

## Prepare and review one plan

Run from a source/deployed copy containing the new CLI, under an account that can
read the panel inventory and call the existing bounded `netctl` printer operation.
Do not run `init_db` or a migration to generate a printer plan. For SQLite, use a
read-only database URI (adapt the path to the configured inventory database):

```sh
export DATABASE_URL='sqlite:///file:/path/to/openvpn-web.sqlite?mode=ro&uri=true'
umask 077
python -m app.inventory.printer_cli plan \
  --pc-asset-id EXISTING_PC_ASSET_UUID \
  --target-uuid INDEPENDENTLY_VERIFIED_MACHINE_UUID \
  --output /private/printer-plan.json
```

The selected card must be an active, non-deleted PC with an existing location and
at least one current unicast MAC unique among active inventory cards. Confirm the
target UUID independently before supplying it. The target must later match both
UUID and an inventory MAC; hostname/IP/employee text are not identity bindings.

The planner uses exact location IDs and explicitly network/IN_USE Kyocera cards.
It deduplicates repeated identical IP identifiers, detects ownership conflicts
across all active assets, and reuses SNMP model/serial/MAC inspection through
netctl. SNMP credentials stay on the existing netctl host. It does not scan a
subnet. At most 16 candidates are probed, with a 30-second bound per candidate.

Review `ready`, `printers`, and `excluded`. An empty or incomplete/conflicting plan
is non-ready and the CLI exits 2; do not ignore the excluded reasons. A physical
printer in another location is not automatically included. Unknown status/type,
ambiguous IP, mismatched identity and unapproved drivers require inventory or
driver review, not a guessed queue. No card is changed by these operations.

## Export exact local driver bytes

Within the 10-minute lifetime, export using the same current inventory and netctl
access. The destination must not exist. Export re-reads inventory, re-probes SNMP,
compares the selection/source fingerprint, and verifies every driver hash/header
and exact model before writing private files.

```sh
python -m app.inventory.printer_cli export \
  --plan /private/printer-plan.json \
  --driver-source /private/approved-drivers/English \
  --destination /private/printer-bundle
```

Transfer the private bundle to the Ansible controller, keeping the PPD and JSON
files out of Git. Set `inventory_printer_driver_dir` in its `vars.json` to the
controller's absolute bundle `drivers` path. If the plan expires, generate and
review a new plan; do not change its timestamp/hash by hand. The plain SHA256 is
an integrity/drift binding, not a signature or substitute for trusted operators
and protected files.

## Execute only the standalone role

Use a one-host Ansible inventory with its trusted SSH key pinned to the verified
target. Never disable host-key checking or replace the shared known-host store to
make a test connect. Use the existing Ansible account and privilege escalation.

```sh
cd deploy/alt-linux/ansible
ansible-playbook -i /private/one-target.ini \
  -e @/private/printer-bundle/vars.json \
  playbooks/07-inventory-printers.yml --syntax-check
ansible-playbook -i /private/one-target.ini \
  -e @/private/printer-bundle/vars.json \
  playbooks/07-inventory-printers.yml --check
ansible-playbook -i /private/one-target.ini \
  -e @/private/printer-bundle/vars.json \
  playbooks/07-inventory-printers.yml
```

The playbook validates input and target first, ensures distribution CUPS packages
and a running scheduler, then validates all PPDs before queue mutation. It preserves
existing scheduler enablement, global CUPS settings, other queues and the default.
Check mode never starts a stopped scheduler; if CUPS is unavailable, it predicts
prerequisite changes and explicitly reports deferred queue inspection.

Queue names are stable `inv_kyocera_` plus the full printer asset UUID without
hyphens. Queues are local, non-shared and use the selected printer's socket URI.
Administrative calls use `/run/cups/cups.sock`, with local peer authentication;
no CUPS password or server policy change is needed. Ownership receipts live in
root-owned `/var/lib/inventory-printers/queues`. Unowned name collisions block
execution. Existing incomplete jobs block drift repair. A repeat of an unchanged
plan must produce `changed=0`.

If a mutation or its receipt cannot be verified, the helper reports `unknown`.
Inspect actual queue/PPD/receipt state before further action; never manufacture an
ownership receipt or automatically take over an existing queue. Queue removal,
location-change pruning and concurrent invocations are not provided in this first
increment; run only one invocation per target at a time.

## Acceptance

Verify queue URI, enabled/accepting state, non-sharing, model and installed driver;
check the filter chain without submitting a job. Compare foreign queues/PPDs and
the default with the saved baseline. Run the playbook a second time and require
zero changes. Technical queue/conversion validation does not establish physical
paper output.

For an isolated VM experiment, keep its inventory fixture separate from production
inventory, use the VM's actual UUID/MAC, and retain the copied printer/location
provenance privately. A fixture with one printer does not establish that the full
production location is ready. Preserve snapshots and historical UNKNOWN Setup
records; this playbook does not operate on those jobs.

## Pantum research

The operator-provided `pantum-1.1.99-alt3.x86_64.rpm` has SHA256
`23f5309ad7743ae39381e0d1bd87892306dc328aaad2270601731fe1a48a0ff7`.
It already contains `Pantum BM5100FDW Series PS.ppd` and the `ptps` filter required
by that PPD. Extracting/copying the PPD alone is insufficient.

The [official BM5100 download page](https://global.pantum.com/search/download-driver/?p=2&s=BM5100)
lists Linux driver 1.1.186 for BM5100FDW. The attempted archive request returned an
HTML browser challenge, not a verified ZIP; no archive hash/installation claim is
made. Pantum installation, runtime dependencies and physical printing remain
outside this Kyocera increment.
