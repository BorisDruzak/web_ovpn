# Standalone inventory-printer acceptance, 2026-10-24

## Outcome and boundary

The standalone inventory planner/exporter and Ansible printer role were exercised
on the dedicated ALT test VM 133 (`alt-t2-pc133`). One real network Kyocera ECOSYS
M2030dn was queried through netctl SNMP and installed as one new owned queue.
General workstation Setup, the web workflow and fleet automation remain unchanged.
Physical paper output was not requested or tested; no print job was submitted.

Only the **M2030dn** driver is enabled in the approved manifest. Native strict
validation rejected the supplied M2040dn/M2540dn/M4125idn/M5526cdw PPDs. Their
hashes/reasons are recorded separately; no conformance check was disabled.

## Native evidence

| Check | Result |
| --- | --- |
| VM identity | UUID and MAC independently read through the trusted hypervisor guest agent; matched by target preflight. |
| SSH trust | Guest public host key verified, pinned in a separate test known-host file; shared controller trust store unchanged. |
| Recovery point | Pre-test VM snapshot created; no reboot, rollback, domain operation or historical UNKNOWN job replay. |
| Inventory | Actual production projection read through existing SQLAlchemy models using a SQLite `mode=ro` URI, without initialization/migration. |
| Test fixture | Temporary VM PC with its real UUID/MAC plus the copied selected printer/location; production cards/relationships unchanged. |
| SNMP | Exact M2030dn model, stored serial and current MAC corroborated through netctl; credentials never transferred to the VM. |
| Printer transport | Selected printer's TCP 9100 reachable directly from the VM; connection opened/closed with zero application bytes sent. |
| Syntax | `ansible-playbook ... playbooks/07-inventory-printers.yml --syntax-check`: exit 0. |
| Check mode | Predicted one queue change; no queue created by the check. |
| First successful apply | `ok=8 changed=1 unreachable=0 failed=0`; one owned queue added. |
| Repeat apply | `ok=8 changed=0 unreachable=0 failed=0`; no duplicate or repair. |
| Drift repair | Disabled only the owned, idle test queue; playbook re-enabled it with `changed=1`, no pending job. |
| Wrong UUID | A deliberately mismatched test request was rejected with `printer_target_identity_mismatch`, before changes. |
| Foreign queue gate | With receipt absence injected into the read adapter, the actual existing CUPS queue was rejected as `printer_queue_not_owned`. Actual receipt/queue files were preserved. |
| Driver conformance | Installed M2030dn PPD: `cupstestppd -q`, exit 0. |
| Conversion chain | `cupsfilter --list-filters ...` returned `universal`, exit 0. Actual PDF-to-printer conversion exited 0 and produced 170075 bytes containing PostScript after the PJL header. Output was captured, not sent to a printer. |
| Preservation | All 48 queue URIs and installed PPD hashes in the saved pre-apply baseline remained unchanged; exactly one queue added. Default destination and CUPS enablement unchanged. |
| Job state | No pending jobs before/after; code and acceptance commands contain no print submission. |

The fixture deliberately includes one copied printer in its location. The full
production location is **not ready**: another Kyocera card there lacks a confirmed
connection type. The planner reports that exclusion and refuses automatic export
of the incomplete location plan. This test does not establish readiness of that
real location, other printers or the fleet.

## Failures found and corrected

1. Ansible's native templating converted a raw JSON string to Python dictionary
   representation at command stdin. A real-Ansible RED test reproduced it; the
   role now passes a structured document through `to_json`. The same Linux test
   subsequently passed, including against the final M2030dn catalog.
2. Supplied M2040dn PPD failed strict `cupstestppd` with Resolution/UIConstraints
   errors. Global and EU English variants failed. Other proposed models were
   checked and rejected as appropriate. M2030dn passed and was used for the test,
   within the user's authorization to select any listed printer.
3. CUPS rejected TCP administrative authentication (`Unauthorized`). No queue or
   ownership receipt existed after the failed attempts. The helper now pins the
   local Unix socket and uses local peer authentication, without credentials or
   CUPS policy changes. A regression test pins that transport choice.
4. Independent review found that check mode would fail when CUPS was unavailable.
   The corrected helper reports prerequisite changes with deferred inspection;
   the role does not start a stopped/missing scheduler during a dry run. A RED to
   GREEN runtime regression covers this case. Existing scheduler enablement is
   deliberately preserved rather than forced on.
5. Post-mutation/receipt failures now remain `unknown`, with no false claim that
   nothing changed; the corresponding runtime regression passes.

## Automated verification

```text
python -m pytest tests/test_inventory_printer_plan.py tests/test_inventory_printer_runtime.py tests/test_inventory_printer_ansible_transport.py tests/test_netctl_printer_snmp.py tests/test_inventory_models.py tests/test_inventory_service.py tests/test_inventory_netctl_sync.py -q --tb=short
92 passed, 1 skipped (23.83s)
```

The Windows skip is the Linux-only real-Ansible transport test. That exact test
was also executed separately on the ALT controller with ansible-core 2.18.6:
`python3 -m pytest tests/test_inventory_printer_ansible_transport.py -q --tb=short`
returned **1 passed**. Pytest emitted the existing asyncio fixture-scope warning.

Scoped `python -m ruff check` and `git diff --check` were run. Independent code
review found one material dry-run issue described above; the reviewer found no
additional material identity, export or queue-ownership defects. GitNexus query,
context and impact confirmed reuse of the existing bounded netctl printer CLI;
no existing API/controller contract was modified. Source and tests additionally
verified the dynamic Python boundaries. Context7 quota was exhausted; official
Ansible/CUPS documentation and the actual 2.18.6/2.4.20 runtimes were used.

## Driver research

The [official Kyocera M2040dn download page](https://www.kyoceradocumentsolutions.us/en/support/downloads.name-L3VzL2VuL21mcC9FQ09TWVNNMjA0MERO.html)
provided Linux package 10.1. Downloaded archive SHA256:
`14235a8e4dbe9f2fdff481252e2cc64431f59a7dcf2497ef54852fb30211568f`.
Its exact M2040dn PPD requires `kyofilter_X` and `kyofilter_pre_X`; the vendor
installer/RPM was not executed. ALT compatibility and physical printing are
unverified, so that driver was not enabled.

The provided Pantum ALT RPM already contains the exact BM5100FDW PS PPD and its
required `ptps` filter. RPM SHA256:
`23f5309ad7743ae39381e0d1bd87892306dc328aaad2270601731fe1a48a0ff7`.
The official Pantum 1.1.186 download attempt returned HTML instead of a ZIP.
Pantum is researched but not installed/enabled in this increment.

Private request/bundle/provenance, raw inventory projection, complete native logs
and baseline hashes remain outside Git in the isolated acceptance workspace.
Source, tests, driver metadata and this sanitized report are the published result.
