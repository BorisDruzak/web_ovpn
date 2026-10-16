# Workstations web clean-VM acceptance — 2026-10-16

The separate clean test VM is operational. Current deep verification reports
all nine office-standard-v1 components compliant; the separately installed
CryptoPro CSP component is compliant and its provided permanent Client license
is verified. The pre-bootstrap snapshot and original VM are preserved.

## Actual installation and graphical session

The stopped pre-setup image was cloned to a separate VM with unique virtual,
network, OS and SSH identities before joining the network. The published
bootstrap checksum matched and bootstrap executed once. An existing enabled
test employee, approved test OU, office-standard-v1 and remote access none were
selected explicitly in the real web wizard. No employee creation/reset, domain
policy modification or global network change occurred.

Full web Setup ran once, published all 518 task events, and reached waiting_reboot.
A real reboot changed boot ID. Explicit web continuation reached
waiting_first_login; genuine LightDM/Plasma X11 authentication created the
domain-owned home. ONLYOFFICE opened and rendered a blank document in that session.

The initial shortcut check rejected permissions narrowed by PAM. A concurrent
independent APT simulation and web continuation overlapped; continuation recorded
UNKNOWN. The exact failing health subcheck was not retained, so overlap is a
plausible cause, not proven RCA. The immutable UNKNOWN was retained. The native
permitted component-predecessor path bound a corrective desktop.shortcuts plan
to the intact completed full legacy run; it succeeded with 84/84 events. Full
Setup and domain join were never replayed. This corrective step used the native
controller because the web gateway does not expose after-job review.

CryptoPro was planned and applied once through the real web interface. Its job
succeeded with 92/92 contiguous task events. All nine approved RPMs match
5.0.13600-7 and their architectures. The installed serial matches the provided
serial; license inspection reports permanent, Client. Acquiring a provider
context as the actual domain UID/GID returned ErrorCode 0x00000000. PCSC socket
activation is active; no key container was requested. The serial was absent from
all 99 retained files of the CryptoPro job.

A second genuine domain login populated all six approved certificates in CSP
user stores. The three root confirmation fingerprints matched the published
manifest. Because CSP was added after the office profile, its new machine stores
were populated by a separate approved government-certificate repair through the
web wizard. That job succeeded with 84/84 contiguous events; all six certificates
were verified in both machine and user stores. Final deep baseline and CSP
verification passed.

## Corrections published to main

| Commit | Message | Included files |
| --- | --- | --- |
| e9760b3529d758d6b9c264f1a100b00eb9b2b8a3 | fix(alt-setup): admit isolated stock ALT package caches | `deploy/alt-linux/control/alt_deploy/component_probe_script.py`, `docs/ALT_SETUP_ENGINE_V2.md`, `tests/alt_linux/test_setup_package_interruption.py` |
| 67051025befe58c430f0ec15faf3c06e8ea48221 | fix(workstations): load ready PCs beyond table pagination | `app/static/workstations.js`, `docs/runbooks/workstations.md`, `tests/browser/workstations_fixture_server.py`, `tests/browser/workstations_journey.js`, `tests/workstations.test.js` |
| d0654f56d540e58dfd6224b58cffe93db1c83be0 | fix(alt-setup): accept restrictive first-login shortcut modes | `deploy/alt-linux/control/alt_deploy/component_probe_script.py`, `docs/ALT_SETUP_ENGINE_V2.md`, `tests/alt_linux/test_component_probe_script.py` |
| ad407c43573a012db8bf2dd71b9f980b8464e8d8 | fix(alt-setup): disable the browser RPM update repository | `deploy/alt-linux/ansible/roles/software_browser/files/disable_vendor_repository.py`, `deploy/alt-linux/ansible/roles/software_browser/tasks/main.yml`, `docs/ALT_SETUP_ENGINE_V2.md`, `tests/test_alt_browser_repository_policy.py` |
| d0dfee40afd3f61589437424584dba798f25b30e | fix(workstations): refresh cached wizard assets | `app/templates/workstations_base.html` |

The cache correction accepts stock root:rpm 2770 only when the isolated probe
cannot traverse it and absence of an access ACL is proven; ordinary cache files
remain protected. The selector reads a complete coherent generation independently
of table pagination. Shortcut verification accepts stricter masked permissions
while retaining owner access, ownership, bytes and safe ancestry checks. The
browser role disables only the exact known vendor source created by the approved
RPM, preserving the strict ALT p11 source policy.
The template also versions the changed script URL so an existing browser session
loads the corrected selector instead of retaining its cached predecessor.

## Verification and installed release

- Linux collector/verification/package-interruption regression: 69 passed.
- Linux browser repository policy and existing Ansible asset checks: 82 passed.
- `node --test tests/workstations.test.js`: 16 passed. Both edited JavaScript
  files passed `node --check`; `git diff --check` passed before every commit.
- `python -m pytest -q tests/test_workstations_web.py`: 6 passed after the asset
  URL version change; the unchanged browser session then loaded the new helper.
- Real Playwright synthetic desktop/mobile journey passed with 201 devices:
  ready PC available before table pagination, selection retained across More,
  one apply/one verify, 205 paged events, 200 journal rows, no console/HTTP errors.
- Independent reviews are clean. A root setuid-fixture issue identified in review
  was corrected before publication.
- Exact runtime CI 38863644901: 6052 passed, 90 skipped, 3478 warnings in 1432.68s.
  ISO contract 38863644872 passed. Superseded intermediate runs were cancelled;
  no success is claimed for them.
- Fresh backup create/verify/rehearse passed before deployment. The latest
  reviewed history retained 1998 records and the original two legacy reservations.
- Unchanged guarded installer completed successfully; mandatory native suite:
  3282 passed, 2 skipped in 1087.77s. Fresh controller readiness passed.
- The 217 installed controller/Ansible files match
  ad407c43573a012db8bf2dd71b9f980b8464e8d8. The 1392 panel source files match
  d0dfee40afd3f61589437424584dba798f25b30e, including the template asset URL
  correction; controller runtime files are identical across those two commits.
  Exact final-source CI 38869780723: 6052 passed, 90 skipped in 1394.99s.
  Panel overlays preserved
  ownership and modes; no panel restart was required.
- On the deployed wizard, a ready PC is offered on the initial 100-row table
  page, and loading more rows retains the explicit selection.
- Real CSP job view fits 390px after the menu closes. Its journal export returned
  HTTP 200, native_complete=true and no native errors. Browser console: zero
  errors/warnings during the checked flow.
- The updated scoped MCP status and job-event tools also succeeded and returned
  the same 92 contiguous CryptoPro events as the web interface.

GitNexus located the committed collector/catalog baseline. Source and tests
verified the dynamic subprocess and Ansible boundaries. HTTP/SDK contracts did
not change. Main publication, controller deployment and target acceptance were
checked separately. A later documentation-only commit does not alter this
CI-verified runtime revision.

## Scope of acceptance

The original UNKNOWN remains historical evidence linked to a successful native
corrective successor; its request/result/status and consumed claims were not
rewritten. The test VM is left running with its original pre-install snapshot.

Technical installation, permanent-license and provider-context proof do not
attest signing with a particular certificate/token, Directum business login or
Nextcloud account setup. Those workflows were not falsely marked accepted.
Private raw evidence and screenshots remain outside Git. This report contains
no credentials, serial, private host addresses or employee identifiers.
