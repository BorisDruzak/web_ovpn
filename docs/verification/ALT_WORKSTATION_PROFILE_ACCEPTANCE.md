# ALT workstation profile acceptance (non-secret template)

> **Scope/status:** This is a local/static procedure and evidence template. No
> deployed controller canary has been executed or proven by this document.
> Runtime acceptance requires Task 6 after a separately authorized deployment
> and successful controller readiness.

This template records acceptance evidence for an already installed workstation.
For findings from one authorized workstation run, see the
[2026-10-10 installation report](ALT_WORKSTATION_INSTALLATION_REPORT_2026-10-10.md).
This blank template does not itself record that run or accept another station.
It is a checklist, not authorization to select a machine, deploy a controller,
run a playbook, invoke `netctl`, modify bootstrap, change network policy, or
change Vault. Use placeholders and boolean results only. Never paste passwords,
Vault values, private logs, artifact contents, or private keys.

## Common run record

- Date/time (UTC): `____________________________`
- Operator / change reference: `____________________________`
- Profile under test: `base` / `core-apps` / `krfb`
- Run ID: `____________________________`
- Hostname (non-secret identifier): `____________________________`
- Preview status: `pass` / `fail`
- Start status: `successful` / `degraded` / `failed`
- `error` is `null` or safe error code: `____________________________`

The fixed route is `workstationctl --json configure preview` followed, only
after review of a successful preview, by the matching `configure start`. Record
status and safe identifiers; do not attach the request file or private logs.

## Base profile checklist

- [ ] `software_profile=base`, `remote_access_profile=none` and no assigned
      domain user were reviewed in the non-secret request.
- [ ] Preview identified the fixed
      `03-configure-domain-workstation.yml` plan and the designated run.
- [ ] Start used the fixed controller route after preview review.
- [ ] DNS and KDC resolution succeeded using the workstation's configured
      DNS servers.
- [ ] Samba trust check (`net ads testjoin`) succeeded.
- [ ] SSSD lookup/authentication check for the existing domain test user
      succeeded.
- [ ] Group Policy update and verification succeeded.
- [ ] `reboot_required` recorded as `true` / `false`: `__________`.
- [ ] If `reboot_required=true`, exactly one approved reboot was completed and
      domain login plus home-directory creation were observed.
- [ ] No machine-selection, firewall/VPN, DNS-policy, Vault, or direct-playbook
      change was made as part of acceptance.

## Core-apps profile checklist

Complete the base checklist first, with `software_profile=core-apps` and the
required existing domain user. Core-apps is fail-closed: every selected
component's controller-side approved artifact preflight must pass before any
component role runs.

- [ ] All selected approved artifact preflights passed before target mutation;
      no URL, path, checksum, or package override was supplied in the request.
- [ ] `verification.software_browser` boolean: `true` / `false` / `not selected`.
- [ ] Browser executable check: `pass` / `fail` / `not selected`.
- [ ] `verification.software_onlyoffice` boolean: `true` / `false` / `not selected`.
- [ ] OnlyOffice executable check: `pass` / `fail` / `not selected`.
- [ ] `verification.software_nextcloud_desktop` boolean: `true` / `false` /
      `not selected`.
- [ ] Nextcloud executable check: `pass` / `fail` / `not selected`.
- [ ] `verification.software_directum` boolean: `true` / `false` / `not selected`.
- [ ] Directum installed version, launcher and packaged autostart checks:
      `pass` / `fail` / `not selected`.
- [ ] After an ordinary graphical login, Directum starts and opening a document
      from the organization's Directum system works: `pass` / `fail` / `not tested`.
- [ ] Only component booleans and executable-check results were retained;
      no artifact bytes or private installer output were retained.

## KRFB profile checklist

Complete the base checklist first, with `remote_access_profile=krfb` and one
explicit, already existing assigned domain user. KRFB must remain opt-in and
must not be started by the controller.

- [ ] Both controller Vault-presence checks passed, without recording values:
      `vault_krfb_desktop_password_obscured` and
      `vault_krfb_unattended_password_obscured`.
- [ ] Assigned domain user: `____________________________` (existing user;
      record the name only, never credentials).
- [ ] Exact controller confirmation setting was present:
      `ALT_DEPLOY_KRFB_TCP_5900_RESTRICTED_CONFIRMED=true`.
- [ ] Separate evidence reference proves the pre-existing VPN/firewall policy
      restricts TCP port 5900: `____________________________`.
- [ ] The port-5900 evidence was reviewed independently of the controller
      setting; no firewall/VPN rule was opened or changed.
- [ ] Assigned user's `krfbrc` exists, is owned by that user, and has mode
      `0600`.
- [ ] Assigned user's Plasma autostart file exists, is owned by that user, and
      has mode `0644`.
- [ ] No controller-started KRFB process was observed or requested.
- [ ] No KRFB password, obscured value, Vault content, or private log was
      copied into this record.

## Acceptance decision

### Desktop, certificates and first-login evidence

- [ ] Plasma power settings verified for both skel and the assigned existing
      profile; active-session display timeout/DPMS result recorded separately.
- [ ] Approved double-click, mouse and window-edge settings verified.
- [ ] OnlyOffice associations verified with effective `xdg-mime` results;
      application availability checked separately (the `base` profile does not
      install OnlyOffice).
- [ ] Government CA payload/expiry and exact certificate identities verified.
- [ ] System root placement, RSA NSS imports and, when installed, CryptoPro
      machine/user imports verified without changing unrelated trust.
- [ ] First-login imports for a newly created domain profile checked:
      `pass` / `fail` / `not tested`.
- [ ] Strict GOST TLS and the required browser site checked:
      `pass` / `fail` / `not tested` (record no cookies or personal data).
- [ ] If the separately installed signature suite is required, actual token
      signing verified: `pass` / `fail` / `not tested`.
- [ ] For KRFB, autostart verified after an ordinary logout/login; a process
      started for the current session is not counted as this evidence.
- [ ] KRFB port access from an approved source and denial from other sources
      verified independently of the controller confirmation flag.
- [ ] Repeat-run scope and recap recorded; separate role repeats are not
      described as a complete end-to-end repeat.
- [ ] Last live workstation verification time recorded; later SSH failure
      does not count as a successful service-state recheck.

### Recorded decision

- Result: `accepted` / `rejected` / `blocked by gate`
- Safe evidence references: `____________________________`
- Reviewer: `____________________________`
- Notes (non-secret only): `____________________________`
