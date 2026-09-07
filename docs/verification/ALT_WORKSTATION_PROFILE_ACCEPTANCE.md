# ALT workstation profile acceptance (non-secret template)

> **Scope/status:** This is a local/static procedure and evidence template. No
> deployed controller canary has been executed or proven by this document.
> Runtime acceptance requires Task 6 after a separately authorized deployment
> and successful controller readiness.

This template records acceptance evidence for an already installed workstation.
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

- Result: `accepted` / `rejected` / `blocked by gate`
- Safe evidence references: `____________________________`
- Reviewer: `____________________________`
- Notes (non-secret only): `____________________________`
