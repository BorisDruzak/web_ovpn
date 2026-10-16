# Workstations deployment and operation

The separate `/workstations` section shares the existing panel authentication,
inventory, network observations and controller. It adds no Endpoint API contract.
Operators can read concurrently. Setup retains the native global one-PC queue;
reconciliation has a separate singleton and runs every five minutes when ready.
Employee creation is a disabled UI control and has no API/MCP implementation.

After the operator confirms a fresh Setup plan, the controller worker performs
technical queue admission automatically, including candidate-specific closed
UNKNOWN checks where applicable. No per-job SSH confirmation is needed. The
original UNKNOWN jobs, claims and identity reservations remain intact and are
never replayed. FIFO and one-time claims remain mandatory. Incomplete, busy,
conflicting or expired evidence leaves the new job unclaimed; its web card shows
`setup_queue_admission_unverified`. Inspect the controller evidence and retain
the original request/job ID rather than submitting another apply.

The Setup machine selector reads all pages of one coherent device generation,
independently of the paginated device table. Only ready registered machines are
offered. Loading more table rows preserves the selected PC. Incomplete, changed,
duplicate or oversized evidence leaves the selector empty and requests a refresh.

## Protected integration account

Use `deploy/alt-linux/provision-directory-observer.ps1` from a protected Windows
administrator session. It uses signed/sealed ADSI LDAP and does not require an
AD Web Services endpoint. Inputs are protected files; neither password appears
in argv, stdout or tracked configuration. Administrator and observer inputs are
DPAPI-protected `PSCredential` CLIXML files created in the same Windows security
context. Only the current owner, SYSTEM and Administrators may access them.
Do not run a transcript around secret preparation or expose the files in chat.

Its protected JSON configuration requires these keys: `server`,
`domain_base`, `account_path`, `account_name`, `upn`, `read_bases`, `dns_bases`.
The only optional key is the boolean `allow_inherited_machine_join`, false by
default. Use true only for an explicitly approved exception described below;
the exact choice is bound into the protected configuration hash/receipt.
Supply actual approved containers and discovered DNS partitions/zones outside
Git. The observer credential username must equal `upn`. The script creates
exactly one managed integration identity, initially disabled, persists its SID
before further steps, and refuses a name/SID/UPN/marker/scope collision. It never
creates employees, edits DNS records, grants administrative membership, removes
another principal's ACE, changes ACL inheritance, or changes domain quota/policy.

Example using paths to already protected inputs:

```powershell
.\provision-directory-observer.ps1 -ConfigPath $approvedConfig `
  -AdminCredentialPath $protectedAdministrator -ObserverCredentialPath $protectedObserver `
  -ReceiptPath $protectedReceipt
.\provision-directory-observer.ps1 -ConfigPath $approvedConfig `
  -AdminCredentialPath $protectedAdministrator -ObserverCredentialPath $protectedObserver `
  -ReceiptPath $protectedReceipt -ExpectedSid $receiptSid -Check
```

The script checks transitive membership, primary group and SID history. It adds
read grants on approved scopes and principal-specific write denies. Where an
explicit object allow overrides an inherited deny, it adds only this principal's
deny on that conflicting object inside the approved scope. The protected receipt
records intended changed objects and original DACL SDDL **before** each write.
All unrelated ACEs remain intact. Failure leaves the managed account disabled
and retains the receipt for review. Recheck is idempotent for the same identity
and exact approved scope; check mode performs no writes.

Required evidence includes actual paged reads and effective attributes/child
classes/security-descriptor rights, plus applicable explicit/inherited deny
proof for control/validated-write/delete rights. It also inspects domain machine
quota: when nonzero, a read-only remote LSA policy query under the current
administrator session must prove the observer's effective principals lack
`SeMachineAccountPrivilege`. LDAP administrator credentials alone do not provide
that LSA session. Unknown/assigned privilege blocks strict readiness; do not claim ACL
child checks alone remove the separate machine-quota privilege. This script does
not change global policy to get past that gate. Never attempt real record/user
changes as a write-permission test.

On 2026-10-15 the operator explicitly accepted the existing Authenticated Users
machine-join privilege as a narrow exception for this integration identity.
`allow_inherited_machine_join=true` accepts only that effective assignee after a
successful LSA read; direct/other-group grants and unknown evidence still fail.
The protected receipt records quota and actual effective assignees. Output
reports `effective_readonly=false`, `directory_dns_readonly=true` and
`inherited_machine_join_exception=true` when this exception is used. Directory
and DNS write restrictions still have to pass. Domain policy/quota are unchanged;
web/MCP never expose the inherited join privilege through the observer.

Microsoft documents [effective modifiable attributes](https://learn.microsoft.com/en-us/windows/win32/adschema/a-allowedattributeseffective),
[security-descriptor write rights](https://learn.microsoft.com/en-us/windows/win32/adschema/a-sdrightseffective),
and the [separate computer-account creation permission paths](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/active-directory-domain-join-permissions).
Static syntax and synthetic policy tests do not prove live directory rights.

Transfer the generated observer secret through the existing protected Vault
workflow into `vault_ad_readonly_user` and `vault_ad_readonly_password`; preserve
join credentials unchanged. Install a root-managed observer JSON based on
`directory-observer.json.sample` at `/etc/alt-deploy/directory-observer.json`.
Use only `readonly-vault` with GSSAPI sealing or certificate-verified TLS. No
anonymous/join fallback exists. Keep the SID/bootstrap receipt private.

DNS names support Windows UTF-8 labels with byte limits. Dot-terminated owners
are absolute and must remain in their approved zone. A malformed record is
excluded from device matching and retained as a separate finding with its zone,
owner and opaque record ID; no DNS data is changed. A complete DNS generation
means every approved zone/page was enumerated, and does not certify the health
of every record. LDAP/page, zone-identity and collection-budget failures still
make the source unavailable and preserve its previous complete generation.
See Microsoft's [Unicode DNS behavior](https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-architecture)
and [absolute/relative node names](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/d0251c9b-9e3e-4eec-bcc5-eb6b995b6108).

## Controller rollout

Use the exact published source and existing native maintenance/backup commands.
Stage controller source below a root-managed directory such as `/opt`; every
ancestor of the source maintenance module must be root-owned and not group/world
writable. `/tmp` is unsuitable for this source-validator path, even when the
release directory itself is protected. Check the exact staged source CLI under
the confirmed maintenance review before starting the installer's full tests.
Create, verify and rehearse a fresh controller backup. Where retained UNKNOWN
history requires maintenance review, obtain a current exact review SHA/TTL and
pass it through the existing protected maintenance contract. Do not erase
UNKNOWN, consume new join claims, revive old requests or repeat Setup to deploy
the controller. Run `install-control-plane.sh --rollback-backup-id ...` with its
required current maintenance argument. The launcher/modules are installed
inside the existing backed-up `/opt/alt-deploy-control` runtime root.

Enroll two panel public keys using `install-workstations-gateway.sh` and a
protected root-owned enrollment JSON. It validates sshd syntax/effective settings
and preserves existing administrator/password/key access. The keys have distinct
read/execute forced commands, one allowed source IP and no forwarding. Verify
that arbitrary commands and write operations on the read key are denied.
Keep the pinned controller host key verified through an existing trusted channel.

## Panel rollout and credentials

Merge `deploy/workstations.env.sample` into the existing protected environment;
it defaults to disabled. Create `/etc/openvpn-web/workstations` as root with
group `openvpn-web`, mode 0750. Private read/execute SSH keys and the API hash
registry are `openvpn-web` owned, mode 0600, inside that root-managed directory.
The existing unrelated systemd credential directory is preserved. Known hosts
must be regular, trusted, and not group/world writable. Do not grant a generic
shell/sudo capability through these keys.

Provision a distinct scoped API token with the deployment helper, as root:

```sh
python deploy/workstations_deployment.py --provision-credential \
  --registry "$protected_registry" --token-output "$protected_token_output" \
  --receipt "$protected_owned_receipt" --actor workstation-reader \
  --grants workstations:read
```

No secret is printed. A protected receipt records actor, grants, hash and owned
paths. The helper preserves other actors, refuses token/name/grant collisions
and serializes registry updates. Repeating the exact enrollment with its
matching token is idempotent. An interrupted enrollment that leaves an orphan
token requires administrator review; it does not silently mint a replacement.
Use separate actors/tokens for explicitly authorized additional grants. Existing
legacy API token defaults gain no permissions. Transfer the chosen token to an
owner-only local MCP file without logging it; see [MCP guide](workstations-mcp.md).

Deploy through the existing `deploy/install-openvpn-web.sh`. Invoke it as
root through the established protected sudo workflow: its host path checks need
access to the protected application and existing virtualenv. Preserve an existing
virtualenv symlink; do not widen application access for the SSH login or recreate
the shared environment to get past a caller-permission failure. It first stops the
workstation timer and running reconciliation service, even if unit files were
removed. It installs the additive units and runs the readiness helper as the
actual panel service user. Only the six workstation tables are initialized;
schema mismatches fail closed. Activation requires a configured sequential
gateway and successful complete AD and DNS reads through the separate observer.
Unconfigured installations remain usable with the timer disabled. A failed
upgrade leaves the timer stopped. No installer silently enables the feature.

The reconciliation service has a five-minute limit, private temporary directory,
private umask and writable state only under `/var/lib/openvpn-web`. A source
failure retains the last complete snapshot and separately reports the attempt.
Snapshot age, inventory revision and relationship revision are checked again
before publication/use; a DNS/IP match never overwrites an employee or owner.

## Acceptance and rollback

Check exact installed hashes against the published controller and panel source,
unit ownership/state, pinned transport, restricted read/write denial, targeted
schema and complete generations for controller/AD/DNS/Netctl. Read source errors
separately from last success. In a separate browser tab verify employee homonyms,
explicit selection, a read-only protected plan preview, retained job stages,
events beyond one page, safe errors, disabled creation, and inventory/network
links. Do not join or reboot a real PC to demonstrate the UI. Verify actual MCP
server tool discovery independently from a running chat's loaded inventory.

On rollback stop/disable reconciliation first, restore the previous protected
panel environment and verified source/database backup, and use native controller
rollback with its guards. Revoke only recorded feature-owned keys/tokens and
drop-ins; preserve existing administrator access. The AD administrator may
disable the integration account and review the recorded SID-specific ACEs.
Never replace a whole DACL from the saved SDDL over newer unrelated changes;
compare first and remove/restore only the recorded change. Keep original receipts,
binding history, completed jobs, genuine AD/DNS objects and manual inventory
records. No rollback path clears UNKNOWN or repeats a domain join.

### Protected AD objects during observer rechecks

AD periodically restores protected accounts/groups from AdminSDHolder. Do not
reapply per-object denies repeatedly or modify that template for this observer.
The Windows bootstrap can prove those restored objects read-only from their
complete protected/canonical DACL, owner, object identity and server effective
rights. Any applicable property/security/reset grant still blocks readiness.
The standard Everyone Change Password ACE requires the target's current password
and is distinct from administrative reset; the observer's own object is excluded
from this alternate proof. Missing facts fail closed. See
[Microsoft protected accounts](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
and [MS-ADTS unicodePwd](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/6e803168-f140-4d23-b2d3-c3a8ab5917d2).
