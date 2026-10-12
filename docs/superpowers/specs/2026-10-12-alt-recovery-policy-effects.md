# Original-policy effect inventory

Preparation scope continues the approved limited recovery. No service/AD/DNS
operation or final execution approval is introduced by this collector.

The original ten-field baseline has passed read-only parser acceptance on the
selected disposable workstation. A terminal approval still needs configured
presence, operative renewal/DNS settings and protected runtime dependencies.
The new worker must reuse the fixed isolated SSSD configuration generation,
observe all section/key names without returning secret values, and return only
a fixed allowlist of non-secret option values and paths. It must bind the fresh
baseline request/receipt, original config metadata, parser and helper hashes,
and end all callbacks with protected rereads. Scratch is private and temporary.
It must preserve every authentication file, existing record and service state.

The inventory is evidence for review, never an effects approval. Unknown keys,
configured credential/TLS overrides and unresolved helper semantics require
explicit review before the terminal attachment can be issued. Configured
presence and missing values remain distinct. No private key contents are
returned. Runtime/default/renewal attribution and execution claims remain false.

The fixed operative set covers identity/domain/server selection and keytab
overrides; machine password age, renewal scheduling, Samba synchronization and
LDAPS; DNS enablement, refresh/offset, PTR, per-family, interface, TTL, TCP,
authentication, fallback server and TLS paths. The initial worker does not claim
resolved values or review arbitrary paths.

Runtime dependencies additionally pin the installed SSSD backend/AD provider,
adcli and nsupdate by protected metadata and exact package. A package label or
command exit code alone is not provenance or proof of absent directory writes.

## Source-review facts to bind in a future closed manifest

Official SSSD 2.9.8-alt3 packaging commit:
`735f9bd77dc114daa4508e20af2f4178cd18387e`; effective source:
`31669d9c2d25aa3382bba68c1889ee3252de9cd7`.
The installed manual's two-field renewal default is incomplete: the option table
uses `86400:750:300`, including a random offset. DNS task initialization uses
delay 10 and default offset 300; online/offline paths preclude treating these
numbers as a guaranteed window without writes. Zero DNS refresh disables
periodic scheduling, not every DNS update path.

Official adcli 0.9.2-alt1 packaging commit:
`334494f9cab4a72825e6643ba5b65729b45bc2a8`; effective source:
`27afd5222c73df51044c16145c3bcb426b05cf2e`.
Its ordinary update can conditionally reconcile DNS hostname, encryption types
and SPNs even if password age prevents renewal. Expired/invalid timestamp may
also change password/keytab; optional Samba synchronization changes local
domain SID/secrets. Some attribute failures may be ignored. Ordinary discovery
does not inherit the separate recovery provider's GUID-only addressing.

A future closed manifest must bind config inventory/projection/source/package
hashes, configured presence and source-supported resolution, helper selection,
all conditional effects and limitations. Terminal pre/postchecks must include
SPNs, UAC, encryption types and DNS hostname in addition to GUID/SID/OU/KVNO.
No normal-policy service start is authorized by this document.

The installed DNS helper's official BIND 9.18.49-alt1 source is packaging commit
`05573d8b67fd4311caea548be188ccb0ce85a370`. Its nsupdate option parser does not
support SSSD's DNS-over-TLS flags. A configured DoT requirement must therefore
refuse terminal approval; it must never silently fall back to plaintext.
SSSD may replace forward A/AAAA and reverse PTR RRsets, with multiple transactions
and partial success. Forward/PTR authentication are separate; `none` requests
unsigned updates. Server selection uses SOA discovery and SSSD fallback, not
the recovery provider's pinned directory peer. Interface/address selection,
transport and RRset replacement must be explicit conditional effects. Pin
`sdap_dyndns.c`, helper option/discovery/GSS/update paths and exact runtime build
evidence before declaring these semantics reviewed for the selected package.

## Implementation and verification

1. RED/GREEN worker tests: missing or forged baseline, unknown/duplicate fields,
   malformed inventory, changed config/helpers/packages/modules, callback drift,
   fixed commands, private scratch removal and unchanged genuine fixture files.
2. Implement a package-free fixed worker, preserving all existing baseline and
   suppression interfaces. No arbitrary command/path/action overrides.
3. Independent review, focused tests and full ALT regression. Keep runtime/CLI
   transport and complete manifest authority as explicit integration work.
4. Compose through fixed transport and obtain fresh read-only installed parser
   evidence before binding final terminal authority. Synthetic collection alone
   does not satisfy the operational gate.
