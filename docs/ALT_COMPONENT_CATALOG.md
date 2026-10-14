# ALT Component Catalog V1

The published `deploy/alt-linux/ansible/group_vars/software_catalog.yml` is the
declaration for Setup components and profiles. `software_catalog` retains the
approved artifact identities; `setup_catalog` references those identities and
defines component order, roles, requirements and verification recipes.

The entire document must pass `ComponentCatalog.load(project)` before any selection
is available. Validation rejects duplicate YAML keys/IDs, unknown fields, unsafe
tags/aliases, unapproved role paths, protected-role execution, missing or cyclic
dependencies, unsupported OS, invalid ordering and incomplete preflight/verification.
Inspection returns defensive copies; catalog SHA binds all published declarations.

## Components

Components declare `id`, integer `version`, `name`, `category`, `supported_os`,
`dependencies`, `execution`, `preflight` and `verification`. Execution contains
either a published role or the protected domain adapter, operation/scope,
domain/home/reboot requirements and retry policy. Supported verification recipes
are fixed controller code; catalog values never contain executable expressions.
Package verification may declare required `services`; CryptoPro declares
`pcscd.socket` here rather than in a separate Python selection/role table.

`domain.ready` represents the existing protected domain/GPO stage. It cannot become
an independently replayable component. Direct domain/account/recovery/provisioning
roles are forbidden as ordinary catalog executors.

## Profiles and compatibility

- `base` retains system/domain/Plasma/certificate baseline without software.
- `core-apps` retains the seven existing software components including the
  signature suite, then certificates and desktop shortcuts.
- `office-standard-v1` includes browser, ONLYOFFICE, Nextcloud and Directum.
- `office-signature-v1` includes the signature suite as well.
- KRFB remains an optional component requiring explicit restricted-access and
  existing domain-home admission. No profile selects it implicitly.

A profile declares `id`, positive integer `version`, `name`, dependency-ordered
required `components`, `optional_components` and `confirmation_policy: sha256`.
Confirmed plans retain the selected declaration, version and SHA. A changed
published profile needs a new version; it does not rewrite historical results.

## Adding an approved component

1. Add/review an Ansible role under the published `roles` directory, with bounded
   preflight, safe results and idempotent or explicitly guarded behavior.
2. Add approved artifact metadata when needed and a component declaration that
   references it through `preflight.artifact_key`. Select a supported verification
   recipe; a new recipe needs its own read-only implementation and tests.
3. Declare dependencies and OS compatibility, and choose a retry policy. Every
   domain-dependent operation must transitively require `domain.ready`.
4. Add the component to a new/versioned profile in dependency order when desired.
5. Run catalog and component tests, publish through Git, then use the ordinary
   guarded deployment. The operator cannot upload a runtime catalog or name an
   arbitrary role, script, playbook or parameter expression.

Catalog installation/execution and live acceptance are later delivery gates;
adding the declarations alone does not deploy or contact a workstation.

See [operator commands](ALT_SETUP_OPERATOR_GUIDE.md) and
[worker/backend/restore contracts](ALT_SETUP_ENGINE_V2.md). Functional acceptance
is explicitly attested against a fresh compliant plan; package presence never
produces `accepted` automatically.

## Independent detection

The fixed probe reads installed RPM names/EVR/epoch/architecture, executables,
required services, session configuration, domain trust/GPO, current and future
Plasma settings, certificate identities/stores, user-owned shortcuts and KRFB
configuration. It never executes a role's apply helper. Desired values come from
the published artifact records, role defaults/templates and literal declarations.

GPO detection uses read-only `gpupdate-setup status/active-backend/active-policy`
and current service result evidence; it does not run `gpupdate` or `gpoa`.
These inspection actions are documented in the
[ALT Domain administrator guide](https://docs.altlinux.org/ru-RU/alt-domain/11.1/html-single/alt-domain/index.html).

Missing or malformed observations remain unknown. A missing domain home remains
deferred; detection does not create it. Technical installation verification and
functional acceptance are separate fields: Directum document opening and token
signing still require actual operator/user evidence.

## Read-only operator commands

```sh
workstationctl --json setup components list
workstationctl --json setup components show software.onlyoffice
workstationctl --json setup profiles list
workstationctl --json setup profiles show office-standard-v1
workstationctl --json setup component plan --machine UUID --component software.onlyoffice
workstationctl --json setup component verify --machine UUID --component software.onlyoffice
```

Inspection uses only the published catalog. Component plan/verify requires a
registered machine and resolved existing Setup employee/domain assignment.
Plans use `setup-component-<SHA256>`, response schema 2, SHA confirmation and the
existing 30-minute TTL. They freeze profile/component declarations, AD and SSH
public identities, source SHA and relevant actual observations. Changed identities,
source/catalog or relevant evidence invalidate an older plan; observation time
alone does not. An active job is allowed only as the exact current plan's own
verified reservation or an explicitly reviewed permitted predecessor. Healthy
components plan noop without reading an installation payload or decrypting a
software license. `setup component apply PLAN_ID --confirm-sha256 SHA256` submits
the immutable plan to the durable worker and returns its job ID. Functional
attestation uses `setup component accept` only after a real completed user
workflow and fresh technical verification; it does not install software.
