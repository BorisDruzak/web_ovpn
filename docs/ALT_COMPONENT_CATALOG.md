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
