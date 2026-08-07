# Yandex Browser for ALT workstations — design

## Goal

Install the approved Yandex Browser RPM on a selected ALT Workstation through
the existing controller-managed Ansible configure playbook. Browser policy
continues to be delivered only through the AD GPO `ALT - Yandex Browser -
Pilot`.

## Approved artifact

- Operator-provided file: `Yandex.rpm`.
- SHA-256: `7fbce78e9799ae36ebfcf750d5880f27d829d5546e9ac77f1868afb9657d9a89`.
- The RPM is copied once to
  `/opt/alt-deploy-control/artifacts/yandex-browser/Yandex.rpm` on the
  controller, owned by `root:root` and not stored in Git.
- The import procedure records the package NEVRA from `rpm -qip`; the role
  verifies the installed package using that declared package name.

## Ansible structure

`03-configure-domain-workstation.yml` remains the only workstation configure
entry point. The existing `standard_software` role becomes an explicit,
allow-listed component dispatcher and invokes `software_browser` only when the
approved `browser` component is selected.

`software_browser` has one responsibility:

1. Assert the controller-side RPM exists, is a regular file, and its SHA-256
   equals the catalog value.
2. Copy the RPM to a private temporary path on the workstation.
3. Install that local RPM through ALT's package manager.
4. Query the declared package name and assert the expected installed version.
5. Delete the temporary RPM and expose only a non-secret verification fact.

The role is idempotent: a host that already has the catalog's package version
does not reinstall it. A different installed version is upgraded or downgraded
only when the local approved RPM is selected by the request.

## Data and safety boundaries

- The software catalog is a controller-owned Ansible variable. Its browser
  entry contains the absolute artifact path, SHA-256, RPM package name, and
  expected version; it contains no credentials.
- No role downloads a browser or accepts an artifact path, URL, checksum, or
  package name from a request.
- The RPM never enters Git, request JSON, public configure results, or logs.
- The role creates no browser managed-policy JSON, preferences, extension
  configuration, or user profiles. GPO is the only browser-policy channel.
- Failure codes distinguish a missing artifact, a checksum mismatch, an RPM
  installation failure, and post-install verification failure.

## Request and verification

The existing base profile keeps its present behaviour. A new fixed
`browser` component selection is allow-listed by `standard_software`; arbitrary
role names are not accepted. `domain_verify` includes `browser: true` only
after `software_browser` verifies the requested package. It does not include
the RPM path, package payload, hash, or any browser policy value.

## Tests

Static Ansible asset tests must prove that:

- `software_browser` exists and is reachable only through the fixed
  `browser` dispatcher entry;
- the catalog has a fixed controller path and SHA-256;
- checksum assertion occurs before installation;
- the temporary RPM is removed after installation;
- no browser policy path or JSON policy content occurs in Ansible roles;
- `domain_verify` publishes only a boolean browser verification result.

Controller deployment additionally runs the repository's ALT test suite and
the controller readiness syntax checks. Functional acceptance on a pilot
workstation verifies the browser package, `browser://policy`, and domain GPO
delivery separately.

## Out of scope

- Browser homepage, proxy, SSO, extension, update, or security policy values.
- Any modification to `Default Domain Policy`.
- Downloading packages from the Internet during workstation provisioning.
- Installation of CryptoPro, Spravki BK, printers, or unrelated software.
