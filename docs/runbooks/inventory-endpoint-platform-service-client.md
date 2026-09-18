# Inventory: Endpoint Platform service client

This runbook prepares an **optional, default-disabled** integration. Production
rollout is a separate administrative operation. Manual Inventory, Netctl and
saved Endpoint context remain usable without a live Endpoint connection.

```text
Endpoint Agent → WSS → Endpoint Platform → HTTPS published SDK → web_ovpn
```

Endpoint Platform owns devices, agent credentials and context collection.
`web_ovpn` owns physical Inventory assets, binding history and the local context
projection. All Endpoint calls use `EndpointPlatformServiceClient` through
`EndpointContextAdapter`; there is no direct HTTP fallback, Endpoint database
access, Agent runtime import or Agent ↔ web_ovpn WSS connection.

## 1. External administrative hand-off

An **Endpoint Platform administrator**, using that service's published
administrative workflow, must create a dedicated non-device service client
for this `web_ovpn` installation (suggested display name:
`web_ovpn-inventory`). Its grants must be exactly:

```text
devices.read
context.read
context.collect
```

`context.collect` is mandatory: the PC card's refresh action requests a new
safe agent snapshot. Do not substitute an administrator token, a human login,
a device credential, or grants such as `operations.*`, `modules.*` or
`provisioning.*`. Record the client ID, owning administrator, exact grants and
rotation/revocation procedure in the protected deployment record. Transfer the
service token via the approved secret channel, never Git, a command argument,
shell history, an issue or a log.

This repository does not contain a source-verified administrative issuance
command and does not create clients. Obtain that command/workflow from Endpoint
Platform administration; this documentation gap does **not** establish that
Endpoint Platform cannot issue the required credential. The consumed SDK also
has no grant-introspection method: the smoke proves the required operations
are authorized, while the absence of extra grants requires the administrator's
attestation. Do not describe a successful smoke as proof of least privilege.

The administrator/release owner must also supply:

- The real HTTPS service origin and its trusted public CA certificate/bundle
  (no CA private key), with a certificate valid for the configured hostname.
- A published immutable `endpoint-platform-client` wheel, its exact version,
  filename and independently supplied SHA-256 from the trusted release channel.
- An approved, non-retired smoke Device UUID accessible to this service client.
  The smoke **requests a real `baseline_v1` collection** on that device. Obtain
  approval for that collection before running it.

## 2. Pin the published SDK release

The committed `deploy/endpoint-platform-client.lock` intentionally contains
`null` release values because **no immutable published SDK release was supplied
for this change**. It is not an installable pin yet. Enablement must remain
blocked with `endpoint_platform_sdk_release_required` until the release owner
provides the wheel and prepares a reviewed lock containing:

| Key | Required value |
| --- | --- |
| `distribution` | `endpoint-platform-client` |
| `version` | Exact wheel distribution version |
| `wheel` | Exact `endpoint_platform_client-…whl` basename |
| `sha256` | Verified 64-character lowercase SHA-256 |

Include the wheel at `deploy/wheels/<locked wheel basename>` in the deployment
release artifact and the populated lock in reviewed release configuration.
Do not invent a version or use `pip install endpoint-platform-client`, a moving
branch, editable install, source checkout, sibling repository or index fallback.
Install the application's pinned `requirements.txt` first; the SDK installer
uses `--no-index --no-deps --force-reinstall`, so dependency compatibility must
be checked when preparing the released wheel.

After staging the release under `/opt/openvpn-web`, validate the wheel without
loading credentials or contacting Endpoint:

```bash
/opt/openvpn-web/.venv/bin/python /opt/openvpn-web/deploy/verify_endpoint_platform.py \
  --app-dir /opt/openvpn-web --artifact-only
```

Require exit `0` and `endpoint_platform_artifact_verified`. The verifier checks
the wheel SHA-256 and internal distribution metadata. Full smoke additionally
checks the installed version, SDK import and pip's local-wheel SHA-256
provenance (`direct_url.json`), rejecting source/editable installs. A digest
match verifies the supplied artifact, not the trustworthiness of its publisher;
obtain the digest through the trusted release hand-off.

## 3. Install protected configuration while disabled

The normal installer provides the service account, virtual environment,
`/usr/local/sbin/verify-endpoint-platform` and systemd units. Before replacing
an existing installation it stops both Endpoint units; it refuses to proceed
when their inactive state cannot be established. Back up the application
database using the existing deployment backup procedure before the additive
Inventory schema migration. Do not run production installation as part of
local verification.

Place the service token and public CA bundle at these absolute, non-symlink
paths. The token file contains the service token only, not `Bearer …`:

| File | Owner/group | Mode |
| --- | --- | --- |
| `/etc/openvpn-web/endpoint-platform.token` | `root:openvpn-web` | `0640` |
| `/etc/openvpn-web/endpoint-platform-ca.pem` | `root:openvpn-web` | `0644` or `0640` |
| `/etc/openvpn-web/openvpn-web.env` | `root:openvpn-web` | `0640` |

Parents must permit traversal by `openvpn-web`. The verifier rejects symlinks,
non-root-owned files, empty/unreadable files, group/world-writable CA, and a
token or environment file that is not exactly `0640` with the service group.
The CA must be a valid PEM trust bundle. Never disable certificate validation
or accept redirects to work around an incorrect origin/CA.

Add these settings to `/etc/openvpn-web/openvpn-web.env`; replace the example
origin with the administrator-supplied origin and the smoke UUID with the
approved device:

```dotenv
ENDPOINT_PLATFORM_ENABLED=0
ENDPOINT_PLATFORM_BASE_URL=https://endpoint.sosnadmin.local
ENDPOINT_PLATFORM_TOKEN_FILE=/etc/openvpn-web/endpoint-platform.token
ENDPOINT_PLATFORM_CA_FILE=/etc/openvpn-web/endpoint-platform-ca.pem
ENDPOINT_PLATFORM_TIMEOUT_SECONDS=5
ENDPOINT_PLATFORM_SMOKE_DEVICE_ID=<approved Device UUID>
```

The origin must be HTTPS with no user information, query, fragment or path
beyond `/`. Timeout is finite, greater than zero and no more than 120 seconds.
Keep one assignment per line and no duplicate Endpoint keys. The verifier
supports simple assignments with optional enclosing quotes, blank lines and
full-line `#`/`;` comments. Inline `#` is literal. Backslash escapes,
continuations, multiline quoted values and Unicode line separators are
rejected, including in unrelated settings. Do not `source` the environment
file to run the verifier: it loads this root-managed file itself and ignores
inherited `ENDPOINT_PLATFORM_*` values.

## 4. Smoke before enabling

Keep the timer stopped and the flag at `0`. As the actual service user, run:

```bash
sudo -u openvpn-web /opt/openvpn-web/.venv/bin/python \
  /usr/local/sbin/verify-endpoint-platform \
  --app-dir /opt/openvpn-web \
  --env-file /etc/openvpn-web/openvpn-web.env --install
```

`--install` installs only the verified local wheel. Omit it on subsequent
checks of the existing install. The verifier temporarily enables its own
in-memory settings for the smoke; it does not change the environment file or
enable the timer. Do **not** pass `--if-enabled` for this pre-enable check:
that option deliberately skips a disabled integration (exit `77`).

Full smoke must exit `0` with `endpoint_platform_verified`. It checks:

1. Immutable wheel, exact installed SDK version/import/provenance and protected
   environment/token/CA readability as `openvpn-web`.
2. CA trust construction and actual HTTPS SDK operations with the configured
   hostname/timeout.
3. `list_devices` authorization (`devices.read`) and presence of the approved,
   non-retired smoke device in the returned list.
4. Safe network identities and latest `baseline_v1`, `health_v1` and
   `network_v1` reads (`context.read`). A legitimately absent snapshot is allowed.
5. A real `baseline_v1` collection request (`context.collect`) with matching
   device/profile and an accepted queued/dispatched/running/completed response.

The collection idempotency key is stable for the approved device and release
digest. Repeated smoke uses that key, with deduplication governed by the
published Endpoint API. A queued response proves accepted collection, not a
fresh agent result; after enablement the worker must observe the completed
snapshot before the card can show newly collected data.

Any missing dependency/file, invalid TLS/configuration, denied scope or
unavailable API fails with exit `1` and a redacted code. Typical codes include
`endpoint_platform_sdk_release_required`, `endpoint_platform_sdk_artifact_invalid`,
`endpoint_platform_sdk_installed_invalid`, `endpoint_platform_file_permissions_invalid`,
`endpoint_platform_scope_denied` and `endpoint_platform_unavailable`. Keep the
feature disabled until corrected; never retry with broader credentials or a
different transport. Store only the redacted result and release metadata in
the acceptance record, not token contents or upstream exception bodies.

## 5. Enable, observe and roll back

Only after the external hand-off and successful smoke, set
`ENDPOINT_PLATFORM_ENABLED=1` in the protected environment file. The normal
installer validates the systemd units and reruns the service-user SDK smoke
before enabling `inventory-endpoint-sync.timer`. A failed gate stops/disables
the timer and resets the flag to `0`; manual Inventory remains available.

For an already installed and verified release, an administrator may perform
the same gated activation (with shell failure propagation):

```bash
sudo systemd-analyze verify /etc/systemd/system/inventory-endpoint-sync.service \
  /etc/systemd/system/inventory-endpoint-sync.timer &&
sudo -u openvpn-web /opt/openvpn-web/.venv/bin/python \
  /usr/local/sbin/verify-endpoint-platform \
  --app-dir /opt/openvpn-web --env-file /etc/openvpn-web/openvpn-web.env &&
sudo systemctl restart openvpn-web.service &&
sudo systemctl enable --now inventory-endpoint-sync.timer
```

If any command fails, keep the timer disabled, restore the flag to `0` and
restart `openvpn-web.service` to reload configuration before retrying. The
settings are cached in running web processes; editing the file alone does
not change the live web process. Before any manual upgrade or token/CA
rotation, disable the timer and stop `inventory-endpoint-sync.service`.
Repeat full smoke after rotation before re-enabling.

The timer performs presence checks about once a minute; full bounded context
reads run at most every five minutes. A lease prevents concurrent workers.
Only the worker automatically persists Endpoint state and observations.
Unchanged semantic hashes refresh freshness without duplicating observations.
Page renders and local context GETs read only the database. The explicit PC
refresh action queues collection through the SDK; the worker stores the result.

Record timer/service status and redacted journal evidence, then verify a PC
card in a browser. Confirm local provenance, last-success timestamps and
assigned person versus current OS user. These live deployment checks are
separate from the repository's automated tests and from a smoke API response.

To roll back the feature, set the flag to `0`, run:

```bash
sudo systemctl disable --now inventory-endpoint-sync.timer
sudo systemctl stop inventory-endpoint-sync.service
sudo systemctl restart openvpn-web.service
```

Preserve `inventory_external_bindings`, `inventory_endpoint_state`, observations
and the Network Observer compatibility cache. Do not drop tables or delete
assets. Manual/Netctl data and the last saved Endpoint values remain readable;
their freshness can become stale/unavailable. Re-enablement repeats the gate.

## Local behavior and consumer contract

- A unique current PC MAC ↔ one Endpoint identity may auto-confirm. Duplicate
  evidence remains a candidate. IP/hostname/username never auto-bind. Once
  confirmed, the Endpoint UUID is the stable reference. Explicit detach is
  preserved and the same discovery evidence does not silently reconnect it.
  The PC card's explicit **Восстановить привязку** action calls the authenticated,
  CSRF-protected `POST /api/v1/inventory/assets/{id}/endpoint-bindings/{binding_id}/reconnect`.
  It creates a new audited confirmed binding and retains the detached history.
  A consumed old reconnect action cannot be replayed; an active conflicting
  binding must first be resolved. The worker collects state for the new binding.
  Network cache reads hide links whose canonical binding ended or was replaced,
  and become stale after ten minutes without a successful worker refresh.
- RAM/serial discrepancies support `accept_endpoint`, `keep_manual` and
  `mark_verified`. Keep manual selects the manual value for that specific
  binding/value comparison; changed binding or compared values invalidate the
  decision. Assigned person, location and other manual authority fields are
  not overwritten by Endpoint.
- `GET /api/v1/inventory/assets/{id}/context` exposes local source values,
  effective values, freshness and discrepancies. Authenticated
  `GET /api/v1/inventory/by-endpoint/{uuid}` resolves only active confirmed
  bindings; candidate/ended/replaced relations do not resolve.
- Discrepancy POSTs require CSRF and an `expected_revision` copied from the
  discrepancy returned by the latest local context GET. For example, send
  `{"action":"keep_manual","expected_revision":"<returned revision>"}` to
  `/api/v1/inventory/assets/{id}/discrepancies/ram_gb/resolve`. A changed
  binding/value comparison returns HTTP `409`: reload the context and let the
  operator decide again. Never auto-resubmit an old choice with a new revision.
- A denied scope fails the operation closed (`503` plus
  `endpoint_platform_scope_denied` for explicit refresh); the worker records
  a redacted failure and preserves confirmed bindings and last good state.
  An outage is `endpoint_platform_unavailable`; disabling is
  `endpoint_platform_disabled`. None authorizes fallback HTTP or token upgrades.
- Network Observer receives a derived local cache. Only bounded presence,
  OS family and device type are forwarded to Netctl, never serial, current OS
  username, tokens, raw context or diagnostics. Unavailable/stale technical
  profiles are not promoted to fresh fingerprint evidence.

## Release blockers and separate Endpoint Platform work

Current enablement blocker: the repository has no supplied immutable SDK
release wheel/version/digest, and thus its lock is deliberately unpopulated.
Required separate release action: publish a versioned `endpoint-platform-client`
wheel supporting the existing consumed methods and provide trusted SHA-256
metadata; then populate/review the web_ovpn deployment lock and run live smoke.
This implementation does not claim a production token, CA or live API has
been verified.

The consumed safe projections also do not provide physical serial, product
UUID or current OS user today. The service/UI can represent these fields, but
the worker cannot manufacture them. Serial/product UUID matching therefore
requires a separately published safe SDK/API identity contract before it can
be activated. A missing optional profile/field is shown as missing/unavailable;
it is not a reason to read an Endpoint database or raw diagnostic payload.

If administration confirms the service cannot issue exactly the three required
scopes, or a required SDK/API operation is absent, leave integration disabled
and file a separate `endpoint_platform` task using this record:

```text
Blocked capability: <credential grant set / published SDK method / safe field>
Observed service/SDK version: <verified versions>
Evidence: <redacted public-contract error or administrator confirmation>
Required change: <exact least-privilege issuance or versioned SDK/API contract>
Required scopes: devices.read, context.read, context.collect (no extras)
Acceptance: immutable release + administrator grant attestation + web_ovpn smoke
Boundary: HTTPS published SDK only; no Endpoint DB, device token or Agent WSS
```

Do not claim a credential capability blocker solely because its administrative
command is not documented here. If machine-verifiable proof of no extra scopes
is needed, request a published credential-introspection contract in that
separate task; it is not supplied by the currently consumed SDK.
