# Mobile Inventory v1 Design

## Purpose and scope

Add a standalone physical-equipment inventory domain to the existing OpenVPN Web Manager. The primary interface is a mobile-first page at `/inventory`, used while walking through rooms. The v1 scope includes locations, assets, workstation relationships, manual and network-derived data, photos, inventory checks, audit records, and an authenticated API under `/api/v1/inventory/`.

The implementation must not change the semantics of existing OpenVPN, Network Observer, `netctl.assets`, `network_hosts`, or runtime-asset data. It must not call Endpoint Platform, Endpoint Agent, `endpoint_agent_network`, `endpoint_context_adapter`, or `endpoint_platform_client`.

## Architecture

The inventory is an isolated application domain within the existing FastAPI/Jinja2 application:

- `app/inventory/models.py` owns inventory ORM models.
- `app/inventory/service.py` owns hierarchy rules, draft-to-persisted workstation creation, identifier normalization, and transactional detach semantics.
- `app/inventory/lookup.py` uses the existing `netctl` CLI/API boundary through the web application's client adapter. It does not read a `netctl` database directly.
- `app/inventory/storage.py` stores and serves photos safely.
- `app/inventory/api.py` provides `/api/v1/inventory/...` endpoints.
- `app/inventory/web.py` and inventory templates provide authenticated HTML flows, including `/inventory`.

Existing authentication, CSRF checks, audit logging, SQLAlchemy session handling, and migration conventions are reused rather than replaced. Network access remains bounded by the existing `netctl` and nmap safety boundaries.

## Data model

All new tables use the `inventory_` prefix. User-entered fields are nullable; only technical IDs, asset type, and timestamps are mandatory.

### Locations and assets

- `inventory_locations`: UUID ID, free-text `name`, nullable `comment`, timestamps.
- `inventory_assets`: UUID ID, `asset_type` (`PC`, `MONITOR`, `PRINTER`, `PHONE`, `UPS`, `OTHER`), direct `location_id`, common descriptive fields, status, person/login fields, notes, and verification timestamp.
- `inventory_asset_identifiers`: asset reference, `ip|mac|hostname|extension|other`, original and normalized values, source, first/last-seen timestamps, and current flag.

Each asset retains its own `location_id`, including related devices. Location is never inferred only from a parent asset.

### Details and relationships

- `inventory_pc_details`, `inventory_printer_details`, `inventory_phone_details`, `inventory_monitor_details`, and `inventory_ups_details` hold type-specific nullable properties.
- `inventory_asset_relations` holds `WORKPLACE_DEVICE` relationships, creation metadata, optional end timestamp, and note.

An active relationship is valid only when its parent is `PC` and its child is one of `MONITOR`, `PRINTER`, `PHONE`, `UPS`, or `OTHER`. A PC cannot be a child, leaf assets cannot have children, and cycles are rejected. Ending a relationship does not delete either asset; the former child remains at its direct location.

### History, checks, and photos

- `inventory_observations` records timestamped normalized `netctl`, `nmap`, or manual snapshots separately from canonical asset fields.
- `inventory_sessions` and `inventory_checks` establish the future-ready survey lifecycle.
- `inventory_asset_photos` and `inventory_location_photos` store only metadata and server-controlled storage paths; image bytes stay outside SQL.

## Lookup and nmap safety

The lookup accepts one IP, MAC, or hostname input. MAC values are normalized across colon, dash, and compact formats. The service first searches current `netctl` data through the approved CLI/API path. A MAC miss may request one throttled fresh collection and retry. It must not launch nmap if the MAC still has no resolved IP.

An IP miss may invoke the existing nmap fingerprint runner only with a single canonical unicast IPv4 address. CIDRs, ranges, extra arguments, scripts, and shell commands are rejected. Returned evidence is represented as a snapshot and shown as a suggestion, never as authoritative inventory data. Lookup failure, unavailable `netctl`, and nmap timeout leave manual workflow usable and retain form state.

## API and security

The `/api/v1/inventory/` namespace exposes locations, assets, workplace projections, relation create/attach/detach, lookup, sessions, and photo operations. The API supports creating a new child asset plus relation and attaching an existing asset without duplication.

All writes use existing authenticated mutation protections and audit records. Required audit actions include location and asset create/update/delete, relation create/end, lookup source, photo add/delete, and session start/finish. API and HTML lookup paths preserve the current CSRF policy for browser mutations.

Photo uploads enforce server-generated filenames, extension-independent MIME validation, configured size limits, traversal-safe storage paths, authorized reads, and cleanup of files if a database transaction fails.

## Mobile UX

`/inventory` presents a one-column, touch-friendly location screen with a persisted current location, a location comment editor, a de-duplicated equipment tree, and clear actions to add a device, change location, and finish a walk.

Every asset type can be added at the location's top level. Only a PC card offers related-device actions. A user can draft a PC, add one or more child devices, attach photos, accept or edit lookup suggestions, and save the workstation in one operation. The save flow persists the PC, children, relations, photos, and observations consistently or rolls back with file cleanup.

The tree displays active children only beneath their PC. A detached asset returns to the top level at the same location. Forms include a `Save and next` action to retain the active location while starting another capture.

## Verification strategy

Tests are written before production changes for:

- nullable-field creation for locations, PC, and leaf assets;
- allowed and rejected relationship combinations, cycle prevention, and detach preservation;
- identifier normalization and netctl/nmap lookup policy;
- no Endpoint Platform use in inventory lookup;
- API authentication, CSRF, audit, and projection behavior;
- file upload MIME/size/path handling and rollback cleanup;
- mobile HTML flow for creating a location, PC, related Monitor and UPS, standalone Printer, and detaching a Monitor.

Targeted unit and integration tests run during each implementation stage. The final verification runs relevant existing application, `netctl`, and frontend/browser checks. Production deployment is excluded unless separately requested.

## Known v1 limits

No Endpoint, AD, UCM, SNMP printer automation, QR/barcode, EDID, universal CMDB graph, subnet scanning, network-infrastructure inventory, RAG, or AI assistant is added. Asset moves have a data model but no full v1 move UI.
