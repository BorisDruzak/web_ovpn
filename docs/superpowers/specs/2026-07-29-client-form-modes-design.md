# Client Form Modes Design

## Goal

Make the profile-creation page show only controls relevant to the selected workflow, without changing the existing server-side creation contracts.

## Selected approach

Keep one `/clients/new` form and use a small browser-side controller to show, hide, enable, and disable field groups when the operator changes mode or client type. This avoids new routes and prevents hidden values from being submitted.

## Modes

### One ordinary user

- Show: client name; access mode; template selector or custom CIDRs; DNS for custom CIDRs; comment.
- Hide and disable: CSV/name list; router type and router-only fields.

### One router

- Show: client name; client type; router profile; optional VPN IP; Remote LAN CIDR; server-route checkbox; comment.
- Hide and disable: CSV/name list; template/custom access controls; DNS.
- The existing backend router branch remains authoritative for router validation and generation.

### Batch of ordinary users

- Show: pasted name list; CSV; shared access mode; template selector or custom CIDRs; DNS for custom CIDRs; comment.
- Hide and disable: single client name; client type; all router-only fields.
- The controller forces the client type to `user` before submission.

## Access mode

- `template` displays and enables the profile selector.
- `custom` displays and enables custom CIDRs and DNS, while disabling the profile selector.
- This preserves the backend rule that exactly one route source is supplied.

## Implementation

- Mark form blocks with stable `data-*` selectors.
- Add a compact inline script in `client_new.html` that recalculates visibility and disabled state on `DOMContentLoaded`, creation-mode changes, client-type changes, and access-mode changes.
- Keep server-side defaults and validation unchanged so direct requests remain safe.

## Testing

- Add a template smoke assertion for the mode-controller selectors and initialization script.
- Use a browser check to confirm all three workflows display only their relevant controls and hidden controls are disabled.

## Non-goals

- No changes to OpenVPN generation, networking, CIDR catalog management, router validation, or download behavior.
