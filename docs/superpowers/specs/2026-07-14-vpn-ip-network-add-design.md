# Effective VPN IP and Network Add Design

## Purpose

Make the web panel display the effective VPN address of a connected client and
allow a network to be added without supplying an optional comment.

## Effective VPN IP

The OpenVPN management/status data is the source of truth while a client is
connected. The client list and client detail will therefore prefer its live
`virtual_address`. When no active session exists, they will fall back to the
configured CCD/registry `vpn_ip`; this preserves visibility of an address
explicitly assigned with `ifconfig-push` for offline clients.

No dynamically issued address is written back to the registry: it is a
session-specific observation, not desired configuration. The existing
connections view already uses the same live-first ordering and remains the
reference behaviour.

## Empty network comments

The web and API network-add handlers will include `--comment VALUE` only when
the trimmed comment is non-empty. This prevents the command wrapper from
removing an empty value while leaving a dangling `--comment` option. The
shared argument-cleaning behaviour stays unchanged, avoiding unintended
effects on commands that use optional positional arguments.

## Tests

Add a rendered-page regression where a connected client has no configured
`vpn_ip` but has a live `virtual_address`; the clients page must display that
live address. Add web and API network-add regressions that submit
`192.168.100.12` without a comment and assert the downstream argv contains no
`--comment` option. Existing non-empty-comment behaviour remains covered.

## Safety and scope

The change is local web/CLI argument handling only. It does not change OpenVPN
server configuration, CCD files, client routes, network devices, or the
deployed copy until a separate deployment request.
