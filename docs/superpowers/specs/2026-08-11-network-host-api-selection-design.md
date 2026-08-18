# Network Host API Selection Design

## Goal

Ensure the host-detail API returns the requested host after it merges Network Observer data with active OpenVPN clients.

## Scope

`GET /api/v1/network/hosts/{ip}` currently sorts all merged rows and returns the first one. A connected VPN address that sorts before the requested address can therefore replace the requested host in the response.

The endpoint will select the merged row whose `ip` equals the requested path parameter. If no such merged row exists, it will keep the existing normalized Network Observer fallback.

## Data flow and errors

The endpoint still obtains the requested source host through `netctl hosts inspect`, then augments it with VPN state. Only the final selection changes; no collector, topology, fingerprint, or SNMP data is changed.

## Verification

A regression test will request `192.168.101.76` while the OpenVPN connection list contains `192.168.50.10`. It must return `192.168.101.76` and its Network Observer identity, never the lower-sorting VPN row.
