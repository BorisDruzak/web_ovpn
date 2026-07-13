# AGENTS.md

## Persistent user context

- The user works in the Codex Windows app, not Codex CLI.
- The in-app terminal is PowerShell unless the user says otherwise.
- Prefer configuring MCP servers through `C:\Users\admin-2\.codex\config.toml` or the app settings UI, not via `codex ...` commands, unless the CLI is explicitly installed.
- Primary use cases: browser automation and Python development.
- For browser automation, prefer the existing Playwright MCP setup when `Node.js`/`npx` is available.

## Project code copies

- Local code copy: `C:\Users\admin-2\Documents\ui_vpn` on this Windows machine.
- Deploy code copy: `openvpm@192.168.100.30`.
- Fast SSH access is configured with `ssh ui-vpn-deploy`.
- Alternate SSH alias: `ssh openvpn-100-30`.
- Make code changes in the local copy first, then deploy or sync them to `192.168.100.30` when requested.
- When reporting status, distinguish clearly between the local copy and the deployed copy.

## Canonical network context

- Treat [`BorisDruzak/network_configuration`](https://github.com/BorisDruzak/network_configuration) as the canonical Git context for the network architecture and declared network intent.
- Primary sources in that repository are `config/network-context.yaml` (canonical context) and `schemas/network-context.schema.json` (its validation contract). Do not duplicate network topology, CIDRs, devices, or credentials into this repository unless the user explicitly requests it.
- The current web-panel integration plan is [`docs/runbooks/step-03-web-ovpn-context-core.md`](https://github.com/BorisDruzak/network_configuration/blob/main/docs/runbooks/step-03-web-ovpn-context-core.md). It defines a small, read-only `web_ovpn`/`netctl` context core: validate an explicitly supplied YAML file, report status and summary, and record validated revisions locally.
- Follow that plan's safety boundary: the context-core work must not modify MikroTik, OpenVPN, DNS, DHCP, switches, firewall rules, or other production-network configuration. Device writes and UI pages are explicitly deferred in this step.

## Diagnostics workflow

- For OpenVPN, client access, Network Observer, MikroTik/RouterOS, IPsec site-to-site, RouterOS backups, and network collection diagnostics, use the local Codex `openvpn-control` plugin and MCP tools first.
- Prefer read-only MCP tools before any changes: `openvpn_diagnostic_snapshot`, `openvpn_status`, `openvpn_network_dashboard`, `openvpn_network_hosts`, `openvpn_network_ipsec`, `openvpn_routeros_backups`, and `openvpn_network_logs`.
- Use direct SSH, Winbox, manual `vpnctl`, or manual `netctl` only as a fallback when MCP/API output is unavailable, stale, contradictory, or the user explicitly asks for low-level server/router work.
- Do not store access passwords, API tokens, private keys, or other secrets in this repository or in `AGENTS.md`.

## Git publishing

- For this project, publish completed and verified work to `main` by default.
- Use short-lived feature branches only for implementation staging; after successful merge to `main`, remove the old feature branch locally and from GitHub.
