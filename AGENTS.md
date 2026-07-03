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
