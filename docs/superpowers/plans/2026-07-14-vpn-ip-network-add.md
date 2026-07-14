# Effective VPN IP and Network Add Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Display the effective OpenVPN address for connected dynamic clients and allow network additions with no comment.

**Architecture:** The web layer renders the management-reported virtual address first and uses the configured CCD address only as an offline fallback. Network-add handlers omit an optional CLI flag rather than changing the shared argument-cleaning client.

**Tech Stack:** Python 3.14, FastAPI, Jinja2, pytest.

## Global Constraints

- Live OpenVPN virtual_address is session truth; never persist dynamically issued addresses as desired client configuration.
- Do not change OpenVPN configuration, CCD files, routes, network devices, APIs outside network add, or deploy the local checkout.
- Preserve configured/push vpn_ip as the fallback for disconnected clients.
- Omit --comment only when its value is empty; retain non-empty comments exactly.
- Use test-first development and run the full pytest suite before committing each task.

---

## File Structure

- Modify: app/main.py:339-344 — derive a presentation-only effective VPN IP for the client detail.
- Modify: app/templates/clients.html:54 — render live virtual_address before stored IP.
- Modify: app/templates/client_detail.html:42-54 — show labelled effective VPN IP.
- Modify: tests/test_routes_smoke.py — add connected-dynamic-client page assertions.
- Modify: app/main.py:814-833 — conditionally append the comment option for HTML form submissions.
- Modify: app/api.py:518-535 — conditionally append the comment option for API submissions.
- Modify: tests/test_routes_smoke.py and tests/test_api_routes.py — verify argv for an empty comment.

### Task 1: Render the effective connected VPN address

**Files:**
- Modify: app/main.py:339-344
- Modify: app/templates/clients.html:54
- Modify: app/templates/client_detail.html:42-54
- Modify: tests/test_routes_smoke.py

**Interfaces:**
- Consumes detail.connected.virtual_address, detail.ccd.vpn_ip, and detail.registry.vpn_ip from existing vpnctl JSON.
- Produces context key effective_vpn_ip and client-list output that prefers row.virtual_address.

- [ ] **Step 1: Write failing rendered-page tests**

Make the fake list command return a client with vpn_ip null, connected true, and virtual_address 192.168.50.77. Assert GET /clients contains 192.168.50.77. Make the fake inspect command return connected.virtual_address 192.168.50.77 and no CCD push address. Assert GET /clients/alpha contains the labelled effective VPN IP and 192.168.50.77.

- [ ] **Step 2: Run the focused test to verify RED**

Run: python -m pytest tests/test_routes_smoke.py -k effective_vpn_ip -q

Expected: FAIL because the clients template currently reads only row.vpn_ip and the detail route has no effective_vpn_ip value.

- [ ] **Step 3: Implement the presentation-only fallback order**

In clients.html change the VPN IP cell to:

~~~
{{ row.virtual_address or row.vpn_ip or row.registry_vpn_ip or '-' }}
~~~

In client_detail(), derive:

~~~
connected = data.get("connected") if isinstance(data.get("connected"), dict) else {}
ccd = data.get("ccd") if isinstance(data.get("ccd"), dict) else {}
registry = data.get("registry") if isinstance(data.get("registry"), dict) else {}
effective_vpn_ip = connected.get("virtual_address") or ccd.get("vpn_ip") or registry.get("vpn_ip") or ""
~~~

Pass effective_vpn_ip to the template. Add a row named Effective VPN IP in the registry/certificate details panel. Do not update the registry or CCD.

- [ ] **Step 4: Verify GREEN and commit**

Run: python -m pytest tests/test_routes_smoke.py -k effective_vpn_ip -q

Expected: PASS.

~~~
git add app/main.py app/templates/clients.html app/templates/client_detail.html tests/test_routes_smoke.py
git commit -m "fix: show effective VPN address for clients"
~~~

### Task 2: Omit an empty network comment argument

**Files:**
- Modify: app/main.py:814-833
- Modify: app/api.py:518-535
- Modify: tests/test_routes_smoke.py
- Modify: tests/test_api_routes.py

**Interfaces:**
- Consumes the existing cidr, tag, comment, nat, and restart_nat fields.
- Produces vpnctl argv where --comment and its value occur only for a non-empty comment.

- [ ] **Step 1: Write failing HTML and API regression tests**

Submit POST /networks/add with cidr 192.168.100.12, tag default, comment empty, nat disabled, and a valid CSRF token. Read FAKE_VPNCTL_LOG and assert the networks add argv includes 192.168.100.12/32 and excludes --comment.

Call POST /api/v1/networks/add with JSON:

~~~
{"cidr": "192.168.100.12", "tag": "default", "comment": "", "nat": false, "restart_nat": false}
~~~

Assert HTTP 200, normalized CIDR in argv, and no --comment. Add one assertion for a non-empty comment proving --comment and its exact value are retained.

- [ ] **Step 2: Run the focused tests to verify RED**

Run: python -m pytest tests/test_routes_smoke.py -k network_add_empty_comment -q

Run: python -m pytest tests/test_api_routes.py -k network_add_empty_comment -q

Expected: FAIL because each handler builds --comment followed by an empty string, which run_vpnctl removes.

- [ ] **Step 3: Implement conditional flag construction in both handlers**

Replace the unconditional append in each handler with:

~~~
args = ["networks", "add", cidr, "--tag", tag]
if comment:
    args.extend(["--comment", comment])
~~~

Append the existing NAT and restart options after this block. Do not modify app/vpnctl_client.py.

- [ ] **Step 4: Verify GREEN, regression suite, and commit**

Run: python -m pytest tests/test_routes_smoke.py -k "effective_vpn_ip or network_add_empty_comment" -q

Run: python -m pytest tests/test_api_routes.py -k network_add_empty_comment -q

Run: python -m pytest -q

Expected: all tests pass.

~~~
git add app/main.py app/api.py tests/test_routes_smoke.py tests/test_api_routes.py
git commit -m "fix: allow network add without comment"
~~~

