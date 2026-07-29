# Client Batch Creation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Create one or many identical OpenVPN user profiles from the web UI, with exactly one route mode and one protected ZIP download.

**Architecture:** Add generate-batch to vpnctl as the lock-protected creation engine. It preflights all names before writes, generates an empty custom base profile, then applies a template or custom catalogue networks. The web layer parses names and CSV, registers CIDRs, calls this command for one or many names, and creates a one-time ZIP download token.

**Tech Stack:** Python 3 standard library (csv, ipaddress, zipfile), FastAPI, Jinja2, SQLAlchemy, pytest, vpnctl.

## Global Constraints

- Bulk creation accepts only dynamic-address user clients.
- A request accepts exactly one route mode: template or custom CIDRs.
- Custom CIDRs are normalized, de-duplicated, catalogued under custom-route, and never restart NAT.
- Empty, invalid, duplicate, or existing names fail before the first profile write.
- A ZIP exists only under an allowed download root and is released through the existing expiring token.
- No router, DNS, DHCP, firewall, or OpenVPN-server configuration changes.

---

### Task 1: Add the validated vpnctl batch command

**Files:**

- Modify: deploy/vpnctl
- Create: tests/test_vpnctl_batch_generation.py

**Interfaces:**

- Command: vpnctl --json generate-batch --client NAME [--client NAME ...] (--template NAME | --cidr CIDR [--cidr CIDR ...]) [--dns] [--comment TEXT] [--dry-run].
- Result: status, clients, requested_count, generated_count, access_mode, template, networks, dns.
- Helper: preflight_batch_clients(clients: Iterable[str]) -> list[str].

- [ ] **Step 1: Write failing five-client and preflight tests.**

~~~python
def test_batch_generates_five_unique_user_profiles(tmp_path):
    result = run_vpnctl(
        tmp_path, "generate-batch",
        "--client", "user_1", "--client", "user_2", "--client", "user_3",
        "--client", "user_4", "--client", "user_5", "--template", "directum",
    )
    assert result["requested_count"] == result["generated_count"] == 5
    assert [row["client"] for row in result["clients"]] == [
        "user_1", "user_2", "user_3", "user_4", "user_5",
    ]


def test_batch_rejects_existing_or_duplicate_names_before_any_write(tmp_path):
    seed_client_files(tmp_path, "taken")
    failed = run_vpnctl(
        tmp_path, "generate-batch", "--client", "taken", "--client", "taken",
        "--template", "directum", check=False,
    )
    assert failed.returncode != 0
    assert not (tmp_path / "out" / "taken.ovpn").exists()
~~~

- [ ] **Step 2: Run the new tests.**

Run: pytest tests/test_vpnctl_batch_generation.py -q

Expected: FAIL because argparse has no generate-batch command.

- [ ] **Step 3: Implement preflight and generation.**

~~~python
def preflight_batch_clients(clients: Iterable[str]) -> list[str]:
    names = [validate_client(str(value).strip()) for value in clients]
    if not names or len(set(names)) != len(names):
        raise SystemExit("batch client names must be non-empty and unique")
    existing = {row["name"] for row in list_clients() if row.get("status") == "active"}
    conflicts = [
        name for name in names
        if name in existing or any(path.exists() for path in client_paths(name).values())
    ]
    if conflicts:
        raise SystemExit(f"batch client names already exist: {', '.join(conflicts)}")
    return names
~~~

Add custom as a zero-route profile. Add parser flags with a mutually exclusive template/CIDR mode. Under one exclusive lock: preflight names, validate mode, create every client from custom, then apply the one selected access mode. Custom CIDRs must exist in the catalogue. Dry-run returns the full result without writes.

- [ ] **Step 4: Add custom-network and DNS tests, then run GREEN.**

~~~python
def test_batch_custom_routes_are_unique_and_dns_is_applied(tmp_path):
    run_vpnctl(tmp_path, "networks", "add", "192.168.100.12/32", "--tag", "custom-route")
    result = run_vpnctl(
        tmp_path, "generate-batch", "--client", "person",
        "--cidr", "192.168.100.12/32", "--cidr", "192.168.100.12/32", "--dns",
    )
    assert result["networks"] == ["192.168.100.12/32"]
    assert "dhcp-option DNS" in (tmp_path / "ccd" / "person").read_text(encoding="utf-8")
~~~

Run: pytest tests/test_vpnctl_batch_generation.py tests/test_vpnctl_networks.py tests/test_vpnctl_config_edit.py -q

Expected: PASS.

- [ ] **Step 5: Commit.**

~~~powershell
git add deploy/vpnctl tests/test_vpnctl_batch_generation.py
git commit -m "feat: add validated OpenVPN batch generation"
~~~

### Task 2: Add browser-input and ZIP helpers

**Files:**

- Create: app/client_batch.py
- Modify: app/config.py
- Modify: app/download_tokens.py
- Create: tests/test_client_batch.py

**Interfaces:**

- parse_batch_client_names(pasted: str, csv_bytes: bytes | None) -> list[str]
- parse_custom_cidrs(raw: str) -> list[str]
- create_batch_zip(paths: Sequence[Path], archive_dir: Path) -> Path
- Settings.batch_download_dir is an allowed root.

- [ ] **Step 1: Write failing parser and archive tests.**

~~~python
def test_names_from_text_and_csv_are_normalized_and_deduplicated():
    assert parse_batch_client_names(
        "anna, bob\nanna ", b"client_name\ncarol\nbob\n"
    ) == ["anna", "bob", "carol"]


def test_csv_rejects_legacy_per_client_overrides():
    with pytest.raises(ClientBatchInputError, match="profile"):
        parse_batch_client_names("", b"client_name,profile\nalice,directum\n")


def test_zip_contains_only_requested_ovpn_files(tmp_path):
    archive = create_batch_zip([write_ovpn(tmp_path, "anna"), write_ovpn(tmp_path, "bob")], tmp_path / "batches")
    with zipfile.ZipFile(archive) as result:
        assert result.namelist() == ["anna.ovpn", "bob.ovpn"]
~~~

- [ ] **Step 2: Run RED.**

Run: pytest tests/test_client_batch.py -q

Expected: FAIL because app.client_batch does not exist.

- [ ] **Step 3: Implement pure helpers.**

Use csv.DictReader and require client_name. Split pasted names by comma or newline. Validate with the current client-name regex, retain first occurrence, and reject an empty result. Reject non-empty CSV profile or vpn_ip because web batches use one shared policy and dynamic addressing. Normalize CIDRs through ipaddress.ip_network. Write UUID ZIPs with mode 0600 into BATCH_DOWNLOAD_DIR. Reject non-OVPN or non-OUT_DIR source paths.

- [ ] **Step 4: Run GREEN and commit.**

Run: pytest tests/test_client_batch.py tests/test_download_tokens.py -q

Expected: PASS.

~~~powershell
git add app/client_batch.py app/config.py app/download_tokens.py tests/test_client_batch.py
git commit -m "feat: add safe batch profile input and archives"
~~~

### Task 3: Unify single and bulk web creation

**Files:**

- Modify: app/main.py
- Modify: app/templates/client_new.html
- Modify: app/api.py
- Modify: tests/test_routes_smoke.py
- Modify: tests/test_api_routes.py

**Interfaces:**

- Form fields: creation_mode, client, client_names, clients_csv, access_mode, template, custom_cidrs, dns, comment.
- A one-name creation calls the same generate-batch command as bulk creation.
- Result context includes requested_count, generated_count, public client rows, access_mode, and a download URL.

- [ ] **Step 1: Add failing web/API tests.**

~~~python
def test_bulk_form_creates_one_profile_per_unique_name_and_offers_zip(tmp_path, monkeypatch):
    response = post_new_client_form(
        client, csrf, creation_mode="bulk", client_names="anna\nbob\nanna",
        clients_csv=("people.csv", b"client_name\ncarol\n"),
        access_mode="custom", custom_cidrs="192.168.100.12,192.168.100.12", dns="1",
    )
    assert "3 / 3" in response.text
    assert "/download/" in response.text
    assert batch_command_names(log_path) == ["anna", "bob", "carol"]


def test_empty_api_comment_is_not_sent_as_a_cli_option():
    assert "--comment" not in profile_command_args("generate", "anna", ClientProfileRequest(profile="directum"))
~~~

- [ ] **Step 2: Run RED.**

Run: pytest tests/test_routes_smoke.py tests/test_api_routes.py -q

Expected: FAIL for absent fields and the missing batch command.

- [ ] **Step 3: Implement controller and API flow.**

Load network templates for the form. Reject a request containing both a template and custom CIDRs. For custom mode, parse CIDRs and call networks add with tag custom-route, no NAT, and comment added from client creation before generate-batch. Include comment only when trimmed text is non-empty. On complete success: sync once, build a ZIP from returned OVPN paths, create a one-time token with created_by the current user and expiry from download_ttl_minutes, and render its download URL. Audit names count, generated count, and route mode only. Update profile_command_args to omit blank comment arguments.

- [ ] **Step 4: Implement form modes.**

Add single/bulk radio buttons and template/custom route radio buttons. Bulk mode shows a textarea plus CSV upload and hides client type, VPN IP, remote LAN, and server-route inputs. Template mode shows a network-template picker; custom mode shows CIDR textarea and DNS checkbox. Add small fieldset-toggle JavaScript, but enforce every condition server-side. Render generated_count / requested_count, public client names, and the ZIP link only after success.

- [ ] **Step 5: Run GREEN and commit.**

Run: pytest tests/test_routes_smoke.py tests/test_api_routes.py tests/test_client_batch.py -q

Expected: PASS.

~~~powershell
git add app/main.py app/templates/client_new.html app/api.py tests/test_routes_smoke.py tests/test_api_routes.py
git commit -m "feat: create single and batch VPN profiles from web"
~~~

### Task 4: Preserve the legacy-script boundary

**Files:**

- Modify: deploy/generate-client-wrapper.sh
- Modify: docs/DEPLOYMENT.md
- Create: tests/test_deploy_batch_client_generation.py

**Interfaces:**

- The installed wrapper forwards generate-batch directly to vpnctl.
- The operator-owned legacy generate-all.sh remains unchanged. Documentation marks it legacy; new group creation uses the panel or vpnctl generate-batch.

- [ ] **Step 1: Write a failing deployment contract.**

~~~python
def test_wrapper_and_docs_expose_batch_generation():
    wrapper = Path("deploy/generate-client-wrapper.sh").read_text(encoding="utf-8")
    docs = Path("docs/DEPLOYMENT.md").read_text(encoding="utf-8")
    assert "vpnctl" in wrapper and '"$@"' in wrapper
    assert "generate-batch" in docs
~~~

- [ ] **Step 2: Run RED.**

Run: pytest tests/test_deploy_batch_client_generation.py -q

Expected: FAIL because deployment documentation does not name generate-batch.

- [ ] **Step 3: Document the boundary and run final verification.**

Document common-profile user batches, CSV client_name input, custom-CIDR catalogue insertion, full-batch preflight, and one-time ZIP delivery. State that legacy generate-all.sh is not called by the panel. Update the wrapper usage text only; do not expose OVPN content.

Run: pytest tests/test_deploy_batch_client_generation.py tests/test_vpnctl_batch_generation.py tests/test_client_batch.py tests/test_routes_smoke.py tests/test_api_routes.py -q

Expected: PASS.

- [ ] **Step 4: Commit.**

~~~powershell
git add deploy/generate-client-wrapper.sh docs/DEPLOYMENT.md tests/test_deploy_batch_client_generation.py
git commit -m "docs: document batch VPN client generation"
~~~

## Self-review

- The plan covers optional comments, arbitrary catalogue CIDRs, template/custom exclusivity, CSV/list input, five names producing five profiles, preflight, ZIP delivery, and the legacy script boundary.
- All layers use generate-batch and never return or audit OVPN private material.
