# ALT Install Plan PR2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (- [ ]) syntax for tracking.

**Goal:** Build a controller-only, strictly validated ALT 11.4 standard-office install-plan pipeline that renders repeatable autoinstall artefacts from synthetic fixtures.

**Architecture:** A small domain layer under alt_deploy accepts a bounded inventory, evaluates a JSON profile and explicit operator selection, then returns a frozen plan with canonical identity hashes. A renderer accepts that validated plan and typed server-side secrets, substitutes only fixed template fields, and produces byte-stable artefacts plus external checksums.

**Tech Stack:** Python 3 standard library (dataclasses, hashlib, json, pathlib, string), pytest, JSON, Scheme text templates.

## Global Constraints

- No HTTP listener, agent protocol, ISO alteration, Alterator launch, shell execution, disk-partitioning command, or target-disk write.
- Use JSON only; add no runtime dependency outside the Python standard library.
- Reject unknown inventory fields at every depth. Do not accept source_ip from an agent.
- Policy is exactly ALT KWorkstation 11.4, UEFI, x86_64, DHCP, one eligible internal disk, Btrfs, 4 GiB swap, 40 GiB Btrfs minimum, 50 GiB physical-disk minimum, subvolumes @ and @home, no encryption/RAID/LVM, and package set standard-office-v1.
- Plans are immutable. plan_hash is external in plan.sha256. Active password hashes never enter inventory, policy, plan, fixtures, snapshots, or logs.
- Preserve deterministic UTF-8, key ordering, whitespace, final newline, and checksum filename ordering.

---

### Task 1: Establish test imports and strict InstallInventory V1

**Files:**

- Create: tests/alt_linux/conftest.py
- Create: tests/alt_linux/fixtures/install/inventory-valid.json
- Create: tests/alt_linux/fixtures/install/inventory-unknown-field.json
- Create: tests/alt_linux/fixtures/install/inventory-oversized.json
- Create: tests/alt_linux/test_install_inventory.py
- Create: deploy/alt-linux/control/alt_deploy/install_inventory.py

**Interfaces:**

- Consumes: pytest and Python standard-library JSON.
- Produces: InventoryError(code, message), frozen InstallInventoryV1, parse_inventory(payload), canonical_inventory_bytes(inventory), inventory_sha256(inventory).

- [ ] **Step 1: Write failing parser and boundary tests**

~~~python
def test_parse_inventory_has_stable_canonical_hash(valid_payload):
    inventory = parse_inventory(valid_payload)
    assert inventory.machine.firmware == "uefi"
    assert inventory_sha256(inventory) == inventory_sha256(
        parse_inventory(inventory.to_dict())
    )


@pytest.mark.parametrize("name, code", [
    ("inventory-unknown-field.json", "inventory_unknown_field"),
    ("inventory-oversized.json", "inventory_limit_exceeded"),
])
def test_parse_inventory_rejects_untrusted_shape(name, code):
    with pytest.raises(InventoryError, match=code):
        parse_inventory(load_install_fixture(name))
~~~

Cover a non-object top level, unsupported schema version, source_ip, unknown nested fields, missing required fields, invalid hash/MAC/path, overlong string, more than 16 interfaces/disks/addresses/filesystem signatures, and an out-of-range integer.

- [ ] **Step 2: Verify the test fails before implementation**

Run: python -m pytest -q tests/alt_linux/test_install_inventory.py

Expected: FAIL because alt_deploy.install_inventory does not exist.

- [ ] **Step 3: Implement frozen inventory types and exact validation**

Add frozen dataclasses for agent, machine, interface, disk, boot media, and inventory. Make every to_dict method explicit. Use a single _require_fields mapping helper to reject unexpected keys. Accept only absolute block paths matching /dev/(sd[a-z]+|vd[a-z]+|nvme[0-9]+n[0-9]+|xvd[a-z]+); encode absent serial and WWN as None.

Canonical JSON must be:

~~~python
json.dumps(
    inventory.to_dict(),
    ensure_ascii=True,
    sort_keys=True,
    separators=(",", ":"),
).encode("utf-8")
~~~

Hash the canonical byte sequence with hashlib.sha256(canonical_bytes).hexdigest(). Do not read files, open sockets, or execute subprocesses.

- [ ] **Step 4: Verify the focused parser suite**

Run: python -m pytest -q tests/alt_linux/test_install_inventory.py

Expected: PASS, including stable hash equality after parse/serialise/parse.

- [ ] **Step 5: Commit the inventory boundary**

~~~bash
git add tests/alt_linux/conftest.py tests/alt_linux/fixtures/install/inventory-*.json tests/alt_linux/test_install_inventory.py deploy/alt-linux/control/alt_deploy/install_inventory.py
git commit -m "feat: validate ALT install inventory"
~~~

### Task 2: Add the standard-office profile and fail-closed policy

**Files:**

- Create: deploy/alt-linux/autoinstall/profiles/standard-office-v1.json
- Create: deploy/alt-linux/control/alt_deploy/install_policy.py
- Create: tests/alt_linux/test_install_policy.py
- Create: tests/alt_linux/fixtures/install/inventory-disk-32g.json
- Create: tests/alt_linux/fixtures/install/inventory-disk-50g.json
- Create: tests/alt_linux/fixtures/install/inventory-disk-100g.json
- Create: tests/alt_linux/fixtures/install/inventory-disk-200g-no-serial-wwn.json
- Create: tests/alt_linux/fixtures/install/inventory-no-disk.json
- Create: tests/alt_linux/fixtures/install/inventory-two-disks.json
- Create: tests/alt_linux/fixtures/install/inventory-boot-media.json
- Create: tests/alt_linux/fixtures/install/inventory-removable.json
- Create: tests/alt_linux/fixtures/install/inventory-no-route.json
- Create: tests/alt_linux/fixtures/install/inventory-two-routes.json

**Interfaces:**

- Consumes: InstallInventoryV1 and profile JSON.
- Produces: InstallProfile, PolicyEvaluation, PolicyError(code, message), load_profile(profile_root, profile_id, profile_version), evaluate_policy(inventory, profile).

- [ ] **Step 1: Write failing eligibility tests**

~~~python
@pytest.mark.parametrize("fixture_name", [
    "inventory-disk-50g.json",
    "inventory-disk-100g.json",
    "inventory-disk-200g-no-serial-wwn.json",
])
def test_standard_office_accepts_one_internal_disk(fixture_name):
    result = evaluate_policy(parse_fixture(fixture_name), standard_office_profile())
    assert result.eligible_disk.path == "/dev/vda"
    assert result.route_interface.name.startswith("enp")
~~~

Add exact rejection assertions for disk_too_small, disk_missing, disk_ambiguous, unsupported_firmware, iso_id_mismatch, iso_sha256_mismatch, unsupported_architecture, disk_is_boot_media, disk_removable, network_missing, network_ambiguous, unknown_profile, and unsupported_profile_version.

- [ ] **Step 2: Verify failure**

Run: python -m pytest -q tests/alt_linux/test_install_policy.py

Expected: FAIL because profile and alt_deploy.install_policy do not exist.

- [ ] **Step 3: Implement data-only profile and policy evaluation**

Put profile ID standard-office, version 1, ISO ID alt-kworkstation-11.4-install-x86_64, a synthetic 64-hex ISO SHA-256, 53687091200 minimum bytes, 4096 swap MiB, and 40960 Btrfs minimum MiB in JSON. Load it only through load_profile(profile_root, "standard-office", 1): a missing matching ID raises unknown_profile, and a matching ID with another requested version raises unsupported_profile_version. Parse exact profile fields.

Eligibility must require type=disk, removable=false, safe path, not boot media, and size at least minimum; reject loop, ram, and zram before candidate selection. Require exactly one eligible disk and exactly one interface whose route_to_controller is true.

- [ ] **Step 4: Verify policy results**

Run: python -m pytest -q tests/alt_linux/test_install_policy.py

Expected: PASS for all accepted and rejected fixtures.

- [ ] **Step 5: Commit policy and fixtures**

~~~bash
git add deploy/alt-linux/autoinstall/profiles/standard-office-v1.json deploy/alt-linux/control/alt_deploy/install_policy.py tests/alt_linux/test_install_policy.py tests/alt_linux/fixtures/install/inventory-*.json
git commit -m "feat: add ALT standard office policy"
~~~

### Task 3: Construct immutable plans and disk fingerprints

**Files:**

- Create: deploy/alt-linux/control/alt_deploy/install_fingerprint.py
- Create: deploy/alt-linux/control/alt_deploy/install_plan.py
- Create: tests/alt_linux/test_install_plan.py

**Interfaces:**

- Consumes: InstallInventoryV1, InstallProfile, and PolicyEvaluation.
- Produces: disk_fingerprint(disk), OperatorSelection, PlanRequest, InstallPlanV1, PlanError(code, message), build_install_plan(inventory, profile, evaluation, selection, request), canonical_plan_bytes(plan), plan_sha256(plan).

- [ ] **Step 1: Write failing plan tests**

~~~python
def test_plan_binds_selected_disk_and_inventory_hash():
    plan = build_valid_plan()
    assert plan.target_disk["fingerprint"].startswith("sha256:")
    assert plan.inventory_sha256 == inventory_sha256(valid_inventory())
    assert "plan_hash" not in plan.to_dict()


def test_plan_rejects_operator_path_outside_policy_candidate():
    with pytest.raises(PlanError, match="selection_disk_mismatch"):
        build_plan_with_selection(disk_path="/dev/sdb")
~~~

Also verify serial/WWN None is canonical, changing model or size changes the fingerprint, dataclasses reject mutation, changed inventory produces a new plan hash, and timestamps/session/revision/temporary hostname are validated.

- [ ] **Step 2: Verify failure**

Run: python -m pytest -q tests/alt_linux/test_install_plan.py

Expected: FAIL because plan and fingerprint modules do not exist.

- [ ] **Step 3: Implement fingerprint and builder**

Fingerprint exactly this canonical identity object:

~~~python
identity = {
    "model": disk.model,
    "path": disk.path,
    "serial": disk.serial,
    "size_bytes": disk.size_bytes,
    "wwn": disk.wwn,
}
fingerprint = "sha256:" + sha256(canonical_json(identity)).hexdigest()
~~~

Require operator selection to match the evaluated single disk path/fingerprint and the single route NIC name/MAC. Build a frozen schema-version-1 plan containing inventory SHA, profile/ISO identity, selected disk/NIC, fixed Btrfs layout, package set, temporary hostname, and approved/expires timestamps. Require timezone-aware ISO-8601 timestamps and expires_at later than approved_at. Persist nothing.

- [ ] **Step 4: Verify plan construction**

Run: python -m pytest -q tests/alt_linux/test_install_plan.py

Expected: PASS including immutability and canonical digest assertions.

- [ ] **Step 5: Commit plan construction**

~~~bash
git add deploy/alt-linux/control/alt_deploy/install_fingerprint.py deploy/alt-linux/control/alt_deploy/install_plan.py tests/alt_linux/test_install_plan.py
git commit -m "feat: build immutable ALT install plans"
~~~

### Task 4: Render fixed templates and external checksums deterministically

**Files:**

- Create: deploy/alt-linux/autoinstall/templates/autoinstall.scm.template
- Create: deploy/alt-linux/autoinstall/templates/vm-profile.scm.template
- Create: deploy/alt-linux/autoinstall/snapshots/README.md
- Create: deploy/alt-linux/autoinstall/snapshots/standard-office-v1.sha256sums
- Create: deploy/alt-linux/control/alt_deploy/install_renderer.py
- Create: tests/alt_linux/test_install_renderer.py

**Interfaces:**

- Consumes: InstallPlanV1 and fixed template directory.
- Produces: RendererSecrets(root_yescrypt_hash, admin_yescrypt_hash), RenderedInstallBundle(files), RenderError(code, message), render_install_bundle(plan, secrets, template_root), write_install_bundle(bundle, destination).

- [ ] **Step 1: Write failing deterministic renderer tests**

~~~python
def test_render_is_byte_identical_for_same_plan_and_secrets(tmp_path):
    first = render_install_bundle(valid_plan(), test_secrets(), TEMPLATE_ROOT)
    second = render_install_bundle(valid_plan(), test_secrets(), TEMPLATE_ROOT)
    assert first.files == second.files
    assert first.files["sha256sums"] == expected_snapshot_bytes()


def test_renderer_rejects_unvalidated_mapping_and_bad_secret():
    with pytest.raises(RenderError, match="plan_type_invalid"):
        render_install_bundle({"disk": "/dev/vda"}, test_secrets(), TEMPLATE_ROOT)
~~~

Assert the checksum list covers only autoinstall.scm then vm-profile.scm, all files are UTF-8 with final newlines, plan hash is absent, an unknown template token fails, and secrets appear only in rendered Scheme.

- [ ] **Step 2: Verify failure**

Run: python -m pytest -q tests/alt_linux/test_install_renderer.py

Expected: FAIL because fixed templates and renderer do not exist.

- [ ] **Step 3: Implement constrained rendering**

Use string.Template with an explicit fixed replacement dictionary constructed by the renderer; reject missing and unused placeholders. Escape Scheme string values before substitution. Validate yescrypt prefix, character set, and bounded length. Return only three byte values: autoinstall.scm, vm-profile.scm, and sha256sums.

Build checksums exactly as:

~~~text
sha256(autoinstall_scm_bytes) + two spaces + autoinstall.scm
sha256(vm_profile_scm_bytes) + two spaces + vm-profile.scm
~~~

Write only those names within an existing caller-supplied destination, reject traversal, and use atomic replacement. Never execute a command.

- [ ] **Step 4: Verify renderer output**

Run: python -m pytest -q tests/alt_linux/test_install_renderer.py

Expected: PASS including repeat byte equality and golden checksum comparison.

- [ ] **Step 5: Commit renderer**

~~~bash
git add deploy/alt-linux/autoinstall/templates deploy/alt-linux/autoinstall/snapshots deploy/alt-linux/control/alt_deploy/install_renderer.py tests/alt_linux/test_install_renderer.py
git commit -m "feat: render deterministic ALT install artefacts"
~~~

### Task 5: Prove full pipeline behaviour and document PR2 scope

**Files:**

- Modify: tests/alt_linux/test_install_inventory.py
- Modify: tests/alt_linux/test_install_policy.py
- Modify: tests/alt_linux/test_install_plan.py
- Modify: tests/alt_linux/test_install_renderer.py
- Modify: docs/ALT_MANAGED_ISO_TECHNICAL_SPIKE.md
- Modify: deploy/alt-linux/README.md

**Interfaces:**

- Consumes: every Task 1–4 public API.
- Produces: an end-to-end synthetic acceptance test and an explicit no-runtime-integration boundary.

- [ ] **Step 1: Write the failing end-to-end acceptance test**

~~~python
def test_standard_office_pipeline_is_controller_only_and_deterministic():
    inventory = parse_inventory(load_install_fixture("inventory-disk-100g.json"))
    profile = load_profile(PROFILE_ROOT, "standard-office", 1)
    evaluation = evaluate_policy(inventory, profile)
    plan = build_install_plan(inventory, profile, evaluation, matching_selection(evaluation), fixed_request())
    assert render_install_bundle(plan, test_secrets(), TEMPLATE_ROOT).files == render_install_bundle(
        plan, test_secrets(), TEMPLATE_ROOT
    ).files
~~~

The forbidden-capability scan remains a manual release gate in Task 6; it is not a source-text unit test.

- [ ] **Step 2: Verify the ALT domain suite fails until complete**

Run: python -m pytest -q tests/alt_linux/test_install_inventory.py tests/alt_linux/test_install_policy.py tests/alt_linux/test_install_plan.py tests/alt_linux/test_install_renderer.py

Expected: FAIL before all Task 1–4 contracts exist, then PASS after their completion.

- [ ] **Step 3: Document the immutable boundary**

State in docs/ALT_MANAGED_ISO_TECHNICAL_SPIKE.md and deploy/alt-linux/README.md that PR2 consumes synthetic metadata and renders controller artefacts only. It does not alter the PR1 ISO, start Alterator, expose approval API, or write a target disk. Link the profile and design document.

- [ ] **Step 4: Run focused and full regression**

~~~bash
python -m pytest -q tests/alt_linux/test_install_inventory.py tests/alt_linux/test_install_policy.py tests/alt_linux/test_install_plan.py tests/alt_linux/test_install_renderer.py
python -m pytest -q
git diff --check
~~~

Expected: all ALT V1 tests and repository tests pass with no whitespace error.

- [ ] **Step 5: Commit integration evidence**

~~~bash
git add tests/alt_linux docs/ALT_MANAGED_ISO_TECHNICAL_SPIKE.md deploy/alt-linux/README.md
git commit -m "test: verify ALT install plan pipeline"
~~~

### Task 6: Perform PR handoff verification

**Files:**

- Modify: docs/superpowers/plans/2026-07-27-alt-install-plan-pr2.md (completed checkboxes only)

**Interfaces:**

- Consumes: final branch from Tasks 1–5.
- Produces: evidence the PR is server-only, deterministic, clean, and reviewable.

- [ ] **Step 1: Inspect the final diff and forbidden capability scan**

~~~bash
git diff --check origin/main...HEAD
git diff --name-only origin/main...HEAD
rg -n -i 'subprocess|socket|http\.server|alterator|sfdisk|wipefs|mkfs|systemctl|reboot' deploy/alt-linux/control/alt_deploy/install_*.py
~~~

Expected: no formatting error, no scope files outside domain/tests/profile/templates/docs, and no forbidden runtime capability in the new modules.

- [ ] **Step 2: Re-run final evidence**

~~~bash
python -m pytest -q tests/alt_linux/test_install_inventory.py tests/alt_linux/test_install_policy.py tests/alt_linux/test_install_plan.py tests/alt_linux/test_install_renderer.py
python -m pytest -q
~~~

Expected: all tests pass; record exact totals only in PR evidence.

- [ ] **Step 3: Mark completed work and commit plan state**

Use apply_patch only after evidence exists to mark completed task checkboxes. Then run git diff --check and commit:

~~~bash
git add docs/superpowers/plans/2026-07-27-alt-install-plan-pr2.md
git commit -m "docs: record ALT install plan verification"
~~~

- [ ] **Step 4: Request review and create a draft PR after checks are green**

Run: gh pr create --draft --base main --head codex/alt-install-plan-pr2 --title "ALT 11.4 install plan V1" --body "Server-only InstallInventory V1, standard-office policy, immutable plan and deterministic renderer. Synthetic fixtures only; no API, Alterator, ISO mutation or target-disk writes. Include final pytest totals in this reviewed text."

Expected: a draft PR whose description states synthetic-fixture scope, no API/Alterator/target-disk side effects, deterministic artefacts, and exact test evidence.
