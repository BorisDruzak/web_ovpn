# Test SSH Server Drafts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Add authenticated, persistent SSH server drafts that safely expose the observer public key and verify gateway-originated SSH access without joining the health collector.

**Architecture:** The web application owns draft metadata in SQLite and writes validated JSON requests to a group-writable queue. A hardened openvpm systemd path/service worker owns the private observer key, scans and pins a user-confirmed host key, and performs only the fixed remote command true. It writes redacted result JSON for the web layer to display.

**Tech Stack:** FastAPI, Jinja2, vanilla browser JavaScript, SQLAlchemy/SQLite, Python standard library, OpenSSH, systemd, pytest.

## Global Constraints

- Drafts never modify collector runtime config, collector timer, or collector snapshot.
- The web process never receives the observer private key or a private host key.
- Never accept a password, an arbitrary remote command, shell syntax, or a non-UUID worker request identifier.
- Validate host and user with the existing observer safe-component patterns; validate port from 1 through 65535.
- Scan first, expose only algorithm and SHA-256 fingerprint, and pin only after authenticated CSRF-protected confirmation.
- Every access test uses the observer key, a draft-specific known-hosts file, BatchMode, StrictHostKeyChecking, and a 20-second timeout.
- Results and audit entries use only pending, ok, timeout, host_key_mismatch, authentication, transport, or invalid_response.
- Use atomic file creation/replacement for queue and result files; redact all subprocess output.
- Do not deploy or alter production during implementation.

---

## File Structure

- app/models.py: persistent ServerDraft metadata only.
- app/server_drafts.py: validation, queue protocol, redacted public results, public-key reader, and worker command construction.
- app/server_draft_worker.py: queue consumer CLI with no FastAPI dependency.
- app/config.py: draft queue/results/public key paths.
- app/main.py: authenticated pages, CSRF posts, audit, and public-key download.
- app/templates/server_drafts.html and app/templates/server_draft_new.html: list and form.
- app/static/app.js: safe clipboard action only.
- deploy/server-draft-worker, service, and path: key-owning worker.
- deploy/install-openvpn-web.sh: permissions, public-key derivation, and units.
- tests/test_server_drafts.py, test_web_server_drafts.py, and test_deploy_server_drafts.py: regression coverage.

### Task 1: Persistent metadata and safe queue boundary

**Files:**
- Modify: app/models.py
- Modify: app/config.py
- Create: app/server_drafts.py
- Create: tests/test_server_drafts.py

**Interfaces:**
- ServerDraft has id, name, host, ssh_user, port, created_at, and updated_at.
- DraftRequest has id, action, host, ssh_user, port, and expected_fingerprint.
- create_draft_request(queue_dir, request), read_public_result(results_dir, draft_id), and observer_public_key(path) are the only web-to-worker helpers.

- [ ] **Step 1: Write failing validation and redaction tests**

    def test_request_rejects_unsafe_components_and_bad_port(tmp_path):
        with pytest.raises(ValueError):
            make_draft_request("not-a-uuid", "host;id", "user", 22, "scan")
        with pytest.raises(ValueError):
            make_draft_request(str(uuid4()), "host", "user", 0, "scan")

    def test_queue_is_atomic_and_has_no_private_material(tmp_path):
        request = make_draft_request(str(uuid4()), "server.example", "observer", 22, "scan")
        path = create_draft_request(tmp_path, request)
        assert json.loads(path.read_text())["action"] == "scan"
        assert "PRIVATE KEY" not in path.read_text()

    def test_public_result_removes_host_key_and_stderr(tmp_path):
        write_result(tmp_path, "draft-id", {"status": "transport", "stderr": "raw", "host_key": "ssh-ed25519 AAA"})
        assert read_public_result(tmp_path, "draft-id") == {"status": "transport"}

- [ ] **Step 2: Run the test and confirm RED**

Run: py -3 -m pytest tests/test_server_drafts.py -q

Expected: failure because model and helper module do not exist.

- [ ] **Step 3: Implement model, settings, and helpers**

    class ServerDraft(Base):
        __tablename__ = "server_drafts"
        id: Mapped[str] = mapped_column(String(36), primary_key=True)
        name: Mapped[str] = mapped_column(String(120), nullable=False)
        host: Mapped[str] = mapped_column(String(253), nullable=False)
        ssh_user: Mapped[str] = mapped_column(String(64), nullable=False)
        port: Mapped[int] = mapped_column(Integer, nullable=False, default=22)

Add settings paths for queue, results, private worker storage, and observer public key. Validate UUIDs with uuid.UUID, use existing safe host/user regular expressions, write temp JSON in the target directory with mode 0640, then use os.replace. Public readers return only status, algorithm, fingerprint, and checked_at.

- [ ] **Step 4: Run GREEN and commit**

Run: py -3 -m pytest tests/test_server_drafts.py -q

Expected: pass.

    git add app/models.py app/config.py app/server_drafts.py tests/test_server_drafts.py
    git commit -m "feat: add SSH server draft queue"

### Task 2: Worker workflow for scan, confirmation, and access check

**Files:**
- Create: app/server_draft_worker.py
- Modify: app/server_drafts.py
- Modify: tests/test_server_drafts.py

**Interfaces:**
- process_queue(queue_dir, results_dir, private_dir, runner) returns processed request count.
- Worker actions are exactly scan, confirm, and check.
- Worker owns private candidate and known-hosts files named by UUID; web never reads them.

- [ ] **Step 1: Write failing worker tests**

    def test_scan_returns_only_algorithm_and_fingerprint(tmp_path, fake_runner):
        fake_runner.return_value = completed_scan("server.example ssh-ed25519 AAA")
        process_request(request_for("scan"), paths(tmp_path), fake_runner)
        result = read_public_result(paths(tmp_path).results, request_for("scan").id)
        assert result["status"] == "pending"
        assert result["fingerprint"].startswith("SHA256:")
        assert "AAA" not in json.dumps(result)

    def test_confirm_requires_exact_scanned_fingerprint(tmp_path, fake_runner):
        save_candidate(paths(tmp_path), "draft-id", "server.example ssh-ed25519 AAA")
        with pytest.raises(DraftWorkerError, match="fingerprint"):
            process_request(request_for("confirm", expected_fingerprint="SHA256:other"), paths(tmp_path), fake_runner)

    def test_check_uses_fixed_true_and_strict_known_host(tmp_path, fake_runner):
        pin_candidate(paths(tmp_path), "draft-id", "server.example ssh-ed25519 AAA")
        process_request(request_for("check"), paths(tmp_path), fake_runner)
        command = fake_runner.call_args.args[0]
        assert command[-1] == "true"
        assert "BatchMode=yes" in command
        assert "StrictHostKeyChecking=yes" in command

- [ ] **Step 2: Run RED**

Run: py -3 -m pytest tests/test_server_drafts.py -q

Expected: failures because worker module and workflow are absent.

- [ ] **Step 3: Implement worker with fixed commands**

For scan, invoke only ssh-keyscan with port, eight-second scan timeout, ED25519 selection, and validated host. Derive fingerprint with ssh-keygen. Save raw scan output only in private worker storage. Confirm compares the browser-independent expected fingerprint with the derived candidate fingerprint, then atomically creates the UUID known-hosts file. Check invokes SSH with observer key, draft known-hosts path, BatchMode, StrictHostKeyChecking, port, validated user at host, and final command true. Use subprocess timeout 20, errors replace, and map every non-success condition to an allowed status without persisting output.

- [ ] **Step 4: Add duplicate and timeout tests**

    def test_duplicate_check_is_not_run_twice(tmp_path, fake_runner):
        mark_checking(paths(tmp_path), "draft-id")
        assert process_request(request_for("check"), paths(tmp_path), fake_runner) == 0
        fake_runner.assert_not_called()

    def test_timeout_writes_only_safe_category(tmp_path, fake_runner):
        fake_runner.side_effect = subprocess.TimeoutExpired(["ssh"], 20, output="raw response")
        process_request(request_for("check"), paths(tmp_path), fake_runner)
        assert read_public_result(paths(tmp_path).results, "draft-id") == {"status": "timeout"}

- [ ] **Step 5: Run GREEN and commit**

Run: py -3 -m pytest tests/test_server_drafts.py -q

Expected: pass.

    git add app/server_draft_worker.py app/server_drafts.py tests/test_server_drafts.py
    git commit -m "feat: add isolated SSH draft worker"

### Task 3: Hardened worker service and installer

**Files:**
- Create: deploy/server-draft-worker
- Create: deploy/server-draft-worker.service
- Create: deploy/server-draft-worker.path
- Modify: deploy/install-openvpn-web.sh
- Create: tests/test_deploy_server_drafts.py

**Interfaces:**
- Wrapper runs the virtualenv module with once.
- Path unit watches only the public request queue.
- Service runs as openvpm:openvpn-web and writes only draft storage.

- [ ] **Step 1: Write failing deployment tests**

    def test_worker_service_is_key_isolated():
        service = Path("deploy/server-draft-worker.service").read_text()
        assert "User=openvpm" in service
        assert "Group=openvpn-web" in service
        assert "TimeoutStartSec=3min" in service
        assert "NoNewPrivileges=true" in service
        assert "ProtectSystem=strict" in service
        assert "BindReadOnlyPaths=/etc/openvpn-web/server-observer.key" in service
        assert "ReadWritePaths=/var/lib/openvpn-web/server-drafts" in service
        assert "InaccessiblePaths=-/var/lib/openvpn-web/openvpn-web.sqlite" in service

    def test_installer_derives_public_key_and_enables_path_only():
        installer = Path("deploy/install-openvpn-web.sh").read_text()
        assert "ssh-keygen -y -f /etc/openvpn-web/server-observer.key" in installer
        assert "/etc/openvpn-web/server-observer.pub" in installer
        assert "server-draft-worker.path" in installer

- [ ] **Step 2: Run RED**

Run: py -3 -m pytest tests/test_deploy_server_drafts.py -q

Expected: failure because assets do not exist.

- [ ] **Step 3: Implement units and permissions**

Create queue and results directories as openvpn-web:openvpn-web mode 0770, and private candidate/known-hosts storage as openvpm:openvpm mode 0700. Derive public key only from a regular observer private key and install it root:openvpn-web mode 0644. Service must bind the private key read-only, hide web env and SQLite, retain all hardening from server-observer.service, allow only draft storage writes, and have a three-minute service limit. The path unit activates the service after a queue file change. Installer daemon-reloads and enables the path unit; it does not trigger a target check.

- [ ] **Step 4: Run GREEN and commit**

Run: py -3 -m pytest tests/test_deploy_server_drafts.py tests/test_deploy_server_observer.py -q

Expected: pass.

    git add deploy/server-draft-worker deploy/server-draft-worker.service deploy/server-draft-worker.path deploy/install-openvpn-web.sh tests/test_deploy_server_drafts.py
    git commit -m "feat: deploy isolated SSH draft worker"

### Task 4: Authenticated pages, CSRF actions, and audit

**Files:**
- Modify: app/main.py
- Modify: app/templates/base.html
- Create: app/templates/server_drafts.html
- Create: app/templates/server_draft_new.html
- Create: tests/test_web_server_drafts.py

**Interfaces:**
- GET /network/server-drafts renders drafts with redacted results.
- GET /network/server-drafts/new renders form.
- POST new, scan, confirm, check, and delete routes require CSRF.
- GET /network/server-drafts/public-key returns only observer public key attachment.

- [ ] **Step 1: Write failing route tests**

    def test_pages_and_key_download_require_session(tmp_path, monkeypatch):
        client = make_client(tmp_path, monkeypatch)
        assert client.get("/network/server-drafts", follow_redirects=False).status_code == 303
        assert client.get("/network/server-drafts/public-key", follow_redirects=False).status_code == 303

    def test_create_requires_csrf_and_queues_scan(tmp_path, monkeypatch):
        client, db = make_logged_in_client(tmp_path, monkeypatch)
        assert client.post("/network/server-drafts/new", data={"name": "new"}).status_code == 403
        response = post_with_csrf(client, "/network/server-drafts/new", {"name": "new", "host": "server.example", "ssh_user": "observer", "port": "22"})
        assert response.status_code == 303
        assert db.query(ServerDraft).one().host == "server.example"
        assert queued_action(tmp_path)["action"] == "scan"

    def test_public_key_download_excludes_private_material(tmp_path, monkeypatch):
        client, _ = make_logged_in_client(tmp_path, monkeypatch, public_key="ssh-ed25519 AAA observer")
        response = client.get("/network/server-drafts/public-key")
        assert response.status_code == 200
        assert response.headers["content-disposition"].endswith('filename="openvpm-observer.pub"')
        assert response.text == "ssh-ed25519 AAA observer\n"
        assert "PRIVATE" not in response.text

- [ ] **Step 2: Run RED**

Run: py -3 -m pytest tests/test_web_server_drafts.py -q

Expected: failure because routes and templates are absent.

- [ ] **Step 3: Implement server-side workflow**

Require session on all routes and verify CSRF before mutations. Creation validates and persists ServerDraft then queues scan. Confirm takes fingerprint only from stored redacted worker result, never from form input. Check may queue only after pending result has been confirmed and pinned result is reported. Deletion removes database row, public results, and queues a worker cleanup request; no web route touches private storage. Audit with action, safe result, and UUID target_client only; never record host, user, host key, or subprocess output.

- [ ] **Step 4: Implement templates and state tests**

List template shows name, host, user, port, state, fingerprint, last safe result, and only valid next actions. Every form contains csrf_token. Add sidebar link named Тестовые серверы. New form contains name, host, SSH user, and port. Add:

    def test_confirm_uses_stored_fingerprint_and_audits_uuid(tmp_path, monkeypatch):
        seed_public_result(tmp_path, "draft-id", {"status": "pending", "fingerprint": "SHA256:expected"})
        post_with_csrf(client, "/network/server-drafts/draft-id/confirm", {})
        assert queued_action(tmp_path) == {"id": "draft-id", "action": "confirm", "expected_fingerprint": "SHA256:expected"}
        assert audit_record(db).target_client == "draft-id"
        assert "server.example" not in audit_record(db).message

- [ ] **Step 5: Run GREEN and commit**

Run: py -3 -m pytest tests/test_web_server_drafts.py tests/test_web_network_observer.py -q

Expected: pass.

    git add app/main.py app/templates/base.html app/templates/server_drafts.html app/templates/server_draft_new.html tests/test_web_server_drafts.py
    git commit -m "feat: add SSH server draft web workflow"

### Task 5: Copy action, operator documentation, and full verification

**Files:**
- Modify: app/static/app.js
- Modify: tests/test_web_server_drafts.py
- Modify: docs/DEPLOYMENT.md

**Interfaces:**
- One button carrying data-copy-observer-key copies only the readonly public-key textarea.

- [ ] **Step 1: Write failing copy safety test**

    def test_draft_key_copy_uses_safe_dom_only():
        template = Path("app/templates/server_drafts.html").read_text()
        script = Path("app/static/app.js").read_text()
        assert "data-copy-observer-key" in template
        assert "navigator.clipboard.writeText" in script
        assert "innerHTML" not in script
        assert "server-observer.key" not in template

- [ ] **Step 2: Run RED**

Run: py -3 -m pytest tests/test_web_server_drafts.py -q

Expected: failure until copy button exists.

- [ ] **Step 3: Implement copy and documentation**

Attach a click listener to the copy button, read only textarea.value, call navigator.clipboard.writeText, and update an existing status node with textContent using fixed success/failure text. Add deployment documentation: download public key, install it in target authorized_keys, create draft, compare fingerprint out-of-band, confirm, then read fixed SSH result. State that drafts do not enroll collector targets and private key remains gateway-only.

- [ ] **Step 4: Run full suite and commit**

Run: py -3 -m pytest -q

Expected: all tests pass; record exact pass/skip count.

    git add app/static/app.js tests/test_web_server_drafts.py docs/DEPLOYMENT.md
    git commit -m "docs: explain SSH server draft checks"

### Task 6: Deployment rehearsal and rollback runbook

**Files:**
- Modify: docs/DEPLOYMENT.md

**Interfaces:**
- Handoff enables only server-draft-worker.path and preserves collector configuration.

- [ ] **Step 1: Verify shell and focused deployment checks**

Run: bash -n deploy/install-openvpn-web.sh && py -3 -m pytest tests/test_deploy_server_drafts.py tests/test_server_drafts.py -q

Expected: success.

- [ ] **Step 2: Add explicit safe handoff steps**

Document backup of only server-draft-worker units and server-drafts directory, installer invocation, systemctl verification of the path unit, public-key group readability, and no target test until an operator creates a draft. Document rollback as disabling only server-draft-worker.path and restoring only draft assets. Explicitly prohibit OpenVPN restart and collector config modification.

- [ ] **Step 3: Run final regression and commit**

Run: py -3 -m pytest -q

Expected: no failures.

    git add docs/DEPLOYMENT.md
    git commit -m "docs: add SSH draft worker deployment runbook"

## Plan Self-Review

- Spec coverage: Task 1 creates drafts and queue boundary; Task 2 implements scan, confirmation, strict check, timeouts, and redaction; Task 3 isolates the service and derives public key; Task 4 adds authenticated web and audit workflow; Task 5 provides safe copying and operator guide; Task 6 provides handoff and rollback.
- Placeholder scan: no unresolved implementation markers are present; every task includes files, interfaces, a failing test, command, implementation direction, verification, and commit.
- Type consistency: Task 1 defines ServerDraft and DraftRequest; Task 2 consumes DraftRequest; Task 3 deploys the worker module from Task 2; Task 4 uses the same UUID and public result fields.

## Execution Handoff

Plan complete and saved to docs/superpowers/plans/2026-07-19-server-draft-ssh.md. Two execution options:

1. **Subagent-Driven (recommended)** — dispatch a fresh subagent per task, review between tasks.
2. **Inline Execution** — execute tasks in this session using executing-plans, in batches with checkpoints.
