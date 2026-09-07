# Manual ALT profile contract — execution plan

> Execute only this plan before starting roles, artifacts, or first-login
> orchestration from the broader ALT resilience integration plan.

**Goal:** Make the controller's manual `configure` request support optional
software and remote-access profiles without weakening existing requests, and
consume only a validated, structured result from stage 03.

**Global constraints:**

- The existing nine-field manual request remains accepted and means
  `software_profile=base`, `remote_access_profile=none`, and no assigned user.
- Unknown request fields, secrets, and arbitrary profiles remain rejected.
- `assigned_domain_user` is required only for `core-apps` or `krfb`; accept a
  short login or `@sosnadmin.local` UPN, normalize it, and never emit a
  password.
- Stage 03 can run for 90 minutes. All public errors expose only its `run_id`.
- Do not contact the deployment host or change an ALT workstation.

## Task 1: Add the backward-compatible profile request contract

**Files:**

- Modify: `deploy/alt-linux/control/alt_deploy/configure.py`
- Modify: `tests/test_alt_manual_configure_request.py`

1. Add failing tests for a legacy nine-field request receiving the safe
   defaults, a selected `core-apps` profile requiring an assigned user, KRFB
   requiring an assigned user, and unsupported/malformed profile input being
   rejected.
2. Run the focused request tests and confirm the profile cases fail because
   the current request schema does not contain those fields.
3. Implement the smallest parser/data-class change that accepts the three new
   optional fields while rejecting omitted/partial ambiguity and preserving
   the fixed domain constraints.
4. Make preview actions describe only explicit selected components.
5. Re-run the focused tests.

## Task 2: Require a safe structured stage-03 result

**Files:**

- Modify: `deploy/alt-linux/control/alt_deploy/configure.py`
- Modify: `tests/test_alt_manual_configure_request.py`

1. Add failing tests for one valid structured result and for a result with an
   unknown field, mismatched machine, unsafe error, or unsupported phase.
2. Confirm those tests fail because current `start()` returns arbitrary JSON.
3. Add a strict result reader that validates identity, status, phase,
   retryability, component map, verification map, reboot flag, and bounded
   safe error details. It returns a result with `run_id` only after validation.
4. Do not change Ansible role execution in this task. Preserve the existing
   manual stage by accepting only its exact legacy result shape after identity
   validation: `machine_uuid`, `hostname`, `profile`, `domain`,
   `already_joined`, `reboot_required`, and `verification`. The domain must
   match the request; the two flags must be booleans; verification must be a
   mapping. An absent, extra-field, or mismatched legacy result remains
   `domain_verification_failed`. This compatibility reader is removed only
   after stage 03 itself emits the structured schema.
5. Re-run focused tests.

## Task 3: Extend timeout and readiness safety checks

**Files:**

- Modify: `deploy/alt-linux/control/alt_deploy/configure.py`
- Modify: `deploy/alt-linux/control/alt_deploy/controller_readiness.py`
- Modify: `tests/test_alt_manual_configure_request.py`
- Modify: `tests/alt_linux/test_or3p1_controller_readiness.py`
- Modify: `tests/alt_linux/test_or3p1_controller_readiness_failures.py`

1. Add failing tests requiring a 5,400-second timeout to produce only
   `domain_join_timeout` and `run_id`, and readiness to syntax-check stage 03
   in addition to stages 01 and 02.
2. Confirm the tests fail against the current 1,800-second timeout and missing
   stage-03 readiness check.
3. Implement the minimum timeout exception mapping and readiness entry.
4. Run targeted controller and readiness tests.

## Task 4: Verify the branch and preserve the next boundary

1. Run `git diff --check` and all focused pytest files.
2. Run Bash syntax validation for bootstrap scripts if changed; otherwise do
   not claim it as part of this change.
3. On an ALT controller, a future canary must run `ansible-playbook
   --syntax-check playbooks/03-configure-domain-workstation.yml`; Windows has
   no Ansible runtime and is not a substitute.
4. Commit only task files with `refactor(alt): align manual configure profile contract`.
