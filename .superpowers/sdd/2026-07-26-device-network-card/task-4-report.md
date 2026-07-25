# Task 4 report — composite collection and recovery services

## RED

Command:

```powershell
python -m pytest tests/test_deploy_netctl.py -q
```

Result: 2 failed. The controlled installer/systemctl double did not observe
`enable --now netctl-collect.timer`, and `systemctl show --property=ExecStart
--value netctl-collect.service` reported the old
`/usr/local/sbin/netctl --json collect all` command.

## GREEN

Implemented the composite collection command, replaced the recovery service's
two operations with one `netctl --json reconcile` operation, and enabled the
collection timer after `systemctl daemon-reload`. The test double stages the
installed units, requires a daemon reload before enabling timers, and observes
service properties through `systemctl show`.

Command:

```powershell
python -m pytest tests/test_netctl_reconcile_units.py tests/test_deploy_netctl.py -q
```

Result: 4 passed.

## Verification

```powershell
python -m pytest tests/test_deploy_network_paths.py tests/test_netctl_deploy_security.py tests/test_netctl_reconcile_units.py tests/test_deploy_netctl.py -q
bash -n deploy/install-openvpn-web.sh
git diff --check
```

Result: 18 passed; shell syntax and whitespace checks exited 0. The Windows
test environment has Git Bash but no `systemd-analyze` or running systemd, so
the Linux-host `systemd-analyze verify` deployment check was not run locally.

## Round 1 — replace the staged-unit `systemctl show` facade

### RED

`python -m pytest tests/test_deploy_netctl.py -q` produced three failures: the
new parser and Linux-only verifier artifact did not yet exist. The installer
test stayed green because it asserts only recorded installer side effects.

### GREEN

Added `deploy/verify_netctl_systemd.py`. On a Linux host with a running systemd
manager it first runs `systemd-analyze verify` on the installed unit files, then
reads `systemctl show --property=ExecStart --value` and compares parsed argv to
the required collection and recovery commands. The parser tests use captured
serialized `systemctl show` output fixtures; they do not read unit-file text.
On Windows or a host without systemd, operational verification exits 77 with a
clear skip message. No deployment was performed.

### Verification

```powershell
python -m pytest tests/test_netctl_reconcile_units.py tests/test_deploy_network_paths.py tests/test_deploy_netctl.py -q
```

Result: 15 passed. The Linux/systemd command was deliberately not run on this
Windows host; the artifact's unsupported-host skip path is covered by the test.

Final follow-up: the broader deployment selection (`tests/test_deploy_network_paths.py`,
`tests/test_netctl_deploy_security.py`, `tests/test_netctl_reconcile_units.py`,
and `tests/test_deploy_netctl.py`) passed 20 tests. `python -m py_compile
deploy/verify_netctl_systemd.py`, `bash -n deploy/install-openvpn-web.sh`, and
`git diff --check` also exited 0.
