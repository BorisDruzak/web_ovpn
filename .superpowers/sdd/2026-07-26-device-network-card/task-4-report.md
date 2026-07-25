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
