# OR-1 verification status

Verification commands required before merge:

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_operational_reliability_contract.py \
  tests/alt_linux/test_operational_reliability_scenarios.py

.venv/bin/python -m pytest -q tests/alt_linux
.venv/bin/python -m pytest -q

git diff --check origin/main...HEAD
```

Current connector session cannot execute repository commands because no local checkout is available and outbound GitHub DNS is unavailable. GitHub reports no workflow runs for branch commits. Therefore this document intentionally records no PASS status or test counts.
