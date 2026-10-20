#!/usr/bin/env bash
# Run as the normal CI user. Do not relax the controller's executable guard.
set -euo pipefail

python - <<'PY'
import json, sys
from pathlib import Path
target = Path(sys.executable).resolve(strict=True)
print(json.dumps({'initial_python': str(target), 'ancestry': [
    {'path': str(p), 'uid': p.stat().st_uid, 'mode': oct(p.stat().st_mode & 0o7777)}
    for p in (target, *target.parents)]}))
PY
sudo apt-get update
sudo apt-get install --yes fakeroot python3.12-venv

# setup-python's toolcache ancestry is writable by the runner. A symlink venv
# resolves to the distribution's root-owned executable under /usr/bin instead.
controller_test_venv="${RUNNER_TEMP:?}/alt-controller-test-venv"
test ! -e "$controller_test_venv"
/usr/bin/python3.12 -m venv "$controller_test_venv"
"$controller_test_venv/bin/python" - <<'PY'
import json, sys
from pathlib import Path
sys.path.insert(0, 'deploy/alt-linux/control')
from alt_deploy.user_session import _trusted_program
assert sys.version_info[:2] == (3, 12)
assert sys.prefix != sys.base_prefix
target = _trusted_program([sys.executable])
print(json.dumps({'controller_test_python': target, 'uid': Path(target).stat().st_uid,
                  'version': sys.version.split()[0], 'trusted_program': True}))
PY
printf '%s\n' "$controller_test_venv/bin" >> "${GITHUB_PATH:?}"
printf 'VIRTUAL_ENV=%s\n' "$controller_test_venv" >> "${GITHUB_ENV:?}"
