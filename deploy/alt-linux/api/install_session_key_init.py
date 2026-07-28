from __future__ import annotations

import json
import sys
from collections.abc import Sequence

from alt_deploy.config import Settings
from alt_deploy.install_session_keys import ensure_install_session_keypair


def main(argv: Sequence[str] | None = None) -> int:
    if argv:
        print("usage: install_session_key_init.py", file=sys.stderr)
        return 2
    try:
        metadata = ensure_install_session_keypair(Settings.from_env())
    except ValueError:
        print("Install signing key initialization failed", file=sys.stderr)
        return 1
    print(json.dumps(metadata, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
