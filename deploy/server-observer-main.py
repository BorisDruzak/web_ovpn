"""Root-owned bootstrap for the isolated server-observer runtime."""

from pathlib import Path
import runpy
import sys


RUNTIME_ROOT = Path("/usr/local/lib/openvpn-web-server-observer")


if __name__ == "__main__":
    sys.path.insert(0, str(RUNTIME_ROOT))
    runpy.run_module("app.server_observer_cli", run_name="__main__", alter_sys=True)
