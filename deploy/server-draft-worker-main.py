"""Immutable bootstrap for the isolated SSH draft worker runtime."""

from pathlib import Path
import runpy
import sys


RUNTIME_ROOT = Path("/usr/local/lib/openvpn-web-server-draft-worker")


if __name__ == "__main__":
    sys.path.insert(0, str(RUNTIME_ROOT))
    runpy.run_module("app.server_draft_worker", run_name="__main__", alter_sys=True)
