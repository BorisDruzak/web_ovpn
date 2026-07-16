from __future__ import annotations

import sys
from pathlib import Path

CONTROL_ROOT = (
    Path(__file__).resolve().parents[2]
    / "deploy"
    / "alt-linux"
    / "control"
)

sys.path.insert(0, str(CONTROL_ROOT))
