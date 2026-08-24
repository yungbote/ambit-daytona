#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path


PACK_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACK_ROOT / "protocol"))

from render_runner import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main(PACK_ROOT))
