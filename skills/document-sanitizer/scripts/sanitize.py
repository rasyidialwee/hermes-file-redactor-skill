#!/usr/bin/env python3
"""Entry point for Hermes terminal: python ${HERMES_SKILL_DIR}/scripts/sanitize.py PATH."""

from __future__ import annotations

import sys
from pathlib import Path

# Allow running without pip install by adding this scripts/ directory to path.
_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from document_sanitizer.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
