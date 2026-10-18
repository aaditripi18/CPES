"""Filesystem locations. The data root is git-ignored (``data/`` in .gitignore)."""

from __future__ import annotations

import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DASHBOARD_ROOT = REPO_ROOT / "dashboard"
CONFIGS = REPO_ROOT / "configs"
ANALYSIS = REPO_ROOT / "analysis"
MODELS = DASHBOARD_ROOT / "models"
WEB_DIST = DASHBOARD_ROOT / "web" / "dist"


def data_root() -> Path:
    """Run/upload store. Overridable so tests never touch real records."""

    root = Path(os.environ.get("CPES_DASHBOARD_DATA", DASHBOARD_ROOT / "data"))
    root.mkdir(parents=True, exist_ok=True)
    return root
