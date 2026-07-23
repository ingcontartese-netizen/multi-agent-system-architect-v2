from __future__ import annotations

import os
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def pytest_configure() -> None:
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
