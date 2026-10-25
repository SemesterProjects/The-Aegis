"""Small, dependency-free local configuration loader.

`.env` is a development convenience only. Existing process environment values
always win, so deployment secret managers and CI remain authoritative.
"""
from __future__ import annotations

import os
from pathlib import Path


def load_local_env(path: Path | None = None) -> None:
    """Load simple KEY=VALUE entries without overwriting process environment."""
    env_path = path or Path.cwd() / ".env"
    try:
        lines = env_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key.startswith("$env:"):
            key = key[5:].strip()
        value = value.strip().strip('"').strip("'")
        if key and key.replace("_", "").isalnum() and key not in os.environ:
            if value and not value.startswith(("Read-Host ", "$env:")):
                os.environ[key] = value
