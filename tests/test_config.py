from __future__ import annotations

import os
from pathlib import Path

from aegis_core.config import load_local_env


def test_local_env_loads_missing_values_without_overwriting_process_env(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / ".env"
    path.write_text("EXAMPLE_VALUE=from-file\nEXISTING_VALUE=from-file\nINVALID-KEY=ignored\n", encoding="utf-8")
    monkeypatch.delenv("EXAMPLE_VALUE", raising=False)
    monkeypatch.setenv("EXISTING_VALUE", "from-process")
    load_local_env(path)
    assert os.environ["EXAMPLE_VALUE"] == "from-file"
    assert os.environ["EXISTING_VALUE"] == "from-process"
    assert "INVALID-KEY" not in os.environ


def test_local_env_accepts_powershell_assignments_but_not_commands(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / ".env"
    path.write_text(
        '$env:AEGIS_LLM_PROVIDER = "openai-compatible"\n'
        '$env:AEGIS_LLM_API_KEY = Read-Host "Paste key"\n',
        encoding="utf-8",
    )
    monkeypatch.delenv("AEGIS_LLM_PROVIDER", raising=False)
    monkeypatch.delenv("AEGIS_LLM_API_KEY", raising=False)
    load_local_env(path)
    assert os.environ["AEGIS_LLM_PROVIDER"] == "openai-compatible"
    assert "AEGIS_LLM_API_KEY" not in os.environ
