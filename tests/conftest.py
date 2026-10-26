"""Global pytest fixtures ensuring hermetic temporary artifact directories."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _isolated_artifacts_dir(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    """Redirect GATEHEAL_ARTIFACTS_DIR to tmp_path so tests never write to repo artifacts/."""
    hermetic_dir = tmp_path / "gateheal_test_artifacts"
    hermetic_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("GATEHEAL_ARTIFACTS_DIR", str(hermetic_dir))
    return hermetic_dir
