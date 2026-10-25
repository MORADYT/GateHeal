"""WP5 test verifying all python and shell scripts compile and parse cleanly."""

from __future__ import annotations

import py_compile
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.lab


def test_lab_python_scripts_compile() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    for p in (repo_root / "lab").rglob("*.py"):
        if "__pycache__" in p.parts:
            continue
        py_compile.compile(str(p), doraise=True)


def test_lab_shell_scripts_parse() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    for p in (repo_root / "lab").rglob("*.sh"):
        res = subprocess.run(["bash", "-n", str(p)], capture_output=True, text=True, check=False)
        assert res.returncode == 0, f"Shell syntax error in {p}: {res.stderr}"
