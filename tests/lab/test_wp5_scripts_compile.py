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
        res = subprocess.run(
            ["bash", "-n", str(p)], capture_output=True, text=True, check=False
        )
        assert res.returncode == 0, f"Shell syntax error in {p}: {res.stderr}"


def test_lab_shell_scripts_have_no_top_level_local() -> None:
    """`local` outside a function aborts the script under `set -e` (WP5 boot-vm regression)."""
    repo_root = Path(__file__).resolve().parents[2]
    for p in (repo_root / "lab").rglob("*.sh"):
        depth = 0
        for lineno, raw in enumerate(p.read_text().splitlines(), start=1):
            line = raw.strip()
            if line.startswith("#"):
                continue
            if line.endswith("() {") or line.endswith("(){"):
                depth += 1
                continue
            if depth and line == "}":
                depth -= 1
                continue
            if depth == 0 and line.startswith("local "):
                raise AssertionError(f"{p}:{lineno}: `local` outside a function")


def test_lab_scripts_never_pin_harness_key_to_loopback() -> None:
    """QEMU hostfwd shows the guest 10.0.2.2, so from="127.0.0.1" breaks root SSH."""
    repo_root = Path(__file__).resolve().parents[2]
    lab = repo_root / "lab"
    for p in [*lab.rglob("*.sh"), *lab.rglob("*.py")]:
        for lineno, line in enumerate(p.read_text().splitlines(), start=1):
            assert 'from="127.0.0.1"' not in line.replace('\\"', '"'), f"{p}:{lineno}"
