"""WP9: the thesis docs stay readable and their commands stay real."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
DOCS = [ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md"))]
GENERATED = {"threat-test-map.md"}
HAND_WRITTEN = [p for p in DOCS if p.name not in GENERATED]


def _fenced_blocks(text: str) -> list[str]:
    return re.findall(r"```[a-z]*\n(.*?)```", text, flags=re.DOTALL)


@pytest.mark.parametrize("path", HAND_WRITTEN, ids=lambda p: p.name)
def test_no_citation_residue_and_balanced_fences(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    assert "[cite:" not in text, f"{path.name}: stray citation tag"
    fences = [ln for ln in text.splitlines() if ln.lstrip().startswith("```")]
    assert len(fences) % 2 == 0, f"{path.name}: unclosed code fence"


@pytest.mark.parametrize("path", HAND_WRITTEN, ids=lambda p: p.name)
def test_relative_links_resolve(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    for target in re.findall(r"\]\(([^)#\s]+)\)", text):
        if "://" in target:
            continue
        assert (path.parent / target).exists(), f"{path.name}: broken link {target}"


def test_documented_command_flags_exist_in_the_code() -> None:
    sources = "\n".join(
        p.read_text(encoding="utf-8")
        for p in [ROOT / "src/gateheal/cli.py", *sorted((ROOT / "lab/scripts").glob("*.py"))]
    )
    seen: set[str] = set()
    for path in (ROOT / "README.md", ROOT / "docs/lab-runbook.md"):
        for block in _fenced_blocks(path.read_text(encoding="utf-8")):
            if "gateheal" not in block and "lab/scripts" not in block:
                continue
            seen.update(re.findall(r"(?<![\w-])(--[a-z][a-z0-9-]+)", block))
    # ssh/qemu options in the runbook blocks that are not GateHeal flags
    seen -= {"--scope"}
    assert seen, "no documented flags found"
    missing = sorted(f for f in seen if f'"{f}"' not in sources)
    assert not missing, f"documented flags not defined in the code: {missing}"


def test_documented_scripts_exist() -> None:
    text = (ROOT / "README.md").read_text(encoding="utf-8") + (
        ROOT / "docs/lab-runbook.md"
    ).read_text(encoding="utf-8")
    for rel in set(re.findall(r"\b(lab/[\w./-]+\.(?:py|sh))\b", text)):
        assert (ROOT / rel).is_file(), f"documented script missing: {rel}"
