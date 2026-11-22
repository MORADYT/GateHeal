"""Threat -> control -> test traceability: registry loader, validator and Markdown renderer.

The registry (``docs/threat-test-map.yaml``) links each threat of ``docs/threat-model.md`` to the
source symbols that implement the control and to the tests that pin it. ``validate_registry``
turns the links into checkable claims: every file, symbol and test must exist, every anchor must
still be a phrase of the threat model, and every bullet of its section 3 must be covered by a
threat. ``render_markdown`` produces ``docs/threat-test-map.md`` so the prose never drifts from
the registry.
"""

from __future__ import annotations

import ast
import re
from collections import defaultdict
from collections.abc import Iterable
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

REGISTRY_RELATIVE_PATH = "docs/threat-test-map.yaml"
RENDERED_RELATIVE_PATH = "docs/threat-test-map.md"
THREAT_MODEL_RELATIVE_PATH = "docs/threat-model.md"

Zone = Literal["Z1", "Z2", "Z3", "Z4", "X"]
Status = Literal["mitigated", "partially-mitigated", "accepted-limitation"]

ZONE_TITLES: dict[str, str] = {
    "Z1": "Zone 1: isolated lab and host protection",
    "Z2": "Zone 2: observation and sanitisation",
    "Z3": "Zone 3: advisory plane (proposer and LLM)",
    "Z4": "Zone 4: policy, execution and oracle",
    "X": "Cross-cutting: evaluation and lab limits",
}

_THREAT_ID_RE = re.compile(r"^TM-\d{2}$")
_TEST_ID_RE = re.compile(r"^(tests/[A-Za-z0-9_./-]+\.py)::(test_[A-Za-z0-9_]+)$")


class Control(BaseModel):
    """A source location that implements a mitigation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str
    symbol: str | None = None
    contains: str | None = None


class Threat(BaseModel):
    """One threat with its controls, tests and documented residual risk."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    zone: Zone
    title: str
    status: Status
    doc_anchors: tuple[str, ...]
    controls: tuple[Control, ...] = ()
    tests: tuple[str, ...] = ()
    residual: str | None = None
    evidence: tuple[str, ...] = ()


class Registry(BaseModel):
    """The whole threat registry."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1]
    threat_model: str
    threats: tuple[Threat, ...] = Field(min_length=1)


def load_registry(repo_root: Path) -> Registry:
    """Load and schema-check the registry file."""
    raw = yaml.safe_load((repo_root / REGISTRY_RELATIVE_PATH).read_text(encoding="utf-8"))
    return Registry.model_validate(raw)


# --------------------------------------------------------------------------- source resolution


def _module_defines(tree: ast.Module, name: str) -> bool:
    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            if node.name == name:
                return True
        elif isinstance(node, ast.Assign):
            if any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
                return True
        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == name
        ):
            return True
    return False


def _class_defines(tree: ast.Module, class_name: str, member: str) -> bool:
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            for item in node.body:
                if isinstance(item, ast.FunctionDef | ast.AsyncFunctionDef):
                    if item.name == member:
                        return True
                elif isinstance(item, ast.Assign):
                    if any(isinstance(t, ast.Name) and t.id == member for t in item.targets):
                        return True
                elif (
                    isinstance(item, ast.AnnAssign)
                    and isinstance(item.target, ast.Name)
                    and item.target.id == member
                ):
                    return True
    return False


def python_symbol_exists(source_path: Path, symbol: str) -> bool:
    """True if ``symbol`` (``name`` or ``Class.member``) is defined at module/class level."""
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    if "." in symbol:
        class_name, _, member = symbol.partition(".")
        return _class_defines(tree, class_name, member)
    return _module_defines(tree, symbol)


def _test_functions(tree: ast.Module) -> dict[str, ast.FunctionDef]:
    found: dict[str, ast.FunctionDef] = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
            found[node.name] = node
        elif isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name.startswith("test_"):
                    found[item.name] = item
    return found


def collect_all_tests(repo_root: Path) -> dict[str, tuple[str, ...]]:
    """Map each ``tests/...py`` file to the names of its test functions."""
    result: dict[str, tuple[str, ...]] = {}
    for path in sorted((repo_root / "tests").rglob("test_*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        names = tuple(_test_functions(tree))
        result[path.relative_to(repo_root).as_posix()] = names
    return result


def _is_lab_module(tree: ast.Module) -> bool:
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "pytestmark" for t in node.targets)
            and "lab" in ast.unparse(node.value)
        ):
            return True
    return False


def flags_for_test(repo_root: Path, test_id: str) -> tuple[str, ...]:
    """Short flags for the rendered map: ``lab`` fixture/guest test, ``live`` skipped w/o guest."""
    match = _TEST_ID_RE.match(test_id)
    if match is None:
        return ()
    path = repo_root / match.group(1)
    if not path.is_file():
        return ()
    tree = ast.parse(path.read_text(encoding="utf-8"))
    flags: list[str] = []
    if _is_lab_module(tree):
        flags.append("lab")
    func = _test_functions(tree).get(match.group(2))
    if func is not None and any("skipif" in ast.unparse(d) for d in func.decorator_list):
        flags.append("live")
    return tuple(flags)


# --------------------------------------------------------------------------- threat model text


def threat_model_bullets(threat_model_text: str) -> list[str]:
    """Return the second-level bullets of section 3 (verified mitigations and limitations)."""
    bullets: list[str] = []
    in_section = False
    for line in threat_model_text.splitlines():
        if line.startswith("## "):
            in_section = line.startswith("## 3.")
            continue
        if in_section and line.startswith("  - "):
            bullets.append(line[4:].strip())
    return bullets


# --------------------------------------------------------------------------- validation


def _check_control(repo_root: Path, threat: Threat, control: Control) -> list[str]:
    errors: list[str] = []
    where = f"{threat.id}: control {control.path}"
    target = (repo_root / control.path).resolve()
    if not target.is_relative_to(repo_root.resolve()):
        return [f"{where} escapes the repository."]
    if not target.is_file():
        return [f"{where} does not exist."]
    if (control.symbol is None) == (control.contains is None):
        return [f"{where} needs exactly one of 'symbol' or 'contains'."]
    if control.symbol is not None:
        if target.suffix != ".py":
            errors.append(f"{where}: 'symbol' is only valid for Python files.")
        elif not python_symbol_exists(target, control.symbol):
            errors.append(f"{where} does not define {control.symbol!r}.")
    elif control.contains is not None and control.contains not in target.read_text(
        encoding="utf-8"
    ):
        errors.append(f"{where} no longer contains {control.contains!r}.")
    return errors


def validate_registry(repo_root: Path, registry: Registry | None = None) -> list[str]:
    """Return every consistency error (empty list means the registry is sound)."""
    reg = registry if registry is not None else load_registry(repo_root)
    errors: list[str] = []
    model_path = repo_root / reg.threat_model
    if not model_path.is_file():
        return [f"threat model {reg.threat_model} does not exist."]
    model_text = model_path.read_text(encoding="utf-8")

    seen_ids: set[str] = set()
    all_tests = collect_all_tests(repo_root)
    for threat in reg.threats:
        if not _THREAT_ID_RE.match(threat.id):
            errors.append(f"{threat.id}: id must look like TM-07.")
        if threat.id in seen_ids:
            errors.append(f"{threat.id}: duplicate id.")
        seen_ids.add(threat.id)

        if not threat.doc_anchors:
            errors.append(f"{threat.id}: needs at least one doc_anchor.")
        for anchor in threat.doc_anchors:
            if anchor not in model_text:
                errors.append(
                    f"{threat.id}: doc_anchor not found in {reg.threat_model}: {anchor!r}"
                )

        for control in threat.controls:
            errors.extend(_check_control(repo_root, threat, control))

        if len(set(threat.tests)) != len(threat.tests):
            errors.append(f"{threat.id}: a test is listed twice.")
        for test_id in threat.tests:
            match = _TEST_ID_RE.match(test_id)
            if match is None:
                errors.append(f"{threat.id}: malformed test id {test_id!r}.")
            elif match.group(2) not in all_tests.get(match.group(1), ()):
                errors.append(f"{threat.id}: test does not exist: {test_id}")

        for item in threat.evidence:
            doc_path, sep, phrase = item.partition(": ")
            target = repo_root / doc_path
            if not sep or not target.is_file():
                errors.append(
                    f"{threat.id}: evidence {item!r} must be '<file>: <phrase>' of a file."
                )
            elif phrase not in target.read_text(encoding="utf-8"):
                errors.append(f"{threat.id}: evidence phrase not found: {item!r}")

        if threat.status in ("mitigated", "partially-mitigated"):
            if not threat.controls:
                errors.append(f"{threat.id}: {threat.status} needs at least one control.")
            if not threat.tests:
                errors.append(f"{threat.id}: {threat.status} needs at least one test.")
        elif not threat.tests and not threat.evidence:
            errors.append(f"{threat.id}: accepted-limitation needs a test or evidence.")
        if threat.status != "mitigated" and not (threat.residual or "").strip():
            errors.append(f"{threat.id}: {threat.status} needs a residual-risk statement.")

    anchors = [a for t in reg.threats for a in t.doc_anchors]
    for bullet in threat_model_bullets(model_text):
        if not any(a in bullet for a in anchors):
            errors.append(f"threat-model bullet is not covered by any threat: {bullet[:90]!r}")
    return errors


# --------------------------------------------------------------------------- rendering


def _short(text: str, limit: int = 100) -> str:
    flat = " ".join(text.replace("[cite: 6]", "").split())
    return flat if len(flat) <= limit else flat[: limit - 3].rstrip() + "..."


def _control_line(control: Control) -> str:
    what = control.symbol if control.symbol is not None else f'text "{control.contains}"'
    return f"`{control.path}` - `{what}`" if control.symbol else f"`{control.path}` - {what}"


def _threats_by_zone(threats: Iterable[Threat]) -> dict[str, list[Threat]]:
    grouped: dict[str, list[Threat]] = defaultdict(list)
    for threat in threats:
        grouped[threat.zone].append(threat)
    return grouped


def render_markdown(repo_root: Path, registry: Registry | None = None) -> str:
    """Render the registry as the Markdown shown in ``docs/threat-test-map.md``."""
    loaded = registry if registry is not None else load_registry(repo_root)
    zone_order = {zone: index for index, zone in enumerate(ZONE_TITLES)}
    reg = loaded.model_copy(
        update={"threats": tuple(sorted(loaded.threats, key=lambda t: (zone_order[t.zone], t.id)))}
    )
    mapped = {t for threat in reg.threats for t in threat.tests}
    model_text = (repo_root / reg.threat_model).read_text(encoding="utf-8")

    out: list[str] = [
        "# GateHeal threat-to-test map",
        "",
        f"Generated from `{REGISTRY_RELATIVE_PATH}` by `lab/scripts/wp8_threat_map.py --write`; "
        "do not edit by hand. "
        "`tests/security/test_wp8_threat_map.py` fails if a listed file, symbol or test is "
        f"missing, if a bullet of section 3 of `{reg.threat_model}` has no threat, or if this "
        "file is stale.",
        "",
        "Status: **mitigated** = control present and pinned by tests; **partially-mitigated** = "
        "control present and tested, with a stated residual risk; **accepted-limitation** = not "
        "mitigated by design, current behaviour pinned. Test flags: `lab` = needs lab fixtures; "
        "`live` = skipped unless `GATEHEAL_RUN_LAB_TESTS=1` and a guest is booted.",
        "",
        "A test listed here shows the control is exercised, not that the threat is absent: "
        "each residual-risk line states what the tests do not cover.",
        "",
        "## 1. Summary",
        "",
        "| ID | Zone | Threat | Status | Controls | Tests |",
        "|---|---|---|---|---:|---:|",
    ]
    for threat in reg.threats:
        out.append(
            f"| {threat.id} | {threat.zone} | {_short(threat.title, 90)} | {threat.status} "
            f"| {len(threat.controls)} | {len(threat.tests)} |"
        )
    counts = {s: sum(1 for t in reg.threats if t.status == s) for s in get_statuses()}
    out += [
        "",
        f"{len(reg.threats)} threats: "
        + ", ".join(f"{counts[s]} {s}" for s in get_statuses())
        + f". {len(mapped)} distinct tests are mapped to a threat.",
        "",
        "## 2. Threats",
    ]
    grouped = _threats_by_zone(reg.threats)
    for zone in ZONE_TITLES:
        if zone not in grouped:
            continue
        out += ["", f"### {ZONE_TITLES[zone]}"]
        for threat in grouped[zone]:
            out += ["", f"#### {threat.id}: {threat.title}", "", f"Status: **{threat.status}**", ""]
            out.append("Threat-model anchors: " + "; ".join(f"“{a}”" for a in threat.doc_anchors))
            out += ["", "Controls:"]
            out += [f"- {_control_line(c)}" for c in threat.controls] or ["- none"]
            out += ["", "Tests:"]
            for test_id in threat.tests:
                flags = flags_for_test(repo_root, test_id)
                suffix = f" [{', '.join(flags)}]" if flags else ""
                out.append(f"- `{test_id}`{suffix}")
            if not threat.tests:
                out.append("- none (see evidence)")
            if threat.evidence:
                out += ["", "Evidence: " + "; ".join(f"`{e}`" for e in threat.evidence)]
            if threat.residual:
                out += ["", f"Residual risk: {' '.join(threat.residual.split())}"]

    out += [
        "",
        f"## 3. Coverage of `{reg.threat_model}` section 3",
        "",
        "| Bullet | Threats |",
        "|---|---|",
    ]
    for bullet in threat_model_bullets(model_text):
        ids = [t.id for t in reg.threats if any(a in bullet for a in t.doc_anchors)]
        out.append(f"| {_short(bullet.replace('|', '/'), 80)} | {', '.join(ids)} |")

    out += [
        "",
        "## 4. Tests not mapped to a threat",
        "",
        "Tests that check functionality, statistics or experiment plumbing rather than a "
        "documented threat are not listed here, so adding one does not make this file stale. "
        "Run `lab/scripts/wp8_threat_map.py --unmapped` for the list.",
    ]
    out.append("")
    return "\n".join(out)


def get_statuses() -> tuple[str, ...]:
    """Status labels in display order."""
    return ("mitigated", "partially-mitigated", "accepted-limitation")


def unmapped_tests(repo_root: Path, registry: Registry | None = None) -> dict[str, tuple[str, ...]]:
    """Tests (by file) that no threat references: functional, statistical or plumbing tests."""
    reg = registry if registry is not None else load_registry(repo_root)
    mapped = {t for threat in reg.threats for t in threat.tests}
    result: dict[str, tuple[str, ...]] = {}
    for file_path, names in collect_all_tests(repo_root).items():
        left = tuple(n for n in names if f"{file_path}::{n}" not in mapped)
        if left:
            result[file_path] = left
    return result
