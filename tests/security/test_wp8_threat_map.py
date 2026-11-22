"""WP8: the threat -> control -> test registry is consistent with the code, tests and docs."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from gateheal.models import PolicyRejectionCode
from gateheal.threatmap import (
    RENDERED_RELATIVE_PATH,
    Control,
    Registry,
    Threat,
    collect_all_tests,
    flags_for_test,
    load_registry,
    python_symbol_exists,
    render_markdown,
    threat_model_bullets,
    unmapped_tests,
    validate_registry,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


def _registry() -> Registry:
    return load_registry(REPO_ROOT)


def _with(threat_id: str, **update: object) -> Registry:
    reg = _registry()
    threats = tuple(
        t.model_copy(update=update) if t.id == threat_id else t for t in reg.threats
    )
    return reg.model_copy(update={"threats": threats})


def _errors(reg: Registry) -> list[str]:
    return validate_registry(REPO_ROOT, reg)


# ----------------------------------------------------------------------------- the real registry


def test_registry_is_consistent_with_code_tests_and_threat_model() -> None:
    assert validate_registry(REPO_ROOT) == []


def test_rendered_map_is_up_to_date() -> None:
    on_disk = (REPO_ROOT / RENDERED_RELATIVE_PATH).read_text(encoding="utf-8")
    assert on_disk == render_markdown(REPO_ROOT), (
        "docs/threat-test-map.md is stale: "
        "run `uv run python lab/scripts/wp8_threat_map.py --write`"
    )


def test_every_threat_is_backed_by_a_test_that_runs_without_a_live_guest() -> None:
    """A mapping resting only on tests that skip without a VM would prove nothing offline."""
    for threat in _registry().threats:
        runnable = [t for t in threat.tests if "live" not in flags_for_test(REPO_ROOT, t)]
        assert runnable or threat.evidence, f"{threat.id} has only live-guest tests"


def test_every_policy_rejection_code_is_named_by_a_test() -> None:
    """A rejection code no test mentions can be deleted or broken unnoticed."""
    sources = "\n".join(
        (REPO_ROOT / path).read_text(encoding="utf-8") for path in collect_all_tests(REPO_ROOT)
    )
    missing = [c.name for c in PolicyRejectionCode if c.name not in sources]
    assert missing == []


def test_threat_model_section_3_is_parsed() -> None:
    text = (REPO_ROOT / "docs/threat-model.md").read_text(encoding="utf-8")
    assert len(threat_model_bullets(text)) >= 13


def test_rendered_map_states_residual_risk_and_lab_flags() -> None:
    text = render_markdown(REPO_ROOT)
    assert "Residual risk:" in text
    assert "[lab, live]" in text
    assert "distinct tests are mapped to a threat" in text
    assert "--unmapped" in text


def test_script_check_mode_passes_and_detects_a_stale_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    spec = importlib.util.spec_from_file_location(
        "wp8_threat_map", REPO_ROOT / "lab" / "scripts" / "wp8_threat_map.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.main(["--repo-root", str(REPO_ROOT)]) == 0
    assert "Threat map OK" in capsys.readouterr().out

    # A copy with a stale rendering is rejected, and --write repairs it.
    for rel in ("docs", "src", "tests", "lab", "configs"):
        src = REPO_ROOT / rel
        dst = tmp_path / rel
        dst.mkdir(parents=True, exist_ok=True)
        _copy_tree(src, dst)
    (tmp_path / RENDERED_RELATIVE_PATH).write_text("stale\n", encoding="utf-8")
    assert module.main(["--repo-root", str(tmp_path)]) == 1
    assert module.main(["--repo-root", str(tmp_path), "--write"]) == 0
    assert module.main(["--repo-root", str(tmp_path)]) == 0


def _copy_tree(src: Path, dst: Path) -> None:
    for item in src.rglob("*"):
        if "__pycache__" in item.parts or ".pytest_cache" in item.parts:
            continue
        target = dst / item.relative_to(src)
        if item.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(item.read_bytes())


# ----------------------------------------------------------------------------- the checker itself


def test_checker_flags_a_missing_test() -> None:
    reg = _with("TM-01", tests=("tests/security/test_phase2_safety.py::test_no_such_test",))
    assert any("test does not exist" in e for e in _errors(reg))


def test_checker_flags_a_malformed_test_id() -> None:
    reg = _with(
        "TM-01", tests=("test_phase2_safety.py::test_local_transport_rejects_host_environment",)
    )
    assert any("malformed test id" in e for e in _errors(reg))


def test_checker_flags_a_missing_symbol_file_and_text() -> None:
    bad_symbol = Control(path="src/gateheal/transport.py", symbol="NoSuchClass.method")
    bad_file = Control(path="src/gateheal/nope.py", symbol="x")
    bad_text = Control(path="lab/scripts/lab_guard.sh", contains="THIS_TEXT_IS_NOT_THERE")
    both = Control(
        path="src/gateheal/transport.py", symbol="HostSafetyViolationError", contains="x"
    )
    escape = Control(path="../outside.py", symbol="x")
    errors = _errors(_with("TM-01", controls=(bad_symbol, bad_file, bad_text, both, escape)))
    assert any("does not define 'NoSuchClass.method'" in e for e in errors)
    assert any("src/gateheal/nope.py does not exist" in e for e in errors)
    assert any("no longer contains" in e for e in errors)
    assert any("exactly one of" in e for e in errors)
    assert any("escapes the repository" in e for e in errors)


def test_checker_flags_an_anchor_that_left_the_threat_model() -> None:
    errors = _errors(_with("TM-01", doc_anchors=("a phrase the threat model never had",)))
    assert any("doc_anchor not found" in e for e in errors)


def test_checker_requires_controls_tests_and_residual_by_status() -> None:
    assert any("needs at least one test" in e for e in _errors(_with("TM-01", tests=())))
    assert any("needs at least one control" in e for e in _errors(_with("TM-01", controls=())))
    assert any("residual-risk" in e for e in _errors(_with("TM-07", residual=None)))
    accepted = _with("TM-33", tests=(), evidence=())
    assert any("needs a test or evidence" in e for e in _errors(accepted))


def test_checker_flags_duplicate_ids_and_duplicate_tests() -> None:
    reg = _registry()
    duplicated = reg.model_copy(update={"threats": (*reg.threats, reg.threats[0])})
    assert any("duplicate id" in e for e in _errors(duplicated))
    first = reg.threats[0]
    doubled = _with(first.id, tests=(first.tests[0], first.tests[0]))
    assert any("listed twice" in e for e in _errors(doubled))
    assert any("must look like" in e for e in _errors(_with("TM-01", id="T1")))


def test_checker_flags_a_bad_evidence_reference() -> None:
    errors = _errors(_with("TM-09", evidence=("docs/experiment-design.md: no such phrase",)))
    assert any("evidence phrase not found" in e for e in errors)
    errors = _errors(_with("TM-09", evidence=("docs/missing.md: x",)))
    assert any("must be '<file>: <phrase>'" in e for e in errors)


def test_checker_flags_a_new_unmapped_limitation(tmp_path: Path) -> None:
    text = (REPO_ROOT / "docs/threat-model.md").read_text(encoding="utf-8")
    new_bullet = "  - **Brand New Limitation:** nobody mapped this one.\n"
    head, sep, tail = text.partition("\n## 4.")  # keep the bullet inside section 3
    extended = head.rstrip("\n") + "\n" + new_bullet + (sep + tail if sep else "")
    assert text.index("## 3.") > text.index("## 2.")
    model = tmp_path / "threat-model.md"
    model.write_text(extended, encoding="utf-8")
    reg = _registry().model_copy(update={"threat_model": str(model)})
    errors = validate_registry(REPO_ROOT, reg)
    assert any("not covered by any threat" in e and "Brand New Limitation" in e for e in errors)


def test_python_symbol_resolution_covers_functions_classes_methods_and_constants() -> None:
    path = REPO_ROOT / "src/gateheal/collector.py"
    assert python_symbol_exists(path, "redact_secrets_text")
    assert python_symbol_exists(path, "IncidentCollector")
    assert python_symbol_exists(path, "IncidentCollector.collect_simulated")
    assert python_symbol_exists(path, "UNTRUSTED_LOG_PREFIX")
    assert not python_symbol_exists(path, "IncidentCollector.no_such_method")
    assert not python_symbol_exists(path, "no_such_name")
    assert not python_symbol_exists(path, "redact_secrets_text.inner")


def test_registry_model_rejects_unknown_fields_and_statuses() -> None:
    with pytest.raises(ValueError):
        Threat.model_validate(
            {
                "id": "TM-99",
                "zone": "Z1",
                "title": "x",
                "status": "fixed",
                "doc_anchors": ["a"],
            }
        )
    with pytest.raises(ValueError):
        Control.model_validate({"path": "a", "symbol": "b", "surprise": 1})


def test_checker_reports_a_missing_threat_model_file() -> None:
    reg = _registry().model_copy(update={"threat_model": "docs/no-such-threat-model.md"})
    assert _errors(reg) == ["threat model docs/no-such-threat-model.md does not exist."]


def test_unmapped_tests_are_the_complement_of_the_mapped_ones(
    capsys: pytest.CaptureFixture[str],
) -> None:
    reg = _registry()
    mapped = {t for threat in reg.threats for t in threat.tests}
    left = unmapped_tests(REPO_ROOT, reg)
    everything = {
        f"{path}::{name}" for path, names in collect_all_tests(REPO_ROOT).items() for name in names
    }
    listed = {f"{path}::{name}" for path, names in left.items() for name in names}
    assert listed == everything - mapped
    assert "tests/security/test_wp8_threat_map.py" in left  # the checker itself is not a threat
    assert "tests/unit/test_wp6_oracle_and_stats.py" in left

    spec = importlib.util.spec_from_file_location(
        "wp8_threat_map", REPO_ROOT / "lab" / "scripts" / "wp8_threat_map.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.main(["--repo-root", str(REPO_ROOT), "--unmapped"]) == 0
    assert "tests are not mapped to a threat" in capsys.readouterr().out
