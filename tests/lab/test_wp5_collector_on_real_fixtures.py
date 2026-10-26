"""F3: Offline test on real captured VM fixtures using IncidentCollector plus DiagnosisEngine."""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

import pytest

from gateheal.collector import IncidentCollector
from gateheal.config import load_config
from gateheal.diagnosis import DiagnosisEngine
from gateheal.lab_bringup import SmokeMatrixExpectation, build_wp5_smoke_expectations
from gateheal.transport import TransportResult

pytestmark = pytest.mark.lab


def _int_from_mapping(
    mapping: dict[str, object], key: str, default: int = 0
) -> int:
    raw = mapping.get(key, default)
    if isinstance(raw, bool):
        return int(raw)
    if isinstance(raw, int):
        return raw
    if isinstance(raw, str) and raw.strip().lstrip("-").isdigit():
        return int(raw.strip())
    return default


class _FixtureCommandTransport:
    """Transport keyed by argv returning captured raw outputs from real VM fixtures."""

    def __init__(
        self, shows: dict[str, object], probes: dict[str, object]
    ) -> None:
        self._shows = shows
        self._probes = probes

    def run(self, argv: Sequence[str], timeout_sec: float) -> TransportResult:
        _ = timeout_sec
        cmd = tuple(argv)
        if cmd[:2] == ("cat", "/proc/uptime"):
            return TransportResult(
                exit_code=0,
                duration_sec=0.01,
                stdout_excerpt=str(
                    self._probes.get("uptime", "50000.0 40000.0\n")
                ),
            )
        if cmd[:2] == ("systemctl", "show"):
            u = str(cmd[2])
            return TransportResult(
                exit_code=0,
                duration_sec=0.01,
                stdout_excerpt=str(self._shows[u]),
            )
        if "--validate-config" in cmd:
            return TransportResult(
                exit_code=_int_from_mapping(
                    self._probes, "validate_config_exit", 0
                ),
                duration_sec=0.01,
            )
        if cmd[0] == "curl":
            curl_out = str(self._probes.get("curl_healthz", ""))
            is_http_200 = "HTTP=200" in curl_out or '"status": "ok"' in curl_out
            return TransportResult(
                exit_code=0 if is_http_200 else 22,
                duration_sec=0.01,
                stdout_excerpt=curl_out,
            )
        if "--check-tcp" in cmd:
            port = cmd[-1]
            key = "tcp_6379_exit" if port == "6379" else "tcp_8081_exit"
            return TransportResult(
                exit_code=_int_from_mapping(self._probes, key, 0),
                duration_sec=0.01,
            )
        if cmd[0] == "journalctl":
            unit_idx = cmd.index("-u") + 1 if "-u" in cmd else -1
            unit = str(cmd[unit_idx]) if 0 < unit_idx < len(cmd) else ""
            jnl_out = (
                str(self._probes.get("journal_api", ""))
                if unit == "lab-api.service"
                else ""
            )
            return TransportResult(
                exit_code=0,
                duration_sec=0.01,
                stdout_excerpt=jnl_out,
            )
        return TransportResult(exit_code=0, duration_sec=0.01)


@pytest.mark.parametrize(
    "exp",
    build_wp5_smoke_expectations(),
    ids=lambda e: e.scenario_id,
)
def test_wp5_collector_on_real_fixtures(exp: SmokeMatrixExpectation) -> None:
    """F3: Feed captured VM outputs via IncidentCollector.collect_from_transport."""
    repo_root = Path(__file__).resolve().parents[2]
    cfg = load_config(repo_root / "configs" / "phase1_lab.yaml")
    fixture_path = (
        repo_root
        / "tests"
        / "lab"
        / "fixtures"
        / "vm_captured_systemd_facts.json"
    )
    assert fixture_path.is_file()

    payload = json.loads(fixture_path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    raw_ver = payload.get("fixture_version", 1)
    fix_ver = raw_ver if isinstance(raw_ver, int) else 1

    scen_shows = payload.get("scenarios_systemctl_show", {})
    scen_probes = payload.get("scenarios_probes", {})
    assert isinstance(scen_shows, dict)
    assert isinstance(scen_probes, dict)

    scen_id = exp.scenario_id
    if scen_id not in scen_shows or scen_id not in scen_probes:
        if fix_ver >= 2:
            pytest.fail(
                f"Fixture v{fix_ver} is missing raw show/probe data for {scen_id}"
            )
        pytest.skip(
            f"Fixture v{fix_ver} lacks raw show/probe capture for {scen_id}; "
            "re-capture with wp5_capture_and_verify.py"
        )

    unit_map = scen_shows[scen_id]
    probes = scen_probes[scen_id]
    assert isinstance(unit_map, dict)
    assert isinstance(probes, dict)

    transport = _FixtureCommandTransport(unit_map, probes)
    collector = IncidentCollector(cfg)
    diagnosis_engine = DiagnosisEngine(cfg)

    incident = collector.collect_from_transport(
        incident_id=f"replay-{scen_id.lower()}",
        target_unit="lab-api.service",
        transport=transport,
        prior_recovery_attempts=exp.seed_prior_recovery_attempts,
        action_history=exp.seed_action_history,
    )
    diag = diagnosis_engine.diagnose(incident)
    assert diag.fault_class in exp.expected_fault_classes, (
        f"Scenario {scen_id} diagnosed {diag.fault_class}, "
        f"expected one of {exp.expected_fault_classes}"
    )
