"""F3: Offline test on real captured VM fixtures using IncidentCollector plus DiagnosisEngine."""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

import pytest

from gateheal.collector import IncidentCollector, parse_systemctl_show
from gateheal.config import load_config
from gateheal.diagnosis import DiagnosisEngine
from gateheal.models import FaultClass
from gateheal.transport import TransportResult

pytestmark = pytest.mark.lab


class _FixtureCommandTransport:
    """Transport keyed by argv returning captured raw outputs from real VM fixtures."""

    def __init__(self, shows: dict[str, str], probes: dict[str, object] | None = None) -> None:
        self._shows = shows
        self._probes = probes or {}

    def run(self, argv: Sequence[str], timeout_sec: float) -> TransportResult:
        _ = timeout_sec
        cmd = tuple(argv)
        if cmd[:2] == ("cat", "/proc/uptime"):
            return TransportResult(
                exit_code=0,
                duration_sec=0.01,
                stdout_excerpt=str(self._probes.get("uptime", "50000.0 40000.0\n")),
            )
        if cmd[:2] == ("systemctl", "show"):
            u = cmd[2]
            excerpt = self._shows.get(u, "")
            return TransportResult(
                exit_code=0,
                duration_sec=0.01,
                stdout_excerpt=str(excerpt),
            )
        if "--validate-config" in cmd:
            return TransportResult(
                exit_code=int(self._probes.get("validate_config_exit", 0)),
                duration_sec=0.01,
            )
        if cmd[0] == "curl":
            return TransportResult(
                exit_code=0 if "200" in str(self._probes.get("curl_healthz", "")) else 22,
                duration_sec=0.01,
                stdout_excerpt=str(self._probes.get("curl_healthz", "")),
            )
        if "--check-tcp" in cmd:
            port = cmd[-1]
            code = (
                int(self._probes.get("tcp_6379_exit", 0))
                if port == "6379"
                else int(self._probes.get("tcp_8081_exit", 0))
            )
            return TransportResult(exit_code=code, duration_sec=0.01)
        return TransportResult(exit_code=0, duration_sec=0.01)


def test_wp5_collector_on_real_fixtures() -> None:
    """F3: Feed captured VM outputs via IncidentCollector.collect_from_transport."""
    repo_root = Path(__file__).resolve().parents[2]
    cfg = load_config(repo_root / "configs" / "phase1_lab.yaml")
    fixture_path = repo_root / "tests" / "lab" / "fixtures" / "vm_captured_systemd_facts.json"
    assert fixture_path.is_file()

    payload = json.loads(fixture_path.read_text(encoding="utf-8"))
    scen_shows = payload.get("scenarios_systemctl_show", {})
    scen_probes = payload.get("scenarios_probes", {})
    assert isinstance(scen_shows, dict)

    expected_fault_classes = {
        "S0_HEALTHY_CONTROL": FaultClass.HEALTHY,
        "S1_SERVICE_CRASH": FaultClass.PROCESS_CRASH,
        "S2_INVALID_CONFIG": FaultClass.INVALID_CONFIG,
        "S3_DEPENDENCY_FAILURE": FaultClass.DEPENDENCY_FAILURE,
        "S4_PERSISTENT_FAILURE": FaultClass.PROCESS_CRASH,
        "S5_COLLATERAL_TRAP": FaultClass.DEGRADED_RUNNING,
        "S5B_COLLATERAL_FORCED_RESTART": FaultClass.DEGRADED_RUNNING,
    }

    collector = IncidentCollector(cfg)
    diagnosis_engine = DiagnosisEngine(cfg)

    for scen_id, expected_fault in expected_fault_classes.items():
        if scen_id not in scen_shows:
            pytest.skip(f"Fixture lacks captured systemctl show output for scenario {scen_id}")

        unit_map = scen_shows[scen_id]
        probes = scen_probes.get(scen_id, {})
        assert isinstance(unit_map, dict)

        transport = _FixtureCommandTransport(unit_map, probes)
        target_unit = "lab-api.service" if scen_id != "S3_DEPENDENCY_FAILURE" else "lab-redis.service"

        incident = collector.collect_from_transport(
            incident_id=f"replay-{scen_id.lower()}",
            target_unit=target_unit,
            transport=transport,
        )
        diag = diagnosis_engine.diagnose(incident)
        assert diag.fault_class == expected_fault, (
            f"Scenario {scen_id} diagnosed {diag.fault_class}, expected {expected_fault}"
        )
