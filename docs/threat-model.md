# GateHeal Security & Threat Model (Phase 2 Baseline)

## 1. Trust Boundaries
GateHeal enforces four explicit trust zones:
1. **Zone 1 (Isolated Linux Lab):** Disposable QEMU/KVM Ubuntu VM (or optional `systemd-nspawn` container) running target `systemd` services (`lab-redis.service`, `lab-api.service`, `lab-worker.service`).
2. **Zone 2 (Observation & Sanitization):** `IncidentCollector` enforces line limits (`max_log_lines = 50`), payload limits (`max_evidence_bytes = 16384`), and regex secret redaction before constructing a frozen `IncidentRecord`.
3. **Zone 3 (Advisory Plane):** Deterministic `DiagnosisEngine` (and optional future LLM/multi-agent modules). Possesses zero subprocess execution authority.
4. **Zone 4 (Independent Policy & Execution Plane):** `PolicyEngine`, `MinimalImpactSelector`, `ExecutionController`, `OutcomeVerifier`, and `AuditRecorder`.

## 2. Host Workstation Protection
- `LocalLabSubprocessTransport` inspects `platform.release()` and `GATEHEAL_INSIDE_LAB`. If invoked on the Omarchy host workstation, it raises `HostSafetyViolationError` before spawning any process.
- Host-side CLI runs default to `SimulatedLabTransport` (`--transport simulated`) or isolated VM SSH (`--transport ssh`).

## 3. Verified Mitigations vs. Known Limitations
- **Command Injection:** Mitigated via closed `ActionId` enum lookup, strict unit regex (`^[a-z0-9_-]+\.service$`), inventory allowlisting, and `shell=False` argument vectors.
- **Hung Subprocesses:** Mitigated via `start_new_session=True` (`setsid`) and `os.killpg` (`SIGTERM` followed by `SIGKILL`), marking timed-out executions as `OUTCOME_UNCERTAIN`.
- **Silent Post-Restart Crashes & Collateral Damage:** Mitigated by `OutcomeVerifier`, which compares pre/post `n_restarts` across the soak window and audits all declared `downstream_dependents`.
- **Known Limitations:** `killpg` terminates processes in the spawned session group but does not automatically revert partial filesystem writes or stop detached daemons reparented by `systemd` outside the session unless wrapped in a transient cgroup scope (to be tested inside the QEMU/KVM guest in Phase 3).
