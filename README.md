# GateHeal

Policy-gated, minimal-impact, risk-aware self-healing platform for Linux services.

> **Status:** Phase 1 Deterministic Prototype (`GateHeal` is a provisional working name pending release trademark/collision verification).

## Safety Invariants
1. **Strict Separation of Concerns:** Diagnosis, action recommendation, and action authorization/execution are isolated modules.
2. **Independent Policy Gate:** All candidate actions must pass deterministic validation before execution.
3. **Lab Isolation:** Destructive fault injection and recovery tests run strictly inside an isolated QEMU/KVM guest (or optional `systemd-nspawn` container), never on the host workstation.

## Quickstart (Development Environment)
```bash
uv sync
uv run ruff check src tests
uv run mypy src tests
uv run pytest -v
uv run gateheal validate-config --config configs/phase1_lab.yaml
uv run gateheal list-actions
