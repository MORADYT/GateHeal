"""Persistent incident state store (cooldowns, flap detection, attempts) and unit lock."""

from __future__ import annotations

import fcntl
import os
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

from gateheal.actions import UNIT_NAME_RE
from gateheal.models import SCHEMA_VERSION, StrictStrTuple


class UnitLockError(RuntimeError):
    """Raised when a per-unit exclusive lock is already held by another controller."""


class IncidentAttemptState(BaseModel):
    """Per-incident attempt counters and action history keyed by incident_id (R4)."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    incident_id: str
    prior_diagnostic_attempts: Annotated[int, Field(ge=0)] = 0
    prior_recovery_attempts: Annotated[int, Field(ge=0)] = 0
    action_history: StrictStrTuple = ()


class UnitPersistentState(BaseModel):
    """Persisted unit-level cooldown and flap timestamps (plus seeded defaults)."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    unit_name: str
    prior_diagnostic_attempts: Annotated[int, Field(ge=0)] = 0
    prior_recovery_attempts: Annotated[int, Field(ge=0)] = 0
    action_history: StrictStrTuple = ()
    last_mutating_action_at_utc: str | None = None
    recent_mutation_timestamps_utc: StrictStrTuple = ()


class PersistentStateSnapshot(BaseModel):
    """Root JSON document persisted atomically across controller invocations."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    schema_version: str = SCHEMA_VERSION
    units: dict[str, UnitPersistentState] = Field(default_factory=dict)
    incidents: dict[str, IncidentAttemptState] = Field(default_factory=dict)
    consumed_approval_tokens: StrictStrTuple = ()


class PersistentStateStore:
    """Manages per-unit fcntl locks and atomic persistence of incident/unit state."""

    def __init__(self, state_file_path: Path) -> None:
        self._state_path = state_file_path.resolve()
        self._lock_dir = self._state_path.parent / "locks"
        self._global_lock_path = self._lock_dir / "_state_store_global.lock"
        self._state_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock_dir.mkdir(parents=True, exist_ok=True)

    @property
    def state_path(self) -> Path:
        """Return the resolved path to the persistent JSON state file."""
        return self._state_path

    @contextmanager
    def _global_state_lock(self) -> Iterator[None]:
        """Acquire a blocking exclusive lock for atomic read-modify-write of state file."""
        fd = os.open(str(self._global_lock_path), os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    @contextmanager
    def lock_unit(self, unit_name: str) -> Iterator[None]:
        """Acquire a non-blocking exclusive flock for a single systemd unit."""
        with self.lock_units((unit_name,)):
            yield

    @contextmanager
    def lock_units(self, unit_names: Sequence[str]) -> Iterator[None]:
        """Acquire non-blocking exclusive flocks in sorted order to prevent deadlock (R6)."""
        unique_sorted = sorted({u for u in unit_names if u})
        fds: list[int] = []
        try:
            for unit_name in unique_sorted:
                safe_name = (
                    unit_name
                    if UNIT_NAME_RE.fullmatch(unit_name)
                    else "invalid_unit.lock"
                )
                lock_file = self._lock_dir / f"{safe_name}.lock"
                fd = os.open(str(lock_file), os.O_CREAT | os.O_RDWR, 0o600)
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError as exc:
                    os.close(fd)
                    raise UnitLockError(
                        f"Unit {unit_name!r} is currently locked by another "
                        "concurrent recovery operation."
                    ) from exc
                fds.append(fd)
            yield
        finally:
            for fd in reversed(fds):
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                finally:
                    os.close(fd)

    def _load_snapshot_unlocked(self) -> PersistentStateSnapshot:
        if not self._state_path.is_file():
            return PersistentStateSnapshot()
        raw = self._state_path.read_text(encoding="utf-8")
        return PersistentStateSnapshot.model_validate_json(raw)

    def _save_snapshot_unlocked(self, snapshot: PersistentStateSnapshot) -> None:
        tmp_path = self._state_path.with_suffix(
            f".tmp.{os.getpid()}.{os.urandom(4).hex()}"
        )
        payload = snapshot.model_dump_json(indent=2)
        with tmp_path.open("w", encoding="utf-8") as f:
            f.write(payload + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, self._state_path)

    def load_snapshot(self) -> PersistentStateSnapshot:
        """Load the persistent state snapshot under the global state lock."""
        with self._global_state_lock():
            return self._load_snapshot_unlocked()

    def save_snapshot(self, snapshot: PersistentStateSnapshot) -> None:
        """Atomically write and fsync the persistent state snapshot under global lock."""
        with self._global_state_lock():
            self._save_snapshot_unlocked(snapshot)

    def compute_unit_runtime_counters(
        self,
        unit_name: str,
        *,
        now_utc: datetime,
        flap_window_sec: float,
        incident_id: str | None = None,
    ) -> tuple[UnitPersistentState, float | None, int]:
        """Return unit state (with per-incident counters), cooldown age, and flap count."""
        with self._global_state_lock():
            snap = self._load_snapshot_unlocked()
        unit_state = snap.units.get(
            unit_name, UnitPersistentState(unit_name=unit_name)
        )

        if incident_id is not None:
            inc_state = snap.incidents.get(incident_id)
            if inc_state is not None:
                unit_state = unit_state.model_copy(
                    update={
                        "prior_diagnostic_attempts": inc_state.prior_diagnostic_attempts,
                        "prior_recovery_attempts": inc_state.prior_recovery_attempts,
                        "action_history": inc_state.action_history,
                    }
                )
            else:
                unit_state = unit_state.model_copy(
                    update={
                        "prior_diagnostic_attempts": 0,
                        "prior_recovery_attempts": 0,
                        "action_history": (),
                    }
                )

        last_age_sec: float | None = None
        if unit_state.last_mutating_action_at_utc is not None:
            last_dt = datetime.fromisoformat(unit_state.last_mutating_action_at_utc)
            if last_dt.tzinfo is None:
                last_dt = last_dt.replace(tzinfo=UTC)
            last_age_sec = max(0.0, (now_utc - last_dt).total_seconds())

        recent_count = 0
        for ts_str in unit_state.recent_mutation_timestamps_utc:
            ts_dt = datetime.fromisoformat(ts_str)
            if ts_dt.tzinfo is None:
                ts_dt = ts_dt.replace(tzinfo=UTC)
            age = (now_utc - ts_dt).total_seconds()
            if 0.0 <= age <= flap_window_sec:
                recent_count += 1

        return unit_state, last_age_sec, recent_count

    def compute_runtime_counters(
        self,
        *,
        incident_id: str,
        unit_name: str,
        now_utc: datetime,
        flap_window_sec: float,
    ) -> tuple[UnitPersistentState, float | None, int]:
        """Return per-incident attempt state + per-unit cooldown/flap counters (R4 & R6)."""
        return self.compute_unit_runtime_counters(
            unit_name,
            now_utc=now_utc,
            flap_window_sec=flap_window_sec,
            incident_id=incident_id,
        )

    def seed_unit_state(
        self,
        unit_name: str,
        *,
        incident_id: str,
        prior_diagnostic_attempts: int = 0,
        prior_recovery_attempts: int = 0,
        action_history: tuple[str, ...] = (),
        last_mutating_action_at_utc: str | None = None,
        recent_mutation_timestamps_utc: tuple[str, ...] = (),
    ) -> None:
        """Initialize or reset unit state for an explicit incident_id."""
        if not incident_id or not incident_id.strip():
            raise ValueError("seed_unit_state requires a non-empty incident_id.")
        with self._global_state_lock():
            snap = self._load_snapshot_unlocked()
            units = dict(snap.units)
            units[unit_name] = UnitPersistentState(
                unit_name=unit_name,
                prior_diagnostic_attempts=prior_diagnostic_attempts,
                prior_recovery_attempts=prior_recovery_attempts,
                action_history=action_history,
                last_mutating_action_at_utc=last_mutating_action_at_utc,
                recent_mutation_timestamps_utc=recent_mutation_timestamps_utc,
            )
            incidents = dict(snap.incidents)
            if (
                prior_diagnostic_attempts > 0
                or prior_recovery_attempts > 0
                or action_history
            ):
                incidents[incident_id] = IncidentAttemptState(
                    incident_id=incident_id,
                    prior_diagnostic_attempts=prior_diagnostic_attempts,
                    prior_recovery_attempts=prior_recovery_attempts,
                    action_history=action_history,
                )
            else:
                incidents.pop(incident_id, None)

            self._save_snapshot_unlocked(
                PersistentStateSnapshot(
                    units=units,
                    incidents=incidents,
                    consumed_approval_tokens=snap.consumed_approval_tokens,
                )
            )

    def record_execution(
        self,
        *,
        unit_name: str,
        action_id: str,
        target_unit: str | None,
        is_mutating: bool,
        is_diagnostic: bool,
        now_utc: datetime,
        flap_window_sec: float,
        consumed_tokens: frozenset[str] | set[str],
        incident_id: str | None = None,
    ) -> UnitPersistentState:
        """Atomically persist per-incident attempts (R4) and mutated-unit cooldown/flap (R6, R7)."""
        with self._global_state_lock():
            snap = self._load_snapshot_unlocked()
            now_iso = now_utc.isoformat()
            mutated_unit = target_unit or unit_name

            incidents = dict(snap.incidents)
            prev_unit_alert = snap.units.get(
                unit_name, UnitPersistentState(unit_name=unit_name)
            )
            if incident_id is not None:
                prev_inc = incidents.get(
                    incident_id,
                    IncidentAttemptState(
                        incident_id=incident_id,
                        prior_diagnostic_attempts=prev_unit_alert.prior_diagnostic_attempts,
                        prior_recovery_attempts=prev_unit_alert.prior_recovery_attempts,
                        action_history=prev_unit_alert.action_history,
                    ),
                )
                diag_attempts = prev_inc.prior_diagnostic_attempts + (
                    1 if is_diagnostic else 0
                )
                rec_attempts = prev_inc.prior_recovery_attempts + (
                    1 if is_mutating else 0
                )
                new_history = (
                    (*prev_inc.action_history, f"{action_id}:{target_unit or ''}")
                    if (is_mutating or is_diagnostic)
                    else prev_inc.action_history
                )
                incidents[incident_id] = IncidentAttemptState(
                    incident_id=incident_id,
                    prior_diagnostic_attempts=diag_attempts,
                    prior_recovery_attempts=rec_attempts,
                    action_history=new_history,
                )
            else:
                diag_attempts = prev_unit_alert.prior_diagnostic_attempts + (
                    1 if is_diagnostic else 0
                )
                rec_attempts = prev_unit_alert.prior_recovery_attempts + (
                    1 if is_mutating else 0
                )
                new_history = (
                    (
                        *prev_unit_alert.action_history,
                        f"{action_id}:{target_unit or ''}",
                    )
                    if (is_mutating or is_diagnostic)
                    else prev_unit_alert.action_history
                )

            units = dict(snap.units)
            affected_units = (
                (mutated_unit,)
                if mutated_unit == unit_name
                else (mutated_unit, unit_name)
            )
            for u_key in affected_units:
                prev_u = units.get(u_key, UnitPersistentState(unit_name=u_key))
                kept_ts: list[str] = []
                for ts_str in prev_u.recent_mutation_timestamps_utc:
                    ts_dt = datetime.fromisoformat(ts_str)
                    if ts_dt.tzinfo is None:
                        ts_dt = ts_dt.replace(tzinfo=UTC)
                    if (now_utc - ts_dt).total_seconds() <= max(
                        flap_window_sec, 3600.0
                    ):
                        kept_ts.append(ts_str)

                last_mut = prev_u.last_mutating_action_at_utc
                if is_mutating and u_key == mutated_unit:
                    last_mut = now_iso
                    kept_ts.append(now_iso)

                u_diag = (
                    diag_attempts
                    if incident_id is None
                    else prev_u.prior_diagnostic_attempts
                )
                u_rec = (
                    rec_attempts
                    if incident_id is None
                    else prev_u.prior_recovery_attempts
                )
                u_hist = (
                    new_history if incident_id is None else prev_u.action_history
                )
                units[u_key] = UnitPersistentState(
                    unit_name=u_key,
                    prior_diagnostic_attempts=u_diag,
                    prior_recovery_attempts=u_rec,
                    action_history=u_hist,
                    last_mutating_action_at_utc=last_mut,
                    recent_mutation_timestamps_utc=tuple(kept_ts),
                )

            merged_tokens = tuple(
                sorted(
                    set(snap.consumed_approval_tokens) | set(consumed_tokens)
                )
            )
            self._save_snapshot_unlocked(
                PersistentStateSnapshot(
                    units=units,
                    incidents=incidents,
                    consumed_approval_tokens=merged_tokens,
                )
            )
            return units[mutated_unit].model_copy(
                update={
                    "prior_diagnostic_attempts": diag_attempts,
                    "prior_recovery_attempts": rec_attempts,
                    "action_history": new_history,
                }
            )
