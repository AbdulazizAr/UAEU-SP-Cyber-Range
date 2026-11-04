"""Pipeline state machine for one live run, persisted as ``state.json`` in the run dir."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from iris.core.vclock import iso_z, real_utc_now

TRANSITIONS: dict[str, set[str]] = {
    "PLANNED": {"BUILDING", "DEPLOYING", "FAILED"},
    "BUILDING": {"DEPLOYING", "FAILED"},
    "DEPLOYING": {"CHECKING", "FAILED", "TEARING_DOWN"},
    "CHECKING": {"HEALTHY", "UNHEALTHY", "FAILED"},
    "HEALTHY": {"TEARING_DOWN", "KEPT"},
    "UNHEALTHY": {"TEARING_DOWN", "KEPT"},
    "FAILED": {"TEARING_DOWN"},
    "TEARING_DOWN": {"TORN_DOWN", "FAILED"},
    "TORN_DOWN": set(),
    "KEPT": {"TEARING_DOWN"},
}


class StateError(RuntimeError):
    pass


@dataclass
class RunState:
    path: Path
    project: str
    state: str = "PLANNED"
    history: list[dict[str, Any]] = field(default_factory=list)

    def to(self, new: str, note: str = "") -> None:
        if new not in TRANSITIONS.get(self.state, set()):
            raise StateError(f"illegal transition {self.state} -> {new}")
        self.history.append({"from": self.state, "to": new, "at_real": iso_z(real_utc_now()), "note": note})
        self.state = new
        self.save()

    def begin_teardown(self, note: str = "") -> None:
        """Move to TEARING_DOWN from any state, routing via FAILED when a direct
        transition is not allowed (e.g. an interrupted or failed health check leaves the
        run in CHECKING). Idempotent: a no-op once teardown has started or finished, so it
        is always safe to call from a ``finally`` block."""
        if self.state in ("TEARING_DOWN", "TORN_DOWN"):
            return
        if "TEARING_DOWN" not in TRANSITIONS.get(self.state, set()):
            if "FAILED" in TRANSITIONS.get(self.state, set()):
                self.to("FAILED", note=note or "forced teardown")
            else:
                raise StateError(f"cannot reach TEARING_DOWN from {self.state}")
        self.to("TEARING_DOWN", note=note)

    def save(self) -> None:
        self.path.write_text(
            json.dumps({"project": self.project, "state": self.state, "history": self.history}, indent=2)
            + "\n",
            encoding="utf-8",
        )
