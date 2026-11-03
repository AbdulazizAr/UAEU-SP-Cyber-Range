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

    def save(self) -> None:
        self.path.write_text(
            json.dumps({"project": self.project, "state": self.state, "history": self.history}, indent=2)
            + "\n",
            encoding="utf-8",
        )
