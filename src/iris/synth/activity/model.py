"""Activity model: what the range controller "did", expressed only as the telemetry it leaves
(builder brief file 05 §1).

An :class:`Activity` is benign or malicious and produces a list of :class:`Footprint` objects —
observable effects (a raw log line, a network flow, a FIM change, an auth/app event). Attacks
are represented by their footprints, never by runnable exploit code or payloads: all the
detection/GRC model needs is the evidence a step leaves, and the repo stays free of attack
tooling (decisions.md "Attack realism boundary").

Every footprint carries its ``activity_id`` so evidence links (activity -> telemetry) are exact
by construction (brief file 05, T-A3). ``background`` footprints carry ``activity_id=None``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

Kind = Literal["raw_log", "flow", "fim", "auth_event", "app_event", "agent_event"]
Outcome = Literal["success", "partial", "failed", "blocked", "n/a"]


@dataclass
class Footprint:
    """One observable effect on one sensor at one instant."""

    kind: Kind
    ts: datetime
    data: dict[str, Any]
    activity_id: str | None = None  # None = background chatter
    asset_id: str | None = None  # host the host-evidence was collected on (None for pure flows)


@dataclass
class Activity:
    activity_id: str
    kind: Literal["benign", "malicious"]
    template_id: str  # hidden
    family: str  # "" for benign, F1..F9 for malicious
    actor_ref: str  # identity_id, external node id, or persona id
    actor_profile: str  # opportunistic|targeted|insider|automated|benign_user|benign_admin|machine
    source_ip: str
    target_asset: str | None
    identity_id: str | None
    service_id: str | None
    start: datetime
    end: datetime
    technique: str | None = None  # ATT&CK id (malicious), validated against pinned catalog
    tactic: str | None = None
    outcome: Outcome = "n/a"
    weakness_module: str | None = None
    enabling_control: str | None = None
    expected_rules: list[int] = field(default_factory=list)
    campaign_id: str | None = None
    parent_activity_id: str | None = None
    footprints: list[Footprint] = field(default_factory=list)
    is_hard_negative: bool = False

    def truth_row(self) -> dict[str, Any]:
        """Hidden activity-truth row (brief file 05 §7)."""
        return {
            "activity_id": self.activity_id,
            "kind": self.kind,
            "template_id": self.template_id,
            "family": self.family or None,
            "actor_profile": self.actor_profile,
            "source_ip": self.source_ip,
            "target_asset": self.target_asset,
            "identity_id": self.identity_id,
            "technique": self.technique,
            "tactic": self.tactic,
            "outcome": self.outcome,
            "weakness_module": self.weakness_module,
            "enabling_control": self.enabling_control,
            "expected_rules": sorted(self.expected_rules),
            "campaign_id": self.campaign_id,
            "parent_activity_id": self.parent_activity_id,
            "is_hard_negative": self.is_hard_negative,
            "malicious": self.kind == "malicious",
            "label_source": "generator_fact",
            "review_status": "unreviewed",
        }
