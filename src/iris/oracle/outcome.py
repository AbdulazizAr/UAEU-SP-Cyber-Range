"""Normalised per-episode activity and its outcome (hidden plane).

Both the live recorder (``plan_truth`` from :mod:`iris.live.activity`) and the composer
(``activity_truth`` from :mod:`iris.compose.episode`) describe what happened in an episode.
This module reduces either to one :class:`EpisodeActivity`, resolves each malicious item
to the target enterprise's own weakness and asset, and states the outcome truth the
oracle keys and the evaluator are scored against.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from iris.contracts.spec import ScenarioSpec
from iris.core.vclock import iso_z, parse_iso
from iris.live.attacks import FAMILIES

OUTCOME_VERSION = "outcome-0.1.0"


@dataclass
class ActivityItem:
    label: str  # benign | malicious
    family: str
    technique: str | None = None
    outcome: str = "n/a"  # success | failed | n/a
    weakness_module: str | None = None
    expected_rules: list[int] = field(default_factory=list)
    asset_id: str | None = None  # resolved target asset (malicious only)
    enabling_control: str | None = None  # from the target's weakness ledger
    criticality: int = 1


@dataclass
class EpisodeActivity:
    episode_id: str
    as_of: datetime  # the episode's virtual start (the context checkpoint)
    items: list[ActivityItem]

    @property
    def malicious(self) -> list[ActivityItem]:
        return [i for i in self.items if i.label == "malicious"]

    @property
    def compromised(self) -> bool:
        return any(i.outcome == "success" for i in self.malicious)


def _resolve(item: ActivityItem, spec: ScenarioSpec) -> ActivityItem:
    """Fill ``asset_id``/``enabling_control``/``criticality`` from the target's weakness
    ledger, for a malicious item that names a weakness module."""
    if item.label != "malicious" or not item.weakness_module:
        return item
    wk = next((w for w in spec.weaknesses if w.module == item.weakness_module), None)
    if wk is None:
        return item
    asset = next((a for a in spec.assets if a.asset_id == wk.asset_id), None)
    item.asset_id = wk.asset_id
    item.enabling_control = wk.enabling_control
    item.criticality = asset.true_criticality if asset else 1
    return item


def from_composed(spec: ScenarioSpec, activity_truth: dict[str, Any]) -> EpisodeActivity:
    items = []
    for p in activity_truth.get("placements", []):
        items.append(
            _resolve(
                ActivityItem(
                    label=p.get("label", "benign"),
                    family=p.get("family", ""),
                    technique=p.get("technique"),
                    outcome=p.get("outcome", "n/a"),
                    weakness_module=p.get("weakness_module"),
                    expected_rules=list(p.get("expected_rules", [])),
                ),
                spec,
            )
        )
    return EpisodeActivity(activity_truth["episode_id"], parse_iso(activity_truth["virtual_start"]), items)


def from_plan_truth(
    spec: ScenarioSpec, episode_id: str, as_of: datetime, plan_truth: list[dict[str, Any]]
) -> EpisodeActivity:
    """Normalise a live episode's ``plan_truth`` (actions carry the resolved target asset
    and ``expect_rules``; map weakness ids back to their module via the spec)."""
    by_id = {w.weakness_id: w for w in spec.weaknesses}
    items = []
    for a in plan_truth:
        wid = a.get("weakness_id")
        wk = by_id.get(wid) if isinstance(wid, str) else None
        asset = next((x for x in spec.assets if x.asset_id == a.get("target_asset")), None)
        items.append(
            ActivityItem(
                label=a.get("label", "benign"),
                family=a.get("family") or "",
                technique=a.get("technique"),
                outcome="success" if a.get("label") == "malicious" else "n/a",
                weakness_module=wk.module if wk else None,
                expected_rules=list(a.get("expect_rules", [])),
                asset_id=a.get("target_asset"),
                enabling_control=wk.enabling_control if wk else None,
                criticality=asset.true_criticality if asset else 1,
            )
        )
    return EpisodeActivity(episode_id, as_of, items)


def family_tactic(family: str) -> str | None:
    meta = FAMILIES.get(family)
    return meta["tactic"] if meta else None


def outcome_key(activity: EpisodeActivity) -> dict[str, Any]:
    """Hidden outcome truth for one episode."""
    mal = activity.malicious
    return {
        "version": OUTCOME_VERSION,
        "episode_id": activity.episode_id,
        "as_of": iso_z(activity.as_of),
        "compromised": activity.compromised,
        "malicious_count": len(mal),
        "families": sorted({i.family for i in mal if i.family}),
        "techniques": sorted({i.technique for i in mal if i.technique}),
        "affected_assets": sorted({i.asset_id for i in mal if i.asset_id}),
        "succeeded": sorted({i.weakness_module for i in mal if i.outcome == "success" and i.weakness_module}),
    }
