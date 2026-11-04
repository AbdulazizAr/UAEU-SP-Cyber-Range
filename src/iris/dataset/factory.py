"""Fragment factory: decide which groups and families still need recording, then drive the
live range to record them.

The *plan* is pure and coverage-driven: given each candidate group's profile, the split
assignment and the fragments already in the library, it asks for more only where a family
is below its per-group target, and it never schedules a held-out family into an
in-distribution group. The *driver* loops the plan and calls a recorder for each target;
the recorder is injected so the planner and loop are testable without Docker (the default
builds, deploys and records a real range on a host that has Docker).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from iris.dataset import DATASET_VERSION
from iris.dataset.splits import IN_DISTRIBUTION, Splits


@dataclass(frozen=True)
class GroupCandidate:
    group_id: str
    master_seed: int
    families: tuple[str, ...]  # families this group's weakness ledger can exercise
    recipes: tuple[str, ...]


@dataclass
class FactoryTarget:
    group_id: str
    master_seed: int
    families: list[str]  # families still short of target in this group
    recipes: list[str]
    needed: dict[str, int] = field(default_factory=dict)  # family -> how many more


@dataclass
class FactoryPlan:
    version: str
    targets: list[FactoryTarget]

    @property
    def total_fragments_wanted(self) -> int:
        return sum(sum(t.needed.values()) for t in self.targets)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "targets": [
                {
                    "group_id": t.group_id,
                    "master_seed": t.master_seed,
                    "families": t.families,
                    "recipes": t.recipes,
                    "needed": t.needed,
                }
                for t in self.targets
            ],
            "total_fragments_wanted": self.total_fragments_wanted,
        }


def _split_of(group_id: str, splits: Splits) -> tuple[str, str | None]:
    for a in splits.assignments:
        if a.group_id == group_id:
            return a.split, a.dimension
    return IN_DISTRIBUTION, None


def plan_factory(
    candidates: list[GroupCandidate],
    splits: Splits,
    have: dict[tuple[str, str], int],
    per_family_target: int = 3,
) -> FactoryPlan:
    """``have`` maps ``(group_id, family)`` to the count already in the library.

    A family is scheduled for a group only when it is below ``per_family_target`` and is not
    a family held out of in-distribution groups by the split."""
    blocked = set(splits.indist_blocked_families)
    targets: list[FactoryTarget] = []
    for cand in candidates:
        split, _dim = _split_of(cand.group_id, splits)
        needed: dict[str, int] = {}
        for fam in cand.families:
            if split == IN_DISTRIBUTION and fam in blocked:
                continue  # a held-out family must not appear in in-distribution data
            short = per_family_target - have.get((cand.group_id, fam), 0)
            if short > 0:
                needed[fam] = short
        if needed:
            targets.append(
                FactoryTarget(cand.group_id, cand.master_seed, sorted(needed), list(cand.recipes), needed)
            )
    return FactoryPlan(DATASET_VERSION, targets)


@dataclass
class FactoryResult:
    targets_run: int
    fragments_recorded: int
    per_group: dict[str, int] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)


def run_factory(
    plan: FactoryPlan,
    record_fn: Callable[[FactoryTarget], int],
) -> FactoryResult:
    """Drive the plan. ``record_fn`` records fragments for one target and returns how many
    it produced; it is where the live range is built, deployed, recorded and torn down.
    Errors are captured per group so one failed build does not abort the whole factory."""
    result = FactoryResult(targets_run=0, fragments_recorded=0)
    for target in plan.targets:
        try:
            n = record_fn(target)
        except Exception as exc:  # a live build can fail (Docker, subnet, health); keep going
            result.errors[target.group_id] = str(exc)
            continue
        result.targets_run += 1
        result.fragments_recorded += n
        result.per_group[target.group_id] = n
    return result
