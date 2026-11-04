"""Compose a whole training scenario: one generated enterprise, every episode stitched
from library fragments.

Episode purpose drives selection:

* ``baseline`` / ``quiet`` / ``post_change``: benign business activity only.
* ``attack_stage``: benign activity plus fragments of one attack family whose weakness
  precondition this enterprise meets (from :func:`iris.live.attacks.applicable_families`).

The result is training-only until it passes the Part 8 drift tests; validation and test
sets are always live Gold.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from iris.compose import COMPOSE_VERSION
from iris.compose.episode import ComposedEpisode, compose_episode
from iris.compose.select import ReuseLedger, choose
from iris.contracts.spec import ScenarioSpec
from iris.core.hashing import episode_id as make_eid
from iris.core.hashing import scenario_id as make_scn
from iris.core.seeds import SeedSet
from iris.fragments.model import Fragment
from iris.generator.secrets import Secrets, scenario_secrets
from iris.live.attacks import applicable_families


@dataclass
class ComposedScenario:
    scenario_id: str
    group_id: str
    allowed_groups: list[str]
    episodes: list[ComposedEpisode]
    fragment_refs: list[str] = field(default_factory=list)

    def visible_telemetry(self) -> dict[str, list[dict[str, Any]]]:
        """All episodes' visible records merged per telemetry file (package-level view)."""
        merged: dict[str, list[dict[str, Any]]] = {}
        for ep in self.episodes:
            for vfile, rows in ep.visible.items():
                merged.setdefault(vfile, []).extend(rows)
        return merged


def _benign_wanted(rng: Any) -> int:
    return int(rng.randint(3, 8))


def _attack_episode(index: int, n_episodes: int, rng: Any) -> bool:
    """Which episodes carry an attack. The first episode is a clean baseline; the second
    always carries one (so a multi-episode scenario is never all-benign when fragments
    exist); later episodes carry one with moderate probability."""
    if index <= 1 or n_episodes < 2:
        return False
    if index == 2:
        return True
    return bool(rng.random() < 0.5)


def compose_scenario(
    spec: ScenarioSpec,
    library: list[Fragment],
    allowed_groups: set[str],
    seeds: SeedSet | None = None,
    *,
    secrets: Secrets | None = None,
    ledger: ReuseLedger | None = None,
    scenario_id: str | None = None,
    archives_retained: bool = True,
    blocked_families: set[str] | None = None,
) -> ComposedScenario:
    seeds = seeds or SeedSet.from_dict(spec.seeds.model_dump())
    secrets = secrets or scenario_secrets(spec)
    ledger = ledger or ReuseLedger()
    scn = scenario_id or make_scn({"seeds": seeds.to_dict()})
    blocked = blocked_families or set()
    # families this enterprise can exercise, minus any held out of in-distribution data
    families = [f for f in applicable_families(spec) if f not in blocked]
    n = len(spec.episodes)

    episodes: list[ComposedEpisode] = []
    used_fragments: set[str] = set()
    for ep in spec.episodes:
        eid = make_eid(scn, ep.index)
        benign_rng = seeds.stream("traffic", f"compose.benign.{ep.index}")
        attack_rng = seeds.stream("attack", f"compose.attack.{ep.index}")
        place_rng = seeds.stream("traffic", f"compose.place.{ep.index}")

        selected = choose(
            library,
            spec,
            secrets,
            allowed_groups,
            ledger,
            _benign_wanted(benign_rng),
            benign_rng,
            label="benign",
        )
        if families and _attack_episode(ep.index, n, attack_rng):
            # try applicable families in a seeded order until one actually places a fragment,
            # so an episode marked as an attack is not silently benign when a family's library
            # is empty for this enterprise.
            order = list(families)
            attack_rng.shuffle(order)
            for fam in order:
                picks = choose(
                    library,
                    spec,
                    secrets,
                    allowed_groups,
                    ledger,
                    attack_rng.randint(1, 2),
                    attack_rng,
                    label="malicious",
                    family=fam,
                )
                if picks:
                    selected += picks
                    break
        place_rng.shuffle(selected)
        composed = compose_episode(
            eid, ep.virtual_start, ep.virtual_end, selected, place_rng, archives_retained=archives_retained
        )
        episodes.append(composed)
        used_fragments.update(p.fragment_id for p in composed.placements)

    return ComposedScenario(
        scenario_id=scn,
        group_id=seeds.group_id(),
        allowed_groups=sorted(allowed_groups),
        episodes=episodes,
        fragment_refs=sorted(used_fragments),
    )


def scenario_truth(composed: ComposedScenario) -> dict[str, Any]:
    """Hidden ``truth/composition.json``: provenance for a composed scenario."""
    return {
        "version": COMPOSE_VERSION,
        "scenario_id": composed.scenario_id,
        "group_id": composed.group_id,
        "allowed_groups": composed.allowed_groups,
        "fragment_refs": composed.fragment_refs,
        "episodes": [ep.activity_truth for ep in composed.episodes],
    }
