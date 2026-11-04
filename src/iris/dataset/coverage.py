"""Coverage reporting over a dataset (decisions.md: random sampling plus a coverage report
replaces the pairwise covering design in v1).

The report counts, across all episodes, how well the data exercises each decision type and
the attack surface: data tiers, D1 verdicts, attack families, ATT&CK techniques and
tactics, detectability classes, D2 priorities, the controls D4 recommends and how many
D6 flaws appear. Given a universe of expected families/techniques it also lists the gaps
(what never appears), so the factory knows what to record next.

Everything here is a pure aggregation over small per-episode records, so a coverage report
can be produced from the hidden keys without rebuilding any package.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from iris.dataset import DATASET_VERSION


@dataclass
class EpisodeCoverage:
    tier: str  # context | train | gold
    verdict: str  # malicious | benign
    family: str | None = None
    techniques: tuple[str, ...] = ()
    tactics: tuple[str, ...] = ()
    detectability: str | None = None
    d2_priority: str | None = None
    d4_controls: tuple[str, ...] = ()
    d6_flaws: int = 0


def from_keys(
    d1: dict[str, Any],
    d2: dict[str, Any],
    d4: dict[str, Any],
    tier: str,
    d6_flaws: int = 0,
) -> EpisodeCoverage:
    return EpisodeCoverage(
        tier=tier,
        verdict=d1.get("verdict", "benign"),
        family=d1.get("family"),
        techniques=tuple(d1.get("techniques", [])),
        tactics=tuple(d1.get("tactics", [])),
        detectability=d1.get("detectability"),
        d2_priority=d2.get("priority"),
        d4_controls=tuple(r["control_id"] for r in d4.get("recommendations", [])),
        d6_flaws=d6_flaws,
    )


@dataclass
class CoverageUniverse:
    """What the dataset is expected to exercise, for gap detection."""

    families: frozenset[str] = frozenset()
    techniques: frozenset[str] = frozenset()


@dataclass
class CoverageReport:
    version: str
    episodes: int
    by_tier: dict[str, int]
    by_verdict: dict[str, int]
    by_family: dict[str, int]
    by_technique: dict[str, int]
    by_tactic: dict[str, int]
    by_detectability: dict[str, int]
    by_priority: dict[str, int]
    controls_recommended: dict[str, int]
    decision_presence: dict[str, int]
    d6_flaws_total: int
    missing_families: list[str] = field(default_factory=list)
    missing_techniques: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "episodes": self.episodes,
            "by_tier": self.by_tier,
            "by_verdict": self.by_verdict,
            "by_family": self.by_family,
            "by_technique": self.by_technique,
            "by_tactic": self.by_tactic,
            "by_detectability": self.by_detectability,
            "by_priority": self.by_priority,
            "controls_recommended": self.controls_recommended,
            "decision_presence": self.decision_presence,
            "d6_flaws_total": self.d6_flaws_total,
            "missing_families": self.missing_families,
            "missing_techniques": self.missing_techniques,
        }


def _counts(values: Any) -> dict[str, int]:
    return dict(sorted(Counter(values).items()))


@dataclass
class D6CoverageReport:
    """Coverage of the context tier (D6 only): read straight from the hidden D6 keys.

    The context tier carries no telemetry and no D1/D2/D4 keys, so the general
    ``coverage_report`` (which iterates D1 files) sees nothing. This report reads the
    per-episode D6 keys that context packages DO have and summarises the GRC flaw task:
    how many episodes, how many are clean, and the spread across detectability classes,
    flaw modules, GRC collections and harm. It needs no Docker and no fragment library.
    """

    version: str
    packages: int
    episodes: int
    clean_episodes: int
    flawed_episodes: int
    flaws_total: int
    by_detectability: dict[str, int]
    by_module: dict[str, int]
    by_collection: dict[str, int]
    by_harm: dict[str, int]
    by_level: dict[str, int]
    missing_modules: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "tier": "context",
            "packages": self.packages,
            "episodes": self.episodes,
            "clean_episodes": self.clean_episodes,
            "flawed_episodes": self.flawed_episodes,
            "flaws_total": self.flaws_total,
            "by_detectability": self.by_detectability,
            "by_module": self.by_module,
            "by_collection": self.by_collection,
            "by_harm": self.by_harm,
            "by_level": self.by_level,
            "missing_modules": self.missing_modules,
        }


def context_coverage_report(
    keys: list[dict[str, Any]],
    *,
    packages: int = 0,
    expected_modules: frozenset[str] = frozenset(),
) -> D6CoverageReport:
    """Aggregate a list of D6 key dicts (one per episode) into a context-tier report.

    Each key is the parsed contents of ``hidden/evaluation_key/d6/<episode>.json``:
    ``{"clean": bool, "flaws": [{"detectability", "module", "collection", "harm",
    "level", ...}], ...}``. Pure aggregation; no I/O.
    """

    clean = sum(1 for k in keys if k.get("clean"))
    flaws = [f for k in keys for f in k.get("flaws", [])]
    modules = [f.get("module") for f in flaws if f.get("module")]
    return D6CoverageReport(
        version=DATASET_VERSION,
        packages=packages,
        episodes=len(keys),
        clean_episodes=clean,
        flawed_episodes=len(keys) - clean,
        flaws_total=len(flaws),
        by_detectability=_counts(f.get("detectability") for f in flaws if f.get("detectability")),
        by_module=_counts(modules),
        by_collection=_counts(f.get("collection") for f in flaws if f.get("collection")),
        by_harm=_counts(f.get("harm") for f in flaws if f.get("harm")),
        by_level=_counts(f.get("level") for f in flaws if f.get("level")),
        missing_modules=sorted(expected_modules - set(modules)),
    )


def coverage_report(items: list[EpisodeCoverage], universe: CoverageUniverse | None = None) -> CoverageReport:
    universe = universe or CoverageUniverse()
    families = [i.family for i in items if i.family]
    techniques = [t for i in items for t in i.techniques]
    presence = {
        "D1": sum(1 for i in items if i.verdict == "malicious"),
        "D2": sum(1 for i in items if i.d2_priority),
        "D4": sum(1 for i in items if i.d4_controls),
        "D6": sum(1 for i in items if i.d6_flaws),
    }
    return CoverageReport(
        version=DATASET_VERSION,
        episodes=len(items),
        by_tier=_counts(i.tier for i in items),
        by_verdict=_counts(i.verdict for i in items),
        by_family=_counts(families),
        by_technique=_counts(techniques),
        by_tactic=_counts(t for i in items for t in i.tactics),
        by_detectability=_counts(
            i.detectability for i in items if i.detectability and i.detectability != "n/a"
        ),
        by_priority=_counts(i.d2_priority for i in items if i.d2_priority),
        controls_recommended=_counts(c for i in items for c in i.d4_controls),
        decision_presence=presence,
        d6_flaws_total=sum(i.d6_flaws for i in items),
        missing_families=sorted(universe.families - set(families)),
        missing_techniques=sorted(universe.techniques - set(techniques)),
    )
