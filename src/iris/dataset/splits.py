"""Assign enterprise groups to in-distribution or out-of-distribution (OOD) sets.

Rules (decisions.md "Splits"):

* Each group belongs to exactly one OOD set; precedence is
  topology > industry > attack family > GRC style.
* The sampler blocks held-out attack families and GRC styles from all in-distribution
  groups (:func:`indist_blocklist` reports what to exclude).
* Each OOD set needs at least 15 Gold groups or its results are only *indicative*.

The splitter is pure and deterministic: it reads group profiles and a held-out config and
never touches disk, so the whole plan can be reviewed before any data is built.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from iris.dataset import DATASET_VERSION

IN_DISTRIBUTION = "in_distribution"
MIN_GOLD_PER_OOD = 15
#: precedence order; the first dimension a group is held out on decides its OOD set.
PRECEDENCE = ("topology", "industry", "attack_family", "grc_style")


@dataclass(frozen=True)
class GroupProfile:
    group_id: str
    topology: str
    industry: str
    families: tuple[str, ...]
    grc_style: str
    gold: bool = False  # True if this group has (or will have) a live Gold set


@dataclass(frozen=True)
class OodConfig:
    """Held-out dimension values. A group matching any of these on the highest-precedence
    dimension is assigned to that dimension's OOD set."""

    topologies: frozenset[str] = frozenset()
    industries: frozenset[str] = frozenset()
    families: frozenset[str] = frozenset()
    grc_styles: frozenset[str] = frozenset()

    def set_name(self, dimension: str) -> str:
        return f"ood_{dimension}"


@dataclass
class SplitAssignment:
    group_id: str
    split: str  # IN_DISTRIBUTION or ood_<dimension>
    dimension: str | None  # the held-out dimension, or None for in-distribution
    reason: str | None = None


def assign(profile: GroupProfile, ood: OodConfig) -> SplitAssignment:
    held_families = set(profile.families) & ood.families
    checks: dict[str, tuple[bool, str]] = {
        "topology": (profile.topology in ood.topologies, profile.topology),
        "industry": (profile.industry in ood.industries, profile.industry),
        "attack_family": (bool(held_families), ",".join(sorted(held_families))),
        "grc_style": (profile.grc_style in ood.grc_styles, profile.grc_style),
    }
    for dimension in PRECEDENCE:
        hit, value = checks[dimension]
        if hit:
            return SplitAssignment(
                profile.group_id, ood.set_name(dimension), dimension, f"{dimension}={value}"
            )
    return SplitAssignment(profile.group_id, IN_DISTRIBUTION, None, None)


@dataclass
class OodSet:
    name: str
    dimension: str
    group_ids: list[str] = field(default_factory=list)
    gold_groups: int = 0

    @property
    def indicative(self) -> bool:
        return self.gold_groups < MIN_GOLD_PER_OOD


@dataclass
class Splits:
    version: str
    assignments: list[SplitAssignment]
    in_distribution: list[str]
    ood_sets: dict[str, OodSet]
    indist_blocked_families: list[str]
    indist_blocked_grc_styles: list[str]

    def warnings(self) -> list[str]:
        return [
            f"{s.name}: only {s.gold_groups} Gold groups (<{MIN_GOLD_PER_OOD}); results are indicative"
            for s in self.ood_sets.values()
            if s.indicative
        ]

    def to_dict(self) -> dict[str, object]:
        return {
            "version": self.version,
            "in_distribution": self.in_distribution,
            "ood_sets": {
                name: {
                    "dimension": s.dimension,
                    "group_ids": s.group_ids,
                    "gold_groups": s.gold_groups,
                    "indicative": s.indicative,
                }
                for name, s in self.ood_sets.items()
            },
            "sampler_blocklist": {
                "attack_families": self.indist_blocked_families,
                "grc_styles": self.indist_blocked_grc_styles,
            },
            "warnings": self.warnings(),
        }


def indist_blocklist(ood: OodConfig) -> tuple[list[str], list[str]]:
    """Attack families and GRC styles the sampler must not use in in-distribution groups."""
    return sorted(ood.families), sorted(ood.grc_styles)


def build_splits(profiles: list[GroupProfile], ood: OodConfig) -> Splits:
    assignments = [assign(p, ood) for p in profiles]
    by_id = {p.group_id: p for p in profiles}
    in_dist: list[str] = []
    ood_sets: dict[str, OodSet] = {}
    for a in assignments:
        if a.split == IN_DISTRIBUTION:
            in_dist.append(a.group_id)
            continue
        oset = ood_sets.setdefault(a.split, OodSet(a.split, a.dimension or ""))
        oset.group_ids.append(a.group_id)
        if by_id[a.group_id].gold:
            oset.gold_groups += 1
    blocked_fams, blocked_styles = indist_blocklist(ood)
    return Splits(
        version=DATASET_VERSION,
        assignments=assignments,
        in_distribution=sorted(in_dist),
        ood_sets={k: ood_sets[k] for k in sorted(ood_sets)},
        indist_blocked_families=blocked_fams,
        indist_blocked_grc_styles=blocked_styles,
    )
