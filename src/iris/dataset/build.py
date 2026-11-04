"""Build a full dataset: compose a training package per target enterprise from the fragment
library, then report the splits and the coverage.

Record-and-compose in practice: fragments are recorded once from a few live Gold groups and
remapped onto many freshly generated target enterprises. A target therefore composes from
the library's *source* groups (``allowed_groups``), not from itself, and a malicious
fragment is only placed where the target's own weakness ledger has the enabling module, so
every composed label stays truthful. Validation and test sets are always live Gold, so this
builder emits the ``train`` tier only.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from iris.compose.select import ReuseLedger
from iris.contracts.spec import ScenarioSpec
from iris.core.seeds import SeedSet
from iris.dataset import DATASET_VERSION
from iris.dataset.coverage import (
    CoverageReport,
    CoverageUniverse,
    EpisodeCoverage,
    coverage_report,
    from_keys,
)
from iris.dataset.splits import GroupProfile, OodConfig, Splits, build_splits
from iris.fragments.library import iter_fragments
from iris.fragments.model import Fragment
from iris.generator.grc.recorded import GrcBundle, build_grc
from iris.generator.sampler import SampleOverrides, sample_spec
from iris.live.attacks import applicable_families
from iris.oracle.decisions import build_d1_key, build_d2_key, build_d4_key
from iris.oracle.keys import activities_from_composed
from iris.packager.build import PackageResult, assemble, write_package
from iris.packager.compose_build import compose_onto


def grc_style_signature(style: object) -> str:
    rs = getattr(style, "risk_scale", "?")
    vocab = getattr(style, "vocabulary", "?")
    return f"{rs}|{vocab}"


@dataclass
class DatasetResult:
    version: str
    root: Path
    packages: list[PackageResult]
    splits: Splits
    coverage: CoverageReport
    profiles: list[GroupProfile] = field(default_factory=list)

    def summary(self) -> dict[str, object]:
        return {
            "version": self.version,
            "packages": len(self.packages),
            "in_distribution_groups": len(self.splits.in_distribution),
            "ood_sets": sorted(self.splits.ood_sets),
            "episodes": self.coverage.episodes,
            "warnings": self.splits.warnings(),
        }


def load_library(data_dir: Path | None = None) -> list[Fragment]:
    return list(iter_fragments(data_dir))


def _clean_out(out_dir: Path) -> None:
    """Remove a previous dataset's artifacts from ``out_dir`` (its ``scenario-*`` packages
    and the three report files) so a rebuild is clean. Only dataset-owned paths are touched;
    any unrelated files are left in place."""
    import shutil

    if not out_dir.exists():
        return
    for child in out_dir.glob("scenario-*"):
        if child.is_dir():
            shutil.rmtree(child)
    for name in ("splits.json", "coverage.json", "dataset.json"):
        (out_dir / name).unlink(missing_ok=True)


@dataclass
class _Prepared:
    master: int
    seeds: SeedSet
    spec: ScenarioSpec
    grc: GrcBundle
    profile: GroupProfile


def _prepare(master: int) -> _Prepared:
    seeds = SeedSet.from_master(master)
    spec = sample_spec(seeds, SampleOverrides(live=True))
    grc = build_grc(spec, seeds)
    profile = GroupProfile(
        group_id=seeds.group_id(),
        topology=spec.archetype,
        industry=spec.organization.industry.value,
        families=tuple(applicable_families(spec)),
        grc_style=grc_style_signature(grc.style),
    )
    return _Prepared(master, seeds, spec, grc, profile)


def build_dataset(
    master_seeds: list[int],
    library: list[Fragment],
    ood: OodConfig,
    out_dir: Path,
    *,
    allowed_groups: set[str] | None = None,
    reuse_cap: int = 5,
    universe: CoverageUniverse | None = None,
    progress: Callable[[str], None] | None = None,
) -> DatasetResult:
    def say(label: str) -> None:
        if progress is not None:
            progress(label)

    allowed = allowed_groups if allowed_groups is not None else {f.group_id for f in library}
    ledger = ReuseLedger(cap=reuse_cap)
    _clean_out(out_dir)  # a rebuild produces a fresh, internally consistent dataset

    # First pass: sample every candidate and compute the split, so training composes only
    # in-distribution groups and never uses a held-out family (decisions.md "Splits").
    prepared = []
    for n, m in enumerate(master_seeds, start=1):
        say(f"sampling enterprise {n}/{len(master_seeds)}")
        prepared.append(_prepare(m))
    uniq = {p.profile.group_id: p.profile for p in prepared}
    splits = build_splits(list(uniq.values()), ood)
    in_dist = set(splits.in_distribution)
    blocked = set(splits.indist_blocked_families)
    # Never compose training data from recordings of a held-out group: all data of one
    # enterprise stays in one set (contract section 16, "never split within a group").
    ood_groups = {gid for s in splits.ood_sets.values() for gid in s.group_ids}
    allowed = allowed - ood_groups

    packages: list[PackageResult] = []
    cov_items: list[EpisodeCoverage] = []
    composed_groups: set[str] = set()
    for p in prepared:
        gid = p.seeds.group_id()
        # one package per group; OOD groups are reserved for live Gold (val/test), not composed
        if gid not in in_dist or gid in composed_groups:
            continue
        composed_groups.add(gid)
        say(f"composing {gid}  ({len(composed_groups)} of {len(in_dist)} in-distribution)")
        assembled = assemble(p.seeds, spec=p.spec)
        composed, options = compose_onto(
            assembled, p.grc.reality, library, allowed, ledger=ledger, blocked_families=blocked
        )
        packages.append(write_package(assembled, out_dir, options))
        states = {cid: c.state for cid, c in p.grc.reality.controls.items()}
        for act in activities_from_composed(p.spec, composed):
            d6 = assembled.hidden.get(f"evaluation_key/d6/{act.episode_id}.json", {})
            cov_items.append(
                from_keys(
                    build_d1_key(act),
                    build_d2_key(act),
                    build_d4_key(act, states),
                    options.data_tier,
                    len(d6.get("flaws", [])),
                )
            )

    coverage = coverage_report(cov_items, universe)
    _write_manifest(out_dir, splits, coverage, packages)
    return DatasetResult(DATASET_VERSION, out_dir, packages, splits, coverage, list(uniq.values()))


def _write_manifest(
    out_dir: Path, splits: Splits, coverage: CoverageReport, packages: list[PackageResult]
) -> None:
    import json

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "splits.json").write_text(json.dumps(splits.to_dict(), indent=2) + "\n", encoding="utf-8")
    (out_dir / "coverage.json").write_text(json.dumps(coverage.to_dict(), indent=2) + "\n", encoding="utf-8")
    manifest = {
        "version": DATASET_VERSION,
        "packages": [
            {"scenario_id": p.scenario_id, "package_id": p.package_id, "path": p.root.name} for p in packages
        ],
    }
    (out_dir / "dataset.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
