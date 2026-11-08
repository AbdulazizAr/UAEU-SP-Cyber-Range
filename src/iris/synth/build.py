"""Build one complete synthetic scenario package (builder brief file 09, Phases 9-10).

Reuses the proven context pipeline (``iris.packager.assemble``: enterprise, GRC, timeline,
SOC, D6 key, generated weaknesses) and layers the synthetic posture, telemetry, GRC coupling,
noise and v1 decision keys on top, then writes a v2.1 ``SYN``-tier package (visible + hidden)
through the existing packager so the no-peek audit and integrity checks still apply.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from iris.core.hashing import episode_id
from iris.core.seeds import SeedSet
from iris.generator.sampler import SampleOverrides, sample_spec
from iris.packager.build import Assembled, PackageOptions, PackageResult, assemble, write_package
from iris.synth import SYNTH_VERSION
from iris.synth.activity.attacks import ATTACK_CATALOG_VERSION
from iris.synth.activity.planner import PLANNER_VERSION, plan_scenario
from iris.synth.grc_link import GRC_LINK_VERSION, build_grc_link
from iris.synth.noise import NOISE_VERSION, apply_noise, data_quality
from iris.synth.posture import POSTURE_VERSION, build_posture
from iris.synth.seeds import SynthSeeds
from iris.synth.soc.miniwazuh import Rule, load_rules
from iris.synth.telemetry import TELEMETRY_VERSION, assemble_telemetry
from iris.synth.truth import TRUTH_VERSION, campaign_truth, decision_keys, detection_expectations
from iris.synth.world import build_world

SYNTH_SCHEMA_VERSION = "2.1.0"
_RULES: dict[int, Rule] | None = None


def _rules() -> dict[int, Rule]:
    global _RULES
    if _RULES is None:
        _RULES = load_rules()
    return _RULES


@dataclass
class BuiltScenario:
    assembled: Assembled
    options: PackageOptions
    noise_level: str
    n_malicious: int
    n_telemetry: int


def build_synth_scenario(
    seeds: SeedSet,
    *,
    noise_level: str = "medium",
    noise_override: int | None = None,
    overrides: SampleOverrides | None = None,
    rules: dict[int, Rule] | None = None,
) -> BuiltScenario:
    rules = rules or _rules()
    spec = sample_spec(seeds, overrides)
    synth = SynthSeeds(seeds, noise_override=noise_override)
    assembled = assemble(seeds, spec=spec)  # context plane
    scn = assembled.scenario_id
    world = build_world(spec, seeds)
    episodes = [(episode_id(scn, e.index), e.virtual_start) for e in spec.episodes]

    # ---- posture (synthetic SBOM + findings), merged into context asof snapshots
    posture = build_posture(world, synth, episodes)
    assembled.visible.update(posture.visible())
    for eid, _ in episodes:
        key = f"snapshots/asof/{eid}.json"
        if key in assembled.visible:
            assembled.visible[key] = {**assembled.visible[key], **posture.asof(eid)}
    _merge_hidden(assembled, posture.hidden())

    # ---- activity + telemetry
    plan = plan_scenario(spec, world, synth)
    clean = assemble_telemetry(world, plan, synth, posture, rules)

    # ---- GRC coupling (uses clean detection truth) + v1 decision keys + truth
    grc = build_grc_link(world, plan, clean, posture, synth)
    assembled.visible.update(grc.visible())
    _merge_hidden(assembled, grc.hidden())
    _merge_hidden(assembled, decision_keys(world, plan))
    _merge_hidden(
        assembled,
        {
            "truth/campaign_truth.jsonl": campaign_truth(plan),
            "truth/detection_expectations.jsonl": detection_expectations(plan),
        },
    )

    # ---- noise (post-processing) + data-quality report
    noisy, ntruth = apply_noise(clean, synth, scn, noise_level)
    assembled.visible.update(
        {k: v for k, v in noisy.visible.items() if k.startswith(("telemetry/", "quality/"))}
    )
    _merge_hidden(assembled, {k: v for k, v in noisy.hidden.items()})
    _merge_hidden(
        assembled,
        {
            "quality/data_quality.json": data_quality(ntruth, clean),
            "quality/noise_report.json": ntruth.to_dict(),
        },
    )

    n_tel = sum(
        len(v) for k, v in assembled.visible.items() if k.startswith("telemetry/") and isinstance(v, list)
    )
    options = PackageOptions(
        data_tier="SYN",
        telemetry=True,
        episode_bundles=False,
        enabled_sensors=("wazuh", "suricata"),
        schema_version=SYNTH_SCHEMA_VERSION,
        extra_versions={
            "synth": SYNTH_VERSION,
            "synth_posture": POSTURE_VERSION,
            "synth_telemetry": TELEMETRY_VERSION,
            "synth_planner": PLANNER_VERSION,
            "synth_attacks": ATTACK_CATALOG_VERSION,
            "synth_truth": TRUTH_VERSION,
            "synth_grc_link": GRC_LINK_VERSION,
            "synth_noise": NOISE_VERSION,
        },
        extra_hidden_manifest={
            "noise_profile": {
                "profile_id": ntruth.profile.profile_id,
                "level": ntruth.profile.level,
                "seed": ntruth.profile.seed,
                "version": ntruth.profile.version,
            }
        },
    )
    return BuiltScenario(
        assembled, options, noise_level, sum(1 for a in plan.activities if a.kind == "malicious"), n_tel
    )


def write_synth_scenario(built: BuiltScenario, out_dir: Path) -> PackageResult:
    return write_package(built.assembled, out_dir, built.options)


def _merge_hidden(assembled: Assembled, files: dict[str, Any]) -> None:
    assembled.hidden.update(files)
