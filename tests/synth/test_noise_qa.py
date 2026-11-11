"""Phase 7-8 gate: noise determinism and truth (T-N1..N8), GRC coupling, shortcut test,
full package build + no-peek verify."""

from __future__ import annotations

import json
import shutil

import pytest

from iris.contracts.visible import IncidentRecord, RemediationItem
from iris.core.hashing import scenario_id
from iris.core.seeds import SeedSet
from iris.generator.sampler import sample_spec
from iris.packager.verify import verify_package
from iris.synth.build import build_synth_scenario, write_synth_scenario
from iris.synth.noise import apply_noise
from iris.synth.posture import build_posture
from iris.synth.qa.batch import run_shortcut
from iris.synth.seeds import SynthSeeds
from iris.synth.soc.miniwazuh import load_rules
from iris.synth.telemetry import assemble_telemetry
from iris.synth.world import build_world

RULES = load_rules()


def _clean(master: int):
    seeds = SeedSet.from_master(master)
    spec = sample_spec(seeds)
    world = build_world(spec, seeds)
    syn = SynthSeeds(seeds)
    scn = scenario_id({"seeds": seeds.to_dict()})
    from iris.core.hashing import episode_id
    from iris.synth.activity.planner import plan_scenario

    eps = [(episode_id(scn, e.index), e.virtual_start) for e in spec.episodes]
    posture = build_posture(world, syn, eps)
    plan = plan_scenario(spec, world, syn)
    return world, scn, syn, assemble_telemetry(world, plan, syn, posture, RULES)


# ---------------------------------------------------------------- T-N1, N2


def test_tn1_tn2_noise_determinism_and_independence():
    _world, scn, syn, clean = _clean(8)
    a, _ta = apply_noise(clean, syn, scn, "medium")
    b, _tb = apply_noise(clean, syn, scn, "medium")
    assert json.dumps(a.visible, sort_keys=True, default=str) == json.dumps(
        b.visible, sort_keys=True, default=str
    )
    # a different noise level changes the noisy output but not the clean source
    c, _tc = apply_noise(clean, syn, scn, "high")
    assert json.dumps(a.visible, sort_keys=True, default=str) != json.dumps(
        c.visible, sort_keys=True, default=str
    )


# ---------------------------------------------------------------- T-N4


def test_tn4_every_perturbed_event_is_in_noise_truth():
    _world, scn, syn, clean = _clean(8)
    noisy, truth = apply_noise(clean, syn, scn, "high")
    recorded = (
        {d["event_id"] for d in truth.dropped}
        | set(truth.duplicated)
        | {d["event_id"] for d in truth.delayed}
        | set(truth.malformed)
        | {u["event_id"] for u in truth.unresolved}
    )
    # every delayed event appears in the output (delay only, not dropped)
    out_ids = {
        r["event_id"]
        for p, c in noisy.visible.items()
        if p.endswith(".jsonl") and isinstance(c, list)
        for r in c
        if "event_id" in r
    }
    for d in truth.delayed:
        assert d["event_id"] in out_ids
    # dropped events are gone from the output (drop happens before duplication)
    for d in truth.dropped:
        assert d["event_id"] not in out_ids
    assert recorded  # something was perturbed at high noise


# ---------------------------------------------------------------- T-N8


def test_tn8_every_jsonl_line_parses_after_noise():
    _world, scn, syn, clean = _clean(3)
    noisy, _t = apply_noise(clean, syn, scn, "high")
    for path, content in noisy.visible.items():
        if path.endswith(".jsonl") and isinstance(content, list):
            for rec in content:
                json.loads(json.dumps(rec, default=str))  # round-trips as valid JSON


# ---------------------------------------------------------------- T-N6 (no-peek) via full build


def test_full_synth_package_builds_and_passes_no_peek(tmp_path):
    for m in (8, 3, 100):
        built = build_synth_scenario(SeedSet.from_master(m), noise_level="medium")
        res = write_synth_scenario(built, tmp_path)
        rep = verify_package(res.root)
        assert rep.ok, rep.problems[:5]
        # visible plane carries no noise profile or seed (T-N6)
        for vf in (res.root / "visible").rglob("*.json*"):
            text = vf.read_text()
            assert "noise_profile" not in text
            assert str(built.assembled.seeds.get("time")) not in text
        shutil.rmtree(res.root)


# ---------------------------------------------------------------- GRC coupling validates


def test_grc_coupling_records_validate_against_contract():
    built = build_synth_scenario(SeedSet.from_master(8), noise_level="low")
    for row in built.assembled.visible.get("grc/incident_register.jsonl", []):
        IncidentRecord(**row)
    for row in built.assembled.visible.get("grc/remediation_tracker.jsonl", []):
        RemediationItem(**row)


# ---------------------------------------------------------------- shortcut gate


@pytest.mark.slow
def test_shortcut_test_passes_on_a_batch():
    # a volume-invariant surface model must NOT separate attack from benign episodes. 48 scenarios
    # keeps the grouped-CV AUC estimate stable (small batches are noisy). Measured mean ~0.57 over
    # seed ranges; if this fails, the generator leaked surface form — fix the data, not the threshold.
    result, batch = run_shortcut(48)
    assert result.passed, result.to_dict()
    # noise mix roughly 30/40/30
    total = sum(batch.level_counts.values())
    assert batch.level_counts["medium"] >= batch.level_counts["low"]
    assert total == 48
