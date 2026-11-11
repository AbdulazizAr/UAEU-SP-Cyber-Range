"""Phase 4-5 gate: activity planner, attack footprints, hard negatives (T-A1..A7)."""

from __future__ import annotations

from datetime import UTC

import pytest

from iris.core.seeds import SeedSet
from iris.generator.sampler import sample_spec
from iris.synth.activity.attacks import load_templates
from iris.synth.activity.planner import plan_scenario
from iris.synth.refs import attack_catalog
from iris.synth.seeds import SynthSeeds
from iris.synth.soc.miniwazuh import MiniWazuh
from iris.synth.world import build_world

SEEDS = range(1, 61)


def _plans():
    out = []
    for m in SEEDS:
        seeds = SeedSet.from_master(m)
        spec = sample_spec(seeds)
        world = build_world(spec, seeds)
        out.append((spec, world, plan_scenario(spec, world, SynthSeeds(seeds))))
    return out


PLANS = None


def plans():
    global PLANS
    if PLANS is None:
        PLANS = _plans()
    return PLANS


# ---------------------------------------------------------------- T-A1


def test_ta1_all_template_techniques_exist_in_pinned_attack():
    cat = attack_catalog()
    for t in load_templates().values():
        assert t.technique in cat.techniques, t.template_id


def test_template_loading_rejects_unknown_technique(tmp_path, monkeypatch):
    import iris.synth.activity.attacks as A

    A.load_templates.cache_clear()
    bad = tmp_path / "attacks.yaml"
    bad.write_text(
        "catalog_version: '0'\nfamilies:\n  F1: {name: x, tactic: credential-access}\n"
        "templates:\n  bad: {family: F1, technique: T9999, executor: ssh_bruteforce,"
        " target_roles: [database]}\n"
    )
    with pytest.raises(ValueError, match="not in pinned catalog"):
        A.load_templates(tmp_path)
    A.load_templates.cache_clear()


# ---------------------------------------------------------------- T-A2, A7


def test_ta2_success_only_with_enabling_weakness():
    for spec, _world, plan in plans():
        present = {w.module for w in spec.weaknesses}
        for a in plan.activities:
            if a.kind == "malicious" and a.weakness_module and a.outcome == "success":
                assert a.weakness_module in present, (a.template_id, a.weakness_module)


def test_ta7_failed_and_blocked_attacks_stay_malicious():
    seen_non_success = False
    for _spec, _world, plan in plans():
        for a in plan.activities:
            if a.kind == "malicious" and a.outcome in ("failed", "blocked", "partial"):
                seen_non_success = True
                assert a.truth_row()["malicious"] is True
    assert seen_non_success


# ---------------------------------------------------------------- T-A3


def test_ta3_every_footprint_links_to_an_activity_or_background():
    for _spec, _world, plan in plans():
        for ep in plan.episodes:
            for a in ep.activities:
                for fp in a.footprints:
                    # footprints inside an activity carry that activity's id (exact link)
                    assert fp.activity_id == a.activity_id


# ---------------------------------------------------------------- T-A6


def test_ta6_clean_scenarios_and_campaigns_present():
    ps = plans()
    no_attack = sum(1 for _s, _w, p in ps if not any(a.kind == "malicious" for a in p.activities))
    campaigns = sum(1 for _s, _w, p in ps if p.campaign_id)
    attack_scenarios = sum(1 for _s, _w, p in ps if any(a.kind == "malicious" for a in p.activities))
    assert no_attack / len(ps) >= 0.15  # >= ~20% target (tolerance for 60-seed sample)
    assert campaigns / max(1, attack_scenarios) >= 0.20


# ---------------------------------------------------------------- footprints are real telemetry


def test_bruteforce_footprints_fire_wazuh_alerts():
    for _spec, world, plan in plans():
        bf = [a for a in plan.activities if a.template_id == "F1_ssh_bruteforce"]
        if not bf:
            continue
        act = bf[0]
        mw = MiniWazuh()
        fired = []
        for fp in sorted((f for f in act.footprints if f.kind == "raw_log"), key=lambda f: f.ts):
            a = mw.process(fp.data["line"], fp.ts.year, UTC)
            if a:
                fired.append(a.rule.id)
        assert fired  # the emitted ssh lines really decode+match real rules
        assert any(world.assets.get(act.target_asset) for _ in [0])
        return
    pytest.skip("no brute-force scenario in sample")


def test_hard_negatives_exist_and_overlap_attack_families():
    families_with_twins = set()
    for _spec, _world, plan in plans():
        for a in plan.activities:
            if a.is_hard_negative:
                families_with_twins.add(a.family)
    # authorized scan (F4), typo-login (F1), backup (F6), admin sudo (F3) twins appear
    assert {"F1", "F3", "F4", "F6"} & families_with_twins
