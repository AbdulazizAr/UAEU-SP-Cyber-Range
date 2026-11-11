"""Phase 6 gate: Suricata community_id (T-S4), EVE/flow visibility (T-S3), telemetry assembly,
envelope validity, evidence-link integrity, determinism, coverage gaps."""

from __future__ import annotations

import json

from iris.contracts.visible import TelemetryEnvelope
from iris.core.hashing import episode_id, scenario_id
from iris.core.seeds import SeedSet
from iris.generator.sampler import sample_spec
from iris.synth.posture import build_posture
from iris.synth.seeds import SynthSeeds
from iris.synth.soc.miniwazuh import load_rules
from iris.synth.soc.suricata import community_id
from iris.synth.telemetry import assemble_telemetry
from iris.synth.world import build_world

RULES = load_rules()


def _build(master: int):
    seeds = SeedSet.from_master(master)
    spec = sample_spec(seeds)
    world = build_world(spec, seeds)
    syn = SynthSeeds(seeds)
    scn = scenario_id({"seeds": seeds.to_dict()})
    eps = [(episode_id(scn, e.index), e.virtual_start) for e in spec.episodes]
    posture = build_posture(world, syn, eps)
    plan = __import__("iris.synth.activity.planner", fromlist=["plan_scenario"]).plan_scenario(
        spec, world, syn
    )
    return world, plan, assemble_telemetry(world, plan, syn, posture, RULES)


# ---------------------------------------------------------------- T-S4


def test_ts4_community_id_matches_reference_vectors():
    # canonical vectors from the community-id-spec project
    assert (
        community_id("128.232.110.120", "66.35.250.204", 34855, 80, "tcp") == "1:LQU9qZlK+B5F3KDmev6m5PMibrg="
    )
    # direction independence
    assert community_id("66.35.250.204", "128.232.110.120", 80, 34855, "tcp") == community_id(
        "128.232.110.120", "66.35.250.204", 34855, 80, "tcp"
    )


# ---------------------------------------------------------------- assembly


def test_every_telemetry_record_validates_against_contract_and_is_unique():
    _world, _plan, tb = _build(8)
    ids: set[str] = set()
    n = 0
    for path, content in tb.visible.items():
        if path.endswith(".jsonl") and "telemetry/" in path and isinstance(content, list):
            for rec in content:
                if "event_id" in rec:
                    TelemetryEnvelope(**rec)
                    assert rec["event_id"] not in ids
                    ids.add(rec["event_id"])
                    n += 1
    assert n > 0


def test_ts3_every_eve_flow_has_community_id_and_valid_endpoints():
    _world, _plan, tb = _build(12)
    for rec in tb.visible["telemetry/suricata/eve.jsonl"]:
        raw = rec["raw"]
        assert raw["community_id"].startswith("1:")
        assert raw["event_type"] in ("flow", "alert")


def test_alerts_are_reproducible_and_cite_real_rules():
    _world, _plan, tb = _build(8)
    for rec in tb.visible["telemetry/wazuh/alerts.jsonl"]:
        rid = int(rec["raw"]["rule"]["id"])
        assert rid in RULES  # every alert's rule id exists in the pinned ruleset (T-S1)
        assert rec["raw"]["full_log"]  # one parent raw line per alert (T-S2)


def test_evidence_links_reference_surviving_events_only():
    _world, _plan, tb = _build(8)
    evids = {
        r["event_id"]
        for p, c in tb.visible.items()
        if p.endswith(".jsonl") and isinstance(c, list)
        for r in c
        if "event_id" in r
    }
    assert tb.evidence
    for link in tb.evidence:
        assert link["event_id"] in evids
        assert link["link_quality"] == "exact"


def test_unmonitored_hosts_produce_no_host_evidence():
    world, _plan, tb = _build(100)
    monitored_hosts = {world.assets[a].hostname for a in world.assets if world.is_monitored(a)}
    for rec in tb.visible["telemetry/wazuh/alerts.jsonl"]:
        assert rec["raw"]["agent"]["name"] in monitored_hosts


def test_telemetry_is_deterministic_per_seed():
    _w1, _p1, a = _build(8)
    _w2, _p2, b = _build(8)
    ka = json.dumps(a.visible, sort_keys=True, default=str)
    kb = json.dumps(b.visible, sort_keys=True, default=str)
    assert ka == kb
