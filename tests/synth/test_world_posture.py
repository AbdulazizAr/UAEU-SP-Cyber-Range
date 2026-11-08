"""Phase 2 gate: World determinism/resolution (T-W*) and posture date-gating (T-V*)."""

from __future__ import annotations

import json

import pytest

from iris.core.hashing import episode_id, scenario_id
from iris.core.seeds import SeedSet
from iris.generator.sampler import sample_spec
from iris.synth.catalogs import load_cves, version_lt
from iris.synth.posture import build_posture
from iris.synth.seeds import SynthSeeds, synth_subseed
from iris.synth.world import build_world

SEEDS = [1, 7, 42, 100, 256]


def _world_and_posture(master: int):
    seeds = SeedSet.from_master(master)
    spec = sample_spec(seeds)
    world = build_world(spec, seeds)
    syn = SynthSeeds(seeds)
    scn = scenario_id({"seeds": seeds.to_dict()})
    episodes = [(episode_id(scn, e.index), e.virtual_start) for e in spec.episodes]
    return world, build_posture(world, syn, episodes), episodes


# ----------------------------------------------------------------- seeds


def test_synth_subseeds_are_independent_and_named():
    seeds = SeedSet.from_master(42)
    vals = {m: synth_subseed(seeds, m) for m in ("activity", "telemetry", "sensor", "noise")}
    assert len(set(vals.values())) == 4  # distinct
    with pytest.raises(KeyError):
        synth_subseed(seeds, "org")  # not a synth module
    # noise override is independent of the scenario seed
    assert synth_subseed(seeds, "noise", override=123) == 123


# ----------------------------------------------------------------- T-W*


def test_tw1_every_recorded_ip_resolves_to_one_asset():
    world, _, _ = _world_and_posture(42)
    for aid in world.ip_to_asset.values():
        assert aid in world.assets
    # each asset's attachments are the source of its ips
    for a in world.spec.assets:
        for att in a.attachments:
            assert world.asset_for_ip(att.ip) == a.asset_id


def test_tw5_same_master_identical_world():
    a = build_world(sample_spec(SeedSet.from_master(42)), SeedSet.from_master(42))
    b = build_world(sample_spec(SeedSet.from_master(42)), SeedSet.from_master(42))
    assert a.ip_to_asset == b.ip_to_asset
    assert a.zone_of == b.zone_of
    assert {k: [s.service_id for s in v] for k, v in a.services_by_asset.items()} == {
        k: [s.service_id for s in v] for k, v in b.services_by_asset.items()
    }


def test_tw3_no_orphan_service_and_flow_lookup():
    world, _, _ = _world_and_posture(100)
    for aid, svcs in world.services_by_asset.items():
        assert aid in world.assets
        assert svcs
    # flow lookup returns a valid verdict for any zone pair
    names = list(world.zones)
    for s in names:
        for d in names:
            assert world.flow_action(s, d, "tcp", 443) in {"allow", "deny", "absent"}


# ----------------------------------------------------------------- T-V*


def test_version_comparator():
    assert version_lt("9.2p1", "9.8p1")
    assert version_lt("1.9.5p1", "1.9.5p2")
    assert version_lt("2.36", "2.38")
    assert not version_lt("3.0.14", "3.0.11")
    assert not version_lt("9.8p1", "9.8p1")


def test_tv2_no_finding_or_enrichment_references_a_future_date():
    for m in SEEDS:
        _, posture, episodes = _world_and_posture(m)
        for f in posture.scanner_findings:
            cve = load_cves().by_id[f["cve"]]
            assert cve.published_at.isoformat() <= f["timestamp"][:10]
        for eid, _as_of in episodes:
            for r in posture.cve_enrichment_by_episode[eid]:
                assert r["published_at"][:10] <= r["as_of"][:10]
                if r["kev_date_added"]:
                    assert r["kev_date_added"] <= r["as_of"][:10]


def test_tv1_same_package_version_same_cve_set_and_determinism():
    _, p1, _ = _world_and_posture(42)
    _, p2, _ = _world_and_posture(42)
    assert json.dumps(p1.scanner_findings, sort_keys=True) == json.dumps(p2.scanner_findings, sort_keys=True)
    # findings only ever cite catalog CVEs (T-V3 shape: nothing invented)
    known = {e.cve_id for e in load_cves().usable()}
    assert all(f["cve"] in known for f in p1.scanner_findings)


def test_tv4_sbom_lists_installed_tracked_packages():
    _, posture, _ = _world_and_posture(100)
    for aid, pkgs in posture.installed.items():
        sbom = posture.sboms[aid]
        names = {c["name"]: c["version"] for c in sbom["components"] if c["type"] == "library"}
        for ip in pkgs:
            assert names.get(ip.package.purl_name) == ip.version


def test_posture_visible_has_no_maturity_leak():
    _, posture, _ = _world_and_posture(100)
    blob = json.dumps(posture.visible())
    assert "maturity" not in blob.lower()
    assert "synthetic_filler" in blob  # filler is labelled
