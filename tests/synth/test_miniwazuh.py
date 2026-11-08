"""Phase 3 gate: MiniWazuh fidelity + coverage (T-S1, S2, S6-ish), emitter round-trip, SCA
weakness evidence, syscollector == SBOM."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from iris.core.hashing import episode_id, scenario_id
from iris.core.seeds import SeedSet
from iris.generator.sampler import sample_spec
from iris.synth.posture import build_posture
from iris.synth.seeds import SynthSeeds
from iris.synth.soc.logs import emitters
from iris.synth.soc.miniwazuh import MiniWazuh, coverage_report, load_rules
from iris.synth.soc.wazuh_modules import sca_results, syscollector
from iris.synth.world import build_world

YEAR = 2026
TZ = UTC


@pytest.fixture(scope="module")
def rules():
    return load_rules()


@pytest.fixture(scope="module")
def engine(rules):
    return MiniWazuh(dict(rules))


# ---------------------------------------------------------------- fidelity


def test_ts1_every_loaded_rule_id_is_real_and_claimed_coverage(rules):
    rep = coverage_report(rules)
    # every rule we loaded came from the pinned XML; ids are therefore all real
    assert rep["total_rules"] > 400
    # claimed-group coverage meets the brief's >= 95% gate
    assert rep["claimed_coverage"] >= 0.95, rep["claimed_coverage"]


def test_sshd_known_lines_match_expected_rules(engine):
    line = emitters.ssh_accepted(
        datetime(YEAR, 3, 3, 8, 41, 11, tzinfo=TZ), "web01", 10, "alice", "10.20.10.5", 51022
    )
    a = engine.process(line, YEAR, TZ)
    assert a and a.rule.id == 5715 and a.rule.level == 3  # authentication success

    line = emitters.ssh_failed(
        datetime(YEAR, 3, 3, 8, 41, 12, tzinfo=TZ), "web01", 11, "root", "203.0.113.9", 40510
    )
    a = engine.process(line, YEAR, TZ)
    assert (
        a and a.rule.level == 5 and "T1110.001" in a.rule.mitre
    )  # authentication failed, brute-force technique


def test_ts2_alert_reproduces_on_reprocessing(engine):
    """Every alert has one parent raw line and re-running MiniWazuh reproduces the same rule."""
    line = emitters.ssh_failed(
        datetime(YEAR, 3, 3, 8, 42, 0, tzinfo=TZ), "db01", 99, "oracle", "198.51.100.9", 2222, invalid=True
    )
    a1 = MiniWazuh(dict(engine.rules)).process(line, YEAR, TZ)
    a2 = MiniWazuh(dict(engine.rules)).process(line, YEAR, TZ)
    assert a1 and a2 and a1.rule.id == a2.rule.id and a1.full_log == line


def test_brute_force_escalates_with_frequency(rules):
    engine = MiniWazuh(dict(rules))
    ids = []
    for i in range(10):
        line = emitters.ssh_failed(
            datetime(YEAR, 3, 3, 9, 0, i, tzinfo=TZ), "web01", 2000 + i, "root", "198.51.100.7", 40000 + i
        )
        a = engine.process(line, YEAR, TZ)
        ids.append(a.rule.id if a else None)
    # the single-event rule fires repeatedly, then a frequency rule escalates (higher level)
    base = ids[0]
    assert any(rid != base for rid in ids), ids
    escalated = next(engine.rules[r] for r in ids if r != base)
    assert escalated.level >= 10


def test_benign_line_does_not_alert(engine):
    line = emitters.systemd_unit(
        datetime(YEAR, 3, 3, 8, 0, 0, tzinfo=TZ), "web01", "nginx.service", "Started"
    )
    assert engine.process(line, YEAR, TZ) is None


# ---------------------------------------------------------------- weakness evidence


def _world(master: int):
    seeds = SeedSet.from_master(master)
    spec = sample_spec(seeds)
    return build_world(spec, seeds), seeds, spec


def test_sca_surfaces_planted_weaknesses_only_as_evidence():
    world, _, spec = _world(42)
    present = {(w.asset_id, w.module) for w in spec.weaknesses}
    for aid in world.assets:
        for check in sca_results(world, aid):
            # a failed SCA check corresponds to a real planted weakness on that host
            if check["result"] == "failed":
                module = next(
                    m
                    for m, (cid, *_rest) in _sca_map().items()
                    if _rest[0] == check["title"] or cid == check["check_id"]
                )
                assert (aid, module) in present
            # every check names the control it tests (DC2 evidence for D6)
            assert check["org_controls"]


def _sca_map():
    from iris.synth.soc.wazuh_modules import _SCA_FOR_WEAKNESS

    return _SCA_FOR_WEAKNESS


def test_syscollector_packages_equal_sbom():
    world, seeds, spec = _world(100)
    syn = SynthSeeds(seeds)
    scn = scenario_id({"seeds": seeds.to_dict()})
    eps = [(episode_id(scn, e.index), e.virtual_start) for e in spec.episodes]
    posture = build_posture(world, syn, eps)
    for aid, installed in posture.installed.items():
        sc = syscollector(world, aid, installed)
        sc_pkgs = {(p["name"], p["version"]) for p in sc["packages"]}
        sbom_pkgs = {
            (c["name"], c["version"])
            for c in posture.sboms[aid]["components"]
            if c["type"] == "library" and "synthetic_filler" not in str(c.get("properties", ""))
        }
        assert sc_pkgs == sbom_pkgs
