import json

import pytest

from iris.core.seeds import SeedSet
from iris.generator.compiler import compile_spec
from iris.generator.grc.recorded import build_grc
from iris.generator.sampler import SampleOverrides, sample_spec
from iris.generator.soc import belief_gaps, build_soc, soc_inventory
from iris.live.logtest import load_cases, parse_logtest, parse_rules, rules_path, rules_report


@pytest.fixture(scope="module")
def cases():
    out = []
    for m in range(60):
        seeds = SeedSet.from_master(m)
        spec = sample_spec(seeds, SampleOverrides(live=True))
        grc = build_grc(spec, seeds)
        out.append((spec, grc, build_soc(spec, grc.reality, seeds)))
    return out


def test_profile_follows_controls_and_maturity(cases):
    for spec, grc, p in cases:
        monitored = {
            a.asset_id for a in spec.assets if a.monitored and a.role.value not in ("ids_sensor", "siem")
        }
        assert set(p.sources) == monitored
        assert all("auth" in s for s in p.sources.values())  # canaries depend on it
        fim = grc.reality.controls.get("CTRL-LOG-003")
        if fim and fim.state == "implemented":
            assert all(p.fim.values())
        if fim is None or fim.state == "missing":
            assert not any(p.fim.values())
        assert all(not on or aid in p.servers for aid, on in p.sca.items())


def test_inventory_is_belief_not_reality(cases):
    for spec, grc, p in cases:
        recorded = {c.control_id: c.implementation_state for c in grc.controls}
        inv = soc_inventory(spec, p, recorded)
        text = json.dumps(inv.model_dump(mode="json"))
        assert "maturity" not in text
        for aid, believed in p.believed.items():
            role = next(a.role.value for a in spec.assets if a.asset_id == aid)
            assert set(believed) <= set(inv.log_sources_by_role[role])
        for g in belief_gaps(p, recorded):
            assert g.detectability == "DC2"


def test_compiler_passes_profile_to_nodes(cases):
    spec, _, p = cases[0]
    c = compile_spec(spec)
    for a in spec.assets:
        svc = c.compose["services"].get(a.hostname, {})
        env = svc.get("environment", {})
        if a.asset_id in p.sources:
            assert env["IRIS_LOGSOURCES"].count("|") == len(p.sources[a.asset_id])
        elif "IRIS_ROLE" in env:
            assert "IRIS_LOGSOURCES" not in env
    assert "soc/local_rules.xml" in c.extra_files
    siem = next(a for a in spec.assets if a.role.value == "siem")
    assert any("local_rules.xml" in v for v in c.compose["services"][siem.hostname]["volumes"])
    assert all(svc.get("init") is True for svc in c.compose["services"].values())


def test_rule_library_is_consistent():
    rules = parse_rules(rules_path().read_text())
    assert not rules_report()
    assert len(rules) >= 10 and sum(1 for r in rules if r["mitre"]) >= 6
    ids = {r["id"] for r in rules}
    assert {int(c["expect"]) for c in load_cases()} <= ids


def test_parse_logtest():
    out = """
**Phase 1: Completed pre-decoding.
\tfull event: 'x'

**Phase 2: Completed decoding.
\tname: 'json'

**Phase 3: Completed filtering (rules).
\tid: '100101'
\tlevel: '5'
\tdescription: 'Shop: failed login'
**Alert to be generated.

**Phase 1: Completed pre-decoding.
\tfull event: 'y'

**Phase 3: Completed filtering (rules).
\tid: '100102'
\tlevel: '10'
"""
    assert parse_logtest(out) == [(100101, 5), (100102, 10)]
