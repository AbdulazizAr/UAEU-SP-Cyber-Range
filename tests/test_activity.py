import pytest

from iris.core.seeds import SeedSet
from iris.generator.sampler import SampleOverrides, sample_spec
from iris.generator.secrets import scenario_secrets
from iris.live.activity import DETECTABLE, build_plan
from iris.live.record import match_detections, rule_id


def _plan(master):
    seeds = SeedSet.from_master(master)
    spec = sample_spec(seeds, SampleOverrides(live=True))
    sec = scenario_secrets(spec)
    return spec, build_plan(spec, sec, seeds.stream("traffic", "activity.1"))


@pytest.mark.parametrize("master", range(40))
def test_malicious_actions_are_grounded_in_planted_weaknesses(master):
    spec, plan = _plan(master)
    planted = {w.module for w in spec.weaknesses}
    for a in plan.actions:
        assert a.label in ("benign", "malicious")
        if a.label == "malicious" and a.name in {d[2] for d in DETECTABLE.values()}:
            module = next(k for k, v in DETECTABLE.items() if v[2] == a.name)
            assert module in planted  # never expect a detection the scenario can't produce
            assert a.weakness_id is not None and a.expect_rules
            assert a.technique and a.technique.startswith("T")


def test_plan_is_deterministic_and_has_benign_majority():
    _, a = _plan(3)
    _, b = _plan(3)
    assert [x.command for x in a.actions] == [x.command for x in b.actions]
    benign = sum(1 for x in a.actions if x.label == "benign")
    assert benign >= sum(1 for x in a.actions if x.label == "malicious")


def test_login_guessing_always_present():
    _, plan = _plan(0)
    assert any(a.name == "login_guessing" and 100102 in a.expect_rules for a in plan.actions)


def test_match_detections():
    _, plan = _plan(9)  # a seed with web weaknesses
    expected = plan.expected_detections
    assert expected  # has detectable actions
    want = {rid for _, rid in expected}
    alerts = [{"rule": {"id": str(rid)}} for rid in want]
    res = match_detections(plan, alerts)
    assert res.ok and not res.missed and set(res.matched) == want
    partial = match_detections(plan, alerts[:-1])
    assert not partial.ok and partial.missed


def test_rule_id_parsing():
    assert rule_id({"rule": {"id": "100102"}}) == 100102
    assert rule_id({"rule": {}}) is None
    assert rule_id({}) is None


def test_commands_are_shell_safe():
    # payloads are built with shlex.quote, so each simple (non-chained) command re-parses
    import shlex

    for master in range(20):
        _, plan = _plan(master)
        for a in plan.actions:
            assert "\n" not in a.command
            if ";" not in a.command:  # chained commands use ' ; ' as a shell separator
                assert shlex.split(a.command)[0] == "curl"
