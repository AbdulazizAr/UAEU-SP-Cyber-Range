from iris.core.seeds import SeedSet
from iris.generator.sampler import SampleOverrides, sample_spec
from iris.oracle.decisions import build_d1_key, build_d2_key, build_d4_key
from iris.oracle.outcome import from_composed, outcome_key


def _spec(m=11):
    return sample_spec(SeedSet.from_master(m), SampleOverrides(live=True))


def _truth(eid, start, placements):
    return {"episode_id": eid, "virtual_start": start, "placements": placements}


def _web_weakness(spec):
    return next((w for w in spec.weaknesses if w.module.startswith("web.")), None)


def test_benign_episode_keys_say_no_incident():
    spec = _spec()
    act = from_composed(
        spec,
        _truth(
            "scn-x-ep001",
            "2026-11-03T08:00:00Z",
            [
                {"label": "benign", "family": "persona_web", "outcome": "n/a"},
            ],
        ),
    )
    d1 = build_d1_key(act)
    assert d1["verdict"] == "benign" and d1["scenario_class"] == "benign_operations"
    assert build_d2_key(act)["incident"] is False
    assert build_d4_key(act, {})["actionable"] is False
    assert outcome_key(act)["compromised"] is False


def test_malicious_episode_resolves_weakness_and_keys():
    spec = _spec()
    wk = _web_weakness(spec)
    if wk is None:  # no web weakness in this sample; nothing to assert
        return
    placement = {
        "label": "malicious",
        "family": "F1",
        "technique": "T1190",
        "outcome": "success",
        "weakness_module": wk.module,
        "expected_rules": [100112],
    }
    act = from_composed(spec, _truth("scn-x-ep002", "2026-11-05T09:00:00Z", [placement]))
    item = act.malicious[0]
    assert item.asset_id == wk.asset_id and item.enabling_control == wk.enabling_control

    d1 = build_d1_key(act)
    assert d1["verdict"] == "malicious"
    assert d1["scenario_class"] == "web_application_compromise"
    assert "T1190" in d1["techniques"] and d1["detectability"] == "DC1"

    d2 = build_d2_key(act)
    assert d2["incident"] is True and d2["priority"] in {"MEDIUM", "HIGH", "CRITICAL"}

    d4 = build_d4_key(act, {wk.enabling_control: "missing"})
    assert d4["actionable"] is True
    rec = d4["recommendations"][0]
    assert rec["control_id"] == wk.enabling_control and rec["action"] == "implement"


def test_d4_action_follows_control_state():
    spec = _spec()
    wk = _web_weakness(spec)
    if wk is None:
        return
    act = from_composed(
        spec,
        _truth(
            "scn-x-ep003",
            "2026-11-06T09:00:00Z",
            [
                {
                    "label": "malicious",
                    "family": "F1",
                    "technique": "T1190",
                    "outcome": "success",
                    "weakness_module": wk.module,
                    "expected_rules": [100112],
                },
            ],
        ),
    )
    assert build_d4_key(act, {wk.enabling_control: "implemented"})["recommendations"][0]["action"] == "verify"
    assert build_d4_key(act, {wk.enabling_control: "partial"})["recommendations"][0]["action"] == "strengthen"


def test_priority_bumps_on_compromise():
    spec = _spec()
    wk = _web_weakness(spec)
    if wk is None:
        return
    base = {
        "label": "malicious",
        "family": "F1",
        "technique": "T1190",
        "weakness_module": wk.module,
        "expected_rules": [100112],
    }
    failed = from_composed(spec, _truth("e1", "2026-11-07T09:00:00Z", [{**base, "outcome": "failed"}]))
    ok = from_composed(spec, _truth("e2", "2026-11-07T09:00:00Z", [{**base, "outcome": "success"}]))
    order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assert order.index(build_d2_key(ok)["priority"]) >= order.index(build_d2_key(failed)["priority"])
