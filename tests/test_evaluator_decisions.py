import itertools
import json
from datetime import UTC, datetime

from iris.contracts.decisions import (
    ControlRecommendation,
    D1Payload,
    D2Payload,
    D4Payload,
    DecisionRecord,
    SubjectRef,
)
from iris.core.seeds import SeedSet
from iris.evaluator.decisions import (
    score_d1_episode,
    score_d2_episode,
    score_d4_episode,
    score_decisions,
)
from iris.generator.grc.recorded import build_grc
from iris.generator.sampler import SampleOverrides, sample_spec
from iris.generator.secrets import scenario_secrets
from iris.packager.build import assemble, write_package
from iris.packager.compose_build import compose_onto
from tests.test_compose_package import _benign_fragment

EID = "scn-000000000000-ep002"
_N = itertools.count()


def _rec(dtype, payload, conf=0.9, status="ASSESSED", eid=EID):
    return DecisionRecord(
        decision_id=f"dec-e{next(_N)}",
        scenario_id="scn-000000000000",
        episode_id=eid,
        as_of=datetime(2026, 1, 1, tzinfo=UTC),
        type=dtype,
        subject_ref=SubjectRef(kind="session", id="s1"),
        payload=payload if status == "ASSESSED" else None,
        status=status,
        confidence=conf if status == "ASSESSED" else None,
        evidence_event_ids=["evt-00000000000000000000"],
        engine_version="t",
        model_version="t",
        policy_version="t",
    )


D1_MAL = {
    "episode_id": EID,
    "verdict": "malicious",
    "scenario_class": "web_application_compromise",
    "techniques": ["T1190", "T1213"],
}
D1_BEN = {"episode_id": EID, "verdict": "benign", "scenario_class": "benign_operations", "techniques": []}


def test_d1_correct_call_scores_class_and_techniques():
    d = _rec(
        "D1",
        D1Payload(verdict="malicious", scenario_class="web_application_compromise", techniques=["T1190"]),
    )
    s = score_d1_episode(D1_MAL, True, [d]).summary()
    assert s["accuracy"] == 1.0 and s["attack_recall"] == 1.0
    assert s["scenario_class_accuracy"] == 1.0 and s["technique_jaccard"] == 0.5
    assert s["harmful"] == 0 and s["brier"] == round((1 - 0.9) ** 2, 4)


def test_d1_confident_benign_on_a_compromise_is_harmful():
    s = score_d1_episode(D1_MAL, True, [_rec("D1", D1Payload(verdict="benign"), conf=0.85)]).summary()
    assert s["attack_recall"] == 0.0 and s["harmful"] == 1
    # the same miss on a failed attempt is an error, not a harm
    assert score_d1_episode(D1_MAL, False, [_rec("D1", D1Payload(verdict="benign"), 0.85)]).harmful == 0


def test_d1_missing_abstained_and_false_positive():
    assert score_d1_episode(D1_MAL, True, []).summary()["missing"] == 1
    assert score_d1_episode(D1_MAL, True, [_rec("D1", None, status="ABSTAINED")]).abstained == 1
    fp = score_d1_episode(D1_BEN, False, [_rec("D1", D1Payload(verdict="malicious"))]).summary()
    assert fp["benign_false_positive_rate"] == 1.0


def test_d2_levels_harm_and_false_escalation():
    key = {"episode_id": EID, "incident": True, "priority": "HIGH"}
    assert score_d2_episode(key, [_rec("D2", D2Payload(priority="HIGH"))]).summary()["exact_accuracy"] == 1.0
    low = score_d2_episode(key, [_rec("D2", D2Payload(priority="LOW"))]).summary()
    assert low["under_prioritised"] == 1 and low["harmful"] == 1 and low["within_one_accuracy"] == 0.0
    # several sessions: the episode's answer is the highest priority given
    multi = score_d2_episode(
        key, [_rec("D2", D2Payload(priority="LOW")), _rec("D2", D2Payload(priority="CRITICAL"))]
    )
    assert multi.over_prioritised == 1 and multi.harmful == 0
    quiet = {"episode_id": EID, "incident": False, "priority": None}
    assert score_d2_episode(quiet, [_rec("D2", D2Payload(priority="CRITICAL"))]).false_escalations == 1


def _d4(*recs, conf=0.9):
    return _rec(
        "D4",
        D4Payload(
            recommendations=[ControlRecommendation(control_id=c, action=a, rationale="r") for c, a in recs]
        ),
        conf,
    )


def test_d4_recall_precision_action_and_harm():
    key = {
        "episode_id": EID,
        "actionable": True,
        "recommendations": [
            {"control_id": "CTRL-WEB-001", "action": "implement"},
            {"control_id": "CTRL-IAM-002", "action": "strengthen"},
        ],
    }
    s = score_d4_episode(key, [_d4(("CTRL-WEB-001", "implement"), ("CTRL-LOG-001", "verify"))]).summary()
    assert s["control_recall"] == 0.5 and s["control_precision"] == 0.5
    assert s["action_accuracy"] == 1.0 and s["hit_at_1"] == 1.0 and s["harmful"] == 0
    bad = score_d4_episode(key, [_d4(("CTRL-IAM-002", "relax"))]).summary()
    assert bad["harmful"] == 1 and bad["action_accuracy"] == 0.0
    quiet = {"episode_id": EID, "actionable": False, "recommendations": []}
    assert score_d4_episode(quiet, [_d4(("CTRL-WEB-001", "implement"))]).noise_recommendations == 1


def test_scores_a_real_composed_package_end_to_end(tmp_path):
    seeds = SeedSet.from_master(21)
    spec = sample_spec(seeds, SampleOverrides(live=True))
    assembled = assemble(seeds, spec=spec)
    library = [_benign_fragment(spec, scenario_secrets(spec), seeds.group_id())]
    _, options = compose_onto(assembled, build_grc(spec, seeds).reality, library, {seeds.group_id()})
    root = write_package(assembled, tmp_path, options).root

    # an oracle-perfect Engine: answer every episode exactly as its key says
    perfect = []
    for kp in sorted((root / "hidden" / "evaluation_key" / "d1").glob("*.json")):
        k = json.loads(kp.read_text(encoding="utf-8"))
        perfect.append(_rec("D1", D1Payload(verdict=k["verdict"]), eid=k["episode_id"]))
    s = score_decisions(root, perfect).summary()
    assert s["D1"]["episodes"] >= 1 and s["D1"]["accuracy"] == 1.0
    assert s["D1"]["missing"] == 0 and s["D1"]["unscored"] == 0
    assert score_decisions(root, []).summary()["D1"]["missing"] == s["D1"]["episodes"]
    # a context-only package has no D1/D2/D4 keys: zero episodes, no crash
    ctx = write_package(assemble(SeedSet.from_master(22)), tmp_path).root
    assert score_decisions(ctx, perfect).summary()["D1"]["episodes"] == 0
