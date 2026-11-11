"""Phase 9 gate: the SYN packages are scorable end to end (T-M1 oracle sanity) and the visible
rule baseline produces valid, non-trivial decisions."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from iris.contracts.decisions import (
    ControlRecommendation,
    D1Payload,
    D2Payload,
    D4Payload,
    DecisionRecord,
    SubjectRef,
)
from iris.core.seeds import SeedSet
from iris.engine.baselines.decision_rules import decide
from iris.evaluator.decisions import score_decisions
from iris.synth.build import build_synth_scenario, write_synth_scenario

_BASE = dict(engine_version="oracle", model_version="oracle", policy_version="oracle")


def _read_keys(root: Path, dtype: str) -> list[dict[str, Any]]:
    d = root / "hidden" / "evaluation_key" / dtype
    return [json.loads(p.read_text()) for p in sorted(d.glob("*.json"))] if d.is_dir() else []


def perfect_decisions(root: Path, scenario_id: str) -> list[DecisionRecord]:
    """Decisions that exactly mirror the hidden keys — the oracle upper bound."""
    out: list[DecisionRecord] = []
    for i, k in enumerate(_read_keys(root, "d1")):
        mal = k["verdict"] == "malicious"
        out.append(
            DecisionRecord(
                decision_id=f"dec-o1-{i:03d}",
                scenario_id=scenario_id,
                episode_id=k["episode_id"],
                as_of=k["as_of"],
                type="D1",
                subject_ref=SubjectRef(kind="session", id=k["episode_id"]),
                status="ASSESSED",
                confidence=0.99,
                payload=D1Payload(
                    verdict="malicious" if mal else "benign",
                    scenario_class=k.get("scenario_class") if mal else None,
                    techniques=k.get("techniques", []) if mal else [],
                    tactics=k.get("tactics", []) if mal else [],
                ),
                context_refs=[f"episode:{k['episode_id']}"],
                **_BASE,
            )
        )
    for i, k in enumerate(_read_keys(root, "d2")):
        if k.get("incident"):
            out.append(
                DecisionRecord(
                    decision_id=f"dec-o2-{i:03d}",
                    scenario_id=scenario_id,
                    episode_id=k["episode_id"],
                    as_of=k["as_of"],
                    type="D2",
                    subject_ref=SubjectRef(kind="incident", id=k["episode_id"]),
                    status="ASSESSED",
                    confidence=0.99,
                    payload=D2Payload(priority=k["priority"]),
                    context_refs=[f"episode:{k['episode_id']}"],
                    **_BASE,
                )
            )
    for i, k in enumerate(_read_keys(root, "d4")):
        if k.get("actionable"):
            recs = [
                ControlRecommendation(control_id=r["control_id"], action=r["action"], rationale="oracle")
                for r in k["recommendations"][:3]
            ]
            out.append(
                DecisionRecord(
                    decision_id=f"dec-o4-{i:03d}",
                    scenario_id=scenario_id,
                    episode_id=k["episode_id"],
                    as_of=k["as_of"],
                    type="D4",
                    subject_ref=SubjectRef(kind="control", id=recs[0].control_id),
                    status="ASSESSED",
                    confidence=0.99,
                    payload=D4Payload(recommendations=recs),
                    context_refs=[f"episode:{k['episode_id']}"],
                    **_BASE,
                )
            )
    return out


def test_tm1_oracle_perfect_decisions_score_perfectly(tmp_path):
    built = build_synth_scenario(SeedSet.from_master(8), noise_level="low")
    res = write_synth_scenario(built, tmp_path)
    scores = score_decisions(res.root, perfect_decisions(res.root, built.assembled.scenario_id))
    d1 = scores.d1.summary()
    assert d1["attack_recall"] == 1.0
    assert d1["benign_false_positive_rate"] in (0.0, None)  # None when a scenario has no benign episodes
    assert d1["harmful"] == 0
    if d1["malicious_episodes"]:
        assert d1["scenario_class_accuracy"] == 1.0
    d4 = scores.d4.summary()
    if d4["actionable_episodes"]:
        assert d4["control_recall"] == 1.0


def test_empty_decisions_score_as_missing(tmp_path):
    built = build_synth_scenario(SeedSet.from_master(3), noise_level="low")
    res = write_synth_scenario(built, tmp_path)
    scores = score_decisions(res.root, [])
    assert scores.d1.summary()["missing"] == scores.d1.summary()["episodes"]


def test_baseline_decisions_are_valid_and_cite_evidence(tmp_path):
    built = build_synth_scenario(SeedSet.from_master(12), noise_level="medium")
    res = write_synth_scenario(built, tmp_path)
    decisions = decide(res.root / "visible")
    assert decisions
    visible_ids = {
        r["event_id"]
        for p in (res.root / "visible" / "telemetry").rglob("*.jsonl")
        for r in (json.loads(line) for line in p.read_text().splitlines() if line.strip())
        if "event_id" in r
    }
    for d in decisions:
        assert d.status == "ASSESSED"
        for eid in d.evidence_event_ids:
            assert eid in visible_ids  # baseline cites only real visible events
    # the baseline is beatable, not perfect: it raises false positives on hard negatives
    scores = score_decisions(res.root, decisions)
    assert scores.d1.summary()["attack_recall"] >= 0.5
