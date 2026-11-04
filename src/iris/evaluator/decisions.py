"""Score D1 (classification), D2 (priority) and D4 (control recommendation) decisions
against the hidden reference keys of a composed (``train``) or live (``gold``) package.

Keys live in ``hidden/evaluation_key/{d1,d2,d4}/<episode_id>.json`` (built by
:mod:`iris.oracle.decisions`). Context-tier packages have no such keys; scoring them
reports zero episodes rather than failing.

Alignment is per episode (the checkpoint the keys are built at). An Engine may emit
several decisions of one type for an episode (one per session); they are reduced to one
episode-level answer:

* D1: the episode is called malicious if any ASSESSED D1 says ``malicious``; its
  probability of being malicious is the strongest such confidence (or one minus the
  strongest ``benign`` confidence). ``unknown`` verdicts count as abstentions.
* D2: the highest priority the Engine assigned in the episode.
* D4: the union of recommended controls, ranked by decision confidence, then by the
  order given inside each decision (at most 3 per decision, contract section 14).

Harmful outcomes are counted separately and never averaged into accuracy (contract
section 14.3): a compromised episode called benign with confidence >= 0.8 (D1), an
incident prioritised two or more levels too low (D2), and recommending ``remove`` or
``relax`` for a control the exploit went through (D4).

The evaluator reads key files only; it never imports generator or packager code.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from iris.contracts.decisions import D1Payload, D2Payload, D4Payload, DecisionRecord

LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
HARMFUL_CONFIDENCE = 0.8
HARMFUL_ACTIONS = {"remove", "relax"}


def _round(x: float | None) -> float | None:
    return None if x is None else round(x, 4)


def _ratio(num: float, den: float) -> float | None:
    return _round(num / den) if den else None


def load_type_keys(package_root: Path, dtype: str) -> list[dict[str, Any]]:
    d = package_root / "hidden" / "evaluation_key" / dtype
    return [json.loads(p.read_text(encoding="utf-8")) for p in sorted(d.glob("*.json"))]


def _mine(decisions: list[DecisionRecord], dtype: str, eid: str) -> list[DecisionRecord]:
    return [d for d in decisions if d.type == dtype and d.episode_id == eid]


# ---------------------------------------------------------------- D1


@dataclass
class D1Score:
    episodes: int = 0
    malicious: int = 0
    benign: int = 0
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    abstained: int = 0
    missing: int = 0
    class_correct: int = 0
    technique_jaccard: list[float] = field(default_factory=list)
    harmful: int = 0
    unscored: int = 0
    brier_terms: list[float] = field(default_factory=list)

    def merge(self, other: D1Score) -> None:
        for name in self.__dataclass_fields__:
            mine, theirs = getattr(self, name), getattr(other, name)
            if isinstance(mine, list):
                mine.extend(theirs)
            else:
                setattr(self, name, mine + theirs)

    def summary(self) -> dict[str, Any]:
        assessed = self.tp + self.fp + self.tn + self.fn

        def f1(tp: int, fp: int, fn: int) -> float | None:
            return _ratio(2 * tp, 2 * tp + fp + fn)

        f_mal, f_ben = f1(self.tp, self.fp, self.fn), f1(self.tn, self.fn, self.fp)
        macro = _round((f_mal + f_ben) / 2) if f_mal is not None and f_ben is not None else None
        return {
            "episodes": self.episodes,
            "malicious_episodes": self.malicious,
            "benign_episodes": self.benign,
            "accuracy": _ratio(self.tp + self.tn, assessed),
            # missing/abstained malicious episodes count as misses for attack recall
            "attack_recall": _ratio(self.tp, self.malicious),
            "benign_false_positive_rate": _ratio(self.fp, self.fp + self.tn),
            "macro_f1": macro,
            "scenario_class_accuracy": _ratio(self.class_correct, self.tp),
            "technique_jaccard": _ratio(sum(self.technique_jaccard), len(self.technique_jaccard)),
            "abstained": self.abstained,
            "missing": self.missing,
            "harmful": self.harmful,
            "unscored": self.unscored,
            "brier": _ratio(sum(self.brier_terms), len(self.brier_terms)),
        }


def score_d1_episode(key: dict[str, Any], compromised: bool, decisions: list[DecisionRecord]) -> D1Score:
    s = D1Score(episodes=1)
    truth_mal = key["verdict"] == "malicious"
    s.malicious, s.benign = (1, 0) if truth_mal else (0, 1)
    mine = _mine(decisions, "D1", key["episode_id"])
    calls = [
        d
        for d in mine
        if d.status == "ASSESSED" and isinstance(d.payload, D1Payload) and d.payload.verdict != "unknown"
    ]
    if not calls:
        if mine:
            s.abstained = 1
        else:
            s.missing = 1
        return s
    mal = [d for d in calls if isinstance(d.payload, D1Payload) and d.payload.verdict == "malicious"]
    if mal:
        best = max(mal, key=lambda d: d.confidence or 0.0)
        p_mal = best.confidence or 0.0
    else:
        best = max(calls, key=lambda d: d.confidence or 0.0)
        p_mal = 1.0 - (best.confidence or 0.0)
    pred_mal = bool(mal)
    s.brier_terms.append(((1.0 if truth_mal else 0.0) - p_mal) ** 2)
    if truth_mal and pred_mal:
        s.tp = 1
        assert isinstance(best.payload, D1Payload)
        if best.payload.scenario_class and best.payload.scenario_class == key.get("scenario_class"):
            s.class_correct = 1
        want, got = set(key.get("techniques", [])), set(best.payload.techniques)
        if want or got:
            s.technique_jaccard.append(len(want & got) / len(want | got))
    elif truth_mal:
        s.fn = 1
        if compromised and (1.0 - p_mal) >= HARMFUL_CONFIDENCE:
            s.harmful = 1
    elif pred_mal:
        s.fp = 1
    else:
        s.tn = 1
    return s


# ---------------------------------------------------------------- D2


@dataclass
class D2Score:
    incidents: int = 0
    quiet: int = 0
    exact: int = 0
    within_one: int = 0
    abs_errors: list[int] = field(default_factory=list)
    under_prioritised: int = 0
    over_prioritised: int = 0
    missing: int = 0
    false_escalations: int = 0  # HIGH/CRITICAL on an episode with no incident
    harmful: int = 0
    unscored: int = 0
    confusion: Counter[str] = field(default_factory=Counter)  # "truth->pred"

    def merge(self, other: D2Score) -> None:
        for name in self.__dataclass_fields__:
            mine, theirs = getattr(self, name), getattr(other, name)
            if isinstance(mine, Counter):
                mine.update(theirs)
            elif isinstance(mine, list):
                mine.extend(theirs)
            else:
                setattr(self, name, mine + theirs)

    def summary(self) -> dict[str, Any]:
        scored = len(self.abs_errors)
        return {
            "incident_episodes": self.incidents,
            "quiet_episodes": self.quiet,
            "exact_accuracy": _ratio(self.exact, scored),
            "within_one_accuracy": _ratio(self.within_one, scored),
            "mean_abs_level_error": _ratio(sum(self.abs_errors), scored),
            "under_prioritised": self.under_prioritised,
            "over_prioritised": self.over_prioritised,
            "missing": self.missing,
            "false_escalations": self.false_escalations,
            "harmful": self.harmful,
            "unscored": self.unscored,
            "confusion": dict(sorted(self.confusion.items())),
        }


def score_d2_episode(key: dict[str, Any], decisions: list[DecisionRecord]) -> D2Score:
    s = D2Score()
    mine = [
        d
        for d in _mine(decisions, "D2", key["episode_id"])
        if d.status == "ASSESSED" and isinstance(d.payload, D2Payload)
    ]
    levels = [LEVELS.index(d.payload.priority) for d in mine if isinstance(d.payload, D2Payload)]
    pred = max(levels) if levels else None
    if not key.get("incident"):
        s.quiet = 1
        if pred is not None and pred >= LEVELS.index("HIGH"):
            s.false_escalations = 1
        return s
    s.incidents = 1
    truth = LEVELS.index(key["priority"])
    if pred is None:
        s.missing = 1
        return s
    err = pred - truth
    s.abs_errors.append(abs(err))
    s.exact = int(err == 0)
    s.within_one = int(abs(err) <= 1)
    s.under_prioritised = int(err < 0)
    s.over_prioritised = int(err > 0)
    s.harmful = int(err <= -2)
    s.confusion[f"{LEVELS[truth]}->{LEVELS[pred]}"] += 1
    return s


# ---------------------------------------------------------------- D4


@dataclass
class D4Score:
    actionable: int = 0
    quiet: int = 0
    key_controls: int = 0
    found_controls: int = 0
    recommended: int = 0
    recommended_in_key: int = 0
    action_correct: int = 0
    top1_hits: int = 0
    answered_actionable: int = 0
    noise_recommendations: int = 0  # recommendations on an episode with nothing to fix
    harmful: int = 0
    unscored: int = 0

    def merge(self, other: D4Score) -> None:
        for name in self.__dataclass_fields__:
            setattr(self, name, getattr(self, name) + getattr(other, name))

    def summary(self) -> dict[str, Any]:
        return {
            "actionable_episodes": self.actionable,
            "quiet_episodes": self.quiet,
            "control_recall": _ratio(self.found_controls, self.key_controls),
            "control_precision": _ratio(self.recommended_in_key, self.recommended),
            "action_accuracy": _ratio(self.action_correct, self.found_controls),
            "hit_at_1": _ratio(self.top1_hits, self.answered_actionable),
            "noise_recommendations": self.noise_recommendations,
            "harmful": self.harmful,
            "unscored": self.unscored,
        }


def _ranked_recommendations(decisions: list[DecisionRecord]) -> list[tuple[str, str]]:
    """(control_id, action) in rank order, first mention of a control wins."""
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for d in sorted(decisions, key=lambda d: -(d.confidence or 0.0)):
        if d.status != "ASSESSED" or not isinstance(d.payload, D4Payload):
            continue
        for r in d.payload.recommendations:
            if r.control_id not in seen:
                seen.add(r.control_id)
                out.append((r.control_id, r.action))
    return out


def score_d4_episode(key: dict[str, Any], decisions: list[DecisionRecord]) -> D4Score:
    s = D4Score()
    recs = _ranked_recommendations(_mine(decisions, "D4", key["episode_id"]))
    want = {r["control_id"]: r["action"] for r in key.get("recommendations", [])}
    if not key.get("actionable"):
        s.quiet = 1
        s.noise_recommendations = len(recs)
        return s
    s.actionable = 1
    s.key_controls = len(want)
    s.recommended = len(recs)
    if recs:
        s.answered_actionable = 1
        s.top1_hits = int(recs[0][0] in want)
    for cid, action in recs:
        if cid in want:
            s.recommended_in_key += 1
            s.found_controls += 1
            s.action_correct += int(action == want[cid])
            s.harmful += int(action in HARMFUL_ACTIONS)
    return s


# ---------------------------------------------------------------- package level


@dataclass
class DecisionScores:
    d1: D1Score = field(default_factory=D1Score)
    d2: D2Score = field(default_factory=D2Score)
    d4: D4Score = field(default_factory=D4Score)

    def merge(self, other: DecisionScores) -> None:
        self.d1.merge(other.d1)
        self.d2.merge(other.d2)
        self.d4.merge(other.d4)

    def summary(self, types: tuple[str, ...] = ("D1", "D2", "D4")) -> dict[str, Any]:
        parts = {"D1": self.d1.summary, "D2": self.d2.summary, "D4": self.d4.summary}
        return {t: parts[t]() for t in types}


def score_decisions(package_root: Path, decisions: list[DecisionRecord]) -> DecisionScores:
    """Score every D1/D2/D4 decision of one package against its hidden keys."""
    out = DecisionScores()
    d1_keys = load_type_keys(package_root, "d1")
    d2_keys = load_type_keys(package_root, "d2")
    d4_keys = load_type_keys(package_root, "d4")
    compromised = {k["episode_id"]: bool(k.get("compromised")) for k in d2_keys}
    for k in d1_keys:
        out.d1.merge(score_d1_episode(k, compromised.get(k["episode_id"], False), decisions))
    for k in d2_keys:
        out.d2.merge(score_d2_episode(k, decisions))
    for k in d4_keys:
        out.d4.merge(score_d4_episode(k, decisions))
    for dtype, keys, score in (("D1", d1_keys, out.d1), ("D2", d2_keys, out.d2), ("D4", d4_keys, out.d4)):
        known = {k["episode_id"] for k in keys}
        score.unscored += sum(1 for d in decisions if d.type == dtype and d.episode_id not in known)
    return out
