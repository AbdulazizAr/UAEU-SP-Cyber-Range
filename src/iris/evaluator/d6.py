"""Score D6 (GRC flaw finding) decisions against the hidden reference key.

Matching is on the entity key (record IDs are unique across registers; assets also
match by hostname or IP). Each flaw can be matched once, highest confidence first.
- DC1-DC3 flaws count toward recall.
- DC4 flaws have no visible evidence by design. A confident claim on one is
  "unsupported", neither a hit nor a false positive.
- Claims on noise-touched records are "noise claims", not false positives.
Harm-weighted recall weights high 3, medium 2, low 1.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from iris.contracts.decisions import D6Payload, DecisionRecord

HARM_WEIGHT = {"high": 3.0, "medium": 2.0, "low": 1.0}
COUNTED = ("DC1", "DC2", "DC3")


def norm_ref(ref: str) -> str:
    """``controls:CTRL-X``, ``grc/controls.json#CTRL-X`` or ``CTRL-X`` -> ``CTRL-X`` (case-folded)."""
    ref = ref.strip()
    if "#" in ref:
        ref = ref.rsplit("#", 1)[1]
    elif ":" in ref and ref.count(".") != 3:  # keep bare IPv4 addresses intact
        ref = ref.split(":", 1)[1]
    return ref.casefold()


@dataclass
class D6Score:
    episodes: int = 0
    clean_episodes: int = 0
    flaws: Counter[str] = field(default_factory=Counter)  # by DC class
    found: Counter[str] = field(default_factory=Counter)
    type_correct: int = 0
    false_positives: int = 0
    noise_claims: int = 0
    unsupported_dc4: int = 0
    abstained: int = 0
    clean_with_alarm: int = 0
    harm_total: float = 0.0
    harm_found: float = 0.0
    brier_terms: list[float] = field(default_factory=list)

    @property
    def tp(self) -> int:
        return sum(self.found[c] for c in COUNTED)

    def summary(self) -> dict[str, Any]:
        counted = sum(self.flaws[c] for c in COUNTED)
        claims = self.tp + self.false_positives
        return {
            "episodes": self.episodes,
            "flaws_by_class": dict(sorted(self.flaws.items())),
            "recall": round(self.tp / counted, 4) if counted else None,
            "recall_by_class": {c: round(self.found[c] / self.flaws[c], 4) for c in COUNTED if self.flaws[c]},
            "precision": round(self.tp / claims, 4) if claims else None,
            "type_accuracy": round(self.type_correct / self.tp, 4) if self.tp else None,
            "harm_weighted_recall": round(self.harm_found / self.harm_total, 4) if self.harm_total else None,
            "false_positives": self.false_positives,
            "noise_claims": self.noise_claims,
            "unsupported_dc4_claims": self.unsupported_dc4,
            "clean_episode_false_alarm_rate": (
                round(self.clean_with_alarm / self.clean_episodes, 4) if self.clean_episodes else None
            ),
            "abstained": self.abstained,
            "brier": round(sum(self.brier_terms) / len(self.brier_terms), 4) if self.brier_terms else None,
        }

    def merge(self, other: D6Score) -> None:
        for name in self.__dataclass_fields__:
            mine, theirs = getattr(self, name), getattr(other, name)
            if isinstance(mine, Counter):
                mine.update(theirs)
            elif isinstance(mine, list):
                mine.extend(theirs)
            else:
                setattr(self, name, mine + theirs)


def score_episode(key: dict[str, Any], decisions: list[DecisionRecord]) -> D6Score:
    s = D6Score(episodes=1, clean_episodes=1 if key["clean"] else 0)
    flaws = key["flaws"]
    for f in flaws:
        s.flaws[f["detectability"]] += 1
        if f["detectability"] in COUNTED:
            s.harm_total += HARM_WEIGHT.get(f["harm"], 1.0)
    alias = {f["flaw_id"]: {a.casefold() for a in f["aliases"]} | {f["key"].casefold()} for f in flaws}
    tolerated = {k.casefold() for k in key.get("tolerated_keys", [])}
    matched: set[str] = set()
    fp_here = 0
    mine = [d for d in decisions if d.type == "D6" and d.episode_id == key["episode_id"]]
    for d in sorted(mine, key=lambda d: -(d.confidence or 0.0)):
        if d.status != "ASSESSED" or not isinstance(d.payload, D6Payload):
            s.abstained += 1 if d.status == "ABSTAINED" else 0
            continue
        ref = norm_ref(d.payload.record_ref)
        hit = next((f for f in flaws if f["flaw_id"] not in matched and ref in alias[f["flaw_id"]]), None)
        conf = d.confidence or 0.0
        if hit is not None:
            matched.add(hit["flaw_id"])
            if hit["detectability"] == "DC4":
                s.unsupported_dc4 += 1 if conf >= 0.5 else 0
                continue
            s.found[hit["detectability"]] += 1
            s.harm_found += HARM_WEIGHT.get(hit["harm"], 1.0)
            s.type_correct += 1 if d.payload.flaw_type == hit["module"] else 0
            s.brier_terms.append((1 - conf) ** 2)
        elif ref in tolerated:
            s.noise_claims += 1
            s.brier_terms.append(conf**2)
        else:
            s.false_positives += 1
            fp_here += 1
            s.brier_terms.append(conf**2)
    if key["clean"] and fp_here:
        s.clean_with_alarm = 1
    return s


def load_keys(package_root: Path) -> list[dict[str, Any]]:
    d = package_root / "hidden" / "evaluation_key" / "d6"
    return [json.loads(p.read_text(encoding="utf-8")) for p in sorted(d.glob("*.json"))]


def score_package(package_root: Path, decisions: list[DecisionRecord]) -> D6Score:
    total = D6Score()
    for key in load_keys(package_root):
        total.merge(score_episode(key, decisions))
    return total
