"""D6 rule baseline: GRC flaws a careful analyst finds with simple checks on visible data.

It reads only the visible package (as-of snapshot per episode, identities, scale
definition). It is the floor the learned D6 model must beat, and a sanity check on the
detectability classes. DC1 and DC3 flaws should mostly be found, DC2 needs telemetry
or posture, and DC4 must not be (nothing visible supports it).
"""

from __future__ import annotations

import json
import statistics
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from iris.contracts.decisions import D6Payload, DecisionRecord, SubjectRef
from iris.core.vclock import parse_iso

BASELINE_VERSION = "d6-rules-0.1.0"
CADENCE_DAYS = {"monthly": 30, "quarterly": 91, "annual": 365, "ad_hoc": 540}
SENSITIVE = {"regulated", "confidential"}


def _load(p: Path) -> Any:
    if p.suffix == ".jsonl":
        return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]
    return json.loads(p.read_text(encoding="utf-8"))


def _dt(v: str | None) -> datetime | None:
    return parse_iso(v) if v else None


class _Out:
    def __init__(self, scn: str, eid: str, at: datetime) -> None:
        self.scn, self.eid, self.at = scn, eid, at
        self.items: list[DecisionRecord] = []
        self.seen: set[str] = set()

    def add(self, coll: str, key: str, flaw_type: str, why: str, conf: float, refs: list[str]) -> None:
        if key in self.seen:
            return
        self.seen.add(key)
        kind = {"risks": "risk", "controls": "control", "exceptions": "exception"}.get(coll, "record")
        self.items.append(
            DecisionRecord(
                decision_id=f"dec-{self.eid[-6:]}-{len(self.items) + 1:03d}",
                scenario_id=self.scn,
                episode_id=self.eid,
                as_of=self.at,
                type="D6",
                subject_ref=SubjectRef(kind=kind, id=key),
                payload=D6Payload(record_ref=f"{coll}:{key}", flaw_type=flaw_type, explanation=why),
                status="ASSESSED",
                confidence=conf,
                context_refs=refs,
                engine_version=BASELINE_VERSION,
                model_version="rules",
                policy_version="baseline",
            )
        )


def decide_episode(visible: Path, eid: str) -> list[DecisionRecord]:
    manifest = _load(visible / "manifest.visible.json")
    snap = _load(visible / "snapshots" / "asof" / f"{eid}.json")
    at = parse_iso(snap["as_of"])
    scale = snap["grc/scale_definition.json"]
    cadence = timedelta(days=CADENCE_DAYS.get(scale["review_cadence"], 365))
    crit_levels: list[str] = scale["criticality_levels"]
    users = {i["username"] for i in _load(visible / "enterprise" / "identities.json")}
    out = _Out(manifest["scenario_id"], eid, at)

    risks = snap["grc/risk_register.json"]
    controls = snap["grc/controls.json"]
    context = snap["grc/business_context.json"]
    exceptions = {e["exception_id"]: e for e in snap["grc/policy_exceptions.json"]}
    history = snap["snapshots/context_history.jsonl"]

    # DC1: internal inconsistencies
    for r in risks:
        if r.get("owner") and r["owner"] not in users:
            out.add("risks", r["risk_id"], "risk.orphan_owner", "risk owner is not a known identity", 0.9,
                    [f"grc/risk_register.json#{r['risk_id']}", "enterprise/identities.json"])  # fmt: skip
    for bc in context:
        if bc.get("data_classification") in SENSITIVE and bc.get("criticality") == crit_levels[0]:
            out.add("business_context", bc["entity_ref"], "asset.criticality_gross",
                    "sensitive data recorded at the lowest criticality", 0.75,
                    [f"grc/business_context.json#{bc['entity_ref']}"])  # fmt: skip

    # DC3: time
    for c in controls:
        exc = exceptions.get(c.get("exception_id") or "")
        if c["implementation_state"] == "exception" and exc and parse_iso(exc["valid_until"]) < at:
            out.add("controls", c["control_id"], "exception.expired_in_use",
                    f"relies on {exc['exception_id']} which expired {exc['valid_until'][:10]}", 0.9,
                    [f"grc/controls.json#{c['control_id']}",
                     f"grc/policy_exceptions.json#{exc['exception_id']}"])  # fmt: skip
        if c["implementation_state"] == "not_assessed":
            out.add("controls", c["control_id"], "control.not_assessed_long", "control never assessed", 0.7,
                    [f"grc/controls.json#{c['control_id']}"])  # fmt: skip
    reviewed = [d for r in risks if (d := _dt(r.get("last_reviewed_at")))]
    if len(reviewed) >= 3:
        median = statistics.median(d.timestamp() for d in reviewed)
        for r in risks:
            d = _dt(r.get("last_reviewed_at"))
            if d and d.timestamp() < median - 1.5 * cadence.total_seconds():
                out.add("risks", r["risk_id"], "risk.stale", "review far older than the rest of the register",
                        0.7, [f"grc/risk_register.json#{r['risk_id']}"])  # fmt: skip
    changed: dict[str, datetime] = {}
    for h in history:
        if h["change_type"] == "business_process_changed":
            changed[h["entity_id"]] = parse_iso(h["effective_at"])
    for h in history:
        if h["change_type"] == "criticality_reassessed":
            changed.pop(h["entity_id"], None)
    for aid, when in sorted(changed.items()):
        out.add("business_context", aid, "asset.criticality_stale",
                f"business process changed {when:%Y-%m-%d}; criticality not re-assessed", 0.6,
                [f"snapshots/context_history.jsonl#{aid}"])  # fmt: skip
        reassessed = {h["entity_id"] for h in history if h["change_type"] == "risk_reassessed"}
        for r in risks:
            if aid in r["entity_refs"] and r["risk_id"] not in reassessed:
                out.add("risks", r["risk_id"], "risk.impact_stale",
                        f"member asset {aid} changed business process; risk not re-scored", 0.5,
                        [f"grc/risk_register.json#{r['risk_id']}"])  # fmt: skip
    return out.items


def decide(visible: Path) -> list[DecisionRecord]:
    manifest = _load(visible / "manifest.visible.json")
    return [d for e in manifest["episodes"] for d in decide_episode(visible, e["episode_id"])]
