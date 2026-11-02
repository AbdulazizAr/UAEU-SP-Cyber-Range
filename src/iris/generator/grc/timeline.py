"""GRC timeline: what changes during the scenario and when the registers catch up.

Reality changes on its own schedule (exceptions expire, an application takes on a new
business process and becomes more critical). The organisation notices through
change management or its periodic reviews, which are sometimes missed and never
catch everything. Each gap between reality and the record is a pending item. While
an item is open and visible, it is a ledgered DC3 flaw (``origin: timeline``).

Outputs:

- ``snapshots/context_history.jsonl`` (visible): an append-only log of recorded changes.
- ``snapshots/asof/<episode_id>.json`` (visible): the registers exactly as recorded
  at each episode start. Only changes with ``recorded_at <= as_of`` are applied.
- ``truth/grc_timeline.json`` and ``truth/asof/<episode_id>.json`` (hidden): reality
  events, pending items, reviews and the flaws active at each episode start.

Seed use: reality events depend only on the org sub-seed and reality itself.
Reviews and change management use the grc sub-seed.
"""

from __future__ import annotations

import copy
import random
from dataclasses import asdict, dataclass, field
from datetime import datetime, time, timedelta
from typing import Any

from iris.contracts.spec import ScenarioSpec
from iris.contracts.visible import (
    Asset,
    BusinessContext,
    ContextChange,
    Control,
    PolicyException,
    Risk,
)
from iris.core.hashing import episode_id, scenario_id
from iris.core.seeds import SeedSet
from iris.core.vclock import iso_z
from iris.generator.grc.recorded import RECORD, FlawEntry, GrcBundle
from iris.generator.grc.style import CADENCE_DAYS, GrcStyle

TIMELINE_VERSION = "timeline-0.1.0"
P_RECLASSIFY = 0.35  # chance that one application changes business process during the scenario
REVIEW_MISS = {"low": 0.40, "medium": 0.20, "high": 0.08}  # P(scheduled review is skipped)
REVIEW_CATCH = {"low": 0.60, "medium": 0.80, "high": 0.95}  # P(held review fixes one pending item)
CHANGE_MGMT = {"low": 0.10, "medium": 0.30, "high": 0.60}  # P(change process re-assesses at once)
CONTROL_SAMPLE = 0.5  # share of controls re-assessed (date only) in a held review
INFRA_PROCESSES = {
    "Core infrastructure",
    "Security monitoring",
    "Identity",
    "Email",
    "Backup and recovery",
    "File sharing",
    "Administration",
    "End-user computing",
}
NON_TARGET_SERVICES = {"Identity"}

ENTITY_COLLECTION = {
    "asset": "business_context",  # timeline asset changes only touch business context
    "control": "controls",
    "risk": "risks",
    "exception": "exceptions",
}
KEY_FIELD = {
    "assets": "asset_id",
    "business_context": "entity_ref",
    "controls": "control_id",
    "risks": "risk_id",
    "exceptions": "exception_id",
}
MODELS: dict[str, Any] = {
    "assets": Asset,
    "business_context": BusinessContext,
    "controls": Control,
    "risks": Risk,
    "exceptions": PolicyException,
}
SNAPSHOT_FILES = {
    "assets": "enterprise/assets.json",
    "business_context": "grc/business_context.json",
    "controls": "grc/controls.json",
    "risks": "grc/risk_register.json",
    "exceptions": "grc/policy_exceptions.json",
}
ITEM_FLAWS = {  # change_type -> (module, evidence, harm, reference action)
    "exception_expired": (
        "exception.expired_in_use",
        ["exception valid_until before as-of", "control still recorded as exception"],
        "high",
        "stop relying on the expired exception: remediate or renew it formally",
    ),
    "criticality_reassessed": (
        "asset.criticality_stale",
        ["context_history business_process change", "criticality valid_from older than the change"],
        "medium",
        "re-assess criticality after the business process change",
    ),
    "risk_reassessed": (
        "risk.impact_stale",
        ["context_history business_process change on a member asset", "risk impact unchanged"],
        "medium",
        "re-score the risk with the new asset criticality",
    ),
}


@dataclass
class RealityEvent:
    event_id: str
    kind: str  # exception_expired | business_reclassified
    effective_at: datetime
    entity_ref: str
    details: dict[str, Any]


@dataclass
class PendingItem:
    item_id: str
    event_id: str
    entity_type: str
    entity_id: str
    change_type: str
    new: dict[str, Any]
    effective_at: datetime  # when reality changed
    visible_from: datetime  # when evidence of the change is visible in the recorded plane
    evidence_ref: str | None = None  # visible pointer written on the fixing change
    resolved_at: datetime | None = None
    resolved_by: str | None = None  # review id | change_management


@dataclass
class Review:
    review_id: str
    scheduled_at: datetime
    held: bool
    recorded_at: datetime | None = None
    caught: list[str] = field(default_factory=list)


@dataclass
class _RawChange:
    entity_type: str
    entity_id: str
    change_type: str
    new: dict[str, Any]
    effective_at: datetime
    recorded_at: datetime
    source: str
    evidence_ref: str | None
    seq: int


def _js(value: Any) -> Any:
    if isinstance(value, datetime):
        return iso_z(value)
    if isinstance(value, list):
        return [_js(v) for v in value]
    return value


def _work_time(day: datetime, rng: random.Random) -> datetime:
    """A moment in office hours (08:00-17:00 UTC) on the given day."""
    base = datetime.combine(day.date(), time(8), tzinfo=day.tzinfo)
    return base + timedelta(minutes=rng.randint(0, 9 * 60))


# ---------------------------------------------------------------- the timeline


@dataclass
class GrcTimeline:
    version: str
    scenario_id: str
    calendar_start: datetime
    calendar_end: datetime
    base: dict[str, dict[str, dict[str, Any]]]
    events: list[RealityEvent]
    items: list[PendingItem]
    reviews: list[Review]
    changes: list[ContextChange]
    baseline_ledger: list[FlawEntry]
    ledger: list[FlawEntry]  # timeline flaws only
    episodes: list[tuple[str, datetime]]  # (episode_id, as_of)
    static_visible: dict[str, Any]  # control mappings + scale definition, unchanged over time

    # ---- views

    def history(self, at: datetime) -> list[ContextChange]:
        return [c for c in self.changes if c.recorded_at <= at]

    def snapshot(self, at: datetime) -> dict[str, list[dict[str, Any]]]:
        """Registers as recorded at ``at``: baseline plus changes recorded by then (validated)."""
        recs = copy.deepcopy(self.base)
        for chg in self.history(at):
            coll = ENTITY_COLLECTION[chg.entity_type]
            rec = recs[coll][chg.entity_id]
            rec.update(chg.new or {})
            rec["recorded_at"] = chg.recorded_at
            rec["valid_from"] = chg.effective_at
        return {
            coll: [MODELS[coll](**v).model_dump(mode="json") for _, v in sorted(recs[coll].items())]
            for coll in MODELS
        }

    def all_flaws(self) -> list[FlawEntry]:
        return [*self.baseline_ledger, *self.ledger]

    def active_flaws(self, at: datetime) -> list[FlawEntry]:
        return [f for f in self.all_flaws() if f.active_at(at)]

    def visible(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "snapshots/context_history.jsonl": [c.model_dump(mode="json") for c in self.changes]
        }
        for eid, at in self.episodes:
            snap = self.snapshot(at)
            out[f"snapshots/asof/{eid}.json"] = {
                "episode_id": eid,
                "as_of": iso_z(at),
                **{SNAPSHOT_FILES[k]: v for k, v in snap.items()},
                **self.static_visible,
                "snapshots/context_history.jsonl": [c.model_dump(mode="json") for c in self.history(at)],
            }
        return out

    def hidden(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "truth/grc_timeline.json": {
                "version": self.version,
                "calendar_start": self.calendar_start,
                "calendar_end": self.calendar_end,
                "events": [asdict(e) for e in self.events],
                "items": [asdict(i) for i in self.items],
                "reviews": [asdict(r) for r in self.reviews],
            },
            "truth/grc_flaw_ledger.jsonl": [asdict(f) for f in self.all_flaws()],
        }
        for eid, at in self.episodes:
            out[f"truth/asof/{eid}.json"] = {
                "episode_id": eid,
                "as_of": iso_z(at),
                "active_flaw_ids": [f.flaw_id for f in self.active_flaws(at)],
                "reality_event_ids": [e.event_id for e in self.events if e.effective_at <= at],
                "open_item_ids": [
                    i.item_id
                    for i in self.items
                    if i.effective_at <= at and (i.resolved_at is None or at < i.resolved_at)
                ],
            }
        return out


# ---------------------------------------------------------------- builder


class _Builder:
    def __init__(self, spec: ScenarioSpec, bundle: GrcBundle, seeds: SeedSet) -> None:
        self.spec = spec
        self.bundle = bundle
        self.seeds = seeds
        self.reality = bundle.reality
        self.style: GrcStyle = bundle.style
        self.maturity = spec.organization.maturity.value
        self.start = self.reality.calendar_start
        self.end = self.reality.calendar_end
        self.cadence = CADENCE_DAYS[self.style.cadence]
        self.base = self._base_records()
        self.used = self._flawed_refs()
        self.events: list[RealityEvent] = []
        self.items: list[PendingItem] = []
        self.raw: list[_RawChange] = []

    def _base_records(self) -> dict[str, dict[str, dict[str, Any]]]:
        b = self.bundle
        lists: dict[str, list[Any]] = {
            "assets": b.assets,
            "business_context": b.business_context,
            "controls": b.controls,
            "risks": b.risks,
            "exceptions": b.exceptions,
        }
        return {
            coll: {getattr(m, KEY_FIELD[coll]): m.model_dump(mode="python") for m in models}
            for coll, models in lists.items()
        }

    def _flawed_refs(self) -> set[str]:
        """Objects a baseline flaw touched: reviews leave them as they are (the flaw persists)."""
        refs: set[str] = set()
        for f in self.bundle.ledger:
            refs.add(f.object_ref)
            coll, key = f.object_ref.split(":", 1)
            if coll == "assets":
                refs.add(f"business_context:{key}")
        return refs

    def _open(self, coll: str, key: str) -> bool:
        return key in self.base[coll] and f"{coll}:{key}" not in self.used

    def _change(self, **kw: Any) -> None:
        if kw["recorded_at"] <= self.end:
            self.raw.append(_RawChange(seq=len(self.raw), **kw))

    def _item(
        self,
        ev: RealityEvent,
        entity_type: str,
        entity_id: str,
        change_type: str,
        new: dict[str, Any],
        visible_from: datetime,
        evidence_ref: str | None = None,
    ) -> None:
        current = self.base[ENTITY_COLLECTION[entity_type]][entity_id]
        new = {k: v for k, v in new.items() if current.get(k) != v}  # already right (by luck or noise)
        if visible_from > self.end or not new:
            return
        self.items.append(
            PendingItem(
                item_id=f"P-{len(self.items) + 1:03d}",
                event_id=ev.event_id,
                entity_type=entity_type,
                entity_id=entity_id,
                change_type=change_type,
                new=new,
                effective_at=ev.effective_at,
                visible_from=visible_from,
                evidence_ref=evidence_ref,
            )
        )

    def _event(self, kind: str, at: datetime, ref: str, details: dict[str, Any]) -> RealityEvent:
        ev = RealityEvent(f"EV-{len(self.events) + 1:03d}", kind, at, ref, details)
        self.events.append(ev)
        return ev

    # ---- reality events (independent of the grc seed)

    def exception_expiries(self) -> None:
        for eid, e in sorted(self.reality.exceptions.items()):
            if not self.start < e.valid_until <= self.end:
                continue
            control = self.reality.controls[e.control_id]
            ev = self._event(
                "exception_expired",
                e.valid_until,
                f"exceptions:{eid}",
                {"control_id": e.control_id, "control_state": control.state},
            )
            rec = self.base["controls"].get(e.control_id)
            if (
                rec is not None
                and self._open("controls", e.control_id)
                and rec["implementation_state"] == "exception"
                and rec["exception_id"] == eid
            ):
                self._item(
                    ev,
                    "control",
                    e.control_id,
                    "exception_expired",
                    {"implementation_state": control.state, "exception_id": None},
                    e.valid_until,
                    f"exception:{eid}",
                )

    def reclassification(self) -> None:
        rng = self.seeds.stream("org", "reclassify")
        if rng.random() >= P_RECLASSIFY:
            return
        services = [s for s in self.spec.organization.business_services if s not in NON_TARGET_SERVICES]
        cands = sorted(
            aid
            for aid, a in self.reality.assets.items()
            if a.business_process not in INFRA_PROCESSES and a.criticality <= 4
        )
        if not cands:
            return
        aid = rng.choice(cands)
        a = self.reality.assets[aid]
        targets = [s for s in services if s != a.business_process]
        if not targets:
            return
        new_process = rng.choice(targets)
        # Place the change before the last episode so at least one episode sees its aftermath
        # (episode times are spec facts from the time sub-seed, not the grc one).
        last = max(e.virtual_start for e in self.spec.episodes)
        span = (last - self.start).days - 2
        if span < 1:
            span = (self.end - self.start).days - 1
        day = self.start + timedelta(days=rng.randint(1, max(1, span)))
        at = _work_time(day, rng)
        new_crit = min(5, a.criticality + 1)
        ev = self._event(
            "business_reclassified",
            at,
            f"assets:{aid}",
            {
                "business_process": [a.business_process, new_process],
                "criticality": [a.criticality, new_crit],
            },
        )
        if not self._open("business_context", aid):
            return  # unregistered or neglected record: nothing gets written
        lag_rng = self.seeds.stream("org", "reclassify_record")
        noted = at + timedelta(hours=lag_rng.randint(1, 72))
        self._change(
            entity_type="asset",
            entity_id=aid,
            change_type="business_process_changed",
            new={"business_process": new_process},
            effective_at=at,
            recorded_at=noted,
            source="business_owner",
            evidence_ref=None,
        )
        if noted > self.end:
            return
        self._item(
            ev,
            "asset",
            aid,
            "criticality_reassessed",
            self._crit_fields(aid, a.criticality, new_crit),
            noted,
            f"asset:{aid}",
        )
        crit = {k: v.criticality for k, v in self.reality.assets.items()} | {aid: new_crit}
        for rid, rr in sorted(self.reality.risks.items()):
            if aid not in rr.entity_refs or not self._open("risks", rid):
                continue
            impact = max(1, min(5, max(crit[m] for m in rr.entity_refs)))
            old, new = (
                self._risk_texts(rr.likelihood, rr.impact, rr.control_factor),
                self._risk_texts(rr.likelihood, impact, rr.control_factor),
            )
            diff = {k: v for k, v in new.items() if old[k] != v}
            self._item(ev, "risk", rid, "risk_reassessed", diff, noted, f"asset:{aid}")

    def _crit_fields(self, aid: str, old: int, new: int) -> dict[str, Any]:
        s = self.style
        if s.crit_to_text(old) == s.crit_to_text(new):
            return {}
        out: dict[str, Any] = {"criticality": s.crit_to_text(new)}
        if s.criticality_scale == "cia":
            data = self.reality.assets[aid].data_class
            out["confidentiality"] = (
                "H" if data in ("regulated", "confidential") else ("M" if new >= 3 else "L")
            )
            out["integrity"] = out["availability"] = s.crit_to_text(new)
        return out

    def _risk_texts(self, likelihood: int, impact: int, cf: float) -> dict[str, Any]:
        s = self.style
        inherent = likelihood * impact
        idx = s.risk_level_index(round(inherent * cf, 1))
        return {
            "impact": s.factor_to_text(impact),
            "raw_risk": s.risk_to_text(inherent),
            "residual_risk": s.risk_levels()[idx],
            "risk_level": s.risk_levels()[idx],
            "treatment": "mitigate" if idx >= len(s.risk_levels()) // 2 else "accept",
        }

    # ---- the organisation catching up (grc seed)

    def _resolve(self, item: PendingItem, at: datetime, by: str, effective: datetime) -> None:
        item.resolved_at, item.resolved_by = at, by
        source = "periodic_review" if by.startswith("RV-") else by
        self._change(
            entity_type=item.entity_type,
            entity_id=item.entity_id,
            change_type=item.change_type,
            new=dict(item.new),
            effective_at=effective,
            recorded_at=at,
            source=source,
            evidence_ref=item.evidence_ref,
        )

    def change_management(self) -> None:
        rng = self.seeds.stream("grc", "change_mgmt")
        for ev in self.events:
            mine = [i for i in self.items if i.event_id == ev.event_id]
            if not mine or rng.random() >= CHANGE_MGMT[self.maturity]:
                continue
            at = mine[0].visible_from + timedelta(days=rng.randint(1, 7), minutes=rng.randint(0, 480))
            if at > self.end:
                continue
            for i in mine:
                self._resolve(i, at, "change_management", i.effective_at)

    def reviews(self) -> list[Review]:
        rng = self.seeds.stream("grc", "reviews")
        out: list[Review] = []
        t = _work_time(self.start + timedelta(days=rng.randint(1, self.cadence)), rng)
        while t < self.end:
            rv = Review(f"RV-{len(out) + 1:02d}", t, held=rng.random() >= REVIEW_MISS[self.maturity])
            out.append(rv)
            if rv.held:
                rec_at = t + timedelta(days=rng.randint(0, 3), minutes=rng.randint(0, 240))
                rv.recorded_at = rec_at
                for item in self.items:
                    pending = item.resolved_at is None and item.visible_from <= t
                    if pending and rng.random() < REVIEW_CATCH[self.maturity] and rec_at <= self.end:
                        self._resolve(item, rec_at, rv.review_id, item.effective_at)
                        rv.caught.append(item.item_id)
                for rid in sorted(self.base["risks"]):
                    if self._open("risks", rid):
                        self._change(
                            entity_type="risk",
                            entity_id=rid,
                            change_type="risk_review",
                            new={"last_reviewed_at": t, "next_review_due": t + timedelta(days=self.cadence)},
                            effective_at=t,
                            recorded_at=rec_at,
                            source="periodic_review",
                            evidence_ref=None,
                        )
                for cid in sorted(self.base["controls"]):
                    if self._open("controls", cid) and rng.random() < CONTROL_SAMPLE:
                        self._change(
                            entity_type="control",
                            entity_id=cid,
                            change_type="control_assessment",
                            new={"last_assessed_at": t},
                            effective_at=t,
                            recorded_at=rec_at,
                            source="periodic_review",
                            evidence_ref=None,
                        )
            t = _work_time(t + timedelta(days=self.cadence), rng)
        return out

    # ---- outputs

    def changes(self) -> list[ContextChange]:
        """Order by recorded time and fill ``previous`` by replaying on the baseline."""
        recs = copy.deepcopy(self.base)
        out: list[ContextChange] = []
        for n, r in enumerate(sorted(self.raw, key=lambda r: (r.recorded_at, r.seq)), start=1):
            rec = recs[ENTITY_COLLECTION[r.entity_type]][r.entity_id]
            previous = {k: _js(rec.get(k)) for k in r.new}
            rec.update(r.new)
            out.append(
                ContextChange(
                    change_id=f"CHG-{n:06d}",
                    effective_at=r.effective_at,
                    recorded_at=r.recorded_at,
                    entity_type=r.entity_type,
                    entity_id=r.entity_id,
                    change_type=r.change_type,
                    previous=previous,
                    new={k: _js(v) for k, v in r.new.items()},
                    evidence_ref=r.evidence_ref,
                    source=r.source,
                )
            )
        return out

    def flaws(self) -> list[FlawEntry]:
        out: list[FlawEntry] = []
        n0 = len(self.bundle.ledger)
        for i in self.items:
            module, evidence, harm, action = ITEM_FLAWS[i.change_type]
            out.append(
                FlawEntry(
                    flaw_id=f"F-{n0 + len(out) + 1:03d}",
                    module=module,
                    level="L4",
                    detectability="DC3",
                    object_ref=f"{ENTITY_COLLECTION[i.entity_type]}:{i.entity_id}",
                    fields=sorted(i.new) or [RECORD],
                    active_from=i.visible_from,
                    evidence_refs=[*evidence, i.event_id],
                    harm_if_ignored=harm,
                    reference_action=action,
                    active_until=i.resolved_at,
                    origin="timeline",
                )
            )
        return out


def build_timeline(
    spec: ScenarioSpec,
    bundle: GrcBundle,
    seeds: SeedSet | None = None,
    scn_id: str | None = None,
) -> GrcTimeline:
    seeds = seeds or SeedSet.from_dict(spec.seeds.model_dump())
    scn = scn_id or scenario_id({"seeds": seeds.to_dict()})
    b = _Builder(spec, bundle, seeds)
    b.exception_expiries()
    b.reclassification()
    b.change_management()
    reviews = b.reviews()
    return GrcTimeline(
        version=TIMELINE_VERSION,
        scenario_id=scn,
        calendar_start=b.start,
        calendar_end=b.end,
        base=b.base,
        events=b.events,
        items=b.items,
        reviews=reviews,
        changes=b.changes(),
        baseline_ledger=list(bundle.ledger),
        ledger=b.flaws(),
        episodes=[(episode_id(scn, e.index), e.virtual_start) for e in spec.episodes],
        static_visible={
            "grc/control_mappings.json": [m.model_dump(mode="json") for m in bundle.control_mappings],
            "grc/scale_definition.json": bundle.scale_definition.model_dump(mode="json"),
        },
    )
