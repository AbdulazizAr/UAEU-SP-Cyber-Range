"""RECORDED view = reality -> organisation style -> bounded noise -> rare ledgered flaws.

Every change to the faithful record goes through :class:`Recorder`, which logs the cause
(``noise:<kind>`` or a flaw ID). :func:`diff_audit` then recomputes the difference
between the faithful and final records independently and proves that every difference
is logged, every logged change is real, noise stays within its bounds, and every flaw in
the ledger produced at least one change (INPUT Part 2, A9 step 8).
"""

from __future__ import annotations

import copy
import random
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from typing import Any

from iris.contracts.common import AssetRole
from iris.contracts.spec import ScenarioSpec
from iris.contracts.visible import (
    Asset,
    BusinessContext,
    Control,
    ControlMapping,
    FrameworkRef,
    PolicyException,
    Risk,
    ScaleDefinition,
)
from iris.core.seeds import SeedSet
from iris.generator.grc.reality import (
    GRC_FORMULA_VERSION,
    GrcReality,
    build_reality,
    load_control_catalog,
)
from iris.generator.grc.style import CADENCE_DAYS, GrcStyle

MAPPING_VERSION = "ctrl-map-0.1.0"
RUBRIC_VERSION = "rubric-0.1.0"
COLLECTIONS = ("assets", "business_context", "controls", "risks", "exceptions")
RECORD = "__record__"

NOISE_RATES = {  # per record, by maturity
    "crit_off_by_one": {"low": 0.10, "medium": 0.05, "high": 0.02},
    "owner_missing": {"low": 0.20, "medium": 0.08, "high": 0.02},
    "unit_variant": {"low": 0.15, "medium": 0.05, "high": 0.0},
    "risk_level_shift": {"low": 0.15, "medium": 0.08, "high": 0.03},
}
FLAW_BUDGET = {  # P(clean), count range when not clean, cap (INPUT Part 2, A7.5)
    "high": (0.45, (1, 2), 3),
    "medium": (0.30, (1, 3), 5),
    "low": (0.15, (2, 5), 8),
}
# Levels L1-L4 follow from each module; L5 compound flaws arrive in v1.1.
ASSET_TYPES = {
    AssetRole.ROUTER_FIREWALL: "network",
    AssetRole.IDS_SENSOR: "security",
    AssetRole.SIEM: "security",
    AssetRole.WORKSTATION: "endpoint",
    AssetRole.ADMIN_WORKSTATION: "endpoint",
}


@dataclass
class Mutation:
    collection: str
    key: str
    field: str
    old: Any
    new: Any
    cause: str


@dataclass
class FlawEntry:
    flaw_id: str
    module: str
    level: str
    detectability: str  # DC1 internal inconsistency | DC2 telemetry | DC3 time | DC4 undetectable by design
    object_ref: str
    fields: list[str]
    active_from: datetime
    evidence_refs: list[str]
    harm_if_ignored: str
    reference_action: str
    rubric_version: str = RUBRIC_VERSION
    # Baseline flaws hold for the whole scenario (None). Timeline flaws end when a review fixes the record.
    active_until: datetime | None = None
    origin: str = "baseline"  # baseline | timeline

    def active_at(self, at: datetime) -> bool:
        return self.active_from <= at and (self.active_until is None or at < self.active_until)


class Recorder:
    def __init__(self, records: dict[str, dict[str, dict[str, Any]]]) -> None:
        self.rec = records
        self.log: list[Mutation] = []

    def set(self, coll: str, key: str, fld: str, new: Any, cause: str) -> None:
        old = self.rec[coll][key][fld]
        if old == new:
            return
        self.rec[coll][key][fld] = new
        self.log.append(Mutation(coll, key, fld, old, new, cause))

    def delete(self, coll: str, key: str, cause: str) -> None:
        old = self.rec[coll].pop(key)
        self.log.append(Mutation(coll, key, RECORD, old, None, cause))

    def insert(self, coll: str, key: str, record: dict[str, Any], cause: str) -> None:
        self.rec[coll][key] = record
        self.log.append(Mutation(coll, key, RECORD, None, record, cause))


# ---------------------------------------------------------------- faithful record


def _faithful(spec: ScenarioSpec, reality: GrcReality, style: GrcStyle, rng: random.Random) -> dict[str, Any]:
    start = reality.calendar_start
    cadence = CADENCE_DAYS[style.cadence]
    svc_by_asset: dict[str, list[str]] = {}
    for s in spec.services:
        svc_by_asset.setdefault(s.asset_id, []).append(s.service_id)

    def recorded_at() -> datetime:
        return start - timedelta(days=rng.randint(cadence // 2 + 5, cadence + 365))

    def reviewed() -> datetime:
        return start - timedelta(days=rng.randint(0, cadence))

    assets: dict[str, dict[str, Any]] = {}
    context: dict[str, dict[str, Any]] = {}
    for a in spec.assets:
        r = reality.assets[a.asset_id]
        rec_at = recorded_at()
        assets[a.asset_id] = {
            "asset_id": a.asset_id,
            "hostname": a.hostname,
            "role": a.role.value,
            "asset_type": ASSET_TYPES.get(a.role, "server"),
            "ip_addresses": [att.ip for att in a.attachments],
            "zone": a.attachments[0].zone if len(a.attachments) == 1 else None,
            "os_profile": a.os_profile,
            "service_ids": svc_by_asset.get(a.asset_id, []),
            "population_size": a.population_size,
            "wazuh_agent_name": a.hostname if a.monitored else None,
            "source_of_record": "cmdb",
            "recorded_at": rec_at,
            "last_reviewed_at": reviewed(),
        }
        cia = None
        if style.criticality_scale == "cia":
            lv = style.crit_to_text(r.criticality)
            conf = (
                "H" if r.data_class in ("regulated", "confidential") else ("M" if r.criticality >= 3 else "L")
            )
            cia = (conf, lv, lv)
        context[a.asset_id] = {
            "entity_ref": a.asset_id,
            "business_unit": r.business_unit,
            "business_process": r.business_process,
            "business_owner": r.business_owner,
            "technical_owner": r.technical_owner,
            "criticality": style.crit_to_text(r.criticality),
            "confidentiality": cia[0] if cia else None,
            "integrity": cia[1] if cia else None,
            "availability": cia[2] if cia else None,
            "data_classification": r.data_class,
            "recorded_at": rec_at,
            "valid_from": rec_at,
        }

    controls: dict[str, dict[str, Any]] = {}
    for cid, c in reality.controls.items():
        exc = reality.active_exception_for(cid, start)
        state = "exception" if exc and c.state != "implemented" else c.state
        controls[cid] = {
            "control_id": cid,
            "control_name": c.name,
            "control_family": style.family(c.function),
            "implementation_state": state,
            "applies_to_assets": sorted(c.per_asset),
            "exception_id": exc.exception_id if state == "exception" and exc else None,
            "last_assessed_at": reviewed(),
            "mapping_version": MAPPING_VERSION,
            "recorded_at": recorded_at(),
        }

    risks: dict[str, dict[str, Any]] = {}
    for rid, rr in reality.risks.items():
        rev = reviewed()
        idx = style.risk_level_index(rr.residual)
        risks[rid] = {
            "risk_id": rid,
            "entity_refs": rr.entity_refs,
            "risk_scenario": rr.scenario,
            "likelihood": style.factor_to_text(rr.likelihood),
            "impact": style.factor_to_text(rr.impact),
            "raw_risk": style.risk_to_text(rr.inherent),
            "control_factor": rr.control_factor,
            "residual_risk": style.risk_levels()[idx],
            "risk_level": style.risk_levels()[idx],
            "treatment": "mitigate" if idx >= len(style.risk_levels()) // 2 else "accept",
            "owner": rr.owner,
            "linked_control_ids": rr.linked_controls,
            "status": "open",
            "last_reviewed_at": rev,
            "next_review_due": rev + timedelta(days=cadence),
            "scoring_version": GRC_FORMULA_VERSION,
            "recorded_at": recorded_at(),
        }

    exceptions: dict[str, dict[str, Any]] = {}
    for eid, e in reality.exceptions.items():
        exceptions[eid] = {
            "exception_id": eid,
            "control_id": e.control_id,
            "asset_ids": e.asset_ids,
            "reason": e.reason,
            "approver": e.approver,
            "approved_state": "approved",
            "valid_from": e.valid_from,
            "valid_until": e.valid_until,
            "compensating_controls": e.compensating,
            "recorded_at": e.valid_from,
        }
    return {
        "assets": assets,
        "business_context": context,
        "controls": controls,
        "risks": risks,
        "exceptions": exceptions,
    }


# ---------------------------------------------------------------- noise


def _canon(text: str | None) -> str:
    t = (text or "").lower().replace(" dept", "").replace(" department", "").replace(" team", "")
    return t.replace("&", "and").strip()


def _apply_noise(rec: Recorder, style: GrcStyle, maturity: str, rng: random.Random) -> None:
    rate = {k: v[maturity] for k, v in NOISE_RATES.items()}
    levels = style.crit_levels()
    for key in sorted(rec.rec["business_context"]):
        bc = rec.rec["business_context"][key]
        if rng.random() < rate["crit_off_by_one"]:
            i = levels.index(bc["criticality"])
            j = i + rng.choice([-1, 1])
            if 0 <= j < len(levels):
                rec.set("business_context", key, "criticality", levels[j], "noise:crit_off_by_one")
        if bc["business_owner"] and rng.random() < rate["owner_missing"]:
            rec.set("business_context", key, "business_owner", None, "noise:owner_missing")
        if rng.random() < rate["unit_variant"]:
            variant = rng.choice(
                [f"{bc['business_unit']} Dept", bc["business_unit"].lower(), f"{bc['business_unit']} team"]
            )
            rec.set("business_context", key, "business_unit", variant, "noise:unit_variant")
    rlevels = style.risk_levels()
    for key in sorted(rec.rec["risks"]):
        r = rec.rec["risks"][key]
        if rng.random() < rate["risk_level_shift"]:
            i = rlevels.index(r["residual_risk"])
            j = i + rng.choice([-1, 1])
            if 0 <= j < len(rlevels):
                rec.set("risks", key, "residual_risk", rlevels[j], "noise:risk_level_shift")
                rec.set("risks", key, "risk_level", rlevels[j], "noise:risk_level_shift")


def _noise_in_bounds(m: Mutation, style: GrcStyle) -> bool:
    kind = m.cause.split(":", 1)[1]
    if kind == "crit_off_by_one":
        lv = style.crit_levels()
        return abs(lv.index(m.new) - lv.index(m.old)) <= 1
    if kind == "owner_missing":
        return m.new is None
    if kind == "unit_variant":
        return _canon(m.new) == _canon(m.old)
    if kind == "risk_level_shift":
        lv = style.risk_levels()
        return abs(lv.index(m.new) - lv.index(m.old)) <= 1
    return False


# ---------------------------------------------------------------- flaws


@dataclass
class _Ctx:
    spec: ScenarioSpec
    reality: GrcReality
    style: GrcStyle
    rec: Recorder
    rng: random.Random
    used: set[str] = field(default_factory=set)
    ledger: list[FlawEntry] = field(default_factory=list)

    def next_id(self) -> str:
        return f"F-{len(self.ledger) + 1:03d}"

    def add(self, entry: FlawEntry) -> None:
        self.ledger.append(entry)
        self.used.add(entry.object_ref)


def _flaw_shadow_asset(ctx: _Ctx) -> bool:
    cands = [
        a.asset_id
        for a in ctx.spec.assets
        if a.monitored
        and a.role not in (AssetRole.ROUTER_FIREWALL, AssetRole.IDS_SENSOR, AssetRole.SIEM)
        and f"assets:{a.asset_id}" not in ctx.used
        and a.asset_id in ctx.rec.rec["assets"]
    ]
    if not cands:
        return False
    aid = ctx.rng.choice(sorted(cands))
    fid = ctx.next_id()
    ctx.rec.delete("assets", aid, fid)
    ctx.rec.delete("business_context", aid, fid)
    ctx.add(
        FlawEntry(
            fid,
            "asset.shadow",
            "L3",
            "DC2",
            f"assets:{aid}",
            [RECORD],
            ctx.reality.calendar_start,
            ["wazuh agent roster", "syscollector", "suricata flows"],
            "medium",
            "add the host to the inventory, assign owner and criticality",
        )
    )
    ctx.used.add(f"business_context:{aid}")
    return True


def _flaw_ghost_asset(ctx: _Ctx) -> bool:
    templates = [
        a
        for a in ctx.spec.assets
        if a.role in (AssetRole.WORKSTATION, AssetRole.APP_SERVER)
        and a.attachments
        and a.asset_id in ctx.rec.rec["assets"]
        and a.asset_id in ctx.rec.rec["business_context"]
    ]
    if not templates:
        return False
    t = ctx.rng.choice(sorted(templates, key=lambda a: a.asset_id))
    code = t.asset_id.split("-")[1]
    aid = f"AST-{code}-9{ctx.rng.randint(10, 99)}"
    if aid in ctx.rec.rec["assets"]:
        return False
    zone = t.attachments[0].zone
    net = next(z for z in ctx.spec.zones if z.name == zone).subnet.rsplit(".", 1)[0]
    used_ips = {att.ip for a in ctx.spec.assets for att in a.attachments}
    free = [f"{net}.{n}" for n in range(10, 251) if f"{net}.{n}" not in used_ips]
    ip = ctx.rng.choice(free)
    base = ctx.rec.rec["assets"].get(t.asset_id) or {}
    host = base.get("hostname", t.hostname).rstrip("0123456789") + str(ctx.rng.randint(90, 99))
    fid = ctx.next_id()
    rec_at = ctx.reality.calendar_start - timedelta(days=ctx.rng.randint(400, 900))
    ctx.rec.insert(
        "assets",
        aid,
        {
            **copy.deepcopy(base),
            "asset_id": aid,
            "hostname": host,
            "ip_addresses": [ip],
            "service_ids": [],
            "wazuh_agent_name": None,
            "recorded_at": rec_at,
            "last_reviewed_at": rec_at,
        },
        fid,
    )
    bc = copy.deepcopy(ctx.rec.rec["business_context"].get(t.asset_id) or {})
    bc.update(entity_ref=aid, recorded_at=rec_at, valid_from=rec_at)
    ctx.rec.insert("business_context", aid, bc, fid)
    ctx.add(
        FlawEntry(
            fid,
            "asset.ghost",
            "L3",
            "DC2",
            f"assets:{aid}",
            [RECORD],
            ctx.reality.calendar_start,
            ["no agent check-in", "no network flows from the recorded IP"],
            "low",
            "confirm decommissioning and remove the record",
        )
    )
    return True


def _flaw_criticality(ctx: _Ctx, gross: bool) -> bool:
    levels = ctx.style.crit_levels()
    cands = []
    for aid, r in ctx.reality.assets.items():
        ref = f"business_context:{aid}"
        if ref in ctx.used or aid not in ctx.rec.rec["business_context"]:
            continue
        rank = levels.index(ctx.rec.rec["business_context"][aid]["criticality"])
        if gross and r.criticality >= 4 and r.data_class in ("regulated", "confidential") and rank > 0:
            cands.append(aid)
        if not gross and r.criticality >= 3 and rank >= 2:
            cands.append(aid)
    if not cands:
        return False
    aid = ctx.rng.choice(sorted(cands))
    rank = levels.index(ctx.rec.rec["business_context"][aid]["criticality"])
    new = levels[0] if gross else levels[rank - 2]
    fid = ctx.next_id()
    ctx.rec.set("business_context", aid, "criticality", new, fid)
    if gross:
        ctx.add(
            FlawEntry(
                fid,
                "asset.criticality_gross",
                "L1",
                "DC1",
                f"business_context:{aid}",
                ["criticality"],
                ctx.reality.calendar_start,
                ["data classification on the same record", "dependencies"],
                "high",
                "raise criticality to match data and dependencies",
            )
        )
    else:
        ctx.add(
            FlawEntry(
                fid,
                "asset.criticality_understated",
                "L2",
                "DC2",
                f"business_context:{aid}",
                ["criticality"],
                ctx.reality.calendar_start,
                ["alert volume on the asset", "service dependencies in topology"],
                "high",
                "re-assess criticality",
            )
        )
    return True


def _paper_evident(ctx: _Ctx, cid: str) -> bool:
    c = ctx.reality.controls[cid]
    gaps = [a for a, s in c.per_asset.items() if s != "implemented"]
    monitored = {a.asset_id for a in ctx.spec.assets if a.monitored}
    return c.test in {"mfa_privileged", "mfa_users", "segmentation"} or any(a in monitored for a in gaps)


def _flaw_paper_control(ctx: _Ctx, want: str | None = None) -> bool:
    techn = {"weakness", "mfa_privileged", "mfa_users", "monitored", "tls", "segmentation"}
    cands = [
        cid
        for cid, c in ctx.reality.controls.items()
        if c.test in techn
        and c.state != "implemented"
        and f"controls:{cid}" not in ctx.used
        and ctx.rec.rec["controls"][cid]["implementation_state"] != "implemented"
        and (want is None or (_paper_evident(ctx, cid) == (want == "DC2")))
    ]
    if not cands:
        return False
    cid = ctx.rng.choice(sorted(cands))
    evident = _paper_evident(ctx, cid)
    fid = ctx.next_id()
    ctx.rec.set("controls", cid, "implementation_state", "implemented", fid)
    ctx.rec.set("controls", cid, "exception_id", None, fid)
    ctx.add(
        FlawEntry(
            fid,
            "control.paper",
            "L4",
            "DC2" if evident else "DC4",
            f"controls:{cid}",
            ["implementation_state"],
            ctx.reality.calendar_start,
            ["SCA results", "authentication logs", "network flows"] if evident else [],
            "high",
            "re-assess the control, record the real state and open remediation",
        )
    )
    return True


def _flaw_understated_control(ctx: _Ctx) -> bool:
    cands = [
        cid
        for cid, c in ctx.reality.controls.items()
        if c.test in {"weakness", "monitored", "tls"}
        and c.state == "implemented"
        and f"controls:{cid}" not in ctx.used
        and ctx.rec.rec["controls"][cid]["implementation_state"] == "implemented"
    ]
    if not cands:
        return False
    cid = ctx.rng.choice(sorted(cands))
    fid = ctx.next_id()
    ctx.rec.set("controls", cid, "implementation_state", "missing", fid)
    ctx.add(
        FlawEntry(
            fid,
            "control.understated",
            "L2",
            "DC2",
            f"controls:{cid}",
            ["implementation_state"],
            ctx.reality.calendar_start,
            ["SCA results"],
            "low",
            "update the register to implemented after verification",
        )
    )
    return True


def _flaw_missing_risk(ctx: _Ctx) -> bool:
    weak = {w.asset_id for w in ctx.spec.weaknesses if w.attackable}
    cands = [
        rid
        for rid, r in ctx.reality.risks.items()
        if set(r.entity_refs) & weak and f"risks:{rid}" not in ctx.used and rid in ctx.rec.rec["risks"]
    ]
    if not cands:
        return False
    rid = ctx.rng.choice(sorted(cands))
    fid = ctx.next_id()
    ctx.rec.delete("risks", rid, fid)
    ctx.add(
        FlawEntry(
            fid,
            "risk.missing",
            "L2",
            "DC2",
            f"risks:{rid}",
            [RECORD],
            ctx.reality.calendar_start,
            ["scanner findings", "SCA failures on the assets"],
            "high",
            "register the risk for the exposed assets",
        )
    )
    return True


def _flaw_stale_risk(ctx: _Ctx) -> bool:
    levels = ctx.style.risk_levels()
    cands = [
        rid
        for rid in sorted(ctx.rec.rec["risks"])
        if f"risks:{rid}" not in ctx.used and levels.index(ctx.rec.rec["risks"][rid]["residual_risk"]) >= 2
    ]
    if not cands:
        return False
    rid = ctx.rng.choice(cands)
    r = ctx.rec.rec["risks"][rid]
    new = levels[max(0, levels.index(r["residual_risk"]) - 2)]
    old_review = ctx.reality.calendar_start - timedelta(days=CADENCE_DAYS[ctx.style.cadence] * 3)
    fid = ctx.next_id()
    for fld, val in (
        ("residual_risk", new),
        ("risk_level", new),
        ("last_reviewed_at", old_review),
        ("next_review_due", old_review + timedelta(days=CADENCE_DAYS[ctx.style.cadence])),
    ):
        ctx.rec.set("risks", rid, fld, val, fid)
    ctx.add(
        FlawEntry(
            fid,
            "risk.stale",
            "L4",
            "DC3",
            f"risks:{rid}",
            ["residual_risk", "risk_level", "last_reviewed_at", "next_review_due"],
            ctx.reality.calendar_start,
            ["review dates vs cadence", "overdue next_review_due"],
            "medium",
            "re-assess the risk; review is overdue",
        )
    )
    return True


def _flaw_expired_exception(ctx: _Ctx) -> bool:
    start = ctx.reality.calendar_start
    cands = [
        e
        for e in ctx.reality.exceptions.values()
        if e.valid_until < start
        and ctx.reality.controls[e.control_id].state != "implemented"
        and f"controls:{e.control_id}" not in ctx.used
    ]
    if not cands:
        return False
    e = ctx.rng.choice(sorted(cands, key=lambda x: x.exception_id))
    fid = ctx.next_id()
    ctx.rec.set("controls", e.control_id, "implementation_state", "exception", fid)
    ctx.rec.set("controls", e.control_id, "exception_id", e.exception_id, fid)
    ctx.add(
        FlawEntry(
            fid,
            "exception.expired_in_use",
            "L4",
            "DC3",
            f"controls:{e.control_id}",
            ["implementation_state", "exception_id"],
            start,
            [f"exception {e.exception_id} valid_until"],
            "high",
            "stop relying on the expired exception: remediate or renew it formally",
        )
    )
    return True


def _flaw_orphan_owner(ctx: _Ctx) -> bool:
    cands = [rid for rid in sorted(ctx.rec.rec["risks"]) if f"risks:{rid}" not in ctx.used]
    if not cands:
        return False
    rid = ctx.rng.choice(cands)
    known = {i.username for i in ctx.spec.identities}
    for _ in range(20):
        initial = ctx.rng.choice(["j", "m", "a", "s", "r"])
        ghost = f"{initial}.{ctx.rng.choice(['doe', 'roe', 'grant', 'hale', 'moss'])}"
        if ghost not in known:
            break
    else:
        return False
    fid = ctx.next_id()
    ctx.rec.set("risks", rid, "owner", ghost, fid)
    ctx.add(
        FlawEntry(
            fid,
            "risk.orphan_owner",
            "L2",
            "DC1",
            f"risks:{rid}",
            ["owner"],
            ctx.reality.calendar_start,
            ["identities.json has no such account"],
            "low",
            "assign an existing risk owner",
        )
    )
    return True


def _flaw_not_assessed(ctx: _Ctx) -> bool:
    crit = {a: r.criticality for a, r in ctx.reality.assets.items()}
    cands = [
        cid
        for cid, c in ctx.reality.controls.items()
        if c.state != "implemented"
        and any(crit[a] >= 4 for a in c.per_asset)
        and f"controls:{cid}" not in ctx.used
        and ctx.rec.rec["controls"][cid]["implementation_state"] in ("partial", "missing")
    ]
    if not cands:
        return False
    cid = ctx.rng.choice(sorted(cands))
    stale = ctx.reality.calendar_start - timedelta(days=CADENCE_DAYS[ctx.style.cadence] * 4)
    fid = ctx.next_id()
    ctx.rec.set("controls", cid, "implementation_state", "not_assessed", fid)
    ctx.rec.set("controls", cid, "last_assessed_at", stale, fid)
    ctx.add(
        FlawEntry(
            fid,
            "control.not_assessed_long",
            "L4",
            "DC3",
            f"controls:{cid}",
            ["implementation_state", "last_assessed_at"],
            ctx.reality.calendar_start,
            ["last_assessed_at far beyond the review cadence on critical assets"],
            "medium",
            "assess the control on the critical assets",
        )
    )
    return True


def _flaw_process_misattributed(ctx: _Ctx) -> bool:
    services = list(ctx.spec.organization.business_services)
    cands = [
        aid
        for aid in sorted(ctx.rec.rec["business_context"])
        if f"business_context:{aid}" not in ctx.used
        and ctx.rec.rec["business_context"][aid]["business_process"] in services
        and aid in ctx.reality.assets  # never on a record another flaw invented (ghost assets)
    ]
    if not cands or len(services) < 2:
        return False
    aid = ctx.rng.choice(cands)
    current = ctx.rec.rec["business_context"][aid]["business_process"]
    fid = ctx.next_id()
    ctx.rec.set(
        "business_context",
        aid,
        "business_process",
        ctx.rng.choice([s for s in services if s != current]),
        fid,
    )
    ctx.add(
        FlawEntry(
            fid,
            "asset.process_misattributed",
            "L2",
            "DC4",
            f"business_context:{aid}",
            ["business_process"],
            ctx.reality.calendar_start,
            [],
            "low",
            "no visible evidence: a confident claim here is unsupported",
        )
    )
    return True


#: Flaws are drawn by detectability class first (fairness targets, INPUT Part 2 A7.4).
DC_WEIGHTS = {"DC1": 0.30, "DC2": 0.40, "DC3": 0.20, "DC4": 0.10}
FLAW_MODULES: dict[str, list[Callable[[_Ctx], bool]]] = {
    "DC1": [lambda c: _flaw_criticality(c, gross=True), _flaw_orphan_owner],
    "DC2": [
        lambda c: _flaw_criticality(c, gross=False),
        _flaw_understated_control,
        _flaw_missing_risk,
        _flaw_shadow_asset,
        _flaw_ghost_asset,
        lambda c: _flaw_paper_control(c, want="DC2"),
    ],
    "DC3": [_flaw_stale_risk, _flaw_expired_exception, _flaw_not_assessed],
    "DC4": [_flaw_process_misattributed, lambda c: _flaw_paper_control(c, want="DC4")],
}


def _inject_flaws(ctx: _Ctx, maturity: str) -> None:
    p_clean, (lo, hi), cap = FLAW_BUDGET[maturity]
    rng = ctx.rng
    target = 0 if rng.random() < p_clean else min(cap, rng.randint(lo, hi))
    attempts = 0
    classes = sorted(DC_WEIGHTS)
    while len(ctx.ledger) < target and attempts < target * 6:
        attempts += 1
        dc = rng.choices(classes, weights=[DC_WEIGHTS[x] for x in classes], k=1)[0]
        modules = list(FLAW_MODULES[dc])
        rng.shuffle(modules)
        for module in modules:
            if module(ctx):
                break


# ---------------------------------------------------------------- audit


@dataclass
class AuditResult:
    ok: bool
    differences: int
    noise_changes: int
    flaw_changes: int
    unexplained: list[str]
    phantom: list[str]
    out_of_bounds: list[str]
    flaws_without_change: list[str]
    changes_without_flaw: list[str]


def _diff(faithful: dict[str, Any], final: dict[str, Any]) -> set[tuple[str, str, str]]:
    out: set[tuple[str, str, str]] = set()
    for coll in COLLECTIONS:
        a, b = faithful[coll], final[coll]
        for key in set(a) | set(b):
            if key not in a or key not in b:
                out.add((coll, key, RECORD))
                continue
            for fld in set(a[key]) | set(b[key]):
                if a[key].get(fld) != b[key].get(fld):
                    out.add((coll, key, fld))
    return out


def diff_audit(
    faithful: dict[str, Any],
    final: dict[str, Any],
    log: list[Mutation],
    ledger: list[FlawEntry],
    style: GrcStyle,
) -> AuditResult:
    diffs = _diff(faithful, final)
    last: dict[tuple[str, str, str], Mutation] = {}
    for m in log:
        last[(m.collection, m.key, m.field)] = m
    deleted = {(m.collection, m.key) for m in log if m.field == RECORD and m.new is None}
    logged = {p for p in last if p[2] == RECORD or (p[0], p[1]) not in deleted}
    unexplained = sorted(":".join(p) for p in diffs - logged)
    phantom = sorted(":".join(p) for p in logged - diffs)
    oob = sorted(
        f"{m.collection}:{m.key}:{m.field}"
        for p, m in last.items()
        if m.cause.startswith("noise:") and p in diffs and not _noise_in_bounds(m, style)
    )
    flaw_ids = {f.flaw_id for f in ledger}
    causes = {m.cause for m in log}
    no_change = sorted(fid for fid in flaw_ids if fid not in causes)
    no_flaw = sorted({m.cause for m in log if not m.cause.startswith("noise:") and m.cause not in flaw_ids})
    return AuditResult(
        ok=not (unexplained or phantom or oob or no_change or no_flaw),
        differences=len(diffs),
        noise_changes=sum(1 for m in last.values() if m.cause.startswith("noise:")),
        flaw_changes=sum(1 for m in last.values() if not m.cause.startswith("noise:")),
        unexplained=unexplained,
        phantom=phantom,
        out_of_bounds=oob,
        flaws_without_change=no_change,
        changes_without_flaw=no_flaw,
    )


# ---------------------------------------------------------------- bundle


@dataclass
class GrcBundle:
    reality: GrcReality
    style: GrcStyle
    assets: list[Asset]
    business_context: list[BusinessContext]
    controls: list[Control]
    control_mappings: list[ControlMapping]
    risks: list[Risk]
    exceptions: list[PolicyException]
    scale_definition: ScaleDefinition
    ledger: list[FlawEntry]
    mutations: list[Mutation]
    audit: AuditResult

    def visible(self) -> dict[str, Any]:
        """The organisation's recorded GRC, as contract-valid JSON (visible plane)."""
        return {
            "enterprise/assets.json": [m.model_dump(mode="json") for m in self.assets],
            "grc/business_context.json": [m.model_dump(mode="json") for m in self.business_context],
            "grc/controls.json": [m.model_dump(mode="json") for m in self.controls],
            "grc/control_mappings.json": [m.model_dump(mode="json") for m in self.control_mappings],
            "grc/risk_register.json": [m.model_dump(mode="json") for m in self.risks],
            "grc/policy_exceptions.json": [m.model_dump(mode="json") for m in self.exceptions],
            "grc/scale_definition.json": self.scale_definition.model_dump(mode="json"),
        }

    def hidden(self) -> dict[str, Any]:
        return {
            "truth/grc_reality.json": self.reality.to_dict(),
            "truth/grc_style.json": asdict(self.style),
            "truth/grc_flaw_ledger.jsonl": [asdict(f) for f in self.ledger],
            "truth/grc_noise_log.jsonl": [asdict(m) for m in self.mutations if m.cause.startswith("noise:")],
            "truth/grc_diff_audit.json": asdict(self.audit),
        }


def build_grc(spec: ScenarioSpec, seeds: SeedSet | None = None) -> GrcBundle:
    seeds = seeds or SeedSet.from_dict(spec.seeds.model_dump())
    maturity = spec.organization.maturity.value
    reality = build_reality(spec, seeds)
    style = GrcStyle.sample(seeds.stream("grc", "style"))
    faithful = _faithful(spec, reality, style, seeds.stream("grc", "record_dates"))
    rec = Recorder(copy.deepcopy(faithful))
    _apply_noise(rec, style, maturity, seeds.stream("grc", "noise"))
    ctx = _Ctx(spec, reality, style, rec, seeds.stream("grc", "flaws"))
    _inject_flaws(ctx, maturity)
    audit = diff_audit(faithful, rec.rec, rec.log, ctx.ledger, style)

    cat = load_control_catalog()
    final = rec.rec
    mappings = [
        ControlMapping(
            control_id=cid,
            mappings=[
                FrameworkRef(framework=fw, ref=ref, provenance="ours")
                for fw, refs in sorted(cat["controls"][cid]["refs"].items())
                for ref in refs
            ],
            mapping_version=MAPPING_VERSION,
        )
        for cid in sorted(final["controls"])
    ]
    return GrcBundle(
        reality=reality,
        style=style,
        assets=[Asset(**v) for _, v in sorted(final["assets"].items())],
        business_context=[BusinessContext(**v) for _, v in sorted(final["business_context"].items())],
        controls=[Control(**v) for _, v in sorted(final["controls"].items())],
        control_mappings=mappings,
        risks=[Risk(**v) for _, v in sorted(final["risks"].items())],
        exceptions=[PolicyException(**v) for _, v in sorted(final["exceptions"].items())],
        scale_definition=style.scale_definition(),
        ledger=ctx.ledger,
        mutations=rec.log,
        audit=audit,
    )
