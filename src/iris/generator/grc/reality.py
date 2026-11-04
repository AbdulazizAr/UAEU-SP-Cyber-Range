"""GRC reality: what is actually true, computed from the spec (hidden plane).

Formulas are fixed and versioned (``GRC_FORMULA_VERSION``). Inputs are only spec facts
and enterprise-level sub-seeds (org, identity), so changing seed_grc never changes reality.
"""

from __future__ import annotations

import random
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, time, timedelta
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from iris.contracts.common import AssetRole
from iris.contracts.spec import AssetSpec, ScenarioSpec
from iris.core.seeds import SeedSet
from iris.settings import repo_root

GRC_FORMULA_VERSION = "grc-0.1.0"
STATE_SCORE = {"implemented": 1.0, "partial": 0.5, "missing": 0.0}
CRIT_WEIGHT = {1: 1.0, 2: 1.5, 3: 2.0, 4: 3.0, 5: 4.0}
DATA_ROLES = {AssetRole.DATABASE, AssetRole.FILE_SERVER, AssetRole.BACKUP_SERVER}
NON_MONITORABLE = {AssetRole.ROUTER_FIREWALL, AssetRole.IDS_SENSOR, AssetRole.SIEM}
TLS_RECIPES = {"nginx", "openldap"}


@lru_cache(maxsize=2)
def load_control_catalog(path: Path | None = None) -> dict[str, Any]:
    p = path or repo_root() / "configs" / "catalog" / "controls.yaml"
    data: dict[str, Any] = yaml.safe_load(p.read_text(encoding="utf-8"))
    return data


@dataclass
class ControlReality:
    control_id: str
    name: str
    function: str
    test: str
    per_asset: dict[str, str]  # asset_id -> implemented|partial|missing ({} for org-scope controls)
    org_state: str | None = None  # for org-scope controls

    @property
    def state(self) -> str:
        """Aggregate state: what an honest register would record."""
        if self.org_state is not None:
            return self.org_state
        states = set(self.per_asset.values())
        if not states:
            return "implemented"
        if states == {"implemented"}:
            return "implemented"
        if states == {"missing"}:
            return "missing"
        return "partial"

    def effectiveness(self, crit: dict[str, int]) -> float:
        """Criticality-weighted share of effective coverage (INPUT Part 7, 2.3)."""
        if self.org_state is not None:
            return STATE_SCORE[self.org_state]
        if not self.per_asset:
            return 1.0
        num = sum(CRIT_WEIGHT[crit[a]] * STATE_SCORE[s] for a, s in self.per_asset.items())
        den = sum(CRIT_WEIGHT[crit[a]] for a in self.per_asset)
        return round(num / den, 4)


@dataclass
class AssetReality:
    asset_id: str
    criticality: int
    data_class: str
    business_unit: str
    business_process: str
    business_owner: str | None
    technical_owner: str | None
    internet_exposed: bool
    monitored: bool


@dataclass
class RiskReality:
    risk_id: str
    template: str
    scenario: str
    entity_refs: list[str]
    linked_controls: list[str]
    likelihood: int
    impact: int
    inherent: int
    control_factor: float
    residual: float
    owner: str | None


@dataclass
class ExceptionReality:
    exception_id: str
    control_id: str
    asset_ids: list[str]
    reason: str
    approver: str | None
    valid_from: datetime
    valid_until: datetime
    compensating: list[str]


@dataclass
class GrcReality:
    formula_version: str
    assets: dict[str, AssetReality]
    controls: dict[str, ControlReality]
    risks: dict[str, RiskReality]
    exceptions: dict[str, ExceptionReality]
    calendar_start: datetime
    calendar_end: datetime
    extras: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        crit = {a: r.criticality for a, r in self.assets.items()}
        d = asdict(self)
        for cid, c in self.controls.items():
            d["controls"][cid]["aggregate_state"] = c.state
            d["controls"][cid]["effectiveness"] = c.effectiveness(crit)
        return d

    def active_exception_for(self, control_id: str, at: datetime) -> ExceptionReality | None:
        for exc in self.exceptions.values():
            if exc.control_id == control_id and exc.valid_from <= at <= exc.valid_until:
                return exc
        return None


def level_of(score: float) -> int:
    """Residual/inherent score (1-25) -> 1 Low, 2 Medium, 3 High, 4 Critical."""
    if score < 5:
        return 1
    if score < 10:
        return 2
    if score < 16:
        return 3
    return 4


# ---------------------------------------------------------------- scope helpers


def _applicable(scope: str, spec: ScenarioSpec) -> list[str] | None:
    """Asset IDs a control applies to; None = organisation-level control."""
    assets = spec.assets
    svc_by_asset: dict[str, set[str]] = {}
    for s in spec.services:
        svc_by_asset.setdefault(s.asset_id, set()).add(s.recipe)
    if scope == "org":
        return None
    if scope == "all":
        return [a.asset_id for a in assets if a.role is not AssetRole.IDS_SENSOR]
    if scope == "servers":
        return [a.asset_id for a in assets if a.asset_id in svc_by_asset and a.role is not AssetRole.SIEM]
    if scope == "data":
        return [a.asset_id for a in assets if a.role in DATA_ROLES]
    if scope == "identity":
        return [a.asset_id for a in assets if a.role in {AssetRole.DIRECTORY, AssetRole.ADMIN_WORKSTATION}]
    if scope == "ssh":
        return [a for a, recipes in svc_by_asset.items() if "openssh" in recipes]
    if scope == "tls_services":
        return [a for a, recipes in svc_by_asset.items() if recipes & TLS_RECIPES]
    if scope == "monitorable":
        return [a.asset_id for a in assets if a.role not in NON_MONITORABLE]
    if scope == "critical":
        return [a.asset_id for a in assets if a.true_criticality >= 4 and a.role is not AssetRole.IDS_SENSOR]
    return [a.asset_id for a in assets if a.role.value == scope]


def _process_state(rng: random.Random, probs: list[float]) -> str:
    x = rng.random()
    if x < probs[0]:
        return "implemented"
    if x < probs[0] + probs[1]:
        return "partial"
    return "missing"


# ---------------------------------------------------------------- the builder


def build_reality(spec: ScenarioSpec, seeds: SeedSet | None = None) -> GrcReality:
    seeds = seeds or SeedSet.from_dict(spec.seeds.model_dump())
    cat = load_control_catalog()
    maturity = spec.organization.maturity.value
    probs = cat["process_probabilities"][maturity]
    assets = {a.asset_id: a for a in spec.assets}
    crit = {a.asset_id: a.true_criticality for a in spec.assets}
    humans = [i for i in spec.identities if i.kind == "human"]
    admins = [i for i in humans if i.privilege == "admin"]
    standard = [i for i in humans if i.privilege != "admin"]
    weak_by_control: dict[str, set[str]] = {}
    for w in spec.weaknesses:
        weak_by_control.setdefault(w.enabling_control, set()).add(w.asset_id)
    has_backup = any(a.role is AssetRole.BACKUP_SERVER for a in spec.assets)
    tls_ok: dict[str, bool] = {}
    for s in spec.services:
        if s.recipe in TLS_RECIPES:
            tls_ok[s.asset_id] = tls_ok.get(s.asset_id, True) and s.tls

    def share_state(people: list[Any]) -> str:
        if not people:
            return "implemented"
        n = sum(1 for p in people if p.mfa_enforced)
        return "implemented" if n == len(people) else ("missing" if n == 0 else "partial")

    zones = {z.name: z for z in spec.zones}
    exceptions_internal = [r for r in spec.policy if r.is_exception and r.action == "allow"]
    if any(r.protocol == "any" for r in exceptions_internal):
        seg = "missing"
    elif exceptions_internal:
        seg = "partial"
    else:
        seg = "implemented"
    exposure_ok = all(
        zones[r.dst_zone].kind.value == "dmz"
        for r in spec.policy
        if r.src_zone == "internet" and r.action == "allow"
    )

    prng = seeds.stream("org", "process_controls")
    controls: dict[str, ControlReality] = {}
    for cid in sorted(cat["controls"]):
        c = cat["controls"][cid]
        scope = _applicable(c["roles"], spec)
        if scope is not None and not scope:
            continue  # not applicable to this enterprise (e.g. no file server)
        test = c["test"]
        per_asset: dict[str, str] = {}
        org_state: str | None = None
        if scope is None:
            org_state = _process_state(prng, probs)
        elif test == "weakness":
            per_asset = {
                a: ("missing" if a in weak_by_control.get(cid, set()) else "implemented") for a in scope
            }
        elif test == "mfa_privileged":
            per_asset = {a: share_state(admins) for a in scope}
        elif test == "mfa_users":
            per_asset = {a: share_state(standard) for a in scope}
        elif test == "segmentation":
            per_asset = {a: seg for a in scope}
        elif test == "exposure":
            per_asset = {a: "implemented" if exposure_ok else "missing" for a in scope}
        elif test == "monitored":
            per_asset = {a: "implemented" if assets[a].monitored else "missing" for a in scope}
        elif test == "tls":
            per_asset = {a: "implemented" if tls_ok.get(a, True) else "missing" for a in scope}
        elif test == "sensor":
            per_asset = {a: "implemented" for a in scope}
        elif test == "backup":
            state = _process_state(prng, probs) if has_backup else "missing"
            per_asset = {a: state for a in scope}
        else:  # process control with an asset scope: one organisational state applied to all
            state = _process_state(prng, probs)
            per_asset = {a: state for a in scope}
        controls[cid] = ControlReality(cid, c["name"], c["function"], test, per_asset, org_state)

    start = datetime.combine(spec.calendar.start, time(0), tzinfo=UTC)
    end = datetime.combine(spec.calendar.end, time(0), tzinfo=UTC)

    asset_real = _business_context(spec, seeds, crit)
    risks = _risks(spec, cat, controls, asset_real)
    exceptions = _exceptions(spec, seeds, controls, admins, start, maturity)
    return GrcReality(GRC_FORMULA_VERSION, asset_real, controls, risks, exceptions, start, end)


def _business_context(spec: ScenarioSpec, seeds: SeedSet, crit: dict[str, int]) -> dict[str, AssetReality]:
    rng = seeds.stream("identity", "owners")
    org = spec.organization
    humans = [i for i in spec.identities if i.kind == "human"]
    it = ([i.username for i in humans if i.department == "IT"] or [humans[0].username]) if humans else []
    by_dept: dict[str, list[str]] = {}
    for i in humans:
        by_dept.setdefault(i.department, []).append(i.username)
    units = [u for u in org.business_units if u != "IT"] or org.business_units
    main_unit = units[0]
    main_service = org.business_services[0]
    infra_roles = {
        AssetRole.ROUTER_FIREWALL: "Core infrastructure",
        AssetRole.IDS_SENSOR: "Security monitoring",
        AssetRole.SIEM: "Security monitoring",
        AssetRole.DNS_SERVER: "Core infrastructure",
        AssetRole.DIRECTORY: "Identity",
        AssetRole.MAIL_SERVER: "Email",
        AssetRole.BACKUP_SERVER: "Backup and recovery",
        AssetRole.FILE_SERVER: "File sharing",
        AssetRole.BASTION: "Administration",
        AssetRole.ADMIN_WORKSTATION: "Administration",
    }
    out: dict[str, AssetReality] = {}
    for a in spec.assets:
        if a.role in infra_roles:
            unit, process = "IT", infra_roles[a.role]
        elif a.role is AssetRole.WORKSTATION:
            unit = rng.choice(units)
            process = "End-user computing"
        else:
            unit, process = main_unit, main_service
        pool = by_dept.get(unit) if unit != "IT" else it
        business_owner = rng.choice(pool) if pool else None
        technical_owner = rng.choice(it) if it else None
        out[a.asset_id] = AssetReality(
            asset_id=a.asset_id,
            criticality=crit[a.asset_id],
            data_class=a.data_class.value,
            business_unit=unit,
            business_process=process,
            business_owner=business_owner,
            technical_owner=technical_owner,
            internet_exposed=a.internet_exposed,
            monitored=a.monitored,
        )
    return out


def _risks(
    spec: ScenarioSpec,
    cat: dict[str, Any],
    controls: dict[str, ControlReality],
    assets: dict[str, AssetReality],
) -> dict[str, RiskReality]:
    attackable: dict[str, int] = {}
    for w in spec.weaknesses:
        if w.attackable:
            attackable[w.asset_id] = attackable.get(w.asset_id, 0) + 1
    by_role: dict[str, list[AssetSpec]] = {}
    for a in spec.assets:
        by_role.setdefault(a.role.value, []).append(a)
    out: dict[str, RiskReality] = {}
    for key in sorted(cat["risk_templates"]):
        t = cat["risk_templates"][key]
        members = [a for role in t["roles"] for a in by_role.get(role, [])]
        if not members:
            continue
        ids = [a.asset_id for a in members]
        linked = [c for c in t["controls"] if c in controls]
        states = [controls[c].state for c in linked]
        n_weak = min(2, sum(attackable.get(a, 0) for a in ids))
        likelihood = 1 + n_weak + (1 if any(a.internet_exposed for a in members) else 0)
        likelihood += 1 if "missing" in states else 0
        likelihood -= 1 if states and all(s == "implemented" for s in states) else 0
        likelihood = max(1, min(5, likelihood))
        impact = max(1, min(5, max(a.true_criticality for a in members)))
        inherent = likelihood * impact
        cf = max(0.4, 1 - 0.08 * states.count("implemented") - 0.04 * states.count("partial"))
        top = max(members, key=lambda a: (a.true_criticality, a.asset_id))
        rid = f"RSK-{key.split('-')[1]}-001"
        if rid in out:  # two templates sharing a code would silently overwrite a risk
            raise ValueError(f"risk template {key} collides with {out[rid].template} on {rid}")
        out[rid] = RiskReality(
            risk_id=rid,
            template=key,
            scenario=t["scenario"],
            entity_refs=ids,
            linked_controls=linked,
            likelihood=likelihood,
            impact=impact,
            inherent=inherent,
            control_factor=round(cf, 2),
            residual=round(inherent * cf, 1),
            owner=assets[top.asset_id].business_owner,
        )
    return out


def _exceptions(
    spec: ScenarioSpec,
    seeds: SeedSet,
    controls: dict[str, ControlReality],
    admins: list[Any],
    start: datetime,
    maturity: str,
) -> dict[str, ExceptionReality]:
    rng = seeds.stream("org", "exceptions")
    p_doc = {"low": 0.2, "medium": 0.35, "high": 0.5}[maturity]
    out: dict[str, ExceptionReality] = {}
    n = 0
    for cid in sorted(controls):
        c = controls[cid]
        if c.test != "weakness":
            continue
        gaps = sorted(a for a, s in c.per_asset.items() if s != "implemented")
        if not gaps or rng.random() >= p_doc:
            continue
        n += 1
        valid_from = start - timedelta(days=rng.randint(30, 300))
        valid_until = valid_from + timedelta(days=rng.randint(60, 365))
        compensating = sorted(
            rng.sample(
                [k for k, v in controls.items() if v.state == "implemented" and k != cid], k=rng.randint(0, 2)
            )
        )
        out[f"EXC-{n:04d}"] = ExceptionReality(
            exception_id=f"EXC-{n:04d}",
            control_id=cid,
            asset_ids=gaps,
            reason=rng.choice(
                [
                    "legacy application dependency",
                    "vendor support constraint",
                    "migration in progress",
                    "business deadline",
                ]
            ),
            approver=rng.choice(admins).username if admins else None,
            valid_from=valid_from,
            valid_until=valid_until,
            compensating=compensating,
        )
    return out
