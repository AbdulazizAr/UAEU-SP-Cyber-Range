"""Episode planner: place benign baseline, hard negatives and malicious activities
(builder brief file 05 §5).

Constraints honoured: identities/services must exist; a malicious template runs only when its
precondition holds in the world (the enabling weakness is present) unless it is a failing-by-
design attempt; ~20% of scenarios are clean; the hard-negative ratio is sampled per scenario
from a wide range (never fixed); >=25% of attack scenarios carry a multi-stage campaign. IDs are
opaque hashes so malicious and benign activities are not distinguishable by id ordering
(brief file 08 §3, no label-correlated ordering).
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import datetime

from iris.contracts.spec import ScenarioSpec
from iris.core.hashing import episode_id, scenario_id, sha256_hex
from iris.synth.activity import personas
from iris.synth.activity.attacks import EXECUTORS, AttackContext, AttackTemplate, load_templates
from iris.synth.activity.model import Activity, Footprint
from iris.synth.seeds import SynthSeeds
from iris.synth.world import World, internet_zone

PLANNER_VERSION = "synth-planner-0.1.0"
CLEAN_SCENARIO_RATE = 0.20
CAMPAIGN_RATE = 0.30  # share of attack scenarios with a multi-stage campaign (brief >= 25%)
# several multi-stage chains so campaigns exercise more than one family mix (one chosen per
# campaign). Stages whose precondition is absent in a given world are skipped (a detection gap).
CAMPAIGN_CHAINS = (
    ("F4_portscan", "F1_ssh_bruteforce", "F5_ssh_pivot", "F7_authorized_keys", "F6_exfil_transfer"),
    ("F4_host_discovery", "F2_web_sqli", "F3_idor", "F7_cron_persistence", "F6_archive_stage"),
    ("F1_ssh_spray", "F3_sudo_abuse", "F7_agent_disable", "F9_c2_beacon"),
    ("F4_portscan", "F2_web_traversal", "F5_ssh_pivot", "F9_c2_beacon", "F6_exfil_transfer"),
)


@dataclass
class EpisodePlan:
    episode_id: str
    index: int
    start: datetime
    end: datetime
    activities: list[Activity] = field(default_factory=list)

    @property
    def footprints(self) -> list[Footprint]:
        return [fp for a in self.activities for fp in a.footprints]


@dataclass
class ScenarioPlan:
    scenario_id: str
    episodes: list[EpisodePlan]
    clean: bool
    hard_negative_ratio: float
    campaign_id: str | None = None

    @property
    def activities(self) -> list[Activity]:
        return [a for ep in self.episodes for a in ep.activities]


def _aid(scn: str, salt: str) -> str:
    return "ACT-" + sha256_hex(f"{scn}|activity|{salt}")[:12]


def _assets_by_role(world: World, role: str) -> list[str]:
    return sorted(a.asset_id for a in world.spec.assets if a.role.value == role)


def _attacker_ip(world: World, rng: random.Random) -> str:
    atk = [e for e in world.externals if e.kind == "attacker"]
    if atk:
        return atk[0].ip
    return f"198.18.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def _pick_target(world: World, template: AttackTemplate, rng: random.Random) -> tuple[str, str | None]:
    """Return (target_asset, weakness_module) or ('', None) if no coherent target exists."""
    if template.weakness is not None:
        wk = next((w for w in world.spec.weaknesses if w.module == template.weakness), None)
        if wk is not None and world.assets[wk.asset_id].role.value in template.target_roles:
            return wk.asset_id, wk.module
        return "", None  # precondition absent -> skip (not a failing-by-design template here)
    candidates = [a for r in template.target_roles for a in _assets_by_role(world, r)]
    return (rng.choice(candidates), None) if candidates else ("", None)


def _has_target(world: World, template: AttackTemplate) -> bool:
    """Whether this template can be placed in this world (its precondition is satisfiable)."""
    if template.weakness is not None:
        wk = next((w for w in world.spec.weaknesses if w.module == template.weakness), None)
        return wk is not None and world.assets[wk.asset_id].role.value in template.target_roles
    return any(_assets_by_role(world, r) for r in template.target_roles)


def _placeable_by_family(
    world: World, templates: dict[str, AttackTemplate]
) -> dict[str, list[AttackTemplate]]:
    """Placeable templates grouped by family, so selection can balance across families instead
    of favouring families with more templates or no weakness gate (keeps every family present
    in a batch rather than starving web/privilege/lateral attacks)."""
    out: dict[str, list[AttackTemplate]] = {}
    for t in templates.values():
        if _has_target(world, t):
            out.setdefault(t.family, []).append(t)
    return out


def _build_attack(
    world: World,
    template: AttackTemplate,
    ep: EpisodePlan,
    rng: random.Random,
    scn: str,
    *,
    campaign: str | None = None,
    parent: str | None = None,
    source_ip: str | None = None,
) -> Activity | None:
    target_asset, weakness = _pick_target(world, template, rng)
    if not target_asset:
        return None
    asset = world.assets[target_asset]
    target_ip = asset.attachments[0].ip if asset.attachments else "10.0.0.1"
    services = world.services_by_asset.get(target_asset, [])
    service_id = services[0].service_id if services else None
    port = services[0].port if services else 22
    src_ip = source_ip or _attacker_ip(world, rng)
    identity = next((i for i in world.spec.identities if target_asset in i.assigned_assets), None)
    username = identity.username if identity else rng.choice(["svc-app", "operator"])
    skill = rng.randint(1, 5)
    # exploitation success requires the enabling weakness to really be present (brief T-A2).
    # families that exploit no planted weakness (recon/exfil/C2/insider/persistence) may still
    # complete from an assumed foothold; they never claim to have exploited a weakness.
    if template.weakness is not None:
        success = weakness is not None and rng.random() < 0.7
    else:
        success = rng.random() < 0.6
    aid = _aid(scn, f"{template.template_id}|{ep.index}|{rng.random()}")
    ctx = AttackContext(
        activity_id=aid,
        source_ip=src_ip,
        target_asset=target_asset,
        target_host=asset.hostname,
        target_ip=target_ip,
        target_port=port,
        username=username,
        start=ep.start,
        end=ep.end,
        success=success,
        skill=skill,
        world=world,
    )
    footprints = EXECUTORS[template.executor](ctx, rng)
    activity = Activity(
        activity_id=aid,
        kind="malicious",
        template_id=template.template_id,
        family=template.family,
        actor_ref=src_ip,
        actor_profile=rng.choice(["opportunistic", "targeted", "automated"]),
        source_ip=src_ip,
        target_asset=target_asset,
        identity_id=identity.identity_id if identity else None,
        service_id=service_id,
        start=ep.start,
        end=ep.end,
        technique=template.technique,
        tactic=template.tactic,
        outcome="success" if success else rng.choice(["failed", "blocked", "partial"]),
        weakness_module=weakness,
        enabling_control=_control_for(world, weakness),
        expected_rules=list(template.expected_rules),
        campaign_id=campaign,
        parent_activity_id=parent,
        footprints=footprints,
    )
    return activity


def _control_for(world: World, weakness_module: str | None) -> str | None:
    if weakness_module is None:
        return None
    wk = next((w for w in world.spec.weaknesses if w.module == weakness_module), None)
    return wk.enabling_control if wk else None


def _benign_baseline(
    world: World, ep: EpisodePlan, rng: random.Random, hard_neg_ratio: float, scn: str
) -> list[Activity]:
    acts: list[Activity] = []
    clients = [e.ip for e in world.externals if e.kind == "client"]
    web = _assets_by_role(world, "web_server")
    admins = [i for i in world.spec.identities if i.privilege in ("admin", "power")]

    def wrap(
        salt: str,
        fps: list[Footprint],
        *,
        hard_negative: bool = False,
        profile: str = "benign_user",
        family: str = "",
    ) -> Activity:
        aid = _aid(scn, f"{salt}|{ep.index}|{rng.random()}")
        for fp in fps:
            fp.activity_id = aid
        return Activity(
            activity_id=aid,
            kind="benign",
            template_id=f"benign.{salt}",
            family=family,
            actor_ref=profile,
            actor_profile=profile,
            source_ip=(fps[0].data.get("src_ip") or "") if fps else "",
            target_asset=None,
            identity_id=None,
            service_id=None,
            start=ep.start,
            end=ep.end,
            footprints=fps,
            is_hard_negative=hard_negative,
        )

    for web_asset in web:
        for cip in clients:
            acts.append(
                wrap("web_browsing", personas.web_browsing(world, web_asset, cip, ep.start, ep.end, rng))
            )
    for aid_asset in sorted(world.assets):
        if world.is_monitored(aid_asset) and rng.random() < 0.5:
            acts.append(wrap("machine", personas.machine_noise(world, aid_asset, ep.start, ep.end, rng)))
    # routine benign traffic on the SAME record types attacks use (ssh logins, app/db calls,
    # service flows), so a benign episode's surface form (record-length spread, timing) matches
    # an attack episode's and cannot be used to fingerprint attacks (keeps the shortcut test honest).
    servers = [
        a
        for r in ("app_server", "web_server", "database", "bastion", "file_server", "directory")
        for a in _assets_by_role(world, r)
    ]
    office = _office_ip(world, rng)
    for aid_asset in servers:
        if not world.is_monitored(aid_asset):
            continue
        ident = next((i for i in world.spec.identities if aid_asset in i.assigned_assets), None)
        user = ident.username if ident else "svc-app"
        if rng.random() < 0.7:
            acts.append(
                wrap(
                    "routine_ssh", personas.routine_ssh(world, aid_asset, user, office, ep.start, ep.end, rng)
                )
            )
        if rng.random() < 0.7:
            acts.append(
                wrap(
                    "app_traffic",
                    personas.app_traffic(
                        world, aid_asset, user, (clients[0] if clients else office), ep.start, ep.end, rng
                    ),
                )
            )
        if rng.random() < 0.6:
            acts.append(
                wrap("service_flows", personas.service_flows(world, office, aid_asset, ep.start, ep.end, rng))
            )
    # hard negatives (ratio sampled per scenario): authorized scan, nightly backup, admin sudo, typo login
    if admins and rng.random() < hard_neg_ratio:
        target = rng.choice(sorted(world.assets))
        adm = rng.choice(admins)
        acts.append(
            wrap(
                "admin_ssh_typos",
                personas.admin_ssh(
                    world, target, adm.username, _office_ip(world, rng), ep.start, ep.end, rng, typos=True
                ),
                hard_negative=True,
                profile="benign_admin",
                family="F1",
            )
        )
    scanners = [e.ip for e in world.externals if e.kind == "scanner"]
    if scanners and web and rng.random() < hard_neg_ratio:
        acts.append(
            wrap(
                "authorized_scan",
                personas.authorized_scan(world, rng.choice(web), scanners[0], ep.start, ep.end, rng),
                hard_negative=True,
                profile="benign_admin",
                family="F4",
            )
        )
    backups = _assets_by_role(world, "backup_server")
    dbs = _assets_by_role(world, "database")
    if backups and dbs and rng.random() < hard_neg_ratio:
        db_ip = world.assets[dbs[0]].attachments[0].ip if world.assets[dbs[0]].attachments else "10.0.0.7"
        acts.append(
            wrap(
                "nightly_backup",
                personas.nightly_backup(world, backups[0], db_ip, ep.start, ep.end, rng),
                hard_negative=True,
                profile="machine",
                family="F6",
            )
        )
    if admins and rng.random() < hard_neg_ratio:
        target = rng.choice(sorted(world.assets))
        acts.append(
            wrap(
                "admin_sudo",
                personas.admin_sudo(world, target, rng.choice(admins).username, ep.start, ep.end, rng),
                hard_negative=True,
                profile="benign_admin",
                family="F3",
            )
        )
    return acts


def _office_ip(world: World, rng: random.Random) -> str:
    ws = _assets_by_role(world, "admin_workstation") or _assets_by_role(world, "workstation")
    if ws and world.assets[ws[0]].attachments:
        return world.assets[ws[0]].attachments[0].ip
    return f"10.0.0.{rng.randint(10, 200)}"


def plan_scenario(spec: ScenarioSpec, world: World, synth: SynthSeeds) -> ScenarioPlan:
    scn = scenario_id({"seeds": spec.seeds.model_dump()})
    rng = synth.rng("activity", "plan", scn)
    _ = internet_zone(world)
    templates = load_templates()
    clean = rng.random() < CLEAN_SCENARIO_RATE
    hard_neg_ratio = rng.uniform(0.2, 0.9)  # sampled per scenario, never fixed
    episodes = [
        EpisodePlan(episode_id(scn, e.index), e.index, e.virtual_start, e.virtual_end) for e in spec.episodes
    ]
    campaign_id: str | None = None

    for ep in episodes:
        erng = synth.rng("activity", "episode", scn, ep.index)
        ep.activities.extend(_benign_baseline(world, ep, erng, hard_neg_ratio, scn))

    if not clean:
        want_campaign = rng.random() < CAMPAIGN_RATE and len(episodes) >= 2
        if want_campaign:
            campaign_id = "CMP-" + sha256_hex(f"{scn}|campaign")[:10]
            _place_campaign(world, episodes, templates, synth, scn, campaign_id)
        else:
            # 1..N independent malicious activities spread over the episodes. Choose a FAMILY
            # first (balanced across placeable families), then a template within it, so no
            # family is starved by uniform-over-templates selection (brief: every family present).
            by_family = _placeable_by_family(world, templates)
            families = sorted(by_family)
            for ep in episodes:
                erng = synth.rng("activity", "attack", scn, ep.index)
                for _i in range(erng.randint(0, 2)):
                    if not families:
                        break
                    tmpl = erng.choice(by_family[erng.choice(families)])
                    act = _build_attack(world, tmpl, ep, erng, scn)
                    if act is not None:
                        ep.activities.append(act)

    return ScenarioPlan(scn, episodes, clean, round(hard_neg_ratio, 3), campaign_id)


def _place_campaign(
    world: World,
    episodes: list[EpisodePlan],
    templates: dict[str, AttackTemplate],
    synth: SynthSeeds,
    scn: str,
    campaign_id: str,
) -> None:
    rng = synth.rng("activity", "campaign", scn)
    chain = rng.choice(CAMPAIGN_CHAINS)
    stages = [templates[t] for t in chain if t in templates]
    parent: str | None = None
    src = _attacker_ip(world, rng)
    for i, tmpl in enumerate(stages):
        ep = episodes[min(i * len(episodes) // max(1, len(stages)), len(episodes) - 1)]
        act = _build_attack(world, tmpl, ep, rng, scn, campaign=campaign_id, parent=parent, source_ip=src)
        if act is not None:
            # some campaign stages intentionally produce no alert (detection gap)
            ep.activities.append(act)
            parent = act.activity_id
