"""Seeds -> ScenarioSpec (INPUT Part 1, 1.2 steps 1-7; Part 2 A4 and B3).

Each part of the enterprise draws ONLY from its own sub-seed and named streams:

=========  =========================================================
org        industry, size, maturity, name, timezone
topology   archetype, IP plan, host counts, hostnames, policy extras, externals
services   versions, TLS, dependency wiring, data classes
identity   people, usernames, privileges, MFA
weakness   planted weaknesses
monitoring agent coverage (blind spots)
time       calendar anchor, horizon, episode placement
=========  =========================================================

so overriding one sub-seed (an alteration) changes only that part. Iteration orders are
fixed (catalog order, sorted keys) so the same seeds always give the same spec.
"""

from __future__ import annotations

import ipaddress
import random
from collections import defaultdict
from dataclasses import dataclass, replace
from datetime import UTC, date, datetime, time, timedelta
from typing import Any
from zoneinfo import ZoneInfo

from iris.contracts.common import AssetRole, DataClass, ZoneKind
from iris.contracts.spec import (
    AssetSpec,
    Attachment,
    CalendarSpec,
    EpisodeSpec,
    ExternalNode,
    FlowRule,
    IdentitySpec,
    OrganizationSpec,
    ScenarioSpec,
    SeedsSpec,
    ServiceSpec,
    WeaknessSpec,
    ZoneSpec,
)
from iris.core.seeds import SeedSet
from iris.generator.catalog import Catalog, load_catalog

ROLE_CODES: dict[str, str] = {
    "router_firewall": "RTR",
    "ids_sensor": "IDS",
    "web_server": "WEB",
    "reverse_proxy": "RP",
    "app_server": "APP",
    "database": "DB",
    "dns_server": "DNS",
    "directory": "DIR",
    "file_server": "FILE",
    "mail_server": "MAIL",
    "backup_server": "BAK",
    "bastion": "BST",
    "siem": "SIEM",
    "workstation": "WS",
    "admin_workstation": "ADM",
}
HOST_LABELS: dict[str, str] = {
    "router_firewall": "fw",
    "ids_sensor": "ids",
    "web_server": "web",
    "reverse_proxy": "proxy",
    "app_server": "app",
    "database": "db",
    "dns_server": "dns",
    "directory": "dc",
    "file_server": "files",
    "mail_server": "mail",
    "backup_server": "backup",
    "bastion": "jump",
    "siem": "siem",
    "workstation": "ws",
    "admin_workstation": "adm",
}
RECIPE_CODES: dict[str, str] = {
    "nginx": "WEB",
    "flask_shop": "APP",
    "postgresql": "DB",
    "unbound": "DNS",
    "openldap": "LDAP",
    "kerberos": "KRB",
    "samba": "SMB",
    "postfix": "SMTP",
    "openssh": "SSH",
    "restic_rest": "BAK",
    "wazuh_manager": "SIEM",
}
#: Optional roles dropped first (in this order) when a scenario exceeds its container cap.
DROP_ORDER = ("mail_server", "backup_server", "file_server", "bastion", "directory", "workstation")
SERVER_ROLES = frozenset(
    {"web_server", "reverse_proxy", "app_server", "database", "dns_server", "directory", "file_server",
     "mail_server", "backup_server", "bastion"}
)  # fmt: skip
WORKSTATION_ROLES = frozenset({"workstation", "admin_workstation"})
SITE_CODES = ("dxb", "auh", "ruh", "lon", "ber", "nyc", "sgp", "hq", "dc1")
HOSTNAME_STYLES = ("{label}-{n:02d}", "{label}{n:02d}", "{site}-{label}-{n:02d}", "{site}{label}{n:02d}")
USERNAME_STYLES = ("first.last", "flast", "firstl", "first_last")
#: Time zones whose organisations work Sunday to Thursday. The single source of truth for
#: both episode placement here and the visible ``organization.json`` workweek.
SUN_THU_TIMEZONES = frozenset({"Asia/Riyadh", "Asia/Kuwait", "Asia/Qatar", "Asia/Bahrain"})
SUN_THU = (6, 0, 1, 2, 3)  # Mon=0
WORKWEEK = dict.fromkeys(sorted(SUN_THU_TIMEZONES), SUN_THU)
DEFAULT_WORKWEEK = (0, 1, 2, 3, 4)
EXCLUDED_10_NETS = range(200, 204)  # docker default-address-pools 10.200.0.0/14


@dataclass(frozen=True)
class SampleOverrides:
    """Targeted alterations (INPUT Part 5, 8.3). None = sample normally."""

    industry: str | None = None
    size: str | None = None
    maturity: str | None = None
    archetype: str | None = None
    live: bool = False  # stay inside the live build matrix (configs/catalog/live.yaml)


def _weighted(rng: random.Random, weights: dict[str, float]) -> str:
    keys = sorted(weights)
    total = sum(weights[k] for k in keys)
    pick = rng.random() * total
    for k in keys:
        pick -= weights[k]
        if pick < 0:
            return k
    return keys[-1]


def _between(rng: random.Random, bounds: list[int]) -> int:
    return rng.randint(int(bounds[0]), int(bounds[1]))


# ---------------------------------------------------------------- org


@dataclass
class _Org:
    spec: OrganizationSpec
    industry: str
    size: str
    maturity: str


def _sample_org(seeds: SeedSet, cat: Catalog, ov: SampleOverrides) -> _Org:
    rng = seeds.stream("org", "profile")
    industry = ov.industry or sorted(cat.industries)[rng.randrange(len(cat.industries))]
    size = ov.size or _weighted(rng, cat.sizes["weights"])
    maturity = ov.maturity or _weighted(rng, cat.maturity["weights"])
    prof = cat.industries[industry]
    name_rng = seeds.stream("org", "name")
    name = f"{name_rng.choice(prof['name_words'])} {name_rng.choice(prof['name_suffix'])}"
    org = OrganizationSpec(
        organization_id=f"ORG-{rng.randint(1, 9999):04d}",
        name=name,
        industry=industry,
        size=size,
        maturity=maturity,
        timezone=rng.choice(cat.timezones),
        business_units=list(prof["business_units"]),
        business_services=list(prof["business_services"]),
    )
    return _Org(org, industry, size, maturity)


# ---------------------------------------------------------------- topology


def _pick_archetype(rng: random.Random, cat: Catalog, industry: str, size: str, forced: str | None) -> str:
    if forced:
        return forced
    weights = {
        a: float(w)
        for a, w in cat.industries[industry]["archetypes"].items()
        if size in cat.archetypes[a]["sizes"]
    }
    if not weights:
        weights = {a: 1.0 for a, spec in cat.archetypes.items() if size in spec["sizes"]}
    return _weighted(rng, weights)


def _zone_subnets(rng: random.Random, zones: list[str]) -> dict[str, ipaddress.IPv4Network]:
    """Private /24 per internal zone from a seeded family; internet from 198.18.0.0/15."""
    internal = [z for z in zones if z != "internet"]
    family = _weighted(rng, {"ten": 6, "172": 2.5, "192": 1.5})
    step = rng.randint(1, 10)
    if family == "ten":
        second = rng.choice([n for n in range(256) if n not in EXCLUDED_10_NETS])
        base = rng.randrange(0, 256 - step * len(internal))
        prefix = f"10.{second}"
    elif family == "172":
        second = rng.choice([n for n in range(16, 32) if n != 17])  # 172.17 is docker0
        base = rng.randrange(0, 256 - step * len(internal))
        prefix = f"172.{second}"
    else:
        base = rng.randrange(2, 256 - step * len(internal))  # skip common home LANs .0/.1
        prefix = "192.168"
    out = {z: ipaddress.IPv4Network(f"{prefix}.{base + i * step}.0/24") for i, z in enumerate(internal)}
    out["internet"] = ipaddress.IPv4Network(f"198.{rng.choice([18, 19])}.{rng.randrange(256)}.0/24")
    return out


def _host_ips(rng: random.Random, net: ipaddress.IPv4Network, count: int) -> list[str]:
    base = int(net.network_address)
    pool = list(range(10, 251))  # .1 is the router, .254 the container bridge
    return [str(ipaddress.ip_address(base + n)) for n in rng.sample(pool, count)]


def _role_counts(rng: random.Random, cat: Catalog, size: str, roles_available: set[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for role, bounds in cat.sizes["roles"][size].items():
        if role in roles_available:
            n = _between(rng, bounds)
            if n:
                counts[role] = n
    for required in ("web_server", "app_server", "database", "dns_server", "siem", "workstation"):
        if required in roles_available:
            counts[required] = max(counts.get(required, 0), 1)
    return counts


def _container_count(counts: dict[str, int], externals: int) -> int:
    return sum(counts.values()) + 2 + externals  # + router + sensor


# ---------------------------------------------------------------- the sampler


def sample_spec(
    seeds: SeedSet, overrides: SampleOverrides | None = None, catalog: Catalog | None = None
) -> ScenarioSpec:
    cat = catalog or load_catalog()
    ov = overrides or SampleOverrides()
    live = cat.live if ov.live else None
    if live is not None:
        ov = replace(ov, archetype=ov.archetype or live["archetype"], size=ov.size or live["size"])
    org = _sample_org(seeds, cat, ov)

    # ---- topology
    trng = seeds.stream("topology", "layout")
    archetype = _pick_archetype(trng, cat, org.industry, org.size, ov.archetype)
    arch = cat.archetypes[archetype]
    zone_names: list[str] = list(arch["zones"])
    zone_kinds = {z: arch.get("zone_kinds", {}).get(z, z) for z in zone_names}
    subnets = _zone_subnets(seeds.stream("topology", "ip_plan"), zone_names)
    role_zone: dict[str, str] = arch["role_zone"]
    if live is not None:  # only roles whose every service has a live image
        role_zone = {
            r: z for r, z in role_zone.items() if all(rc in live["recipes"] for rc in cat.role_services[r])
        }

    ext_rng = seeds.stream("topology", "externals")
    externals_plan = [("client", n) for n in range(1, ext_rng.randint(1, 2) + 1)] + [("attacker", 1)]
    if ext_rng.random() < 0.6:
        externals_plan.append(("scanner", 1))

    counts = _role_counts(seeds.stream("topology", "hosts"), cat, org.size, set(role_zone))
    cap = int(cat.sizes["container_cap"][org.size])
    for role in DROP_ORDER:
        while _container_count(counts, len(externals_plan)) > cap and counts.get(role, 0) > (
            1 if role == "workstation" else 0
        ):
            counts[role] -= 1
        if counts.get(role) == 0:
            counts.pop(role)

    name_rng = seeds.stream("topology", "hostnames")
    style = name_rng.choice(HOSTNAME_STYLES)
    site = name_rng.choice(SITE_CODES)

    def hostname(role: str, n: int) -> str:
        return style.format(label=HOST_LABELS[role], n=n, site=site)

    ip_rng = seeds.stream("topology", "host_ips")
    per_zone_roles: dict[str, list[tuple[str, int]]] = defaultdict(list)
    for role in sorted(counts):
        for n in range(1, counts[role] + 1):
            per_zone_roles[role_zone[role]].append((role, n))
    ip_of: dict[tuple[str, int], str] = {}
    for zone in zone_names:
        members = per_zone_roles.get(zone, [])
        for member, ip in zip(members, _host_ips(ip_rng, subnets[zone], len(members)), strict=True):
            ip_of[member] = ip

    # ---- services, data classes, criticality (services stream)
    srng = seeds.stream("services", "versions")
    trng_tls = seeds.stream("services", "tls")
    drng = seeds.stream("services", "data")
    mat = org.maturity
    tls_p = float(cat.maturity["tls_probability"][mat])
    regulated_db_p = 0.7

    os_rng = seeds.stream("services", "os")
    assets: list[dict[str, Any]] = []
    services: list[ServiceSpec] = []
    svc_counter: dict[str, int] = defaultdict(int)
    services_by_role: dict[str, list[ServiceSpec]] = defaultdict(list)
    asset_by_member: dict[tuple[str, int], str] = {}

    for role in sorted(counts):
        for n in range(1, counts[role] + 1):
            aid = f"AST-{ROLE_CODES[role]}-{n:03d}"
            asset_by_member[(role, n)] = aid
            kind = "workstation" if role in WORKSTATION_ROLES else "server"
            data_class = DataClass.INTERNAL
            if role == "database":
                data_class = DataClass.REGULATED if drng.random() < regulated_db_p else DataClass.CONFIDENTIAL
            elif role in {"app_server", "file_server", "directory", "backup_server"}:
                data_class = DataClass.CONFIDENTIAL
            elif role in {"web_server", "reverse_proxy"}:
                data_class = DataClass.PUBLIC
            assets.append(
                {
                    "asset_id": aid,
                    "hostname": hostname(role, n),
                    "role": role,
                    "os_profile": live["os_profile"] if live else os_rng.choice(cat.os_profiles[kind]),
                    "attachments": [{"zone": role_zone[role], "ip": ip_of[(role, n)]}],
                    "data_class": data_class,
                    "internet_exposed": role_zone[role] == "dmz"
                    and role in {"web_server", "reverse_proxy", "mail_server"},
                }
            )
            for recipe in cat.role_services[role]:
                rec = cat.recipes[recipe]
                code = RECIPE_CODES[recipe]
                svc_counter[code] += 1
                tls = bool(rec.get("tls_capable")) and trng_tls.random() < tls_p
                port = int(rec["port"])
                if rec.get("tls_capable") and not tls:
                    port = int(rec.get("plain_port", port))
                if tls and rec.get("tls_port"):
                    port = int(rec["tls_port"])
                svc = ServiceSpec(
                    service_id=f"SVC-{code}-{svc_counter[code]:03d}",
                    asset_id=aid,
                    recipe=recipe,
                    version=str(live["recipes"][recipe]) if live else str(srng.choice(rec["versions"])),
                    port=port,
                    protocol=rec["protocol"],
                    tls=tls,
                    auth_required=bool(rec["auth_required"]),
                    data_class=DataClass.REGULATED
                    if data_class is DataClass.REGULATED
                    else rec["data_class"],
                )
                services.append(svc)
                if recipe == cat.role_services[role][0]:
                    services_by_role[role].append(svc)

    # dependency wiring: each consumer's primary service depends on one provider of each provider role
    dep_rng = seeds.stream("services", "dependencies")
    depends: dict[str, list[str]] = defaultdict(list)
    for role in sorted(services_by_role):
        for provider_role in cat.role_dependencies.get(role, []):
            providers = services_by_role.get(provider_role)
            consumers = services_by_role[role]
            if not providers:
                continue
            used: set[str] = set()
            for svc in consumers:
                pick = dep_rng.choice(providers).service_id
                depends[svc.service_id].append(pick)
                used.add(pick)
            for p in providers:  # no orphan providers: every one gets at least one consumer
                if p.service_id not in used:
                    depends[dep_rng.choice(consumers).service_id].append(p.service_id)
    services = [
        s.model_copy(update={"depends_on": sorted(set(depends.get(s.service_id, [])))}) for s in services
    ]

    # criticality: base by role, +1 regulated data, +1 high fan-in (INPUT Part 2, A4)
    svc_asset = {s.service_id: s.asset_id for s in services}
    fan_in: dict[str, int] = defaultdict(int)
    for s in services:
        for d in s.depends_on:
            fan_in[svc_asset[d]] += 1

    # ---- monitoring (blind spots)
    mrng = seeds.stream("monitoring", "agent_coverage")
    cov = cat.maturity["agent_coverage"]

    asset_specs: list[AssetSpec] = []
    for a in assets:
        role = a["role"]
        crit = int(cat.base_criticality[role])
        crit += 1 if a["data_class"] is DataClass.REGULATED else 0
        crit += 1 if fan_in[a["asset_id"]] >= 3 else 0
        if role == "siem":
            monitored = False
        elif role in WORKSTATION_ROLES:
            monitored = mrng.random() < float(cov["workstations"][mat])
        else:
            monitored = mrng.random() < float(cov["servers"][mat])
        population = 1
        if role == "workstation":
            population = _between(
                seeds.stream("topology", f"population.{a['asset_id']}"), cat.sizes["population"][org.size]
            )
        asset_specs.append(
            AssetSpec(
                asset_id=a["asset_id"],
                hostname=a["hostname"],
                role=AssetRole(role),
                os_profile=a["os_profile"],
                attachments=[Attachment(**att) for att in a["attachments"]],
                population_size=population,
                monitored=monitored,
                true_criticality=min(crit, 5),
                data_class=a["data_class"],
                internet_exposed=a["internet_exposed"],
            )
        )

    # router + sensor
    router = AssetSpec(
        asset_id="AST-RTR-001",
        hostname=hostname("router_firewall", 1),
        role=AssetRole.ROUTER_FIREWALL,
        os_profile="debian-12",
        attachments=[Attachment(zone=z, ip=str(subnets[z].network_address + 1)) for z in zone_names],
        monitored=False,
        true_criticality=int(cat.base_criticality["router_firewall"]),
    )
    sensor = AssetSpec(
        asset_id="AST-IDS-001",
        hostname=hostname("ids_sensor", 1),
        role=AssetRole.IDS_SENSOR,
        os_profile="debian-12",
        shares_namespace_with="AST-RTR-001",
        monitored=True,
        true_criticality=int(cat.base_criticality["ids_sensor"]),
    )
    asset_specs = [router, sensor, *asset_specs]

    zones = [
        ZoneSpec(
            name=z,
            kind=ZoneKind(zone_kinds[z]),
            subnet=str(subnets[z]),
            gateway=str(subnets[z].network_address + 1),
        )
        for z in zone_names
    ]

    ext_ips = _host_ips(ext_rng, subnets["internet"], len(externals_plan))
    ext_codes = {"client": "CLIENT", "attacker": "ATK", "scanner": "SCAN"}
    externals = [
        ExternalNode(node_id=f"EXT-{ext_codes[k]}-{n:03d}", kind=k, zone="internet", ip=ip)
        for (k, n), ip in zip(externals_plan, ext_ips, strict=True)
    ]

    policy = _sample_policy(
        seeds, cat, mat, zone_names, zone_kinds, role_zone, counts, services, svc_asset, asset_specs
    )
    identities = _sample_identities(seeds, cat, org, asset_specs, services)
    weaknesses = _sample_weaknesses(seeds, cat, mat, services, set(live["weaknesses"]) if live else None)
    calendar, episodes = _sample_time(seeds, cat, org.spec.timezone)

    return ScenarioSpec(
        seeds=SeedsSpec(**seeds.to_dict()),
        organization=org.spec,
        calendar=calendar,
        archetype=archetype,
        zones=zones,
        policy=policy,
        assets=asset_specs,
        externals=externals,
        services=services,
        identities=identities,
        weaknesses=weaknesses,
        episodes=episodes,
    )


# ---------------------------------------------------------------- policy


def _sample_policy(
    seeds: SeedSet,
    cat: Catalog,
    maturity: str,
    zone_names: list[str],
    zone_kinds: dict[str, str],
    role_zone: dict[str, str],
    counts: dict[str, int],
    services: list[ServiceSpec],
    svc_asset: dict[str, str],
    assets: list[AssetSpec],
) -> list[FlowRule]:
    zone_of = {a.asset_id: a.attachments[0].zone for a in assets if a.attachments}
    svc_by_id = {s.service_id: s for s in services}
    allow: dict[tuple[str, str, str], set[int]] = defaultdict(set)

    def add(src: str, dst: str, proto: str, ports: list[int]) -> None:
        if src != dst:
            allow[(src, dst, proto)].update(ports)

    for s in services:  # dependency flows
        for dep in s.depends_on:
            p = svc_by_id[dep]
            add(zone_of[s.asset_id], zone_of[svc_asset[dep]], p.protocol, [p.port])
    web_zones = {zone_of[s.asset_id] for s in services if s.recipe == "nginx"}
    web_ports = sorted({s.port for s in services if s.recipe == "nginx"})
    user_zones = {zone_of[a.asset_id] for a in assets if a.role.value in WORKSTATION_ROLES}
    dns = [s for s in services if s.recipe == "unbound"]
    siem = [s for s in services if s.recipe == "wazuh_manager"]
    internal = [z for z in zone_names if z != "internet"]

    for uz in user_zones:
        for wz in web_zones:
            add(uz, wz, "tcp", web_ports)
    for z in internal:
        for d in dns:
            add(z, zone_of[d.asset_id], "udp", [53])
        for m in siem:
            add(z, zone_of[m.asset_id], "tcp", [1514, 1515])
    admin_zone = role_zone.get("admin_workstation")
    bastion_zone = role_zone.get("bastion") if counts.get("bastion") else None
    ssh_src = bastion_zone or admin_zone
    if ssh_src:
        for s in services:
            if s.recipe == "openssh":
                add(ssh_src, zone_of[s.asset_id], "tcp", [22])
    if bastion_zone and admin_zone:
        add(admin_zone, bastion_zone, "tcp", [22])

    rules = [
        FlowRule(src_zone="internet", dst_zone=wz, protocol="tcp", ports=web_ports, action="allow")
        for wz in sorted(web_zones)
        if wz in zone_names and zone_kinds.get(wz) == "dmz"
    ]
    rules += [
        FlowRule(src_zone=s, dst_zone=d, protocol=p, ports=sorted(ports), action="allow")
        for (s, d, p), ports in sorted(allow.items())
    ]

    # maturity-driven over-permissive exceptions (realistic drift)
    prng = seeds.stream("topology", "policy_extras")
    n_extra = _between(prng, cat.maturity["extra_allow_rules"][maturity])
    pairs = [(a, b) for a in internal for b in internal if a != b]
    for src, dst in prng.sample(pairs, min(n_extra, len(pairs))):
        rules.append(FlowRule(src_zone=src, dst_zone=dst, protocol="any", action="allow", is_exception=True))

    rules += [FlowRule(src_zone="internet", dst_zone=z, protocol="any", action="deny") for z in internal]
    return rules


# ---------------------------------------------------------------- identities


def _username(style: str, first: str, last: str) -> str:
    return {
        "first.last": f"{first}.{last}",
        "flast": f"{first[0]}{last}",
        "firstl": f"{first}{last[0]}",
        "first_last": f"{first}_{last}",
    }[style][:32]


def _sample_identities(
    seeds: SeedSet, cat: Catalog, org: _Org, assets: list[AssetSpec], services: list[ServiceSpec]
) -> list[IdentitySpec]:
    rng = seeds.stream("identity", "people")
    style = rng.choice(USERNAME_STYLES)
    n_people = _between(rng, cat.sizes["identities"][org.size])
    mfa_p = float(cat.maturity["mfa_probability"][org.maturity])
    units = [u for u in org.spec.business_units if u != "IT"]
    ws = [a.asset_id for a in assets if a.role is AssetRole.WORKSTATION]
    adm = [a.asset_id for a in assets if a.role is AssetRole.ADMIN_WORKSTATION]

    people: list[IdentitySpec] = []
    used: set[str] = set()
    n_admins = min(3, max(1, n_people // 10))
    for i in range(n_people):
        for _ in range(50):
            first, last = rng.choice(cat.first_names), rng.choice(cat.last_names)
            username = _username(style, first, last)
            if username not in used:
                break
        else:
            username = f"{_username(style, first, last)}{i}"
        used.add(username)
        is_admin = i < n_admins
        dept = "IT" if is_admin or rng.random() < 0.1 else rng.choice(units)
        privilege = "admin" if is_admin else ("power" if rng.random() < 0.1 else "standard")
        assigned = adm if is_admin else ([rng.choice(ws)] if ws else [])
        people.append(
            IdentitySpec(
                identity_id=f"IDN-{i + 1:04d}",
                username=username,
                kind="human",
                department=dept,
                privilege=privilege,
                groups=["sudo", "it-admins"] if is_admin else [dept.lower().replace(" ", "-")],
                assigned_assets=assigned,
                mfa_enforced=rng.random() < (min(1.0, mfa_p + 0.2) if is_admin else mfa_p),
            )
        )

    service_accounts: list[IdentitySpec] = []
    seen: set[str] = set()
    for s in services:
        if s.recipe in {"flask_shop", "postgresql", "restic_rest", "samba"} and s.recipe not in seen:
            seen.add(s.recipe)
            uname = f"svc_{s.recipe.split('_')[0]}"
            service_accounts.append(
                IdentitySpec(
                    identity_id=f"IDN-{len(people) + len(service_accounts) + 1:04d}",
                    username=uname,
                    kind="service",
                    department="IT",
                    privilege="service",
                    assigned_assets=[s.asset_id],
                )
            )
    return people + service_accounts


# ---------------------------------------------------------------- weaknesses


def _sample_weaknesses(
    seeds: SeedSet,
    cat: Catalog,
    maturity: str,
    services: list[ServiceSpec],
    allowed: set[str] | None = None,
) -> list[WeaknessSpec]:
    rng = seeds.stream("weakness", "plant")
    target = _between(rng, cat.maturity["weakness_count"][maturity])
    candidates = [
        (module_id, svc)
        for module_id, mod in sorted(cat.weaknesses.items())
        for svc in services
        if svc.recipe == mod["recipe"]
        and (allowed is None or module_id in allowed)
        and (mod.get("requires") != "tls" or svc.tls)
    ]
    chosen: list[tuple[str, ServiceSpec]] = []
    used: set[tuple[str, str]] = set()
    while candidates and len(chosen) < target:
        weights = [float(cat.weaknesses[m]["weight"]) for m, _ in candidates]
        idx = rng.choices(range(len(candidates)), weights=weights, k=1)[0]
        module_id, svc = candidates.pop(idx)
        if (module_id, svc.asset_id) in used:
            continue
        used.add((module_id, svc.asset_id))
        chosen.append((module_id, svc))
    out = []
    for i, (module_id, svc) in enumerate(chosen, start=1):
        mod = cat.weaknesses[module_id]
        out.append(
            WeaknessSpec(
                weakness_id=f"WK-{i:04d}",
                module=module_id,
                kind=mod["kind"],
                asset_id=svc.asset_id,
                service_id=svc.service_id,
                enabling_control=mod["control"],
                cwe=mod.get("cwe"),
                attackable=bool(mod["attackable"]),
            )
        )
    return out


# ---------------------------------------------------------------- time


def _sample_time(seeds: SeedSet, cat: Catalog, tz_name: str) -> tuple[CalendarSpec, list[EpisodeSpec]]:
    rng = seeds.stream("time", "calendar")
    cfg = cat.calendar
    snapshot = cfg["intel_snapshot_date"]
    snapshot = snapshot if isinstance(snapshot, date) else date.fromisoformat(str(snapshot))
    months = _between(rng, cfg["anchor_months_before"])
    start = snapshot - timedelta(days=30 * months + rng.randint(0, 27))
    horizon = _between(rng, cfg["horizon_days"])
    tz = ZoneInfo(tz_name)
    workweek = WORKWEEK.get(tz_name, DEFAULT_WORKWEEK)
    observe = timedelta(minutes=int(cfg["observe_minutes"]))

    n_episodes = _between(rng, cfg["episodes"])
    erng = seeds.stream("time", "episodes")
    days = sorted(erng.sample(range(1, horizon - 1), n_episodes))
    episodes: list[EpisodeSpec] = []
    for idx, day_offset in enumerate(days, start=1):
        day = start + timedelta(days=day_offset)
        if erng.random() < 0.8:  # mostly business hours on a working day
            while day.weekday() not in workweek:
                day += timedelta(days=1)
            local = time(hour=erng.randint(8, 17), minute=erng.choice([0, 10, 20, 30, 40, 50]))
        else:
            local = time(
                hour=erng.choice([0, 1, 2, 3, 5, 6, 19, 20, 21, 22]), minute=erng.choice([0, 15, 30, 45])
            )
        start_utc = datetime.combine(day, local, tzinfo=tz).astimezone(UTC)
        if episodes and start_utc <= episodes[-1].virtual_end:
            start_utc = episodes[-1].virtual_end + timedelta(days=1)
        end_utc = start_utc + observe
        if start_utc.year != end_utc.year:  # never straddle a year boundary
            start_utc -= observe * 2
            end_utc = start_utc + observe
        episodes.append(
            EpisodeSpec(
                index=idx,
                virtual_start=start_utc,
                virtual_end=end_utc,
                purpose="baseline" if idx == 1 else "quiet",  # the attack planner (P4) re-labels stages
            )
        )
    last_day = max(e.virtual_end.date() for e in episodes)
    horizon = max(horizon, (last_day - start).days + 1)
    calendar = CalendarSpec(start=start, horizon_days=horizon, timezone=tz_name)
    return calendar, episodes
