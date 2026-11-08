"""The simulated world: one immutable source of truth every synthetic sensor reads from
(builder brief file 02).

``World`` wraps the already-sampled :class:`ScenarioSpec` (true topology, assets with true
criticality, identities, services, planted weaknesses, externals), the :class:`GrcReality`
(true control states and effectiveness) and the :class:`SocProfile` (what the SOC really
collects), and adds the lookups the activity and telemetry layers need: which asset owns an
IP, which zone a host is in, which flows the topology allows, which hosts carry an agent.

Nothing here invents facts — it is a read model over the generator's output. Reality (not a
coin flip) decides attack outcomes downstream: a step succeeds only when the enabling
weakness is really present and the path is really allowed.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from iris.contracts.spec import (
    AssetSpec,
    ExternalNode,
    FlowRule,
    IdentitySpec,
    ScenarioSpec,
    ServiceSpec,
    WeaknessSpec,
    ZoneSpec,
)
from iris.core.seeds import SeedSet
from iris.generator.grc.reality import GrcReality, build_reality
from iris.generator.soc import SocProfile, build_soc


@dataclass(frozen=True)
class World:
    spec: ScenarioSpec
    reality: GrcReality
    soc: SocProfile

    assets: dict[str, AssetSpec]
    zones: dict[str, ZoneSpec]
    zone_of: dict[str, str]  # asset_id -> primary zone name
    ip_to_asset: dict[str, str]  # recorded IP -> asset_id (shadow IPs resolve to None)
    services_by_asset: dict[str, list[ServiceSpec]]
    identities_by_asset: dict[str, list[IdentitySpec]]
    weaknesses_by_asset: dict[str, list[WeaknessSpec]]
    externals: list[ExternalNode]
    _allow: dict[tuple[str, str], list[FlowRule]] = field(default_factory=dict)

    # ------------------------------------------------------------------ lookups
    def asset_for_ip(self, ip: str) -> str | None:
        """Recorded asset owning ``ip``; ``None`` means a shadow host (in telemetry, not
        inventory) — a real signal, not an error (contract §2.3)."""
        return self.ip_to_asset.get(ip)

    def is_monitored(self, asset_id: str) -> bool:
        """True when a Wazuh agent on this host really forwards logs (coverage model)."""
        return asset_id in self.soc.sources

    def collects(self, asset_id: str, source: str) -> bool:
        return source in self.soc.sources.get(asset_id, [])

    def flow_action(self, src_zone: str, dst_zone: str, protocol: str, port: int | None) -> str:
        """``allow`` / ``deny`` / ``absent`` for a zone-pair flow under the recorded policy.

        A connection may exist only via an allowed flow (plus attacker-driven flows that are
        allowed, blocked-and-logged, or misconfig-permitted — the planner decides which)."""
        if src_zone == dst_zone:
            return "allow"  # intra-zone traffic is not gated by the zone policy
        rules = self._allow.get((src_zone, dst_zone), [])
        decision = "absent"
        for r in rules:
            if r.protocol not in (protocol, "any"):
                continue
            if r.ports and port is not None and port not in r.ports:
                continue
            if r.action == "allow":
                return "allow"
            decision = "deny"
        return decision

    def weakness(self, module: str, asset_id: str | None = None) -> WeaknessSpec | None:
        for w in self.spec.weaknesses:
            if w.module == module and (asset_id is None or w.asset_id == asset_id):
                return w
        return None

    def true_criticality(self, asset_id: str) -> int:
        a = self.assets.get(asset_id)
        return a.true_criticality if a else 1


def build_world(
    spec: ScenarioSpec,
    seeds: SeedSet | None = None,
    *,
    reality: GrcReality | None = None,
    soc: SocProfile | None = None,
) -> World:
    seeds = seeds or SeedSet.from_dict(spec.seeds.model_dump())
    reality = reality or build_reality(spec, seeds)
    soc = soc or build_soc(spec, reality, seeds)

    assets = {a.asset_id: a for a in spec.assets}
    zones = {z.name: z for z in spec.zones}
    zone_of: dict[str, str] = {}
    ip_to_asset: dict[str, str] = {}
    for a in spec.assets:
        if a.attachments:
            zone_of[a.asset_id] = a.attachments[0].zone
        elif a.shares_namespace_with:
            host = assets.get(a.shares_namespace_with)
            if host and host.attachments:
                zone_of[a.asset_id] = host.attachments[0].zone
        for att in a.attachments:
            ip_to_asset[att.ip] = a.asset_id

    services_by_asset: dict[str, list[ServiceSpec]] = {}
    for s in spec.services:
        services_by_asset.setdefault(s.asset_id, []).append(s)
    identities_by_asset: dict[str, list[IdentitySpec]] = {}
    for i in spec.identities:
        for aid in i.assigned_assets:
            identities_by_asset.setdefault(aid, []).append(i)
    weaknesses_by_asset: dict[str, list[WeaknessSpec]] = {}
    for w in spec.weaknesses:
        weaknesses_by_asset.setdefault(w.asset_id, []).append(w)

    allow: dict[tuple[str, str], list[FlowRule]] = {}
    for r in spec.policy:
        allow.setdefault((r.src_zone, r.dst_zone), []).append(r)

    return World(
        spec=spec,
        reality=reality,
        soc=soc,
        assets=assets,
        zones=zones,
        zone_of=zone_of,
        ip_to_asset=ip_to_asset,
        services_by_asset=services_by_asset,
        identities_by_asset=identities_by_asset,
        weaknesses_by_asset=weaknesses_by_asset,
        externals=list(spec.externals),
        _allow=allow,
    )


def internet_zone(world: World) -> str:
    from iris.contracts.common import ZoneKind

    return next(z.name for z in world.spec.zones if z.kind is ZoneKind.INTERNET)
