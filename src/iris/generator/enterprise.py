"""Recorded enterprise files: organization, topology, identities, services (visible plane).

These are what the organisation documented. In v0 they match the spec, except where the
GRC recorder already changed the inventory: topology zone membership lists only assets
in the recorded inventory, so shadow assets are missing and ghost assets are listed.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from iris.contracts.common import AssetRole, ZoneKind
from iris.contracts.spec import ScenarioSpec
from iris.contracts.visible import (
    Identity,
    Organization,
    Service,
    Topology,
    TopologyPath,
    TopologyZone,
)
from iris.generator.grc.recorded import GrcBundle

SUN_THU = {"Asia/Riyadh", "Asia/Kuwait", "Asia/Qatar", "Asia/Bahrain"}


def organization(spec: ScenarioSpec) -> Organization:
    org = spec.organization
    week = (
        ["sun", "mon", "tue", "wed", "thu"]
        if org.timezone in SUN_THU
        else ["mon", "tue", "wed", "thu", "fri"]
    )
    return Organization(
        organization_id=org.organization_id,
        name=org.name,
        industry=org.industry,
        size=org.size,
        timezone=org.timezone,
        workweek=week,
        business_units=list(org.business_units),
        business_services=list(org.business_services),
    )


def _exposure(spec: ScenarioSpec, asset_id: str) -> str:
    a = next(x for x in spec.assets if x.asset_id == asset_id)
    if a.internet_exposed:
        return "internet"
    zones = {z.name: z.kind for z in spec.zones}
    if any(zones[att.zone] is ZoneKind.MGMT for att in a.attachments):
        return "restricted"
    return "internal"


def services(spec: ScenarioSpec) -> list[Service]:
    return [
        Service(
            service_id=s.service_id,
            asset_id=s.asset_id,
            service_type=s.recipe,
            name=f"{s.recipe} {s.version}",
            port=s.port,
            protocol=s.protocol,
            dependencies=list(s.depends_on),
            exposure=_exposure(spec, s.asset_id),
            authentication_required=s.auth_required,
            data_classification=s.data_class,
        )
        for s in sorted(spec.services, key=lambda s: s.service_id)
    ]


def identities(spec: ScenarioSpec) -> list[Identity]:
    out: list[Identity] = []
    for i in sorted(spec.identities, key=lambda i: i.identity_id):
        if i.kind == "service":
            mfa, method = "unknown", "key_or_secret"
        else:
            mfa, method = ("enforced", "password+totp") if i.mfa_enforced else ("not_enrolled", "password")
        out.append(
            Identity(
                identity_id=i.identity_id,
                username=i.username,
                identity_type=i.kind,
                role=i.privilege if i.kind == "human" else "service",
                department=i.department,
                privilege_level=i.privilege,
                groups=list(i.groups),
                assigned_asset_ids=list(i.assigned_assets),
                mfa_state=mfa,
                authentication_method=method,
            )
        )
    return out


def topology(spec: ScenarioSpec, bundle: GrcBundle) -> Topology:
    recorded: dict[str, Any] = {a.asset_id: a for a in bundle.assets}
    router = next(a for a in spec.assets if a.role is AssetRole.ROUTER_FIREWALL)
    zones: list[TopologyZone] = []
    for z in spec.zones:
        net = ipaddress.ip_network(z.subnet)
        members = sorted(
            aid
            for aid, a in recorded.items()
            if any(ipaddress.ip_address(ip) in net for ip in a.ip_addresses)
        )
        zones.append(TopologyZone(name=z.name, subnet=z.subnet, gateway=z.gateway, member_asset_ids=members))
    paths = [
        TopologyPath(
            src=r.src_zone,
            dst=r.dst_zone,
            protocol=r.protocol,
            ports=list(r.ports),
            action=r.action,
            via=[router.asset_id],
        )
        for r in spec.policy
    ]
    deps = sorted({(s.service_id, d) for s in spec.services for d in s.depends_on})
    facing = sorted(a.asset_id for a in spec.assets if a.internet_exposed and a.asset_id in recorded)
    return Topology(zones=zones, paths=paths, dependencies=deps, internet_facing=facing)


def visible_files(spec: ScenarioSpec, bundle: GrcBundle) -> dict[str, Any]:
    return {
        "enterprise/organization.json": organization(spec).model_dump(mode="json"),
        "enterprise/topology.json": topology(spec, bundle).model_dump(mode="json"),
        "enterprise/identities.json": [i.model_dump(mode="json") for i in identities(spec)],
        "enterprise/services.json": [s.model_dump(mode="json") for s in services(spec)],
    }
