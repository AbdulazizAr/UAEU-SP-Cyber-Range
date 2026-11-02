"""Topology invariants (INPUT Part 1, 1.5): realism rules beyond schema consistency.

The schema validator (``ScenarioSpec``) proves the spec is internally consistent; these
checks prove it is a plausible enterprise. A sampled spec that breaks any of them is
resampled, never patched by hand.
"""

from __future__ import annotations

from collections import defaultdict

from iris.contracts.common import AssetRole, ZoneKind
from iris.contracts.spec import ScenarioSpec
from iris.generator.catalog import Catalog, load_catalog

SERVER_ROLES = {
    AssetRole.WEB_SERVER,
    AssetRole.APP_SERVER,
    AssetRole.DATABASE,
    AssetRole.DNS_SERVER,
    AssetRole.DIRECTORY,
    AssetRole.FILE_SERVER,
    AssetRole.MAIL_SERVER,
    AssetRole.BACKUP_SERVER,
}


def container_count(spec: ScenarioSpec) -> int:
    return sum(1 for a in spec.assets) + len(spec.externals)


def check(spec: ScenarioSpec, catalog: Catalog | None = None) -> list[str]:
    cat = catalog or load_catalog()
    arch = cat.archetypes.get(spec.archetype, {})
    zones = {z.name: z for z in spec.zones}
    zone_of = {a.asset_id: a.attachments[0].zone for a in spec.assets if a.attachments}
    roles: dict[AssetRole, list[str]] = defaultdict(list)
    for a in spec.assets:
        roles[a.role].append(a.asset_id)
    out: list[str] = []

    for required in (AssetRole.ROUTER_FIREWALL, AssetRole.IDS_SENSOR, AssetRole.DNS_SERVER, AssetRole.SIEM):
        if not roles.get(required):
            out.append(f"missing mandatory role {required.value}")

    router = next((a for a in spec.assets if a.role is AssetRole.ROUTER_FIREWALL), None)
    if router is not None:
        attached = {att.zone for att in router.attachments}
        missing = set(zones) - attached
        if missing:
            out.append(f"router not attached to zones {sorted(missing)}")

    if not arch.get("allows_db_in_user_zone"):
        for aid in roles.get(AssetRole.DATABASE, []):
            if zones[zone_of[aid]].kind is ZoneKind.USERS:
                out.append(f"{aid}: database inside a user zone")

    if "mgmt" in zones:
        for aid in roles.get(AssetRole.ADMIN_WORKSTATION, []):
            if zone_of[aid] != "mgmt":
                out.append(f"{aid}: admin workstation outside the management zone")

    for a in spec.assets:
        if a.role in SERVER_ROLES and a.attachments and zones[zone_of[a.asset_id]].kind is ZoneKind.INTERNET:
            out.append(f"{a.asset_id}: server placed in the internet zone")

    if not any(a.internet_exposed for a in spec.assets):
        out.append("no internet-exposed asset (nothing for external users or attackers to reach)")

    dependents: dict[str, int] = defaultdict(int)
    for s in spec.services:
        for d in s.depends_on:
            dependents[d] += 1
    for s in spec.services:
        if s.recipe == "postgresql" and dependents[s.service_id] == 0:
            out.append(f"{s.service_id}: orphan database (nothing depends on it)")

    web = [s for s in spec.services if s.recipe == "nginx"]
    if web and roles.get(AssetRole.APP_SERVER) and not any(s.depends_on for s in web):
        out.append("web tier does not depend on the application tier")

    cap = int(cat.sizes["container_cap"][spec.organization.size.value])
    if container_count(spec) > cap:
        out.append(
            f"{container_count(spec)} containers exceed the {spec.organization.size.value} cap of {cap}"
        )

    allowed_internet = {r.dst_zone for r in spec.policy if r.src_zone == "internet" and r.action == "allow"}
    for z in allowed_internet:
        if zones[z].kind not in (ZoneKind.DMZ,):
            out.append(f"internet may reach non-DMZ zone {z}")
    return out
