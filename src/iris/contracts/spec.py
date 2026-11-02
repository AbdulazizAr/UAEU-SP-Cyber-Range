"""Scenario Spec v0: the single declarative description of one enterprise (INPUT Part 1, 0).

The sampler (P2) produces it from seeds; the compiler turns it into Docker objects;
the resolved spec is stored in every recipe so replication never depends on old code.
This module validates internal consistency: references resolve, IPs fit their zone,
only gateways span zones, episodes are ordered and never cross a year boundary.
"""

from __future__ import annotations

import ipaddress
import itertools
from datetime import date, timedelta
from typing import Literal, Self

from pydantic import Field, field_validator, model_validator

from iris import GENERATOR_MAJOR, SPEC_VERSION
from iris.contracts.common import (
    MULTI_ZONE_ROLES,
    AssetId,
    AssetRole,
    ControlId,
    DataClass,
    IdentityId,
    Industry,
    Maturity,
    NonEmptyStr,
    ServiceId,
    SizeTier,
    StrictModel,
    UtcDateTime,
    ZoneKind,
)

SEED_MODULE_NAMES = (
    "org",
    "topology",
    "services",
    "identity",
    "weakness",
    "traffic",
    "attack",
    "monitoring",
    "time",
    "grc",
)


class SeedsSpec(StrictModel):
    master: int = Field(ge=0)
    generator_major: int = GENERATOR_MAJOR
    subseeds: dict[str, int]
    overridden: list[str] = Field(default_factory=list)

    @field_validator("subseeds")
    @classmethod
    def _all_modules(cls, v: dict[str, int]) -> dict[str, int]:
        if set(v) != set(SEED_MODULE_NAMES):
            raise ValueError(f"subseeds must contain exactly {list(SEED_MODULE_NAMES)}")
        return v


class OrganizationSpec(StrictModel):
    organization_id: str = Field(pattern=r"^ORG-\d{4}$")
    name: NonEmptyStr
    industry: Industry
    size: SizeTier
    maturity: Maturity  # generator input only; never exported to the visible plane
    timezone: NonEmptyStr = "UTC"
    business_units: list[NonEmptyStr] = Field(min_length=1)
    business_services: list[NonEmptyStr] = Field(min_length=1)


class CalendarSpec(StrictModel):
    start: date
    horizon_days: int = Field(ge=1, le=366)
    timezone: NonEmptyStr = "UTC"

    @property
    def end(self) -> date:
        return self.start + timedelta(days=self.horizon_days)


class ZoneSpec(StrictModel):
    name: str = Field(pattern=r"^[a-z][a-z0-9_]{1,30}$")
    kind: ZoneKind
    subnet: str
    gateway: str | None = None  # None only for the external INTERNET zone

    @field_validator("subnet")
    @classmethod
    def _cidr(cls, v: str) -> str:
        net = ipaddress.ip_network(v, strict=True)
        if net.version != 4:
            raise ValueError("v1 is IPv4 only")
        return str(net)

    @model_validator(mode="after")
    def _gateway_in_subnet(self) -> Self:
        if self.gateway is not None and ipaddress.ip_address(self.gateway) not in ipaddress.ip_network(
            self.subnet
        ):
            raise ValueError(f"zone {self.name}: gateway {self.gateway} not in {self.subnet}")
        if self.gateway is None and self.kind is not ZoneKind.INTERNET:
            raise ValueError(f"zone {self.name}: only the internet zone may lack a gateway")
        return self


class FlowRule(StrictModel):
    src_zone: str
    dst_zone: str
    protocol: Literal["tcp", "udp", "icmp", "any"]
    ports: list[int] = Field(default_factory=list)
    action: Literal["allow", "deny"]
    is_exception: bool = False

    @field_validator("ports")
    @classmethod
    def _ports(cls, v: list[int]) -> list[int]:
        if any(not 0 < p < 65536 for p in v):
            raise ValueError("port out of range")
        return v


class Attachment(StrictModel):
    zone: str
    ip: str


class AssetSpec(StrictModel):
    asset_id: AssetId
    hostname: str = Field(pattern=r"^[a-z][a-z0-9-]{0,62}$")
    role: AssetRole
    os_profile: NonEmptyStr
    attachments: list[Attachment] = Field(default_factory=list)
    shares_namespace_with: AssetId | None = None  # e.g. the Suricata sensor inside the router
    population_size: int = Field(default=1, ge=1)  # 1 container may represent many identical hosts
    monitored: bool = True  # has a Wazuh agent (False = deliberate blind spot)
    true_criticality: int = Field(ge=1, le=5)
    data_class: DataClass = DataClass.INTERNAL
    internet_exposed: bool = False

    @model_validator(mode="after")
    def _network_shape(self) -> Self:
        if self.shares_namespace_with is not None:
            if self.attachments:
                raise ValueError(f"{self.asset_id}: a namespace-sharing asset has no attachments of its own")
        elif not self.attachments:
            raise ValueError(f"{self.asset_id}: needs at least one network attachment")
        if len(self.attachments) > 1 and self.role not in MULTI_ZONE_ROLES:
            raise ValueError(f"{self.asset_id}: only gateway roles may attach to several zones")
        return self


class ExternalNode(StrictModel):
    """A node in the simulated Internet that is not an organisation asset."""

    node_id: str = Field(pattern=r"^EXT-[A-Z0-9]+-\d{3}$")
    kind: Literal["client", "attacker", "service", "scanner"]
    zone: str
    ip: str


class ServiceSpec(StrictModel):
    service_id: ServiceId
    asset_id: AssetId
    recipe: NonEmptyStr
    version: NonEmptyStr
    port: int = Field(gt=0, lt=65536)
    protocol: Literal["tcp", "udp"] = "tcp"
    tls: bool = False
    auth_required: bool = True
    depends_on: list[ServiceId] = Field(default_factory=list)
    data_class: DataClass = DataClass.INTERNAL


class IdentitySpec(StrictModel):
    identity_id: IdentityId
    username: str = Field(pattern=r"^[a-z_][a-z0-9_.-]{0,31}$")
    kind: Literal["human", "service"]
    department: NonEmptyStr
    privilege: Literal["standard", "power", "admin", "service"]
    groups: list[NonEmptyStr] = Field(default_factory=list)
    assigned_assets: list[AssetId] = Field(default_factory=list)
    mfa_enforced: bool = False


class WeaknessSpec(StrictModel):
    """A planted weakness. Hidden plane only; the visible plane never lists these."""

    weakness_id: str = Field(pattern=r"^WK-\d{4}$")
    module: NonEmptyStr
    kind: Literal["A", "B", "C"]  # A version CVE, B configuration, C application logic
    asset_id: AssetId
    service_id: ServiceId | None = None
    enabling_control: ControlId
    cwe: str | None = Field(default=None, pattern=r"^CWE-\d+$")
    cve: str | None = Field(default=None, pattern=r"^CVE-\d{4}-\d{4,}$")
    attackable: bool = False  # True only if the verification check must pass at deploy


class EpisodeSpec(StrictModel):
    index: int = Field(ge=1, le=999)
    virtual_start: UtcDateTime
    virtual_end: UtcDateTime
    purpose: Literal["baseline", "attack_stage", "post_change", "quiet"]

    @model_validator(mode="after")
    def _window(self) -> Self:
        if self.virtual_end <= self.virtual_start:
            raise ValueError(f"episode {self.index}: end must be after start")
        if self.virtual_start.year != self.virtual_end.year:
            raise ValueError(f"episode {self.index}: window crosses a year boundary")
        return self


class ScenarioSpec(StrictModel):
    spec_version: Literal["0.1.0"] = SPEC_VERSION  # type: ignore[assignment]
    seeds: SeedsSpec
    organization: OrganizationSpec
    calendar: CalendarSpec
    archetype: NonEmptyStr
    zones: list[ZoneSpec] = Field(min_length=2)
    policy: list[FlowRule] = Field(default_factory=list)
    assets: list[AssetSpec] = Field(min_length=1)
    externals: list[ExternalNode] = Field(default_factory=list)
    services: list[ServiceSpec] = Field(default_factory=list)
    identities: list[IdentitySpec] = Field(default_factory=list)
    weaknesses: list[WeaknessSpec] = Field(default_factory=list)
    episodes: list[EpisodeSpec] = Field(min_length=1)

    @model_validator(mode="after")
    def _consistency(self) -> Self:
        errors: list[str] = []

        def unique(label: str, values: list[str]) -> None:
            dupes = sorted({v for v in values if values.count(v) > 1})
            if dupes:
                errors.append(f"duplicate {label}: {dupes}")

        unique("zone names", [z.name for z in self.zones])
        unique("asset ids", [a.asset_id for a in self.assets])
        unique("hostnames", [a.hostname for a in self.assets])
        unique("service ids", [s.service_id for s in self.services])
        unique("identity ids", [i.identity_id for i in self.identities])
        unique("usernames", [i.username for i in self.identities])
        unique("weakness ids", [w.weakness_id for w in self.weaknesses])
        unique("external ids", [e.node_id for e in self.externals])

        zones = {z.name: z for z in self.zones}
        assets = {a.asset_id: a for a in self.assets}
        services = {s.service_id: s for s in self.services}

        internet = [z for z in self.zones if z.kind is ZoneKind.INTERNET]
        if len(internet) != 1:
            errors.append("exactly one internet zone is required")

        for a, b in itertools.combinations(self.zones, 2):
            if ipaddress.ip_network(a.subnet).overlaps(ipaddress.ip_network(b.subnet)):
                errors.append(f"subnets overlap: {a.name} {a.subnet} / {b.name} {b.subnet}")

        used_ips: dict[str, str] = {}

        def claim(ip: str, owner: str, zone_name: str) -> None:
            zone = zones.get(zone_name)
            if zone is None:
                errors.append(f"{owner}: unknown zone {zone_name}")
                return
            addr = ipaddress.ip_address(ip)
            net = ipaddress.ip_network(zone.subnet)
            if addr not in net:
                errors.append(f"{owner}: {ip} not in {zone_name} {zone.subnet}")
            elif addr in (net.network_address, net.broadcast_address):
                errors.append(f"{owner}: {ip} is the network or broadcast address")
            elif addr == net.broadcast_address - 1:
                errors.append(f"{owner}: {ip} is reserved for the container bridge (last usable address)")
            if ip in used_ips and used_ips[ip] != owner:
                errors.append(f"{owner}: IP {ip} already used by {used_ips[ip]}")
            used_ips[ip] = owner

        gateways: dict[str, str] = {}
        for asset in self.assets:
            seen_zones: set[str] = set()
            for att in asset.attachments:
                if att.zone in seen_zones:
                    errors.append(f"{asset.asset_id}: attached twice to {att.zone}")
                seen_zones.add(att.zone)
                claim(att.ip, asset.asset_id, att.zone)
                zone = zones.get(att.zone)
                if zone is not None and zone.gateway == att.ip:
                    gateways[att.zone] = asset.asset_id
            if asset.shares_namespace_with is not None:
                host = assets.get(asset.shares_namespace_with)
                if host is None:
                    errors.append(
                        f"{asset.asset_id}: shares namespace with unknown {asset.shares_namespace_with}"
                    )
                elif host.role not in MULTI_ZONE_ROLES:
                    errors.append(f"{asset.asset_id}: may only share a gateway's namespace")

        for zone in self.zones:
            if zone.gateway is not None and zone.name not in gateways:
                errors.append(f"zone {zone.name}: gateway {zone.gateway} is not held by any gateway asset")
        for ext in self.externals:
            claim(ext.ip, ext.node_id, ext.zone)
            if ext.zone in zones and zones[ext.zone].kind is not ZoneKind.INTERNET:
                errors.append(f"{ext.node_id}: external nodes must live in the internet zone")

        for rule in self.policy:
            for z in (rule.src_zone, rule.dst_zone):
                if z not in zones:
                    errors.append(f"policy rule references unknown zone {z}")

        for svc in self.services:
            if svc.asset_id not in assets:
                errors.append(f"{svc.service_id}: unknown asset {svc.asset_id}")
            for dep in svc.depends_on:
                if dep not in services:
                    errors.append(f"{svc.service_id}: depends on unknown {dep}")
                elif dep == svc.service_id:
                    errors.append(f"{svc.service_id}: depends on itself")

        for idn in self.identities:
            for aid in idn.assigned_assets:
                if aid not in assets:
                    errors.append(f"{idn.identity_id}: assigned to unknown asset {aid}")

        for wk in self.weaknesses:
            if wk.asset_id not in assets:
                errors.append(f"{wk.weakness_id}: unknown asset {wk.asset_id}")
            if wk.service_id is not None and wk.service_id not in services:
                errors.append(f"{wk.weakness_id}: unknown service {wk.service_id}")

        cal_start, cal_end = self.calendar.start, self.calendar.end
        for prev, cur in itertools.pairwise(self.episodes):
            if cur.index != prev.index + 1:
                errors.append(f"episode indices must be consecutive ({prev.index} then {cur.index})")
            if cur.virtual_start < prev.virtual_end:
                errors.append(f"episode {cur.index} overlaps episode {prev.index}")
        for ep in self.episodes:
            if not (cal_start <= ep.virtual_start.date() and ep.virtual_end.date() <= cal_end):
                errors.append(f"episode {ep.index} lies outside the scenario calendar")
        if self.episodes and self.episodes[0].index != 1:
            errors.append("first episode index must be 1")

        if errors:
            raise ValueError("scenario spec is inconsistent:\n  - " + "\n  - ".join(errors))
        return self
