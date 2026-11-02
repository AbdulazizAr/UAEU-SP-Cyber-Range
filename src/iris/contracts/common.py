"""Shared types for every contract model."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, PlainSerializer

from iris.core.vclock import ensure_utc, iso_z


class StrictModel(BaseModel):
    """Producer-side model: unknown fields are errors, so typos never pass silently.

    Consumers (the Engine) should parse leniently, because minor contract versions
    may add fields (semantic versioning, IRIS Input Agreement v2.0 section 1)."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, validate_assignment=True)


#: Timezone-aware datetime, stored as UTC and serialised as ISO-8601 with ``Z``.
UtcDateTime = Annotated[
    datetime,
    AfterValidator(ensure_utc),
    PlainSerializer(iso_z, return_type=str, when_used="json"),
]

NonEmptyStr = Annotated[str, Field(min_length=1)]
Confidence = Annotated[float, Field(ge=0.0, le=1.0)]

# ID patterns. IDs are opaque and never encode seeds, templates or truth.
ScenarioId = Annotated[str, Field(pattern=r"^scn-[0-9a-f]{12}$")]
EpisodeId = Annotated[str, Field(pattern=r"^scn-[0-9a-f]{12}-ep\d{3}$")]
PackageId = Annotated[str, Field(pattern=r"^pkg-[0-9a-f]{12}$")]
EventId = Annotated[str, Field(pattern=r"^evt-[0-9a-f]{20}$")]
AssetId = Annotated[str, Field(pattern=r"^AST-[A-Z0-9]+-\d{3}$")]
ServiceId = Annotated[str, Field(pattern=r"^SVC-[A-Z0-9]+-\d{3}$")]
IdentityId = Annotated[str, Field(pattern=r"^IDN-\d{4}$")]
ControlId = Annotated[str, Field(pattern=r"^CTRL-[A-Z]+-\d{3}$")]
RiskId = Annotated[str, Field(pattern=r"^RSK-[A-Z0-9]+-\d{3}$")]
ExceptionId = Annotated[str, Field(pattern=r"^EXC-\d{4}$")]
AttackTechniqueId = Annotated[str, Field(pattern=r"^T\d{4}(\.\d{3})?$")]


class Maturity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class SizeTier(StrEnum):
    S = "S"
    M = "M"
    L = "L"


class Industry(StrEnum):
    RETAIL = "retail"
    HOSPITAL = "hospital"
    FINANCE = "finance_lite"
    UNIVERSITY = "university"
    SAAS = "saas"
    MANUFACTURING = "manufacturing_lite"
    PUBLIC_SECTOR = "public_sector_lite"
    LOGISTICS = "logistics_lite"


class ZoneKind(StrEnum):
    INTERNET = "internet"
    DMZ = "dmz"
    USERS = "users"
    SERVERS = "servers"
    DATA = "data"
    MGMT = "mgmt"
    GUEST = "guest"
    DEV = "dev"
    BACKUP = "backup"
    OT = "ot"
    MEDICAL = "medical"
    PCI = "pci"
    VPN = "vpn"


class AssetRole(StrEnum):
    WORKSTATION = "workstation"
    ADMIN_WORKSTATION = "admin_workstation"
    DEV_WORKSTATION = "dev_workstation"
    REMOTE_ENDPOINT = "remote_endpoint"
    WEB_SERVER = "web_server"
    APP_SERVER = "app_server"
    DATABASE = "database"
    FILE_SERVER = "file_server"
    BACKUP_SERVER = "backup_server"
    DNS_SERVER = "dns_server"
    DIRECTORY = "directory"
    MAIL_SERVER = "mail_server"
    BASTION = "bastion"
    ROUTER_FIREWALL = "router_firewall"
    VPN_GATEWAY = "vpn_gateway"
    REVERSE_PROXY = "reverse_proxy"
    IDS_SENSOR = "ids_sensor"
    SIEM = "siem"
    SCANNER = "scanner"
    INDUSTRY_ENDPOINT = "industry_endpoint"


#: Roles allowed to attach to more than one zone (gateways).
MULTI_ZONE_ROLES = frozenset({AssetRole.ROUTER_FIREWALL})


class DataClass(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    REGULATED = "regulated"


class ControlState(StrEnum):
    IMPLEMENTED = "implemented"
    PARTIAL = "partial"
    MISSING = "missing"
    NOT_ASSESSED = "not_assessed"
    COMPENSATING = "compensating"
    EXCEPTION = "exception"
