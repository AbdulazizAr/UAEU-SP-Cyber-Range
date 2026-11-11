"""Visible plane: what the Engine may read (IRIS Input Agreement v2.0).

Everything under ``enterprise/`` and ``grc/`` is the organisation's RECORDED view:
fields may be missing, stale or wrong (baseline noise and rare ledgered flaws),
so most business fields are optional. Reality never appears here.
"""

from __future__ import annotations

from datetime import date
from typing import Any, Literal

from pydantic import Field

from iris.contracts.common import (
    AssetId,
    AssetRole,
    Confidence,
    ControlId,
    ControlState,
    DataClass,
    EpisodeId,
    EventId,
    ExceptionId,
    IdentityId,
    Industry,
    NonEmptyStr,
    PackageId,
    RiskId,
    ScenarioId,
    ServiceId,
    SizeTier,
    StrictModel,
    UtcDateTime,
)

# ---------------------------------------------------------------- manifest


class EpisodeRef(StrictModel):
    episode_id: EpisodeId
    virtual_start: UtcDateTime
    virtual_end: UtcDateTime


class VirtualCalendar(StrictModel):
    start: UtcDateTime
    end: UtcDateTime
    timezone: NonEmptyStr


class VisibleManifest(StrictModel):
    """``manifest.visible.json``. Deliberately excludes generator version, seeds, tier,
    group_id, lineage, real creation date and activity counts (they would leak)."""

    schema_version: Literal["2.0.0", "2.1.0"] = "2.0.0"
    package_id: PackageId
    scenario_id: ScenarioId
    organization_id: str = Field(pattern=r"^ORG-\d{4}$")
    virtual_calendar: VirtualCalendar
    determinism: NonEmptyStr = "recipe and spec exact; telemetry equivalent, not byte-identical"
    episodes: list[EpisodeRef] = Field(min_length=1)
    coverage_windows_ref: NonEmptyStr = "quality/coverage_windows.json"
    enabled_sensors: list[Literal["wazuh", "suricata"]]
    available_artifacts: list[NonEmptyStr]
    record_counts: dict[str, int]
    tool_versions: dict[str, str]
    enrichment_as_of: dict[str, str]
    artifact_hashes: dict[str, str]
    merkle_root: str = Field(pattern=r"^[0-9a-f]{64}$")


# ---------------------------------------------------------------- enterprise (recorded)


class Organization(StrictModel):
    organization_id: str = Field(pattern=r"^ORG-\d{4}$")
    name: NonEmptyStr
    industry: Industry
    size: SizeTier
    timezone: NonEmptyStr
    workweek: list[Literal["mon", "tue", "wed", "thu", "fri", "sat", "sun"]]
    holidays: list[date] = Field(default_factory=list)
    business_units: list[NonEmptyStr]
    business_services: list[NonEmptyStr]
    # NOTE: security maturity is intentionally absent (it is a D7 target).


class Asset(StrictModel):
    asset_id: AssetId
    hostname: NonEmptyStr
    display_name: str | None = None
    role: AssetRole
    asset_type: Literal["server", "endpoint", "network", "security", "other"]
    ip_addresses: list[str]
    zone: str | None = None
    os_profile: str | None = None
    service_ids: list[ServiceId] = Field(default_factory=list)
    population_size: int = Field(default=1, ge=1)
    wazuh_agent_name: str | None = None
    source_of_record: Literal["cmdb", "spreadsheet", "scanner_discovered"] = "cmdb"
    recorded_at: UtcDateTime
    last_reviewed_at: UtcDateTime | None = None


class TopologyZone(StrictModel):
    name: NonEmptyStr
    subnet: str
    gateway: str | None = None
    switch_group: str | None = None
    member_asset_ids: list[AssetId] = Field(default_factory=list)


class TopologyPath(StrictModel):
    src: NonEmptyStr  # zone name, asset id or service id
    dst: NonEmptyStr
    protocol: Literal["tcp", "udp", "icmp", "any"]
    ports: list[int] = Field(default_factory=list)
    action: Literal["allow", "deny"]
    via: list[AssetId] = Field(default_factory=list)
    exception_id: ExceptionId | None = None


class Topology(StrictModel):
    zones: list[TopologyZone]
    paths: list[TopologyPath]
    dependencies: list[tuple[str, str]] = Field(default_factory=list)  # (from_ref, to_ref)
    internet_facing: list[str] = Field(default_factory=list)


class Identity(StrictModel):
    identity_id: IdentityId
    username: NonEmptyStr
    identity_type: Literal["human", "service"]
    role: str | None = None
    department: str | None = None
    privilege_level: Literal["standard", "power", "admin", "service"] | None = None
    groups: list[str] = Field(default_factory=list)
    assigned_asset_ids: list[AssetId] = Field(default_factory=list)
    enabled: bool = True
    mfa_state: Literal["enforced", "enrolled", "not_enrolled", "unknown"] = "unknown"
    authentication_method: str | None = None


class Service(StrictModel):
    service_id: ServiceId
    asset_id: AssetId
    service_type: NonEmptyStr
    name: NonEmptyStr
    port: int | None = None
    protocol: Literal["tcp", "udp"] | None = None
    dependencies: list[ServiceId] = Field(default_factory=list)
    exposure: Literal["internet", "internal", "restricted"] | None = None
    authentication_required: bool | None = None
    data_classification: DataClass | None = None


class Component(StrictModel):
    component_id: str = Field(pattern=r"^CMP-[A-Z0-9]+-\d{3}$")
    asset_id: AssetId
    service_id: ServiceId | None = None
    component_type: NonEmptyStr
    name: NonEmptyStr
    version: str | None = None
    exposure: Literal["internet", "internal", "restricted"] | None = None
    linked_package_refs: list[str] = Field(default_factory=list)
    linked_finding_ids: list[str] = Field(default_factory=list)
    linked_control_ids: list[ControlId] = Field(default_factory=list)


# ---------------------------------------------------------------- GRC (recorded, bitemporal)


class Bitemporal(StrictModel):
    valid_from: UtcDateTime | None = None
    valid_to: UtcDateTime | None = None
    recorded_at: UtcDateTime


class BusinessContext(Bitemporal):
    entity_ref: NonEmptyStr  # asset, service or component id
    business_unit: str | None = None
    business_process: str | None = None
    business_owner: str | None = None
    technical_owner: str | None = None
    criticality: str | None = None  # value in the organisation's own scale (see scale_definition)
    confidentiality: str | None = None
    integrity: str | None = None
    availability: str | None = None
    data_classification: DataClass | None = None
    regulatory_relevance: list[str] = Field(default_factory=list)


class Control(Bitemporal):
    control_id: ControlId
    control_name: NonEmptyStr
    control_family: NonEmptyStr
    implementation_state: ControlState
    applies_to_assets: list[AssetId] = Field(default_factory=list)
    applies_to_services: list[ServiceId] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    exception_id: ExceptionId | None = None
    last_assessed_at: UtcDateTime | None = None
    mapping_version: NonEmptyStr


class FrameworkRef(StrictModel):
    framework: Literal["NIST_SP_800_53_R5", "NIST_CSF_2_0", "ISO_27001_2022", "CIS_V8_1", "MITRE_D3FEND"]
    ref: NonEmptyStr
    provenance: Literal["official", "ours"]


class ControlMapping(StrictModel):
    control_id: ControlId
    mappings: list[FrameworkRef]
    mapping_version: NonEmptyStr


class Risk(Bitemporal):
    risk_id: RiskId
    entity_refs: list[str]
    risk_scenario: NonEmptyStr
    likelihood: str | None = None  # organisation's scale
    impact: str | None = None
    raw_risk: str | None = None
    control_factor: float | None = None
    residual_risk: str | None = None
    risk_level: str | None = None
    treatment: Literal["accept", "mitigate", "transfer", "avoid"] | None = None
    owner: str | None = None
    linked_control_ids: list[ControlId] = Field(default_factory=list)
    status: Literal["open", "closing", "closed", "accepted"] = "open"
    last_reviewed_at: UtcDateTime | None = None
    next_review_due: UtcDateTime | None = None
    scoring_version: NonEmptyStr


class PolicyException(Bitemporal):
    exception_id: ExceptionId
    control_id: ControlId
    asset_ids: list[AssetId]
    reason: NonEmptyStr
    approver: str | None = None
    approved_state: Literal["approved", "pending", "rejected", "revoked"]
    valid_until: UtcDateTime
    compensating_controls: list[ControlId] = Field(default_factory=list)


class IncidentRecord(Bitemporal):
    incident_id: str = Field(pattern=r"^INC-\d{4}$")
    opened_at: UtcDateTime
    closed_at: UtcDateTime | None = None
    status: Literal["open", "investigating", "contained", "closed"]
    affected_assets: list[AssetId] = Field(default_factory=list)
    summary: NonEmptyStr
    root_cause: str | None = None
    linked_risk_ids: list[RiskId] = Field(default_factory=list)
    linked_control_ids: list[ControlId] = Field(default_factory=list)


class RemediationItem(Bitemporal):
    item_id: str = Field(pattern=r"^REM-\d{4}$")
    finding_ref: NonEmptyStr
    owner: str | None = None
    severity: Literal["low", "medium", "high", "critical"]
    sla_days: int = Field(ge=0)
    due_at: UtcDateTime
    status: Literal["open", "in_progress", "done", "risk_accepted"]
    last_update_at: UtcDateTime | None = None


class ScaleDefinition(StrictModel):
    risk_scale: Literal["5x5", "3_level", "1_10", "qualitative"]
    risk_levels: list[NonEmptyStr]
    criticality_scale: Literal["1_5", "tier_0_3", "named", "cia"]
    criticality_levels: list[NonEmptyStr]
    control_vocabulary: Literal["iso_27001", "nist_csf", "cis", "home_grown"]
    review_cadence: Literal["monthly", "quarterly", "annual", "ad_hoc"]


class KpiValue(StrictModel):
    name: NonEmptyStr
    value: float
    unit: NonEmptyStr
    period_start: UtcDateTime
    period_end: UtcDateTime
    as_of: UtcDateTime


# ---------------------------------------------------------------- posture


class ScannerFinding(StrictModel):
    finding_id: str = Field(pattern=r"^FND-\d{5}$")
    asset_id: AssetId
    scanner: NonEmptyStr
    scanner_version: NonEmptyStr
    timestamp: UtcDateTime
    finding_type: Literal["cve", "misconfiguration", "secret", "license"]
    cve: str | None = Field(default=None, pattern=r"^CVE-\d{4}-\d{4,}$")
    package: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    severity: Literal["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    cvss: float | None = Field(default=None, ge=0, le=10)
    fix_available: bool = False
    evidence: str | None = None


class CveEnrichment(StrictModel):
    cve_id: str = Field(pattern=r"^CVE-\d{4}-\d{4,}$")
    cvss: float | None = Field(default=None, ge=0, le=10)
    cvss_version: Literal["3.1", "4.0"] | None = None
    severity: str | None = None
    epss: Confidence | None = None
    epss_percentile: Confidence | None = None
    kev_listed: bool = False
    kev_date_added: date | None = None
    published_at: UtcDateTime | None = None
    modified_at: UtcDateTime | None = None
    source: NonEmptyStr
    as_of: UtcDateTime  # date-gated: nothing after this virtual time is included


# ---------------------------------------------------------------- telemetry


TelemetrySource = Literal[
    "wazuh_alert",
    "wazuh_archive",
    "wazuh_fim",
    "wazuh_sca",
    "wazuh_syscollector",
    "wazuh_agent_status",
    "wazuh_manager_health",
    "suricata_eve",
    "suricata_stats",
    "app_event",
    "auth_event",
]


class TelemetryEnvelope(StrictModel):
    """Common envelope on every telemetry record (contract v2.0, section 2.3)."""

    event_id: EventId
    scenario_id: ScenarioId
    episode_id: EpisodeId
    source_type: TelemetrySource
    event_timestamp: UtcDateTime
    ingest_timestamp: UtcDateTime | None = None
    asset_ref: AssetId | None = None  # null = host absent from the recorded inventory
    eve_event_id: str | None = None  # shared by a Suricata event and its Wazuh-carried copy
    raw: dict[str, Any]


# ---------------------------------------------------------------- SOC self-description and quality


class SocInventory(StrictModel):
    wazuh_version: NonEmptyStr
    agents: list[dict[str, Any]]
    groups: dict[str, list[str]]
    log_sources_by_role: dict[str, list[str]]
    ruleset_version: NonEmptyStr
    loaded_rule_files: list[str]
    fim_scope: dict[str, list[str]] = Field(default_factory=dict)
    sca_policies: list[str] = Field(default_factory=list)
    retention_days: dict[str, int] = Field(default_factory=dict)
    archives_retained: bool
    coverage_statements: list[str] = Field(default_factory=list)  # what the SOC BELIEVES


class SensorInventory(StrictModel):
    suricata_version: NonEmptyStr
    placement_summary: list[str]
    eve_types: list[str]
    ruleset_snapshot_date: date
    loaded_categories: list[str]
    local_rules: list[str]


class SensorHealth(StrictModel):
    sensor: NonEmptyStr
    episode_id: EpisodeId
    status: Literal["healthy", "degraded", "down"]
    ready_at: UtcDateTime | None = None
    last_event_at: UtcDateTime | None = None
    collection_scope: list[str] = Field(default_factory=list)
    known_gaps: list[dict[str, Any]] = Field(default_factory=list)
    event_count: int = Field(default=0, ge=0)


class CoverageWindow(StrictModel):
    sensor: NonEmptyStr
    kind: Literal["observed", "unobserved"]
    start: UtcDateTime
    end: UtcDateTime
    episode_id: EpisodeId | None = None


class ContextChange(StrictModel):
    """One line of ``snapshots/context_history.jsonl`` (append-only)."""

    change_id: str = Field(pattern=r"^CHG-\d{6}$")
    effective_at: UtcDateTime
    recorded_at: UtcDateTime
    entity_type: Literal[
        "asset",
        "service",
        "component",
        "identity",
        "control",
        "risk",
        "exception",
        "incident",
        "sensor",
        "intel",
    ]
    entity_id: NonEmptyStr
    change_type: NonEmptyStr
    previous: dict[str, Any] | None = None
    new: dict[str, Any] | None = None
    evidence_ref: str | None = None
    source: NonEmptyStr


VISIBLE_MODELS: dict[str, type[StrictModel]] = {
    "manifest.visible": VisibleManifest,
    "enterprise.organization": Organization,
    "enterprise.asset": Asset,
    "enterprise.topology": Topology,
    "enterprise.identity": Identity,
    "enterprise.service": Service,
    "enterprise.component": Component,
    "grc.business_context": BusinessContext,
    "grc.control": Control,
    "grc.control_mapping": ControlMapping,
    "grc.risk": Risk,
    "grc.policy_exception": PolicyException,
    "grc.incident": IncidentRecord,
    "grc.remediation_item": RemediationItem,
    "grc.scale_definition": ScaleDefinition,
    "grc.kpi_value": KpiValue,
    "posture.scanner_finding": ScannerFinding,
    "posture.cve_enrichment": CveEnrichment,
    "telemetry.envelope": TelemetryEnvelope,
    "soc.soc_inventory": SocInventory,
    "telemetry.suricata.sensor_inventory": SensorInventory,
    "quality.sensor_health": SensorHealth,
    "quality.coverage_window": CoverageWindow,
    "snapshots.context_change": ContextChange,
}
