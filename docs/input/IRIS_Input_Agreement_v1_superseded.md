# IRIS_Input_Agreement

## Purpose

This document defines the **proposed output contract from the Cyber Range / Dataset Generator to the IRIS Engine**.

It is intentionally focused on one question:

> **What data will the Cyber Range produce that the Engine can rely on as input?**

The transport is not fixed here. The same logical records may later be delivered as files, replayed JSONL, an API, or a live stream. The Engine should depend on the **data contract**, not on one delivery method.

This is a proposal for the Engine team to review and reply to with:
- accepted inputs,
- requested changes,
- additional inputs they require,
- and the exact ML prediction task(s) they intend to build.

---

# 1. Common rules for every run

Every run must be identifiable and joinable across all files.

Common identifiers:

```text
scenario_id
run_id
generator_version
schema_version
organization_id
timestamp / valid_at where relevant
```

Where applicable:

```text
asset_id
identity_id
service_id
component_id
activity_id
attack_id
campaign_id
event_id
control_id
risk_id
```

All timestamps should use ISO-8601 UTC.

Raw generator-only identifiers such as the seed may be preserved for reproducibility, but they are **not automatically valid ML features**.

---

# 2. Proposed output package

A generated run should expose the following logical structure.

```text
scenario-<id>/
|
|-- manifest.json
|
|-- enterprise/
|   |-- organization.json
|   |-- assets.json
|   |-- topology.json
|   |-- identities.json
|   |-- services.json
|   |-- components.json
|
|-- grc/
|   |-- business_context.json
|   |-- controls.json
|   |-- risk_register.json
|   |-- control_mappings.json
|   |-- policy_exceptions.json
|
|-- posture/
|   |-- generated_weaknesses.json
|   |-- scanner_findings.jsonl
|   |-- cve_enrichment.jsonl
|   |-- sbom/
|       |-- <asset_id>.cdx.json
|
|-- telemetry/
|   |-- wazuh/
|   |   |-- alerts.jsonl
|   |   |-- archives.jsonl
|   |   |-- fim.jsonl
|   |   |-- rule_metadata.json
|   |
|   |-- applications/
|   |   |-- application_events.jsonl
|   |   |-- authentication_events.jsonl
|   |
|   |-- suricata/
|       |-- eve.jsonl                  [optional if Suricata is adopted]
|
|-- activity/
|   |-- activities.jsonl
|   |-- attack_catalog_snapshot.json
|   |-- benign_catalog_snapshot.json
|
|-- truth/
|   |-- activity_truth.jsonl
|   |-- campaign_truth.jsonl
|   |-- detection_expectations.jsonl
|   |-- evidence_links.jsonl
|
|-- snapshots/
|   |-- pre_activity_context.json
|   |-- context_history.jsonl
|   |-- post_activity_context.json
|
|-- quality/
|   |-- verification.json
|   |-- sensor_health.json
|   |-- data_quality.json
|
|-- performance/
    |-- run_metrics.json
```

Not every physical file must remain separate forever. The Engine team should treat these as **logical data objects**. For example, FIM records may later be carried inside a unified telemetry stream with `source_type="wazuh_fim"`.

---

# 3. Enterprise and infrastructure inputs

## 3.1 `enterprise/organization.json`

**Purpose:** tells the Engine what organization the generated environment represents.

Expected fields include:

```text
organization_id
organization_type
organization_size
industry/profile
security_maturity
departments / business_units
business_services
scenario_id
run_id
```

This corrects the prototype problem where `organization.size` was declared in schema but not actually generated.

Example:

```json
{
  "organization_id": "ORG-0007",
  "organization_type": "retail",
  "organization_size": "medium",
  "security_maturity": "developing",
  "business_units": ["Retail Operations", "IT", "Finance"],
  "business_services": ["E-Commerce", "Inventory", "Identity"]
}
```

**Availability:** Runtime context.

---

## 3.2 `enterprise/assets.json`

**Purpose:** authoritative inventory used by the Engine for asset resolution.

Expected per asset:

```text
asset_id
hostname
display_name
role
asset_type
IP address(es)
network / zone
OS profile
deployed image / actual runtime platform
criticality
owner_id / owner_role
business_unit
business_process
data_sensitivity / classification
internet_exposed
service_ids
identity relationships
Wazuh agent identity if enrolled
```

The full project should not repeat the prototype gap where some deployed components such as the gateway existed without a proper inventory asset ID.

The asset catalogue is expected to cover more than application servers. Depending on the generated organization, valid asset roles may include:

```text
employee workstation
admin workstation
developer workstation
remote endpoint / laptop
web server
API / application server
database server
file server
backup server
DNS server
identity / directory server
mail server
firewall
router
VPN gateway
reverse proxy / WAF
monitoring / security system
vulnerability scanner
industry-specific endpoint such as POS or kiosk
```

The organization generator should determine which roles are sensible for the generated business. Asset roles are not selected as an unrelated random list. A hospital, retailer and small office should therefore produce different but internally coherent infrastructure.

Example:

```json
{
  "asset_id": "AST-WEB-001",
  "hostname": "web01",
  "role": "web_server",
  "zone": "dmz",
  "ip_addresses": ["10.20.10.11"],
  "os_profile": "ubuntu-24.04",
  "criticality": "high",
  "business_unit": "Retail Operations",
  "business_process": "E-Commerce",
  "data_sensitivity": "internal",
  "wazuh_agent_name": "scenario-7-web01"
}
```

**Availability:** Runtime context.

---

## 3.3 `enterprise/topology.json`

**Purpose:** gives the Engine the logical technical relationships around an event.

Expected information:

```text
networks / zones
asset membership
allowed communication paths
service dependencies
application dependencies
identity dependencies
internet-facing paths
router / firewall relationships
```

Example relationships:

```text
AST-WS-004 -> SVC-ID-001
AST-WS-004 -> SVC-WEB-001
AST-ADMIN-001 -> SVC-VPN-001
AST-WEB-001 -> SVC-API-001
SVC-API-001 -> AST-DB-001
AST-BACKUP-001 -> AST-DB-001
INTERNET -> AST-FW-001 -> DMZ_WEB : allowed tcp/443
DMZ -> INTERNAL_API : allowed tcp/443
```

Topology should therefore be able to represent endpoint-to-identity, endpoint-to-application, application-to-database, backup/storage dependencies, and network/security-device paths rather than only server-to-server links.

The Engine does not need Docker-internal runtime IDs as its primary topology model.

**Availability:** Runtime context.

---

## 3.4 `enterprise/identities.json`

**Purpose:** enables identity-aware correlation and prevents the prototype mismatch where telemetry used account `employee` while generated identities were `user001`, `user002`, etc.

Expected fields:

```text
identity_id
username
identity_type: human | service
role
department
privilege_level
groups
assigned_asset_ids
enabled
MFA_state
authentication_method
```

Activity generation should reference identities that actually exist here.

**Availability:** Runtime context.

Passwords and secrets are never part of the Engine contract.

---

## 3.5 `enterprise/services.json`

**Purpose:** describes the applications and services the Engine may see in telemetry.

Expected fields:

```text
service_id
asset_id
service_type
name
port / protocol
application_role
dependencies
exposure
authentication_required
data_classification
```

Examples:

```text
web frontend
REST API
database
identity provider
file service
SSH service
admin portal
```

**Availability:** Runtime context.

---

## 3.6 `enterprise/components.json`

**Purpose:** represents important software or logical components inside an asset without treating every package in an SBOM as a separate GRC asset.

This creates an explicit middle layer:

```text
business service
-> asset
-> service / important component
-> package / dependency evidence
```

Expected fields may include:

```text
component_id
asset_id
service_id where applicable
component_type
name
version
role
exposure
authentication_role
data_role
configuration_state
linked_package_refs
linked_finding_ids
linked_control_ids
```

Examples of components worth representing explicitly:

```text
nginx / Apache
Flask / FastAPI application
PostgreSQL / MySQL
Keycloak / directory service
OpenSSL or another security-critical runtime component
backup agent
web authentication module
reverse proxy
```

Raw low-level packages remain primarily SBOM/scanner evidence. The Range should not turn every library into a full business asset.

**Availability:** Runtime/supporting context.

---

# 4. GRC and business inputs

The prototype GRC data was too limited for the full system. The big project should generate richer business and control context rather than leaving fields such as owner, business process and sensitivity absent.

## 4.1 `grc/business_context.json`

**Purpose:** business meaning of assets/services and, where useful, important components.

The intended relationship is hierarchical rather than flat:

```text
organization
-> business service / process
-> asset
-> service or important component
-> technical evidence such as packages, CVEs and telemetry
```

Expected fields:

```text
asset_id / service_id / component_id where applicable
business_unit
business_process
business_owner
technical_owner
criticality
confidentiality_requirement
integrity_requirement
availability_requirement
data_classification
customer_impact
operational_impact
financial_impact category
regulatory_relevance
third_party_dependency if generated
```

**Availability:** Runtime context.

---

## 4.2 `grc/controls.json`

**Purpose:** current control posture.

Expected fields:

```text
control_id
control_name
control_family
implementation_state
applies_to_assets
applies_to_services
evidence_refs
exception_id if applicable
last_assessed_at
mapping_version
```

Recommended implementation states:

```text
implemented
partial
missing
not_assessed
compensating
exception
```

Example:

```json
{
  "control_id": "CTRL-IAM-002",
  "control_name": "Multi-factor authentication",
  "implementation_state": "missing",
  "applies_to_assets": ["AST-WS-004", "AST-ID-001"],
  "evidence_refs": ["CFG-ID-22"]
}
```

**Availability:** Runtime context.

---

## 4.3 `grc/control_mappings.json`

**Purpose:** stable mapping from internal controls to external frameworks.

Example:

```json
{
  "control_id": "CTRL-IAM-002",
  "mappings": [
    {"framework": "NIST_SP_800_53", "control": "IA-2"},
    {"framework": "CIS_V8", "control": "6.3"}
  ],
  "mapping_version": "grc-map-1.0"
}
```

Mappings should not pretend different frameworks are perfectly equivalent; they are references.

**Availability:** Runtime context.

---

## 4.4 `grc/risk_register.json`

**Purpose:** baseline organizational risk state before IRIS adds incident context.

Expected fields:

```text
risk_id
asset_id / service_id
risk_scenario
likelihood
impact
raw_risk
control_factor where used
residual_risk
risk_level
treatment
linked_control_ids
snapshot_time
scoring_version
```

Important:
- baseline risk must be distinguishable from risk calculated later by IRIS;
- formulas must be versioned;
- factors already included in `residual_risk` must not be applied again downstream.

**Availability:** Runtime context.

---

## 4.5 `grc/policy_exceptions.json`

**Purpose:** prevents IRIS from treating an approved exception exactly like an unknown missing control.

Expected fields:

```text
exception_id
control_id
asset_ids
reason
approved_state
valid_from
valid_until
compensating_controls
```

**Availability:** Runtime context.

---

# 5. Security posture and vulnerability inputs

## 5.1 `posture/generated_weaknesses.json`

**Purpose:** what the Range intentionally configured.

Examples:

```text
weak credentials
missing MFA
insecure permissions
exposed database
outdated package selection
weak TLS
exposed admin interface
excessive privileges
```

Expected fields:

```text
weakness_id
asset_id
weakness_type
configured_state
related_control_ids
introduced_by_generator
generator_version
```

**Availability:** Runtime context where the state would realistically be knowable.

It must remain semantically separate from scanner findings.

---

## 5.2 `posture/scanner_findings.jsonl`

**Purpose:** what security scanners actually observed.

Expected fields:

```text
finding_id
asset_id
scanner
scanner_version
timestamp
finding_type
CVE if applicable
package
installed_version
severity
CVSS if supplied
fix_available
evidence
```

A scanner finding is **not proof of exploitation**.

**Availability:** Runtime context.

---

## 5.3 `posture/cve_enrichment.jsonl`

**Purpose:** snapshot external vulnerability intelligence so the Engine does not depend on live Internet APIs during inference.

Possible sources:

```text
NVD / CVE
CISA KEV
FIRST EPSS
vendor advisory data where intentionally supported
```

Expected fields:

```text
cve_id
CVSS
severity
EPSS
EPSS_percentile
KEV_listed
known_exploitation metadata where sourced
published_at
modified_at
source
enrichment_as_of
```

Example:

```json
{
  "cve_id": "CVE-2021-44228",
  "cvss": 10.0,
  "epss": 0.94,
  "epss_percentile": 0.99,
  "kev_listed": true,
  "enrichment_as_of": "2026-09-27T00:00:00Z"
}
```

**Availability:** Runtime context.

Whether these fields are fed to ML is a separate decision after the Engine ML target is fixed.

---

## 5.4 `posture/sbom/<asset_id>.cdx.json`

**Purpose:** detailed software/component evidence.

CycloneDX SBOMs may be supplied per relevant asset/image.

The Engine does not necessarily need every package as a direct ML feature. It may use summarized or queried software context.

**Availability:** Supporting runtime context.

---

# 6. Wazuh and host telemetry inputs

The Engine review correctly requires both alert and archive/raw evidence rather than alerts alone.

## 6.1 `telemetry/wazuh/alerts.jsonl`

Expected fields preserve the original Wazuh evidence and normalized identifiers.

Typical fields:

```text
event_id
event_timestamp
ingestion_timestamp where available
scenario_id
run_id
agent.id
agent.name
resolved_asset_id if known
rule.id
rule.level
rule.description
rule.groups
MITRE tactic/technique if supplied by Wazuh
source_ip
destination_ip
source_port / destination_port if present
user / account if present
decoder
location
full_log
raw_ref
```

**Availability:** Runtime telemetry.

---

## 6.2 `telemetry/wazuh/archives.jsonl`

**Purpose:** raw/unfiltered collected evidence, including activity that never produced a Wazuh alert.

This is important for:
- missed detections,
- benign activity,
- weak signals,
- comparison of what happened vs what Wazuh elevated.

Expected common envelope:

```text
event_id
event_timestamp
ingestion_timestamp
agent
asset_id where resolved
location
decoder
event family
raw event / full_log
raw_ref
```

**Availability:** Runtime telemetry.

---

## 6.3 `telemetry/wazuh/fim.jsonl`

**Purpose:** explicit system-change evidence when Wazuh FIM/Syscheck is collected.

Examples:

```text
file created
file modified
file deleted
permission change
account/configuration change where represented
```

If the final implementation carries FIM inside `archives.jsonl`, this logical input may be represented using `source_type="wazuh_fim"` instead of a separate physical file.

**Availability:** Runtime telemetry.

---

## 6.4 `telemetry/wazuh/rule_metadata.json`

**Purpose:** metadata about the Wazuh rules relevant to the generated run.

Expected information:

```text
Wazuh version
rule_id
description
level
groups
MITRE mapping
default_or_custom
custom rule version
```

For custom Range-created rules, the underlying rule definition should be available as a referenced artifact.

This allows later evaluation of expected vs observed detection without forcing the model itself to use rule IDs as features.

**Availability:** Runtime/evaluation metadata.

---

# 7. Application and authentication telemetry

The prototype review identified that only workstation Wazuh collection was established; collection from web/API/database components was not demonstrated. The full project should close this gap.

## 7.1 `telemetry/applications/application_events.jsonl`

Possible events:

```text
HTTP request
API operation
database access
admin action
application error
authorization failure
service action
```

Expected envelope:

```text
event_id
event_timestamp
scenario_id
run_id
asset_id
service_id
identity_id or username if observable
event_type
action
result
source_ip / destination_ip where relevant
request/resource metadata
raw_ref
```

**Availability:** Runtime telemetry.

---

## 7.2 `telemetry/applications/authentication_events.jsonl`

Purpose: normalized authentication evidence from applications/identity services.

Possible fields:

```text
event_id
timestamp
identity/account
asset/service
authentication_method
success/failure
source
MFA_used
failure_reason if available
```

**Availability:** Runtime telemetry.

---

# 8. Optional network telemetry

## `telemetry/suricata/eve.jsonl`

Suricata is **not assumed to be mandatory until both teams decide to include network telemetry in V1**.

If adopted, the Range can provide Suricata EVE JSON including:

```text
alert
flow
dns
http
tls
fileinfo
```

Typical common fields:

```text
timestamp
flow_id
src_ip
src_port
dest_ip
dest_port
proto
event_type
```

Alert records may additionally contain:

```text
signature_id
signature
category
severity
```

**Availability:** Runtime telemetry when enabled.

No fake “network flow fallback” is promised if Suricata/another proper flow collector is not implemented.

---

# 9. Activity execution outputs

These records describe what the Range controller actually executed. They are essential for training/evaluation, but they are not automatically allowed as runtime ML features.

## 9.1 `activity/activities.jsonl`

Every benign or malicious controller action should produce one record.

Expected fields:

```text
activity_id
scenario_id
run_id
activity_kind: benign | malicious
template_id
controller_timestamp_start
controller_timestamp_end
source_asset_id
target_asset_id
identity_id if applicable
service_id
action
parameters or parameter summary
MITRE tactic if malicious
MITRE technique/sub-technique if malicious
execution_status
observed_outcome if deterministically known
```

**Availability:** Truth/training/evaluation plane, not runtime inference input by default.

---

## 9.2 `activity/attack_catalog_snapshot.json`

Snapshot of the exact attack-template library used for the run.

Expected template metadata:

```text
template_id
template_version
name
attack_family
preconditions
target roles/services
MITRE tactic
MITRE technique/sub-technique
expected telemetry sources
expected detection IDs where defined
```

This fixes the prototype problem where attack catalog files existed but execution remained hardcoded to one SSH attack.

**Availability:** Truth/evaluation metadata.

---

## 9.3 `activity/benign_catalog_snapshot.json`

Snapshot of the benign-template library used for the run.

The full project should include ordinary benign behavior **and hard negatives**, for example:

```text
legitimate SSH administration
repeated but benign login mistakes
authorized network/admin scans
bulk backup/file operations
scheduled scripts
software maintenance
privileged but legitimate administration
normal API/database use
```

**Availability:** Truth/evaluation metadata.

---

# 10. Ground truth outputs

Ground truth must be physically/logically separated from runtime Engine inference.

## 10.1 `truth/activity_truth.jsonl`

Expected fields:

```text
activity_id
scenario_id
run_id
true_class
malicious
attack_family if malicious
MITRE tactic
MITRE technique/sub-technique
source_asset_id
target_asset_id
identity_id if applicable
intended_outcome
execution_result
label_source
review_status
```

Useful label-source values:

```text
generator_fact
observed_verified
human_reviewed
inferred_unverified
```

The model must not receive fields such as `true_class`, `template_id`, `expected_rule_id`, `expected_mitre`, `malicious`, campaign IDs, or generator seed as hidden shortcuts during inference.

---

## 10.2 `truth/campaign_truth.jsonl`

For multi-stage attacks:

```text
campaign_id
activity_id
step_number
parent_activity_id
tactic
technique
source_asset_id
target_asset_id
```

The Engine should build its own sessions/incidents. Campaign truth exists so sessionization can later be evaluated.

---

## 10.3 `truth/detection_expectations.jsonl`

Defines what each reviewed activity template is expected to produce in monitoring.

Expected fields:

```text
activity_id or template_id
expected_sensor
expected_event_family
expected_wazuh_rule_ids
expected_suricata_signatures if applicable
expected_log_sources
expectation_strength
mapping_version
```

This supports the bidirectional IRIS goal: not only “what risk does this mean?” but also “did the SOC observe what it should have observed?”

---

## 10.4 `truth/evidence_links.jsonl`

Purpose: explicit linkage between generated activity and observed telemetry when that link can be established.

Expected fields:

```text
activity_id
event_id
sensor
link_method
link_quality
time_delta_ms
review_status
```

Possible link quality:

```text
exact
strong
probable
uncertain
```

Uncertain links should not silently become training labels.

---

# 11. Time-valid context and history

The prototype review noted that scans/GRC snapshots were generated after activity. The big project should distinguish what was known **before** an incident from what was collected afterward, and it should also support state that changes more than once during a scenario.

Time is part of the data contract because asset importance, software state, vulnerability intelligence, identities, controls, exceptions and monitoring coverage can all change. An assessment that was valid at one point must not automatically be treated as valid forever.

## 11.1 `snapshots/pre_activity_context.json`

Snapshot before activity begins:

```text
asset state
service/component state
control state
baseline risk
vulnerability/scanner context available at that time
sensor readiness
identity state
business criticality/context
```

## 11.2 `snapshots/context_history.jsonl`

**Purpose:** records meaningful state changes during longer or evolving scenarios instead of reducing time to only one before/after pair.

Possible records include:

```text
asset added/removed/reclassified
service or component version changed
software patched or became outdated
new CVE/intelligence became known
identity/privilege/MFA state changed
network exposure changed
business criticality changed
control state changed
policy exception opened/expired
Wazuh/sensor coverage changed
risk assessment updated
```

Expected common fields:

```text
change_id
effective_at
recorded_at
entity_type
entity_id
change_type
previous_state_ref or summary
new_state_ref or summary
evidence_ref
source
```

The goal is not to simulate calendar time for its own sake. It is to preserve enough history for the Engine and later evaluation to know **which context was valid when an event occurred**.

## 11.3 `snapshots/post_activity_context.json`

Post-run state for retrospective analysis.

This prevents future ML experiments from accidentally using information that did not exist when the incident occurred and supports scenarios where earlier assumptions become stale after technical or business changes.

**Availability:** pre-activity and time-valid historical state may be runtime context when it would realistically have been available; post-activity context is evaluation/retrospective context.

---

# 12. Quality and verification outputs

## 12.1 `quality/verification.json`

Expected results:

```text
run_status
deployment_success
activity_execution_success
required_assets_present
Wazuh_ready
expected_sensors_present
telemetry_export_success
scanner_status
missing_artifacts
validation_errors
```

A failed attack remains a malicious attempt if that is what was launched. An undetected attack remains an attack.

---

## 12.2 `quality/sensor_health.json`

Expected:

```text
sensor
status
ready_at
last_event_at
collection_scope
known_gaps
event_count
drop/error indicators where measurable
```

This is particularly important because the Engine should know whether “no alert” means “no detection” or “sensor unavailable”.

---

## 12.3 `quality/data_quality.json`

Expected:

```text
record_counts
label_link_quality counts
missing_field counts
unresolved_asset count
ambiguous_asset count
duplicate/overlap warnings
time synchronization warnings
schema validation result
```

**Availability:** Quality metadata.

---

# 13. Dataset and run manifest

## `manifest.json`

This is the top-level index the Engine should be able to read first.

Expected contents:

```text
scenario_id
run_id
schema_version
generator_version
activity_catalog_version
grc_mapping_version
start_time
end_time
organization_id
enabled_sensors
available_artifacts
artifact hashes
record counts
run_status
quality status
external enrichment snapshot dates
scanner versions
Wazuh version
Suricata version if used
```

It should also report actual activity counts, for example:

```json
{
  "activity_counts": {
    "benign": 840,
    "malicious": 24
  }
}
```

This is better than merely declaring a planned benign/malicious ratio.

---

# 14. Performance/provenance output

## `performance/run_metrics.json`

Not necessarily an Engine ML feature, but included for experiment provenance:

```text
scenario duration
deployment time
activity time
telemetry export time
asset count
container count
CPU summary
RAM summary
storage size
telemetry event counts
host/system load summary
```

Useful for benchmarking dataset-generation scale and excluding corrupted runs.

---

# 15. Data planes: what the Engine may see and when

The Range will distinguish data by **availability plane**, not by prematurely deciding what the Engine model should use as features.

## Runtime telemetry

Observed events that a deployed IRIS system could realistically receive:

```text
Wazuh alerts
Wazuh archives
Wazuh FIM
application logs
authentication logs
optional Suricata events
```

## Runtime context

State that can legitimately exist before/during assessment:

```text
asset inventory
service/component inventory
topology
identity context
business context
controls
baseline risk
scanner/exposure context
CVE enrichment snapshot
pre-activity context snapshot
time-valid context history where available
```

## Truth-only

Range/controller knowledge used for training/evaluation, not runtime inference:

```text
activity true label
attack template identity
malicious/benign truth
campaign ID
expected detections
generator-only execution facts
seed
```

## Evaluation-only

Derived after comparing truth with observations/Engine results:

```text
detected / missed
false positive
detection latency
session/campaign grouping quality
model performance
SOC coverage
```

## Quality metadata

```text
sensor health
run validity
schema validation
missing artifacts
collection gaps
performance/provenance
```

---

# 16. ML-specific requirements

The Range can produce the data needed for ML, but **the final feature set cannot be agreed until the Engine team defines exactly what the model predicts**.

The Engine team should specify one or more concrete targets, for example:

```text
session -> security scenario class
session -> ATT&CK tactic/technique
session -> malicious/benign/unknown
session + context -> relevant control category
telemetry + expected coverage -> detection sufficiency class
```

Different targets require different feature restrictions.

The Range contract therefore guarantees **availability**, while feature eligibility is decided after the ML target is frozen.

The Engine must support an uncertainty outcome rather than forcing every session into a class:

```text
ASSESSED
ABSTAINED / UNKNOWN
FAILED
```

A confidence/score must be tied to the learned/inferred assessment, not to deterministic facts.

---

# 17. Training/evaluation safeguards

The dataset should support the following rules:

```text
No random row/event train-test split across the same scenario/run.
Keep related captures/template families grouped.
Hold out scenarios/runs and, when possible, attack templates or environment families.
Do not expose seed, template IDs, truth labels, campaign IDs or expected rule IDs as shortcuts.
Keep failed attacks as malicious attempts.
Keep undetected attacks as attacks.
Measure benign false positives separately.
Report detection coverage separately from classifier accuracy.
```

Future dataset releases may define train/validation/test assignments separately from the raw generated run package.

---

# 18. GRC grounding requirement

GRC data in the big project must be tied to actual generated enterprise state, not generated independently as random paperwork.

Examples:

```text
MFA disabled
-> authentication control state becomes missing/partial
-> associated access risk context changes

Internet-exposed database
-> network/data protection control weakness
-> associated exposure/risk context changes

Excessive privilege
-> access-control control weakness
-> privilege-abuse risk context changes

Outdated/EOL component
-> vulnerability/patch-management control weakness
-> exposure context changes
```

Each mapping should be versioned and traceable through:

```text
technical_condition
control_id
mapping_rule_id
mapping_version
evidence_ref
```

This lets IRIS explain why a technical incident affects a specific business/control context.

---

# 19. Human review and label quality

Human review should focus on high-value reusable definitions rather than manually labelling every event.

Recommended review targets:

```text
attack template ATT&CK mapping
expected detection mappings
control/GRC mappings
ambiguous evidence links
new or changed template families
sampled dataset-quality audits
```

LLMs may assist with suggestions or drafting, but an LLM-generated label is not automatically ground truth.

Any assisted mapping should preserve:

```text
label_source
review_status
review_version
```

---

# 20. What the Cyber Range is NOT promising as Engine input

Unless later agreed, the Range does not promise:

```text
pre-built Engine session IDs
ML feature vectors
automatic model labels exposed at runtime
automatic remediation execution
a mandatory Suricata deployment
full PCAP capture
live dependence on NVD/EPSS/KEV APIs
Docker-internal implementation identifiers as business asset identity
```

The Engine owns session/incident construction from observable inputs.

---

# 21. What we need from the Engine team in reply

The Engine team should return a short response covering:

1. **Exact ML prediction task(s).**
2. Which proposed Range outputs they require for V1.
3. Which proposed outputs they do not need.
4. Any additional fields/data they require.
5. Whether they require network telemetry/Suricata in V1.
6. Whether Engine V1 consumes replay/batch only, incremental input, or live streaming.
7. The canonical normalized event/session schema they expect internally.
8. Their proposed Engine output schema for:
   - assessment,
   - confidence/abstention,
   - SOC-side findings/recommendations,
   - GRC-side findings/recommendations,
   - evidence references,
   - model/policy versions.
9. Their preferred method for consuming the contract during integration:
   - mounted files,
   - API,
   - or another transport.

After that reply, both sides can freeze a smaller **v1 required subset** of this full output catalogue and define machine-valid JSON Schemas/Pydantic models for it.

---

# 22. Core principle

The final integration should preserve this separation:

```text
Cyber Range
    |
    |-- enterprise + business + GRC context
    |-- security posture + vulnerabilities
    |-- observed telemetry
    |-- generated activity
    |-- independent truth/evaluation data
    v
IRIS Engine
    |
    |-- builds sessions/incidents
    |-- performs ML/rule assessment
    |-- links technical evidence to business/control context
    |-- produces traceable SOC-side and GRC-side outputs
```

The Engine should be able to use the Range output without needing to know how the Range internally generated Docker services, selected templates, or orchestrated the environment.
