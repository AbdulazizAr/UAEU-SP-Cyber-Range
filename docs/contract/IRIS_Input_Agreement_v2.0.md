# IRIS Input Agreement v2.0

Nov 2, 2026 · @Abdulrahman

## 1. Purpose and status

This is the frozen v2.0 contract (schema 2.0.0) between the Cyber Range (scenario generator) and the IRIS Engine. It replaces the v1 proposal and is aligned with INPUT Parts 1 to 8.

It answers three questions:

1. What the Range delivers that the Engine may read (the **visible plane**).
2. What the Range keeps from the Engine (the **hidden plane**), and who may use it.
3. What the Engine must return so its decisions can be scored (the **decision contract**).

Transport is not fixed. The same logical records may be delivered as files, replayed JSONL, an API or a stream. The Engine depends on records and fields, not on paths or delivery method.

**Core principle.** The Engine sees only what a real SOC/GRC team would have: telemetry, the organization's *recorded* GRC and inventory (which may be wrong), scanner posture, and as-of context. What actually happened, what is actually true, and what a good decision would have been stay hidden and are used only for training labels and evaluation.

**Engine-owned.** Sessions, incidents, features, models, thresholds and the final assessment. The Range never ships feature vectors or pre-built sessions.

**Freeze rule.** Changes to this contract follow semantic versioning: patch = clarification, minor = additive field, major = breaking. Both teams sign off on minor and major changes.

## 2. Common rules

Every visible record is joinable through stable IDs, carries virtual-time UTC timestamps, and never contains seeds or generator internals.

### 2.1 Identifiers

| ID | Form | Visible to Engine | Notes |
| --- | --- | --- | --- |
| `scenario_id` | `scn-` + 12 hex of SHA-256(recipe) | Yes | Same recipe, same ID. Grouping only, never a feature |
| `episode_id` | `<scenario_id>-epNNN` | Yes | One live observation window |
| `run_id` | equals `episode_id` in episode bundles | Yes | Kept for Engine v0.3.3 importer compatibility |
| `package_id` | `pkg-` + 12 hex of Merkle root | Yes | Integrity reference |
| `event_id` | deterministic hash of source-specific fields | Yes | Unique within the package |
| `organization_id`, `asset_id`, `identity_id`, `service_id`, `component_id`, `control_id`, `risk_id`, `exception_id`, `incident_id`, `finding_id` | generated, opaque | Yes | Recorded-view IDs |
| `group_id`, data tier, lineage, seeds, template/flaw/weakness/campaign IDs | various | **No** | Hidden plane only |

IDs are opaque. They never encode seeds, template names, roles of truth or split membership.

### 2.2 Time

- All timestamps are ISO-8601 UTC in **virtual time** (the scenario's calendar), never real wall-clock time.
- Each organization has a local timezone in `organization.json`; persona schedules follow it.
- Bitemporal GRC records carry `valid_from`, `valid_to` and `recorded_at` (section 11).
- Telemetry may contain deliberate, rare time faults (host timezone mismatch, clock skew, delayed delivery). These are realistic data-quality issues the Engine must tolerate.

### 2.3 Telemetry envelope

Every telemetry record, whatever its source, carries:

```text
event_id          deterministic, unique in package
scenario_id       grouping only
episode_id        grouping only
source_type       wazuh_alert | wazuh_archive | wazuh_fim | wazuh_sca | wazuh_syscollector |
                  wazuh_agent_status | wazuh_manager_health | suricata_eve | suricata_stats |
                  app_event | auth_event
event_timestamp   virtual UTC, when the event happened per the source
ingest_timestamp  virtual UTC, when the collector received it (if known)
asset_ref         resolved asset_id if the agent or IP maps to a recorded asset, else null
raw               original record, unmodified apart from the virtual-time shift
```

`asset_ref` is null when the source host is absent from the recorded inventory. That is a real signal (possible shadow asset), not an error.

## 3. Package layout and delivery

Each scenario ships as two physically separate archives: `visible.tar.zst`, which the Engine mounts read-only, and `hidden.tar.zst`, which the Engine process can never reach.

&#91;embedded content: data planes · who reads what\]

The Engine has no path to the hidden archive; the evaluator compares its decision records with the truth and reference key.

### 3.1 Scenario and episodes

A scenario covers 30 to 180 virtual days. Only short **episodes** (live windows of minutes to a few hours) produce telemetry; time between episodes is unobserved. Slow-changing state (GRC edits, patches, new accounts, exception expiries, CVE publications) is recorded continuously in the change log.

### 3.2 Visible archive (Engine input)

```text
scenario-<scenario_id>/
  manifest.visible.json
  enterprise/   organization.json, assets.json, topology.json, identities.json,
                services.json, components.json
  grc/          business_context.json, controls.json, control_mappings.json,
                risk_register.json, policy_exceptions.json, incident_register.jsonl,
                remediation_tracker.jsonl, scale_definition.json, kpi_report.json (optional)
  posture/      scanner_findings.jsonl, cve_enrichment.jsonl, sbom/<asset_id>.cdx.json
  soc/          soc_inventory.json
  telemetry/
    wazuh/      alerts.jsonl, archives.jsonl (if retained), fim.jsonl, sca.jsonl,
                agents_status.jsonl, manager_health.jsonl, rule_metadata.json,
                syscollector/<episode_id>/<agent_name>.json
    suricata/   eve.jsonl, suricata_stats.jsonl, sensor_inventory.json
    applications/ application_events.jsonl, authentication_events.jsonl
  snapshots/    context_history.jsonl, asof/<episode_id>.json
  quality/      sensor_health_visible.json, coverage_windows.json
  episodes/<episode_id>/   import-ready run bundle (3.4)
```

### 3.3 Hidden archive (never Engine input)

```text
  manifest.json (full), recipe/, activity/, truth/, evaluation_key/, preroll/,
  posture/generated_weaknesses.json, snapshots/post_scenario.json,
  quality/verification.json, quality/data_quality.json, quality/sensor_health_full.json,
  performance/run_metrics.json, captures/ (Gold only)
```

Section 13 describes the hidden contents and who may use them.

### 3.4 Episode bundles

Each episode is exported under `episodes/<episode_id>/` as a self-contained run the Engine v0.3.3 importer can load unchanged, with `run_id = episode_id`. A bundle holds the telemetry for that episode's window, the as-of context snapshot at episode start, and the recorded enterprise and GRC files as of that time. Scenario-level files at the archive root give cross-episode history for multi-episode reasoning.

Boot and settle telemetry (pre-roll) is never in a bundle. It lives in the hidden archive.

### 3.5 Delivery

- v1: files. Archives are verified (per-file SHA-256, Merkle root) and mounted read-only into the Engine sandbox.
- Replay mode: the Engine may consume episode bundles in timestamp order to simulate streaming. The records are identical either way.
- Live streaming is out of scope for v1.

## 4. Visible manifest

`manifest.visible.json` is the first file the Engine reads; it lists what exists and how complete it is, and nothing about how the scenario was generated.

```json
{
  "schema_version": "2.0.0",
  "package_id": "pkg-3f9a1c7e20b4",
  "scenario_id": "scn-8d21f0a6c3e9",
  "organization_id": "ORG-0007",
  "virtual_calendar": {"start": "2025-03-01T00:00:00Z", "end": "2025-06-28T23:59:59Z", "timezone": "Asia/Dubai"},
  "determinism": "recipe and spec exact; telemetry equivalent, not byte-identical",
  "episodes": [
    {"episode_id": "scn-8d21f0a6c3e9-ep001", "virtual_start": "2025-03-03T08:40:00Z", "virtual_end": "2025-03-03T09:25:00Z"}
  ],
  "coverage_windows_ref": "quality/coverage_windows.json",
  "enabled_sensors": ["wazuh", "suricata"],
  "available_artifacts": ["enterprise/assets.json", "telemetry/wazuh/alerts.jsonl"],
  "record_counts": {"telemetry/wazuh/alerts.jsonl": 4120, "telemetry/suricata/eve.jsonl": 18877},
  "tool_versions": {"wazuh": "<pinned>", "suricata": "<pinned>", "trivy": "<pinned>", "trivy_db_date": "2025-06-30"},
  "enrichment_as_of": {"nvd": "date-gated", "kev": "date-gated", "epss": "date-gated or absent"},
  "artifact_hashes": {"enterprise/assets.json": "sha256:..."},
  "merkle_root": "..."
}
```

Rules:

- Fields are not features. `scenario_id`, `episode_id` and `package_id` are for grouping and integrity only.
- Not in the visible manifest: generator version, image digests, seeds, data tier, `group_id`, lineage, real creation date, planned benign/malicious counts. Real activity counts are hidden because they would leak the label distribution.
- Tool versions are visible because a real SOC knows its own tooling.
- Example values are illustrative; JSON Schemas for every file ship with the golden sample (section 19).

## 5. Enterprise context (recorded view)

Everything under `enterprise/` is what the organization has *documented*, so it is usually right but can contain human noise and rare injected flaws; the Engine must treat it as a claim to check against telemetry, not as ground truth.

| File | Purpose | Key fields |
| --- | --- | --- |
| `organization.json` | What the organization is | `organization_id`, industry/profile, size tier (S/M/L), local timezone, business units, business services, workweek and holidays |
| `assets.json` | Recorded technical inventory | `asset_id`, hostname, role, asset type, IPs, zone, OS profile, service IDs, `wazuh_agent_name` if enrolled, `source_of_record` (CMDB, spreadsheet, scanner-discovered), `recorded_at`, `last_reviewed_at` |
| `topology.json` | Network as documented | zones, subnets, asset membership, allowed zone-pair flows, firewall/router relationships, service and identity dependencies, internet-facing paths, `switch_group` metadata |
| `identities.json` | Accounts | `identity_id`, username, type (human/service), role, department, privilege level, groups, assigned assets, enabled, MFA state, auth method |
| `services.json` | Services in telemetry | `service_id`, `asset_id`, service type, port/protocol, dependencies, exposure, auth required, data classification |
| `components.json` | Security-relevant software layer between asset and package | `component_id`, `asset_id`, `service_id`, type, name, version, exposure, linked package refs, finding IDs, control IDs |

Notes:

- **Security maturity is not in `organization.json`.** It is a generator input and a scored estimate (decision D7), so exposing it would leak the answer.
- **Business context lives in `grc/business_context.json`**, not here. There is no `asset_inventory.json`; the inventory is `assets.json` plus `business_context.json`.
- **Asset roles** follow the organization: workstations (employee, admin, developer, remote), web, API/app, database, file, backup, DNS, directory (OpenLDAP + Kerberos in v1), mail, firewall/router, VPN, reverse proxy/WAF, IDS sensor, monitoring, and industry-specific endpoints. Groups of identical workstations are represented by one or two hosts with a `population_size` field.
- **Routers, firewalls and sensors are assets** with IDs, in both inventory and topology.
- **Identities are complete** for every account the organization created. Accounts an attacker creates appear only in telemetry, which is realistic and detectable.
- **Usernames in telemetry always match `identities.json`** for organization-created accounts; both come from one generated source.
- No passwords, keys, tokens or agent secrets appear anywhere in the visible archive.

## 6. GRC context (recorded view)

GRC records are derived from the real enterprise state and then passed through a degradation layer, so they use each organization's own scales and vocabulary and may be stale, incomplete or wrong in ways the Engine is expected to detect.

| File | Purpose | Key fields |
| --- | --- | --- |
| `business_context.json` | Business meaning of assets, services, components | entity ref, business unit, business process, business and technical owner, criticality (in the org's scale), C/I/A requirements, data classification, customer/operational/financial impact category, regulatory relevance |
| `controls.json` | Recorded control posture | `control_id`, name, family, `implementation_state`, applies to assets/services, evidence refs, `exception_id`, `last_assessed_at`, `mapping_version` |
| `control_mappings.json` | Internal control to framework references | `control_id`, mappings (framework, control), `mapping_version`. References, not equivalences |
| `risk_register.json` | The organization's own risk estimates | `risk_id`, linked assets/services, scenario, likelihood, impact, raw risk, control factor, residual risk, level, treatment, owner, linked controls, status, `last_reviewed_at`, `next_review_due`, `scoring_version` |
| `policy_exceptions.json` | Time-bounded exceptions | `exception_id`, `control_id`, asset IDs, reason, approver, approval state, `valid_from`, `valid_until`, compensating controls |
| `incident_register.jsonl` | Incidents the organization recorded | `incident_id`, opened/closed, status, affected assets, summary, root cause, linked risks/controls |
| `remediation_tracker.jsonl` | Findings under remediation | finding ref, owner, severity, SLA, due date, status, last update |
| `scale_definition.json` | What the numbers mean | risk scale (5x5, 3-level, 1-10, qualitative), criticality scale, control vocabulary, framework style, review cadence |
| `kpi_report.json` (optional) | KPIs the organization reports | metric name, value, period, as-of. May be inflated |

Control implementation states: `implemented`, `partial`, `missing`, `not_assessed`, `compensating`, `exception`.

Rules:

- **Read `scale_definition.json` first.** A risk of "4" means nothing without its scale. Translating between scales and vocabularies is part of the Engine's job.
- **Recorded is not real.** Typical flaws include paper controls, wrong criticality, stale risk scores, expired exceptions still in use, shadow or ghost assets, and incidents missing from the register. Some flaws are deliberately undetectable from visible data; the correct response there is to not claim certainty.
- **Baseline risk is the organization's figure.** Factors already inside `residual_risk` must not be applied again downstream.
- Every record is bitemporal and filtered as-of (section 11).
- **GRC grounding.** GRC is derived from the real enterprise state through versioned mapping rules (technical condition to control to risk). The per-condition links are hidden because they reveal weaknesses. The Engine builds its own technical-to-control reasoning from visible evidence, and its control recommendations are scored against those links (section 14).

## 7. Posture and vulnerability inputs

The Engine sees what scanners found, dated vulnerability intelligence, and SBOMs; it never sees the list of weaknesses the generator actually planted.

| File | Purpose | Key fields |
| --- | --- | --- |
| `scanner_findings.jsonl` | What the scanner (Trivy, offline DB) observed | `finding_id`, `asset_id`, scanner and version, timestamp, finding type, CVE, package, installed and fixed version, severity, CVSS, fix available, evidence |
| `cve_enrichment.jsonl` | Vulnerability intelligence, date-gated | `cve_id`, CVSS, severity, EPSS and percentile (only if dated data exists), KEV listed and `kev_date_added`, `published_at`, `modified_at`, source, `as_of` |
| `sbom/<asset_id>.cdx.json` | CycloneDX software inventory per asset | components, versions, purls, dependency graph |

Rules:

- **Presence is not exploitability.** A scanner finding proves a package version is present, nothing more. Whether it was exploitable or exploited is hidden and is what prioritization is scored against.
- **No future leakage.** Every intelligence field is filtered to dates on or before the virtual time it is viewed at. A CVE published after that date does not appear. If dated EPSS is unavailable, EPSS is omitted rather than taken from the future.
- **Configuration weaknesses** (weak credentials, missing MFA, exposed admin panels, weak TLS) are not listed anywhere visible. They must be inferred from evidence: SCA failures, auth patterns, syscollector ports, Suricata flows.
- **No live intelligence at inference.** The Engine never calls NVD, KEV or EPSS during a scenario. A later rescan of the same SBOM against a fresher database is a separate, out-of-scenario analysis.

## 8. SOC self-description and Wazuh telemetry

Wazuh (manager and agents, one pinned version per release) is the host evidence source; coverage, rules and tuning vary per scenario, so the Engine must reason about what the SOC could and could not see.

### 8.1 `soc/soc_inventory.json`

What the SOC believes about itself: agent roster, groups and modules enabled per group, collected log sources per role, ruleset version and loaded files, FIM and SCA scope, retention settings, last ruleset update, and the SOC's own coverage statements. It is the SOC counterpart to the asset inventory; comparing the two is a GRC task. It may overstate real coverage.

### 8.2 Wazuh files

| File | Content | Notes |
| --- | --- | --- |
| `alerts.jsonl` | Alerts with original Wazuh fields: agent, rule (id, level, description, groups, MITRE, compliance tags), decoder, location, `full_log`, `predecoder.timestamp`, src/dst IP and port, user | Envelope from 2.3 added |
| `archives.jsonl` | All collected events, alerting or not | Present only if the organization retains archives; absence is itself a scenario property |
| `fim.jsonl` | File integrity events: created, modified, deleted, permission/owner change, with diff where `report_changes` is on | No who-data (container limit) |
| `sca.jsonl` | Configuration assessment results per asset: policy, check ID, title, result pass/fail/not-applicable | Policies are derived from the control catalog; the strongest control evidence |
| `syscollector/<episode_id>/<agent_name>.json` | Per-agent inventory: OS, network interfaces, packages, listening ports, processes | Hardware scan disabled |
| `agents_status.jsonl` | Roster and status history: name, IP, OS, groups, labels, status, last keepalive | Shows disconnects and gaps |
| `manager_health.jsonl` | Queue pressure, dropped events, restarts, errors | Monitoring reliability evidence |
| `rule_metadata.json` | Rules loaded: id, level, description, groups, MITRE, compliance tags, stock or custom, library version | Evaluation and explanation, not a feature source |

### 8.3 Behaviors the Engine must expect

- **Coverage gaps are deliberate.** Some assets have no agent; some log sources are not collected; some rules are not loaded. "No alert" never means "nothing happened" on an unmonitored asset or outside an episode.
- **Agent labels and roster may disagree with the inventory.** Both are evidence; neither is truth.
- **Rules describe behavior classes**, never the Range's attack templates. Custom rules use ranges 110000 to 115999.
- **Scan intervals are compressed** (FIM, SCA and syscollector every 5 to 15 minutes) so periodic evidence appears inside short episodes. Features must not depend on absolute scan periodicity.
- **Severity mapping** between Wazuh levels and Suricata severity is the Engine's choice; the Range exports both untouched.
- **Real reboots happen** inside episodes (agent stopped/started, first-scan bursts) and are benign look-alikes. Harness startup bursts are removed (pre-roll is hidden).

## 9. Suricata network telemetry

Suricata is mandatory in v1: one detection-only sensor captures every router interface (perimeter and inter-zone), and high-maturity scenarios add taps inside server and data zones.

| File | Content |
| --- | --- |
| `eve.jsonl` | EVE events: `alert`, `flow`, `dns`, `http`, `tls` (SNI, certificate metadata, JA3/JA3S), `ssh`, `fileinfo`, `anomaly` as enabled. Common fields: `timestamp`, `flow_id`, `community_id`, `src_ip`, `src_port`, `dest_ip`, `dest_port`, `proto`, `event_type`. Alerts add `signature_id`, `signature`, `category`, `severity` |
| `suricata_stats.jsonl` | Sensor statistics including kernel drops |
| `sensor_inventory.json` | What the SOC knows about its sensor: placement summary, EVE types enabled, ruleset snapshot date, loaded categories, local rule list |

Rules:

- **One record per real event.** The Range de-duplicates the copies a multi-interface capture produces (by `community_id`, event type, signature and a 1 second window) before export.
- **Wazuh copies share an ID.** When the sensor also ships EVE through Wazuh, each Suricata event gets `eve_event_id` = hash(`flow_id`, `timestamp`, `event_type`, `signature_id`), and the Wazuh copy carries the same value. The Engine must de-duplicate on it.
- **Flows belong to the episode in which they start.** A flow still open at episode end is truncated and flagged.
- **No decryption.** Encrypted content is invisible; the share of TLS traffic varies by scenario.
- **Blind segments exist.** Traffic inside a zone without a tap is not seen. Silence there is not evidence of safety.
- **Rules are date-gated** to the scenario's virtual date and local rules describe behaviors only. Signature IDs are explanation material, not features.
- **No pcaps** are delivered to the Engine. Raw captures exist only in the hidden archive for Gold scenarios.

## 10. Application and authentication telemetry

Application and authentication events are normalized copies of logs from web, API, database, mail, directory and SSH services, and are delivered only for services whose logs the scenario's SOC actually collects.

| File | Events | Key fields |
| --- | --- | --- |
| `application_events.jsonl` | HTTP requests, API operations, database access, admin actions, application errors, authorization failures | envelope + `service_id`, username or `identity_id` if observable, action, resource, result, status code, src/dst IP |
| `authentication_events.jsonl` | Logins, logouts, failures, lockouts, MFA prompts | envelope + account, `service_id`, auth method, success/failure, failure reason, MFA used, source IP |

Rules:

- **Normalized, not invented.** Each record keeps a `raw_ref` to the original log line, which is also visible in Wazuh archives when retained.
- **Coverage follows collection.** If the SOC does not collect database logs in a scenario, there are no database records. That gap is real and listed in `soc_inventory.json`.
- **Standard software logs are the default** (nginx, sshd, PostgreSQL, Postfix, OpenLDAP). Sample applications are used only for specific application-logic roles, so their logs do not dominate.
- **Logs can be messy** on purpose: multi-line errors, partial fields, inconsistent formats.

## 11. Time: as-of rule, history and coverage windows

The Engine may use, at virtual time T, only context recorded on or before T; this one rule prevents future leakage and is enforced by the Range's exports and checked by the evaluator.

### 11.1 Bitemporal records

| Field | Meaning |
| --- | --- |
| `valid_from` / `valid_to` | When the fact was true in the enterprise |
| `recorded_at` | When the organization wrote it down |
| `effective_at` (change log) | When a change took effect |

The gap between `valid_from` and `recorded_at` is the organization's lag and the main source of stale records.

### 11.2 Files

- `snapshots/context_history.jsonl`: append-only change log across the whole scenario. Fields: `change_id`, `effective_at`, `recorded_at`, `entity_type`, `entity_id`, `change_type`, previous and new state (or summary), `evidence_ref`, source. Covers asset add/remove/reclassify, version changes and patches, new CVE intelligence, identity/privilege/MFA changes, exposure changes, criticality changes, control state changes, exceptions opened/expired, sensor coverage changes, risk reviews, incidents recorded.
- `snapshots/asof/<episode_id>.json`: complete recorded context as of each episode start. Replaces v1's `pre_activity_context.json`.
- The v1 `post_activity_context.json` is now `post_scenario.json` in the hidden archive (retrospective only).

### 11.3 Coverage windows

`quality/coverage_windows.json` lists every observed window (the episodes) and every unobserved gap, per sensor. Between episodes no telemetry exists, by design, while the change log keeps running. The Engine must treat gaps as unknown, never as quiet.

### 11.4 Consumption rule

For a decision at time T, the Engine may use telemetry with `event_timestamp` up to T, and context records with `recorded_at` up to T. Episodes are consumed in order. The evaluator replays these rules and flags any decision that cites evidence from after T.

## 12. Visible quality metadata

The Engine gets the sensor health a real SOC would notice, so it can tell "no detection" from "sensor unavailable"; full verification and data-quality reports stay hidden.

`quality/sensor_health_visible.json`, per sensor and episode:

```text
sensor            wazuh_manager | wazuh_agent:<name> | suricata
status            healthy | degraded | down
ready_at, last_event_at
collection_scope  what it was configured to collect
known_gaps        disconnect windows, buffer overflows, kernel drops, delayed delivery
event_count
```

It reports only what monitoring itself would show (agent disconnects, manager drop counters, Suricata drop stats). Faults the SOC would not notice, such as a silently stale allowlist or a log source that quietly stopped, are hidden and only appear through their consequences.

Every visible package has passed the Range's release gates (health, time consistency, schema, cross-references, forbidden-content scan). Failed scenarios are discarded, never delivered.

## 13. Hidden planes (never Engine input)

The hidden archive holds what happened, what was true, and what a good decision would have been; the Engine process has no path or credential to it, and only the trainer's label builder and the evaluator may read it.

| Plane | Content | Used by |
| --- | --- | --- |
| H1 World truth | Recipe, resolved spec and timeline; real topology and versions; planted weaknesses with verification results; activity log (benign and malicious, template, actor, target, executed time, status); campaigns; evidence links (activity to telemetry, quality exact/strong/probable/uncertain) | Label builder, evaluator |
| H2 Outcome truth | Per activity: verified result (success/partial/failed/blocked), reach, causal weakness, enabling control, detection per sensor and latency, containment, persistence, impact score; incidents; benign alarms; GRC response lag | Label builder, evaluator |
| H3 GRC and SOC reality | True criticality, control effectiveness and risk; GRC flaw ledger; diff audit; real SOC profile, blind spots, SOC flaw ledger; true sensor placement; reality metrics (maturity, posture, vulnerability) | Label builder, evaluator |
| H4 Reference key | Checkpoints; oracle reference decisions in hindsight and evidence-limited views; acceptable alternatives; harm rules; perturbation pairs; counterfactual outcomes (sample) | Evaluator only |
| H5 Evaluation results | Scored decisions, verdicts, reports (stored outside packages) | Evaluator, teams |

Access rules:

- **Engine:** visible archive only, in a sandbox. A no-peek test runs it with the hidden archive absent and requires identical output.
- **Trainer:** visible features plus labels from the label builder (H1 to H3, oracle tiers T1 and T2 only). The builder outputs targets and never copies hidden fields into features.
- **Evaluator:** everything, including H4. T3 references (governance judgment) are evaluation-only, never training labels.
- **Split membership** reaches the trainer through the release's `split_manifest.json`, never through the package.

## 14. Engine output contract: decisions D1 to D7

The Engine is scored on seven decision types at defined checkpoints, and every decision must carry its confidence, abstention flag and the event IDs it relies on.

### 14.1 Decision types

| Type | Decision | Payload | Scored against |
| --- | --- | --- | --- |
| D1 | Session assessment | class, malicious/benign/unknown, ATT&CK tactic/technique | Activity truth |
| D2 | Priority | priority level for a session or incident | Oracle band from outcome impact and true criticality |
| D3 | Risk movement | risk ID, direction, magnitude in the org's scale | Change in real residual risk |
| D4 | Control recommendation | up to 3 controls, ranked, with rationale | Causal, relevant, irrelevant and harmful control sets |
| D5 | Governance action | open incident, escalate, review control, review exception, update register, and similar | Preferred, acceptable and forbidden sets |
| D6 | GRC flaw finding | record ref, flaw type, explanation | GRC flaw ledger |
| D7 | Metric estimates | maturity tier and score, posture and vulnerability metrics, GRC reliability | Reality metrics |

Checkpoints: every closed session (D1 to D4), end of each episode (D3, D5, D6), after each campaign stage, and end of scenario (D7). The Engine owns session construction; the evaluator aligns Engine sessions to checkpoints by time and evidence.

### 14.2 Decision record

```json
{
  "decision_id": "dec-000123",
  "scenario_id": "scn-8d21f0a6c3e9",
  "episode_id": "scn-8d21f0a6c3e9-ep006",
  "as_of": "2025-04-10T11:32:00Z",
  "type": "D2",
  "subject_ref": {"kind": "asset", "id": "AST-DB-001"},
  "payload": {"priority": "CRITICAL"},
  "status": "ASSESSED",
  "confidence": 0.82,
  "rationale": "short text",
  "evidence_event_ids": ["evt-...", "evt-..."],
  "context_refs": ["risk:R-DB-01", "control:CTRL-IAM-002"],
  "engine_version": "...",
  "model_version": "...",
  "policy_version": "..."
}
```

`status` is `ASSESSED`, `ABSTAINED` or `FAILED`. Confidence attaches to learned or inferred assessments, never to deterministic facts.

### 14.3 Verdicts

Each decision is scored **Correct**, **Acceptable**, **Incorrect** or **Harmful**, plus **FairMiss** (the deciding fact was not observable by T, so no penalty) and **ValidAbstain** (credited). Harmful decisions are counted and reported separately, never averaged into accuracy. Examples: classifying a successful attack as benign with confidence of 0.8 or more, lowering risk after a real breach, recommending removal of an effective control, treating an unmonitored asset as safe, citing evidence that does not exist.

Cited `evidence_event_ids` must exist, be visible by `as_of`, and relate to the subject. Invalid citations are themselves a harm rule.

## 15. Feature eligibility and leakage rules

Any visible field may be read, but grouping IDs, rule and signature IDs, and scan periodicity are not valid model features, and hidden fields must never reach a feature vector.

### 15.1 Forbidden as features

```text
scenario_id, episode_id, run_id, package_id, event_id, organization_id    grouping and integrity only
rule.id, signature_id, rule_metadata entries                          evidence and explanation only
absolute scan periodicity, episode boundary position                  harness artifacts
anything from the hidden archive: true_class, malicious, template_id, campaign_id,
  attack_family, expected rule IDs, flaw_id, weakness_id, soc_profile, blind_spot,
  episode_index, scenario_index, tier, group_id, seeds, oracle_*, reference_*, impact_*
```

Rule and signature IDs may appear in rationale and citations. They are not features because a model can learn the Range's rule library instead of the behavior.

### 15.2 Range-side safeguards

- The visible archive is scanned before release for seeds, template/flaw/weakness/campaign names and IDs, generator banners, real current dates and 1970 timestamps.
- Fingerprint probes trained on visible data must not predict generator internals (template, episode index, data tier, generator version) above chance; any that do block the release.
- Tool banners, user agents, timing and payloads are randomized per attacker profile so tooling does not label itself.

### 15.3 Engine-side safeguards

- The forbidden list above is enforced in the Engine's feature builder (extends the existing `features.py` guard).
- The Engine runs sandboxed with only the visible archive mounted, and passes the no-peek test.

## 16. Training, evaluation and release safeguards

Splits are by enterprise family (`group_id`), pre-registered per release, and all validation and test sets contain Gold scenarios only.

| Set | Share of groups | Content |
| --- | --- | --- |
| Train | about 60% | Gold, Silver and Bulk |
| Validation | about 10% | Gold only |
| Test-IID (lock-box) | about 10% | Gold only; run once per release candidate |
| Out-of-distribution | about 20% in total | Held-out topology archetype, industry, attack family and GRC style, each its own set |
| Long-horizon | subset | Longest, multi-campaign scenarios |

Rules:

- **Never split within a group.** All episodes, alterations and counterfactual twins of one enterprise stay in one set. No event-level or row-level random splits.
- **Each group is in exactly one out-of-distribution set**, chosen by precedence: topology, then industry, then attack family, then GRC style. Held-out attack families and GRC styles never appear in in-distribution groups.
- **Small sets are flagged.** An out-of-distribution set with fewer than 15 Gold groups is reported as indicative.
- **Data tiers.** Gold = full live stack. Silver = real-stack rerun of a Gold enterprise with altered seeds (training only). Bulk = synthesized from Gold/Silver recordings or GRC-only (training only, capped, drift-tested). Results are always reported per tier.
- **Reported separately, always:** benign false-positive rate, detection coverage vs classifier accuracy, harmful decision counts, out-of-distribution results even when worse, and slices by decision type, maturity, industry, difficulty, flaw level and blind-spot involvement.
- **Baselines the Engine must beat:** always-benign, always-high, majority class, the existing rule baseline, and a context-blind variant.
- **Failed attacks remain malicious; undetected attacks remain attacks.**
- **Oracle frozen first.** Oracle and rubric versions are hashed before any lock-box run. Nothing is tuned after seeing lock-box results.
- **Human review is for reusable definitions**, not per-event labels: template ATT&CK mappings, expected detections, control mappings, oracle rules, and a sampled audit of about 150 checkpoints by at least two reviewers. LLM suggestions are drafts, never ground truth; reviewed items carry `label_source`, `review_status`, `review_version`.

## 17. Generator guarantees and known limitations

The Range guarantees internal consistency of every delivered package and states its realism limits openly.

### 17.1 Guarantees

- Every telemetry source host maps to exactly one real asset and one IP per episode. If that asset is in the recorded inventory, `asset_ref` resolves; if not, the gap is a deliberate, ledgered flaw.
- Organization-created usernames in telemetry exist in `identities.json`.
- Every recorded-vs-reality difference is either bounded baseline noise or a ledgered flaw (automatic diff audit).
- Every attack the Range claims succeeded was verified by a post-condition check.
- All timestamps pass the time-consistency validator: inside their episode, consistent across sources, no real dates.
- Archives are immutable. Corrections ship as new packages with `supersedes` (hidden manifest).
- Replay is byte-exact. Regenerating from the recipe gives the same spec, plan, profile and timeline, with telemetry that is equivalent but not byte-identical.

### 17.2 Limitations

| Limitation | Effect for the Engine |
| --- | --- |
| Linux containers only; no Windows hosts or event channel | Windows concepts appear as Linux equivalents (OpenLDAP + Kerberos for directory) |
| Shared host kernel | No kernel CVEs; no Wazuh who-data |
| Episodes, not continuous time | Telemetry exists only inside coverage windows |
| Compressed scan intervals | Scan-based evidence is denser than in production |
| No TLS decryption | Encrypted content invisible to Suricata |
| IPv4 only; no VLANs or tunnels | Simplified network layer |
| Synthetic traffic volumes and plausible, not fitted, distributions | Realism is "plausible enterprise-like", not a replica of any real organization |
| Long outages occur only between episodes | No live disconnect alert for them; visible through roster gaps |

## 18. What is not promised

The Range does not deliver:

- Engine sessions, incidents, feature vectors or labels in the visible archive.
- Planted weakness lists, activity logs or attack catalogs to the Engine. These moved to the hidden archive in v2.
- Security maturity as an input field (it is a D7 target).
- Real activity counts or benign/malicious ratios.
- Pcaps, Wazuh native vulnerability detection, or Wazuh indexer/dashboard data in generation mode.
- Live NVD, KEV or EPSS access during a scenario.
- Docker-internal identifiers as asset identity.
- Automatic remediation execution inside the Range in response to Engine output. Counterfactual replays of recommended controls are run by the evaluator on a sample.
- Live streaming delivery in v1.

## 19. Integration plan and first deliverable

Integration starts with one small golden sample package, which unblocks the Engine importer and validates this contract end to end before any scale-up.

**Golden sample content:** 7 to 10 assets, 2 to 3 short episodes, one attack campaign spanning two episodes, one benign look-alike, two GRC flaws at different levels, one SOC blind spot, one time fault. All visible and hidden files present.

**Steps:**

1. Range ships the golden sample plus JSON Schemas (Pydantic models generated from them) for every visible file and for the decision record.
2. Engine imports one episode bundle unchanged with the v0.3.3 importer and reports any friction.
3. Engine runs on the full scenario and emits decision records (section 14) for at least D1, D2 and D4.
4. Evaluator scores them and runs the no-peek test.
5. Both teams fix issues as patch or minor contract versions, then the Range starts batch generation.

**Acceptance:** schema validation passes on 100% of visible files; the episode import needs no Engine code change; the no-peek test gives identical output; at least one decision of each attempted type is scored without manual intervention.

**Open items carried into integration (not blockers):** the Engine's Wazuh-to-Suricata severity mapping, session window validation on real data, and Engine handling of null `asset_ref`.

## 20. Changes from v1

v2.0 is a breaking change: the unit became a multi-episode scenario, GRC became a recorded (possibly wrong) view, and generator knowledge moved out of the Engine's reach.

| Area | v1 | v2.0 |
| --- | --- | --- |
| Unit | One run | Scenario of 30 to 180 virtual days with episodes; each episode is an importable run bundle |
| Planes | One package, planes by convention | Two archives, visible and hidden, physically separate |
| `enterprise/`, `grc/` | Authoritative | Recorded view with noise and rare flaws |
| `organization.json` | Included security maturity | Maturity removed (D7 target); timezone, workweek added |
| `activity/` | In the package | Hidden |
| `posture/generated_weaknesses.json` | Runtime context | Hidden |
| Suricata | Optional | Mandatory, with de-duplication rules |
| New visible files | none | `soc_inventory.json`, `sca.jsonl`, `syscollector/`, `agents_status.jsonl`, `manager_health.jsonl`, `suricata_stats.jsonl`, `sensor_inventory.json`, `incident_register.jsonl`, `remediation_tracker.jsonl`, `scale_definition.json`, `kpi_report.json`, `coverage_windows.json`, `asof/`, `episodes/` |
| Snapshots | `pre_activity_context.json`, `post_activity_context.json` | `asof/<episode_id>.json` (visible), `post_scenario.json` (hidden) |
| Quality | `verification`, `sensor_health`, `data_quality` visible | Only `sensor_health_visible.json` and `coverage_windows.json` visible |
| Manifest | Generator version, activity counts visible | Visible subset only; generator data hidden |
| Time | Real timestamps, before/after snapshots | Virtual time, bitemporal records, as-of rule |
| Intelligence | Snapshot at real date | Date-gated to virtual time |
| ML targets | Asked of the Engine team | Fixed as decision types D1 to D7 with a scoring contract |
| Evaluation | Not specified | Oracle reference key, verdicts, harm rules, fair-miss, grouped and out-of-distribution splits |
