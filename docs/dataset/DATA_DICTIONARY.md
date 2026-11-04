# IRIS visible-plane data dictionary (context tier)

Plain-language field reference for everything the model is allowed to read. Field names are taken
verbatim from generated packages. "Bitemporal" files carry `valid_from` / `valid_to` (when the
fact was true in the world) and `recorded_at` (when the org wrote it down) — the gap between those
two is where many flaws hide.

## manifest.visible.json
The only index the model gets. Deliberately excludes seeds, tier and generator version.
- `schema_version`, `package_id`, `scenario_id`, `organization_id`
- `virtual_calendar` — `start`, `end`, `timezone` of the scenario's simulated time span
- `episodes[]` — each `episode_id`, `virtual_start`, `virtual_end` (the checkpoints)
- `available_artifacts[]` — the visible files present
- `enabled_sensors` — empty on the context tier (no live telemetry)

## enterprise/organization.json
- `organization_id`, `name`, `industry`, `size`
- `timezone`, `workweek`, `holidays` — drive the virtual calendar and "office hours"
- `business_units[]`, `business_services[]` — the org structure risks and assets attach to

## enterprise/assets.json  (the asset inventory)
One row per recorded asset.
- `asset_id`, `display_name`, `hostname`, `ip_addresses`
- `role`, `asset_type`, `os_profile`, `zone` — what it is and where it sits
- `service_ids` — services running on it (join to services.json)
- `population_size` — how many real machines this row stands for (a lab of 50 = one row)
- `wazuh_agent_name` — SOC agent identity, if monitored
- `source_of_record`, `recorded_at`, `last_reviewed_at` — provenance and review freshness

## enterprise/topology.json
- `zones` — network zones (internet, dmz, users, servers, …)
- `paths` — allowed flows between zones (the firewall policy, abstracted)
- `dependencies` — service/asset dependency edges
- `internet_facing` — which assets/services are exposed

## enterprise/services.json
- `service_id`, `name`, `service_type`, `asset_id` (host)
- `port`, `protocol`, `exposure` (internal/external), `authentication_required`
- `data_classification` — sensitivity of what it handles
- `dependencies` — other services it needs

## enterprise/identities.json
- `identity_id`, `username`, `identity_type` (human/service), `role`, `department`
- `privilege_level`, `groups`, `assigned_asset_ids`
- `authentication_method`, `mfa_state`, `enabled`

## grc/controls.json  (the control register, bitemporal)
One row per control.
- `control_id`, `control_name`, `control_family`
- `implementation_state` — e.g. implemented / partial / planned / not-implemented (the claim)
- `applies_to_assets`, `applies_to_services` — scope
- `evidence_refs` — what the org cites as proof (a "paper" control cites weak/absent evidence)
- `exception_id` — a policy exception that modifies this control, if any
- `last_assessed_at`, `valid_from`, `valid_to`, `recorded_at`, `mapping_version`

## grc/control_mappings.json
- `control_id` → `mappings` (framework references: NIST SP 800-53, CSF 2.0, ISO 27001 Annex A,
  CIS v8.1), with `mapping_version`.

## grc/risk_register.json  (bitemporal)
- `risk_id`, `risk_scenario`, `risk_level`
- `likelihood`, `impact`, `control_factor`, `raw_risk`, `residual_risk`, `scoring_version`
- `linked_control_ids`, `entity_refs` — controls/assets the risk ties to
- `owner`, `status`, `treatment`, `last_reviewed_at`, `next_review_due`
- `valid_from`, `valid_to`, `recorded_at`
- *Common flaws here:* `risk.orphan_owner` (owner gone), `risk.impact_stale` (asset criticality
  changed, impact never re-scored), `risk.stale`, `risk.missing`.

## grc/business_context.json  (bitemporal, per asset/entity)
- `entity_ref` — the asset/service this describes
- `confidentiality`, `integrity`, `availability`, `criticality` — the CIA + crit rating
- `business_process`, `business_unit`, `business_owner`, `technical_owner`
- `data_classification`, `regulatory_relevance`
- `valid_from`, `valid_to`, `recorded_at`
- *Common flaws here:* `asset.criticality_stale` / `_gross` / `_understated`, `asset.ghost`
  (recorded asset that isn't real), `asset.shadow` (real asset never recorded),
  `asset.process_misattributed`.

## grc/policy_exceptions.json  (bitemporal)
- `exception_id`, `control_id`, `asset_ids`
- `approved_state`, `approver`, `reason`, `compensating_controls`
- `valid_from`, `valid_to`, `valid_until`, `recorded_at`
- *Common flaw:* `exception.expired_in_use` (past `valid_until` but still relied on).

## grc/scale_definition.json
This org's own measurement scales (every org words things differently):
- `risk_scale`, `risk_levels`, `criticality_scale`, `criticality_levels`
- `control_vocabulary` — the words this org uses for control states
- `review_cadence` — how often each register is supposed to be reviewed

## soc/soc_inventory.json  (what the SOC *believes* it collects)
- `wazuh_version`, `ruleset_version`, `loaded_rule_files`
- `agents`, `groups` — the monitored roster
- `log_sources_by_role`, `fim_scope`, `sca_policies`
- `coverage_statements` — claimed coverage (the hidden `soc_gap_ledger` records where this is wrong)
- `archives_retained`, `retention_days`

## snapshots/context_history.jsonl  (append-only, bitemporal change log)
One line per recorded GRC change: which `collection`, which `key`, which field changed, the
`previous` and new value, and when it was recorded. This is the model's main lever for DC3 flaws:
a change recorded here whose dependent record was never updated is a stale-value flaw.

## snapshots/asof/<episode>.json
The registers as they stood at that episode's checkpoint — the exact state to reason over for that
episode's D6 key.
