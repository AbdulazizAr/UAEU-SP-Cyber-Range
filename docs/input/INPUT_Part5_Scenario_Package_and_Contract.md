# INPUT Part 5: Scenario Package, Versioning, Replication and Data Contract

Status: FINAL DRAFT. Tags: [PROTO] already in prototype/contract, [NEW] proposed, [MEASURE] verify with numbers, [VERIFY] confirm detail.

Goal (your Seniorita line): a scenario package that is **compressed, maintained, stored, and can be replicated or altered given the correct seeds** for every pseudo-random algorithm. This part defines the artifact, how it is named, versioned, stored, verified, replayed, regenerated and altered, and reconciles the older PF Dataset Contract with everything added in Parts 1 to 4 and 6 to 8.

---

## 1. Three different things people call "replication"

| Operation | What it does | Result |
|---|---|---|
| **Replay (read)** | Load the stored package, verify hashes | Byte-exact original data |
| **Regenerate** | Rebuild from the recipe and run again | **Equivalent** scenario: same spec, plan, profile, timeline; telemetry equivalent but not byte-identical (Part 3: Wazuh/Suricata timing and interleaving vary) |
| **Alter** | Change one seed module or an override, then regenerate | A related new scenario with recorded lineage (section 8) |

The package states this distinction in its manifest (`determinism` field), so nobody expects byte-identical reruns.

---

## 2. Two artifacts per scenario

```text
RECIPE (tiny, KB)              everything needed to rebuild: master seed, sub-seeds, versions, overrides,
                               resolved Scenario Spec, master timeline
PACKAGE (recorded data, MB)    what was actually produced: telemetry, recorded GRC, hidden planes, quality, hashes
```
Decision: store both **the seed and the fully resolved spec** in the recipe (Part 1). Replication must not depend on old generator code still sampling identically.

Additional lock: `generator_lock.json` records the generator container image digest, so the exact code that produced the scenario can be re-run later.

---

## 3. Identifiers

```text
scenario_id   = "scn-" + first 12 hex of SHA-256(canonical recipe JSON)          content-derived, same recipe = same id
group_id      = "grp-" + hash(seed_org, seed_topology, seed_services, generator major)   the enterprise family (for ML splits)
episode_id    = scenario_id + "-ep" + 3-digit index
run_id        = unique per execution attempt (retries produce new run_ids; accepted run recorded in manifest)
package_id    = "pkg-" + Merkle root (first 12 hex) of all package files
event_id      = deterministic per source (sha1 of source-specific fields), unique within package   [PROTO event_id]
```
Rules: IDs never contain seeds or template names (leakage). `scenario_id` hashing the recipe means altering anything creates a new ID automatically.

---

## 4. Versioning

Every axis that can change output is versioned and recorded in the manifest:

| Axis | Examples |
|---|---|
| Contract | `schema_version` (this document = 2.0) |
| Generator | `generator_version`, generator image digest |
| Catalogs | service recipes, weakness modules, attack templates, benign templates, persona models, flaw modules, rule library, SCA control policy set, risk templates, control catalog, topology archetypes |
| Formulas | GRC formulas, impact formula, oracle/rubric, maturity and vulnerability metric formulas (Part 7) |
| Tools | Wazuh, Suricata, ET ruleset snapshot date, Trivy + DB date, libfaketime, Docker, base OS snapshot dates |
| Images | digest of every container image used |
| Enrichment | NVD, KEV, EPSS snapshot dates (Part 2, B8) |

Compatibility policy:
- semantic versioning for schema: patch = no format change, minor = additive fields, **major = breaking** (this contract is 2.0 because of the visible/hidden split and episodes).
- Packages are **immutable**. A correction creates a new package with `supersedes: <old package_id>`; the old one remains.
- Migration scripts for visible-plane schema upgrades; hidden planes may be migrated or regenerated.
- A package whose generator image or tools cannot be reproduced is still valid for **replay**; only regenerate is limited.

---

## 5. Package layout and plane assignment

Two archives with the same internal root, plus a recipe. `V` = visible to the Engine, `H` = hidden. This table is the authoritative visible/hidden assignment.

```text
scenario-<scenario_id>/
  manifest.json                       V  (visible subset in manifest.visible.json; full manifest in hidden)
  enterprise/
    organization.json                 V  recorded view
    assets.json                       V  recorded technical inventory (+ Wazuh agent identity)
    topology.json                     V  as documented by the organization
    identities.json                   V  no secrets
    services.json, components.json    V
  grc/
    business_context.json             V  recorded: criticality, owners, data class
    controls.json                     V  recorded states
    control_mappings.json             V
    risk_register.json                V  recorded
    policy_exceptions.json            V
    incident_register.jsonl           V  recorded
    remediation_tracker.jsonl         V
    scale_definition.json             V
    kpi_report.json                   V  optional, recorded KPIs (Part 7)
  posture/
    scanner_findings.jsonl            V
    cve_enrichment.jsonl              V  date-gated to virtual time (Part 2, B8)
    sbom/                             V
    generated_weaknesses.json         H  (true weakness ledger)
  soc/
    soc_inventory.json                V  what the SOC believes about itself
  telemetry/
    wazuh/alerts.jsonl, fim.jsonl, sca.jsonl, agents_status.jsonl, manager_health.jsonl, rule_metadata.json   V
    wazuh/archives.jsonl              V  only if profile retained_by_org
    wazuh/syscollector/               V
    applications/*.jsonl              V
    suricata/eve.jsonl, suricata_stats.jsonl, sensor_inventory.json   V
  snapshots/
    context_history.jsonl             V  append-only change log (as recorded)
    asof/ep-NNN.json                  V  as-of snapshot at each episode start
    post_scenario.json                H  retrospective
  quality/
    sensor_health_visible.json        V  what the SOC would notice (agent status, drops)
    coverage_windows.json             V  observed windows vs gaps
    verification.json                 H
    data_quality.json                 H  full
    sensor_health_full.json           H
  episodes/ep-NNN/                    V  import-ready slice per episode (section 9)
  recipe/                             H  recipe.json, resolved_spec.json, timeline.jsonl, overrides.json, generator_lock.json
  activity/                           H  activities.jsonl, catalog snapshots   (template IDs live here)
  truth/                              H  (Part 4, section 11 and Parts 2, 3, 7)
  evaluation_key/                     H  (Part 4)
  preroll/                            H  boot/settle telemetry, per episode
  performance/run_metrics.json        H  ops metadata: timings, counts, compression ratio, resource use
  captures/                           H  optional raw pcaps (Part 6) for Gold
```

Changes vs the old PF contract: `activity/` moved to hidden (it contains template IDs, the contract itself marks a runtime feature restriction); `truth/` as before but expanded; `sensor_health` split into visible and full; `enterprise/` and `grc/` are explicitly the **recorded** views.

Naming reconciliation: Part 2 listed a combined "asset inventory". In files it is `enterprise/assets.json` (technical) + `grc/business_context.json` (business). The Engine loads both; no separate `asset_inventory.json` exists.

---

## 6. Manifest

Full manifest (hidden), visible subset is marked `*`:

```json
{
 "schema_version": "2.0.0",                       *
 "package_id": "pkg-...", "scenario_id": "scn-...", "group_id": "grp-...",   * (group_id hidden-only? see note)
 "supersedes": null,
 "created_at_real": "2026-..Z",                   (hidden: real creation date; never in visible plane)
 "virtual_calendar": {"start":"2026-03-01","end":"2026-06-28","timezone":"Asia/Dubai"},  *
 "tier": "gold|silver|bulk",                      (hidden)
 "determinism": "recipe+spec exact; telemetry equivalent not byte-identical",   *
 "versions": {"generator":"...","generator_image_digest":"...","catalogs":{...},"formulas":{...},
              "tools":{"wazuh":"...","suricata":"...","et_ruleset_snapshot":"...","trivy":"...","trivy_db":"...","libfaketime":"..."},
              "enrichment_snapshots":{"nvd":"...","kev":"...","epss":"..."}},
 "episodes": [{"episode_id":"...","virtual_start":"...","virtual_end":"...","purpose":"...","status":"accepted","records":{...}}],
 "coverage_windows_ref": "quality/coverage_windows.json",   *
 "enabled_sensors": ["wazuh","suricata"],         *
 "available_artifacts": [...],                    *
 "record_counts": {...},                          *
 "run_status": "PASS|FAIL", "quality_status": "...",   (flags honest as in prototype: e.g. training_corpus_ready false until gates pass)
 "artifact_hashes": {"path": "sha256", "...": "..."},
 "merkle_root": "...",
 "visible_package": {"file":"visible.tar.zst","sha256":"..."},
 "hidden_package":  {"file":"hidden.tar.zst","sha256":"..."},
 "metrics": {"compression_ratio": ..., "wall_hours": ..., "virtual_days": ...},   (hidden)
 "lineage": {"parent_scenario_id": null, "alteration": null}   (hidden)
}
```
Note: `group_id` and `tier` and `lineage` are hidden (they would reveal split structure and generator internals); the Engine trainer receives group assignment through the dataset release split file (Part 8), not through the visible package.

---

## 7. Storage format and layout

**Format**
- Records stay **JSONL** (compatibility with the Engine importer, human-inspectable) [PROTO]. Large per-event telemetry may additionally be written as Parquet in derived/analysis copies, not as the contract format.
- Each plane is bundled as `tar` and compressed with **zstd** (high ratio, fast decode). Per-file SHA-256 in the manifest; package ID is the Merkle root. JSON event streams typically compress very well [MEASURE actual ratio on our data].
- Raw pcaps (Part 6) only for Gold, stored separately (`captures/`), because of size.
- Container images are **not stored**; digests + SBOM only.

**Estimated size per scenario** (rough planning only, [MEASURE]): a scenario with ~15 assets and ~8 episodes of 20-45 observed minutes produces on the order of tens to a few hundred MB of raw JSONL and a fraction of that compressed; pcaps could dominate if kept. Numbers replace these after the golden sample (section 11).

**Store layout**
```text
store/
  scenarios/<scenario_id>/
      recipe.json                 (copy, small, for catalog queries)
      visible.tar.zst, hidden.tar.zst, manifest.json
      captures/ (optional)
  releases/<release_id>/
      dataset_release.json        scenario list, split manifest, versions, hash, gate results   [PROTO: datasets/ releases]
      split_manifest.json
      release_report.json
  catalog.db                      queryable index (SQLite): scenario_id, group_id, tier, industry, size, maturity,
                                  topology family, attack families, flaw counts/levels, episodes, virtual span, status,
                                  split, versions, supersedes
  staging/                        raw run dirs for N days after packaging, then deleted
```
`catalog.db` is rebuildable from manifests (it is an index, not a source of truth).

Retention: packages immutable; staging purged after the package passes integrity re-check; hidden packages access-controlled (filesystem permissions at minimum, optional encryption at rest); no secrets inside any package (Part 1: secrets only in private runtime files, and not exported).

---

## 8. Operations

### 8.1 Replay / verify
`verify`: recompute hashes, check Merkle root, validate schema (visible and hidden), validate cross-references (every link resolves, event IDs unique), validate time consistency (Part 2, B7), validate visible-plane forbidden-content scan (Part 4, section 10).

### 8.2 Regenerate
`regenerate <recipe>`: rebuild from the resolved spec using the pinned generator image; run; produce a new package; run an **equivalence report**:
```text
exact:       resolved_spec hash, topology, profile, timeline, attack plan, GRC reality and flaw ledger
approximate: event counts per source within tolerance, detection outcomes vs expected, session counts, class distribution
not compared: byte content, event order within the same second, internal IDs
```

### 8.3 Alter
Allowed alterations (each produces a **new** recipe, new `scenario_id`, with lineage):

| Alteration | Effect | Group handling |
|---|---|---|
| change `seed_attack` | same enterprise, different attacks/timing | same `group_id` |
| change `seed_traffic` | same enterprise, different background | same `group_id` |
| change `seed_grc` | same enterprise, different GRC flaws/noise | same `group_id` |
| change `seed_monitoring` | different SOC coverage | same `group_id` |
| override fields (maturity, add/remove weakness, attacker profile, horizon, episode count) | targeted variation (including counterfactual control-applied runs, Part 4, section 8) | same `group_id` |
| change `seed_org` / `seed_topology` / `seed_services` | **a different enterprise** | new `group_id` |

`lineage`: `{parent_scenario_id, alteration: {type, field, old, new}}`. Lineage forms a tree; the dataset catalog can show it.

**ML rule:** every scenario sharing a `group_id` goes to the same train/val/test split (Part 8). Altered scenarios are not independent samples.

### 8.4 Diff
`diff A B`: compares recipes, specs, profiles, flaw ledgers, outcome summaries, to explain what changed.

---

## 9. Import compatibility with Engine v0.3.3

The Engine's importer wants "bundle folder layout" and "one complete sample run" [PROTO: Engine integration status]. Its unit is a **run**. Mapping:

- Each **episode** is exported as an import-ready run bundle under `episodes/ep-NNN/` (telemetry slice for the observe window, as-of context snapshot, topology/identity/GRC as-of, `manifest` slice). The Engine can import it as one run with no changes, using `run_id = episode_id`.
- Scenario-level files at the root provide cross-episode context for later Engine versions (multi-episode reasoning, GRC history).
- **Grouping for ML** is by `group_id` (from the release split file), not by `run_id`, so multiple episodes of one scenario never leak across splits.
- Pre-roll data is not in the episode slice (Part 3, 6.2).

Open Engine-side items already known [PROTO]: identity/account name matching (identities must come from the same generated source as telemetry usernames), session window validation, Suricata severity mapping (provisional), asset IP per asset. The generator guarantees: one IP per asset, all assets in topology, accounts consistent between `identities.json` and telemetry.

---

## 10. Contract reconciliation: what is new, changed, removed

| Area | Change |
|---|---|
| New visible | `soc/soc_inventory.json`, `telemetry/wazuh/{sca,agents_status,manager_health}.jsonl`, `syscollector/`, `suricata_stats.jsonl`, `sensor_inventory.json`, `grc/{incident_register,remediation_tracker}`, `grc/scale_definition.json`, `grc/kpi_report.json`, `snapshots/asof/`, `quality/coverage_windows.json`, `episodes/` |
| New hidden | `recipe/`, outcome/GRC/SOC truth files, `evaluation_key/`, `preroll/`, flaw ledgers, metrics truth, optional captures |
| Moved to hidden | `activity/` (template/catalog snapshots), parts of `quality/`, `performance/` |
| Changed semantics | `enterprise/` and `grc/` are **recorded** views (may contain baseline noise and rare flaws); reality lives in `truth/` |
| Time | All timestamps ISO-8601 UTC in virtual time; `episode_id` on every event envelope; pre-roll separated |
| Archives | Present only if profile `retained_by_org`; otherwise hidden for evaluation of missed detections |
| Keys | Wazuh agent keys, passwords, private keys never exported anywhere [PROTO] |
| Field restrictions | Forbidden runtime-feature list extended (Part 4, section 10) |
| Versioning | `schema_version` 2.0.0; breaking vs PF contract v1 |

Time-valid context principle unchanged [PROTO]: Engine only gets as-of data (`recorded_at <= T`).

---

## 11. First deliverable: the golden sample package

Before scale, produce one **small complete scenario** to unblock the Engine importer and validate the contract end to end:
- ~7-10 assets, 2-3 episodes (short), one attack campaign across two episodes, one benign look-alike, one GRC flaw of each of two levels, one SOC blind spot, one time fault.
- All visible and hidden files present, validated, packaged, replayed, regenerated, one alteration made.
- Used to measure real sizes, boot times and compression, and to replace the estimates in Parts 1-3 and 5.

---

## 12. Decisions (final)

1. Recipe + resolved spec + generator image digest stored with every package.
2. Content-derived `scenario_id`; `group_id` for splits; IDs never carry seeds/templates.
3. Immutable packages with `supersedes` for corrections.
4. Visible/hidden physically separate archives; assignment table in section 5 is authoritative.
5. JSONL + tar + zstd, per-file SHA-256, Merkle root; SQLite catalog as rebuildable index.
6. Replay = exact, regenerate = equivalent (with equivalence report), alter = new scenario with lineage; altered scenarios inherit `group_id` unless the enterprise itself changes.
7. Episodes exported as Engine-importable run bundles; ML grouping by `group_id`.
8. Schema 2.0.0 with the reconciliation in section 10.
9. Golden sample package is the first build target.

## 13. Tests before trust

| Test | Pass criterion | Fallback |
|---|---|---|
| Round trip: package, verify, replay | Hash and schema pass on 100% of 50 packages | Fix packager |
| Regenerate equivalence on 20 scenarios | Exact items identical; approximate items within tolerance | Tighten determinism in generator, or relax tolerances with justification |
| Alteration lineage and group inheritance | Correct `group_id`/lineage on 30 alterations | Fix alteration engine |
| No-peek: visible archive contains no forbidden content | Scan clean | Fix assignment table |
| Engine import of an episode bundle | Engine imports and processes without changes | Adapt bundle layout (small) |
| Size/compression measurement | Real numbers recorded | Adjust retention (e.g. drop captures) |
| Old-generator replay | Package from generator vN readable by tooling vN+1 | Add migration |

Next: Part 6 (Suricata).
