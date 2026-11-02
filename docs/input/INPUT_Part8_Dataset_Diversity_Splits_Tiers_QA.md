# INPUT Part 8: Scenario Diversity and Splits, Gold/Bulk Tiers, Generator QA and Leakage Audit

Status: FINAL DRAFT. Tags: [PROTO] already in prototype, [NEW] proposed, [MEASURE] verify with numbers. All numeric sizes below are **planning models**, not measurements; they are replaced by measured values after the golden sample (Part 5, section 11).

---

# PART A: DIVERSITY PLAN

## A1. Factor space (what varies)

| Factor | Levels (v1 target) | Source |
|---|---|---|
| Industry/profile | 6-8 (retail, hospital, finance-lite, university, SaaS/dev-heavy, manufacturing-lite, public-sector-lite, logistics-lite) [PROTO: retail, hospital] | Part 1 |
| Size tier | 3 (S/M/L) | Part 1 |
| Security maturity (input) | 3 | Parts 1-3 |
| Topology archetype | at least 6 (compact three-zone, segmented five-zone [PROTO], flat small office, DMZ-heavy web, dev/CI-heavy, medical/OT-lite zone) | Part 1 |
| OS/service mix | recipe combinations from the service catalog | Part 1 |
| SOC profile | coverage, rules, tuning, retention, faults | Part 3 |
| Sensor profile | placement, EVE types, ruleset tuning, TLS share | Part 6 |
| GRC style | risk scale, control vocabulary, criticality scale, cadence | Part 2 |
| Traffic workload | light/standard/busy [PROTO], persona mix, noise level | Part 1 |
| Time horizon and episode plan | 30-180 virtual days, 6-20 episodes | Part 2 |
| Attack families | at least 9 (below) | Part 1 |
| Attacker profile | origin x skill x stealth x goal | Part 1 |
| Benign hard negatives | at least 10 | Part 1 |
| GRC flaws | levels L1-L5, detectability D1-D4 | Part 2 |
| Faults | sensor, time, delivery | Parts 3, 6 |

Attack families for v1 (grouped for splitting):
```text
F1 credential attacks   (SSH brute force, spraying, stuffing)
F2 web exploitation     (injection, traversal)
F3 access/privilege abuse (IDOR/object access, privilege update)   [PROTO F2/F3 types]
F4 reconnaissance       (scans, enumeration)
F5 lateral movement     (SSH pivot, share access)
F6 exfiltration         (large transfers, DNS tunneling-lite)
F7 persistence/evasion  (authorized_keys, cron, log tampering)
F8 insider misuse       (off-hours bulk copy, privilege abuse)
F9 C2/beaconing (harmless simulator)
```
Hard negatives (examples): legitimate SSH admin, typo then success, authorized scans, backups, scheduled scripts, software updates, privileged legitimate administration, normal API/DB use, host reboot burst, monitoring probes, large legitimate transfers [PROTO list extended].

## A2. Coverage strategy: not full factorial

A full factorial over the factors explodes. Use:

1. **Pairwise (all-pairs) covering design** over the main factors (industry, size, maturity, topology, workload, attack family, SOC profile level, GRC style) so every pair of levels appears at least once, using a covering-array generator (e.g. PICT or allpairspy [VERIFY tool choice]).
2. **Random fill** from seeds with constraints (Part 1 dependency rules) for the remaining factors.
3. A coverage report (section C4) shows achieved pairwise coverage and underrepresented combinations; the next batch targets gaps.

## A3. Scenario mix targets (proportions, tunable)

| Category | Share of scenarios | Why |
|---|---|---|
| Quiet (no attack, benign-heavy) | 25-30% | "Nothing happened" is the most common real state; FPR measurement |
| Single campaign | 40-45% | Core learning |
| Multi-campaign / multi-stage over time | 15% | Long-horizon reasoning, repeated attacks |
| Insider-centric | 8-10% | Different evidence pattern |
| Failed or blocked attacks | 15-20% of campaigns | Failed attacks stay malicious [PROTO] |
| Attacks inside blind spots/gaps | 10-15% of campaigns | Fair-miss/abstention (Part 4) |
| Sensor/time fault scenarios | ~10% | Robustness |
| GRC flaw budget | per Part 2 rates | |
| Counterfactual twins (control applied) | sample | Part 4 section 8 |

## A4. Difficulty levels (assigned after the fact)

Computed from outcome truth, not guessed: observable evidence count, detection latency, ambiguity (benign look-alike overlap), flaw detectability class, blind-spot involvement, noise level. Three bands (easy/medium/hard) used for curriculum, reporting slices and honest "performance by difficulty" statements.

## A5. Size model (planning)

Training units for ML are **sessions and checkpoints**, not scenarios. Prototype reference [PROTO]: 96 captures produced 864 episode rows. Suppose a Gold scenario has E episodes; per scenario we obtain on the order of tens to a few hundred sessions plus checkpoint decisions.

Wall-time model per scenario (single lane):
```text
wall_hours ~= E * (pre_roll + T_observe + drain + overhead) + build_once
example: E = 8, pre_roll 5 min, observe 20 min, drain 3 min, overhead 2 min  -> 8 * 30 min = 4 h per scenario
```
Capacity example with 2 parallel lanes, 20 effective hours/day: about 10 scenarios/day, roughly 300 per month. These are **planning estimates [MEASURE]**; first real numbers come from the golden sample. Consequences:
- "Thousands of scenarios" is not realistic for Gold alone; Gold is hundreds, and volume comes from the Silver and Bulk tiers (section C).
- Prefer shorter observe windows (10-30 min) and fewer episodes per scenario for volume, longer scenarios for the long-horizon evaluation set.
- Measure phase timings first (prototype optimization plan [PROTO]); pre-built images, early drain exit, and lane parallelism come before any architecture change.

---

# PART B: SPLITS AND EVALUATION SETS

## B1. Grouping hierarchy

```text
group_id      enterprise family (seed_org + seed_topology + seed_services)   -> the split unit
family labels topology_family, industry, attack_family set, GRC style, maturity
scenario      one recipe (may be an alteration of another in the same group)
episode       one live window
session       Engine unit within an episode
```
**Rule:** never split across a group. All scenarios derived from the same enterprise (alterations, counterfactual twins, paired arms [PROTO]) stay together.

## B2. Sets

| Set | Content | Purpose |
|---|---|---|
| Train | ~60% of groups (Gold + Silver + Bulk allowed) | Learning |
| Validation | ~10% of groups (Gold only) | Model selection, thresholds |
| Test-IID (lock-box) | ~10% of groups (Gold only) | Final unbiased estimate; same families as train |
| Test-OOD-Attack | Held-out attack family (e.g. one of F6, F7, F9) [PROTO: held out `privilege_update`] | Generalization to new attacks |
| Test-OOD-Topology | Held-out topology archetype (all its groups) | Topology generalization (addresses prototype weakness) |
| Test-OOD-Industry | Held-out industry | Business-context generalization |
| Test-OOD-Style | Held-out GRC style/vocabulary | "Language translation" generalization |
| Long-horizon set | Scenarios with the longest horizons and multi-campaign plans | Sequence-over-time reasoning |

OOD sets together ~20% of groups. All validation and test sets are **Gold only**.

## B3. Rules

1. **Pre-registered splits:** `split_manifest.json` is created at release; assignment by stable hash of `group_id` (plus held-out family lists), so adding new scenarios never reshuffles old assignments.
2. **Lock-box:** the final test sets are evaluated once per release candidate, after the oracle and rubric are frozen and hashed (Part 4, section 9). No tuning after viewing results; every access is logged.
3. **Stratification:** within train/val/test, stratify by class, maturity, industry, difficulty (StratifiedGroupKFold with `group_id` for cross-validation [PROTO]).
4. **Near-duplicate control:** exact and near-duplicate feature vectors found across splits (prototype M9 finding) are removed or moved to the same split; duplicates are measured by session-fingerprint hashing and clustering.
5. **Slices reported always:** by decision type, class, maturity, industry, difficulty, flaw level, detectability class, blind-spot involvement, checkpoint position in the campaign, tier (Gold vs Silver vs Bulk).
6. **Engine ML gate** (macro-F1, attack recall, benign FPR, coverage, improvement over rule baseline [PROTO]) is evaluated on Test-IID and Test-OOD separately; OOD numbers are reported even when lower.
7. Data counting follows the prototype lesson: count independent groups/scenarios/templates, not only event rows.

---

# PART C: GOLD, SILVER, BULK

## C1. Definitions

| Tier | What it is | Real stack? | Allowed in |
|---|---|---|---|
| **Gold** | Brand-new scenario, full pipeline: Docker range, Wazuh, Suricata, health gates, truth, QA | Yes | Train, validation, all tests |
| **Silver** | Alteration of a Gold scenario (new attack/traffic/GRC/monitoring seed or override), rerun on the **real stack** reusing built images, spec and network (cheaper: no new environment design/build, shorter setup) | Yes | Train only; group stays with its parent |
| **Bulk** | Telemetry-level synthesis without running the stack (below) | No | **Train only**, capped share |

## C2. Bulk techniques (honest limits)

Bulk must not pretend to be Gold. Allowed techniques:

1. **GRC-only scenarios (strong, cheap):** GRC reality, recorded views, flaws, timeline, and metrics are generated purely by code (Parts 2, 7). Flaws of detectability classes D1 and D3 need no telemetry. D2-type flaws need telemetry evidence: use **structured evidence synthesized exactly** where the format is simple and deterministic from the spec (agent roster, syscollector inventory JSON, scanner outputs) and mark such records `synthesized=true` in the hidden plane.
2. **Remix augmentation of recorded Gold/Silver event sequences:** take real recorded sequences per activity template and persona, then **remap identities** (assets, IPs, users) to a new spec, **re-time** consistently (virtual calendar, diurnal schedules), **subsample/drop** to simulate coverage gaps, **merge** with background pools, and shift GRC context. Telemetry that depends on live correlation (Wazuh frequency rules) is **not regenerated**; existing recorded alerts are re-labeled/remapped, never re-run through a replay engine (Wazuh correlation uses processing time, Part 3, 6.5).
3. **Network variants by pcap reprocessing** (Part 6, section 5): same traffic under different sensor profiles.

Excluded: free-form text generation of logs by a language model (uncontrolled fingerprints), and replaying logs into a live Wazuh as if they were live.

## C3. Drift control between tiers

Bulk is useful only if it is statistically close to Gold for the features the model sees.

| Check | Method | Target (proposed, tuned later) |
|---|---|---|
| Classifier two-sample test | Train a classifier to distinguish Gold from Bulk sessions on Engine features | AUC close to 0.5; AUC > 0.7 means Bulk is distinguishable, fix before use |
| Per-feature distribution distance | KS or Wasserstein per feature, class-conditional | Report; flag large shifts |
| Transfer test | Train on Bulk-only, test on Gold validation | Within a stated margin of Gold-trained |
| Additive value test | Gold-only vs Gold+Bulk training on Gold validation/test | Adding Bulk must not reduce Gold-test metrics; share capped at the best-performing ratio (start at <= 70% of training rows) |
| Fingerprint probe | Section D2 probes applied to Bulk vs Gold | No Bulk-specific artifacts |

## C4. Planning scale (indicative, [MEASURE])

```text
Gold    hundreds of scenarios           validation, tests, core training
Silver  ~3-5 x Gold count              training diversity at lower cost
Bulk    thousands of scenario-equivalents   training augmentation only, capped
```
Tier appears in the hidden manifest; evaluation reports always show results by tier.

---

# PART D: GENERATOR QA AND LEAKAGE AUDIT

Two levels: per-scenario gates (already defined in Parts 1-6) and per-release audits (new here).

## D1. Per-scenario gates (summary)

```text
spec validity and resource estimate         (Part 1)
health gates: network, services, Wazuh, Suricata, canaries   (Parts 1, 3, 6)
time-consistency validator, no real-date leakage              (Part 2, B7)
weakness verification checks pass for attackable weaknesses  (Part 1, 3.4)
detection expected-vs-observed comparison                     (Parts 3, 6)
GRC diff audit: recorded vs reality fully explained           (Part 2, A9)
cross-scenario contamination check (agent/prefix/IP)          (Part 3)
package verify: hashes, schema, cross-references              (Part 5)
visible-plane forbidden-content scan                          (Part 4, section 10)
```
A scenario failing any gate is rejected and logged (seed, stage, reason), never hand-patched.

## D2. Per-release audits

**1. Shortcut and fingerprint probes (automatic).**
- Train simple probes (decision stumps, shallow trees, gradient boosting on single features and small sets) on **visible data only** to predict: the label (class), and generator-internal variables that should carry no information: `template_id`, `attacker_profile`, `scenario index`, `episode index`, `tier`, `generator_version`, `seed parity`, `lane`, `host/container naming scheme`.
- Report top single-feature AUCs for the label. A feature with AUC near 1.0 for the class (e.g. a rule ID or log string that only appears in attacks) is flagged for **review**, not automatically removed: some legitimate signals are highly predictive (that is detection), but generator artifacts are not.
- Any probe that predicts a generator-internal variable above chance blocks the release.

**2. Content and artifact scans on the visible plane.**
- Forbidden strings: seeds, template names/IDs, flaw/weakness/campaign IDs, `truth`, `oracle`, container naming patterns, generator banners, expected rule IDs list, real current date, `1970`.
- Constant or low-entropy artifacts: identical User-Agent strings per class (attack tooling vs benign), constant source ports/MACs/UUIDs/hostnames across scenarios, fixed timing patterns (always :00 seconds, fixed jitter), identical payload bodies, identical banners, default account names repeated, deterministic ordering.
- Per-field **entropy and cardinality by class** comparison: fields whose value set differs strongly between benign and malicious solely because of our tooling are flagged.
- Required mitigations when found: randomize tool banners and user agents, vary tool choice per attacker profile, jitter timing, diversify payloads, use standard software logs.

**3. Duplicate and near-duplicate detection** across scenarios and splits (session fingerprint hash, feature-vector clustering) [PROTO M9].

**4. Realism plausibility checks (not truth).**
- Event rates per host role, diurnal and weekly curves present, heavy-tailed session lengths, plausible class balance, log-format validity against reference parsers (100% parse of standard-service logs), message variety, presence of configured "messiness".
- Compare event-type distributions to published/typical reference ranges where available, documented as plausibility only.

**5. Factor-space coverage report.**
Pairwise coverage achieved, per-split group counts, class balance, maturity/industry/topology distribution, flaw level and detectability counts, difficulty distribution, tier mix, OOD set composition.

**6. Oracle and metrics audits.** Expert sample audit and counterfactual agreement (Part 4); metric validation (Part 7).

**7. Reproducibility audit.** Regenerate a random sample (e.g. 20) and report the equivalence results (Part 5, 8.2).

**8. Human review packet.** Stratified sample (target ~150 items) for review of templates, labels, and reference decisions, with at least two reviewers and agreement statistics [PROTO: M10 packet of 36 rows, not complete]. Review is a release gate item, not optional.

**9. Generator software QA.**
- All unit/integration tests pass (the prototype review found stale/failing tests and release hash drift): **no release with failing tests**.
- Golden-run regression: the golden sample must regenerate within equivalence tolerances after every generator change.
- Release artifact hashes verified (no drift between documented and shipped hashes).
- CI runs on every change; generator image digest recorded.

## D3. Release gate and honest flags

`release_report.json` lists every audit with pass/fail and numbers. Flags follow the prototype's honesty convention:

```text
training_corpus_ready:   true only if all gates pass and the human review is complete
ml_model_trained:        false inside the generator (the range does not train models) [PROTO]
oracle_frozen:           true only after hashing rubric + oracle versions
lockbox_untouched:       tracked
tier_mix, coverage and OOD composition recorded
```
A failed audit never silently passes; the release is marked incomplete with the list of blockers, as in M9/M10 [PROTO].

---

## Decisions (final)

1. Diversity by pairwise covering design plus constrained random fill; explicit mix targets including quiet and failed/blind-spot scenarios.
2. Gold = hundreds; volume from Silver (real-stack alterations) and Bulk (code-level synthesis, remix, pcap variants); Bulk and Silver are train-only.
3. Split unit = `group_id`; pre-registered stable-hash splits; lock-box; OOD sets for attack family, topology, industry and GRC style; validation and tests Gold-only.
4. Bulk is validated for drift with a classifier two-sample test, distribution distances, transfer and additive-value tests, with a capped share.
5. Automated shortcut/fingerprint probes, artifact scans and duplicate detection are release blockers.
6. Human review, oracle audit, reproducibility audit and software QA are mandatory release gates; flags remain honest.

## Tests before trust

| Test | Pass criterion | Fallback |
|---|---|---|
| Pairwise coverage generator | 100% pair coverage on chosen factors | Add scenarios for gaps |
| Stable-hash split assignment | Adding scenarios never changes earlier assignments | Fix hashing |
| Group integrity | No group spans two splits (automated check) | Fix split builder |
| Fingerprint probe run on prototype M8 data first | Reproduces known M9 findings (feature duplication, generator fingerprint) | Improve probes |
| Bulk drift tests on first Bulk batch | AUC and transfer within targets | Reduce Bulk techniques to GRC-only |
| Timing measurement from golden sample | Real wall-time per phase replaces the planning model | Rescale tier plan |
| Release gate dry run on golden sample | All checks execute and produce report | Fix harness |
