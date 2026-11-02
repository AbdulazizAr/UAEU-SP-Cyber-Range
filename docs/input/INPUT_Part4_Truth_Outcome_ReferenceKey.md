# INPUT Part 4: Truth, Outcome and Reference Key (Evaluation Planes)

Status: FINAL DRAFT. Decisions made between us. Tags: [PROTO] already in the prototype/Engine, [NEW] proposed here, [MEASURE] verify with numbers, [VERIFY] confirm detail.

Terminology kept from Seniorita.txt: **Truth = what actually happened, as INPUT**. It is never the AI's recommendation. Part 4 adds the two layers needed to judge the AI's recommendations (outcome truth, reference key), built on top of it.

---

## 1. The planes and who may see what

```text
VISIBLE to the Engine (what a real SOC/GRC team would have)
  telemetry, recorded GRC, scanner posture, SOC inventory, as-of context

HIDDEN (never reaches the Engine at inference or training time as a feature)
  H1 World truth        what the generator built and did
  H2 Outcome truth      what it meant (consequences), recorded as facts
  H3 GRC reality + flaw ledger + SOC truth (Parts 2, 3)
  H4 Reference key      what a good decision would have been (computed by the oracle)
  H5 Evaluation results scores, verdicts, feedback
```

Access rules:
- Engine process: visible package only. No path, mount or credential to hidden data.
- Trainer: visible features + hidden **labels** for Tier 1/2 targets only (section 5), through a label-builder that outputs targets and never copies hidden fields into features [PROTO: features.py forbidden-field guard].
- Evaluator: both.
- Hidden data is stored in a separate archive (Part 5), with separate permissions.

---

## 2. H1 World truth (what happened)

Everything the generator knows, as facts:

| Group | Content | Source |
|---|---|---|
| Recipe | master seed, sub-seeds, generator/catalog versions, resolved Scenario Spec, master timeline | Parts 1, 2 |
| Environment reality | full topology and policy matrix, true OS/service versions, real credentials policy (secrets kept private), SBOM reality, weakness ledger with verification results (kind A/B/C, check passed/failed) | Part 1 |
| GRC reality | true criticality, true control effectiveness, true risk values, flaw ledger, diff audit | Part 2 |
| SOC truth | soc_profile, blind spots, SOC flaw ledger, faults, expected detections | Part 3 |
| Network truth | sensor placement truth, blind segments | Part 6 |
| Activity truth | benign and malicious activity log: template, actor, source, target, identity, parameters, scheduled vs executed time, execution status; campaign structure, step order, parent links | [PROTO: activities/activity_truth/campaign_truth] |
| Evidence links | which telemetry events came from which activity, link quality exact/strong/probable/uncertain | [PROTO: evidence_links] |
| Time truth | master timeline, episodes, clock offsets, time faults, pre-roll telemetry | Part 2, 3 |

Existing principles stay: failed malicious activity stays malicious; undetected malicious activity stays malicious; scanner finding is not exploitation proof; sensor failure is not "no detection" [PROTO].

---

## 3. H2 Outcome truth (what it meant): recorded, not judged

Outcome truth is **instrumented by the controller as a by-product of running the scenario**. No human opinion is involved and it scales to any number of scenarios.

### 3.1 What is recorded

For every attack step and every notable benign activity:

```text
result:         success | partial | failed | blocked   (post-condition verified by a check script,
                not assumed: e.g. "file marker read", "uid==0 obtained", "row count extracted")
timestamps:     start, end, time of first success (virtual time)
reach:          asset(s), account(s), data object(s) touched; blast radius (assets reachable afterwards)
weakness used:  link to the weakness-ledger entry that enabled it (causal_weakness_link)
control state:  controls that were operating (blocked/limited) and those absent (enabling control missing)
detection:      per sensor: first detection time, rule/signature IDs, or "not detected"; detection latency
containment:    active-response blocks, manual-like containment events, time to contain
persistence:    footholds left (keys, accounts, cron) and when removed (if ever)
```
For benign activity: whether it caused alerts (false-positive load), and at what severity.

For GRC side-effects: when the registers were updated after an incident (lag), or never.

### 3.2 Business impact (formula over generated facts)

```text
step_severity_factor:  attempted 0.1 | foothold 0.4 | privilege gained 0.6 | data accessed 0.8 | exfiltrated/destroyed 1.0
asset_weight:          crit_weight(true criticality) * data_sensitivity_weight * dependency_multiplier(fan-in)
impact_raw  = sum over touched assets of ( asset_weight * max step_severity_factor reached on that asset )
impact_score = normalize(impact_raw) to 0-100,  impact_band = LOW/MEDIUM/HIGH/CRITICAL
```
Weights are a versioned table (`impact_formula_version`). It uses generator-assigned fields (criticality, sensitivity, dependency), so it is a calculation, not an opinion.

### 3.3 Files (hidden)

```text
truth/outcome_truth.jsonl            per activity: result, reach, impact, timestamps
truth/causal_weakness_links.jsonl    activity -> weakness -> enabling control
truth/detection_outcomes.jsonl       per activity/sensor: detected? when? by what?
truth/benign_alarm_outcomes.jsonl    benign activities that raised alerts
truth/incident_truth.jsonl           incident = group of activities with start/end/impact (what a correct incident register would contain)
truth/grc_response_lag.jsonl         time from event to register update
```

---

## 4. Decision checkpoints and the observability problem

### 4.1 What the Engine is judged on (decision types)

```text
D1 Session assessment      class, confidence, abstain                           [PROTO classes]
D2 Priority                severity bucket x criticality -> priority
D3 Risk movement           direction and magnitude of risk change for an asset/risk entry
D4 Control recommendation  up to 3 controls, with rationale                     [PROTO max 3]
D5 Governance action       open incident / escalate / review control / request exception review ...
D6 GRC flaw finding        "this inventory/risk/control/exception record looks wrong because ..."
D7 Metric estimates        maturity/posture estimates (Part 7)
```

### 4.2 Checkpoints

A **checkpoint** = (scenario, episode, as-of virtual time T, scope). The timeline defines them:
- every closed session (D1-D4),
- end of each episode (D3, D5, D6 over the GRC registers as-of T),
- after each campaign stage (so decisions are evaluated as evidence accumulates),
- end of scenario (D7).

Decision submission schema (the Engine team already has the decision/recommendation structure [PROTO]; this adds the evaluator-facing minimum):
```json
{"decision_id": "...", "scenario_id": "...", "episode_id": "...", "checkpoint_id": "...",
 "as_of": "ISO-UTC", "type": "D2", "subject_ref": "asset|risk|control|session id",
 "payload": {...}, "confidence": 0.0-1.0, "abstained": false,
 "evidence_event_ids": ["..."], "model_version": "..."}
```

### 4.3 Two reference views (fairness)

A decision at time T must not be judged only by what happened later.

| View | Meaning | Use |
|---|---|---|
| **R-H hindsight reference** | What would be right knowing the outcome | Main scoring target for correctness |
| **R-E evidence-limited reference** | What was supportable from visible evidence as-of T (using evidence_links and coverage windows to see whether the proving evidence existed in visible telemetry by T) | Decides whether a miss was **fair** |

Fact-level flag `observable_by_T` (true/false). If the decisive fact was not observable (blind spot, sensor gap, unobserved window, event after T), a wrong decision is marked **fair_miss**: no penalty for the miss, and credit for correct abstention. If observable and ignored, it is a full miss. This is what makes "AI can't know" separable from "AI got it wrong".

---

## 5. H4 Reference key: the oracle policy

The oracle is a **versioned rulebook as data + small code**, applied automatically to every checkpoint. Inputs: world truth, outcome truth, GRC reality, checkpoint knowledge state. Outputs: per decision type a reference with tolerance. Written once, reviewed by experts (section 9), then applied to thousands of scenarios. No per-scenario hand labeling.

### 5.1 Tiers of confidence and what each may be used for

| Tier | Nature | Examples | Training | Evaluation |
|---|---|---|---|---|
| **T1 objective** | Direct recorded fact | malicious?, attack family, success/fail, asset hit, causal weakness, flaw ledger match, observable_by_T | Yes (labels) | Yes |
| **T2 formula-derived** | Computed from T1 + versioned formula, with tolerance band | impact band, expected priority band, expected risk direction/magnitude, causal/relevant control sets, metric values | Yes, as band targets or soft labels | Yes (bands) |
| **T3 policy/judgment** | Subjective governance | preferred/acceptable/forbidden governance actions | **No** (weak signal at most) | Yes (sets) |

### 5.2 Oracle outputs per decision type

**D1 Classification.** T1 truth. Abstention is correct when the class is genuinely ambiguous in visible evidence or `observable_by_T=false`.

**D2 Priority.**
```text
expected_priority_band = priority_matrix_oracle(impact_band, true_criticality, attack_success)
```
The oracle matrix differs in inputs from the Engine's own matrix (Engine uses Wazuh severity x recorded criticality; oracle uses outcome impact x true criticality). Using outcome and true values, not recorded or sensor-side values, is what keeps the oracle from simply copying the Engine [PROTO: Engine priority matrix is rule-based].

**D3 Risk movement.** Re-evaluate the GRC reality formula (Part 2, A5) before and after the incident/change facts:
```text
reference_delta = reality_residual_risk(T+) - reality_residual_risk(T-)
reference = (direction, magnitude band [lo, hi])
```
Also covers risk reduction after real remediation, and "no change" for failed/benign events.

**D4 Control recommendation.** From the weakness ledger and causal links:
```text
CAUSAL set      enabling controls of the exploited weakness (gain 3)
RELEVANT set    controls linked to the affected asset class/risk, not causal (gain 1)
IRRELEVANT set  everything else (gain 0)
HARMFUL set     "remove/relax/disable" actions on controls that are effective in reality (gain -3)
```

**D5 Governance action.** Playbook table: `situation_type -> {preferred, acceptable, forbidden}` (T3), e.g. confirmed critical data breach: preferred {open incident + notify owner + review control}, acceptable {escalate to risk owner}, forbidden {close, accept risk}.

**D6 GRC flaw finding.** Matched against the flaw ledger (Part 2) with object reference and flaw type; baseline-noise discrepancies listed separately as "minor, acceptable to flag".

**D7 Metric estimates.** Compared with reality metrics (Part 7) with tolerance.

### 5.3 Reference record

```json
{"checkpoint_id":"...", "decision_type":"D2", "subject_ref":"asset-db-01",
 "view":"R-H", "expected":{"band":["HIGH","CRITICAL"],"core":"CRITICAL"},
 "observable_by_T": true, "fair_miss_if_wrong": false,
 "derivation":{"impact_band":"CRITICAL","true_criticality":5,"attack_success":true,"oracle_rule":"PRI-07"},
 "tier":"T2", "oracle_version":"1.0.0", "rubric_version":"1.0.0"}
```
Every reference has `derivation` so it can be audited and explained to evaluators.

---

## 6. Verdicts (computable definitions)

Four levels: **Correct, Acceptable, Incorrect, Harmful**, plus **FairMiss** (not penalized) and **ValidAbstain**.

| Decision | Correct | Acceptable | Incorrect | Harmful (examples) |
|---|---|---|---|---|
| D1 | class equals T1 truth | abstain when ambiguous/unobservable (ValidAbstain); adjacent class with correct malicious/benign split | wrong malicious/benign split, or abstain when answerable | predicts benign for a successful attack on criticality >= 4 with confidence >= 0.8 |
| D2 | inside oracle band core | within 1 level outside the band | farther than 1 level | >= 2 levels below band on a successful attack with data access or worse; or LOW on a confirmed critical incident |
| D3 | direction and magnitude inside band | direction right, magnitude within +/-50% of band width outside it | no change or wrong direction when delta is small | opposite direction when |reference delta| is large (lowering risk after a real breach) |
| D4 | a CAUSAL control in positions 1-2, no HARMFUL | at least one CAUSAL/RELEVANT, no HARMFUL | only IRRELEVANT | any HARMFUL (e.g. recommend disabling an effective control) |
| D5 | in preferred set | in acceptable set | not in either | in forbidden set |
| D6 | matches a ledger flaw (object + type family) | right object, wrong subtype; or flags a baseline-noise discrepancy | flags a clean record, or misses an observable (D1-D3) flaw | proposes a wrong change that lowers criticality of a truly critical asset or marks a missing control as implemented |
| D7 | within tolerance | within 2x tolerance | beyond | n/a |

**Harm rules are data** (`evaluation_key/harm_rules.json`), each with an ID, condition, and why it is harmful, so the list is auditable and extendable:

```text
H01 downgrade confirmed successful attack on crit>=4 asset below MEDIUM
H02 classify successful attack as benign with confidence >= 0.8
H03 recommend removing/relaxing an effective control
H04 recommend closing an incident whose enabling weakness is still present
H05 lower risk after a real breach
H06 approve/extend an exception that lacks a compensating control
H07 treat an unmonitored asset or unobserved window as "no activity" (claiming safety from silence)
H08 high confidence (>= 0.8) on a wrong D2 with impact band HIGH/CRITICAL
H09 recommend an action that cites evidence that does not exist or is unrelated (fabricated evidence)
H10 (reserved)
```
Harmful decisions are **counted and reported separately**, never averaged into accuracy.

---

## 7. Turning verdicts into feedback and learning signal

The goal ("guide it, verify it, and evaluate, something we can't do manually") is met by four independent signals, none of which needs a human per scenario:

1. **Supervised targets (T1/T2)** from the label builder: class, attack family, success, priority band, risk direction/magnitude, causal controls, flaw findings. Grouped splits only (Part 8). Targets never leak into features [PROTO: ml/labels.py, features.py].
2. **Cost-sensitive loss and selection:** asymmetric penalties from the verdict table (a harmful miss costs far more than a conservative over-flag). Model selection and the activation gate use per-decision-type metrics plus the harmful count, not one blended score.
3. **Ranking and set signals (D4, D5):** nDCG/precision-recall against causal/relevant sets; T3 sets used for evaluation only.
4. **Behavioral tests built into the dataset (no extra labels needed):**
   - **Perturbation pairs:** same telemetry, altered GRC context (criticality 2 to 5, control state flipped, exception expired). The reference differs by a known amount; a decision that does not move appropriately shows the model ignores context.
   - **Evidence validity check:** cited event IDs must exist, belong to the same asset/session, and link (evidence_links) to the activity concerned.
   - **Calibration:** Brier score/expected calibration error; coverage-vs-accuracy curve for abstention; ValidAbstain credit.
   - **Time-to-decision:** metrics per checkpoint over a campaign (earlier correct is better; decisions should not get worse as evidence accumulates).
   - **Baselines it must beat:** always-benign, always-high, majority class, the Engine's existing rule baseline [PROTO], and a "context-blind" variant. The activation gate in the Engine (macro-F1, attack recall, benign FPR, coverage, improvement over rule baseline) remains [PROTO] and is extended with the harmful-decision cap (e.g. zero H01/H02/H03 events on the test lock-box; exact threshold set when the first real results exist).

Feedback record per decision (hidden, mapped to the Engine's feedback structure [PROTO: feedback.py]):
```text
decision_id, verdict, score_vector (per type), harm_rule_ids, fair_miss, reasons (reference derivation diff),
evidence_valid (bool), confidence_calibration_bin
```

---

## 8. Counterfactual replay (causal check on a sample)

Because scenarios are seeded and paired arms already exist [PROTO: fixed/vulnerable, restricted/exception], recommendations can be tested causally:

```text
Engine recommends control X for scenario S
 -> control X has an apply_recipe (e.g. enforce MFA, deny path, patch package, add rate limit)
 -> regenerate S from its recipe with X applied (alteration, Part 5), same attack plan
 -> did the attack still succeed? how did impact change?
```
Output: `counterfactual_outcomes.jsonl` (hidden). Uses:
- strongest evidence that a recommendation is beneficial,
- **calibrates the oracle**: agreement rate between oracle CAUSAL sets and counterfactual results on a sample (target to report, not hide),
- not applied to all scenarios (cost): Gold sample, stratified, plus all D4 recommendations in the final lock-box where affordable.

Limitation stated: counterfactual only tests controls with an implemented apply_recipe (v1 subset), and replays are equivalent, not identical, to the original run.

---

## 9. Validating the oracle itself

The oracle defines "correct", so it must be audited:

1. **Rule review:** every oracle rule (priority matrix, impact weights, harm rules, playbook sets, control gains) reviewed by at least two reviewers with SOC/GRC background; version-controlled; changes logged.
2. **Expert sample audit:** stratified sample of ~150 checkpoints across decision types, tiers, maturities; two or more reviewers independently rate "is the reference reasonable?" and, for T3, choose acceptable sets. Report inter-rater agreement (e.g. Cohen's kappa) and oracle-vs-expert agreement. Proposed acceptance targets: oracle-expert agreement >= 85% on T1/T2, kappa >= 0.6 among experts; disagreements go to a log and drive rule changes. Targets are proposals to be confirmed once real numbers exist.
3. **Counterfactual agreement** (section 8) as an independent, rubric-free check.
4. **Freeze before final evaluation:** oracle and rubric versions frozen and hashed before the lock-box test is run; no tuning after seeing model results.
5. **Circularity controls:**
   - Oracle code lives separately and never imports Engine code or Engine features.
   - Oracle uses hidden facts the Engine cannot see; its formulas differ from Engine's by design.
   - Report how well the **rule baseline** agrees with the oracle: if a trivial rule matches the oracle almost perfectly, the benchmark is too easy or circular.
   - Held-out attack families, topologies, industries and GRC styles (Part 8).
6. **Honest claim:** the AI cannot be "more correct" than the oracle's definition of correct. The claim is: *the AI reproduces outcome-consistent, policy-consistent decisions using only information available in real operations, better than baselines, including under noise, missing data and unseen scenarios.* T3 correctness is always reported as set-membership, never as a single truth.

---

## 10. Leakage enforcement (physical, not just promises)

- Hidden and visible data are separate archives with separate access (Part 5).
- The Engine runs in a sandbox with only the visible path mounted; a **no-peek test** runs the Engine with hidden data absent and confirms identical results.
- Visible package scan for forbidden content: seeds, template IDs/names, flaw IDs, weakness IDs, campaign IDs, "truth", generator naming patterns, expected rule IDs [PROTO forbidden list extended], real current date (Part 2, B7).
- Forbidden feature list (Engine) extended with: `flaw_id, weakness_id, soc_profile, blind_spot, episode_index, scenario_index, tier, oracle_*, reference_*, impact_*`.
- Runtime fields like `scenario_id`/`run_id` stay in envelopes for grouping but are never features [PROTO].

---

## 11. Hidden/evaluation files

```text
truth/ (H1-H3)
  activity_truth.jsonl, campaign_truth.jsonl, evidence_links.jsonl, detection_expectations.jsonl   [PROTO]
  outcome_truth.jsonl, causal_weakness_links.jsonl, detection_outcomes.jsonl,
  benign_alarm_outcomes.jsonl, incident_truth.jsonl, grc_response_lag.jsonl                         [NEW]
  grc_reality.json, grc_flaw_ledger.jsonl, grc_diff_audit.json, soc_profile.json,
  blind_spots.json, soc_flaw_ledger.jsonl, metrics_reality.json, metrics_timeline.jsonl            (Parts 2,3,7)
evaluation_key/ (H4)
  checkpoints.jsonl                 checkpoint definitions with as-of times
  reference_decisions.jsonl         R-H and R-E views per checkpoint
  acceptable_alternatives.jsonl     T3 playbook sets and control gain sets used
  harm_rules.json                   H01...
  perturbation_pairs.jsonl          context-altered twins and expected reference diffs
  counterfactual_outcomes.jsonl     (sample only)
  oracle_version.json               oracle_version, rubric_version, impact_formula_version, hashes
evaluation_results/ (H5, produced per model run, stored outside scenario packages)
  decisions_scored.jsonl, report.json
```

---

## 12. Worked example (one checkpoint)

Facts: scenario S, day 40, episode 6. Attacker used SQL injection weakness W-12 (kind C) on `web-02`, then DB credentials from config to read `customers` on `db-01` (true criticality 5, regulated data). MFA control on DB admin account missing in reality; recorded register says "implemented" (a paper-control flaw, level L4). Wazuh saw web alerts; DB read produced archives events but no alert; Suricata saw the flow.

Oracle at checkpoint (end of episode 6):
```text
D1 class = credential/data access attack, malicious, success=true, observable_by_T=true
D2 expected band HIGH-CRITICAL, core CRITICAL
D3 risk R-DB-01: direction UP, magnitude +15..+30 (reality residual rises as likelihood and control factor change)
D4 CAUSAL {input validation/WAF on web-02, MFA on DB admin, DB network segmentation}; RELEVANT {log monitoring}; HARMFUL {remove segmentation rule}
D5 preferred {open incident, notify DB owner, review MFA control}; forbidden {close, accept risk}
D6 flaw finding: control C-MFA "implemented" contradicts SCA failure on db-01 (ledger F-031, detectability D2 telemetry-evident)
```
Engine outputs:
- **A:** CRITICAL, risk +20, controls [MFA on DB admin, segmentation], opens incident, flags C-MFA vs SCA. -> D2 Correct, D3 Correct, D4 Correct, D5 Correct, D6 Correct.
- **B:** MEDIUM, risk +3, controls [log retention], no flag. -> D2 Incorrect (2 levels below, success + data access, so also Harmful H01), D3 Incorrect, D4 Incorrect, D6 missed observable flaw.
- **C:** benign, confidence 0.9. -> D1 Harmful (H02).
- **D:** variant where the DB read happened inside an unobserved window and no archives exist: abstain with explanation. -> ValidAbstain (fair_miss), credited, not penalized.

---

## 13. Decisions (final)

1. Truth stays "what happened"; outcome truth and reference key are separate hidden planes.
2. Outcome truth is instrumented by the controller; success is verified by post-condition checks, never assumed.
3. Reference key = versioned oracle (rules as data), computed automatically, with derivation stored per record.
4. Three tiers (T1/T2/T3); T3 is evaluation-only.
5. Two reference views (hindsight and evidence-limited) with `observable_by_T` and fair-miss handling.
6. Verdicts: Correct / Acceptable / Incorrect / Harmful, plus FairMiss and ValidAbstain; harm rules are explicit data; harmful decisions reported separately.
7. Feedback comes from supervised T1/T2 targets, cost-sensitive selection, ranking/set metrics, and built-in behavioral tests (perturbation pairs, evidence validity, calibration, time-to-decision, baselines).
8. Counterfactual replay on a stratified sample to calibrate the oracle.
9. Oracle is audited (expert sample, agreement stats, counterfactual agreement), frozen and hashed before the final lock-box evaluation.
10. Hidden planes are physically separate and enforced by sandbox and scans.

## 14. Tests before trust

| Test | Pass criterion | Fallback |
|---|---|---|
| Post-condition checks for each attack template | Verified success/failure matches actual effect on 100% of 200 test runs | Mark steps `unverified`; exclude from T1 success labels |
| Impact formula sanity (monotonicity, ordering) | More assets or higher criticality never lowers impact | Fix weights |
| Oracle vs rule baseline agreement | Baseline clearly worse than oracle on D2-D4 | Redesign oracle inputs if circular |
| Expert audit (150 checkpoints, 2+ reviewers) | Targets in section 9 | Revise rules and re-audit |
| Perturbation pairs | Reference diff exists and is stable | Drop unstable pair types |
| No-peek test | Identical Engine output without hidden data | Fix packaging/access |
| Counterfactual agreement on 30 scenarios | Reported; large disagreement triggers oracle review | Restrict D4 oracle to counterfactual-verified controls |

Next: Part 5 (scenario package and data contract).
