# IRIS dataset — Datasheet (context / GRC tier, D6)

*Checked against the IRIS source and generated packages (November 2026).*

## 1. What this dataset is

IRIS is a synthetic SOC/GRC cyber-range and dataset generator. This datasheet covers its
**context tier**: per-scenario packages that carry a full, recorded **GRC program** (asset
inventory, control register, risk register, business context, policy exceptions, SOC inventory,
and SBOM/posture when built with `--posture`) with **deliberately planted flaws** hidden from the model. The learning task on
this tier is **D6 — GRC flaw finding**: given only what an organization *records* about itself,
find the records whose stated state hides a real gap.

The context tier needs **no Docker and no network**. It is fully deterministic from a seed.

## 2. Motivation

Real GRC registers drift from reality: an asset's criticality goes stale after a process change,
a control is marked "implemented" on paper, a risk's owner has left, an exception has expired but
is still relied on. A SOC/GRC analyst's job is to notice. IRIS manufactures these situations at
scale, with a hidden answer key, so a model can be trained and scored on exactly that skill.

## 3. Composition

Each scenario is one package directory `scenario-scn-<id>/` with two planes:

```
visible/                         # everything the model MAY read
  manifest.visible.json          # ids, virtual calendar, episode windows (NO seeds, NO tier)
  enterprise/
    organization.json            # org, size, industry, workweek, business units/services
    assets.json                  # asset inventory (11 assets in the sample)
    topology.json                # zones, paths, dependencies, internet-facing
    services.json                # running services, ports, exposure, data class
    identities.json              # users/service accounts, privilege, MFA, groups
  grc/
    controls.json                # control register (28 controls), mapped to frameworks
    control_mappings.json        # control -> framework refs (NIST/CSF/ISO/CIS)
    risk_register.json           # risks: likelihood, impact, residual, owner, treatment
    business_context.json        # per-asset CIA, criticality, owners, regulatory
    policy_exceptions.json       # exceptions with approver and validity window
    scale_definition.json        # this org's risk/criticality scales and review cadence
  soc/
    soc_inventory.json           # what the SOC believes it collects (agents, rules, sources)
  snapshots/
    context_history.jsonl        # append-only log of recorded GRC changes (bitemporal)
    asof/<episode>.json          # registers as they stood at each episode checkpoint

hidden/                          # GROUND TRUTH — never shown to the model
  manifest.json                  # full manifest incl. data_tier
  recipe/seeds.json, spec.json   # the exact seeds and scenario spec (reproducibility)
  evaluation_key/d6/<episode>.json   # THE ANSWER KEY for D6 (see §5)
  truth/grc_reality.json         # what is actually true before recording
  truth/grc_flaw_ledger.jsonl    # every planted flaw, with cause
  truth/grc_diff_audit.json      # proof that visible = reality + style + noise + ledgered flaws
  truth/soc_gap_ledger.jsonl     # SOC belief-vs-reality gaps
  posture/generated_weaknesses.json
```

**Episodes.** Each scenario has a small number of episodes (2 in the context sample, 3 in the
golden example) placed at points along a ~2-month virtual calendar. An episode is a checkpoint:
the model is asked about the registers *as of* that virtual time, and the D6 key is per episode.

## 4. Scale and balance (measured, 40 scenarios / 96 episodes)

| Dimension | Observed |
| --- | --- |
| Episodes | 96 (33 clean, 63 with flaws) |
| Flaws total | 152 |
| Detectability | DC1 52, DC2 54, DC3 40, DC4 6 |
| Harm | high 56, medium 44, low 52 |
| Flaw level | L1 23, L2 52, L3 20, L4 57 |
| Collection hit | risks 54, business_context 43, controls 35, assets 20 |
| Flaw modules | 14 distinct (see coverage report) |

These are stable per seed. A 1,000-scenario build gives the same proportions at larger N.

## 5. The D6 answer key (hidden)

`hidden/evaluation_key/d6/<episode>.json` is the ground truth the evaluator scores against:

```json
{
  "version": "d6-key-0.1.0",
  "episode_id": "scn-...-ep001",
  "as_of": "2025-05-30T19:50:00Z",
  "clean": false,
  "flaws": [
    {
      "flaw_id": "F-001",
      "key": "AST-APP-001",
      "aliases": ["10.19.233.237", "AST-APP-001", "app01"],
      "collection": "business_context",
      "module": "asset.criticality_stale",
      "level": "L4",
      "detectability": "DC3",
      "fields": ["criticality"],
      "harm": "medium",
      "reference_action": "re-assess criticality after the business process change",
      "origin": "timeline",
      "evidence_refs": ["context_history business_process change", "...", "EV-001"]
    }
  ],
  "tolerated_keys": ["RSK-NET-001"]
}
```

- **clean**: episode has no planted flaw (a hard negative — the model must NOT invent one).
- **flaws[]**: each planted flaw; the model is scored on naming its `key` (`recall`) and on
  giving the right flaw type (`module`; `type_accuracy`, `strict_recall`). `evidence_refs`
  describe where the evidence lives; citations are not scored yet.
- **aliases**: acceptable ways to name the same subject (id, IP, hostname) — scoring is not fooled
  by which alias the model uses.
- **tolerated_keys**: records changed only by bounded, realistic noise (an off-by-one
  criticality, a missing owner, a unit spelling variant). A claim on one is a *noise claim*:
  not a false positive and not in precision, but a confident one still costs Brier score.

### Detectability classes (why this dataset matters)
- **DC1** internal inconsistency inside the visible plane (e.g. a risk owner who is not in
  `identities.json`, regulated data recorded at the lowest criticality).
- **DC2** needs **posture or telemetry evidence**; context packages do not carry it, so DC2
  is near-unfindable on this tier by construction. Score DC2 on the train/gold tiers.
- **DC3** time: dates against the review cadence or an expiry (expired exception still in use,
  overdue review, a business change never followed by a re-assessment in the history).
- **DC4** no visible evidence by design: excluded from recall; a confident claim (>= 0.5) is
  counted as *unsupported*, which tests that a model abstains instead of over-claiming.

## 6. The task and the baseline to beat

**Task D6.** Input: the `visible/` plane of an episode. Output: a list of `DecisionRecord`s, each
naming a flawed record (`collection` + `key`), the flaw type, a confidence, and references. The
evaluator (`iris eval d6`) reports recall over DC1-DC3 and per class, `strict_recall` (right
record and right type), precision, type accuracy, harm-weighted recall, false alarms on clean
episodes, unsupported DC4 claims, decisions for unknown episodes (`unscored`) and Brier score.

**Rule baseline** (`iris baseline d6`, reads visible only) on a 500-scenario batch scored roughly:
DC1 ≈ 0.99, DC3 ≈ 1.0, **DC2 ≈ 0.07**, precision ≈ 0.89. The simple checks clear DC1/DC3 but
cannot touch DC2. **Closing DC2 is the entire point of the learned model** — it is the headline
number to track.

## 7. Collection / use

- **Build:** `iris package batch --count N --out <dir>`
- **Verify:** `iris package verify <pkg>` — hashes, Merkle root, and the **no-peek audit** (proves
  no hidden identifier leaked into `visible/`).
- **Coverage (this tier):** `iris dataset coverage-context <dir>` (`dataset coverage` is for
  composed train-tier packages and reports 0 on context data).
- **Score a model:** `iris eval d6 <pkg> --decisions <decisions.jsonl>`
  (`iris eval all` adds D1/D2/D4 on composed or live packages).

## 8. Splits (how to train/validate honestly)

Group by enterprise `group_id` (from the seed). Hold out whole groups, never episodes, so a group
never appears in both train and test. OOD holdout dimensions (topology, industry, GRC style) are
supported by `iris dataset splits`. **Validation/test must be live Gold only**; composed/synthetic
data is training-only until it passes the drift tests. For a D6-only model on the context tier,
hold out ~10–20% of groups for validation and keep at least one GRC-style value entirely unseen.

## 9. Determinism and provenance

Same seed → same spec and same recorded registers (`"determinism": "recipe and spec exact"`).
With `SOURCE_DATE_EPOCH` set, whole packages (hidden manifest included) are byte-identical.
Each package carries its seeds and spec in `hidden/recipe/`, and `grc_diff_audit.json` proves the
visible registers equal *reality + org style + bounded noise + ledgered flaws* — so every single
difference between truth and record is explained.

## 10. Honest limits

- **In scope now:** GRC registers, SOC configuration/inventory, SBOM + date-gated CVEs (with
  `--posture`), and the **D6** task. Docker-free and reproducible.
- **Not in this tier:** live attack **telemetry** (Wazuh/Suricata alerts from real attacks) and the
  decisions that depend on it — **D1** classification, **D2** priority, **D4** control
  recommendation. Their keys and evaluator (`iris eval d1|d2|d4|all`) exist; the data requires
  the live Docker range to be built and proven on a Docker host, and ships separately as the
  *train* (composed) and *gold* (live) tiers.
- **DC4** flaws are intentionally not findable from the visible plane; they exist to test that a
  model abstains rather than hallucinating evidence.
