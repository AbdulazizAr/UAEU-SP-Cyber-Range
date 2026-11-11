# Datasheet — IRIS synthetic SOC/GRC dataset

**SYNTHETIC-ONLY EVIDENCE.** Every record in this dataset is synthetic: generated
deterministically from a seed by `iris.synth`, with no Docker and no live Wazuh/Suricata/Trivy.
It exists to build, train and stress-test the IRIS Engine (SOC↔GRC translation), not to measure
real-world detection. Results on this data do not transfer to production without validation on
real SOC telemetry.

## Motivation & composition
- One **scenario** = one simulated Linux enterprise (assets, identities, services, topology,
  GRC controls, planted weaknesses) observed over several 10-minute **episodes**.
- Each scenario carries: enterprise + GRC context, posture (SBOM + scanner findings), observed
  telemetry (Wazuh alerts/archives/FIM/SCA, Suricata EVE, application & auth events), generated
  activity (benign, hard-negative, malicious F1–F9), and a **hidden** truth/evaluation plane.
- ~22 % of scenarios contain no attack. Hard-negative ratio is sampled per scenario.

## Collection process
- Deterministic from a master seed; four independent sub-seeds (activity, telemetry, sensor,
  noise). The noise seed is independent, so a scenario can be regenerated at another noise level
  with identical world/activities/clean logs.
- Wazuh alerts are produced by **MiniWazuh** over the pinned Wazuh 4.14.9 ruleset. Suricata EVE
  carries a correct Community ID v1. ATT&CK ids are validated against pinned v20.0 STIX.

## Labels & splits
- Ground truth (labels, families, techniques, campaign structure, evidence links, noise truth)
  is in the **hidden** plane only. The visible plane is the Engine's input and carries no labels,
  no seed, no noise profile, and no maturity tier (enforced by the no-peek audit).
- Split by **scenario/enterprise group**, never by row. Hold out whole scenarios, and where
  possible whole noise profiles and template families. Do not expose seed, template ids, truth
  labels, campaign ids or expected rule ids as features.

## Known limitations (read before using)
1. **MiniWazuh fidelity is unverified** until a one-time `wazuh-logtest` calibration. 95.5 % of
   the relied-on rule groups are supported; the rest are listed in `docs/UNSUPPORTED_RULES.md`.
2. **CVE catalog is a small hand-curated seed** (offline option B). Each entry carries `source`
   and `review_status: unreviewed`; `needs_human_review` entries are excluded. No CVE id, score,
   date or fixed version is invented — replace with a pinned NVD/Trivy snapshot before trusting
   findings as validated.
3. **No ET Open ruleset offline**: Suricata is mostly flow/protocol telemetry plus two labelled
   behaviour signatures; no ET SID is invented.
4. **SBOMs** list security-relevant packages fully and pad to a realistic count with *labelled*
   synthetic filler; hashes are marked synthetic.
5. **Attacks are footprints, not tooling**: a step is represented by the telemetry it leaves
   (log lines, flows, FIM, auth/app events), never runnable exploit code or payloads.
6. **Family coverage is uneven in small batches** — weakness-gated families (e.g. F2 web) appear
   only when their weakness is planted. Use larger batches for even coverage.
7. Version comparison for findings is a simplified comparator, not full dpkg/rpm vercmp.

## Recommended uses & anti-uses
- **Use for:** building/benchmarking the Engine, ablations, pipeline and split hygiene, teaching
  SOC↔GRC reasoning, and the anti-fingerprint shortcut test (`iris synth qa shortcut`).
- **Do not use for:** claiming real-world detection rates, publishing CVE/KEV facts as verified,
  or any security decision about a real system.

## Maintenance
Regenerate with `iris synth build --master N --noise LEVEL`. Determinism is pinned by
`tests/synth/test_golden.py`; if it fails, generation changed — fix the cause, do not re-bless.
