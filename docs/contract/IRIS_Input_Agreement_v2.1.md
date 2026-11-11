# IRIS Input Agreement v2.1 (synthetic path addendum)

**v2.1 = v2.0 + hidden noise additions.** This is an *additive, minor* revision. Every visible
file name and field from v2.0 (`IRIS_Input_Agreement_v2.0.md`) is kept unchanged; the Engine
reads a v2.1 package exactly as it reads a v2.0 package. The additions below are all **hidden**
(training/evaluation plane) or are new hidden quality reports — nothing new appears on the
visible plane, so the no-peek contract is unchanged.

`schema_version` is `"2.1.0"`; `data_tier` is `"SYN"` (synthetic). JSON Schemas are the same
models as v2.0 (`iris schema export`); the `VisibleManifest.schema_version` field now also
accepts `"2.1.0"`.

## What a synthetic (SYN) package is

Produced by `iris synth build` / `iris synth batch`, with no Docker and no live Wazuh/Suricata
at generation time. Telemetry is synthesised deterministically from one simulated world; Wazuh
alerts are produced by MiniWazuh over the pinned Wazuh 4.14.9 ruleset; Suricata EVE carries a
correct Community ID v1. The visible plane is the v2.0 catalogue.

## Hidden additions (training/evaluation only)

| Path (hidden) | Contents |
|---|---|
| `truth/noise_truth.json` | every perturbation applied: dropped / duplicated / delayed / skewed / malformed / unresolved event ids, with the `activity_id` of any dropped attack evidence |
| `quality/noise_report.json` | the applied `noise_profile` and its sampled parameters |
| `quality/data_quality.json` (extended) | `noise_profile_id`, `actual_drop_rate`, `actual_duplicate_rate`, `delay_distribution_summary`, and the `shortcut_test` result |
| `truth/activities.jsonl`, `truth/evidence_links.jsonl` | ground-truth activities and exact activity→event links |
| `truth/campaign_truth.jsonl`, `truth/detection_expectations.jsonl` | multi-stage campaign structure; expected detection per template |
| `truth/outcomes/<episode>.json` | per-episode outcome truth (compromise, families, affected assets) |
| `evaluation_key/{d1,d2,d4}/<episode>.json` | reference keys for scoring D1/D2/D4 |
| `truth/reality_metrics.json`, `truth/grc_coupling_flaws.jsonl`, `posture/posture_reality.json` | hidden maturity/posture metrics and injected GRC flaws |

### Hidden manifest

`hidden/manifest.json` gains a `noise_profile` block:

```json
{ "noise_profile": { "profile_id": "NOISE-MED-AB12CD", "level": "medium", "seed": 918234, "version": "noise-1.0" } }
```

The seed is **independent** of the scenario seed, so the same scenario regenerates at another
noise level with identical world, activities and clean logs — only the noise differs.

## No-peek, restated for v2.1

The visible plane never carries the noise profile, any seed, the hidden truth, or the maturity
tier. The `iris synth validate` audit fails the package if it does. Drops are independent of the
activity label except whole-sensor outage bursts (which hit benign and malicious alike), so a
missing record is never by itself a label signal.

## Still NOT promised (unchanged from v2.0 §20)

Pre-built session ids, ML feature vectors, runtime labels, automatic remediation, a mandatory
Suricata/ET deployment, full PCAP, live NVD/EPSS/KEV, or Docker-internal ids as asset identity.
The Engine owns session/incident construction from the observable inputs.
