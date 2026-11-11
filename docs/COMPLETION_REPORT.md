# IRIS synthetic generator — completion report

This reports what the `iris.synth` package builds, with **measured** numbers (not targets), and
how it maps to the builder brief's acceptance criteria. It describes **synthetic** data: every
package is generated deterministically from a seed, with no Docker and no live sensors.

## What was built

The project shifted from "record a live Docker range" to "synthesise from a world simulation"
(see `docs/decisions.md`). The new `src/iris/synth/` package turns one seed into a complete,
contract-valid **v2.1 SYN** package:

```
seed → ScenarioSpec → World (reality) → posture (SBOM + CVE findings)
                                      → activities (benign + hard negatives + attacks F1–F9)
                                      → telemetry (MiniWazuh alerts, Suricata EVE, FIM, SCA, app/auth)
                                      → GRC coupling (incidents, remediation)
                                      → noise layer (+ hidden noise_truth)
                                      → D1/D2/D4 keys + truth → packaged (visible + hidden)
```

The frozen live path (`iris.live`, `compose/`, `images/`) is untouched and still passes.

### Pinned references (real, hash-locked in `configs/references/lock.json`)
- **Wazuh 4.14.9** rule + decoder XML subset — MiniWazuh loads and evaluates these.
- **Suricata 8.0.6** built-in event rules.
- **ATT&CK Enterprise v20.0** STIX (Linux/Network/Containers/PRE) — every technique used is validated against it.

### MiniWazuh
A faithful reimplementation of the Wazuh analysis subset (predecoder, decoders, rule engine
with `if_sid`/`if_matched_sid`+frequency/`match`/`regex`/dynamic-field tags/`maxsize`). Alerts
are **produced** by running it over the emitted raw lines, so every alert id/level/group/MITRE
tag is real and reproduces on re-run. Coverage of the rule groups we rely on: **95.5 %**;
the 26 unsupported rules are listed in `docs/UNSUPPORTED_RULES.md`. Fidelity is **unverified**
until a one-time `wazuh-logtest` calibration (not in CI).

## Measured results (40-scenario batch, seeds 0–39)

| Metric | Value |
|---|---|
| Packages built & verified (integrity + contract + no-peek) | 40 / 40 pass |
| Determinism | visible Merkle reproduces byte-for-byte across processes (`tests/synth/test_golden.py`) |
| Telemetry records generated | 8,158 |
| No-attack ("clean") scenarios | 22 % |
| Attack families exercised | F1, F3, F4, F5, F6, F7, F8, F9 (F2 web needs its weakness planted — rarer) |
| Maturity mix (emergent) | low 9 / medium 14 / high 17 |
| Noise mix (30/40/30) | low 12 / medium 16 / high 12 |
| **Shortcut test (anti-fingerprint gate)** | **malicious-vs-benign AUC 0.50** (threshold ≤ 0.65) — a trivial model on non-semantic features cannot separate attack from benign |

### Baseline floor for the Engine to beat (visible-plane rules)
- **D1** attack recall 0.91, benign false-positive rate 0.80 (hard negatives trip it), scenario-class accuracy 0.12.
- **D2** under-prioritises hidden compromise (it cannot see it): exact-priority 0.02, 45 harmful under-prioritisations.
- **D4** control precision 0.80, recall 0.40.

These are intentionally weak: the ML Engine has clear room to beat them, and the high benign
FP rate confirms the hard negatives are doing their job.

## Acceptance-criteria mapping

| Brief criterion | Where |
|---|---|
| `iris synth batch` builds + verifies many packages | `iris/cli.py` (`synth` group); 40/40 verified |
| v2.1 JSON Schemas / Pydantic validate every record | `iris schema export`; enforced in `verify_package` |
| MiniWazuh over pinned ruleset, real ids, reproducible | `synth/soc/miniwazuh.py`; T-S1/S2 tests |
| Community ID matches reference vectors | `synth/soc/suricata.py`; T-S4 test |
| Attacks footprint-only, ATT&CK validated, success needs weakness | `synth/activity/`; T-A1/A2/A7 tests |
| Hard negatives overlap attack families | `synth/activity/personas.py`; T-A4 test |
| Noise recorded, independent seed, JSON stays valid | `synth/noise.py`; T-N1/N4/N8 tests |
| Shortcut test is a release gate | `synth/qa/`; `iris synth qa shortcut` (exit 1 on fail) |
| No-peek: no hidden leakage into visible | `packager/verify.py`; full-build test |
| Oracle sanity: perfect decisions score perfectly | `tests/synth/test_eval_baseline.py` (T-M1) |
| Determinism / golden sample | `tests/synth/test_golden.py` |

Full suite: **lint, types, import-boundaries and all tests green** (`make check`).

## Honest limitations (see `docs/synth/DATASHEET.md` for the full list)
- MiniWazuh fidelity is **unverified** until `wazuh-logtest` calibration.
- The CVE seed catalog is a small hand-curated set (option B); entries carry `source` +
  `review_status` and should be replaced by a pinned NVD/Trivy snapshot (option A) before any
  result is called validated. No CVE id/score/date/fixed-version is invented.
- No ET Open ruleset offline, so Suricata here is mostly flow/protocol telemetry plus two
  labelled behaviour signatures; no ET SID is invented.
- SBOMs list the security-relevant packages fully and pad the count with **labelled** synthetic
  filler components.
- F2 (web) and some families are under-represented in small batches because they require their
  enabling weakness to be planted; run larger batches for even family coverage.
- This is synthetic data: it is for building and stress-testing the Engine, not a substitute for
  validation on real SOC data.
