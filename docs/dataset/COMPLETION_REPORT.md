# IRIS — Status report (November 2026)

Status of the dataset generator and evaluation harness, based on running the code: the test
suite, the architecture checks, package builds, `verify`, the D6 rule baseline and the
evaluators.

## Verified state

| Check | Result |
| --- | --- |
| Tests | 269 passed (249 existing + 20 added in the review) |
| Lint, format, types | `ruff` clean, `mypy --strict` clean |
| Architecture (real-clock ban, import boundaries) | 0 violations; relative imports now checked too |
| Package build | 300 packages in about 15 s, 0 verify failures |
| Determinism | visible plane byte-identical per seed; whole package byte-identical with `SOURCE_DATE_EPOCH` |
| Integrity and no-peek | tampering with a visible or hidden file, a hidden Merkle root or the GRC diff audit is caught; no hidden IDs appear in visible files |
| Evaluator sanity | oracle-perfect decisions score 1.0; empty decisions score 0; spamming claims lowers precision; wrong flaw types lower type accuracy |

## Two tiers

**Context tier (GRC, D6): ready.** Docker-free, deterministic and documented
([DATASHEET.md](DATASHEET.md), [DATA_DICTIONARY.md](DATA_DICTIONARY.md)). A D6 model can be
trained and scored on it now.

**Telemetry tiers (train = composed, gold = live; D1, D2, D4): code complete, data pending.**
The oracle keys and the evaluator (`iris eval d1|d2|d4|all`) exist and are tested on composed
packages. Producing the data needs a successful live range run on a Docker host to record the
fragment library.

## Rule baseline (D6, 300 packages, 758 episodes)

| Measure | Result |
| --- | --- |
| DC1 recall | 99% |
| DC3 recall | 99.5% |
| DC2 recall | 10% (evidence is telemetry/posture, absent from context packages) |
| Precision | 89% |
| Type accuracy | 93% |
| Clean-episode false alarms | 4% |

Simple rules nearly solve DC1 and DC3. The research value is in DC2 (on telemetry tiers) and in
calibrated abstention on DC4.

## Coverage of the original brief

| Brief | Status |
| --- | --- |
| Reproducible pseudo-random scenarios from seeds | Done: 10-module seed hierarchy |
| Linux enterprise topology (zones, firewall, routing) | Done: compiled to Docker with an nftables router |
| Web, app, database, DNS servers | Done (live images) |
| Mail, file, directory, backup servers | In the catalog; not yet live images |
| Users, privileges, credentials, access control | Done |
| GRC generated from reality, with drift and flaws | Done: reality → style → noise → ledgered flaws, audited |
| SBOM and vulnerability scanning | Done: CycloneDX, offline Trivy, date-gated KEV/EPSS |
| Virtual time | Done: virtual clock, constant per-episode shift at export |
| Attacks | F1 (web compromise) and F2 (password guessing) live; F4, F5 declared, inactive |
| Benign traffic | HTTP customer personas live; richer personas designed |
| Truth hidden from the model | Done: hidden plane plus no-peek audit |
| Packaged, replicable, alterable scenarios | Done |
| Dashboards for evaluators | Not started |

## Fixed in the November 2026 review

1. **Fragment abstraction corrupted unmapped IPs.** IPs were replaced as plain substrings, so a
   mapped `10.5.20.25` turned the Docker bridge `10.5.20.254` into a token plus a stray digit,
   which realised as a fake address on the target enterprise. IPv4 values now match only on
   address boundaries.
2. **Password guessing was labelled as a successful compromise.** Every malicious action was
   recorded with `outcome: success`, so failed guessing marked episodes as compromised and
   raised the D2 priority key. Outcomes now come from `ACTION_OUTCOME`; guessing is `failed`
   (still malicious).
3. **Held-out groups could leak into training.** `dataset build` composed training packages from
   any library group, including groups the splitter had just assigned to an OOD set. Those
   groups are now excluded.
4. **D1, D2 and D4 had keys but no evaluator.** Added `iris.evaluator.decisions` and
   `iris eval d1|d2|d4|all`, with harmful decisions counted separately (contract 14.3).
5. **Log retiming crashed on `Feb 29` syslog stamps** and truncated nanosecond ISO stamps.
6. **The release script sealed an empty baseline** (`package batch --count 0` scored nothing).
7. **D6 scoring on records with several flaws** matched the first flaw regardless of type; a
   correct claim could count as a type error. Claims now match a same-type flaw first; added
   `strict_recall` and `unscored`.
8. **Verify** now checks the hidden Merkle root and that the GRC diff audit passed.
9. **Boundary checker** ignored relative imports, so the engine/generator rule could be bypassed.
10. **Smaller fixes:** globally unique baseline decision IDs; one Sun–Thu workweek list shared by
    the sampler and `organization.json`; a guard against risk-ID collisions; the D4 key labels
    its control state as the true state; explicit UTF-8 on every file read/write; datasheet
    statements corrected to match the code.

## Next steps

1. Seal a release: `./build_final_dataset.sh 1000`.
2. Train the D6 model on the context tier; report DC1/DC3 and DC4 abstention there.
3. On a Docker host: one successful live run, then record the fragment library, then build the
   train tier and evaluate D1/D2/D4 and DC2.
4. Check evidence citations (`evidence_event_ids` must exist and be visible by `as_of`).
