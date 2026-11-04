# IRIS

Synthetic SOC/GRC cyber range, dataset generator and evaluation harness, plus the IRIS Engine that learns from it.

- Design: `docs/input/` (INPUT Parts 1-8), final decisions in `docs/decisions.md` (wins on conflict).
- Engine contract: `docs/contract/IRIS_Input_Agreement_v2.0.md`.
- Measurements that replace planning estimates: `docs/measurements.md`.

## Setup

Needs Python 3.12+ and [uv](https://docs.astral.sh/uv/). Docker is only needed for the live
range (`iris range ...`, `iris spike ...`); everything else runs offline.

```bash
git clone https://github.com/AbdulazizAr/UAEU-SP-Cyber-Range.git iris && cd iris
make setup                       # uv sync + pre-commit hooks (needs internet once)
export IRIS_DATA=/srv/iris       # where data goes (default /srv/iris); any writable path works
uv run iris data init            # creates $IRIS_DATA/{store,fragments,runs,cache,references,registry}
make check                       # lint, types, architecture checks, tests
make refs                        # optional: download + pin ATT&CK, NIST 800-53 ... then verify
```

Quick smoke test (about a minute, no Docker):

```bash
uv run iris package batch --count 20 --out /tmp/iris-demo     # build, verify, score the D6 baseline
```

After the first `make refs`, commit `configs/references/lock.json` so every machine pins the
same reference bytes.

## Layout

```text
src/iris/
  core/         vclock (virtual time), seeds (10 sub-seeds, group_id), hashing (IDs, Merkle)
  contracts/    ScenarioSpec, visible plane v2.0, Engine decision records, JSON Schema export
  references/   pinned standards: ATT&CK STIX, NIST OSCAL, CTID mappings (+ registry/lock)
  devtools/     architecture checks run in CI
  generator/    sampler, compiler, GRC (reality, record, timeline), enterprise files, posture
  packager/     scenario packages: visible + hidden planes, manifests, Merkle, verify (no-peek)
  oracle/       reference keys: D6 (all packages), D1, D2, D4 (packages with telemetry)
  evaluator/    scoring against the keys: d6.py, decisions.py (D1, D2, D4)
  compose/      record-and-compose: fragments realised and re-timed onto new enterprises
  fragments/    recorded activity fragments and the token abstraction
  live/         live range: deploy, health gate, activity plans, recording
  dataset/      splits by group, coverage, drift tests, packing
  engine/       IRIS Engine, visible plane only (baselines/ now; models in P8)
configs/references/   registry.yaml (what we use), lock.json (exact bytes)
examples/             golden_v0.spec.yaml
tests/                unit tests + small reference fixtures
```

## Rules the code enforces

- **No real clock.** Only `iris/core/vclock.py` may read wall time; everything else uses `VClock`. Checked by `iris check` / `make arch`.
- **Import boundaries.** `engine` never imports `generator`, `oracle` or `evaluator`; `oracle` never imports `engine`; `contracts` and `core` are leaves. Relative imports are resolved, so `from ..generator import x` is caught too.
- **Strict contracts.** Unknown fields are errors on the producer side; timestamps are UTC-aware and serialised with `Z`.
- **Pinned references.** A reference is usable only when its file matches the SHA-256 in `lock.json`.

## Commands

```text
iris info                              versions and data paths
iris data init                         create $IRIS_DATA sub-directories
iris seeds derive --master N [--override attack=42]
iris spec validate examples/*.spec.yaml
iris schema export [--out DIR]         JSON Schemas for the Engine team
iris refs list | fetch [ID..] [--repin] | verify | show ID
iris check                             real-clock ban + import boundaries
```

## Generating scenarios (P2)

```bash
uv run iris gen spec --master 42                     # sample one enterprise and summarise it
uv run iris gen spec --master 42 --out /tmp/s42.yaml # ...and save the spec
uv run iris gen batch --count 1000                   # validity, invariants, factor coverage
uv run iris gen compile /tmp/s42.yaml --out /tmp/s42 # compose.yaml + router.nft + compiled.json
uv run iris gen grc --master 42 --out /tmp/g42       # GRC reality, registers, flaws, diff audit, timeline, as-of snapshots
```

## Posture (P5): SBOM, Trivy, date-gated intel

```bash
uv run iris posture db                    # once, needs network: Trivy DB snapshot
uv run iris refs fetch trivy-db           # pin it (and `make refs` pins KEV + EPSS snapshots)
uv run iris posture scan --master 42      # scan that enterprise's built images (offline, no docker.sock)
uv run iris posture show iris/wazuh-manager:4.14.9-1
uv run iris posture build --master 42 --out /tmp/p42   # GRC + timeline + posture + merged as-of snapshots
```

Catalogs (archetypes, industries, recipes, weaknesses, names) live in `configs/catalog/` and are documented assumptions.

## Live range (P2)

```bash
uv run iris range plan --master 42        # the live enterprise for a seed: hosts, services, weaknesses, images
uv run iris range build --master 42       # build its images (first time ~10-20 min, then cached)
uv run iris range up --master 42          # deploy, health gate, teardown; --keep leaves it running
uv run iris range status                  # iris ranges on this machine
uv run iris range down --all              # remove kept ranges (label-scoped)
uv run iris range gate --count 20         # P2 exit gate
```

Each run writes compose.yaml, router.nft, compiled.json (with credentials: hidden), health.json, timings.json, state.json and container logs to `$IRIS_DATA/runs/live/<stamp>-<project>/`.

### Docker address pools

Scenarios use realistic enterprise ranges (10.x, 172.16-31.x, 192.168.x). Docker gives other projects' networks addresses from 172.17-31 and 192.168 by default, so a scenario can collide with them: `iris range` then reports `SKIPPED: subnet conflict` (a lane problem, not a range failure). To keep Docker's own allocations out of the way, add this to `/etc/docker/daemon.json` and restart Docker (`sudo systemctl restart docker`):

```json
{ "default-address-pools": [ { "base": "10.200.0.0/14", "size": 24 } ] }
```

Networks that already exist keep their addresses until their projects are recreated (`docker network ls`; `docker compose down && docker compose up -d` in those projects).

## SOC (P3)

```bash
uv run iris soc profile --master 42 --live   # what the SOC really collects vs believes, and the gaps
uv run iris soc rules                        # rule library: IDs, parents, ATT&CK tags (pinned release)
uv run iris soc logtest                      # rule tests through wazuh-logtest (Docker, ~1 min)
uv run iris range up --master 42 --light     # production health gate (faster)
uv run iris range record --master 42         # record episodes + verify SOC detections
uv run iris range detect-gate --count 10     # P3 exit gate
```

## Packages and the D6 baseline (P6)

```bash
uv run iris package build --master 42              # one context package + verify -> $IRIS_DATA/store/context
uv run iris package batch --count 1000             # many packages, verify each, D6 rule-baseline scores
uv run iris package verify $IRIS_DATA/store/context/scenario-<id>
uv run iris baseline d6 <package> --out /tmp/dec.jsonl
uv run iris eval d6 <package> --decisions /tmp/dec.jsonl
```

`eval d6` reports `recall` (right record named) and `strict_recall` (right record and right
flaw type), per-class recall, precision, type accuracy, harm-weighted recall, clean-episode
false alarms, unsupported DC4 claims, `unscored` decisions (for episodes the package does not
contain) and Brier. On context packages DC2 is near-unfindable by construction (its evidence is
telemetry/posture), so judge DC2 on train/gold packages.

Composed (`train`) and live (`gold`) packages also carry D1, D2 and D4 keys:

```bash
uv run iris eval d1 <package> --decisions dec.jsonl    # classification
uv run iris eval d2 <package> --decisions dec.jsonl    # priority
uv run iris eval d4 <package> --decisions dec.jsonl    # control recommendation
uv run iris eval all <package> --decisions dec.jsonl   # D1, D2, D4 and D6 together
```

Harmful decisions (contract 14.3) are reported separately from accuracy. A malformed line in
`decisions.jsonl` is reported with its line number.

### Reproducible releases

The visible plane is byte-deterministic per seed. Set `SOURCE_DATE_EPOCH` (integer seconds) to
pin the one real-time field in the hidden manifest, and whole packages become byte-identical:

```bash
SOURCE_DATE_EPOCH=1767225600 uv run iris package batch --count 1000 --out /srv/iris/store/context
./build_final_dataset.sh 1000    # sets SOURCE_DATE_EPOCH itself and records it in MANIFEST.json
```

## P1 spikes (need Docker + internet, about 15-25 minutes the first time)

```bash
uv run iris spike wazuh      # boot/RAM, correlation, export time shift, warm restart into a later window
uv run iris spike network    # router + Suricata in the router namespace, duplicates, dedup, drops, time shift
uv run iris spike all
```

Each run prints pass/fail per check and writes `results.json` plus logs to `$IRIS_DATA/runs/spikes/<stamp>-<name>/`. `--keep` leaves the containers up for inspection; `--no-build` reuses images; Virtual time is applied at export (no libfaketime): see docs/decisions.md, P1 results.

## Reference notes

`fetch: url` references download automatically. `fetch: manual` ones (CTID mappings, CSF 2.0 export, ISO 27001 and CIS ID lists) must be placed at `$IRIS_DATA/references/<id>/<filename>` and then `iris refs fetch <id>` pins them. URLs marked `url_verified: false` could not be checked from the build environment; if one fails, fix the URL in `registry.yaml`.

## Known limitations

- **Live services:** web, app, database and DNS servers are built live; mail, file, directory
  and backup servers exist in the catalog but not yet as live images.
- **Attack families:** F1 (web compromise) and F2 (password guessing) run end to end; F4
  (lateral movement) and F5 (exfiltration) are declared but inactive.
- **Outcome verification:** a malicious action's outcome comes from the action catalog
  (`iris.live.attacks.ACTION_OUTCOME`), not from checking its post-condition on the range.
- **Decisions scored:** D1, D2, D4 and D6. D3, D5 and D7 are planned for v1.1. Evidence
  citations (`evidence_event_ids`) are required but not yet checked by the evaluator.
- **Realism:** telemetry comes from a real Wazuh/Suricata stack, but traffic and attacks are
  scripted; no comparison with a public SOC dataset has been made yet.
