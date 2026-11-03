# IRIS

Synthetic SOC/GRC cyber range, dataset generator and evaluation harness, plus the IRIS Engine that learns from it.

- Design: `docs/input/` (INPUT Parts 1-8), final decisions in `docs/decisions.md` (wins on conflict).
- Engine contract: `docs/contract/IRIS_Input_Agreement_v2.0.md`.
- Measurements that replace planning estimates: `docs/measurements.md`.

## Setup (Ubuntu, once)

```bash
cd ~/work/iris
git init && git add -A && git commit -m "P0 skeleton"    # first time only
make setup                 # uv sync + pre-commit hooks (needs internet)
export IRIS_DATA=/srv/iris # already in ~/.bashrc
uv run iris data init      # creates /srv/iris/{store,fragments,runs,cache,references,registry}
make check                 # lint, types, architecture checks, tests
make refs                  # download + pin ATT&CK v20, NIST 800-53 ... then verify
```

Commit `uv.lock` and `configs/references/lock.json` after the first run.

## Layout

```text
src/iris/
  core/         vclock (virtual time), seeds (10 sub-seeds, group_id), hashing (IDs, Merkle)
  contracts/    ScenarioSpec, visible plane v2.0, Engine decision records, JSON Schema export
  references/   pinned standards: ATT&CK STIX, NIST OSCAL, CTID mappings (+ registry/lock)
  devtools/     architecture checks run in CI
  generator/    sampler, compiler, GRC (reality, record, timeline), enterprise files, posture
  packager/     scenario packages: visible + hidden planes, manifests, Merkle, verify (no-peek)
  oracle/       reference keys (D6 now; D1, D2, D4 with telemetry)
  evaluator/    scoring against the keys (D6 now)
  engine/       IRIS Engine, visible plane only (baselines/ now; models in P8)
configs/references/   registry.yaml (what we use), lock.json (exact bytes)
examples/             golden_v0.spec.yaml
tests/                unit tests + small reference fixtures
```

## Rules the code enforces

- **No real clock.** Only `iris/core/vclock.py` may read wall time; everything else uses `VClock`. Checked by `iris check` / `make arch`.
- **Import boundaries.** `engine` never imports `generator`, `oracle` or `evaluator`; `oracle` never imports `engine`; `contracts` and `core` are leaves.
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

## P1 spikes (need Docker + internet, about 15-25 minutes the first time)

```bash
uv run iris spike wazuh      # boot/RAM, correlation, export time shift, warm restart into a later window
uv run iris spike network    # router + Suricata in the router namespace, duplicates, dedup, drops, time shift
uv run iris spike all
```

Each run prints pass/fail per check and writes `results.json` plus logs to `$IRIS_DATA/runs/spikes/<stamp>-<name>/`. `--keep` leaves the containers up for inspection; `--no-build` reuses images; Virtual time is applied at export (no libfaketime): see docs/decisions.md, P1 results.

## Reference notes

`fetch: url` references download automatically. `fetch: manual` ones (CTID mappings, CSF 2.0 export, ISO 27001 and CIS ID lists) must be placed at `$IRIS_DATA/references/<id>/<filename>` and then `iris refs fetch <id>` pins them. URLs marked `url_verified: false` could not be checked from the build environment; if one fails, fix the URL in `registry.yaml`.
