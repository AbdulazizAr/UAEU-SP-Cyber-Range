# Decision record

Final decisions made after the INPUT parts were written. Where an INPUT part (in `docs/input/`) disagrees, this file wins. The Engine contract is the IRIS Input Agreement v2.0 (claude.ai doc, exported to `docs/contract/` when it changes).

## Architecture

- **Record-and-compose.** The live Docker + Wazuh + Suricata range records self-contained activity fragments (raw logs, alerts, flows and truth per activity or attack stage) and builds the live Gold validation and test sets. Training scenarios are composed by code: generated enterprise, GRC and timeline plus fragments remapped to new hosts, IPs and users and re-timed.
- Composed data is training-only until it passes the Part 8 drift tests. Validation and test sets are always live Gold.
- The fragment library is split by enterprise group like everything else; fragment reuse is capped per split.
- Composed scenarios store only their recipe (seeds and fragment references) and are rebuilt on demand.

## v1 scope

- **Decision types in v1:** D1 classification, D2 priority, D4 control recommendation, D6 GRC flaw finding.
- **Moved to v1.1 (P10):** D3, D5, D7; the full Part 7 metric set; KPI reports; counterfactual replay; time faults; intra-zone taps; Wazuh active response; lineage trees; scenarios longer than 3 episodes. Random sampling plus a coverage report replaces the pairwise covering design.
- **Never simplified:** the visible/hidden separation, recorded-vs-real GRC with a flaw ledger, verified attack outcomes, the reference key for v1 decision types, splits by enterprise.

## Part 1 closures

| Question | Decision |
| --- | --- |
| Store resolved spec with seeds | Yes, plus the generator image digest |
| Wazuh isolation | Part 3 model: stateless manager per episode, state volume per scenario, agents enrolled once per scenario. Part 1 section 8 is superseded |
| microVM tier | No; containers only in v1 |
| First recipes | router/firewall, Suricata sensor, DNS, nginx, Flask sample app, PostgreSQL, OpenSSH bastion, OpenLDAP + Kerberos, Samba, Postfix, workstation, restic backup |
| Directory | OpenLDAP + Kerberos in v1; Samba AD later as a P item |
| Attackers | Pre-planned only in v1 |
| Topology archetypes | The 6 in Part 8 |
| Realism review | The Part 8 two-reviewer pool |

## Naming

- Part 5 file layout is authoritative: `enterprise/assets.json` + `grc/business_context.json` (no `asset_inventory.json`); `snapshots/asof/<episode_id>.json`; `quality/sensor_health_{visible,full}.json`; top-level hidden `preroll/`.
- Detectability classes are **DC1-DC4** (decision types stay D1-D7). Oracle confidence tiers stay T1-T3. Gold/Silver/Bulk are called **data tiers**. Test IDs are `TBT-<part>.<n>`. Attack families F1-F9; prototype attack types are referred to by name.

## Seeds and grouping

- 10 sub-seeds: org, topology, services, identity, weakness, traffic, attack, monitoring, time, grc. Derived from the master seed and the generator MAJOR version, stored explicitly, each overridable.
- `group_id` = hash(org, topology, services, identity, generator major). Changing any other sub-seed keeps the group.
- `group_id`, data tier and lineage are hidden only.

## Splits

- Each group belongs to exactly one out-of-distribution set; precedence topology > industry > attack family > GRC style.
- The sampler blocks held-out attack families and GRC styles from all in-distribution groups.
- Each out-of-distribution set needs at least 15 Gold groups or its results are reported as indicative.

## Suricata

- One sensor in the router's namespace captures every router interface (perimeter merged in).
- Export de-duplicates by `community_id`, event type, signature and a 1 s window. Health gate S3 asserts exactly one record per canary flow.
- Mandatory in v1.

## Pinned tools (P1)

- Wazuh manager and agents **4.14.9-1** (Debian 12 packages, manager-only in generation mode, JSON archives on, indexer and vulnerability detector off).
- Suricata **8.0.6** (`jasonish/suricata:8.0.6` for the spike; our own image later). Digests replace tags once P1 passes.
- Trivy **0.76.1** (`aquasec/trivy:0.76.1`), see Posture.
- **No libfaketime.** Live episodes run on the real clock; every record is moved by one constant per-episode offset at export (`iris.generator.retime` for Wazuh, `iris.generator.eve.shift_event` for Suricata). See P1 results.

## P1 results (2026-11-02, laptop, Docker 29.1.3)

- **Virtual time:** with libfaketime preloaded, no Wazuh 4.14 manager daemon starts, and nothing is logged. This happens at every offset, including +0, with both Debian's 0.9.10 and 0.9.12 built from source. Decision: capture on the real clock and shift at export. Intervals are preserved exactly, so frequency rules are unaffected. Syslog stamps inside `full_log` and `predecoder.timestamp` are rewritten (the year is inferred from the record time), and so are ISO-8601 stamps.
- **Wazuh readiness** means these six daemons are running: analysisd, remoted, authd, wazuh-db, monitord, modulesd. Others (clusterd, maild, agentlessd, integratord, dbd, csyslogd) are off by default and always report "not running".
- **Cold start:** the agent restarts once after the manager pushes shared config, and log lines written during that restart are skipped. Canaries are therefore re-emitted until seen, both in the spikes and in the deploy health gate.
- **Network:** a router container between Docker bridges works on Docker 29.1.3 in every mode tried (internal, nat, nat-unprotected, routed), so the compiler keeps `internal: true`. Earlier failures were in the spike itself: `fwd` is an nftables keyword, and `python3-minimal` has no `http.server`.
- **Suricata:** one sensor in the router namespace sees each forwarded flow on both interfaces. De-duplication by community_id leaves exactly one record per connection. Kernel drops are 0.

## Generator (P2)

- **IP plans are sampled per enterprise** (10.x 60%, 172.16-31 25%, 192.168 15%), excluding 10.200.0.0/14 (Docker pools), 172.17/16 (docker0) and 192.168.0-1. The internet zone uses a /24 inside 198.18.0.0/15. Specs stay lane-independent; the P7 scheduler refuses to run two scenarios with overlapping subnets on one machine.
- **Wazuh agent name = hostname** (realistic). Provenance comes from Compose project labels, never from names visible in telemetry.
- **Zone networks are Docker `internal` bridges** (no real-internet egress). Containers get `IRIS_GATEWAY` + NET_ADMIN and route through the router container.
- **Hostname and username styles vary per enterprise** (4 styles each) so naming is not a generator fingerprint.
- Every provider service gets at least one consumer (no orphan databases); the container cap (S 14, M 20, L 26) drops optional roles in a fixed order.
- Externals (1-2 clients, 1 attacker node, 60% a background scanner) exist in every scenario, including quiet ones, so "an attacker container exists" is never a signal.

## GRC generator (P5, part 1)

- **Reality depends only on enterprise seeds** (org, identity) and spec facts; seed_grc changes only style, noise and flaws. Tested.
- 32 controls in `configs/catalog/controls.yaml`, each with a reality test; controls with no applicable asset are dropped as not applicable.
- Risks come from 8 templates; likelihood counts attackable weaknesses, exposure and missing controls; impact is the highest true criticality; residual = inherent x control factor (floor 0.4). Formula version `grc-0.1.0`.
- Noise kinds (bounded, unledgered): criticality off by one level, missing owner, business-unit spelling variant, residual risk off by one level. Rates by maturity in `recorded.py`.
- Flaws are drawn by **detectability class first** (DC1 30%, DC2 40%, DC3 20%, DC4 10%); measured on 1,000 enterprises: 31/39/19/11. Clean-scenario shares measured: high 45%, medium 33%, low 14%.
- 12 flaw modules in v0. L5 compound flaws and KPI reports come in v1.1.
- The diff audit is independent of the mutation log and found two real module conflicts during development; 0 failures over 2,000 enterprises since.

## GRC timeline (P5, part 2)

- **Reality events** depend only on the org sub-seed, reality and spec facts, never on seed_grc (tested). v0 has two kinds. An exception expires when its `valid_until` falls inside the calendar. With P = 0.35 one business application takes on another business service, and its true criticality goes up by one. That change lands before the last episode so at least one episode sees it.
- **Catching up** uses the grc sub-seed. Change management re-assesses at once with P 0.10, 0.30 or 0.60 (low, medium or high maturity), 1-7 days after the evidence appears. Otherwise periodic reviews follow the style cadence. A review is skipped with P 0.40, 0.20 or 0.08, and a held review fixes each pending item with P 0.60, 0.80 or 0.95. A review is recorded 0-3 days after it is held. It also refreshes risk review dates and the assessment dates of about half the controls.
- An open pending item is a **timeline flaw**: L4, DC3, `origin: timeline`, active from when its evidence is visible until it is fixed. Modules: `exception.expired_in_use`, `asset.criticality_stale`, `risk.impact_stale`. Objects that carry a baseline flaw are never touched by the timeline, so baseline flaws stay active for the whole scenario.
- `snapshots/context_history.jsonl` is append-only and ordered by `recorded_at`. Asset changes edit the business-context record. Applying a change sets the record's `recorded_at` to the change's `recorded_at` and its `valid_from` to the change's `effective_at`. `previous` holds the values before the change.
- `snapshots/asof/<episode_id>.json` holds the recorded registers plus the change history up to the episode start. The top-level `grc/*.json` files are the registers at calendar start. The harness exposes `context_history.jsonl` only up to the current episode.
- Hidden: `truth/grc_timeline.json` (events, items, reviews), `truth/asof/<episode_id>.json` (active flaw IDs, open items). The flaw ledger holds baseline and timeline flaws.
- Measured on 1,000 enterprises (2,493 episodes): 0 future leaks; on average 1.7 baseline and 0.28 timeline flaws active per episode. Episodes with no active flaw: high 37%, medium 33%, low 8%.

## Posture (P5, part 3)

- **Real CVEs, dated visibility.** Each image is scanned once with Trivy against one pinned DB snapshot (reference `trivy-db`), and the scan is cached per image digest in `$IRIS_DATA/cache/posture/`. A scenario never invents CVEs; it only decides when each one becomes visible.
- **Trivy 0.76.1, hardened.** Trivy 0.69.4 and the Docker images 0.69.5-0.69.6 were compromised in March 2026 (CVE-2026-33634). We pin an exact version and record the tool image digest in every cache entry. Scans run with `--network none` and no Docker socket: the image comes in as a `docker save` tarball and the DB is read offline. Only `iris posture db` uses the network.
- **Scanner reality follows GRC reality.** The real state of CTRL-VUL-001 sets the scanner. Implemented means every 7 days on about 95% of in-scope assets; partial means every 30 days on about 60%; missing means no scanner and no findings. Routers and IDS sensors are out of Trivy's scope. CTRL-INV-002 sets SBOM coverage: implemented 100%, partial 50%, missing none. A "paper" vulnerability-scanning control therefore has visible counter-evidence.
- **Date gate.**
  - A finding at scan time S lists only CVEs published on or before S. CVEs with no publication date are never shown, and non-CVE advisory IDs (`TEMP-...`) are skipped.
  - Enrichment at as-of T uses KEV entries added by T and the latest monthly EPSS snapshot on or before T. If there is no snapshot, EPSS is omitted. `modified_at` is blank when it falls after T.
- **Known approximations** (also listed in hidden `posture_reality.json`): `fixed_version` and CVSS come from the pinned DB and may postdate the scan. Package versions are those of the built image, not of a dated distribution snapshot; dated Debian snapshots are a v1.1 option.
- `scanner_findings.jsonl` holds the latest scan per asset before each episode. `cve_enrichment.jsonl` has one row per CVE and episode (`as_of` = episode start). The as-of snapshots carry the per-episode slice. Components are one per service plus a `base_system` component per recorded asset; their finding links use the scan visible at episode 1.
- Recipe images must install services from distro or vendor apt/rpm repositories so the package database knows them. Software built from source is invisible to Trivy, which is realistic but must be deliberate.
- References: `cisa-kev` (date-gated by `dateAdded`) and the EPSS series `epss-YYYY-MM-01` from 2025-04 to 2026-11. Registry entries with `series_dates` expand to one pinned file per date.

## Packages, D6 key and the first baseline (P6, part 1)

- **Layout:** `scenario-<scenario_id>/visible/` (Engine input, mounted read-only) and `.../hidden/` (manifest, recipe, truth, evaluation key, generated weaknesses). Packages are immutable: rebuilding one means deleting it first.
- **Context packages first:** enterprise (organization, assets, topology, identities, services, components), GRC, timeline, as-of snapshots, and posture when scans are cached. `enabled_sensors` is empty and the data tier is `context` until telemetry and episode bundles arrive (P6, part 2). D6 can already be trained and evaluated on them.
- **Recorded topology:** zone members are the assets in the recorded inventory, so shadow assets are missing and ghost assets are listed. Workweek is Sunday-Thursday for Riyadh, Kuwait, Qatar and Bahrain, Monday-Friday elsewhere.
- **Integrity:** SHA-256 per file, Merkle root over the visible files, `package_id = pkg-` + the first 12 hex of that root. The visible plane is byte-deterministic per seed (tested). The hidden manifest holds the real creation time, seeds, group_id, versions of every generator part and split hints.
- **No-peek audit (`iris package verify`):** visible bytes must not contain sub-seeds, group_id, flaw, event, item, review or weakness IDs, image names, compose project names, or the words maturity, true_criticality, attackable, evaluation_key, truth/. Every known visible file is validated against its v2.0 model.
- **D6 reference key** (`hidden/evaluation_key/d6/<episode_id>.json`): the flaws active at the episode start. Matching is on the entity key, and assets also match by hostname or IP, since shadow assets have no inventory ID. Records changed by noise are tolerated, so a claim on one is a "noise claim", not a false positive. A confident claim on a DC4 flaw is "unsupported", counting neither as a hit nor a false positive.
- **D6 metrics:** recall per DC class and overall over DC1-DC3, precision, type accuracy, harm-weighted recall (high 3, medium 2, low 1), false-alarm rate on clean episodes, and Brier score.
- **Rule baseline** (`iris.engine.baselines.d6_rules`, visible plane only). Measured on 300 packages (758 episodes):

  | Measure | Result |
  | --- | --- |
  | DC1 recall | 99.2% |
  | DC3 recall | 99.5% |
  | DC2 recall | 9.5% (needs telemetry or posture) |
  | Precision | 89% |
  | Type accuracy | 94% |
  | Clean-episode false alarms | 4% |
  | Unsupported DC4 claims | 0 |

  These numbers confirm the detectability classes behave as designed. The learned D6 model must beat this baseline, mainly on DC2.
- **Import boundaries added:** the Engine may not import the packager or `iris.references.intel` (current intel would leak the future), the evaluator scores key files without importing the generator, and the oracle never imports the evaluator.

## Live range (P2, part 2)

- **Live build matrix** (`configs/catalog/live.yaml`, used by `SampleOverrides(live=True)`): Debian 12, compact three-zone archetype, size S.
  - Recipes, at the versions Debian 12 ships: nginx 1.22.1, OpenSSH 9.2p1, PostgreSQL 15 (major line; exact versions are recorded in the image and by the scanner), Unbound 1.17.1, the shop app 0.3.0, Wazuh 4.14.9.
  - Roles are kept only when every service they need has an image, so mail, directory, file and backup servers wait for P7.
  - Weaknesses come only from the 12 modules the images realise.
- **One node image** (`images/node/debian-12`) for every role, with a `RECIPES` build argument per compiler image tag.
  - Packages come from the distribution, so the scanner sees them.
  - The base layers, including a vendor deploy key, are shared by every node built on a machine, which is what makes `auth.shared_ssh_key` a real shared key.
  - Configuration arrives only as environment variables written by the compiler (`node_env`): services, upstreams, database clients, users, planted weaknesses, DNS records. `node-init` logs every step as `ok` or `FAIL`.
- **Real weaknesses:** sshd password and root login, the shared key, NOPASSWD sudo, the postgres default password, pg_hba open to all, nginx `/admin` exposed, weak TLS. The shop app switches its SQL injection, path traversal, IDOR and role-update flaws by configuration, so unplanted flaws are really absent.
- **Credentials** (`iris.generator.secrets`): deterministic per scenario, 20-character random passwords. A weakness makes the matching credential weak, using a short list of common passwords (for example `postgres/postgres`). They exist only in the run directory and hidden truth.
- **DNS:** each enterprise has its own resolver (Unbound) with `<org>.lan` A and PTR records. Nodes write `resolv.conf` themselves, so Docker's embedded DNS (and container names) never answer.
- **Routing:** the router container has no default route and loads `router.nft`. The Wazuh manager image gained `iproute2` to route back to agents in other zones through the router.
- **Health gate (`iris.live.health`)**, run during the hidden pre-roll:
  - containers running, init finished with no failed step;
  - router policy loaded and no default route;
  - every port listening, internal DNS resolving, app reaching its database;
  - internet to web allowed and internet to database blocked, no egress to a public IP;
  - Wazuh manager ready, monitored agents Active and blind spots without an agent;
  - a syslog canary per agent arrives in the archives;
  - Suricata sees the canary HTTP/TLS exactly once after de-duplication;
  - every planted weakness verified, and spot checks prove unplanted ones absent.
- **Run-scoped teardown:** every container, network and volume carries `iris.project`. Teardown saves container logs, then proves no labelled object is left. A run refuses to start while another iris project exists on the lane. Each run is driven by the state machine PLANNED → BUILDING → DEPLOYING → CHECKING → HEALTHY/UNHEALTHY → TEARING_DOWN → TORN_DOWN (or KEPT/FAILED), recorded in `state.json`.
- **P2 exit gate:** `iris range gate --count 20` must deploy, pass health and tear down cleanly for 20 seeds in a row. Seeds whose subnets overlap Docker networks already on the machine are reported as `SKIPPED_CONFLICT` (a lane problem). Lane machines should set Docker `default-address-pools` to 10.200.0.0/14, which the sampler already avoids.
- **First gate run (2026-11-03):** 16/20 passed.
  - Two failures had weak TLS planted on non-TLS websites. Fixed: the weakness catalog now has `requires: tls`, catalog version 0.2.0.
  - Two collided with other Docker projects' 172.18 and 172.21 networks. These are now detected before deploy.

## SOC (P3, part 1)

- **Speed:** every container gets `init: true`, so the Wazuh manager stops on SIGTERM. Teardown drops from 22 s to a few seconds. Health checks now poll instead of sleeping. `iris range up --light` is the production gate: containers, init, router, ports, Wazuh, canaries and Suricata. The full gate stays for acceptance.
- **SOC profile** (`iris.generator.soc`, monitoring sub-seed):
  - **Reality.** Each monitored host collects its standard sources (`auth` always) with probability 0.97, 0.88 or 0.70 by maturity.
  - FIM follows the real state of CTRL-LOG-003 (implemented means on, partial about half, missing off).
  - The SCA baseline follows CTRL-CFG-001, on servers only.
  - Alert retention is 365, 180 or 90 days; archives are retained with probability 1.0, 0.5 or 0.0.
  - **Belief.** The visible `soc/soc_inventory.json` lists the standard sources per role and the coverage statements. The statements repeat the *recorded* control states, so a paper control becomes a false SOC belief.
  - **Gaps.** A source believed but not collected, or FIM/SCA claimed by a recorded "implemented" control but not active, is a hidden SOC gap (`truth/soc_gap_ledger.jsonl`, DC2).
- **Agent configuration** is derived from that reality: the compiler passes `IRIS_LOGSOURCES` (format and path), `IRIS_FIM` and `IRIS_SCA` to each monitored node.
- **SCA baseline `org_baseline`** is written per node from its recipes. Each check carries `org_controls: [CTRL-...]`, so SCA results are visible evidence about the real state of the recorded controls (DC2 for D6). Checks cover NOPASSWD sudo, SSH password auth, root login, the vendor deploy key, pg_hba open to all, admin paths and legacy TLS.
- **Rule library** `configs/soc/local_rules.xml` (org-rules-0.1.0, IDs 100100-100199): 14 rules on the shop app's JSON events, 8 of them tagged with ATT&CK (T1110, T1110.001, T1190, T1078, T1087, T1213, T1098, T1083). It is mounted read-only into the manager, and its SHA-256 is recorded in compiled.json. Built-in Wazuh rules cover sshd, nginx and PostgreSQL. The app logs the submitted user name (`submitted`), which is how SQL-injection logins are detected.
- **Rule tests:** `iris soc rules` (IDs, parents, ATT&CK tags against the pinned release) and `iris soc logtest` (10 cases through `wazuh-logtest` in a throwaway manager, frequency rules included).
- **Exporter** (`iris.generator.export`):
  - The episode window is [observe start, observe end) on the real clock. Before it is pre-roll and after it is drain; both are hidden (`preroll/<episode_id>/`).
  - Inside the window, records are shifted to the virtual start. EVE is de-duplicated before splitting.
  - Health-gate canaries (`healthcheck` syslog tag, `/hc` HTTP) are never visible.
  - Archives are visible only when the SOC retains them.

## Activity and detection verification (P3, part 2)

- **Scripted episode activity** (`iris.live.activity`, traffic sub-seed): steady benign business traffic (browsing, logins, orders) plus a set of labelled, known-detectable actions. Every action carries ground truth: label (benign/malicious), actor, target, ATT&CK technique and the Wazuh rule IDs a correct SOC should raise.
- **Detections are grounded in truth.** A malicious action is scheduled only when the enabling weakness is actually in the scenario's weakness ledger, so "what should be detected" is never assumed. Password-guessing (rule 100102) is the one action detectable on any shop, since it needs no planted flaw.
- **Commands are built with `shlex.quote`** and run from the external client/attacker nodes against the shop's own endpoints (black-box, like a real SOC validation).
- **Recorder** (`iris.live.record`): marks the observe window, runs the plan with small gaps, lets detections settle, collects raw alerts/archives/eve, and runs them through the exporter. `match_detections` (a pure, tested function) checks that every expected rule fired.
- **Outputs** go to the run directory's `episodes/<episode_id>/`: shifted telemetry (visible-shaped), `activity_truth.json` and `detections.json` (hidden: expected vs observed rule IDs, matched, missed).
- **New commands:** `iris range record --master N` (deploy, record, verify, tear down) and `iris range detect-gate --count N` (P3 exit gate: N seeds whose expected detections all fire).
- **Field mapping:** Wazuh's JSON decoder renames the app's `user` field to `dstuser`, so correlation rules group on `dstuser` (not `user`); the `src_ip` field keeps its name. Ruleset `org-rules-0.1.1`.
- **IDOR is harvesting, not enumeration:** when the IDOR flaw is present the attacker successfully reads other customers' orders, so it is detected as data harvesting (100109, T1213). The enumeration rule (100107) fires only when the flaw is absent. The attacker registers its own account and signs in before exploiting IDOR or self-promotion, since it cannot use the seeded customers' passwords.
- **P3 exit gate:** expected detections fire for every recorded episode across the gate seeds.

## Addressing

- Docker's bridge occupies the **last usable address** of every zone subnet (.254 in a /24). The spec validator rejects any asset or gateway on it; zone gateways (our router) use .1.

## Metrics

- Six CSF functions weighted equally (1/6). DETECT and RESPOND are 50% control-based, 50% operational.

## Engine contract (v2.0) highlights

- Security maturity is not in `organization.json` (it is a D7 target).
- `posture/generated_weaknesses.json` and `activity/` are hidden.
- An ASSESSED decision must cite visible evidence (event IDs or context refs); D4 has at most 3 controls.

## References (pinned in `configs/references/`)

- ATT&CK Enterprise **v20.0** (13 Oct 2026); Linux, Network, Network Devices, Containers platforms. Tactic names come from the pinned data (v19 split Defense Evasion into Stealth and Impair Defenses).
- NIST SP 800-53 Rev. 5 (OSCAL) is the control spine; crosswalks to CSF 2.0, ISO/IEC 27001:2022 Annex A (IDs and our short names only), CIS Controls v8.1 (CC BY-NC-ND 4.0: IDs only).
- CTID Mappings Explorer for control-to-technique links, re-checked against v20. D3FEND for D4 vocabulary. CWE, CAPEC, CVE/NVD, CVSS, EPSS, KEV, all date-gated.
- Mappings carry provenance (`official` or `ours`) and review status; ours need two reviewers. Upgrades only between releases.

## Machines and paths

- Code: `~/work/iris`. Data: `/srv/iris` via `IRIS_DATA`. Same layout on lab machines.
- Laptop (i7-1355U, 14.8 GiB): development, golden sample, one live lane. Lab machines (32 GB): three lanes each, fragment factory and live Gold sets.
- Live episode profile: about 14.5 min (2.5 warm pre-roll, 10 observed, 1.5 drain, 0.5 snapshot).
