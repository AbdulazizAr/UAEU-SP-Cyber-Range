# INPUT Part 1: Pseudo-Random Realistic Enterprise Generation

Status: DRAFT for discussion. Scope is only the generation of the scenario environment (topology, nodes, services, vulnerabilities, traffic, attackers, Wazuh). The virtual clock, GRC generation, truth/evaluation planes and scenario packaging are separate topics for later.

Conventions used in this document:
- **[PROTO]** = already demonstrated in the PF prototype (M1 to M10).
- **[NEW]** = not built yet, proposed here.
- **[DECIDE]** = needs a decision from the team.
- **[MEASURE]** = a claim that should be verified with real numbers before we rely on it.
- Algorithm and tool names are cited from memory. Versions and current maintenance status were not re-verified for this write-up.

---

## 0. The core idea in one paragraph

We do not generate "a network". We generate a **Scenario Spec**: a small declarative file (YAML/JSON) that completely describes one enterprise (zones, hosts, OS images, services, users, weaknesses, traffic schedule, attackers, monitoring config). The spec is produced from a **master seed** by a layered pseudo-random sampler that respects constraints. A separate deterministic **compiler** turns the spec into Docker objects (networks, containers, config files). Same seed + same generator version = same spec = same environment. Everything else (health checks, traffic, attacks, packaging) hangs off the spec. This separation is what makes thousands of scenarios, replication and alteration by seed possible.

```text
master_seed
   -> sampler (constraint-aware, layered, seeded sub-streams)
   -> Scenario Spec   <- the single source of truth for "what to build"
   -> validator       (is it internally consistent and affordable?)
   -> compiler        (Docker networks, containers, configs, Wazuh groups)
   -> deploy + health gate
   -> traffic + attacks (driven by the spec)
```

### 0.1 Seed hierarchy (so alteration is possible)

One seed is not enough. If everything is drawn from one random stream, changing one thing (say, adding a host) shifts every random number after it and changes the whole scenario. Fix: derive independent sub-seeds per module.

```text
master_seed
  |- seed_org        (industry, size, maturity)
  |- seed_topology   (zones, host counts, IP plan)
  |- seed_services   (which services, versions, configs)
  |- seed_identity   (users, groups, privileges)
  |- seed_weakness   (which weaknesses go where)
  |- seed_traffic    (personas, schedules, noise)
  |- seed_attack     (attacker profiles, paths, timing)
  |- seed_monitoring (Wazuh coverage profile, rules enabled)
```

Each sub-seed = hash(master_seed, module_name, generator_version). Rules:
- Changing only `seed_attack` gives the same enterprise with different attacks (very useful for ML: same environment, different behaviour).
- Changing only `seed_traffic` gives the same enterprise with different background noise.
- Every random choice inside a module uses a named sub-stream, so adding a new choice later does not silently change old scenarios.
- The generator version is part of the hash, so we know exactly which code reproduces which scenario. Old versions must stay runnable, or the spec file itself is stored as the replication artifact (recommended: store both seed and the resolved spec).

[DECIDE] Store the resolved spec in every scenario package (recommended), so replication does not depend on old code still working.

---

## 1. Network topology

### 1.1 What is out there (and what is actually relevant)

Honest summary: there is no off-the-shelf algorithm that "replicates real enterprise networks". The academic topology generators target the wrong thing, and the practical cyber range tools use templates.

| Approach | Examples | What it does | Useful for us? |
|---|---|---|---|
| Internet / ISP topology generators | GT-ITM (transit-stub), BRITE, Inet, Waxman model | Router-level graphs for WANs and the Internet | Mostly no. Wrong scale and no hosts, services or policy |
| Generic random graph models | Erdos-Renyi, Barabasi-Albert, small-world | Statistical graph shapes | Not directly. Enterprises are not scale-free graphs; they are hierarchical with policy |
| Stochastic Block Model (SBM) | Standard in network science | Nodes belong to groups; connection probability depends on group pair | **Yes, as a component**: zones are blocks, and the "who may talk to whom" matrix is the block probability matrix |
| Reference architectures | Purdue model, zero-trust zoning, three-tier web, DMZ patterns | Human-designed layouts | **Yes**: the backbone of our archetypes |
| Attack-graph tools | MulVAL, NetSPA, Caldera planner | Given a network and vulnerabilities, compute attack paths | **Yes, for the attacker side** (Section 7), and for validating that a scenario is attackable |
| RL network-attack simulators | NASim (Network Attack Simulator), CyberBattleSim, CybORG | Random network generators for training attackers | Ideas worth borrowing (host/subnet/service sampling), but they are abstract simulators, not real telemetry |
| VM/lab scenario generators | SecGen, GOAD, Ludus, Vagrant-based labs | Build vulnerable machines and labs | Closest in spirit to our job; good source of ideas for "weakness modules". Mostly VM-based and heavy |

### 1.2 Our approach: archetype grammar + constrained sampling [NEW, builds on PROTO]

Instead of one clever algorithm, combine three simple ones. Each does a job it is good at.

**Step 1: Organization profile.** Sample: industry (retail, hospital, finance-lite, university, SaaS, manufacturing-lite...), size tier (S/M/L), security maturity (low/medium/high), remote-work share, cloud dependence flag. [PROTO: retail, hospital; maturity; asset counts.]

**Step 2: Zone set from an archetype grammar.** Each industry/size picks a zone archetype, with optional zones added by probability:

```text
Always:     INTERNET (external), DMZ, USERS, SERVERS
Often:      MGMT/ADMIN, DATA (databases), GUEST
By profile: OT/INDUSTRIAL (manufacturing), MEDICAL (hospital), PCI (retail),
            DEV/CI, BACKUP, VPN-REMOTE
```
[PROTO: compact three-zone, four-zone routed, segmented five-zone.]

**Step 3: Hosts per zone from distributions.** Role counts are drawn from ranges tied to size tier (e.g. M-size: 2-4 web, 1-2 API, 1-3 DB, 1 mail, 1-2 DNS, 1 directory, 1 file, 1-2 workstation representatives...). Ranges are documented assumptions, not measured truth [DECIDE: who reviews these ranges? Ideally use published sources such as vendor reference architectures and mark them as assumptions].

**Step 4: Policy matrix (the SBM part).** A zone-by-zone matrix of allowed flows with probability of exceptions, depending on maturity:

```text
maturity low:    flat-ish, many allowed paths, some "any-any" exceptions
maturity medium: standard zoning, a few exceptions
maturity high:   strict zoning, deny by default, jump host for admin
```
[PROTO: restricted vs exception policy, guarded router.] This matrix becomes router/firewall rules and also becomes the ground for attack-path computation.

**Step 5: Dependency graph.** Services depend on other services, and this is where realism comes from: web -> API -> DB; all hosts -> DNS, NTP, directory/auth; app -> mail relay; everything -> monitoring/log collector; backup server -> file server and DB. The sampler creates hosts, then wires dependencies. Orphaned services (a DB nobody calls) are rejected by the validator unless intentionally "forgotten" (a legitimate weakness type).

**Step 6: IP plan.** A deterministic allocator: pick a private supernet per scenario lane, split with VLSM into per-zone subnets sized to host count, assign addresses. The actual addresses do not matter (as you said); what matters is that subnetting is consistent, no overlaps, and parallel scenarios do not collide (see 1.4).

**Step 7: Validate.** Reject and resample (with a new derived sub-seed, logged) if: unreachable required paths, overlapping subnets, missing mandatory roles (no DNS), resource estimate over budget, or no feasible attack path when the scenario is meant to contain an attack.

### 1.3 What we keep and what we drop (to stay lightweight)

| Real-world thing | Our representation |
|---|---|
| Switches, VLANs, access/distribution layers | **Dropped**. One Docker bridge network per zone *is* the switch. Documented in the topology as `switch_group` metadata so GRC/visual layers can still display it |
| Routers | Linux container with `ip_forward` and nftables/iptables. Optionally FRR if we want routing protocols later [PROTO: guarded router] |
| Firewalls / NGFW | Same router container with stateful nftables rules; zone-pair policy comes from the policy matrix |
| IDS | Suricata sensor container on a mirrored/tapped segment [PROTO] |
| WAF / reverse proxy | nginx (+ModSecurity) container in DMZ |
| VPN gateway | WireGuard or OpenVPN container |
| Hundreds of identical workstations | 1-2 representative workstation containers + `population_size` metadata + synthetic user population in directory |
| Wi-Fi, printers, IoT | Dropped by default; optional "noisy device" containers (printer = CUPS, camera = tiny HTTP service) if useful |
| Windows hosts / AD | Not simulated. Represented by Linux equivalents (Samba AD-compatible DC or OpenLDAP + Kerberos) with the mapping documented |

### 1.4 Parallel lanes and isolation [NEW]

If we run several scenarios at once (the prototype was almost entirely serial and the cost was the fixed infrastructure overhead), each parallel "lane" gets its own address pool and its own Docker network name prefix (`s<id>_users`, `s<id>_dmz`...). No scenario shares a network with another. This is a hard rule from the prototype lessons: never contaminate one run's telemetry with another's.

### 1.5 How we make sure the topology is "realistic enough"

There is no measurable ground truth for "realistic". Honest approach:
1. Archetypes are derived from published reference architectures, and every parameter range is written in a config file with a source/assumption note.
2. A set of **topology invariants** is checked automatically (every zone has a gateway, every host has DNS, DB hosts never in a user zone, admin access goes via MGMT, etc.).
3. A small review by one or two people with real network/SOC background on a sample of generated topologies, scored on a rubric. Report the result.
4. We claim "plausible enterprise-like", not "replicates real enterprises".

---

## 2. Making sure every node actually works

### 2.1 What a "node" is

Every endpoint is a Docker container (a lightweight Linux userland), as in the prototype. Layered image model to stay light:

```text
Layer 1  base OS image         (debian / ubuntu / alpine / rocky...)  -> shared, cached
Layer 2  service layer         (nginx 1.18, postgres 13, postfix...)   -> shared, cached by (service, version)
Layer 3  monitoring layer      (Wazuh agent, optional auditd)          -> shared, cached
Layer 4  configuration         (injected at start via mounted files)   -> per scenario, tiny
Layer 5  data seed             (users, tables, files)                  -> per scenario, small
```

Only layers 4 and 5 are different per scenario, so building thousands of scenarios does not mean building thousands of images. Images are pinned by digest and stored in a local registry. [PROTO: pf/network-runtime, pf/suricata-sensor images exist.]

### 2.2 The honest limits of containers

- Containers share the host kernel. Kernel CVEs and kernel-level attacks cannot be reproduced; userland package CVEs can. [Already documented in the prototype report.]
- A container is not a full OS (often no systemd). We use a small process supervisor (s6, supervisord or tini + a script) per container [PROTO: collector supervisor]. If a service truly needs systemd or a full init, use system containers (LXC/Incus) for that node type only.
- Optional upgrade path for high-realism "gold" runs: microVMs (Firecracker/QEMU) for a few nodes, at a clear RAM/boot-time cost. Not for the default path. [DECIDE: needed at all?]

### 2.3 The health gate (nothing starts until the environment is proven working) [PROTO partly, NEW formalization]

A staged check, run automatically after deploy. Any failure = scenario discarded and cleaned up, failure recorded with the seed (so bad seeds can be analysed), then regenerated with a derived seed or retried once.

```text
Stage 1  containers up, no crash loops
Stage 2  network: every host has its IP, default gateway reachable,
         expected cross-zone paths work, forbidden paths are blocked
         (policy test matrix derived from the spec)
Stage 3  DNS: names resolve inside the range
Stage 4  services: each service passes its own health probe
         (HTTP 200 on a known route, DB accepts a test query,
          SMTP banner, SSH banner, LDAP bind...)
Stage 5  monitoring: Wazuh agent connected and authenticated [PROTO]
Stage 6  telemetry canary: generate one harmless known event per host
         and confirm it arrives as a Wazuh archive/alert and, where
         relevant, a Suricata flow
Stage 7  baseline stability: short quiet period, no unexpected restarts
```
Stage 6 is the one that most often catches silent problems (agent connected but logs not being collected). The prototype's M2 rule-chain problem is the typical example.

### 2.4 Internet connectivity

Three different meanings, handled differently:

| Need | Approach |
|---|---|
| Build time: download packages, images | Allowed. Done once and cached (apt/pip/npm mirror cache, local registry). Pin exact versions or use Debian/Ubuntu snapshot archives for historical versions |
| Run time: "external users" and the "Internet" zone | **Simulated** inside the range: an INTERNET zone containing external client/attacker containers and fake external services (DNS, mirror, a "SaaS" endpoint) |
| Run time: real outbound Internet from nodes | **Off by default.** Reasons: reproducibility (the Internet changes), safety (attack tooling must never leave the range), and packet-capture noise. Where a scenario needs "Internet access", route through a controlled egress proxy container that serves only cached/simulated content |

Live CVE database access is the separate optional feature in the original spec; it happens outside the range at the posture/enrichment stage [PROTO: M7 NVD/KEV/EPSS snapshots with dates], never from inside scenario nodes.

### 2.5 Subnetting and addressing check

Docker user-defined networks with explicit `--subnet`/`--gateway`, static IPs via IPAM, and a router container joined to every zone network. Inter-zone traffic must pass through the router (hosts have no direct attachment to a foreign zone). This is the M3 design [PROTO]. The validator checks that no host is attached to two zones except gateways.

---

## 3. Services: how they are configured, varied and made vulnerable

### 3.1 The Service Recipe (the unit of customization) [NEW formalization]

Every service type is a recipe file, not a hand-built container. A recipe contains:

```text
id, category, supported OS families
version catalog        (pinned list of installable versions + source: apt snapshot / image tag / upstream tarball)
config template        (Jinja2 with sampled parameters)
parameters + ranges    (port, worker count, TLS on/off, auth type, log verbosity...)
dependencies           (needs DNS, needs DB, needs directory...)
default accounts       (generated, never real secrets)
data seeder            (sample content, tables, users)
health probe           (Section 2.3, Stage 4)
log format + Wazuh decoder mapping
normal-usage generator hooks (what clients do with it; Section 6)
weakness hooks         (which weaknesses can be applied; Section 3.4)
SBOM source            (package manager database or image scan)
```

Adding a new service = adding a recipe, with no changes to the generator core. That is how the catalog grows to "lots of others".

### 3.2 Initial service catalog (all Linux-friendly)

| Category | Candidates |
|---|---|
| Web | nginx, Apache httpd, Caddy |
| Application | Python (Flask/FastAPI) sample apps, Node/Express, Tomcat/Java app, PHP-FPM app |
| Database | PostgreSQL, MySQL, MariaDB, Redis, MongoDB (older versions optional) |
| Mail | Postfix + Dovecot, with a webmail optional |
| DNS | BIND, Unbound, dnsmasq |
| Directory/auth | OpenLDAP + Kerberos, Samba AD DC (AD-compatible behaviour, with limitations), FreeIPA if affordable |
| File | Samba, NFS, SFTP/vsftpd |
| Remote access | OpenSSH, WireGuard, OpenVPN, bastion/jump host |
| Proxy/gateway | Squid, HAProxy, nginx reverse proxy + ModSecurity |
| Dev/ops | Gitea, Jenkins, a registry, CI runner |
| Backup | restic/rsync/borg jobs |
| Monitoring | Wazuh agent (every node), Suricata sensor, a log collector, a vulnerability scanner container |
| Printing/misc | CUPS, NTP, syslog relay |

Start with roughly 10 recipes done well (those already in the prototype: web, API, DB, workstation, admin/identity, file, router, collector, sensor) and grow from there. [DECIDE: the order of expansion.]

### 3.3 Can we pull real packages from the Internet and install them in the node? Yes, with discipline.

- **Distro packages with exact versions**: Debian (snapshot.debian.org) and Ubuntu archives let us install older, genuinely vulnerable package versions. This is the cleanest source of real version-based CVEs.
- **Official container image tags** of old versions (nginx:1.18, postgres:12...) give pinned older userland quickly.
- **Upstream tarballs / source builds** for versions not packaged. Slower to build, cached by digest, and recorded in the SBOM.
- **Dependency conflicts**: the sampler is constraint-aware (a service version is only offered on OS families where it installs). A pre-flight "build test" per (service, version, OS) combination is run once and cached; a combination that fails is blacklisted so scenarios never roll it.
- Everything is installed at **build time**, never fetched at scenario start. Scenario start is only config + data injection. That keeps startup fast and offline-capable.

### 3.4 Vulnerabilities: three kinds, all documented automatically

| Kind | How it is created | Example | Proof level |
|---|---|---|---|
| **A. Version-based (real CVE)** | Install an old package version | nginx / OpenSSL / log4j-era library version | Present, but *not* proven exploitable. Class: posture evidence (matches prototype rule: scanner finding != exploitation) |
| **B. Configuration weakness** | A "weakness module" applied to a recipe | weak/default credentials, missing MFA, anonymous SMB, world-writable files, exposed admin panel, weak TLS, DB listening on all interfaces, over-privileged accounts, unrotated keys | Provable by a check script |
| **C. Application-logic flaw** | Parameterized flaws in our own small sample apps (and optionally known intentionally vulnerable apps) | SQL injection login, IDOR object access, broken privilege update [PROTO: login_injection, object_access, privilege_update], path traversal, command injection | Provable by running the exploit template |

Each weakness module has a fixed schema:

```text
weakness_id, kind (A/B/C), applies_to (recipes/versions)
injection steps (idempotent, parameterized)
verification check (script that proves it is really present)
exploit template link (if any) and what telemetry it should produce
CWE / CVE / CIS-benchmark mapping
enabling control (what control, if present, would have prevented it)   <- feeds GRC/control logic
```

Every applied weakness is written to the hidden truth plane **and** (for the parts a scanner would legitimately find) shows up in scanner output. The *difference* between "what exists" and "what the scanner/sensors reported" is intentional and valuable. Important consequence: for a weakness we claim is *attackable*, the verification check must pass at deploy time. Otherwise we would label scenarios as vulnerable when the exploit does not actually work.

### 3.5 SBOM and CVE scanning

- SBOM (CycloneDX) per image via Syft or Trivy, generated once per image digest and reused (cheap). [PROTO: M7 did SBOM + Trivy, 3 images, 416 packages, 1023 findings.]
- Scenario SBOM = union of the SBOMs of its images + app-level dependencies (pip/npm lists from the sample apps).
- CVE scan with Trivy offline against a dated vulnerability DB snapshot, and enrichment with NVD, CISA KEV and EPSS snapshots with explicit "as of" dates [PROTO].
- Live database linkage (optional, per the original spec): the same SBOM can be rescanned later against a fresher DB to show how risk changes over real time. Outside the range, no effect on the scenario itself.

### 3.6 "Different for each, pseudo-random" without chaos

Randomization axes per node: OS family and version, service and version, port (within allowed ranges), TLS/auth settings, log verbosity, user accounts and groups, installed extra packages (noise packages), file layout, hardening level (tied to maturity), and which weaknesses it carries. Constraints keep each node coherent. Maturity governs *probabilities* (a "high maturity" org rarely has default credentials but may still have one forgotten host, which is realistic and useful).

### 3.7 Identities, privileges, keys, encryption

Generated per scenario: users and groups from a name/department generator, privilege tiers (standard, power, admin, service account), SSH key policy (key-only, password allowed, shared keys as a weakness), sudo rules, MFA state per identity (modeled as policy state, with TOTP only where a service really supports it), TLS settings (cert validity, cipher suites, self-signed vs internal CA). Passwords/secrets are generated and kept only in the hidden truth plane/private runtime files. The contract already excludes them from exported identities [PROTO]. [NEW: an internal CA container to issue certificates, so TLS looks real.] Note on the earlier mismatch found by the Engine team: usernames in telemetry and in `identities.json` must come from the same generated source, never separately.

---

## 4. Full automation (no human in the loop)

### 4.1 Pipeline as a state machine

```text
QUEUED -> SPEC_GENERATED -> SPEC_VALIDATED -> BUILT/PULLED -> DEPLOYED
 -> HEALTH_GATED -> BASELINE_RUNNING -> ACTIVITY_RUNNING -> DRAINING
 -> VERIFIED -> PACKAGED -> TORN_DOWN -> (ACCEPTED | REJECTED with reason)
```

Rules:
- Each state is idempotent and resumable from a checkpoint [PROTO: .pf state/checkpoints].
- Teardown is **run-scoped**: remove only containers/networks/agents labelled with that run's ID. Never global cleanup [PROTO lesson from M6].
- A failure records seed, spec, stage and logs, then cleans up. Failures are data: a seed that fails repeatedly is quarantined, and failure rates per recipe are tracked (a recipe failing 30% of the time is a bug to fix).
- Scenarios are rejected, not patched by hand. Humans only look at aggregate dashboards and quarantined seeds.

### 4.2 Scheduler and resources

A simple queue with a resource budget: estimate RAM/CPU from the spec before deploying (sum of per-recipe estimates), run lanes in parallel only while the budget allows. Every container gets CPU and memory limits. [MEASURE] Per-recipe RAM numbers; the prototype's hardware plan (three 32 GB machines) used planning estimates, not measurements.

### 4.3 Gold vs Bulk

[PROTO design intent] Keep the full pipeline above as the **Gold** tier (real Docker + Wazuh + Suricata). Add a **Bulk** tier later that reuses Gold-validated environments and generates schema-compatible variations more cheaply (for example, replaying/perturbing recorded behaviour). The Bulk tier must be statistically checked against Gold so it does not drift. This addresses the main cost issue seen in M8 (96 captures took hours, mostly fixed infrastructure overhead).

---

## 5. Lightweight by design (rules we follow)

- No desktop environments or GUIs. "Workstations" are headless containers running traffic agents and CLI tooling.
- Shared cached image layers; per-scenario config injected, never baked.
- Memory/CPU limits on every container; `tmpfs` for scratch where possible; logs rotated and capped.
- Collapse identical machines (1-2 representatives + population metadata).
- Wazuh manager without the heavy indexer/dashboard stack for generation (see Section 8).
- Short-lived: environment exists only for the scenario duration, then is destroyed.
- Rough scale target: 8 to 25 containers per scenario, dozens of MB to low hundreds of MB each. [MEASURE]

---

## 6. Normal traffic, noise and activity

### 6.1 Principle

Background activity is produced by **personas and schedules**, not random packets. Every action is a real action against a real service, so Wazuh logs and Suricata packets are genuine rather than faked.

### 6.2 Components

**Personas** (sampled per scenario, assigned to workstation/user identities): office worker, developer, administrator, executive, contractor, remote worker, service/batch account, external customer (web/mail), external partner (API/VPN).

Each persona has a daily schedule model:
- Arrival of actions follows a non-homogeneous Poisson process with a diurnal curve (busy mid-morning, lunch dip, quiet nights/weekends), with per-persona parameters.
- Session lengths and file/object popularity use heavy-tailed distributions (log-normal, Zipf), because real usage is not uniform.
- Actions are small state machines (login -> browse/query -> logout; SSH -> run commands -> exit; send mail; fetch file share; DB queries by app).

**Traffic agents.** A tiny script runner inside workstation/external-client containers, driven by a per-node schedule file generated from `seed_traffic`. Controlled centrally, so the same virtual-clock mechanism (separate topic) can pace it.

**System-generated chatter.** Cron jobs, backups, patch checks, NTP, DNS, LDAP binds, health checks, monitoring heartbeats, log rotation, scheduled reports.

**Noise and hard negatives (essential for a useful AI):**
- Typo logins followed by success, forgotten passwords, locked accounts.
- Authorized vulnerability scans and legitimate admin SSH sessions that look scary.
- Misconfigurations and errors: 404/500 storms, failed jobs, DNS failures, broken certificates.
- Internet background radiation: random external scanners, bots hitting web ports, brute-force-looking junk that never succeeds.
- Large legitimate transfers (backup, software updates) that resemble exfiltration.
- Sensor-side noise: occasional agent disconnects, delayed logs, dropped packets (recorded as quality facts, not hidden).

**Intensity tiers** (light/standard/busy) multiply rates [PROTO].

### 6.3 Realism limits we should state openly

- Distributions are plausible assumptions, not fitted to a real company.
- Application logs from our own sample apps are cleaner than production logs [PROTO review finding]. Mitigation: use standard software (nginx, sshd, postgres, postfix) for most logs, with our own apps limited to specific roles, and add log-format "messiness" options (multi-line stack traces, inconsistent timestamps, partial fields).
- Benign background diversity is the identified weak area [PROTO review]. It deserves the largest share of improvement effort.

---

## 7. Attackers: who, where from, what they decide

### 7.1 Attacker profiles [NEW]

A profile defines how the actor behaves, not only what they do:

```text
origin & access type:  external anonymous | external with stolen credentials |
                       insider (low priv) | insider (privileged) |
                       compromised workstation (malware) | supplier/VPN partner |
                       red team (authorized, noisy or stealthy)
skill: low / medium / high
stealth: noisy / moderate / quiet (affects rate, timing, tool choice)
goal: recon only | credential theft | data theft | disruption | persistence
persistence & patience: single burst vs slow multi-day campaign
tool set: scanner, password sprayer, web exploit scripts, SSH lateral movement, etc.
```

### 7.2 Attack library [PROTO: 3 families; NEW: expansion]

Attack **templates**, each with preconditions, steps, expected telemetry and an ATT&CK mapping (in the style of Atomic Red Team / Caldera "abilities"). Candidate list to grow toward:

```text
Recon:            port scan, service enumeration, web crawling, DNS enumeration
Credential:       SSH brute force, password spraying, credential stuffing, default creds
Initial access:   web injection [PROTO], exposed admin panel, weak VPN, phishing-lite (simulated click)
Execution/privesc: sudo misconfig, SUID misuse, privilege update flaw [PROTO], cron abuse
Lateral movement: SSH pivot with stolen key [PROTO bounded SSH], pass-the-ticket-lite, share access
Collection/exfil: object access/IDOR [PROTO], DB dump, large HTTP/SFTP transfer, DNS tunnelling-lite
Persistence:      new user, authorized_keys, cron/systemd, web shell (benign marker)
Defense evasion:  log deletion, timestomp-lite, slow-and-low
Impact:           file encryption simulator (harmless marker files), service stop
Insider:          off-hours bulk file copy, privilege abuse, USB-like transfer
C2:               harmless beacon simulator on a schedule
```

Safety rules: no real malware, no real exploit code that could be reused outside the lab, strict network isolation, no real Internet reachability from attacker containers. "Malware" behaviour is imitated by harmless simulators that generate the same system and network observables.

### 7.3 How attack endpoints and paths are chosen (the "decision") [NEW]

1. Build an **attack graph** from the generated spec: nodes = hosts/accounts/privileges; edges = actions whose preconditions are satisfied (reachable by policy matrix, weakness present, credential obtained). This is the MulVAL/NASim/Caldera planner idea, restricted to our template library.
2. Given the attacker profile (start position, goal, skill), sample a feasible path from the graph using `seed_attack`. Skill/stealth modify the weights: low skill prefers noisy known-weakness paths; high skill prefers quiet ones and may chain more steps.
3. The path becomes a **campaign plan**: ordered steps with timing, linked to the schedule (virtual clock). Plans may include failures on purpose (wrong password list, blocked by firewall) because failed attacks are still malicious truth.
4. Execution is by a controller that runs each template and records the intended action and the real outcome (success/failure, timestamps, evidence). Attackers are pre-planned from the spec at first. Reactive attackers that adapt to defenses are a later upgrade [DECIDE].
5. Every campaign must be *possible* by construction (the graph proves a path exists) but not guaranteed to be *successful* (some branches fail).

Also generated: **non-attack "look-alikes"** that exercise the same sensors (see hard negatives), and **quiet scenarios with no attack at all**, so the AI learns that "nothing happened" is a valid and frequent state.

---

## 8. Wazuh: one big shared one, or a configured one per scenario?

### 8.1 Options

| Option | How | Pros | Cons |
|---|---|---|---|
| A. Fresh Wazuh manager per scenario | Start a new manager for every run | Perfect isolation, clean state, rules per scenario trivially | Slow (startup, enrollment), heavy if repeated thousands of times, wasteful |
| B. One big persistent Wazuh for all scenarios | Agents from all scenarios enroll in the same manager; output is filtered later | Cheapest start-up | State and rule changes leak between runs; alert streams interleave; reloads affect everyone; unbounded growth; identity/time-collision risks; hard to guarantee a clean per-run corpus |
| C. **Hybrid (recommended)**: one long-lived manager *per lane*, reused across runs, with strict run isolation | Manager stays up; per-run agents with unique names (`<run_id>-<host>`) in per-run groups; rules preloaded; per-run alert/archives slices exported by agent-name prefix and time window; agents removed at teardown | Good speed, good isolation if disciplined, matches what the prototype already did (shared collector/manager with per-run enrollment and scoped cleanup) | Needs careful cleanup and verification that nothing from the previous run bleeds into the next |

[DECIDE] Choose C, and **[MEASURE]** manager startup time and memory first. If a fresh manager turns out to be cheap (it may be), A for Gold runs is the safest. The decision should come from numbers, not from guessing.

### 8.2 Do we need the indexer and dashboard?

For *generation*, no. The Wazuh manager writes `alerts.json` and `archives.json` itself, which is what the dataset needs. The indexer/dashboard is the main RAM consumer (the prototype's planning estimate for the Wazuh/indexer machine was ~10-12+ GB). Use manager only for data generation, and a full stack only for demo/visualization runs (for the "wazuh monitoring" visuals for evaluators). Wazuh's built-in vulnerability detection also relies on the indexer in recent versions, so we keep Trivy-based posture scanning (offline, lighter) instead.

### 8.3 Custom rules: how to avoid per-scenario headaches

Key insight: **do not write rules per scenario.** Write rule *libraries* once, vary which parts apply.

1. **Layer 0: stock Wazuh ruleset.** The realistic baseline. Low-maturity organizations rely on this only.
2. **Layer 1: generic custom library**, written once, generic and attack-agnostic: rules for our sample apps' log formats, failed/succeeded login patterns, privilege changes, FIM paths, unusual service restarts, etc. Pre-validated and versioned, with fixed rule-ID ranges (as in the prototype's 110201-110203 style).
3. **Layer 2: maturity/coverage profile.** Maturity decides which Layer 1 modules are *enabled* for that scenario (via agent group configuration and a per-run enabled-set), so detection coverage varies realistically: low maturity = fewer rules, high = more rules + FIM + extra log sources. Coverage gaps become valuable "missed detection" training examples.
4. **Layer 3 (rare): scenario-specific rules**, only when a scenario introduces a unique app log format. Auto-generated from the recipe's log-format mapping (the recipe already knows its log format), then validated automatically before use (`wazuh-logtest` with sample lines; configuration test of the ruleset) so a bad rule can never take down the manager. Failure = fall back to Layer 0-1 and flag the run.

Avoiding the problems seen in the prototype:
- **Rule circularity** (rules written to recognize exactly the range's own attacks, which the ML can then shortcut): rules must describe *behaviour classes* (e.g. repeated auth failures), never the attack template name or generator identifiers. Template-specific rules are forbidden. Rule IDs are for sensor validation, not features.
- **Reload cost/risk**: ruleset loaded once per lane, not reloaded per run. Variation comes from groups and enabled-sets, not from editing and restarting.
- **Rule metadata** (`rule_metadata.json`) is exported with each run: which rules existed and were enabled. Sensor facts are recorded, not hidden.
- Alternative for "one general big Wazuh" idea: yes, the library is general and big; what changes per scenario is *coverage*, and then we filter by run. That is the hybrid.

### 8.4 Per-run isolation checklist for Wazuh

```text
unique agent names/IDs per run (run_id prefix)       -> no identity collisions
per-run agent group                                   -> per-run config scope
record manager start time + ruleset version           -> provenance
export by agent prefix AND time window                -> clean slice
verify no events from other run IDs in the slice      -> contamination check
remove agents + keys at teardown [PROTO]              -> clean state
rotate/clear archives between runs (or snapshot offsets) -> bounded growth
```

---

## 9. Known risks and open items for this part

| # | Risk / open item | Mitigation / next action |
|---|---|---|
| 1 | "Realism" is not measurable; ranges are assumptions | Document sources, invariants, small expert review, claim "plausible", not "real" |
| 2 | One deep topology family in the M8 corpus | Generate the three known families (and more archetypes) as first-class training data; hold out whole families for evaluation |
| 3 | Container limits (no kernel CVEs, no native Windows/AD) | State openly; map Windows concepts to Linux equivalents; optional microVM for a few nodes |
| 4 | Generator fingerprints become ML shortcuts (identical logs, rule IDs, template names) | Normalize identifiers, vary log formats, use standard software logs, vary rule coverage, exclude generator fields from Engine inputs [PROTO guard exists on the Engine side] |
| 5 | Application logs too clean | Use real software logs as default; add messiness options |
| 6 | Benign diversity too thin | Largest improvement budget goes to personas, noise and hard negatives |
| 7 | Cost per full-stack run | Phase timing first, caching, lanes, then Gold/Bulk split |
| 8 | Claiming a weakness is exploitable without proof | Verification check must pass at deploy; otherwise class it as posture-only |
| 9 | Version-pinned old packages may not install or may break dependencies | Pre-flight build matrix, blacklist failures |
| 10 | Wazuh isolation strategy unmeasured | Measure manager startup and memory, then confirm Option C or choose A |
| 11 | Per-recipe RAM/CPU unknown | Measure with `docker stats`, feed the scheduler |
| 12 | Attack template safety | Harmless simulators only, isolated network, no reusable exploit tooling in exports |

---

## 10. Decisions needed before we call this part "done"

1. Store resolved spec + seed in every package (recommended: yes).
2. Wazuh strategy: hybrid per-lane manager (recommended) vs fresh manager per run; after measuring.
3. Is a microVM tier needed at all, or is containers-only acceptable for the project scope?
4. Initial service catalog order (which ~10 recipes to harden first).
5. Attackers: pre-planned only for v1, or reactive from the start (recommended: pre-planned first).
6. Who reviews the realism ranges (industry/size/role counts) and the topology sample?
7. How many topology archetypes for v1 (suggested: at least the three already shown plus one or two industry-specific ones).
8. Do we include Samba AD-style directory in v1, or keep OpenLDAP + Kerberos for simplicity?

When these are settled, the next topics are: virtual clock/time compression, GRC generation, the three-layer truth/evaluation planes, and scenario packaging with seed-based replication.
