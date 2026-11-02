# INPUT Part 3: SOC (Wazuh) Generation, Configuration and Time Behavior

Status: FINAL DRAFT. Decisions are made between us. Every uncertain mechanism has a test and a fallback (Part 12).

Tags:
- [PROTO] already shown in the PF prototype (M2 to M10).
- [NEW] proposed here.
- [MEASURE] a number or behavior we must measure on our own pinned Wazuh version.
- [VERIFY] a Wazuh detail recalled from general knowledge of Wazuh 4.x. It is believed correct, but must be confirmed against the documentation of the exact version we pin. None of the [VERIFY] items change the design; they only affect exact option names or defaults.
- Guarantee tiers for configurable items: **G** (we can guarantee: plain configuration, low risk), **P** (probable: needs one test before use), **X** (not doing, or not guaranteeable).

---

## 0. Goal of the SOC side

The SOC side does two jobs at once:

1. Produce realistic SOC telemetry (alerts, raw events, file-integrity events, configuration-check results, inventory, sensor health) whose *coverage and quality vary per scenario*.
2. Produce **evidence that lets the AI reason about GRC**: does the asset inventory match what the SOC actually sees, are control states true, is a risk understated given observed activity, did an incident happen that the registers never recorded.

Design rule: every configurable Wazuh component must be justified by at least one of: (a) it produces SOC-useful signal, (b) it produces GRC-useful evidence, (c) it creates a realistic gap or noise source that the AI must handle. Components that do none of these are left at defaults or disabled.

---

## 1. What Wazuh we run

| Component | Generation mode | Demo/visual mode |
|---|---|---|
| Wazuh manager (analysisd, remoted, authd, logcollector, syscheckd, modulesd, wazuh-db, API) | Yes | Yes |
| Wazuh agents (one per monitored asset) | Yes | Yes |
| Wazuh indexer + dashboard + filebeat | **No** (RAM-heavy, not needed to produce data) | Yes, only for presentation runs |
| Suricata sensor | Yes [PROTO] | Yes |

In generation mode we read `alerts.json` and `archives.json` straight from the manager's log files, plus a few manager API calls at the end of an episode (inventory, agent status). This is what the prototype did [PROTO]. The indexer/dashboard stack is used only to produce the "Wazuh monitoring" visuals for evaluators in demo mode, over a finished scenario.

**Version pinning (decision):** exactly one Wazuh version per generator release (manager and agents), recorded in the manifest. Rule IDs, field names and defaults differ between versions, so mixing versions would silently change telemetry. An optional later "outdated agent version" weakness (agent minor version older than the manager, which Wazuh supports) is tier P and off by default.

---

## 2. The SOC Profile: everything configurable, with guarantee tiers

Each scenario gets a `soc_profile` generated from `seed_monitoring` and the organization's security maturity. It is part of the Scenario Spec (Part 1) and fully determines the Wazuh configuration.

```yaml
soc_profile:
  wazuh_version: "<pinned>"
  maturity: medium
  agent_coverage:               # which assets are monitored (blind spots are deliberate)
    servers: 1.0
    dmz: 1.0
    workstations: 0.85
    network_devices: 0.0        # routers/firewalls: logs via syslog instead, or none
  blind_spot_assets: [asset ids sampled from the coverage ratios]
  agent_labels: {criticality_label: true, owner_label: true}   # may later carry stale values
  log_sources: {per role: [auth, syslog, web_access, web_error, db, mail, app_json, suricata_eve]}
  fim: {mode: realtime|scheduled, dirs_per_role: {...}, frequency_s: 600, report_changes: true, alert_new_files: true}
  sca: {policy_set: control_derived, interval_s: 900, assets_covered: 0.7}
  syscollector: {os: true, network: true, packages: true, ports: true, processes: true, hardware: false, interval_s: 300}
  command_monitoring: [listening_ports, last_logins, disk_usage]
  ruleset: {layers: [stock, generic_library, level_tuning], excluded_stock_files: [...], library_modules_enabled: [...]}
  tuning: {allowlists: {...}, level_overrides: {...}}
  archives: {captured: true, retained_by_org: true}     # retained_by_org=false hides archives from the Engine
  active_response: {enabled: false|true, actions: [...], timeouts: {...}}
  suricata_via_wazuh: true
  reliability: {client_buffer: ..., eps_limit: ..., fault_schedule: [...]}
  time: {manager_tz: "...", host_tz_faults: [...], clock_skew_faults: [...]}
  retention: {alerts_days: .., archives_days: ..}        # config fact only (see section 5)
```

### 2.1 Component table

| # | Component | What we configure (pseudo-random, per scenario) | Tier | SOC value | GRC value |
|---|---|---|---|---|---|
| 1 | **Agent deployment / coverage** | Which assets have an agent; agent names, IDs, groups; blind spots | G [PROTO] | Missed-detection realism (nothing seen on unmonitored hosts) | Asset inventory validation: shadow assets, "monitored: yes" claims vs reality |
| 2 | **Agent labels** | Custom labels (e.g. criticality, owner, environment) set per agent | G [VERIFY: labels appear in alert metadata] | Context in alerts | Stale/wrong tags vs inventory = flaw class; criticality evidence |
| 3 | **Agent groups + centralized config (`agent.conf`)** | Per-role group configs: which logs, FIM paths, scans | G | Different roles produce different telemetry | Config coverage by role |
| 4 | **Log collection (`localfile`)** | Which files/commands each role collects; formats (syslog, json, apache/nginx, mysql, etc.) | G | Core detection input | Evidence for logging controls |
| 5 | **Decoders** | Custom decoders for our sample-app logs (generated from the service recipe's log format) | G (validated by `wazuh-logtest`) | Parse our apps | n/a |
| 6 | **Rule library (custom)** | Generic behavior rules, fixed ID ranges, versioned (section 3) | G [PROTO: 110201-110203 style] | Detection | Compliance/MITRE tags on rules |
| 7 | **Rule coverage profile** | Which stock rule files and library modules are loaded, per scenario (manager-level) | G [VERIFY: `rule_exclude` in ruleset section] | Detection coverage varies with maturity | Control "monitoring/detection" effectiveness |
| 8 | **Rule level tuning** | Overrides of rule levels (`overwrite="yes"` local rules) so low-maturity orgs have raw/noisy levels, high-maturity tuned ones | G | Severity realism | Priority calibration evidence |
| 9 | **Allowlists / CDB lists** | Known admin users, authorized scanner IPs, trusted hosts | G | Hard negatives and false-positive suppression (tuned orgs) or flood (untuned) | Exception/authorization context |
| 10 | **FIM (syscheck)** | Monitored dirs per role, realtime (inotify) vs scheduled, frequency, ignore patterns, `report_changes`, `alert_new_files` | G for realtime/scheduled; **X for whodata** in containers (see 10) | Tamper/change detection | Change-management and integrity control evidence |
| 11 | **SCA (security configuration assessment)** | Custom policies **generated from the control register's reality tests** (e.g. "SSH root login disabled", "MFA enforced", "TLS min version"), plus interval and coverage | P (one syntax test per pinned version, section 12) | Hardening posture | **Strongest GRC link**: machine-checked pass/fail per control per asset to compare against the recorded control state |
| 12 | **Syscollector (inventory)** | OS, packages, listening ports, processes, network interfaces; intervals. Hardware scan disabled (in containers it reports host hardware, which would make all assets look identical) | G | Exposure context | **Asset inventory validation** (unknown host, wrong OS/version, extra open ports) |
| 13 | **Command monitoring** | Periodic commands (listening ports, logged-in users, disk usage) | G | Exposure drift (new listening port) | Exposed-service flaws |
| 14 | **Rootcheck** | Enabled with defaults in low maturity, minimal in others | G | Mostly noise in containers (useful as noise) | none |
| 15 | **Suricata via Wazuh** | Agent on the sensor collects `eve.json` so Suricata alerts also appear as Wazuh events (as in many real SOCs) | G | Realistic correlation path | Network evidence for risk |
| 16 | **Active response** | Block/limit actions (e.g. firewall-drop for repeated auth failures), timeouts, which assets | P (needs `NET_ADMIN` on target containers; changes the scenario outcome) | Containment realism | Control "operating effectively" evidence; outcome truth must record blocks |
| 17 | **Anti-flooding / EPS limits / agent buffer** | Client buffer size, manager event rate limits | G | Realistic dropped events under bursts | Monitoring-reliability evidence (recorded as sensor-health facts) |
| 18 | **Keepalive/reconnect timers, disconnection thresholds** | Agent notify/reconnect timers, manager disconnection time | G [VERIFY defaults] | Agent-status alerts | Monitoring-coverage gaps |
| 19 | **Archives (`logall_json`)** | Always captured by the generator; `retained_by_org` decides whether the Engine may see them | G [PROTO] | "Missed by rules" evidence | Retention/logging-control realism |
| 20 | **Timezone / clock faults** | Host timezone mismatch, skewed clock | G (section 6.9) | Dirty-timestamp robustness | Time-sync control evidence |
| 21 | **Retention config** | Log rotation/retention values | G as config fact; effect only observable via config snapshot | n/a | Log-retention control claims vs config |
| 22 | **API exports** | Agent list, syscollector, SCA summaries at episode end | G | Inventory/health | Inventory evidence |
| 23 | **Integrations (VirusTotal, Slack, ...)** | Not used (external network) | **X** | n/a | n/a |
| 24 | **Native Wazuh vulnerability detection** | Not used for generation (needs indexer and external feeds); Trivy offline posture scanning remains our source [PROTO M7] | **X** (demo mode only) | n/a | Findings come from Trivy |
| 25 | **Wazuh cluster, Windows event channel, docker-listener, osquery, cloud modules** | Out of scope | **X** | n/a | n/a |
| 26 | **Local ticketing sink (webhook integration to a local container)** | Simulated "SOC ticket" events | P, later | Alert-to-ticket workflow | Incident register evidence |

Guarantee statement: everything marked **G** is plain configuration of documented Wazuh features validated automatically by the preflight (section 9). **P** items are enabled per profile only after their test passes. **X** items never appear in a scenario.

### 2.2 How the profile is sampled

- Maturity sets probabilities: low maturity = lower agent coverage, stock rules only, raw levels, no allowlists, few SCA policies, FIM scheduled with long intervals, no active response, noisier. High maturity = near-full coverage, library rules + tuning, allowlists, SCA broad, realtime FIM on sensitive paths, active response on some assets.
- Dependencies are respected: a log source is only configured if the recipe produces that log; a rule module is only enabled if its log source is collected; an SCA policy only covers controls that apply to the role.
- **Coverage gaps are intentional and recorded.** Blind-spot assets are listed in the hidden truth, and the visible `soc_inventory.json` shows only what the SOC would know (section 8).

---

## 3. Detection engineering: rule library without circularity

### 3.1 Principles

1. Rules describe **behavior classes**, never attack templates or generator identifiers (fixes the "rule circularity" problem from the prototype review).
2. The stock Wazuh ruleset is the realism baseline. Our library adds generic rules once; it is not rewritten per scenario.
3. Per-scenario variation comes from the *profile* (which modules load, how levels are tuned, which logs are collected), not from writing new rules.
4. Rule metadata is exported every run (`rule_metadata.json`) so the evaluation knows which rules were active [PROTO].

### 3.2 ID ranges (custom rules start at 100000)

```text
110000-110999  generic authentication / privilege behavior
111000-111999  application and database behavior (our sample apps, standard services)
112000-112999  FIM / configuration-drift behavior
113000-113999  compliance-oriented rules (control evidence, section 4)
114000-114999  profile overrides (level tuning, allowlist suppression)
115000-115999  scenario-specific generated rules (rare, only for a scenario-unique log format)
```
Prototype rules 110201-110203 fall in the first range [PROTO] and are kept.

### 3.3 Generic rule categories (v1)

```text
Auth:      failure burst (frequency), success after failures, off-hours admin login, new source for account,
           privileged account used from user zone
Privilege: new user added, user added to privileged group, sudo by unexpected account, SSH key added
Config:    sshd/web/db config file changed, service disabled or stopped, new listening port,
           security tool stopped, log file truncated or deleted
Web:       injection/traversal patterns in access logs (stock web rules cover much of this), repeated 4xx/5xx bursts,
           unusual admin-path access
DB:        failed-login burst, new DB user, access from unexpected zone
Network:   Suricata alerts and flow summaries (via Wazuh or separate), scan patterns
Data:      large transfer by single account (using flow/log volume where available), bulk object access (our app logs)
Sensor:    agent disconnected, agent offline long, agent buffer overflow, manager queue pressure
Controls:  SCA critical check failed, SCA score dropped (section 4)
```

### 3.4 Compliance and MITRE tags (a direct GRC bridge)

Stock Wazuh rules carry compliance tags in their groups (e.g. PCI DSS, GDPR, HIPAA, NIST 800-53 style tags) and MITRE ATT&CK mappings [VERIFY]. Every library rule we write carries:
- MITRE technique IDs (consistent with the attack catalog),
- compliance group tags consistent with our `control_mappings.json` (Part 2), so an alert can be traced to the controls it provides evidence for.

This lets the Engine map "alert -> control -> risk" with real tags instead of guesses, and tests the framework-translation function.

### 3.5 Tuning and allowlists as realism

- Low-maturity: stock levels, no allowlists. An authorized vulnerability scan or an admin SSH session generates alarming alerts (good hard negatives).
- High-maturity: allowlisted scanner IPs and admin accounts partially suppress those, but some suppression is wrong or outdated (a **SOC-side flaw type**, ledgered: an allowlist entry that is stale or too broad and hides a real attack path). Rate: rare, same flaw machinery as Part 2 (levels L1-L5, detectability classes).

### 3.6 Validation (automatic, mandatory before use)

1. Configuration test of the ruleset (`wazuh-analysisd -t` [VERIFY]) must pass.
2. Each library module has a sample-line test file run through `wazuh-logtest` [VERIFY] and must produce the expected rule ID.
3. Any generated scenario-specific rule (range 115000) is tested the same way. On failure: fall back to the layers below it, flag the run. A bad rule can never block an episode.
4. **Detection expectation computation:** from the profile and the attack plan, compute which detections *should* occur (given collected logs and loaded rules) into `detection_expectations.jsonl` [PROTO]. After the episode, compare observed vs expected. An unexpected miss is a generator bug to investigate; an expected miss (coverage gap) is intended training signal.

---

## 4. Evidence-to-insight matrix: how SOC data helps GRC (and SOC)

This table is the justification for every SOC component. It states what the AI can legitimately conclude, and which flaw classes (Part 2) become discoverable.

| Wazuh evidence | Compared against | AI insight (SOC and GRC) | Flaw classes enabled |
|---|---|---|---|
| Agent roster (names, IPs, OS, status, groups) + syscollector OS/network | Asset inventory | Unknown active host (shadow asset); listed asset that never reported (ghost/decommissioned); wrong OS, IP or zone | Missing asset, ghost asset, stale network data, wrong version |
| Syscollector packages, ports, processes | Asset inventory, service list, findings tracker | Services running that nobody recorded; version drift; undocumented exposed port | Wrong software version, missing exposure flag |
| Agent labels | Asset inventory criticality/owner | Tag disagrees with inventory | Wrong/stale criticality, owner mismatch |
| SCA results (control-derived policies) | Control register states | "Implemented" control failing on some assets (paper control); "missing" control actually present; scope too narrow | Paper control, understated posture, narrow scope |
| FIM events | Change records, exceptions, control claims | Unauthorized or unexplained change on critical files; integrity control claimed but no FIM coverage | Control scope gaps, missing incident |
| Auth events (success/failure patterns, sources, hours) | Identity data, MFA claims, risk register | Password-only successes where MFA is claimed; privileged account misuse; brute force against a "low risk" asset | Paper control (MFA), stale risk, wrong likelihood |
| Alert volume, severity and targets per asset | Asset criticality, risk register | Heavily attacked asset recorded as low criticality; risk residual too low for observed activity | Wrong criticality, stale or understated risk |
| Confirmed attack outcome in telemetry | Incident register | Incident visible in telemetry but absent from register; closed incident with weakness still present | Missing incident, closed-without-fix |
| Active-response logs | Control register | Auto-block control claimed but never fired, or blocked as intended | Compensating control not compensating |
| Agent status history, sensor-health, buffer/queue events | "Monitoring" control, risk | Coverage gap or unreliable logging weakens residual risk assumptions | Monitoring control overstated |
| Rule compliance/MITRE tags on alerts | Control mappings, framework | Which framework controls an alert is evidence for | Mapping errors |
| Suricata alerts/flows | Topology/exposure data, policy exceptions | Traffic across a path the policy says is closed; exception being used | Expired/unused exceptions, exposure flags |
| Absence of events (blind spots, gaps) | Coverage claims | "No alerts" must not be read as "safe" for unmonitored assets or unobserved windows | Calibration/abstention test |

For SOC-only value: alert correlation into sessions, severity/priority adjustment from asset context, hard-negative separation (admin vs attack, scan vs recon), missed-detection awareness from archives.

---

## 5. What the Engine is allowed to see of the SOC itself

Visible (`telemetry/wazuh/` and `soc/`):
```text
alerts.jsonl, archives.jsonl (if profile retained_by_org), fim.jsonl, sca.jsonl,
syscollector snapshots (per asset, per episode), agents_status.jsonl, manager_health.jsonl,
rule_metadata.json, soc_inventory.json
```
`soc_inventory.json` = what a SOC knows about itself: agent roster, modules enabled per group, ruleset version and loaded files, retention settings, last ruleset update, known coverage statements (what the SOC *believes* it covers). It is the SOC counterpart to `asset_inventory.json`, and comparing the two is precisely a GRC task.

Hidden (truth plane): blind-spot list, the full `soc_profile`, true coverage, SOC-side flaw ledger entries (stale allowlist, etc.), unredacted configuration, expected detections.

Never exported anywhere: agent keys, authd passwords, private keys [PROTO].

---

## 6. WAZUH AND VIRTUAL TIME (DETAILED)

This is the part that must respect Wazuh's real limitations: boot time, scan-on-start bursts, reboot behavior, timers, log rotation, and clock handling.

### 6.1 Principles carried from Part 2

- Real Wazuh is never accelerated. It runs at 1x inside live episodes with a constant clock offset: `virtual_time = real_time + offset(episode)`.
- Between episodes there is no Wazuh activity (explicit gaps).
- Time only moves forward within a scenario.

### 6.2 Episode lifecycle for the SOC (phases)

```text
PRE-ROLL (virtual time before the episode window; telemetry here is NOT part of the episode)
  P1 BOOT     restore state, start manager, start agents, services
  P2 SETTLE   agents connect, first-scan bursts finish, health gate, telemetry canary
OBSERVE       the official episode window (virtual start/end from the master timeline)
DRAIN         stop activity, flush Wazuh queues, collect exports
TEARDOWN      stop agents, then manager, snapshot state
```

The clock offset is chosen so that **OBSERVE starts exactly at the planned virtual time**. BOOT and SETTLE therefore occur at earlier virtual times (pre-roll), and their output is stored separately as `telemetry/preroll/` with `phase=boot|settle`, never mixed into the episode's telemetry.

Reason: a Wazuh startup produces a recognizable burst (manager started, agents started and connected, first FIM baseline, first SCA scan, first syscollector scan, rootcheck). If these appeared at the start of every episode, "burst of startup events" would become a learnable fingerprint of "episode begins". Real startup bursts still exist in real SOCs (after reboots), so we model those deliberately as events (6.7), not as a side effect of our test harness.

### 6.3 Launch and reboot timing: budget (planning estimates, [MEASURE] all)

| Step | Estimate | Notes |
|---|---|---|
| Manager start (ruleset load, wazuh-db, daemons) | 30-120 s | Grows with ruleset size; custom library is small relative to the stock ruleset |
| Each agent start | 5-30 s | Parallel across agents |
| Agent connect after manager is up | 10-60 s | Agents retry on a timer; many agents retrying at once can stretch this |
| First scans after start (FIM baseline, SCA, syscollector) | seconds to a few minutes | Depends on monitored directory size and policy count; **we keep monitored dirs small** |
| Telemetry canary round-trip | 10-60 s | |
| Total PRE-ROLL | roughly 3-6 min | Added to wall time per episode, not to virtual episode length |
| Drain + export + snapshot | 1-3 min | |

Rule: the health gate is **time-boxed** (e.g. 8 minutes). Exceeding it rejects the episode and re-runs it (same seed) after cleanup; repeated failure quarantines the seed.

### 6.4 Wazuh's own timers and why we compress them

Wazuh does scheduled work on intervals that were designed for production (indicatively: FIM scans on the order of hours, SCA on the order of hours, syscollector hourly, agent keepalive on the order of seconds) [VERIFY defaults]. In a 30-60 minute episode, hour-scale intervals never fire again after the start-up scan.

Decision: the profile sets **compressed intervals** (e.g. FIM 300-900 s, SCA 600-900 s, syscollector 300 s) so that periodic evidence appears inside episodes.

Consequences, handled explicitly:
- Compression factor `k = production_interval / used_interval` is recorded in the manifest as `wazuh_time_compression`.
- Telemetry density from scans is higher than in a real SOC; keep monitored paths small and SCA policies focused to limit this.
- Engine features must not depend on absolute scan periodicity (known limitation, documented in the manifest so the Engine team can exclude such features).
- Real-time FIM (inotify) is time-independent and preferred for sensitive paths.

### 6.5 Clock mechanics for Wazuh

Primary mechanism (from Part 2): **libfaketime in offset mode** applied to the manager container and every agent/app container. Checklist [MEASURE each]:

1. LD_PRELOAD set in the container entrypoint so every Wazuh daemon inherits it (Wazuh daemons start as root and drop privileges by `setuid()` without re-exec, so preload should persist [VERIFY]; if any daemon is exec'd through a setuid wrapper the preload would be ignored).
2. Offset/absolute-start mode only, **no speed multiplier**.
3. Do not fake the monotonic clock, if the library version supports excluding it (so internal sleep/timer logic is untouched) [VERIFY: option name `FAKETIME_DONT_FAKE_MONOTONIC`].
4. The manager and all agents share the same offset (constant for the whole episode).
5. Python-based Wazuh components (API) use libc time and should be affected correctly [VERIFY].
6. Every component that writes timestamps (rsyslog if used, sshd, nginx, postgres, cron) also runs under the same offset, or logs are inconsistent.

What Wazuh timestamps come from [VERIFY]:
- Alert/archive `timestamp`: the **manager's** clock when it processes the event.
- `predecoder.timestamp`: the timestamp string inside the original log line.
- Year-less syslog timestamps are completed using the manager's current date, so the manager *must* run under the virtual clock, and an episode must not straddle a year boundary (the episode generator avoids placing windows across 31 Dec/1 Jan, simple rule).
- Frequency/timeframe correlation rules use time at the manager when events are processed [VERIFY]. This is the key reason we run logs through live Wazuh at 1x and **do not** inject stored logs into Wazuh later: stored logs replayed after the fact would be correlated against the replay-time clock, not the original event times. (Relevant to the future Bulk tier: replay must go through the live path with the clock set, or be done by a separate non-Wazuh generator labeled as such.)

Fallback if libfaketime fails measurement: run on real time, then apply the constant episode offset to structured JSON timestamp fields of alerts/archives/FIM/syscollector (and Suricata, which needs this anyway), and run verified per-format rewriters for timestamp strings inside `full_log`. The time-consistency validator (Part 2, B7) decides pass/fail for either path.

### 6.6 State, restarts and agent identity across episodes

Because each episode is deploy-from-state (Part 2, B5), Wazuh state must persist, per **scenario**:

Manager side (persisted, exact list verified in test T3):
```text
etc/ (client.keys, ossec.conf, local rules/decoders/lists, shared group configs)
queue/ (agent registration data, replay counters "rids", per-agent databases, agent-info)
var/db/ (global database)
logs/ (rotated alerts/archives are exported, then pruned)
```
Agent side (persisted per asset):
```text
etc/client.keys
queue/rids (replay counters)
queue/syscheck (FIM baseline database)
(syscollector/SCA state as needed)
```

Why this matters:
- **Agent identity continuity:** same agent ID and key across episodes, as in real life. The prototype used per-run enrollment and cleanup [PROTO]; for multi-episode scenarios we enroll **once per scenario** (at episode 1) and keep keys. Across *different scenarios* nothing is shared.
- **Replay protection:** Wazuh agent-manager messages carry counters; if an agent restarts with the same key but a reset counter, the manager may reject its messages [VERIFY]. Persisting `rids` on both sides avoids it. If a persisted-state restore fails the canary, fallback is to re-enroll that asset with a new identity and record an `agent_reenrolled` event (real SOCs also re-enroll hosts, but this must be ledgered).
- **FIM continuity:** the FIM baseline persists, so changes made during a gap (by the reconciler applying a patch, a config change, attacker persistence) are detected at the next scan as real "changed since baseline" events. These appear with episode-time timestamps (realistic for scheduled scanning). The truth plane records `change_source=reconciler|attacker|benign` with the true change time, so the evaluation knows these are gap-origin changes. To avoid a flood of "changed" events caused only by our reconciler (e.g. a package swap touching hundreds of files), the reconciler **refreshes the FIM baseline for reconciler-origin changes** after applying them, except for changes that are intentionally security-relevant (planned tampering). Documented as an explicit generator behavior.
- **Manager container is stateless; state volume is per scenario.** This **replaces** the Part 1 suggestion of one long-lived manager per lane filtered by agent-name prefix. New rule: any lane can run any scenario's episode by mounting that scenario's state volume into a fresh manager container. No cross-scenario contamination is possible by construction. We still prefix agent names with the scenario ID for provenance.
- **Rule enabling is manager-level.** Correction to Part 1: coverage differences between assets come from *what each agent collects* (agent groups), while *which rules exist* is a per-scenario manager setting loaded at BOOT. Both are fixed at episode start, so no rule reloads happen mid-episode.

### 6.7 Reboots, restarts, outages (what is live, what is a gap fact)

| Case | How we realize it | What Wazuh shows | Notes |
|---|---|---|---|
| **Short planned reboot inside an episode** (host patch) | Stop the asset's agent and services, wait `downtime` (30 s to ~10 min), start again | Agent stopped/started events [VERIFY rule IDs ~501-506 range], first-scan burst (FIM/SCA/syscollector) after restart, possibly a disconnection alert only if downtime exceeds the manager's disconnection threshold [VERIFY] | Models real post-reboot bursts, which are a classic benign look-alike |
| **Unexpected crash** | `kill -9` of the agent/service container | No graceful "stopped" message; manager notices after timeout | Fault-schedule item in the profile; ledgered as sensor outage |
| **Long outage / maintenance window spanning a gap** | Layer 1 fact only: `agent offline from T1 to T2` in the truth and sensor-health ledger; no live Wazuh output during the gap | At the next episode the roster shows last keepalive long ago | We cannot create a "disconnected at the right time" alert in a gap, because Wazuh is not running then. The limitation is documented and visible in `coverage_windows.json` |
| **Manager restart/upgrade** | Part of episode BOOT (always), or a scheduled in-episode event for a high-visibility case | Manager started event; agents reconnect over seconds to a minute | |
| **Whole-asset decommission/commission** | Layer 1 event; at next episode the asset exists or not | New agent enrollment event for new assets | Shadow-IT flaw: asset deployed without agent |

Rule: nothing longer than ~10 virtual minutes is executed live (it would waste wall time with no new information); longer outages are Layer 1 facts.

### 6.8 Log rotation and date boundaries

Wazuh writes alerts/archives into per-date files and rotates at day boundaries according to the (virtual) clock, so an episode crossing virtual midnight touches two files. The exporter reads by **time window**, across the current and rotated files, and verifies no gap or duplicate at the seam. Retention pruning never runs on exported episode data until packaging is complete.

### 6.9 Time faults (rare, ledgered)

- **Host timezone misconfiguration:** host logs with local time strings without offset; Wazuh interprets them relative to the manager's timezone, producing a consistent offset between `predecoder.timestamp` and `timestamp` of several hours for that host. A natural, realistic data-quality issue.
- **Clock skew:** one host's clock off by minutes (libfaketime offset specific to that container); visible as disagreement between host log time and manager time.
- **NTP outage/drift** scheduled as a fault.
- **Delayed delivery:** agent buffer pauses so events arrive later (arrival time differs from event time).
All are entries in `sensor_health.json` and the truth ledger; the base timeline is otherwise clean. Rates are low and maturity-dependent.

### 6.10 Forward-only and window rules

- Virtual time inside a scenario is strictly increasing across episodes; each next episode starts at least `pre_roll + drain + gap_min` after the previous one ended.
- No episode crosses a year boundary or a daylight-saving transition (v1 simplification; avoids ambiguous/missing local times).
- The master timeline owns all offsets; no component computes its own date.

---

## 7. SOC generation pipeline (per scenario)

```text
1. read Scenario Spec + GRC reality (assets, services, weaknesses, controls, maturity)
2. sample soc_profile (section 2), checking dependencies
3. render configs: ossec.conf (manager), agent.conf per group, local rules/decoders/lists, overrides,
   SCA policies (from control reality tests), FIM profiles, command monitors
4. preflight (no containers yet): ruleset config test, logtest suites, SCA policy syntax check,
   profile-vs-recipe consistency check
5. compute expected detections for the planned activities given the profile
6. (per episode) deploy-from-state with offset, health gate (section 9), observe, drain, export, snapshot
7. post-episode: compare observed vs expected detections, build SOC-side truth (blind spots, faults)
8. package visible and hidden planes (section 8)
```

---

## 8. Telemetry and SOC output files

Visible to the Engine:
```text
telemetry/wazuh/alerts.jsonl
telemetry/wazuh/archives.jsonl           (only if profile retained_by_org)
telemetry/wazuh/fim.jsonl
telemetry/wazuh/sca.jsonl                (SCA events/summaries per asset, with policy and check IDs)
telemetry/wazuh/syscollector/<episode>/<asset>.json
telemetry/wazuh/agents_status.jsonl      (roster + status history per episode)
telemetry/wazuh/manager_health.jsonl     (queue, drops, restarts, errors from manager logs)
telemetry/wazuh/rule_metadata.json
telemetry/suricata/eve.jsonl             (and optionally the same events inside Wazuh)
soc/soc_inventory.json
quality/sensor_health.json, quality/coverage_windows.json
```
Hidden:
```text
truth/soc_profile.json, truth/blind_spots.json, truth/soc_flaw_ledger.jsonl,
truth/detection_expectations.jsonl [PROTO], truth/preroll/ (boot/settle telemetry)
```
Every record carries scenario_id, run_id/episode_id, virtual timestamp (UTC ISO-8601) [PROTO fields], and an `agent_asset_map` resolves agent to asset ID [PROTO: resolved_asset_id].

Determinism statement: seeds reproduce the *spec, plan, profile and timeline* exactly. Wazuh telemetry is **not byte-for-byte reproducible** (timing, event interleaving, internal IDs). A replicated scenario yields structurally and statistically equivalent telemetry, and the package states this explicitly (relevant to the packaging topic).

---

## 9. Health gate and validation (SOC-specific additions to Part 1, 2.3)

```text
W1  all Wazuh daemons running (control status), no crash loops
W2  ruleset loaded: expected rule count/files match the profile
W3  every expected agent: connected, authenticated, correct group, correct labels
W4  logall/archives active, alerts file being written, correct inode/path
W5  clock check: canary event timestamp inside expected virtual window
W6  canary per log source: one harmless event per collected source arrives as archive and, where a rule exists, as alert
W7  FIM canary (touch a monitored test file) and SCA run reports results
W8  syscollector snapshot present for each covered agent
W9  manager log scan: no errors beyond an allowlist (queue full, disk, db corruption)
W10 disk space and event-rate headroom
```
Also, after OBSERVE: expected-vs-observed detection comparison, per-episode event counts vs profile expectations, check that no events from another scenario/agent prefix exist in the export, and the time-consistency validator (Part 2, B7).

---

## 10. Honest limitations

| Limitation | Effect | Handling |
|---|---|---|
| Containers share the host kernel; auditd/whodata FIM is not reliable in containers (kernel audit is not namespaced) | No who-data (which process/user changed a file) | Use realtime (inotify) or scheduled FIM; do not promise whodata; process attribution comes from app/auth logs |
| No systemd or full init in containers | Some stock decoders/rules assume journald/auth.log | Each recipe runs rsyslog or logs to files explicitly, and declares collected log files |
| Hardware/inventory in containers reflects host | Identical hardware on all assets | Disable hardware scan |
| Many CIS-style SCA checks do not apply in containers | Noisy/irrelevant failures | Use **control-derived custom SCA policies** instead of stock CIS policies (stock CIS only as optional noise in low maturity) |
| Rootcheck mostly noise | Meaningless alerts | Treated as noise source only |
| Compressed scan intervals | Higher telemetry density than real | Recorded `wazuh_time_compression`, documented |
| Gaps between episodes | No continuous telemetry | `coverage_windows.json`; Engine must treat gaps as unobserved |
| Long outages cannot generate live disconnect alerts | Missing alert type for gap-spanning outages | Layer 1 facts only |
| Startup bursts | Fingerprint risk | Pre-roll separated; real reboot bursts modeled deliberately |
| Not byte-reproducible | Replication = equivalence, not identity | Stated in the manifest |
| Windows/AD logs not generated | No eventchannel | Linux equivalents only (Part 1) |
| Wazuh vulnerability detector not used | Findings come from Trivy | Documented |
| Synthetic apps cleaner than production logs | ML shortcut risk | Use standard services' native logs by default; messiness options (Part 1, 6.3) |

---

## 11. Final decisions

1. Generation uses Wazuh manager + agents only; indexer/dashboard only for demo visuals.
2. One pinned Wazuh version per generator release, recorded in the manifest.
3. SOC behavior is fully determined by a generated `soc_profile`; every configurable item has a guarantee tier; only G items are enabled unconditionally, P after tests, X never.
4. Rules describe behavior classes only; a generic library plus stock ruleset; per-scenario variation via profile (loaded rules, tuning, allowlists, collected logs), not new rules.
5. Rule coverage is a manager-level per-scenario setting; asset-level coverage is agent-level collection config.
6. Library rules carry MITRE and compliance tags consistent with `control_mappings.json`.
7. SCA custom policies are generated from the control register's reality tests and are the main control-evidence source for GRC.
8. Syscollector and agent roster are the asset-inventory evidence source; labels are a flaw-capable tag channel; hardware inventory disabled.
9. Archives always captured; `retained_by_org` controls visibility to the Engine.
10. Wazuh runs at 1x with a constant episode offset (libfaketime offset mode, Suricata post-shifted by the same constant, validated fallback exists).
11. Each episode has PRE-ROLL (boot, settle, health gate) kept out of the episode telemetry, then OBSERVE, DRAIN, TEARDOWN.
12. Scan intervals are compressed and the compression factor is recorded.
13. Wazuh state persists per scenario (manager and agent), identity enrolled once per scenario; the manager container is stateless. This supersedes the per-lane persistent manager idea of Part 1.
14. Reconciler-origin changes refresh the FIM baseline unless they are intentional security-relevant tampering.
15. Reboots up to ~10 virtual minutes are live; longer outages are Layer 1 facts.
16. Time faults (timezone, skew, delay) are rare, ledgered, and added only on top of a clean timeline.
17. Replication guarantees identical spec/plan/profile/timeline, equivalent but not byte-identical telemetry.
18. The Engine sees `soc_inventory.json` (what the SOC believes); true coverage and flaws stay hidden.

---

## 12. Tests before trust (each with a fallback)

| # | Test | Pass criterion | Fallback |
|---|---|---|---|
| T1 | Boot-time measurement: manager, agents, first scans, canary, with realistic profile size | Pre-roll fits the time-box; numbers replace the estimates in 6.3 | Reduce monitored paths/policies; raise time-box |
| T2 | libfaketime with manager + agents + sample services; offset mode, monotonic handling | All alerts/archives/app logs carry virtual dates; no daemon crash; correlation rules fire correctly | Post-run constant-offset retiming + verified rewriters |
| T3 | State persistence: stop/snapshot/restore manager and agents; list of required directories confirmed | Same agent IDs reconnect, no replay-counter rejection, FIM baseline retained | Re-enroll with ledgered `agent_reenrolled` |
| T4 | Replay-counter behavior with reset agent state | Documents exact failure mode | Persist counters (above) |
| T5 | SCA custom policy: syntax, checks (file/regex/command), result export, on pinned version | Per-control results appear in alerts/archives | Use command-monitoring checks as evidence instead |
| T6 | Rule coverage via `rule_exclude` and local overrides | Excluded files do not fire; overrides change levels | Level-0 overwrite rules |
| T7 | Agent labels in alerts | Labels visible in alert metadata | Use group names and asset-map for tags |
| T8 | FIM realtime in containers (inotify), scheduled compression, baseline refresh by reconciler | Expected events only | Scheduled-only FIM |
| T9 | Reboot cases: short, crash, manager restart; observed rule IDs and thresholds | Matches table in 6.7 and documents real rule IDs/timings | Adjust downtime/thresholds |
| T10 | Day boundary: log rotation and exporter seam | No loss/duplicates | Avoid midnight windows in v1 |
| T11 | Active response on one asset | Block effective, outcome recorded in truth | Disable active response in v1 |
| T12 | Anti-flooding: brute-force burst vs agent buffer/EPS limits | Drops recorded as sensor-health facts | Lower attack rates |
| T13 | Detection-expectation accuracy over 50 generated scenarios | Unexplained expected/observed mismatches near zero | Fix profile/rule dependency logic |
| T14 | Contamination: two scenarios sequentially in the same lane | No cross-scenario events or state | Fresh containers + wiped volumes |

Next topic: the truth/outcome/reference-key planes and scenario packaging (compressed package, seeds, replication, versioning), now that network, GRC, SOC and time are defined.
