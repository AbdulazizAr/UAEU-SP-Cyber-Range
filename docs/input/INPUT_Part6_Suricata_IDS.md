# INPUT Part 6: Suricata (Network IDS) Generation, Configuration and Time

Status: FINAL DRAFT. Tags: [PROTO] shown in the prototype (M4: pf/suricata-sensor:0.4.0, live EVE, per-zone capture, 0 kernel drops), [NEW] proposed, [MEASURE] measure on our setup, [VERIFY] confirm detail on the pinned version. Suricata details are recalled from general knowledge of Suricata 6/7 and must be confirmed against the pinned version.

---

## 1. Role of Suricata in the project

Suricata is the **network evidence source**, independent of host agents.

- SOC value: detects scans, web attacks, SSH brute force, suspicious DNS/TLS, anomalous flows; sees hosts that have no Wazuh agent (blind spots on the host side).
- GRC value: evidence of exposure (internet-facing paths that exist), traffic across paths policy says are closed, policy exceptions actually used, unencrypted protocols where a control claims TLS, unknown IPs (shadow assets), data-volume flows relevant to data classification.
- Realism value: IDS alert noise (many low-value alerts) is part of real SOC life.

Principle: like Wazuh (Part 3), Suricata **coverage varies per scenario** through a generated sensor profile.

---

## 2. Sensor placement and tap points

Containers on Docker bridges: a normal container only sees traffic to/from itself. So placement is a design decision.

| Placement | How | Sees | Notes |
|---|---|---|---|
| **P1 Perimeter** | Capture on the router's external-facing interface (Internet zone to DMZ) | external attacks, inbound scans, outbound C2/exfil | Always present in v1 |
| **P2 Inter-zone** | Sidecar sharing the router's network namespace, capturing on every router interface | All cross-zone traffic (the router sees everything that crosses zones) | [PROTO: per-zone capture "users" and "DMZ"] Preferred default: simple and complete for inter-zone flows |
| **P3 Intra-zone tap** | Capture on the host-side bridge interface of a zone (or mirror via `tc mirred`) | East-west traffic inside one zone (e.g. servers talking to each other) | Optional, more expensive; high-maturity profiles only [MEASURE feasibility on the lab Linux VMs] |
| **P4 Host-level** | none (Wazuh/app logs instead) | n/a | Suricata is not run per host |

Decision: P1 + P2 always; P3 on selected zones by maturity. Intra-zone traffic in zones without P3 is an **intentional blind segment**, listed in hidden truth, and consequences are recorded as coverage facts (Part 3 style).

Capture environment: the lab uses Linux VMs on Windows hosts (Part 2/hardware plan). All capture happens inside the Linux VM/network namespaces; the Windows host is irrelevant to packet capture.

---

## 3. Configurable components (sensor profile)

Generated from `seed_monitoring` and maturity, part of the Scenario Spec. Guarantee tiers as in Part 3: **G** guaranteed, **P** after test, **X** not used.

| # | Component | Pseudo-random configuration | Tier |
|---|---|---|---|
| 1 | Sensor count and placement | P1, P2 always; P3 zones sampled | G |
| 2 | HOME_NET / EXTERNAL_NET | Derived from the IP plan (Part 1) | G |
| 3 | Capture method | AF_PACKET per interface, thread count, ring size | G |
| 4 | Ruleset layers | (a) Emerging Threats Open snapshot (pinned date) with selected categories, (b) generic local rules, (c) maturity tuning (disabled noisy SIDs, thresholds, suppressions) | G |
| 5 | Local rules | Generic behaviors: port scan thresholds, SSH auth-fail bursts, SQLi/traversal strings, odd user agents, large outbound transfer. SID range 9900000+ [PROTO: 9904001/9904002] | G |
| 6 | EVE output types | alert, flow, dns, http, tls, ssh, fileinfo, optional anomaly, stats; low maturity = alert (+flow), high = all | G |
| 7 | Metadata | `community_id` on flows/alerts (join key across tools) [VERIFY], flow ids, app-layer fields | G |
| 8 | Payload logging | Off by default (size/privacy); optional limited payload on alerts for low maturity | G |
| 9 | TLS handling | Metadata only (SNI, certificate subject/issuer/validity, JA3/JA3S [VERIFY]); no decryption | G |
| 10 | Encrypted traffic share | Per scenario: some internal services use TLS, some plain HTTP, by maturity and service recipe | G |
| 11 | Rate/limits | Thresholds, detection engine profile, flow timeouts | G |
| 12 | Sensor reliability faults | Sensor down for a window, packet drops under overload, delayed log shipping | G (scheduled faults, ledgered) |
| 13 | Via-Wazuh shipping | Wazuh agent on the sensor host ships `eve.json` (stock decoder/rules) | G [PROTO Wazuh] |
| 14 | pcap capture | Raw pcaps for Gold scenarios (hidden), enabling reprocessing | P |
| 15 | Native Suricata IPS/inline mode | Not used (detection only) | X |
| 16 | Live rule updates from the internet at run time | Not used; ruleset is snapshot-based and pinned | X |
| 17 | File extraction / Lua scripting / multi-tenancy | Not used | X |

Maturity effect summary:
- **Low:** perimeter only, `alert`+`flow`, default rules without tuning (noisy), lots of plain-text protocols, no intra-zone visibility.
- **Medium:** perimeter + inter-zone, standard EVE set, ET categories selected, basic suppressions.
- **High:** + intra-zone taps in server/data zones, full EVE, tuned thresholds, stats logging, sensor health monitored via Wazuh.

---

## 4. Rules: gating by virtual date and avoiding circularity

- Rule snapshot: ET Open fetched at build time with `suricata-update` and **pinned** (date recorded in the manifest). Offline at run time.
- **Future-knowledge leakage:** a snapshot taken in real time `R` contains signatures for vulnerabilities published after a scenario's virtual date `V < R`. Handling: filter signatures by their creation date metadata (ET rules carry `created_at` style metadata [VERIFY]) so only rules with `created_at <= V` load. Fallback if metadata is absent for a rule: exclude CVE-specific rules newer than V by CVE year, keep behavior-class rules. Same principle as enrichment gating (Part 2, B8).
- Local rules describe **behaviors**, never the generator's attack template names or markers. SIDs and rule messages are generic (e.g. "SSH repeated authentication failures"), never "PF test attack". This addresses the prototype's circularity finding.
- Rule metadata exported (ruleset snapshot date, loaded categories, count, local rule list) as `sensor_inventory.json` (visible, what the SOC knows) and detailed truth hidden.

---

## 5. Virtual time and Suricata

Suricata in live capture stamps packets with **kernel capture time (real time)**, not the faked userland clock used for Wazuh/containers (Part 3, 6.5). So every episode:

```text
virtual_ts = real_capture_ts + episode_offset      (constant offset, 1x speed)
```

Mechanism, default: **schema-aware shift in post-processing** of the EVE JSON:
- Shift: top-level `timestamp`, `flow.start`, `flow.end`, and other **capture-derived** timestamps only.
- Do **not** shift data carried inside traffic that is already in virtual time (TLS certificate validity dates and HTTP `Date` headers come from containers running under the virtual clock, so they are already virtual) [VERIFY field list].
- A per-field allowlist drives the shifter; the validator (below) compares with Wazuh and controller times, which catches mistakes.

Flow records: Suricata emits flow records when flows end or time out, so a flow can finish after the episode window. Drain procedure: stop traffic, wait for the configured flow timeout or shut Suricata down gracefully so remaining flows are logged [VERIFY shutdown behavior], then export. Flows are assigned to episodes by **flow start time**; a flow that crosses the window end is truncated/flagged.

Alternative mechanism (documented, optional, used by the Bulk/variant path in Part 8): **capture pcap, then run Suricata offline** (`-r`) after rewriting packet timestamps by the constant offset. Suricata in pcap mode uses packet time, so thresholds and flows are consistent, outputs carry virtual timestamps natively, and the **same pcap can be reprocessed under different sensor profiles** (different ruleset, EVE types) to create coverage variants cheaply. Live mode remains the default and the validated path [PROTO M4]; pcap retention is Gold-only because of size.

Time of rules: thresholds and windows (e.g. 10 SSH failures in 60 s) run on packet time at 1x, so behavior matches reality.

Between episodes there is no capture (explicit gap, Part 2); `coverage_windows.json` applies to Suricata as well.

---

## 6. What network evidence each activity produces (observability matrix)

Used to compute `detection_expectations` for the network sensor and to avoid claiming detection that cannot occur.

| Activity | Typical network evidence | Typical Suricata output | Caveat |
|---|---|---|---|
| Port scan / recon | many short flows, SYN patterns | flow records, scan-class alerts if rules match | stealthy slow scans may stay below thresholds |
| SSH brute force | many SSH flows from one source, failed sessions | `ssh` events, flow counts, threshold alert | auth failures themselves are in host logs |
| Web injection / traversal | HTTP requests with payload patterns | `http` + `alert` if signature matches | no visibility if TLS and no inspection |
| IDOR / object access | normal-looking HTTP sequences | `http`/`flow` only | rarely alerts; correlation needed |
| Lateral movement via SSH | new internal SSH flows from unusual source | `ssh`/`flow` | invisible if intra-zone and no P3 tap |
| Data exfiltration | large outbound flow, long-lived session, DNS anomalies | `flow` byte counts, `dns`, `tls` metadata | encrypted content invisible |
| C2 beacon (simulator) | periodic small flows, fixed intervals | `flow`, `dns`, `tls` (JA3) | detectable by regularity analysis rather than signatures |
| Benign look-alikes (authorized scan, backup transfer, admin SSH) | resembles the above | same event types | these are the hard negatives |

Each activity template declares `network_observability` (expected event families and whether detection is expected under the profile).

---

## 7. Integration with Wazuh and the Engine

- Raw `eve.jsonl` is always exported (one source of truth) [PROTO: Engine reads EVE].
- If the profile has `suricata_via_wazuh`, the same events also appear inside Wazuh alerts/archives. To prevent double counting, every Suricata event gets a deterministic `event_id` = hash(`flow_id`, `timestamp`, `event_type`, `signature_id`) computed at export; Wazuh-carried copies are tagged with the same `eve_event_id`, so the Engine can de-duplicate [PROTO: de-dupe by event ID].
- Provisional severity mapping in the Engine (severity 1 to level 10, 2 to 7, 3 to 4) is a known open item [PROTO]; the generator exports `alert.severity` untouched and records the mapping assumption; mapping validation happens on the golden sample.
- Evidence links: each activity with `network_observability` gets `evidence_links` to flows/alerts (`link_quality` exact/strong/probable/uncertain) [PROTO].
- Session correlation limits noted by the Engine team (simplified asset/source/time correlation) are not a generator problem, but the generator makes sure `src_ip`/`dest_ip` map to exactly one asset per episode (static IP plan) so correlation is possible.

---

## 8. GRC value (evidence-to-insight)

| Suricata evidence | Compared with | Insight |
|---|---|---|
| Flows from outside to a host recorded as internal-only | assets/topology/exposure flags | Exposure flag wrong; exposed service |
| Flows across zones the policy matrix denies (or only via exception) | topology, policy_exceptions | Exception in use, expired exception still used, firewall rule drift |
| Plain HTTP/FTP/telnet to a data asset | controls ("TLS enforced"), data classification | Paper control; missing encryption in transit |
| Unknown internal IP communicating | asset inventory | Shadow asset (D2 telemetry-evident flaw) |
| Large flows from a regulated-data asset | data classification, risk register | Data exposure not reflected in risk |
| Alerts concentrated on an asset | criticality, risk | Understated criticality/risk |
| No network evidence for a host with an inventory entry | asset inventory | Ghost/decommissioned asset |
| Silence in untapped segments | sensor_inventory | Coverage claims vs real; must not be read as "no activity" |

---

## 9. Health gate and validation (adds to Part 1, 2.3 and Part 3, section 9)

```text
S1  sensor processes up, interfaces up and capturing, rules loaded (rule count matches profile),
    `suricata -T`-style configuration test passes [VERIFY]
S2  checksum handling set correctly for virtual NICs (see section 10); canary packets produce flow records
S3  canary traffic between known hosts across each tapped boundary appears with correct 5-tuple in `flow`
S4  EVE file writing, rotation path correct, `stats` events show kernel drops = 0 (threshold configurable)
S5  time check: canary flow timestamp after shift lies in the expected virtual window and agrees with the Wazuh canary within tolerance
S6  post-drain: no truncated final EVE line, flows flushed
S7  per-activity evidence check: controller-launched network activities have observable evidence where `network_observability` says so [PROTO: M6 HTTP join]
```

---

## 10. Limitations and known pitfalls

| Issue | Effect | Handling |
|---|---|---|
| No TLS decryption | Encrypted app content invisible | Realistic; TLS share is a profile variable |
| Virtual NICs and checksum offload can make packets look like they have invalid checksums | False "invalid checksum" drops or noise | Disable checksum validation / offload for the capture (`checksum-validation` off or `-k none`) [VERIFY], documented |
| Docker bridge behavior (MAC learning, no promiscuous mirroring) | Sensor sees nothing unless placed correctly | Placement P1/P2/P3 as in section 2 |
| Low traffic volume and synthetic content | Rules tuned for real internet traffic behave differently | Local behavior rules + volume realism via personas (Part 1, section 6) |
| ET rules include many internet-specific signatures irrelevant to our traffic | Mostly silent | Expected; keep ruleset focused by category |
| Same-host resource contention | Capture drops under load | Resource limits, drops recorded in `stats` and sensor health, faults ledgered |
| IPv6, VLAN tags, tunnels | Not modeled | v1 IPv4 only; documented |
| Real-time vs packet-time: live thresholds depend on capture timing | Slight run-to-run variation | Accept; equivalent-not-identical statement (Part 5) |
| Custom signatures can become shortcuts (prototype M9) | ML shortcut | Generic behavior rules; SIDs flagged as non-feature; per-scenario variation of ruleset profile |

---

## 11. Output files

Visible: `telemetry/suricata/eve.jsonl`, `telemetry/suricata/suricata_stats.jsonl`, `telemetry/suricata/sensor_inventory.json` (placement summary as the SOC knows it, ruleset snapshot date, EVE types enabled, local rules list).
Hidden: true placement and blind segments, sensor fault ledger, expected network detections (`detection_expectations`), optional `captures/*.pcap.zst` for Gold, preroll sensor logs.

---

## 12. Decisions (final)

1. Suricata is detection-only (no inline IPS).
2. Placement: P1 perimeter + P2 inter-zone (router namespace) always; P3 intra-zone taps by maturity; blind segments recorded as truth.
3. Sensor profile generated per scenario (EVE types, ruleset layers, tuning, TLS share, faults).
4. ET Open snapshot pinned and **date-gated** to the scenario's virtual date; local rules behavior-based and generic.
5. Live capture by default with schema-aware constant-offset shift to virtual time; pcap-then-offline reprocessing documented as the variant/Bulk technique; pcaps kept for Gold only.
6. Always export raw `eve.jsonl`; via-Wazuh copies share a deterministic `eve_event_id` for de-duplication.
7. Flows are assigned to episodes by start time; drain flushes remaining flows.
8. Observability matrix drives expected network detections.

## 13. Tests before trust

| Test | Pass criterion | Fallback |
|---|---|---|
| Tap placement on lab VMs (P1, P2, P3) | Canary traffic visible exactly where expected | Drop P3; keep P1+P2 |
| Checksum/offload handling | No spurious invalid-checksum drops | Adjust interface offload settings |
| Timestamp shift allowlist | Shifted EVE aligns with Wazuh/controller times within tolerance on 20 episodes | Switch to pcap-offline path |
| Flow flush at drain | No flows lost at shutdown | Add flush wait |
| ET date-gating with metadata | Rules filtered correctly; sample CVE-newer rule excluded | CVE-year heuristic |
| Profile reprocessing from pcap (variant path) | Two profiles from one pcap give different, valid EVE | Keep live-only |
| Via-Wazuh de-duplication | No double counting in Engine on golden sample | Fix id hashing |
| Drop rate at busy workload | Kernel drops 0 or recorded | Lower load or add resources |

Next: Part 7 (maturity and vulnerability metrics).
