# Measurements

Every planning estimate in the roadmap is replaced by a number recorded here. One row per measurement; never edit a row, add a new one.

| Date | Machine | What | Value | Method / notes |
| --- | --- | --- | --- | --- |
| 2026-11-02 | laptop (i7-1355U, 14.8 GiB) | Baseline specs | 12 threads, 9.8 GiB free with desktop, 402 GB free NVMe, Docker 29.1.3, cgroup v2 | `specs.txt` |
| 2026-11-02 | laptop | Wazuh manager ready (cold / warm) | 15.3 s / 11.3 s | `iris spike wazuh`, six required daemons running |
| 2026-11-02 | laptop | Agents active after manager (cold / warm) | 31.2 s / 20.9 s | both agents `Active` |
| 2026-11-02 | laptop | Canary alert seen after agents active (cold / warm) | 43.7 s / 6.2 s | cold includes the agent's restart after its first shared-config push |
| 2026-11-02 | laptop | Warm pre-roll total (restore to canary) | 40.1 s | was planned as 2.5 min |
| 2026-11-02 | laptop | Wazuh RAM | manager 269-299 MiB, agent 24-26 MiB | `docker stats` |
| 2026-11-02 | laptop | Suricata 8.0.6 in router namespace | start 2.2 s, 112.5 MiB, 0 kernel drops | 2 interfaces |
| 2026-11-02 | laptop | EVE duplication | each forwarded flow seen on both interfaces; dedup leaves 1 per connection | 10 raw -> 5 |
| 2026-11-02 | laptop | libfaketime with Wazuh 4.14 | no daemon starts at any offset (incl. +0), 0.9.10 and 0.9.12 | dropped: shift at export |
| 2026-11-02 | laptop | Context packages | 1,000 built + verified in 20.5 s, 0 failures | `iris package batch` |
| 2026-11-02 | laptop | First live range (seed 42, 13 containers) | 768 MiB total (manager 321, Suricata 174, DB 70, app 75, others 1-40) | estimate was 3.5 GB |
| 2026-11-02 | laptop | Live run timings (images cached) | compose up 3.3 s, sensor 2.0 s, health gate 64 s, teardown 22 s | `iris range up` |
| 2026-11-02 | laptop | Image builds (first time) | wazuh-manager 146 s, node images 8-48 s, router 17 s, external 22 s | Docker layer cache shared |

## P1 spikes to fill

| Spike | Metric | Target | Result |
| --- | --- | --- | --- |
| Wazuh manager boot | seconds to all daemons up | under 120 s | 15.3 s cold, 11.3 s warm |
| Wazuh manager RAM | steady-state RSS | under 1.5 GB | about 300 MiB |
| Agent connect | seconds after manager up | under 60 s | 31.2 s cold, 20.9 s warm |
| Warm restore pre-roll | seconds from restore to canary seen | under 180 s | 40.1 s |
| libfaketime offset | alerts/archives carry virtual dates; correlation rules fire | pass | FAIL: replaced by export shift (pass) |
| State restore | same agent IDs, no replay-counter rejection, FIM baseline kept | pass | pass (IDs 001/002 kept, 0 replay errors) |
| Custom SCA policy | per-control results appear | pass | |
| Suricata in router namespace | canary flows seen once, correct 5-tuple, 0 drops | pass | pass after dedup |
| EVE time shift | aligned with Wazuh canary within 2 s | pass | |
| ET date-gating | CVE-newer sample rule excluded | pass | |
| EPSS history | dated values retrievable | pass or fallback | |
| Lane RAM | standard scenario peak | under 9 GB | |
| Fragment self-containment | correlation alert stays inside one fragment | pass | |
