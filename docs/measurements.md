# Measurements

Every planning estimate in the roadmap is replaced by a number recorded here. One row per measurement; never edit a row, add a new one.

| Date | Machine | What | Value | Method / notes |
| --- | --- | --- | --- | --- |
| 2026-11-02 | laptop (i7-1355U, 14.8 GiB) | Baseline specs | 12 threads, 9.8 GiB free with desktop, 402 GB free NVMe, Docker 29.1.3, cgroup v2 | `specs.txt` |

## P1 spikes to fill

| Spike | Metric | Target | Result |
| --- | --- | --- | --- |
| Wazuh manager boot | seconds to all daemons up | under 120 s | |
| Wazuh manager RAM | steady-state RSS | under 1.5 GB | |
| Agent connect | seconds after manager up | under 60 s | |
| Warm restore pre-roll | seconds from restore to canary seen | under 180 s | |
| libfaketime offset | alerts/archives carry virtual dates; correlation rules fire | pass | |
| State restore | same agent IDs, no replay-counter rejection, FIM baseline kept | pass | |
| Custom SCA policy | per-control results appear | pass | |
| Suricata in router namespace | canary flows seen once, correct 5-tuple, 0 drops | pass | |
| EVE time shift | aligned with Wazuh canary within 2 s | pass | |
| ET date-gating | CVE-newer sample rule excluded | pass | |
| EPSS history | dated values retrievable | pass or fallback | |
| Lane RAM | standard scenario peak | under 9 GB | |
| Fragment self-containment | correlation alert stays inside one fragment | pass | |
