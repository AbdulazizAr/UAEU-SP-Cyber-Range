"""P1 Wazuh spike (TBT-3.1, 3.2, 3.3, 3.4 and the warm-restore measurement).

Measures and checks, on the pinned Wazuh version:

1. manager boot time and RAM; agent enrolment/connect time and RAM;
2. libfaketime offset mode: alerts and archives carry VIRTUAL dates, and a frequency
   correlation rule (sshd brute force, 5712) still fires;
3. warm restart = next episode: containers recreated from the same state volumes with
   the clock jumped 7 days forward. Agent IDs must survive, no replay-counter errors,
   new alerts must land in the new virtual window; warm pre-roll time is measured.
"""

from __future__ import annotations

import json
import re
import time
from datetime import UTC, datetime, timedelta
from typing import Any

from iris.core.vclock import EpisodeClock, iso_z, real_utc_now
from iris.spikes.common import (
    SpikeError,
    SpikeResult,
    build_image,
    compose,
    docker_exec,
    image_exists,
    images_dir,
    mem_mib,
    new_run_dir,
    require_docker,
    sh,
    spike_file,
    wait_until,
    write_result,
)

PROJECT = "iris-spike-wazuh"
MANAGER = "iris-spike-wazuh-manager"
AGENTS = {"iris-spike-wazuh-agent1": "spike-web-01", "iris-spike-wazuh-agent2": "spike-db-01"}
CANARY_AGENT = "iris-spike-wazuh-agent1"
EXPECTED_RULES = {"5710", "5712", "5716", "5760", "5503", "5551"}
BRUTE_FORCE_RULE = "5712"
LIBFAKETIME = "/usr/local/lib/libfaketime.so.1"
EPISODE_1 = datetime(2025, 3, 3, 5, 40, tzinfo=UTC)
JUMP = timedelta(days=7)
REPLAY_PATTERNS = ("invalid message", "counter", "rids", "error getting key", "duplicate", "already in use")

# ---------------------------------------------------------------- pure parsers (unit-tested)

_AGENT_LINE = re.compile(r"ID:\s*(\d+),\s*Name:\s*([^,]+),\s*IP:\s*([^,]+),\s*(.+?)\s*$")


def parse_agent_list(text: str) -> dict[str, tuple[str, str]]:
    """``agent_control -l`` -> {name: (id, status)}; skips the manager (ID 000)."""
    out: dict[str, tuple[str, str]] = {}
    for line in text.splitlines():
        m = _AGENT_LINE.search(line)
        if m and m.group(1) != "000":
            out[m.group(2).strip()] = (m.group(1), m.group(4).strip())
    return out


def parse_control_status(text: str) -> tuple[int, list[str]]:
    """``wazuh-control status`` -> (running count, names not running)."""
    running, down = 0, []
    for line in text.splitlines():
        line = line.strip()
        if " not running" in line:
            down.append(line.split()[0])
        elif " is running" in line:
            running += 1
    return running, down


def parse_json_lines(text: str) -> list[dict[str, Any]]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def alert_time(alert: dict[str, Any]) -> datetime:
    """Wazuh alert timestamps look like ``2025-03-03T05:41:02.123+0000``."""
    return datetime.strptime(alert["timestamp"], "%Y-%m-%dT%H:%M:%S.%f%z").astimezone(UTC)


def canary_alerts(
    alerts: list[dict[str, Any]], agent_name: str, since: datetime | None = None
) -> list[dict[str, Any]]:
    picked = []
    for a in alerts:
        if a.get("agent", {}).get("name") != agent_name:
            continue
        if str(a.get("rule", {}).get("id")) not in EXPECTED_RULES:
            continue
        if since is not None and alert_time(a) < since:
            continue
        picked.append(a)
    return picked


def error_lines(log: str, patterns: tuple[str, ...] = ("ERROR:", "CRITICAL:")) -> list[str]:
    return [line.strip() for line in log.splitlines() if any(p in line for p in patterns)]


# ---------------------------------------------------------------- live helpers


def _env(clock: EpisodeClock | None) -> dict[str, str]:
    if clock is None:
        return {"FAKETIME": "", "IRIS_LD_PRELOAD": ""}
    return {"FAKETIME": clock.faketime_spec(), "IRIS_LD_PRELOAD": LIBFAKETIME}


#: Daemons generation mode needs. Others (clusterd, maild, agentlessd, integratord, dbd,
#: csyslogd) are disabled by default and always report "not running".
REQUIRED_DAEMONS = (
    "wazuh-analysisd",
    "wazuh-remoted",
    "wazuh-authd",
    "wazuh-db",
    "wazuh-monitord",
    "wazuh-modulesd",
)


def manager_ready_from(status_text: str) -> tuple[bool, list[str]]:
    """Ready when every required daemon reports running. Returns (ready, missing)."""
    running = {line.split()[0] for line in status_text.splitlines() if " is running" in line and line.split()}
    missing = [d for d in REQUIRED_DAEMONS if d not in running]
    return not missing, missing


def _logs(container: str) -> str:
    cp = sh(["docker", "logs", "--tail", "60", container], check=False)
    return (cp.stdout or "") + (cp.stderr or "")


def _manager_ready() -> bool:
    ok, _ = manager_ready_from(docker_exec(MANAGER, "/var/ossec/bin/wazuh-control status", check=False))
    return ok


def _diagnose(result: SpikeResult, label: str) -> None:
    """On a failed start, keep what is needed to see why (status, container log, ossec.log)."""
    status = docker_exec(MANAGER, "/var/ossec/bin/wazuh-control status", check=False)
    _, missing = manager_ready_from(status)
    result.measure(f"{label}.missing_daemons", missing)
    result.measure(f"{label}.control_status", status.strip().splitlines()[-20:])
    result.measure(
        f"{label}.container_log_tail",
        _logs(MANAGER).splitlines()[-60:],
    )
    result.measure(
        f"{label}.ossec_errors",
        error_lines(docker_exec(MANAGER, "tail -n 400 /var/ossec/logs/ossec.log", check=False))[-30:],
    )


def _agents() -> dict[str, tuple[str, str]]:
    return parse_agent_list(docker_exec(MANAGER, "/var/ossec/bin/agent_control -l", check=False))


def _agents_active() -> bool:
    listed = _agents()
    return all(listed.get(name, ("", ""))[1].startswith("Active") for name in AGENTS.values())


def _alerts() -> list[dict[str, Any]]:
    return parse_json_lines(docker_exec(MANAGER, "cat /var/ossec/logs/alerts/alerts.json", check=False))


def _write_canary(lines: int = 12) -> None:
    cmd = (
        f"for i in $(seq 1 {lines}); do "
        "printf '%s web-01 sshd[%d]: Failed password for invalid user admin%d "
        "from 198.51.100.66 port %d ssh2\\n' "
        "\"$(date '+%b %e %H:%M:%S')\" $((4000+i)) $i $((40000+i)) >> /var/log/iris/canary.log; "
        "sleep 0.5; done"
    )
    docker_exec(CANARY_AGENT, cmd, timeout=60)


def _episode(
    result: SpikeResult, label: str, clock: EpisodeClock | None, window_start: datetime | None, cold: bool
) -> None:
    t_up = time.monotonic()
    compose(PROJECT, spike_file("wazuh.compose.yml"), ["up", "-d", "manager"], env=_env(clock))
    ok, secs = wait_until(_manager_ready, timeout=240)
    result.check(f"{label}.manager_ready", ok, secs, "required wazuh daemons running")
    result.measure(f"{label}.manager_ready_s", secs)
    if not ok:
        _diagnose(result, label)
        raise SpikeError(f"{label}: manager did not come up (diagnostics in results.json)")

    t_agents = time.monotonic()
    compose(PROJECT, spike_file("wazuh.compose.yml"), ["up", "-d", "agent1", "agent2"], env=_env(clock))
    ok, secs = wait_until(_agents_active, timeout=240)
    result.check(f"{label}.agents_active", ok, secs, "both agents Active")
    result.measure(f"{label}.agents_active_s", secs)
    if not ok:
        raise SpikeError(f"{label}: agents did not connect")

    before = {name: aid for name, (aid, _) in _agents().items()}
    result.measure(f"{label}.agent_ids", before)

    since = (window_start - timedelta(minutes=10)) if window_start else None
    _write_canary()
    ok, secs = wait_until(lambda: bool(canary_alerts(_alerts(), AGENTS[CANARY_AGENT], since)), timeout=180)
    result.check(f"{label}.canary_alert", ok, secs, f"rules {sorted(EXPECTED_RULES)}")
    total = round(time.monotonic() - t_up, 1)
    result.measure(f"{label}.preroll_total_s", total)
    result.measure(f"{label}.agents_to_canary_s", round(time.monotonic() - t_agents, 1))

    ok_bf, _ = wait_until(
        lambda: any(
            str(a["rule"]["id"]) == BRUTE_FORCE_RULE
            for a in canary_alerts(_alerts(), AGENTS[CANARY_AGENT], since)
        ),
        timeout=60,
    )
    result.check(f"{label}.correlation_rule_{BRUTE_FORCE_RULE}", ok_bf, None, "frequency rule fired")

    alerts = canary_alerts(_alerts(), AGENTS[CANARY_AGENT], since)
    if window_start is not None and alerts:
        times = [alert_time(a) for a in alerts]
        lo, hi = min(times), max(times)
        in_window = all(
            window_start - timedelta(minutes=10) <= t <= window_start + timedelta(minutes=90) for t in times
        )
        result.check(
            f"{label}.alert_times_virtual", in_window, f"{iso_z(lo)} .. {iso_z(hi)}", "manager clock"
        )
        pre = [a.get("predecoder", {}).get("timestamp", "") for a in alerts]
        want = window_start.strftime("%b %e").replace("  ", " ")
        same_day = all(" ".join(p.split()[:2]) == want for p in pre if p)
        result.check(f"{label}.log_line_times_virtual", same_day, pre[:2], "timestamp inside the log line")
    archives = docker_exec(
        MANAGER,
        "grep -c 'Failed password for invalid user' /var/ossec/logs/archives/archives.json",
        check=False,
    )
    result.check(f"{label}.archives_have_canary", archives.strip() not in ("", "0"), archives.strip())

    mems = {"manager": mem_mib(MANAGER), **{name: mem_mib(c) for c, name in AGENTS.items()}}
    result.measure(f"{label}.mem_mib", mems)
    if cold:
        result.measure("cold_start", True)


def run(build: bool = True, keep: bool = False, faketime: bool = True) -> SpikeResult:
    run_dir = new_run_dir("wazuh")
    result = SpikeResult("wazuh", iso_z(real_utc_now()))
    result.measure("run_dir", str(run_dir))
    result.measure("faketime", faketime)
    try:
        require_docker()
        for tag, ctx in (
            ("iris/wazuh-manager:spike", "wazuh-manager"),
            ("iris/wazuh-agent:spike", "wazuh-agent"),
        ):
            if build or not image_exists(tag):
                result.measure(f"build_s.{ctx}", build_image(tag, images_dir() / ctx))
        compose(PROJECT, spike_file("wazuh.compose.yml"), ["down", "-v", "--remove-orphans"])

        # Episode 1: cold start (enrolment happens here).
        clock1 = EpisodeClock.for_observe_start(EPISODE_1, real_utc_now()) if faketime else None
        _episode(result, "ep1", clock1, EPISODE_1 if faketime else None, cold=True)
        ids1 = result.measurements["ep1.agent_ids"]
        log1 = docker_exec(MANAGER, "cat /var/ossec/logs/ossec.log", check=False)
        (run_dir / "ep1_manager_ossec.log").write_text(log1)
        errs = error_lines(log1)
        result.check("ep1.manager_errors", None, len(errs), "; ".join(sorted(set(errs))[:10]))

        # Episode 2: recreate containers from the same volumes, clock jumped forward.
        compose(PROJECT, spike_file("wazuh.compose.yml"), ["stop", "-t", "30"])
        compose(PROJECT, spike_file("wazuh.compose.yml"), ["rm", "-f"])
        ep2 = EPISODE_1 + JUMP
        clock2 = EpisodeClock.for_observe_start(ep2, real_utc_now()) if faketime else None
        _episode(result, "ep2", clock2, ep2 if faketime else None, cold=False)
        ids2 = result.measurements["ep2.agent_ids"]
        result.check("ep2.agent_ids_stable", ids1 == ids2, {"ep1": ids1, "ep2": ids2})
        log2 = docker_exec(MANAGER, "cat /var/ossec/logs/ossec.log", check=False)
        (run_dir / "ep2_manager_ossec.log").write_text(log2)
        new_part = log2[len(log1) :] if log2.startswith(log1[:200]) else log2
        replay = [
            line
            for line in error_lines(new_part, ("ERROR:", "WARNING:", "CRITICAL:"))
            if any(p in line.lower() for p in REPLAY_PATTERNS)
        ]
        result.check("ep2.no_replay_errors", not replay, len(replay), "; ".join(replay[:5]))
        result.measure("warm_preroll_s", result.measurements.get("ep2.preroll_total_s"))
        (run_dir / "alerts.json").write_text(json.dumps(_alerts()[-500:], indent=1))
    except SpikeError as exc:
        result.errors.append(str(exc))
    except Exception as exc:  # report anything unexpected instead of losing the run
        result.errors.append(f"{type(exc).__name__}: {exc}")
    finally:
        if not keep:
            try:
                compose(PROJECT, spike_file("wazuh.compose.yml"), ["down", "-v", "--remove-orphans"])
            except SpikeError as exc:
                result.errors.append(f"teardown: {exc}")
        write_result(result, run_dir)
    return result
