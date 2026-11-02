"""P1 network spike (TBT-6.1, 6.2, 6.3, 6.4 and the dedup decision).

Two zones joined by a router/firewall container; one Suricata sensor runs inside the
router's network namespace and captures every router interface. Checks:

* allowed path works (5 HTTP requests) and the forbidden path is blocked by nftables;
* the sensor sees the traffic, community_id is present, kernel drops are 0;
* forwarded flows appear on BOTH interfaces (the duplication we predicted) and
  :func:`iris.generator.eve.dedup` brings them back to exactly one per connection;
* the EVE timestamp format parses and shifts cleanly into a virtual window.
"""

from __future__ import annotations

import json
import re
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from iris.core.vclock import iso_z, real_utc_now
from iris.generator.eve import dedup, kernel_drops, parse_eve_ts, shift_event
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

PROJECT = "iris-spike-net"
ROUTER, CLIENT, SERVER, SENSOR = (
    "iris-spike-net-router",
    "iris-spike-net-client",
    "iris-spike-net-server",
    "iris-spike-net-sensor",
)
DEFAULT_SURICATA_IMAGE = "jasonish/suricata:8.0.6"
SERVER_IP, CLIENT_IP = "10.99.2.10", "10.99.1.10"
HTTP_REQUESTS = 5
VIRTUAL_START = datetime(2025, 3, 10, 6, 0, tzinfo=UTC)

NFT_RULES = [
    "add table inet iris",
    "add chain inet iris fwd { type filter hook forward priority 0 ; policy drop ; }",
    "add rule inet iris fwd ct state established,related accept",
    "add rule inet iris fwd ip saddr 10.99.1.0/24 ip daddr 10.99.2.0/24 tcp dport 8080 accept",
    "add rule inet iris fwd icmp type echo-request accept",
]

_ADDR = re.compile(r"^\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)/")


def parse_interfaces(ip_addr_output: str) -> dict[str, str]:
    """``ip -o -4 addr show`` -> {ip: ifname}, loopback excluded."""
    out: dict[str, str] = {}
    for line in ip_addr_output.splitlines():
        m = _ADDR.match(line.strip())
        if m and m.group(1) != "lo":
            out[m.group(2)] = m.group(1).split("@")[0]
    return out


def load_eve(text: str) -> list[dict[str, Any]]:
    events = []
    for line in text.splitlines():
        if line.strip():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def flows_to(
    events: list[dict[str, Any]], dest_ip: str, dest_port: int, event_type: str = "flow"
) -> list[dict[str, Any]]:
    return [
        e
        for e in events
        if e.get("event_type") == event_type
        and e.get("dest_ip") == dest_ip
        and e.get("dest_port") == dest_port
    ]


def analyse(events: list[dict[str, Any]], result: SpikeResult) -> None:
    raw_flows = flows_to(events, SERVER_IP, 8080)
    deduped = dedup(events)
    clean_flows = flows_to(deduped, SERVER_IP, 8080)
    clean_http = flows_to(deduped, SERVER_IP, 8080, "http")
    result.measure("eve.raw_events", len(events))
    result.measure("eve.deduped_events", len(deduped))
    result.measure("eve.raw_flows_8080", len(raw_flows))
    result.measure("eve.interfaces_seen", sorted({e.get("in_iface", "?") for e in raw_flows}))
    result.check("eve.community_id_present", any(e.get("community_id") for e in events), None)
    result.check(
        "eve.duplicates_observed", None, len(raw_flows) - len(clean_flows), "copies removed by dedup"
    )
    result.check("eve.dedup_one_per_connection", len(clean_flows) == HTTP_REQUESTS, len(clean_flows))
    result.check("eve.http_events_after_dedup", len(clean_http) == HTTP_REQUESTS, len(clean_http))
    blocked = flows_to(deduped, SERVER_IP, 9090)
    result.check(
        "eve.blocked_attempt_visible", None, len(blocked), "SYNs to the denied port seen by the sensor"
    )
    drops = kernel_drops(events)
    result.check("eve.kernel_drops_zero", drops == 0 if drops is not None else None, drops)

    stamped = [e for e in deduped if "timestamp" in e]
    if stamped:
        first = min(parse_eve_ts(e["timestamp"]) for e in stamped)
        offset = VIRTUAL_START - first
        shifted = [parse_eve_ts(shift_event(e, offset)["timestamp"]) for e in stamped]
        ok = all(VIRTUAL_START <= t <= VIRTUAL_START + timedelta(minutes=30) for t in shifted)
        result.check(
            "eve.time_shift_into_virtual_window", ok, f"{iso_z(min(shifted))} .. {iso_z(max(shifted))}"
        )


def _sensor_started() -> bool:
    logs = sh(["docker", "logs", SENSOR], check=False, timeout=30)
    text = (logs.stdout + logs.stderr).lower()
    if "error" in text and "exited" in text:
        raise SpikeError("sensor exited")
    return "engine started" in text


def run(build: bool = True, keep: bool = False, suricata_image: str = DEFAULT_SURICATA_IMAGE) -> SpikeResult:
    run_dir = new_run_dir("network")
    result = SpikeResult("network", iso_z(real_utc_now()))
    result.measure("run_dir", str(run_dir))
    result.measure("suricata_image", suricata_image)
    cfile = spike_file("network.compose.yml")
    try:
        require_docker()
        if build or not image_exists("iris/netbox:spike"):
            result.measure("build_s.netbox", build_image("iris/netbox:spike", images_dir() / "netbox"))
        t0 = time.monotonic()
        sh(["docker", "pull", suricata_image], timeout=900)
        result.measure("pull_s.suricata", round(time.monotonic() - t0, 1))
        sh(["docker", "rm", "-f", SENSOR], check=False)
        compose(PROJECT, cfile, ["down", "-v", "--remove-orphans"])
        compose(PROJECT, cfile, ["up", "-d"])

        for rule in NFT_RULES:
            docker_exec(ROUTER, f"nft '{rule}'")
        docker_exec(CLIENT, "ip route replace 10.99.2.0/24 via 10.99.1.1")
        docker_exec(SERVER, "ip route replace 10.99.1.0/24 via 10.99.2.1")
        ifaces = parse_interfaces(docker_exec(ROUTER, "ip -o -4 addr show"))
        result.measure("router_interfaces", ifaces)
        if len(ifaces) < 2:
            raise SpikeError(f"router should have 2 interfaces, found {ifaces}")

        iface_args = [arg for name in sorted(set(ifaces.values())) for arg in ("-i", name)]
        t0 = time.monotonic()
        sh(
            [
                "docker", "run", "-d", "--name", SENSOR, "--network", f"container:{ROUTER}",
                "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW", "--cap-add", "SYS_NICE",
                suricata_image, *iface_args, "-k", "none",
                "--set", "outputs.1.eve-log.community-id=true",
            ],
            timeout=120,
        )  # fmt: skip
        ok, secs = wait_until(_sensor_started, timeout=120)
        result.check("sensor.started", ok, secs, f"capturing on {sorted(set(ifaces.values()))}")
        result.measure("sensor.start_s", round(time.monotonic() - t0, 1))
        if not ok:
            raise SpikeError("suricata did not start; see sensor logs in run dir")
        time.sleep(3)

        codes = docker_exec(
            CLIENT,
            f"for i in $(seq 1 {HTTP_REQUESTS}); do curl -s -o /dev/null -w '%{{http_code}}\\n' --max-time 5 "
            f"http://{SERVER_IP}:8080/; sleep 1; done",
            timeout=60,
        ).split()
        result.check("path.allowed_http_200", codes.count("200") == HTTP_REQUESTS, codes)
        rc = docker_exec(CLIENT, f"nc -z -w 3 {SERVER_IP} 9090; echo $?", timeout=30, check=False).strip()
        server_seen = docker_exec(SERVER, "cat /tmp/nc9090.log", check=False).strip()
        result.check("path.forbidden_blocked", rc.endswith("1") and not server_seen, {"nc_rc": rc})
        docker_exec(CLIENT, f"ping -c 3 -W 2 {SERVER_IP}", timeout=30, check=False)

        time.sleep(5)
        result.measure("sensor.mem_mib", mem_mib(SENSOR))
        sh(["docker", "stop", "-t", "30", SENSOR], timeout=60)  # graceful: flushes open flows
        logs = sh(["docker", "logs", SENSOR], check=False)
        (run_dir / "suricata.log").write_text(logs.stdout + logs.stderr)
        sh(["docker", "cp", f"{SENSOR}:/var/log/suricata/eve.json", str(run_dir / "eve.json")], timeout=60)
        events = load_eve(Path(run_dir / "eve.json").read_text())
        analyse(events, result)
    except SpikeError as exc:
        result.errors.append(str(exc))
    except Exception as exc:
        result.errors.append(f"{type(exc).__name__}: {exc}")
    finally:
        if not keep:
            sh(["docker", "rm", "-f", SENSOR], check=False)
            try:
                compose(PROJECT, cfile, ["down", "-v", "--remove-orphans"])
            except SpikeError as exc:
                result.errors.append(f"teardown: {exc}")
        write_result(result, run_dir)
    return result
