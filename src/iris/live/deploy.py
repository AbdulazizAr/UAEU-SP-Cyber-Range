"""Deploy, health-gate and tear down one compiled enterprise (one lane, one scenario).

Run directory: ``$IRIS_DATA/runs/live/<stamp>-<project>/`` holds compose.yaml,
router.nft, compiled.json, health.json, state.json, timings.json and container logs.
These are hidden-plane files: compiled.json includes the scenario's credentials.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from iris.contracts.common import AssetRole
from iris.contracts.spec import ScenarioSpec
from iris.core.vclock import iso_z, real_utc_now
from iris.generator.compiler import SURICATA_IMAGE, CompiledRange, compile_spec
from iris.live.health import HealthGate, Target
from iris.live.images import ensure_images
from iris.live.state import RunState
from iris.settings import paths
from iris.spikes.common import SpikeError, compose, mem_mib, sh, wait_until
from iris.spikes.network import parse_interfaces

LABEL = "iris.project"


@dataclass
class LiveRun:
    spec: ScenarioSpec
    compiled: CompiledRange
    run_dir: Path
    state: RunState
    timings: dict[str, float] = field(default_factory=dict)
    health: dict[str, Any] = field(default_factory=dict)

    @property
    def project(self) -> str:
        return self.compiled.project

    @property
    def sensor(self) -> str:
        return f"{self.project}-ids"

    def compose_file(self) -> Path:
        return self.run_dir / "compose.yaml"


def new_run(spec: ScenarioSpec) -> LiveRun:
    compiled = compile_spec(spec)
    stamp = iso_z(real_utc_now()).replace(":", "").replace("-", "")
    run_dir = paths().runs / "live" / f"{stamp}-{compiled.project}"
    run_dir.mkdir(parents=True, exist_ok=True)
    compiled.write(run_dir)
    (run_dir / "spec.json").write_text(spec.model_dump_json(indent=2), encoding="utf-8")
    state = RunState(run_dir / "state.json", compiled.project)
    state.save()
    return LiveRun(spec, compiled, run_dir, state)


def running_projects() -> dict[str, list[str]]:
    """Every iris project with containers on this machine -> container names."""
    out = sh(
        [
            "docker",
            "ps",
            "-a",
            "--filter",
            f"label={LABEL}",
            "--format",
            '{{.Names}}\t{{.Label "iris.project"}}',
        ],
        check=False,
    ).stdout
    projects: dict[str, list[str]] = {}
    for line in out.splitlines():
        if "\t" in line:
            name, proj = line.split("\t", 1)
            projects.setdefault(proj, []).append(name)
    return projects


def docker_subnets() -> dict[str, list[str]]:
    """Every Docker network on this machine -> its IPv4 subnets."""
    ids = sh(["docker", "network", "ls", "-q"], check=False).stdout.split()
    if not ids:
        return {}
    out = sh(
        [
            "docker",
            "network",
            "inspect",
            "--format",
            "{{.Name}}|{{range .IPAM.Config}}{{.Subnet}} {{end}}",
            *ids,
        ],
        check=False,
    ).stdout
    nets: dict[str, list[str]] = {}
    for line in out.splitlines():
        name, _, subs = line.partition("|")
        nets[name] = [x for x in subs.split() if "." in x]
    return nets


def subnet_conflicts(spec: ScenarioSpec, existing: dict[str, list[str]]) -> list[str]:
    """Zones of this scenario that overlap a network already on the machine."""
    import ipaddress

    out = []
    for z in spec.zones:
        mine = ipaddress.ip_network(z.subnet)
        for name, subs in sorted(existing.items()):
            for sub in subs:
                if mine.overlaps(ipaddress.ip_network(sub, strict=False)):
                    out.append(f"{z.name} {z.subnet} overlaps {name} {sub}")
    return out


def _states() -> dict[str, str]:
    out = sh(["docker", "ps", "-a", "--format", "{{.Names}}\t{{.State}}"], check=False).stdout
    return dict(line.split("\t", 1) for line in out.splitlines() if "\t" in line)


def _logs(name: str) -> str:
    cp = sh(["docker", "logs", name], check=False, timeout=60)
    return (cp.stdout or "") + (cp.stderr or "")


def _timed(run: LiveRun, key: str, t0: float) -> None:
    run.timings[key] = round(time.monotonic() - t0, 1)


def build(run: LiveRun, force: bool = False) -> None:
    run.state.to("BUILDING")
    t0 = time.monotonic()
    run.health["builds"] = ensure_images(run.compiled.meta, force=force)
    _timed(run, "build_s", t0)


def deploy(run: LiveRun) -> None:
    run.state.to("DEPLOYING")
    t0 = time.monotonic()
    compose(run.project, run.compose_file(), ["up", "-d", "--no-build"])
    _timed(run, "compose_up_s", t0)
    start_sensor(run)
    _timed(run, "deploy_total_s", t0)


def start_sensor(run: LiveRun) -> None:
    router = next(a for a in run.spec.assets if a.role is AssetRole.ROUTER_FIREWALL)
    rc = f"{run.project}-{router.hostname}"
    ok, _ = wait_until(lambda: len(parse_interfaces(_exec(rc, "ip -o -4 addr show"))) >= 2, timeout=60)
    if not ok:
        raise SpikeError("router interfaces did not come up")
    ifaces = sorted(set(parse_interfaces(_exec(rc, "ip -o -4 addr show")).values()))
    sh(["docker", "rm", "-f", run.sensor], check=False)
    sh(
        [
            "docker", "run", "-d", "--name", run.sensor, "--label", f"{LABEL}={run.project}",
            "--network", f"container:{rc}",
            "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW", "--cap-add", "SYS_NICE",
            SURICATA_IMAGE, *[x for i in ifaces for x in ("-i", i)], "-k", "none",
            "--set", "outputs.1.eve-log.community-id=true",
        ],
        timeout=120,
    )  # fmt: skip
    ok, secs = wait_until(lambda: "engine started" in _logs(run.sensor).lower(), timeout=120)
    run.timings["sensor_start_s"] = secs
    if not ok:
        raise SpikeError("suricata did not start")


def _exec(container: str, cmd: str) -> str:
    return sh(["docker", "exec", container, "sh", "-c", cmd], check=False, timeout=60).stdout


def check(run: LiveRun, light: bool = False) -> bool:
    """Full gate (acceptance) or light gate (production: what recording depends on)."""
    run.state.to("CHECKING")
    t0 = time.monotonic()
    gate = HealthGate(Target(run.spec, run.project, run.compiled.meta), run=_exec)
    gate.containers(_states())
    gate.init(_logs)
    gate.router()
    gate.ports()
    if not light:
        gate.dns()
        gate.app_db()
        gate.paths()
        gate.egress()
    gate.wazuh()
    gate.canary()
    gate.suricata(run.sensor)
    if not light:
        gate.weaknesses()
    _timed(run, "health_s", t0)
    mems = {n: mem_mib(n) for n in running_projects().get(run.project, [])}
    run.health["mem_mib"] = mems
    run.health["mem_total_mib"] = round(sum(v for v in mems.values() if v), 1)
    run.health["result"] = gate.r.to_dict()
    healthy = gate.r.passed
    run.state.to("HEALTHY" if healthy else "UNHEALTHY")
    return healthy


def teardown(run: LiveRun) -> list[str]:
    """Stop everything with this project's label, then prove nothing is left."""
    run.state.to("TEARING_DOWN")
    t0 = time.monotonic()
    logdir = run.run_dir / "logs"
    logdir.mkdir(exist_ok=True)
    for name in running_projects().get(run.project, []):
        (logdir / f"{name.removeprefix(run.project + '-')}.log").write_text(_logs(name), encoding="utf-8")
    sh(["docker", "rm", "-f", run.sensor], check=False)
    try:
        compose(run.project, run.compose_file(), ["down", "-v", "--remove-orphans", "-t", "20"])
    except SpikeError as exc:
        run.health["teardown_error"] = str(exc)
    left = leftovers(run.project)
    _timed(run, "teardown_s", t0)
    run.health["leftovers"] = left
    run.state.to("TORN_DOWN" if not left else "FAILED", "; ".join(left))
    return left


def leftovers(project: str) -> list[str]:
    out = []
    for kind, cmd in (
        ("container", ["docker", "ps", "-a", "-q", "--filter", f"label={LABEL}={project}"]),
        ("network", ["docker", "network", "ls", "-q", "--filter", f"label={LABEL}={project}"]),
        ("volume", ["docker", "volume", "ls", "-q", "--filter", f"label={LABEL}={project}"]),
    ):
        out += [f"{kind}:{x}" for x in sh(cmd, check=False).stdout.split()]
    return out


def save(run: LiveRun) -> None:
    (run.run_dir / "health.json").write_text(json.dumps(run.health, indent=2, default=str) + "\n")
    (run.run_dir / "timings.json").write_text(json.dumps(run.timings, indent=2) + "\n")


def down_project(project: str) -> list[str]:
    """Remove every object of one project (used by ``iris range down``)."""
    names = running_projects().get(project, [])
    if names:
        sh(["docker", "rm", "-f", *names], check=False, timeout=300)
    for kind in ("network", "volume"):
        ids = sh(
            ["docker", kind, "ls", "-q", "--filter", f"label={LABEL}={project}"], check=False
        ).stdout.split()
        if ids:
            sh(
                ["docker", kind, "rm", "-f", *ids] if kind == "volume" else ["docker", kind, "rm", *ids],
                check=False,
            )
    return leftovers(project)
