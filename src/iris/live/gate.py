"""One live run end to end, and the P2 exit gate (N seeds: deploy, healthy, clean teardown)."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from iris.core.seeds import SeedSet
from iris.generator.sampler import SampleOverrides, sample_spec
from iris.live import deploy as d
from iris.spikes.common import SpikeError, require_docker


@dataclass
class RunSummary:
    master: int
    project: str
    run_dir: str
    state: str
    healthy: bool
    failed_checks: list[str] = field(default_factory=list)
    timings: dict[str, float] = field(default_factory=dict)
    mem_total_mib: float | None = None
    containers: int = 0
    leftovers: list[str] = field(default_factory=list)
    error: str | None = None
    failed_details: dict[str, str] = field(default_factory=dict)
    conflict: list[str] = field(default_factory=list)


def run_once(
    master: int, keep: bool = False, build: bool = True, force_build: bool = False, light: bool = False
) -> RunSummary:
    require_docker()
    spec = sample_spec(SeedSet.from_master(master), SampleOverrides(live=True))
    others = sorted(d.running_projects())
    if others:
        raise SpikeError(f"other range projects are present on this lane: {others} (iris range down --all)")
    conflict = d.subnet_conflicts(spec, d.docker_subnets())
    if conflict:  # a lane problem, not a range failure: the gate moves on to the next seed
        return RunSummary(
            master=master,
            project="-",
            run_dir="-",
            state="SKIPPED_CONFLICT",
            healthy=False,
            conflict=conflict,
        )
    run = d.new_run(spec)
    healthy, error = False, None
    t0 = time.monotonic()
    try:
        if build:
            d.build(run, force=force_build)
        d.deploy(run)
        healthy = d.check(run, light=light)
    except Exception as exc:  # record, then always tear down unless asked to keep
        error = f"{type(exc).__name__}: {str(exc)[:500]}"
        if "Pool overlaps" in str(exc):  # a network appeared after the pre-check: still a lane conflict
            d.teardown(run)
            d.save(run)
            return RunSummary(
                master=master,
                project=run.project,
                run_dir=str(run.run_dir),
                state="SKIPPED_CONFLICT",
                healthy=False,
                conflict=[str(exc).strip().splitlines()[-1][:300]],
            )
        if run.state.state not in ("FAILED", "HEALTHY", "UNHEALTHY"):
            run.state.to("FAILED", error)
    run.timings["total_until_checked_s"] = round(time.monotonic() - t0, 1)
    left: list[str] = []
    if keep and run.state.state in ("HEALTHY", "UNHEALTHY"):
        run.state.to("KEPT")
    else:
        left = d.teardown(run)
    d.save(run)
    result: dict[str, Any] = run.health.get("result", {})
    failed = [c["name"] for c in result.get("checks", []) if c["status"] == "fail"]
    details = {
        c["name"]: str(c.get("detail") or c.get("value"))[:300]
        for c in result.get("checks", [])
        if c["status"] == "fail"
    }
    return RunSummary(
        master=master,
        project=run.project,
        run_dir=str(run.run_dir),
        state=run.state.state,
        healthy=healthy,
        failed_checks=failed,
        timings=run.timings,
        mem_total_mib=run.health.get("mem_total_mib"),
        containers=len(run.compiled.compose["services"]) + 1,
        leftovers=left,
        error=error,
        failed_details=details,
    )
