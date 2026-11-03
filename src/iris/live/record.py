"""Record one episode of a deployed range and check the SOC detected what it should.

Flow (all on the real clock; the exporter shifts to virtual time afterwards):
1. pre-roll: the range is already deployed and health-gated (hidden).
2. mark observe_start, run the activity plan from the external nodes with small gaps.
3. mark observe_end, let detections settle, collect the raw alerts/archives/eve.
4. export the window (``iris.generator.export``) and compare the alerts actually raised
   against the plan's ``expect_rules``.

The detection matching is a pure function (:func:`match_detections`) so it is unit
tested without Docker; the capture itself needs a running range.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from iris.core.seeds import SeedSet
from iris.core.vclock import real_utc_now
from iris.generator.export import EpisodeCapture, ExportedEpisode, export_episode
from iris.generator.secrets import scenario_secrets
from iris.live.activity import ActivityPlan, build_plan
from iris.live.health import Target
from iris.spikes.common import sh


def rule_id(alert: dict[str, Any]) -> int | None:
    rule = alert.get("rule")
    if isinstance(rule, dict):
        try:
            return int(rule["id"])
        except (KeyError, TypeError, ValueError):
            return None
    return None


@dataclass
class DetectionResult:
    expected: list[int]
    observed_rules: list[int]
    matched: list[int] = field(default_factory=list)
    missed: list[int] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.missed


def match_detections(plan: ActivityPlan, alerts: list[dict[str, Any]]) -> DetectionResult:
    """Every rule a malicious action expects must appear among the observed alerts."""
    observed = sorted({r for a in alerts if (r := rule_id(a)) is not None})
    expected = sorted({rid for a in plan.actions if a.label == "malicious" for rid in a.expect_rules})
    observed_set = set(observed)
    matched = [rid for rid in expected if rid in observed_set]
    missed = [rid for rid in expected if rid not in observed_set]
    return DetectionResult(expected=expected, observed_rules=observed, matched=matched, missed=missed)


@dataclass
class EpisodeRecord:
    episode_id: str
    exported: ExportedEpisode
    detections: DetectionResult
    plan_truth: list[dict[str, Any]]
    counts: dict[str, Any]


def _exec(container: str, cmd: str, timeout: float = 60) -> str:
    return sh(["docker", "exec", container, "sh", "-c", cmd], check=False, timeout=timeout).stdout


def _jsonl(text: str) -> list[dict[str, Any]]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def record_episode(
    target: Target,
    episode_index: int,
    archives_retained: bool = True,
    gap_seconds: float = 1.0,
    settle_seconds: float = 12.0,
) -> EpisodeRecord:
    from iris.contracts.common import AssetRole
    from iris.core.hashing import episode_id as make_eid
    from iris.core.hashing import scenario_id

    spec = target.spec
    seeds = SeedSet.from_dict(spec.seeds.model_dump())
    scn = scenario_id({"seeds": seeds.to_dict()})
    ep = spec.episodes[episode_index]
    eid = make_eid(scn, ep.index)
    secrets = scenario_secrets(spec)
    plan = build_plan(spec, secrets, seeds.stream("traffic", f"activity.{ep.index}"))

    siem = target.by_role(AssetRole.SIEM)[0]
    mgr = target.container(siem.asset_id)
    actor_container = {
        "client": target.external("client"),
        "attacker": target.external("attacker") or target.external("client"),
    }

    observe_start = real_utc_now()
    for action in plan.actions:
        container = actor_container.get(action.actor)
        if container:
            _exec(container, action.command, timeout=90)
            time.sleep(gap_seconds)
    observe_end = real_utc_now()
    time.sleep(settle_seconds)  # let analysisd finish and alerts land

    cap = EpisodeCapture(
        episode_id=eid,
        virtual_start=ep.virtual_start,
        observe_start_real=observe_start,
        observe_end_real=observe_end,
        alerts=_jsonl(_exec(mgr, "cat /var/ossec/logs/alerts/alerts.json", timeout=120)),
        archives=_jsonl(_exec(mgr, "cat /var/ossec/logs/archives/archives.json", timeout=120)),
        eve=_jsonl(_exec(target.sensor_container(), "cat /var/log/suricata/eve.json", timeout=120)),
    )
    exported = export_episode(cap, archives_retained=archives_retained)
    window_alerts = exported.visible["telemetry/wazuh/alerts.jsonl"]
    detections = match_detections(plan, window_alerts)
    return EpisodeRecord(
        episode_id=eid,
        exported=exported,
        detections=detections,
        plan_truth=plan.truth(),
        counts={
            **exported.counts,
            "actions": len(plan.actions),
            "malicious_actions": sum(1 for a in plan.actions if a.label == "malicious"),
            "expected_rules": detections.expected,
            "observed_rules": detections.observed_rules,
        },
    )


def window(ep: Any, observe_minutes: int) -> timedelta:
    return ep.virtual_end - ep.virtual_start if ep else timedelta(minutes=observe_minutes)
