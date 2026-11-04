"""Record self-contained fragments from a deployed range (one activity per fragment).

For each action in the episode plan, snapshot the telemetry line counts, run just that
action, then read the newly appended alerts and EVE records. Those records are the
fragment's telemetry; they are abstracted with the scenario mapping and saved. Because
each action runs alone, attribution is exact: every record in the fragment belongs to it.

Needs a healthy deployed range (Docker). The pure helpers (delta extraction, timestamp
parsing) are unit tested without Docker.
"""

from __future__ import annotations

import time
from datetime import datetime
from typing import Any

from iris.core.hashing import sha256_hex
from iris.core.seeds import SeedSet
from iris.core.vclock import parse_iso
from iris.fragments.assemble import assemble_fragment
from iris.fragments.library import save_fragment
from iris.fragments.mapping import scenario_mapping
from iris.fragments.model import Fragment, FragmentTruth
from iris.generator.eve import parse_eve_ts
from iris.generator.secrets import scenario_secrets
from iris.live.activity import build_plan
from iris.live.attacks import outcome_of_action
from iris.live.health import Target
from iris.spikes.common import sh


def _lines(container: str, path: str) -> list[str]:
    out = sh(
        ["docker", "exec", container, "sh", "-c", f"cat {path} 2>/dev/null"], check=False, timeout=60
    ).stdout
    return [ln for ln in out.splitlines() if ln.strip().startswith("{")]


def _count(container: str, path: str) -> int:
    out = sh(
        ["docker", "exec", container, "sh", "-c", f"wc -l < {path} 2>/dev/null || echo 0"], check=False
    ).stdout
    try:
        return int(out.strip() or "0")
    except ValueError:
        return 0


def delta(before: int, lines: list[str]) -> list[str]:
    """Records appended after line index ``before`` (JSON lines only)."""
    return lines[before:]


def wazuh_time(body: dict[str, Any]) -> datetime:
    return parse_iso(body["timestamp"].replace("+0000", "+00:00"))


def eve_time(body: dict[str, Any]) -> datetime:
    return parse_eve_ts(body["timestamp"])


def record_fragments(
    target: Target, group_id: str, data_dir: Any = None, settle: float = 8.0
) -> list[Fragment]:
    import json

    from iris.contracts.common import AssetRole

    spec = target.spec
    seeds = SeedSet.from_dict(spec.seeds.model_dump())
    sec = scenario_secrets(spec)
    pairs, hints = scenario_mapping(spec, sec)
    plan = build_plan(spec, sec, seeds.stream("traffic", "fragments"))
    mgr = target.container(target.by_role(AssetRole.SIEM)[0].asset_id)
    sensor = target.sensor_container()
    actor = {
        "client": target.external("client"),
        "attacker": target.external("attacker") or target.external("client"),
    }
    out: list[Fragment] = []
    for action in plan.actions:
        container = actor.get(action.actor)
        if not container:
            continue
        a0 = _count(mgr, "/var/ossec/logs/alerts/alerts.json")
        e0 = _count(sensor, "/var/log/suricata/eve.json")
        sh(["docker", "exec", container, "sh", "-c", action.command], check=False, timeout=120)
        time.sleep(settle)
        new_alerts = delta(a0, _lines(mgr, "/var/ossec/logs/alerts/alerts.json"))
        new_eve = delta(e0, _lines(sensor, "/var/log/suricata/eve.json"))
        raw: list[tuple[str, datetime, str, dict[str, Any]]] = []
        for line in new_alerts:
            try:
                b = json.loads(line)
                raw.append(("wazuh_alert", wazuh_time(b), "timestamp", b))
            except (json.JSONDecodeError, KeyError, ValueError):
                continue
        for line in new_eve:
            try:
                b = json.loads(line)
                if b.get("event_type") in ("http", "tls", "flow", "alert"):
                    raw.append(("suricata_eve", eve_time(b), "timestamp", b))
            except (json.JSONDecodeError, KeyError, ValueError):
                continue
        if not raw:
            continue
        truth = FragmentTruth(
            label=action.label,
            family=action.family or ("persona_customer" if action.label == "benign" else "F0"),
            outcome=outcome_of_action(action.name, action.label),
            technique=action.technique,
            weakness_module=_module_of(spec, action.weakness_id),
            stage=action.stage,
            expected_rules=action.expect_rules,
        )
        fid = "frg-" + sha256_hex(f"{group_id}|{action.name}|{action.step}")[:16]
        requires = {"family": truth.family}
        if truth.weakness_module:
            requires["weakness"] = truth.weakness_module
        frag = assemble_fragment(
            fid,
            group_id,
            "attack_stage" if action.label == "malicious" else "benign",
            truth,
            raw,
            pairs,
            hints,
            requires,
        )
        save_fragment(frag, data_dir)
        out.append(frag)
    return out


def _module_of(spec: Any, weakness_id: str | None) -> str | None:
    if not weakness_id:
        return None
    return next((w.module for w in spec.weaknesses if w.weakness_id == weakness_id), None)
