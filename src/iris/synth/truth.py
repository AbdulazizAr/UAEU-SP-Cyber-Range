"""Hidden truth and reference keys for the synthetic path (builder brief file 05 §7, file 08 §2).

D1/D2/D4 keys are built here (not reused from ``iris.oracle.keys``) because the synth attack
families use the brief's numbering, while the frozen oracle assumes the live code's numbering
(decisions.md "Attack-family numbering"). The key SHAPE matches what ``iris.evaluator.decisions``
already consumes, so the evaluator runs unchanged. D6 (GRC flaw) keys still come from the GRC
timeline in the packager. Keys are derived only from what actually happened on the enterprise.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from iris.core.vclock import iso_z
from iris.synth.activity.model import Activity
from iris.synth.activity.planner import EpisodePlan, ScenarioPlan
from iris.synth.world import World

TRUTH_VERSION = "synth-truth-0.1.0"
D1_KEY_VERSION = "d1-key-syn-0.1.0"
D2_KEY_VERSION = "d2-key-syn-0.1.0"
D4_KEY_VERSION = "d4-key-syn-0.1.0"

SCENARIO_CLASS = {
    "F1": "credential_access",
    "F2": "web_application_compromise",
    "F3": "privilege_abuse",
    "F4": "reconnaissance",
    "F5": "lateral_movement",
    "F6": "collection_exfiltration",
    "F7": "persistence",
    "F8": "insider_misuse",
    "F9": "command_and_control",
}
_PRIORITY_BY_CRIT = {1: "LOW", 2: "LOW", 3: "MEDIUM", 4: "HIGH", 5: "HIGH"}
_BUMP = {"LOW": "MEDIUM", "MEDIUM": "HIGH", "HIGH": "CRITICAL", "CRITICAL": "CRITICAL"}
_ACTION_BY_STATE = {"missing": "implement", "partial": "strengthen", "implemented": "verify"}


def _malicious(ep: EpisodePlan) -> list[Activity]:
    return [a for a in ep.activities if a.kind == "malicious"]


def _dominant_family(mal: list[Activity]) -> str | None:
    fams = Counter(a.family for a in mal if a.family)
    return min(fams, key=lambda f: (-fams[f], f)) if fams else None


def _compromised(mal: list[Activity]) -> bool:
    return any(a.outcome == "success" for a in mal)


def _max_crit(world: World, mal: list[Activity]) -> int:
    return max((world.true_criticality(a.target_asset) for a in mal if a.target_asset), default=1)


def build_d1_key(world: World, ep: EpisodePlan) -> dict[str, Any]:
    mal = _malicious(ep)
    fam = _dominant_family(mal)
    return {
        "version": D1_KEY_VERSION,
        "episode_id": ep.episode_id,
        "as_of": iso_z(ep.start),
        "verdict": "malicious" if mal else "benign",
        "family": fam,
        "scenario_class": SCENARIO_CLASS.get(fam or "", "benign_operations" if not mal else "other"),
        "techniques": sorted({a.technique for a in mal if a.technique}),
        "tactics": sorted({a.tactic for a in mal if a.tactic}),
        "detectability": ("DC1" if any(a.expected_rules for a in mal) else "DC3") if mal else "n/a",
        "compromised": _compromised(mal),
        "confidence_tier": "T1",
    }


def build_d2_key(world: World, ep: EpisodePlan) -> dict[str, Any]:
    mal = _malicious(ep)
    if not mal:
        return {
            "version": D2_KEY_VERSION,
            "episode_id": ep.episode_id,
            "as_of": iso_z(ep.start),
            "incident": False,
            "priority": None,
            "compromised": False,
            "confidence_tier": "T1",
        }
    crit = _max_crit(world, mal)
    priority = _PRIORITY_BY_CRIT.get(crit, "MEDIUM")
    if _compromised(mal):
        priority = _BUMP[priority]
    return {
        "version": D2_KEY_VERSION,
        "episode_id": ep.episode_id,
        "as_of": iso_z(ep.start),
        "incident": True,
        "priority": priority,
        "max_criticality": crit,
        "compromised": _compromised(mal),
        "confidence_tier": "T1",
    }


def build_d4_key(world: World, ep: EpisodePlan) -> dict[str, Any]:
    recs: list[dict[str, Any]] = []
    seen: set[str] = set()
    for a in _malicious(ep):
        cid = a.enabling_control
        if cid is None or cid in seen:
            continue
        seen.add(cid)
        state = world.reality.controls[cid].state if cid in world.reality.controls else "missing"
        recs.append(
            {
                "control_id": cid,
                "action": _ACTION_BY_STATE.get(state, "implement"),
                "control_state": state,
                "state_source": "reality",
                "because": {
                    "weakness_module": a.weakness_module,
                    "asset_id": a.target_asset,
                    "technique": a.technique,
                    "outcome": a.outcome,
                },
            }
        )
    return {
        "version": D4_KEY_VERSION,
        "episode_id": ep.episode_id,
        "as_of": iso_z(ep.start),
        "actionable": bool(recs),
        "recommendations": recs,
        "confidence_tier": "T1",
    }


def outcome_truth(world: World, ep: EpisodePlan) -> dict[str, Any]:
    mal = _malicious(ep)
    return {
        "version": TRUTH_VERSION,
        "episode_id": ep.episode_id,
        "as_of": iso_z(ep.start),
        "compromised": _compromised(mal),
        "malicious_count": len(mal),
        "families": sorted({a.family for a in mal if a.family}),
        "techniques": sorted({a.technique for a in mal if a.technique}),
        "affected_assets": sorted({a.target_asset for a in mal if a.target_asset}),
        "succeeded": sorted({a.weakness_module for a in mal if a.outcome == "success" and a.weakness_module}),
    }


def campaign_truth(plan: ScenarioPlan) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    step: dict[str, int] = {}
    for ep in plan.episodes:
        for a in ep.activities:
            if a.campaign_id:
                step[a.campaign_id] = step.get(a.campaign_id, 0) + 1
                rows.append(
                    {
                        "campaign_id": a.campaign_id,
                        "activity_id": a.activity_id,
                        "step_number": step[a.campaign_id],
                        "parent_activity_id": a.parent_activity_id,
                        "tactic": a.tactic,
                        "technique": a.technique,
                        "target_asset": a.target_asset,
                    }
                )
    return rows


def detection_expectations(plan: ScenarioPlan) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for a in plan.activities:
        if a.kind != "malicious":
            continue
        rows.append(
            {
                "activity_id": a.activity_id,
                "template_id": a.template_id,
                "expected_wazuh_rule_ids": sorted(a.expected_rules),
                "expected_sensor": "wazuh" if a.expected_rules else "suricata_or_none",
                "expectation_strength": "strong" if a.expected_rules else "weak",
                "mapping_version": "synth-detect-0.1.0",
                "review_status": "unreviewed",
            }
        )
    return rows


def decision_keys(world: World, plan: ScenarioPlan) -> dict[str, dict[str, Any]]:
    """Return ``{hidden_relpath: key}`` for D1/D2/D4 and outcome truth per episode."""
    out: dict[str, dict[str, Any]] = {}
    for ep in plan.episodes:
        out[f"evaluation_key/d1/{ep.episode_id}.json"] = build_d1_key(world, ep)
        out[f"evaluation_key/d2/{ep.episode_id}.json"] = build_d2_key(world, ep)
        out[f"evaluation_key/d4/{ep.episode_id}.json"] = build_d4_key(world, ep)
        out[f"truth/outcomes/{ep.episode_id}.json"] = outcome_truth(world, ep)
    return out
