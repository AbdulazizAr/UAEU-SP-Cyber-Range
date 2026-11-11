"""A transparent rule baseline for D1/D2/D4 over the VISIBLE plane (builder brief file 08 §5).

Reads only the visible package (telemetry, inventory, SCA) — never the hidden truth — and emits
DecisionRecords the evaluator scores against the hidden keys. It is deliberately simple ("alerts
present -> malicious"), so the ML Engine has a floor to beat; it is not the Engine. Lives in
``engine`` and imports only ``contracts``/``core`` (no generator/synth), per the boundaries.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from iris.contracts.decisions import (
    ControlRecommendation,
    D1Payload,
    D2Payload,
    D4Payload,
    DecisionRecord,
    SubjectRef,
)

BASELINE_ENGINE_VERSION = "baseline-rules-0.1.0"
BASELINE_POLICY_VERSION = "baseline-policy-0.1.0"

# dominant Wazuh rule group -> D1 scenario class (visible, coarse).
_GROUP_CLASS = {
    "authentication_failed": "credential_access",
    "authentication_failures": "credential_access",
    "web": "web_application_compromise",
    "attack": "web_application_compromise",
    "web_scan": "reconnaissance",
    "recon": "reconnaissance",
    "privilege_escalation": "privilege_abuse",
    "syscheck": "persistence",
}


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def _episode_ids(visible: Path) -> list[str]:
    asof = visible / "snapshots" / "asof"
    if asof.is_dir():
        return sorted(p.stem for p in asof.glob("*.json"))
    return []


def _priority(level: int, criticality: int) -> str:
    base = "LOW"
    if level >= 12:
        base = "HIGH"
    elif level >= 7:
        base = "MEDIUM"
    if criticality >= 4 and base in ("LOW", "MEDIUM"):
        base = {"LOW": "MEDIUM", "MEDIUM": "HIGH"}[base]
    return base


def _episode_as_of(visible: Path, eid: str, fallback: str) -> str:
    snap = _read_json(visible / "snapshots" / "asof" / f"{eid}.json") or {}
    return snap.get("valid_at") or snap.get("as_of") or fallback


def decide(visible: Path) -> list[DecisionRecord]:
    manifest = _read_json(visible / "manifest.visible.json") or _read_json(visible / "manifest.json") or {}
    scenario_id = str(manifest.get("scenario_id", ""))
    alerts = _read_jsonl(visible / "telemetry" / "wazuh" / "alerts.jsonl")
    eve = _read_jsonl(visible / "telemetry" / "suricata" / "eve.jsonl")
    sca = _read_jsonl(visible / "telemetry" / "wazuh" / "sca.jsonl")
    # asset criticality is a business judgement carried in the (visible) GRC business context
    crit: dict[str, int] = {}
    for row in _read_json(visible / "grc" / "business_context.json") or []:
        try:
            crit[row["entity_ref"]] = int(row.get("criticality") or 1)
        except (ValueError, TypeError):
            crit[row["entity_ref"]] = 1
    assets = crit

    per_ep_alerts: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for rec in alerts:
        per_ep_alerts[rec.get("episode_id", "")].append(rec)
    per_ep_eve_alert: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for rec in eve:
        if rec.get("raw", {}).get("event_type") == "alert":
            per_ep_eve_alert[rec.get("episode_id", "")].append(rec)

    out: list[DecisionRecord] = []
    for i, eid in enumerate(_episode_ids(visible)):
        ep_alerts = per_ep_alerts.get(eid, [])
        ep_eve = per_ep_eve_alert.get(eid, [])
        as_of = _episode_as_of(visible, eid, manifest.get("start_time") or manifest.get("end_time") or "")
        out.extend(_decide_episode(scenario_id, eid, i, as_of, ep_alerts, ep_eve, sca, assets))
    return out


def _decide_episode(
    scenario_id: str,
    eid: str,
    idx: int,
    as_of: str,
    ep_alerts: list[dict[str, Any]],
    ep_eve: list[dict[str, Any]],
    sca: list[dict[str, Any]],
    assets: dict[str, Any],
) -> list[DecisionRecord]:
    records: list[DecisionRecord] = []
    base = dict(
        scenario_id=scenario_id,
        episode_id=eid,
        as_of=as_of,
        engine_version=BASELINE_ENGINE_VERSION,
        model_version=BASELINE_ENGINE_VERSION,
        policy_version=BASELINE_POLICY_VERSION,
    )
    evidence = [a["event_id"] for a in ep_alerts] + [a["event_id"] for a in ep_eve]
    # Naive analyst-triage floor: flag on an alert of meaningful severity (Wazuh level >= 5) or any
    # Suricata signature hit — not on level-3 informational noise (successful logins, service
    # restarts), which fire in benign episodes too. This keeps the baseline beatable but
    # non-degenerate: hard negatives (authorized scans, admin sudo, backup bursts) still raise
    # false positives, and low-and-slow / insider attacks that never cross level 5 slip past it —
    # exactly the gap the ML Engine must close.
    high_alerts = [a for a in ep_alerts if int(a["raw"]["rule"]["level"]) >= 5]
    malicious = bool(high_alerts or ep_eve)

    # ---- D1
    if malicious:
        levels = [int(a["raw"]["rule"]["level"]) for a in ep_alerts] or [3]
        techniques = sorted({t for a in ep_alerts for t in a["raw"]["rule"].get("mitre", {}).get("id", [])})
        groups = [g for a in ep_alerts for g in a["raw"]["rule"].get("groups", [])]
        sclass = next((_GROUP_CLASS[g] for g in groups if g in _GROUP_CLASS), "other")
        conf = min(0.95, 0.5 + 0.04 * max(levels))
        records.append(
            DecisionRecord(
                decision_id=f"dec-d1-{idx:03d}",
                type="D1",
                subject_ref=SubjectRef(kind="session", id=eid),
                status="ASSESSED",
                confidence=conf,
                payload=D1Payload(verdict="malicious", scenario_class=sclass, techniques=techniques[:8]),
                evidence_event_ids=evidence[:16],
                **base,
            )
        )
    else:
        records.append(
            DecisionRecord(
                decision_id=f"dec-d1-{idx:03d}",
                type="D1",
                subject_ref=SubjectRef(kind="session", id=eid),
                status="ASSESSED",
                confidence=0.6,
                payload=D1Payload(verdict="benign"),
                context_refs=[f"episode:{eid}"],
                **base,
            )
        )

    # ---- D2 (only when there is an incident)
    if malicious:
        crit = max((assets.get(_asset_of(a), 1) for a in ep_alerts), default=1)
        levels = [int(a["raw"]["rule"]["level"]) for a in ep_alerts] or [3]
        records.append(
            DecisionRecord(
                decision_id=f"dec-d2-{idx:03d}",
                type="D2",
                subject_ref=SubjectRef(kind="incident", id=eid),
                status="ASSESSED",
                confidence=0.7,
                payload=D2Payload(priority=_priority(max(levels), crit)),
                evidence_event_ids=evidence[:16],
                **base,
            )
        )

    # ---- D4 (recommend fixing the controls behind failed SCA checks on alerting assets)
    if malicious:
        alert_assets = {_asset_of(a) for a in ep_alerts}
        recs: list[ControlRecommendation] = []
        seen: set[str] = set()
        for check in sca:
            if check.get("raw", {}).get("result") == "failed" and check.get("asset_ref") in alert_assets:
                for cid in check["raw"].get("org_controls", []):
                    if cid not in seen:
                        seen.add(cid)
                        recs.append(
                            ControlRecommendation(
                                control_id=cid,
                                action="implement",
                                rationale="SCA check failed on an alerting asset",
                            )
                        )
        if recs:
            records.append(
                DecisionRecord(
                    decision_id=f"dec-d4-{idx:03d}",
                    type="D4",
                    subject_ref=SubjectRef(kind="control", id=recs[0].control_id),
                    status="ASSESSED",
                    confidence=0.6,
                    payload=D4Payload(recommendations=recs[:3]),
                    evidence_event_ids=evidence[:8],
                    **base,
                )
            )
    return records


def _asset_of(alert: dict[str, Any]) -> str:
    return str(alert.get("asset_ref") or alert.get("raw", {}).get("agent", {}).get("name", ""))
