"""Couple GRC records to telemetry and posture (builder brief file 06 §9).

The recorded incident register is built from the malicious activities the SOC actually
detected (an alert fired), with realistic lag and omissions — a detected attack that never
makes it into the register is a ledgered flaw ("incident missing from register"), and a
benign alarm that does is a "false incident". The remediation tracker is built from scanner
findings with SLAs by severity and maturity, including overdue items and paper closures
(closed yet still vulnerable). These are the organisation's RECORDED view and may be wrong.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from iris.core.hashing import sha256_hex
from iris.core.vclock import iso_z
from iris.synth.activity.planner import ScenarioPlan
from iris.synth.posture import SynthPosture
from iris.synth.seeds import SynthSeeds
from iris.synth.telemetry import TelemetryBundle
from iris.synth.world import World

GRC_LINK_VERSION = "synth-grc-link-0.1.0"

# detection -> recorded-incident probability and recording lag (days) by maturity.
_INCIDENT_P = {"high": 0.85, "medium": 0.6, "low": 0.35}
_SLA_DAYS = {"CRITICAL": 7, "HIGH": 15, "MEDIUM": 30, "LOW": 90, "UNKNOWN": 90}


@dataclass
class GrcLink:
    incidents: list[dict[str, Any]] = field(default_factory=list)
    remediation: list[dict[str, Any]] = field(default_factory=list)
    flaws: list[dict[str, Any]] = field(default_factory=list)  # hidden coupling flaws

    def visible(self) -> dict[str, Any]:
        return {
            "grc/incident_register.jsonl": self.incidents,
            "grc/remediation_tracker.jsonl": self.remediation,
        }

    def hidden(self) -> dict[str, Any]:
        return {"truth/grc_coupling_flaws.jsonl": self.flaws}


def _detected_activity_ids(bundle: TelemetryBundle) -> set[str]:
    alert_events = {
        rec["event_id"]
        for rec in bundle.visible.get("telemetry/wazuh/alerts.jsonl", [])
        if isinstance(rec, dict)
    } | {
        rec["event_id"]
        for rec in bundle.visible.get("telemetry/suricata/eve.jsonl", [])
        if isinstance(rec, dict) and rec.get("raw", {}).get("event_type") == "alert"
    }
    return {link["activity_id"] for link in bundle.evidence if link["event_id"] in alert_events}


def build_grc_link(
    world: World, plan: ScenarioPlan, bundle: TelemetryBundle, posture: SynthPosture, synth: SynthSeeds
) -> GrcLink:
    scn = plan.scenario_id
    rng = synth.rng("activity", "grc_link", scn)
    maturity = world.spec.organization.maturity.value
    link = GrcLink()
    detected = _detected_activity_ids(bundle)

    # ---- incident register from detected malicious activities
    inc_n = 0
    for act in plan.activities:
        if act.kind != "malicious":
            continue
        was_detected = act.activity_id in detected
        if was_detected and rng.random() < _INCIDENT_P[maturity]:
            inc_n += 1
            lag = timedelta(days=rng.randint(0, 5))
            opened = act.start + lag
            closed = opened + timedelta(days=rng.randint(1, 10)) if rng.random() < 0.6 else None
            link.incidents.append(
                {
                    "incident_id": f"INC-{inc_n:04d}",
                    "opened_at": iso_z(opened),
                    "closed_at": iso_z(closed) if closed else None,
                    "status": "closed" if closed else rng.choice(["open", "investigating", "contained"]),
                    "affected_assets": [act.target_asset] if act.target_asset else [],
                    "summary": f"Suspicious {act.family or 'activity'} detected on {act.target_asset}",
                    "root_cause": None,
                    "linked_risk_ids": [],
                    "linked_control_ids": [act.enabling_control] if act.enabling_control else [],
                    "recorded_at": iso_z(opened),
                }
            )
        elif was_detected:
            # detected but never recorded: a flaw the Engine should catch (DC2)
            link.flaws.append(
                {"flaw": "incident_missing_from_register", "activity_id": act.activity_id, "dc": "DC2"}
            )

    # ---- remediation tracker from scanner findings
    for rem_n, f in enumerate(posture.scanner_findings, start=1):
        sla = _SLA_DAYS.get(f["severity"], 90)
        found = datetime.fromisoformat(f["timestamp"].replace("Z", "+00:00"))
        due = found + timedelta(days=sla)
        # some paper closures: status done while the finding is still present
        paper = rng.random() < {"high": 0.05, "medium": 0.12, "low": 0.25}[maturity]
        overdue = rng.random() < 0.3
        status = "done" if (paper or rng.random() < 0.4) else rng.choice(["open", "in_progress"])
        link.remediation.append(
            {
                "item_id": f"REM-{rem_n:04d}",
                "finding_ref": f["finding_id"],
                "owner": None,
                "severity": f["severity"].lower() if f["severity"] != "UNKNOWN" else "low",
                "sla_days": sla,
                "due_at": iso_z(due - timedelta(days=sla + 1) if overdue else due),
                "status": "done" if paper else status,
                "last_update_at": iso_z(found + timedelta(days=rng.randint(0, sla))),
                "recorded_at": iso_z(found),
            }
        )
        if paper:
            link.flaws.append(
                {
                    "flaw": "remediation_closed_not_fixed",
                    "finding_id": f["finding_id"],
                    "dc": "DC2",
                    "ledger_id": "GL-" + sha256_hex(f["finding_id"])[:8],
                }
            )

    return link
