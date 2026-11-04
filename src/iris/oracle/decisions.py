"""Reference keys for the v1 decision types the Engine is scored on: D1 (classification),
D2 (priority) and D4 (control recommendation). D6 (GRC flaw) lives in :mod:`iris.oracle.d6`.

Keys are the hidden ground truth at each episode checkpoint (the episode's virtual start).
Each is derived only from what actually happened on the target enterprise — the resolved
:class:`iris.oracle.outcome.EpisodeActivity` — and, for D4, the recorded-vs-real control
state, so a key never assumes a detection or a control it cannot ground.

Oracle confidence tiers (decisions.md "Naming") stay T1-T3: T1 is direct ground truth
(a planted weakness exploited and verified), T2 an inferred-but-certain consequence, T3 a
weaker signal. Planted, verified activity is T1.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from iris.core.vclock import iso_z
from iris.oracle.outcome import EpisodeActivity, family_tactic

D1_KEY_VERSION = "d1-key-0.1.0"
D2_KEY_VERSION = "d2-key-0.1.0"
D4_KEY_VERSION = "d4-key-0.1.0"

#: attack family -> classification label used as the D1 scenario class.
SCENARIO_CLASS = {
    "F1": "web_application_compromise",
    "F2": "credential_access",
    "F4": "lateral_movement",
    "F5": "collection_exfiltration",
}
_PRIORITY_BY_CRIT = {1: "LOW", 2: "LOW", 3: "MEDIUM", 4: "HIGH", 5: "HIGH"}
_BUMP = {"LOW": "MEDIUM", "MEDIUM": "HIGH", "HIGH": "CRITICAL", "CRITICAL": "CRITICAL"}
#: control state -> the D4 action a correct recommendation takes.
_ACTION_BY_STATE = {
    "missing": "implement",
    "partial": "strengthen",
    "paper": "strengthen",
    "implemented": "verify",
}


def _dominant_family(activity: EpisodeActivity) -> str | None:
    """The most frequent malicious family; ties break to the lowest family id."""
    fams = Counter(i.family for i in activity.malicious if i.family)
    if not fams:
        return None
    return min(fams, key=lambda f: (-fams[f], f))


def build_d1_key(activity: EpisodeActivity) -> dict[str, Any]:
    mal = activity.malicious
    fam = _dominant_family(activity)
    techniques = sorted({i.technique for i in mal if i.technique})
    tactics = sorted({t for i in mal if (t := family_tactic(i.family))})
    detectable = any(i.expected_rules for i in mal)
    return {
        "version": D1_KEY_VERSION,
        "episode_id": activity.episode_id,
        "as_of": iso_z(activity.as_of),
        "verdict": "malicious" if mal else "benign",
        "family": fam,
        "scenario_class": SCENARIO_CLASS.get(fam or "", "benign_operations" if not mal else "other"),
        "techniques": techniques,
        "tactics": tactics,
        "detectability": ("DC1" if detectable else "DC3") if mal else "n/a",
        "confidence_tier": "T1",
    }


def build_d2_key(activity: EpisodeActivity) -> dict[str, Any]:
    mal = activity.malicious
    if not mal:
        return {
            "version": D2_KEY_VERSION,
            "episode_id": activity.episode_id,
            "as_of": iso_z(activity.as_of),
            "incident": False,
            "priority": None,
            "confidence_tier": "T1",
        }
    max_crit = max((i.criticality for i in mal), default=1)
    priority = _PRIORITY_BY_CRIT.get(max_crit, "MEDIUM")
    if activity.compromised:
        priority = _BUMP[priority]
    return {
        "version": D2_KEY_VERSION,
        "episode_id": activity.episode_id,
        "as_of": iso_z(activity.as_of),
        "incident": True,
        "priority": priority,
        "max_criticality": max_crit,
        "compromised": activity.compromised,
        "confidence_tier": "T1",
    }


def build_d4_key(activity: EpisodeActivity, control_states: dict[str, str]) -> dict[str, Any]:
    """One recommendation per enabling control exploited this episode.

    ``control_states`` is the control's TRUE state from GRC reality (callers pass
    ``GrcReality.controls[...].state``), not what the register records: the correct fix
    depends on what is really missing, while the recorded state is exactly what the
    Engine has to see through. The action follows that true state; an exploited-yet-
    implemented control is recommended for verification (the exploit proves it is not
    truly effective)."""
    recs: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in activity.malicious:
        cid = item.enabling_control
        if cid is None or cid in seen:
            continue
        seen.add(cid)
        state = control_states.get(cid, "missing")
        recs.append(
            {
                "control_id": cid,
                "action": _ACTION_BY_STATE.get(state, "implement"),
                "control_state": state,
                "state_source": "reality",
                "because": {
                    "weakness_module": item.weakness_module,
                    "asset_id": item.asset_id,
                    "technique": item.technique,
                    "outcome": item.outcome,
                },
            }
        )
    return {
        "version": D4_KEY_VERSION,
        "episode_id": activity.episode_id,
        "as_of": iso_z(activity.as_of),
        "actionable": bool(recs),
        "recommendations": recs,
        "confidence_tier": "T1",
    }
