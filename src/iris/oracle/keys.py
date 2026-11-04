"""Assemble every v1 reference key and the outcome truth for a scenario's episodes.

The output is keyed by the package's hidden layout, ready to drop into
``hidden/evaluation_key/<type>/<episode_id>.json`` and ``hidden/truth/outcomes/``.
D6 (GRC flaw) keys are assembled separately in the packager from the GRC timeline.
"""

from __future__ import annotations

from typing import Any

from iris.compose.scenario import ComposedScenario
from iris.contracts.spec import ScenarioSpec
from iris.oracle.decisions import build_d1_key, build_d2_key, build_d4_key
from iris.oracle.outcome import EpisodeActivity, from_composed, outcome_key

ORACLE_VERSION = "oracle-0.1.0"


def activities_from_composed(spec: ScenarioSpec, composed: ComposedScenario) -> list[EpisodeActivity]:
    return [from_composed(spec, ep.activity_truth) for ep in composed.episodes]


def decision_keys(
    activities: list[EpisodeActivity], control_states: dict[str, str]
) -> dict[str, dict[str, Any]]:
    """Return ``{hidden_relpath: key}`` for D1, D2, D4 and the outcome truth per episode."""
    out: dict[str, dict[str, Any]] = {}
    for act in activities:
        eid = act.episode_id
        out[f"evaluation_key/d1/{eid}.json"] = build_d1_key(act)
        out[f"evaluation_key/d2/{eid}.json"] = build_d2_key(act)
        out[f"evaluation_key/d4/{eid}.json"] = build_d4_key(act, control_states)
        out[f"truth/outcomes/{eid}.json"] = outcome_key(act)
    return out
