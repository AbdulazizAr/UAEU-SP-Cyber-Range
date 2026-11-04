"""Assemble a composed training package: a generated enterprise's context plus telemetry
stitched by the composer, the v1 reference keys, and per-episode activity truth.

Layout added on top of the v0 context package::

    visible/telemetry/<episode_id>/wazuh/alerts.jsonl      (+ archives, suricata/eve)
    hidden/activity/<episode_id>.json                      composer placement truth
    hidden/evaluation_key/{d1,d2,d4}/<episode_id>.json     v1 decision keys
    hidden/truth/outcomes/<episode_id>.json                outcome truth
    hidden/truth/composition.json                          fragment provenance

Composed packages are the ``train`` tier; validation and test sets are live Gold
(decisions.md). ``enabled_sensors`` is populated from the telemetry actually present, so
the visible manifest tells the Engine which sensors to expect.
"""

from __future__ import annotations

from typing import Any

from iris.compose import COMPOSE_VERSION
from iris.compose.scenario import ComposedScenario, compose_scenario, scenario_truth
from iris.compose.select import ReuseLedger
from iris.contracts.spec import ScenarioSpec
from iris.fragments.model import Fragment
from iris.generator.grc.reality import GrcReality
from iris.generator.secrets import scenario_secrets
from iris.generator.soc import build_soc
from iris.oracle.keys import ORACLE_VERSION, activities_from_composed, decision_keys
from iris.packager.build import Assembled, PackageOptions


def _sensor_set(visible: dict[str, Any]) -> tuple[str, ...]:
    sensors = []
    if any("/wazuh/" in k for k in visible):
        sensors.append("wazuh")
    if any("/suricata/" in k for k in visible):
        sensors.append("suricata")
    return tuple(sensors)


def _control_states(reality: GrcReality) -> dict[str, str]:
    return {cid: c.state for cid, c in reality.controls.items()}


def attach_composition(
    assembled: Assembled,
    composed: ComposedScenario,
    reality: GrcReality,
) -> PackageOptions:
    """Fold a composed scenario's telemetry, keys and truth into an existing context
    :class:`Assembled` (mutated in place) and return the matching package options."""
    spec = assembled.spec
    enabled: set[str] = set()
    for ep in composed.episodes:
        for rel, rows in ep.visible.items():
            dest = f"telemetry/{ep.episode_id}/{rel.removeprefix('telemetry/')}"
            assembled.visible[dest] = rows
            enabled.update(_sensor_set({dest: rows}))
        assembled.hidden[f"activity/{ep.episode_id}.json"] = ep.activity_truth

    activities = activities_from_composed(spec, composed)
    for rel, key in decision_keys(activities, _control_states(reality)).items():
        assembled.hidden[rel] = key
    assembled.hidden["truth/composition.json"] = scenario_truth(composed)

    return PackageOptions(
        data_tier="train",
        telemetry=bool(enabled),
        episode_bundles=bool(composed.episodes),
        enabled_sensors=tuple(sorted(enabled)),
        extra_versions={"compose": COMPOSE_VERSION, "oracle": ORACLE_VERSION},
    )


def compose_onto(
    assembled: Assembled,
    reality: GrcReality,
    library: list[Fragment],
    allowed_groups: set[str],
    *,
    ledger: ReuseLedger | None = None,
    blocked_families: set[str] | None = None,
) -> tuple[ComposedScenario, PackageOptions]:
    """Compose a scenario onto a context ``Assembled`` and attach it. ``archives_retained``
    follows the enterprise's own SOC profile so composed telemetry matches what that SOC
    would really keep. ``blocked_families`` are attack families held out of in-distribution
    training and must not be composed into this scenario."""
    spec: ScenarioSpec = assembled.spec
    secrets = scenario_secrets(spec)
    soc = build_soc(spec, reality, assembled.seeds)
    composed = compose_scenario(
        spec,
        library,
        allowed_groups,
        assembled.seeds,
        secrets=secrets,
        ledger=ledger,
        scenario_id=assembled.scenario_id,
        archives_retained=soc.archives_retained,
        blocked_families=blocked_families,
    )
    options = attach_composition(assembled, composed, reality)
    return composed, options
