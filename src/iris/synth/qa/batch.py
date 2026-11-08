"""Batch generation and QA sample extraction (builder brief file 07 §7, file 08).

Builds N scenarios across a noise-level mix and extracts the per-episode, non-semantic feature
samples the shortcut test consumes. Labels come from the HIDDEN D1 key (malicious/benign), never
from any visible field; the group id is the enterprise family, so cross-validation is grouped.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from iris.core.seeds import SeedSet
from iris.synth.build import BuiltScenario, build_synth_scenario
from iris.synth.qa.shortcut import EpisodeSample, ShortcutResult, episode_features, shortcut_test

DEFAULT_MIX = {"low": 0.30, "medium": 0.40, "high": 0.30}
_TELEMETRY_KEYS = (
    "telemetry/wazuh/alerts.jsonl",
    "telemetry/wazuh/archives.jsonl",
    "telemetry/wazuh/fim.jsonl",
    "telemetry/suricata/eve.jsonl",
    "telemetry/applications/application_events.jsonl",
    "telemetry/applications/authentication_events.jsonl",
)


@dataclass
class BatchResult:
    builts: list[BuiltScenario]
    level_counts: dict[str, int]


def noise_for_index(i: int, mix: dict[str, float]) -> str:
    """Deterministic level assignment that realises the mix proportions over a batch."""
    position = (i % 10) / 10.0
    cum = 0.0
    for lvl in ("low", "medium", "high"):
        cum += mix.get(lvl, 0.0)
        if position < cum:
            return lvl
    return "high"


def build_batch(count: int, start: int = 0, mix: dict[str, float] | None = None) -> BatchResult:
    mix = mix or DEFAULT_MIX
    builts: list[BuiltScenario] = []
    counts: dict[str, int] = {"low": 0, "medium": 0, "high": 0}
    for i in range(count):
        level = noise_for_index(i, mix)
        b = build_synth_scenario(SeedSet.from_master(start + i), noise_level=level)
        counts[level] += 1
        builts.append(b)
    return BatchResult(builts, counts)


def _episode_label(built: BuiltScenario, episode_id: str) -> int:
    key = built.assembled.hidden.get(f"evaluation_key/d1/{episode_id}.json", {})
    return 1 if key.get("verdict") == "malicious" else 0


def shortcut_samples(builts: list[BuiltScenario]) -> list[EpisodeSample]:
    samples: list[EpisodeSample] = []
    for built in builts:
        group_id = built.assembled.seeds.group_id()
        by_ep: dict[str, list[dict[str, Any]]] = {}
        for key in _TELEMETRY_KEYS:
            for rec in built.assembled.visible.get(key, []):
                if isinstance(rec, dict) and "episode_id" in rec:
                    by_ep.setdefault(rec["episode_id"], []).append(rec)
        for eid, records in by_ep.items():
            samples.append(
                EpisodeSample(
                    features=episode_features(records),
                    malicious=_episode_label(built, eid),
                    group_id=group_id,
                )
            )
    return samples


def run_shortcut(
    count: int, start: int = 0, mix: dict[str, float] | None = None
) -> tuple[ShortcutResult, BatchResult]:
    batch = build_batch(count, start, mix)
    return shortcut_test(shortcut_samples(batch.builts)), batch
