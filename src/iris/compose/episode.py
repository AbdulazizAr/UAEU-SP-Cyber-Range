"""Stitch chosen fragments into one composed episode.

Fragments are placed sequentially inside the episode's virtual window with seeded gaps,
so intervals within each fragment are preserved and fragments never interleave (safe for
frequency and correlation rules). A fragment that would run past the window end is
dropped rather than truncated. The result has the same visible shape as a live episode
export (``telemetry/wazuh/alerts.jsonl`` etc.), plus a hidden ``activity_truth`` that
records exactly which fragments were placed, where, and what a correct SOC should raise.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from iris.compose import COMPOSE_VERSION
from iris.compose.realize import realize_fragment
from iris.core.vclock import ensure_utc, iso_z
from iris.fragments.model import Fragment
from iris.generator.eve import dedup

EVE_FILE = "telemetry/suricata/eve.jsonl"


@dataclass
class Placement:
    fragment_id: str
    label: str
    family: str
    at: datetime
    duration_ms: int
    truth: dict[str, Any]


@dataclass
class ComposedEpisode:
    episode_id: str
    visible: dict[str, list[dict[str, Any]]]
    activity_truth: dict[str, Any]
    counts: dict[str, int]
    placements: list[Placement] = field(default_factory=list)


def _place(
    fragments: list[tuple[Fragment, dict[str, str]]],
    start: datetime,
    end: datetime,
    rng: Any,
    min_gap_s: float,
    max_gap_s: float,
) -> list[tuple[Fragment, dict[str, str], datetime]]:
    """Lay fragments out end-to-end from ``start`` with jittered gaps; drop any that would
    finish after ``end``."""
    placed: list[tuple[Fragment, dict[str, str], datetime]] = []
    cursor = start + timedelta(seconds=rng.uniform(0, max_gap_s))
    for frag, bindings in fragments:
        finish = cursor + timedelta(milliseconds=frag.duration_ms)
        if finish > end:
            continue
        placed.append((frag, bindings, cursor))
        cursor = finish + timedelta(seconds=rng.uniform(min_gap_s, max_gap_s))
    return placed


def compose_episode(
    episode_id: str,
    virtual_start: datetime,
    virtual_end: datetime,
    fragments: list[tuple[Fragment, dict[str, str]]],
    rng: Any,
    *,
    archives_retained: bool = True,
    min_gap_s: float = 2.0,
    max_gap_s: float = 20.0,
) -> ComposedEpisode:
    start, end = ensure_utc(virtual_start), ensure_utc(virtual_end)
    placed = _place(fragments, start, end, rng, min_gap_s, max_gap_s)

    visible: dict[str, list[dict[str, Any]]] = {}
    placements: list[Placement] = []
    for frag, bindings, at in placed:
        for vfile, _vtime, body in realize_fragment(frag, bindings, at):
            if vfile == "telemetry/wazuh/archives.jsonl" and not archives_retained:
                continue
            visible.setdefault(vfile, []).append(body)
        placements.append(
            Placement(
                fragment_id=frag.fragment_id,
                label=frag.truth.label,
                family=frag.truth.family,
                at=at,
                duration_ms=frag.duration_ms,
                truth={
                    **frag.truth.to_dict(),
                    "fragment_id": frag.fragment_id,
                    "placed_at": iso_z(at),
                },
            )
        )

    if EVE_FILE in visible:
        visible[EVE_FILE] = dedup(visible[EVE_FILE])
    for vfile in visible:
        visible[vfile].sort(key=lambda r: _sort_key(vfile, r))

    expected_rules = sorted(
        {rid for p in placements if p.label == "malicious" for rid in p.truth.get("expected_rules", [])}
    )
    activity_truth = {
        "version": COMPOSE_VERSION,
        "episode_id": episode_id,
        "virtual_start": iso_z(start),
        "virtual_end": iso_z(end),
        "placements": [p.truth for p in placements],
        "expected_rules": expected_rules,
        "malicious_fragments": sum(1 for p in placements if p.label == "malicious"),
        "benign_fragments": sum(1 for p in placements if p.label == "benign"),
    }
    counts = {
        "fragments_placed": len(placements),
        "records": sum(len(v) for v in visible.values()),
        **{
            k.replace("telemetry/", "").replace("/", "_").replace(".jsonl", ""): len(v)
            for k, v in visible.items()
        },
    }
    return ComposedEpisode(episode_id, visible, activity_truth, counts, placements)


def _sort_key(vfile: str, record: dict[str, Any]) -> str:
    ts = record.get("timestamp")
    return ts if isinstance(ts, str) else ""
