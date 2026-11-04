"""Load episode feature vectors from built packages, for drift comparison.

Reads each ``scenario-*`` package under a dataset directory: for every episode it gathers
that episode's visible telemetry (``visible/telemetry/<episode_id>/...``) and, when present,
the composer's activity truth (``hidden/activity/<episode_id>.json``), and reduces them to an
:class:`iris.dataset.drift.EpisodeFeatures`. Live Gold packages without composer truth still
yield volume and sensor-mix features.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from iris.dataset.drift import EpisodeFeatures, episode_features


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _episode_ids(pkg: Path) -> list[str]:
    tdir = pkg / "visible" / "telemetry"
    if not tdir.exists():
        return []
    return sorted(p.name for p in tdir.iterdir() if p.is_dir())


def package_features(pkg: Path) -> list[EpisodeFeatures]:
    out: list[EpisodeFeatures] = []
    for eid in _episode_ids(pkg):
        base = pkg / "visible" / "telemetry" / eid
        visible = {
            f"telemetry/{eid}/{p.relative_to(base).as_posix()}": _load_jsonl(p)
            for p in sorted(base.rglob("*.jsonl"))
        }
        truth_path = pkg / "hidden" / "activity" / f"{eid}.json"
        truth = json.loads(truth_path.read_text(encoding="utf-8")) if truth_path.exists() else {}
        out.append(episode_features(visible, truth))
    return out


def dataset_features(root: Path) -> list[EpisodeFeatures]:
    out: list[EpisodeFeatures] = []
    for pkg in sorted(root.glob("scenario-*")):
        out.extend(package_features(pkg))
    return out
