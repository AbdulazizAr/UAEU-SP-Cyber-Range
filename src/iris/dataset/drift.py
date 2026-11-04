"""Drift tests (INPUT Part 8): composed training data is training-only until it is shown
to be statistically close to the live Gold it imitates.

Per episode a small feature vector is extracted: numeric features (record volume, the
malicious fraction, mean inter-event gap, sensor mix, technique count) and categorical
features (dominant family, detectability). Two populations — live Gold (reference) and
composed (candidate) — are compared feature by feature:

* numeric features by standardised mean difference (SMD), |mean_r - mean_c| / pooled_std;
* categorical features by total-variation distance (TVD) between their distributions.

The composed set passes when every feature is within its threshold. Thresholds are
deliberately conservative; a fail blocks the composed data from training, never the other
way round.
"""

from __future__ import annotations

import itertools
import math
import statistics
from dataclasses import dataclass, field
from typing import Any

from iris.core.vclock import parse_iso
from iris.dataset import DATASET_VERSION

SMD_THRESHOLD = 0.3
TVD_THRESHOLD = 0.2


@dataclass
class EpisodeFeatures:
    numeric: dict[str, float] = field(default_factory=dict)
    categorical: dict[str, str] = field(default_factory=dict)


def _wazuh_count(visible: dict[str, list[dict[str, Any]]]) -> int:
    return sum(len(v) for k, v in visible.items() if "/wazuh/" in k)


def _eve_count(visible: dict[str, list[dict[str, Any]]]) -> int:
    return sum(len(v) for k, v in visible.items() if "/suricata/" in k)


def _event_times(visible: dict[str, list[dict[str, Any]]]) -> list[float]:
    times: list[float] = []
    for rows in visible.values():
        for r in rows:
            ts = r.get("timestamp")
            if isinstance(ts, str):
                try:
                    times.append(parse_iso(ts.replace("+0000", "Z")).timestamp())
                except ValueError:
                    continue
    return sorted(times)


def episode_features(
    visible: dict[str, list[dict[str, Any]]], activity_truth: dict[str, Any]
) -> EpisodeFeatures:
    """Extract one feature vector from an episode's visible telemetry and activity truth.
    Works for both composed and live episodes (identical visible shape)."""
    total = sum(len(v) for v in visible.values())
    placements = activity_truth.get("placements", [])
    mal = [p for p in placements if p.get("label") == "malicious"]
    times = _event_times(visible)
    gaps = [b - a for a, b in itertools.pairwise(times)]
    mean_gap = statistics.fmean(gaps) if gaps else 0.0
    families = [p.get("family") for p in mal if p.get("family")]
    dominant = max(set(families), key=families.count) if families else "none"
    return EpisodeFeatures(
        numeric={
            "records": float(total),
            "wazuh_records": float(_wazuh_count(visible)),
            "eve_fraction": (_eve_count(visible) / total) if total else 0.0,
            "malicious_fraction": (len(mal) / len(placements)) if placements else 0.0,
            "mean_inter_event_gap_s": mean_gap,
            "distinct_techniques": float(len({p.get("technique") for p in mal if p.get("technique")})),
        },
        categorical={
            "dominant_family": dominant,
            "detectability": "DC1" if any(p.get("expected_rules") for p in mal) else "none",
        },
    )


def smd(reference: list[float], candidate: list[float]) -> float:
    if not reference or not candidate:
        return 0.0
    mr, mc = statistics.fmean(reference), statistics.fmean(candidate)
    vr = statistics.variance(reference) if len(reference) > 1 else 0.0
    vc = statistics.variance(candidate) if len(candidate) > 1 else 0.0
    pooled = math.sqrt((vr + vc) / 2)
    if pooled == 0:
        return 0.0 if mr == mc else float("inf")
    return abs(mr - mc) / pooled


def tvd(reference: list[str], candidate: list[str]) -> float:
    cats = set(reference) | set(candidate)
    if not reference or not candidate or not cats:
        return 0.0
    total = 0.0
    for c in cats:
        pr = reference.count(c) / len(reference)
        pc = candidate.count(c) / len(candidate)
        total += abs(pr - pc)
    return 0.5 * total


@dataclass
class FeatureDrift:
    feature: str
    kind: str  # numeric | categorical
    distance: float
    threshold: float

    @property
    def ok(self) -> bool:
        return self.distance <= self.threshold


@dataclass
class DriftReport:
    version: str
    reference_n: int
    candidate_n: int
    features: list[FeatureDrift]

    @property
    def ok(self) -> bool:
        return all(f.ok for f in self.features)

    def failures(self) -> list[FeatureDrift]:
        return [f for f in self.features if not f.ok]

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "reference_n": self.reference_n,
            "candidate_n": self.candidate_n,
            "passed": self.ok,
            "features": [
                {
                    "feature": f.feature,
                    "kind": f.kind,
                    "distance": round(f.distance, 4),
                    "threshold": f.threshold,
                    "ok": f.ok,
                }
                for f in self.features
            ],
            "failures": [f.feature for f in self.failures()],
        }


def drift_report(
    reference: list[EpisodeFeatures],
    candidate: list[EpisodeFeatures],
    *,
    smd_threshold: float = SMD_THRESHOLD,
    tvd_threshold: float = TVD_THRESHOLD,
) -> DriftReport:
    numeric_keys = sorted({k for f in reference + candidate for k in f.numeric})
    categorical_keys = sorted({k for f in reference + candidate for k in f.categorical})
    out: list[FeatureDrift] = []
    for key in numeric_keys:
        d = smd([f.numeric.get(key, 0.0) for f in reference], [f.numeric.get(key, 0.0) for f in candidate])
        out.append(FeatureDrift(key, "numeric", d, smd_threshold))
    for key in categorical_keys:
        d = tvd(
            [f.categorical.get(key, "none") for f in reference],
            [f.categorical.get(key, "none") for f in candidate],
        )
        out.append(FeatureDrift(key, "categorical", d, tvd_threshold))
    return DriftReport(DATASET_VERSION, len(reference), len(candidate), out)
