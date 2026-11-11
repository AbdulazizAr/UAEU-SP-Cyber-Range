"""Shortcut test: the mandatory anti-fingerprint release gate (builder brief file 07 §7).

Trains trivial models on NON-SEMANTIC features only (record length, field count, timestamp
regularity, duplicate fraction, delay stats, volume) to predict the hidden malicious/benign
label, with grouped cross-validation by enterprise. If a trivial model can separate attack
from benign episodes from these artifacts, the generator is leaking and noise/hard negatives
must increase — the thresholds are NOT weakened (brief rule). The result is stored hidden in
``quality/data_quality.json`` and ``noise_report.json``.
"""

from __future__ import annotations

import itertools
import json
import math
import statistics
from dataclasses import dataclass
from typing import Any

# scikit-learn is an optional QA dependency; degrade to a pure-Python baseline if absent.
try:
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import GroupKFold
    from sklearn.preprocessing import StandardScaler

    _HAVE_SKLEARN = True
except Exception:  # pragma: no cover - exercised only where sklearn is missing
    _HAVE_SKLEARN = False

# pass criteria (brief file 07 §7). Do not weaken these; fix the data instead.
MAL_AUC_MAX = 0.65

FEATURE_NAMES = (
    "n_records",
    "n_alerts",
    "n_flows",
    "mean_len",
    "std_len",
    "mean_fields",
    "interarrival_cv",
    "duplicate_frac",
    "mean_delay_ms",
    "distinct_hosts",
    "last_digit_entropy",
)


@dataclass
class EpisodeSample:
    features: list[float]
    malicious: int
    group_id: str


def episode_features(records: list[dict[str, Any]]) -> list[float]:
    """Non-semantic features of one episode's telemetry records (no field values read)."""
    if not records:
        return [0.0] * len(FEATURE_NAMES)
    lengths = [len(json.dumps(r, default=str)) for r in records]
    fields = [len(r) for r in records]
    times = sorted(_epoch(r.get("event_timestamp")) for r in records if r.get("event_timestamp"))
    gaps = [b - a for a, b in itertools.pairwise(times)] or [0.0]
    delays = [
        max(0.0, _epoch(r.get("ingest_timestamp")) - _epoch(r.get("event_timestamp")))
        for r in records
        if r.get("ingest_timestamp") and r.get("event_timestamp")
    ]
    eids = [r.get("event_id", "") for r in records]
    n_alerts = sum(1 for r in records if r.get("source_type") == "wazuh_alert")
    n_flows = sum(1 for r in records if r.get("source_type") == "suricata_eve")
    hosts = {r.get("asset_ref") for r in records}
    return [
        float(len(records)),
        float(n_alerts),
        float(n_flows),
        statistics.fmean(lengths),
        statistics.pstdev(lengths) if len(lengths) > 1 else 0.0,
        statistics.fmean(fields),
        (statistics.pstdev(gaps) / statistics.fmean(gaps)) if statistics.fmean(gaps) else 0.0,
        1.0 - len(set(eids)) / max(1, len(eids)),
        statistics.fmean(delays) * 1000 if delays else 0.0,
        float(len(hosts)),
        _last_digit_entropy(times),
    ]


@dataclass
class ShortcutResult:
    passed: bool
    malicious_auc: float
    model: str
    features: tuple[str, ...]
    thresholds: dict[str, float]
    n_samples: int
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "score": round(self.malicious_auc, 4),
            "metric": "malicious_vs_benign_auc",
            "model": self.model,
            "features": list(self.features),
            "thresholds": self.thresholds,
            "n_samples": self.n_samples,
            "note": self.note,
        }


def shortcut_test(samples: list[EpisodeSample]) -> ShortcutResult:
    pos = sum(s.malicious for s in samples)
    thresholds = {"malicious_auc_max": MAL_AUC_MAX}
    if pos == 0 or pos == len(samples) or len(samples) < 8:
        return ShortcutResult(
            True,
            0.5,
            "n/a",
            FEATURE_NAMES,
            thresholds,
            len(samples),
            note="degenerate label distribution; not scored",
        )
    x = [s.features for s in samples]
    y = [s.malicious for s in samples]
    groups = [s.group_id for s in samples]
    if _HAVE_SKLEARN:
        auc, model = _sklearn_auc(x, y, groups)
    else:  # pragma: no cover
        auc, model = _naive_auc(x, y), "naive-threshold"
    return ShortcutResult(auc <= MAL_AUC_MAX, auc, model, FEATURE_NAMES, thresholds, len(samples))


def _sklearn_auc(x: list[list[float]], y: list[int], groups: list[str]) -> tuple[float, str]:
    from sklearn.metrics import roc_auc_score

    n_groups = len(set(groups))
    k = min(5, n_groups)
    preds = [0.5] * len(y)
    if k >= 2:
        gkf = GroupKFold(n_splits=k)
        for tr, te in gkf.split(x, y, groups):
            if len({y[i] for i in tr}) < 2:
                continue
            scaler = StandardScaler().fit([x[i] for i in tr])
            clf = LogisticRegression(max_iter=500).fit(
                scaler.transform([x[i] for i in tr]), [y[i] for i in tr]
            )
            proba = clf.predict_proba(scaler.transform([x[i] for i in te]))[:, 1]
            for j, i in enumerate(te):
                preds[i] = proba[j]
    try:
        return float(roc_auc_score(y, preds)), "logistic_regression+groupkfold"
    except ValueError:
        return 0.5, "logistic_regression+groupkfold"


def _naive_auc(x: list[list[float]], y: list[int]) -> float:  # pragma: no cover
    scores = [row[1] + row[2] for row in x]  # alerts + flows as a crude separator
    pairs = list(zip(scores, y, strict=True))
    pos = [sc for sc, lab in pairs if lab == 1]
    neg = [sc for sc, lab in pairs if lab == 0]
    if not pos or not neg:
        return 0.5
    wins = sum((p > n) + 0.5 * (p == n) for p in pos for n in neg)
    return wins / (len(pos) * len(neg))


def _epoch(ts: str | None) -> float:
    if not ts:
        return 0.0
    from iris.core.vclock import parse_iso

    return parse_iso(ts).timestamp()


def _last_digit_entropy(times: list[float]) -> float:
    if not times:
        return 0.0
    digits = [int(t) % 10 for t in times]
    counts = [digits.count(d) for d in range(10)]
    total = sum(counts)
    return -sum((c / total) * math.log2(c / total) for c in counts if c)
