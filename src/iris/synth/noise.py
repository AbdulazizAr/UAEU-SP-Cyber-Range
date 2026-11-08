"""Noise layer: a pure post-processing stage over clean telemetry (builder brief file 07).

Synthetic data is clean by default, so a model trained on it learns the generator, not the
attacks. This stage injects a controlled, recorded, seeded amount of imperfection AFTER clean
generation, so the same scenario regenerates at another noise level with identical world,
activities and clean logs — only the noise differs (T-N1). Everything it does is logged to the
hidden ``noise_truth`` so the evaluator can attribute a missed detection to SOC rules, sensor
loss or injected noise.

Order (brief §2): clock skew -> drops/duplicates -> delay/reorder -> malformed -> unresolved.
Drops are independent of the activity label except sensor-outage bursts (which hit benign and
malicious alike), so losing the one record that proves an attack is never a tell.
"""

from __future__ import annotations

import math
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from iris.core.hashing import sha256_hex
from iris.core.vclock import iso_z, parse_iso
from iris.synth.seeds import SynthSeeds
from iris.synth.telemetry import TelemetryBundle

NOISE_VERSION = "noise-1.0"

# per-level parameter ranges; a per-scenario vector is sampled within the level (so two
# "medium" scenarios differ), and the profile_id encodes that vector.
LEVELS: dict[str, dict[str, tuple[float, float]]] = {
    "low": {
        "drop": (0.005, 0.02),
        "dup": (0.002, 0.01),
        "delay_s": (1, 4),
        "skew_frac": (0.0, 0.1),
        "malformed": (0.001, 0.004),
        "unresolved": (0.005, 0.02),
    },
    "medium": {
        "drop": (0.02, 0.06),
        "dup": (0.01, 0.03),
        "delay_s": (4, 15),
        "skew_frac": (0.1, 0.3),
        "malformed": (0.004, 0.015),
        "unresolved": (0.02, 0.05),
    },
    "high": {
        "drop": (0.06, 0.14),
        "dup": (0.03, 0.07),
        "delay_s": (15, 45),
        "skew_frac": (0.25, 0.5),
        "malformed": (0.015, 0.04),
        "unresolved": (0.04, 0.09),
    },
}

TELEMETRY_FILES = (
    "telemetry/wazuh/alerts.jsonl",
    "telemetry/wazuh/archives.jsonl",
    "telemetry/wazuh/fim.jsonl",
    "telemetry/suricata/eve.jsonl",
    "telemetry/applications/application_events.jsonl",
    "telemetry/applications/authentication_events.jsonl",
)


@dataclass
class NoiseProfile:
    profile_id: str
    level: str
    seed: int
    version: str = NOISE_VERSION
    params: dict[str, float] = field(default_factory=dict)


@dataclass
class NoiseTruth:
    profile: NoiseProfile
    dropped: list[dict[str, Any]] = field(default_factory=list)  # {event_id, activity_id?, cause}
    duplicated: list[str] = field(default_factory=list)
    delayed: list[dict[str, Any]] = field(default_factory=list)  # {event_id, delay_ms}
    skewed_assets: list[dict[str, Any]] = field(default_factory=list)  # {asset_id, offset_s}
    malformed: list[str] = field(default_factory=list)
    unresolved: list[dict[str, Any]] = field(default_factory=list)  # {event_id, fields}

    def to_dict(self) -> dict[str, Any]:
        return {
            "noise_profile_id": self.profile.profile_id,
            "version": self.profile.version,
            "level": self.profile.level,
            "sampled_parameters": self.profile.params,
            "dropped_event_ids": self.dropped,
            "duplicated_event_ids": self.duplicated,
            "delayed_event_ids": self.delayed,
            "skewed_assets": self.skewed_assets,
            "malformed_event_ids": self.malformed,
            "unresolved_field_events": self.unresolved,
        }


def _sample_params(level: str, rng: Any) -> dict[str, float]:
    return {k: round(rng.uniform(lo, hi), 5) for k, (lo, hi) in LEVELS[level].items()}


def choose_profile(synth: SynthSeeds, scenario_id: str, level: str) -> NoiseProfile:
    rng = synth.rng("noise", "profile", scenario_id, level)
    params = _sample_params(level, rng)
    vec = sha256_hex(f"{level}|{synth.noise}|{params}")[:6].upper()
    return NoiseProfile(
        profile_id=f"NOISE-{level[:3].upper()}-{vec}", level=level, seed=synth.noise, params=params
    )


def apply_noise(
    bundle: TelemetryBundle, synth: SynthSeeds, scenario_id: str, level: str
) -> tuple[TelemetryBundle, NoiseTruth]:
    profile = choose_profile(synth, scenario_id, level)
    p = profile.params
    out = TelemetryBundle(
        visible=deepcopy(bundle.visible),
        hidden=deepcopy(bundle.hidden),
        enabled_sensors=bundle.enabled_sensors,
        evidence=list(bundle.evidence),
    )
    truth = NoiseTruth(profile=profile)
    act_of: dict[str, str] = {link["event_id"]: link["activity_id"] for link in bundle.evidence}

    # ---- clock skew: a per-asset constant offset applied to event_timestamp
    skew: dict[str, float] = {}
    skew_rng = synth.rng("noise", "skew", scenario_id)
    assets: list[str] = sorted(
        {
            str(rec["asset_ref"])
            for f in TELEMETRY_FILES
            for rec in out.visible.get(f, [])
            if isinstance(rec, dict) and rec.get("asset_ref")
        }
    )
    for aid in assets:
        if skew_rng.random() < p["skew_frac"]:
            off = round(skew_rng.uniform(-120, 120), 1)
            skew[aid] = off
            truth.skewed_assets.append({"asset_id": aid, "offset_s": off, "drift_ppm": 0})

    # ---- per-file transforms
    for fname in TELEMETRY_FILES:
        rows = out.visible.get(fname)
        if not isinstance(rows, list) or not rows:
            continue
        rng = synth.rng("noise", "file", scenario_id, fname)
        burst = _burst_window(rows, rng, p["drop"])
        kept: list[dict[str, Any]] = []
        for rec in rows:
            if not isinstance(rec, dict) or "event_id" not in rec:
                kept.append(rec)
                continue
            eid = rec["event_id"]
            # skew
            if rec.get("asset_ref") in skew:
                rec["event_timestamp"] = _shift(rec["event_timestamp"], skew[rec["asset_ref"]])
            # drop (independent, plus burst outage)
            in_burst = burst is not None and burst[0] <= parse_iso(rec["event_timestamp"]) <= burst[1]
            if in_burst or rng.random() < p["drop"]:
                truth.dropped.append(
                    {
                        "event_id": eid,
                        "activity_id": act_of.get(eid),
                        "cause": "burst_outage" if in_burst else "random",
                    }
                )
                continue
            # delay: ingest later than event
            delay = abs(_lognormal(rng, p["delay_s"]))
            rec["ingest_timestamp"] = _shift(rec["event_timestamp"], delay)
            truth.delayed.append({"event_id": eid, "delay_ms": int(delay * 1000)})
            # malformed: corrupt inside raw.full_log, keep the JSONL line valid
            if (
                rng.random() < p["malformed"]
                and isinstance(rec.get("raw"), dict)
                and rec["raw"].get("full_log")
            ):
                rec["raw"]["full_log"] = str(rec["raw"]["full_log"])[: rng.randint(5, 30)] + "�"
                truth.malformed.append(eid)
            # unresolved fields: decoder failures null out asset_ref / user
            if rng.random() < p["unresolved"]:
                fields = []
                if rec.get("asset_ref") is not None and rng.random() < 0.5:
                    rec["asset_ref"] = None
                    fields.append("asset_ref")
                if fields:
                    truth.unresolved.append({"event_id": eid, "fields": fields})
            kept.append(rec)
            # duplicate: same event delivered twice
            if rng.random() < p["dup"]:
                dup = deepcopy(rec)
                dup["ingest_timestamp"] = _shift(rec["ingest_timestamp"], rng.uniform(0, 3))
                kept.append(dup)
                truth.duplicated.append(eid)
        # out-of-order delivery: sort by ingest, then perturb locally
        kept.sort(key=lambda r: r.get("ingest_timestamp", "") if isinstance(r, dict) else "")
        _local_reorder(kept, rng)
        out.visible[fname] = kept

    # evidence links for dropped events are removed from the visible-link view (brief file 08 §2:
    # events lost to noise are simply absent); the full exact links stay in hidden truth.
    dropped_ids = {d["event_id"] for d in truth.dropped}
    out.hidden["truth/evidence_links.jsonl"] = [
        link for link in bundle.evidence if link["event_id"] not in dropped_ids
    ]
    out.hidden["truth/noise_truth.json"] = truth.to_dict()
    return out, truth


def data_quality(
    truth: NoiseTruth, bundle_before: TelemetryBundle, shortcut: dict[str, Any] | None = None
) -> dict[str, Any]:
    total = sum(len(bundle_before.visible.get(f, [])) for f in TELEMETRY_FILES)
    delays = [d["delay_ms"] for d in truth.delayed]
    return {
        "noise_profile_id": truth.profile.profile_id,
        "actual_drop_rate": round(len(truth.dropped) / max(1, total), 5),
        "actual_duplicate_rate": round(len(truth.duplicated) / max(1, total), 5),
        "delay_distribution_summary": {
            "count": len(delays),
            "mean_ms": round(sum(delays) / max(1, len(delays)), 1),
            "p95_ms": sorted(delays)[int(0.95 * len(delays))] if delays else 0,
        },
        "malformed_count": len(truth.malformed),
        "unresolved_count": len(truth.unresolved),
        "skewed_asset_count": len(truth.skewed_assets),
        "shortcut_test": shortcut or {"passed": None, "note": "run iris synth qa shortcut on a batch"},
    }


# ---------------------------------------------------------------- helpers


def _shift(ts_iso: str, seconds: float) -> str:
    return iso_z(parse_iso(ts_iso) + timedelta(seconds=seconds))


def _lognormal(rng: Any, mean_s: float) -> float:
    mu = math.log(max(0.1, mean_s))
    return math.exp(rng.gauss(mu, 0.6))


def _burst_window(rows: list[Any], rng: Any, base_drop: float) -> tuple[datetime, datetime] | None:
    times = [
        parse_iso(r["event_timestamp"]) for r in rows if isinstance(r, dict) and r.get("event_timestamp")
    ]
    if len(times) < 5 or rng.random() > min(0.3, base_drop * 4):
        return None
    lo, hi = min(times), max(times)
    span = (hi - lo).total_seconds()
    start = lo + timedelta(seconds=rng.uniform(0, span * 0.7))
    return start, start + timedelta(seconds=span * rng.uniform(0.05, 0.2))


def _local_reorder(rows: list[Any], rng: Any) -> None:
    for i in range(len(rows) - 1):
        if isinstance(rows[i], dict) and isinstance(rows[i + 1], dict) and rng.random() < 0.08:
            rows[i], rows[i + 1] = rows[i + 1], rows[i]
