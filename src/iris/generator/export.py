"""Turn one live episode's raw capture into package telemetry (INPUT Part 3, 6.2 and Part 5).

The capture is taken on the real clock. The observe window is
[observe_start_real, observe_end_real). Everything before it is pre-roll (boot, settle,
health gate) and goes to the hidden ``preroll/``. Everything after it is drain, also
hidden. Records inside the window are shifted into virtual time by one constant offset,
so the window starts exactly at the episode's virtual start.

Rules:
- EVE is de-duplicated (the sensor sees forwarded flows on two interfaces) before splitting.
- Health-gate canaries (syslog tag ``healthcheck``) and canary HTTP paths (``/hc``) are
  never visible, even if they land inside the window.
- Wazuh archives are visible only when the SOC really retains them (SOC profile).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from iris.core.vclock import EpisodeClock, ensure_utc
from iris.generator.eve import dedup, parse_eve_ts, shift_event
from iris.generator.retime import parse_wazuh_ts, shift_wazuh

CANARY_MARKERS = ("healthcheck", " hc-")


@dataclass
class EpisodeCapture:
    episode_id: str
    virtual_start: datetime
    observe_start_real: datetime
    observe_end_real: datetime
    alerts: list[dict[str, Any]] = field(default_factory=list)
    archives: list[dict[str, Any]] = field(default_factory=list)
    eve: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class ExportedEpisode:
    episode_id: str
    visible: dict[str, list[dict[str, Any]]]
    hidden: dict[str, list[dict[str, Any]]]
    counts: dict[str, int]


def _is_canary_wazuh(rec: dict[str, Any]) -> bool:
    text = str(rec.get("full_log", ""))
    return any(m in text for m in CANARY_MARKERS)


def _is_canary_eve(e: dict[str, Any]) -> bool:
    http = e.get("http")
    return isinstance(http, dict) and str(http.get("url", "")).startswith("/hc")


Rows = list[dict[str, Any]]


def _split(
    records: Rows,
    when: Callable[[dict[str, Any]], datetime],
    start: datetime,
    end: datetime,
    is_canary: Callable[[dict[str, Any]], bool],
) -> tuple[Rows, Rows, Rows]:
    pre: Rows = []
    inside: Rows = []
    post: Rows = []
    for r in records:
        t = when(r)
        if t < start or is_canary(r):
            pre.append(r)
        elif t >= end:
            post.append(r)
        else:
            inside.append(r)
    return pre, inside, post


def export_episode(cap: EpisodeCapture, archives_retained: bool = True) -> ExportedEpisode:
    start, end = ensure_utc(cap.observe_start_real), ensure_utc(cap.observe_end_real)
    clock = EpisodeClock.for_observe_start(cap.virtual_start, start)

    def wazuh_t(r: dict[str, Any]) -> datetime:
        return parse_wazuh_ts(r["timestamp"])

    def eve_t(e: dict[str, Any]) -> datetime:
        return parse_eve_ts(e["timestamp"])

    a_pre, a_in, a_post = _split(cap.alerts, wazuh_t, start, end, _is_canary_wazuh)
    r_pre, r_in, r_post = _split(cap.archives, wazuh_t, start, end, _is_canary_wazuh)
    eve = dedup(cap.eve)
    e_pre, e_in, e_post = _split(eve, eve_t, start, end, _is_canary_eve)

    visible = {
        "telemetry/wazuh/alerts.jsonl": sorted((shift_wazuh(r, clock.offset) for r in a_in), key=wazuh_t),
        "telemetry/suricata/eve.jsonl": sorted((shift_event(e, clock.offset) for e in e_in), key=eve_t),
    }
    if archives_retained:
        visible["telemetry/wazuh/archives.jsonl"] = sorted(
            (shift_wazuh(r, clock.offset) for r in r_in), key=wazuh_t
        )
    eid = cap.episode_id
    hidden = {  # real clock, untouched: what the range really did around the window
        f"preroll/{eid}/wazuh_alerts.jsonl": a_pre,
        f"preroll/{eid}/wazuh_archives.jsonl": r_pre,
        f"preroll/{eid}/suricata_eve.jsonl": e_pre,
        f"preroll/{eid}/drain.jsonl": [*a_post, *r_post, *e_post],
    }
    if not archives_retained:  # collected by the manager but not retained by the SOC: hidden only
        hidden[f"preroll/{eid}/archives_not_retained.jsonl"] = r_in
    counts = {
        "alerts_visible": len(a_in),
        "archives_visible": len(r_in) if archives_retained else 0,
        "eve_visible": len(e_in),
        "eve_raw": len(cap.eve),
        "eve_deduped": len(eve),
        "preroll_records": len(a_pre) + len(r_pre) + len(e_pre),
        "drain_records": len(a_post) + len(r_post) + len(e_post),
    }
    return ExportedEpisode(eid, visible, hidden, counts)
