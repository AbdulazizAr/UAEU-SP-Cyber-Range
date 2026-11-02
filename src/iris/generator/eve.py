"""Suricata EVE post-processing (INPUT Part 6, sections 5 and 7; decisions.md "Suricata").

* :func:`shift_event` moves capture-derived timestamps from real to virtual time by the
  episode's constant offset. Only allowlisted fields are shifted: data carried inside
  traffic (TLS validity, HTTP Date) already comes from containers on the virtual clock.
* :func:`dedup` removes the copies a multi-interface capture produces: one sensor in the
  router namespace sees a forwarded packet on its ingress AND egress interface. Events
  are duplicates when community_id, event type and signature match within 1 second.
"""

from __future__ import annotations

import copy
from collections.abc import Iterable
from datetime import datetime, timedelta
from typing import Any

from iris.core.hashing import event_id

#: Capture-derived fields (dotted paths) that are shifted. Everything else is untouched.
SHIFT_FIELDS: tuple[str, ...] = ("timestamp", "flow.start", "flow.end")

EVE_TS_FORMAT = "%Y-%m-%dT%H:%M:%S.%f%z"


def parse_eve_ts(text: str) -> datetime:
    """EVE timestamps look like ``2025-03-03T05:41:02.123456+0000``."""
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%f%z")  # same as EVE_TS_FORMAT; aware via %z


def format_eve_ts(ts: datetime) -> str:
    return ts.strftime(EVE_TS_FORMAT)


def _get_parent(event: dict[str, Any], path: str) -> tuple[dict[str, Any] | None, str]:
    *parents, leaf = path.split(".")
    node: Any = event
    for p in parents:
        node = node.get(p) if isinstance(node, dict) else None
        if node is None:
            return None, leaf
    return (node if isinstance(node, dict) else None), leaf


def shift_event(event: dict[str, Any], offset: timedelta) -> dict[str, Any]:
    """Return a copy with every allowlisted timestamp moved by ``offset``."""
    out = copy.deepcopy(event)
    for path in SHIFT_FIELDS:
        parent, leaf = _get_parent(out, path)
        if parent is not None and isinstance(parent.get(leaf), str):
            parent[leaf] = format_eve_ts(parse_eve_ts(parent[leaf]) + offset)
    return out


def _signature_id(event: dict[str, Any]) -> int | None:
    alert = event.get("alert")
    return alert.get("signature_id") if isinstance(alert, dict) else None


def eve_event_id(event: dict[str, Any]) -> str:
    """Deterministic ID shared by a Suricata event and its Wazuh-carried copy."""
    return event_id(
        "suricata_eve",
        {
            "flow_id": event.get("flow_id"),
            "timestamp": event.get("timestamp"),
            "event_type": event.get("event_type"),
            "signature_id": _signature_id(event),
        },
    )


def flow_key(event: dict[str, Any]) -> Any:
    """community_id when present, else the direction-independent 5-tuple, else None."""
    if event.get("community_id"):
        return event["community_id"]
    if event.get("src_ip") and event.get("dest_ip"):
        a = (event["src_ip"], event.get("src_port", 0))
        b = (event["dest_ip"], event.get("dest_port", 0))
        return (event.get("proto"), *sorted([a, b]))
    return None


def dedup(events: Iterable[dict[str, Any]], window: timedelta = timedelta(seconds=1)) -> list[dict[str, Any]]:
    """Drop multi-interface duplicates. Events with no flow identity (stats, some
    anomalies) always pass. Order of the surviving events follows their timestamps."""
    ordered = sorted(events, key=lambda e: parse_eve_ts(e["timestamp"]))
    kept: list[dict[str, Any]] = []
    seen: dict[tuple[Any, ...], list[datetime]] = {}
    for ev in ordered:
        fk = flow_key(ev)
        if fk is None:
            kept.append(ev)
            continue
        key = (fk, ev.get("event_type"), _signature_id(ev))
        ts = parse_eve_ts(ev["timestamp"])
        times = seen.setdefault(key, [])
        if any(abs(ts - t) <= window for t in times):
            continue
        times.append(ts)
        kept.append(ev)
    return kept


def kernel_drops(events: Iterable[dict[str, Any]]) -> int | None:
    """Kernel drops from the last ``stats`` event, if any."""
    last: int | None = None
    for ev in events:
        if ev.get("event_type") == "stats":
            capture = ev.get("stats", {}).get("capture", {})
            if "kernel_drops" in capture:
                last = int(capture["kernel_drops"])
    return last
