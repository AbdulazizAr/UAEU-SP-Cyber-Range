from datetime import timedelta

from iris.generator.eve import (
    dedup,
    eve_event_id,
    format_eve_ts,
    kernel_drops,
    parse_eve_ts,
    shift_event,
)


def _flow(ts: str, cid: str, iface: str, start: str | None = None) -> dict:
    return {
        "timestamp": ts,
        "event_type": "flow",
        "community_id": cid,
        "in_iface": iface,
        "flow_id": hash(iface + cid) & 0xFFFF,
        "flow": {"start": start or ts, "end": ts},
        "tls": {"notbefore": "2025-01-01T00:00:00"},
    }


def test_shift_moves_only_allowlisted_fields():
    ev = _flow("2026-11-02T10:00:00.250000+0000", "1:abc", "eth0", start="2026-11-02T09:59:58.000000+0000")
    out = shift_event(ev, timedelta(days=-610))
    assert out["timestamp"] == "2025-03-02T10:00:00.250000+0000"
    assert out["flow"]["start"] == "2025-03-02T09:59:58.000000+0000"
    assert out["tls"] == ev["tls"]  # traffic-carried time is already virtual
    assert ev["timestamp"].startswith("2026")  # input untouched


def test_dedup_merges_ingress_and_egress_copies():
    a1 = _flow("2026-11-02T10:00:00.100000+0000", "1:aaa", "eth0")
    a2 = _flow("2026-11-02T10:00:00.400000+0000", "1:aaa", "eth1")  # same flow, other interface
    b = _flow("2026-11-02T10:00:05.000000+0000", "1:bbb", "eth0")
    a_later = _flow("2026-11-02T10:00:09.000000+0000", "1:aaa", "eth0")  # same tuple, new connection later
    stats = {
        "timestamp": "2026-11-02T10:00:10.000000+0000",
        "event_type": "stats",
        "stats": {"capture": {"kernel_drops": 0}},
    }
    kept = dedup([b, a2, stats, a1, a_later])
    assert [e.get("in_iface") for e in kept] == ["eth0", "eth0", "eth0", None]
    assert sum(1 for e in kept if e.get("community_id") == "1:aaa") == 2


def test_dedup_keeps_distinct_alert_signatures():
    base = _flow("2026-11-02T10:00:00.100000+0000", "1:aaa", "eth0")
    a = {**base, "event_type": "alert", "alert": {"signature_id": 9904001}}
    b = {**base, "event_type": "alert", "alert": {"signature_id": 9904002}}
    assert len(dedup([a, b])) == 2


def test_eve_event_id_is_deterministic():
    ev = _flow("2026-11-02T10:00:00.100000+0000", "1:aaa", "eth0")
    assert eve_event_id(ev) == eve_event_id(dict(ev))
    assert eve_event_id(ev) != eve_event_id({**ev, "timestamp": "2026-11-02T10:00:01.100000+0000"})


def test_kernel_drops_and_ts_round_trip():
    events = [
        {"event_type": "stats", "stats": {"capture": {"kernel_drops": 3}}},
        {"event_type": "stats", "stats": {"capture": {"kernel_drops": 7}}},
    ]
    assert kernel_drops(events) == 7
    assert kernel_drops([]) is None
    ts = "2025-03-03T05:41:02.123456+0000"
    assert format_eve_ts(parse_eve_ts(ts)) == ts
