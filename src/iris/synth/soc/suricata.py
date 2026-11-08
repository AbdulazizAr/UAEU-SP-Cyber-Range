"""Suricata EVE synthesis (builder brief file 04 §5).

Flows derived from activity footprints (and benign background) become EVE JSON with the real
field structure, including a correct Community ID (v1) so the same flow has the same ID on
every record and can be joined to a Wazuh-carried copy. Alerts come only from a signature
matcher over conditions we can actually evaluate; we never invent an ET SID (the full ET Open
set is not available offline — documented limitation), so Suricata here is mostly flow/protocol
telemetry plus a small set of behaviour alerts.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
from datetime import datetime
from typing import Any

from iris.core.vclock import iso_z

COMMUNITY_SEED = 0
_PROTO_NUM = {"tcp": 6, "udp": 17, "icmp": 1}


def community_id(
    src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: str, seed: int = COMMUNITY_SEED
) -> str:
    """Community ID v1 (https://github.com/corelight/community-id-spec). Deterministic and
    direction-independent: the (ip, port) pair tuples are ordered before hashing."""
    pnum = _PROTO_NUM[proto]
    sa = ipaddress.ip_address(src_ip).packed
    da = ipaddress.ip_address(dst_ip).packed
    sp, dp = src_port, dst_port
    # order so the flow hashes the same in both directions
    if (sa, sp) > (da, dp):
        sa, da, sp, dp = da, sa, dp, sp
    buf = seed.to_bytes(2, "big") + sa + da + pnum.to_bytes(1, "big") + b"\x00"
    buf += sp.to_bytes(2, "big") + dp.to_bytes(2, "big")
    digest = hashlib.sha1(buf).digest()
    return "1:" + base64.b64encode(digest).decode("ascii")


def _flow_id(src_ip: str, dst_ip: str, src_port: int, dst_port: int, ts: datetime) -> int:
    raw = f"{src_ip}|{dst_ip}|{src_port}|{dst_port}|{iso_z(ts)}"
    return int(hashlib.sha256(raw.encode()).hexdigest()[:15], 16)


def eve_timestamp(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000"


def flow_event(
    ts: datetime,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    proto: str,
    *,
    in_iface: str = "eth0",
    bytes_toserver: int = 0,
    bytes_toclient: int = 0,
    pkts_toserver: int = 1,
    pkts_toclient: int = 0,
    app_proto: str | None = None,
    state: str = "established",
) -> dict[str, Any]:
    cid = community_id(src_ip, dst_ip, src_port, dst_port, proto)
    ev: dict[str, Any] = {
        "timestamp": eve_timestamp(ts),
        "flow_id": _flow_id(src_ip, dst_ip, src_port, dst_port, ts),
        "in_iface": in_iface,
        "event_type": "flow",
        "src_ip": src_ip,
        "src_port": src_port,
        "dest_ip": dst_ip,
        "dest_port": dst_port,
        "proto": proto.upper(),
        "community_id": cid,
        "flow": {
            "pkts_toserver": pkts_toserver,
            "pkts_toclient": pkts_toclient,
            "bytes_toserver": bytes_toserver,
            "bytes_toclient": bytes_toclient,
            "start": eve_timestamp(ts),
            "state": state,
            "reason": "timeout",
        },
    }
    if app_proto:
        ev["app_proto"] = app_proto
    return ev


# ---------------------------------------------------------------- signature matcher


def match_signatures(flow: dict[str, Any]) -> dict[str, Any] | None:
    """Evaluate the few conditions we can support and return an ``alert`` record or None.

    These use Suricata's own GID 1 anomaly/stream space conceptually; we DO NOT emit ET Open
    SIDs (not available offline). A scan flow (tiny bytes, failed app) and a very large
    outbound transfer are the two behaviours surfaced, clearly marked as behaviour signals."""
    f = flow.get("flow", {})
    bts = f.get("bytes_toserver", 0)
    btc = f.get("bytes_toclient", 0)
    if flow.get("app_proto") == "failed" and bts < 200 and btc < 200:
        return {
            "signature_id": 2001,
            "signature": "IRIS behaviour: probable port scan (failed small flow)",
            "category": "Attempted Information Leak",
            "severity": 2,
            "gid": 1,
            "rev": 1,
        }
    if bts > 20_000_000:
        return {
            "signature_id": 2002,
            "signature": "IRIS behaviour: large outbound transfer",
            "category": "Potentially Bad Traffic",
            "severity": 2,
            "gid": 1,
            "rev": 1,
        }
    return None


def alert_event(flow: dict[str, Any], sig: dict[str, Any]) -> dict[str, Any]:
    ev = dict(flow)
    ev["event_type"] = "alert"
    ev["alert"] = sig
    return ev


def suricata_stats(ts: datetime, flow_count: int, kernel_drops: int = 0) -> dict[str, Any]:
    return {
        "timestamp": eve_timestamp(ts),
        "event_type": "stats",
        "stats": {
            "capture": {"kernel_packets": flow_count * 6, "kernel_drops": kernel_drops},
            "decoder": {"pkts": flow_count * 6, "bytes": flow_count * 800},
            "flow": {"total": flow_count},
        },
    }


def sensor_inventory(placement: list[str], ruleset_date: str) -> dict[str, Any]:
    return {
        "suricata_version": "8.0.6",
        "placement_summary": placement,
        "eve_types": ["alert", "flow", "dns", "http", "tls", "ssh", "stats"],
        "ruleset_snapshot_date": ruleset_date,
        "loaded_categories": ["app-layer-events", "stream-events", "iris-behaviour"],
        "local_rules": ["iris-behaviour-2001", "iris-behaviour-2002"],
    }
