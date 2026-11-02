"""Move captured Wazuh records into virtual time (P1 decision: capture real, shift at export).

libfaketime cannot be used with Wazuh 4.14: with it preloaded, no manager daemon starts,
at any offset including +0 (P1 spike, 2026-11-02). Every live episode therefore runs on
the real clock, and every record is moved by one constant offset per episode, the
:class:`iris.core.vclock.EpisodeClock` offset. Because the offset is the same for all
records, intervals are kept exactly, so frequency and correlation rules behave the same.

Shifted fields:
- ``timestamp``: ``2026-11-02T08:07:41.123+0000``.
- ``predecoder.timestamp``: syslog ``Nov  2 08:07:41``, which has no year.
- The leading syslog stamp, and every ISO-8601 stamp, inside ``full_log``.

Suricata EVE uses :func:`iris.generator.eve.shift_event`.
"""

from __future__ import annotations

import copy
import re
from datetime import UTC, datetime, timedelta
from typing import Any

WAZUH_TS = "%Y-%m-%dT%H:%M:%S.%f%z"
MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
SYSLOG_RE = re.compile(r"^(?P<mon>[A-Z][a-z]{2}) (?P<day>[ \d]\d) (?P<hms>\d{2}:\d{2}:\d{2})")
ISO_RE = re.compile(
    r"(?P<date>\d{4}-\d{2}-\d{2})T(?P<time>\d{2}:\d{2}:\d{2})(?P<frac>\.\d+)?(?P<tz>Z|[+-]\d{2}:?\d{2})?"
)


def parse_wazuh_ts(value: str) -> datetime:
    return datetime.strptime(value, WAZUH_TS).astimezone(UTC)


def format_wazuh_ts(dt: datetime) -> str:
    dt = dt.astimezone(UTC)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}+0000"


def format_syslog(dt: datetime) -> str:
    return f"{MONTHS[dt.month - 1]} {dt.day:2d} {dt:%H:%M:%S}"


def _syslog_dt(match: re.Match[str], ref: datetime) -> datetime:
    """Syslog stamps carry no year: take the one that puts the stamp closest to ``ref``."""
    mon = MONTHS.index(match["mon"]) + 1
    h, m, s = (int(x) for x in match["hms"].split(":"))
    candidates = [
        datetime(y, mon, int(match["day"]), h, m, s, tzinfo=UTC)
        for y in (ref.year - 1, ref.year, ref.year + 1)
    ]
    return min(candidates, key=lambda c: abs(c - ref))


def shift_syslog_prefix(text: str, offset: timedelta, ref: datetime) -> str:
    m = SYSLOG_RE.match(text)
    if not m:
        return text
    return format_syslog(_syslog_dt(m, ref) + offset) + text[m.end() :]


def shift_iso_stamps(text: str, offset: timedelta) -> str:
    def repl(m: re.Match[str]) -> str:
        tz = m["tz"]
        stamp = f"{m['date']}T{m['time']}{m['frac'] or ''}"
        if tz in (None, "Z"):
            dt = datetime.fromisoformat(stamp).replace(tzinfo=UTC)
        else:
            dt = datetime.fromisoformat(stamp + (tz if ":" in tz else f"{tz[:3]}:{tz[3:]}"))
        out = (dt + offset).astimezone(dt.tzinfo)
        frac = f".{out.microsecond:06d}"[: len(m["frac"])] if m["frac"] else ""
        return f"{out:%Y-%m-%dT%H:%M:%S}{frac}{tz or ''}"

    return ISO_RE.sub(repl, text)


def shift_wazuh(event: dict[str, Any], offset: timedelta) -> dict[str, Any]:
    """A shifted copy of one Wazuh alert or archive record."""
    if "timestamp" not in event:
        raise ValueError("Wazuh record without a timestamp cannot be placed in virtual time")
    out = copy.deepcopy(event)
    ref = parse_wazuh_ts(out["timestamp"])
    out["timestamp"] = format_wazuh_ts(ref + offset)
    pre = out.get("predecoder")
    if isinstance(pre, dict) and isinstance(pre.get("timestamp"), str):
        m = SYSLOG_RE.match(pre["timestamp"])
        if m:
            pre["timestamp"] = format_syslog(_syslog_dt(m, ref) + offset)
    if isinstance(out.get("full_log"), str):
        out["full_log"] = shift_iso_stamps(shift_syslog_prefix(out["full_log"], offset, ref), offset)
    return out
