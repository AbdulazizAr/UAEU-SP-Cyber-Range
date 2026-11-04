"""Realise and re-time one fragment onto a target enterprise.

Two independent transforms are applied to every record body:

* **Re-time.** The fragment keeps each record's original capture timestamps (timestamps
  are never abstracted). The first record is pinned to a chosen virtual time ``at`` and
  every record is moved by one constant offset, so intervals, and therefore frequency and
  correlation behaviour, are preserved exactly. The existing, tested shifters
  (:func:`iris.generator.retime.shift_wazuh`, :func:`iris.generator.eve.shift_event`) do
  the work, so embedded syslog/ISO stamps inside ``full_log`` move too.
* **Realise.** Placeholder tokens (``@@IRIS:...@@``) are replaced by this enterprise's
  concrete values. A realised body must contain no residual token; if any token cannot be
  bound the fragment does not fit this enterprise and is rejected before placement.

The two transforms commute (timestamps are never tokens and tokens are never timestamps),
so the order here is immaterial; re-time runs first purely for readability.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from iris.core.vclock import ensure_utc, iso_z, parse_iso
from iris.fragments.model import (
    Fragment,
    Record,
    get_path,
    realize_value,
    residual_tokens,
    set_path,
)
from iris.generator.eve import parse_eve_ts
from iris.generator.eve import shift_event as _shift_eve
from iris.generator.retime import parse_wazuh_ts
from iris.generator.retime import shift_wazuh as _shift_wazuh

#: source -> visible telemetry file the realised record belongs in.
SOURCE_FILE: dict[str, str] = {
    "wazuh_alert": "telemetry/wazuh/alerts.jsonl",
    "wazuh_archive": "telemetry/wazuh/archives.jsonl",
    "suricata_eve": "telemetry/suricata/eve.jsonl",
}
WAZUH_SOURCES = ("wazuh_alert", "wazuh_archive")


class CompositionError(ValueError):
    """A fragment could not be realised onto the target (unbound tokens, unparsable time)."""


def record_time(record: Record) -> datetime:
    """The record's own (original) capture time, read from its ``ts_field``."""
    raw = get_path(record.body, record.ts_field)
    if not isinstance(raw, str):
        raise CompositionError(f"record has no timestamp at {record.ts_field!r}")
    if record.source in WAZUH_SOURCES:
        return parse_wazuh_ts(raw)
    if record.source == "suricata_eve":
        return parse_eve_ts(raw)
    return parse_iso(raw)


def _shift(record: Record, offset: timedelta) -> dict[str, Any]:
    if record.source in WAZUH_SOURCES:
        return _shift_wazuh(record.body, offset)
    if record.source == "suricata_eve":
        return _shift_eve(record.body, offset)
    # generic ISO timestamp field (app/auth events): shift just that field
    out = {**record.body}
    original = record_time(record)
    set_path(out, record.ts_field, iso_z(original + offset))
    return out


def fragment_offset(fragment: Fragment, at: datetime) -> timedelta:
    """Offset that pins the fragment's first record to virtual time ``at``."""
    if not fragment.records:
        return timedelta(0)
    first = min(fragment.records, key=lambda r: r.offset_ms)
    return ensure_utc(at) - record_time(first)


def realize_fragment(
    fragment: Fragment, bindings: dict[str, str], at: datetime
) -> list[tuple[str, datetime, dict[str, Any]]]:
    """Return ``(visible_file, virtual_time, body)`` for every record of ``fragment``,
    re-timed so the first record lands at ``at`` and realised with ``bindings``.

    Raises :class:`CompositionError` if any token is left unbound (the caller is expected
    to have screened the fragment with :func:`iris.fragments.mapping.unresolved` first).
    """
    offset = fragment_offset(fragment, at)
    out: list[tuple[str, datetime, dict[str, Any]]] = []
    for record in sorted(fragment.records, key=lambda r: r.offset_ms):
        shifted = _shift(record, offset)
        realized = realize_value(shifted, bindings)
        left = residual_tokens(realized)
        if left:
            raise CompositionError(f"{fragment.fragment_id}: unresolved tokens {sorted(left)}")
        vfile = SOURCE_FILE.get(record.source, f"telemetry/other/{record.source}.jsonl")
        out.append((vfile, record_time(record) + offset, realized))
    return out
