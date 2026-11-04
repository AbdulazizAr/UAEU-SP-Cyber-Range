"""Assemble abstracted fragments from recorded telemetry of a single activity window."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from iris.fragments.model import (
    Fragment,
    FragmentTruth,
    Record,
    abstract_value,
    residual_tokens,
)


def assemble_fragment(
    fragment_id: str,
    group_id: str,
    kind: str,
    truth: FragmentTruth,
    raw: list[tuple[str, datetime, str, dict[str, Any]]],
    mapping_pairs: list[tuple[str, str]],
    hints: dict[str, str],
    requires: dict[str, Any] | None = None,
) -> Fragment:
    """``raw`` is (source, event_time, ts_field, body) per record. Bodies are abstracted
    with ``mapping_pairs`` (concrete->token); offsets are measured from the first record."""
    ordered = sorted(raw, key=lambda r: r[1])
    base = ordered[0][1] if ordered else None
    records: list[Record] = []
    for source, ts, ts_field, body in ordered:
        offset_ms = int((ts - base).total_seconds() * 1000) if base else 0
        records.append(
            Record(
                source=source,
                offset_ms=offset_ms,
                ts_field=ts_field,
                body=abstract_value(body, mapping_pairs),
            )
        )
    present = residual_tokens([r.body for r in records])
    tokens = {tok: hints.get(tok, "unknown") for tok in sorted(present)}
    duration = records[-1].offset_ms if records else 0
    return Fragment(
        fragment_id=fragment_id,
        kind=kind,
        group_id=group_id,
        duration_ms=duration,
        tokens=tokens,
        records=records,
        truth=truth,
        requires=requires or {},
    )
