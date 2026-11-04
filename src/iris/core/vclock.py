"""Virtual time.

This is the ONLY module allowed to read the real clock (enforced by
``iris.devtools.boundaries``). Everything else asks a :class:`VClock` for the time.

Two-layer time model (INPUT Part 2, B2):

* Layer 1 (state timeline) jumps instantly between events: :meth:`VClock.advance_to`.
* Layer 2 (live episodes) runs at 1x with a constant offset:
  ``virtual = real + offset``. :class:`EpisodeClock` holds that offset.

Rules enforced here:

* Virtual time is always timezone-aware UTC.
* Virtual time only moves forward within a scenario.
* An episode window must not cross a year boundary (Wazuh completes year-less
  syslog timestamps from the manager's date; INPUT Part 3, 6.5).
"""

from __future__ import annotations

import heapq
import itertools
import os
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any


class TimeError(ValueError):
    """Raised when a time rule is violated (backwards move, naive datetime, bad window)."""


def ensure_utc(ts: datetime) -> datetime:
    """Return ``ts`` converted to UTC; reject naive datetimes."""
    if ts.tzinfo is None or ts.tzinfo.utcoffset(ts) is None:
        raise TimeError(f"naive datetime not allowed: {ts!r}")
    return ts.astimezone(UTC)


def iso_z(ts: datetime) -> str:
    """Format as ISO-8601 UTC with a trailing ``Z`` (the contract format)."""
    ts = ensure_utc(ts)
    text = ts.isoformat(timespec="milliseconds" if ts.microsecond else "seconds")
    return text.replace("+00:00", "Z")


def parse_iso(text: str) -> datetime:
    """Parse an ISO-8601 timestamp that carries an offset or ``Z``."""
    return ensure_utc(datetime.fromisoformat(text.replace("Z", "+00:00")))


def real_utc_now() -> datetime:
    """The real wall clock. Use only for provenance (e.g. when a reference file was
    downloaded) and for episode offsets; never for scenario content."""
    return datetime.now(UTC)


def provenance_utc_now() -> datetime:
    """Creation time for provenance fields in package manifests.

    Honours ``SOURCE_DATE_EPOCH`` (the reproducible-builds convention): when it is set,
    the same seeds produce byte-identical packages, hidden manifest included. Otherwise
    it is the real clock."""
    epoch = os.environ.get("SOURCE_DATE_EPOCH", "").strip()
    if epoch:
        try:
            return datetime.fromtimestamp(int(epoch), UTC)
        except (ValueError, OverflowError, OSError) as exc:
            raise TimeError(f"SOURCE_DATE_EPOCH must be integer seconds, got {epoch!r}") from exc
    return real_utc_now()


@dataclass(order=True)
class _Scheduled:
    at: datetime
    seq: int
    event: Any = field(compare=False)


class VClock:
    """Forward-only virtual clock with a simple event schedule.

    >>> c = VClock(datetime(2025, 3, 1, tzinfo=UTC))
    >>> c.schedule(datetime(2025, 3, 2, tzinfo=UTC), "review")
    >>> [e for _, e in c.run_until(datetime(2025, 3, 3, tzinfo=UTC))]
    ['review']
    """

    def __init__(self, start: datetime) -> None:
        self._now = ensure_utc(start)
        self._queue: list[_Scheduled] = []
        self._seq = itertools.count()

    def now(self) -> datetime:
        return self._now

    def advance_to(self, ts: datetime) -> datetime:
        ts = ensure_utc(ts)
        if ts < self._now:
            raise TimeError(f"virtual time cannot move backwards: {iso_z(ts)} < {iso_z(self._now)}")
        self._now = ts
        return self._now

    def advance_by(self, delta: timedelta) -> datetime:
        if delta < timedelta(0):
            raise TimeError("negative advance not allowed")
        return self.advance_to(self._now + delta)

    def schedule(self, at: datetime, event: Any) -> None:
        at = ensure_utc(at)
        if at < self._now:
            raise TimeError(f"cannot schedule in the past: {iso_z(at)} < {iso_z(self._now)}")
        heapq.heappush(self._queue, _Scheduled(at, next(self._seq), event))

    def pending(self) -> int:
        return len(self._queue)

    def peek(self) -> datetime | None:
        return self._queue[0].at if self._queue else None

    def run_until(self, until: datetime) -> Iterator[tuple[datetime, Any]]:
        """Yield due events in time order (ties keep insertion order), advancing the
        clock to each event, then to ``until``."""
        until = ensure_utc(until)
        while self._queue and self._queue[0].at <= until:
            item = heapq.heappop(self._queue)
            self.advance_to(item.at)
            yield item.at, item.event
        self.advance_to(until)

    def drain(self, until: datetime, handler: Callable[[datetime, Any], None]) -> int:
        """Run ``handler`` for every event due up to ``until``; return the count."""
        count = 0
        for at, event in self.run_until(until):
            handler(at, event)
            count += 1
        return count


def crosses_year_boundary(start: datetime, end: datetime) -> bool:
    start, end = ensure_utc(start), ensure_utc(end)
    return start.year != end.year


@dataclass(frozen=True)
class EpisodeWindow:
    """One live observation window in virtual time."""

    index: int
    virtual_start: datetime
    virtual_end: datetime

    def __post_init__(self) -> None:
        start, end = ensure_utc(self.virtual_start), ensure_utc(self.virtual_end)
        if end <= start:
            raise TimeError(f"episode {self.index}: end must be after start")
        if crosses_year_boundary(start, end):
            raise TimeError(f"episode {self.index}: window crosses a year boundary")
        object.__setattr__(self, "virtual_start", start)
        object.__setattr__(self, "virtual_end", end)

    @property
    def duration(self) -> timedelta:
        return self.virtual_end - self.virtual_start

    def contains(self, ts: datetime, tolerance: timedelta = timedelta(0)) -> bool:
        ts = ensure_utc(ts)
        return self.virtual_start - tolerance <= ts <= self.virtual_end + tolerance


@dataclass(frozen=True)
class EpisodeClock:
    """Constant offset between real time and virtual time during one live episode.

    The offset is chosen so that OBSERVE starts exactly at the planned virtual start;
    pre-roll therefore happens at earlier virtual times (INPUT Part 3, 6.2).
    """

    offset: timedelta

    @classmethod
    def for_observe_start(cls, virtual_observe_start: datetime, real_observe_start: datetime) -> EpisodeClock:
        return cls(offset=ensure_utc(virtual_observe_start) - ensure_utc(real_observe_start))

    def to_virtual(self, real_ts: datetime) -> datetime:
        return ensure_utc(real_ts) + self.offset

    def to_real(self, virtual_ts: datetime) -> datetime:
        return ensure_utc(virtual_ts) - self.offset

    def now(self) -> datetime:
        """Current virtual time during a live episode."""
        return self.to_virtual(real_utc_now())

    def offset_seconds(self) -> float:
        """The export shift in seconds (negative when the virtual date is in the past)."""
        return self.offset.total_seconds()


def validate_episode_sequence(windows: list[EpisodeWindow], min_gap: timedelta = timedelta(0)) -> None:
    """Episodes must be strictly ordered, non-overlapping and separated by ``min_gap``."""
    for prev, cur in itertools.pairwise(windows):
        if cur.index != prev.index + 1:
            raise TimeError(f"episode indices must be consecutive: {prev.index} then {cur.index}")
        if cur.virtual_start < prev.virtual_end + min_gap:
            raise TimeError(f"episode {cur.index} starts before episode {prev.index} ends (+gap)")
