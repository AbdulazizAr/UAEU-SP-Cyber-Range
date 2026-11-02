"""Vulnerability intelligence references: CISA KEV and FIRST EPSS snapshots.

Both are read from pinned files only (never live) and queried *as of* a virtual time.
"""

from __future__ import annotations

import bisect
import csv
import gzip
import io
import json
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any

from iris.references.registry import ReferenceError, load_lock, load_registry, require, series, verify


@dataclass(frozen=True)
class KevEntry:
    cve_id: str
    date_added: date
    ransomware: str | None = None


def parse_kev(doc: dict[str, Any]) -> dict[str, KevEntry]:
    out: dict[str, KevEntry] = {}
    for v in doc.get("vulnerabilities", []):
        cve = v["cveID"].strip()
        out[cve] = KevEntry(cve, date.fromisoformat(v["dateAdded"]), v.get("knownRansomwareCampaignUse"))
    return out


@dataclass(frozen=True)
class EpssSnapshot:
    snapshot_date: date
    model_version: str | None
    scores: dict[str, tuple[float, float]]  # cve -> (epss, percentile)


def parse_epss(data: bytes, snapshot_date: date) -> EpssSnapshot:
    """EPSS CSV (optionally gzipped). The first line may be ``#model_version:...,score_date:...``."""
    if data[:2] == b"\x1f\x8b":
        data = gzip.decompress(data)
    text = data.decode("utf-8")
    model: str | None = None
    lines = text.splitlines()
    if lines and lines[0].startswith("#"):
        for part in lines[0].lstrip("#").split(","):
            key, _, value = part.partition(":")
            if key.strip() == "model_version":
                model = value.strip()
        lines = lines[1:]
    scores: dict[str, tuple[float, float]] = {}
    for row in csv.DictReader(io.StringIO("\n".join(lines))):
        scores[row["cve"]] = (float(row["epss"]), float(row["percentile"]))
    return EpssSnapshot(snapshot_date, model, scores)


@dataclass
class Intel:
    """Dated intelligence. Every query takes the virtual time it is asked at."""

    kev: dict[str, KevEntry]
    epss: list[EpssSnapshot] = field(default_factory=list)  # sorted by date
    kev_version: str | None = None

    def __post_init__(self) -> None:
        self.epss.sort(key=lambda s: s.snapshot_date)
        self._dates = [s.snapshot_date for s in self.epss]

    def kev_at(self, cve: str, at: datetime) -> KevEntry | None:
        e = self.kev.get(cve)
        return e if e is not None and e.date_added <= at.date() else None

    def epss_snapshot_at(self, at: datetime) -> EpssSnapshot | None:
        i = bisect.bisect_right(self._dates, at.date())
        return self.epss[i - 1] if i else None

    def epss_at(self, cve: str, at: datetime) -> tuple[float, float] | None:
        snap = self.epss_snapshot_at(at)
        return snap.scores.get(cve) if snap else None


def load_intel(data_dir: Path | None = None, allow_partial_epss: bool = True) -> Intel:
    """Load KEV and every pinned EPSS snapshot. KEV is mandatory; EPSS files that are not
    pinned are skipped when ``allow_partial_epss`` (EPSS is then omitted for those dates)."""
    kev_path = require("cisa-kev", data_dir)
    kev = parse_kev(json.loads(kev_path.read_text(encoding="utf-8")))
    specs = load_registry()
    lock = load_lock()
    snaps: list[EpssSnapshot] = []
    for spec in series("epss", specs):
        status = verify({spec.id: spec}, lock, data_dir)[0].status
        if status != "ok":
            if allow_partial_epss:
                continue
            raise ReferenceError(f"{spec.id}: {status}")
        snaps.append(parse_epss(spec.local_path(data_dir).read_bytes(), date.fromisoformat(spec.version)))
    return Intel(kev=kev, epss=snaps, kev_version=lock.get("cisa-kev", {}).get("sha256", "")[:12] or None)
