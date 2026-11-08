"""Loaders and validators for the synthetic-path catalogs (builder brief file 09 §1).

* ``software.yaml``  — security-relevant software, real versions, per OS profile.
* ``cve_seed.yaml``  — compact offline CVE seed catalog (brief file 03 §3 option B).

Validation is strict: a CVE entry must name a package the software catalog tracks, and an
entry is usable in generation only when it is not ``needs_human_review`` (brief: unverified
entries are excluded). Every usable entry still carries its ``source`` and ``review_status``
into findings so nothing is silently presented as validated.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from iris.settings import repo_root


@dataclass(frozen=True)
class Package:
    id: str
    purl_name: str
    os_profiles: tuple[str, ...]
    versions: tuple[str, ...]
    recipe: str | None = None


@dataclass(frozen=True)
class CveEntry:
    cve_id: str
    package: str
    affected_below: str
    fixed_version: str
    published_at: date
    severity: str | None = None
    cvss: float | None = None
    cvss_version: str | None = None
    cwe: str | None = None
    kev_listed: bool = False
    kev_date_added: date | None = None
    epss: float | None = None
    epss_date: date | None = None
    source: str = "unknown"
    review_status: str = "unreviewed"
    needs_human_review: bool = False


@dataclass(frozen=True)
class SoftwareCatalog:
    version: str
    packages: dict[str, Package]
    os_base_count: dict[str, int]
    purl_type: dict[str, str]
    patch_floor: dict[str, float]

    def for_os(self, os_profile: str) -> list[Package]:
        return [p for p in self.packages.values() if os_profile in p.os_profiles]

    def by_recipe(self, recipe: str) -> list[Package]:
        return [p for p in self.packages.values() if p.recipe == recipe]


@dataclass(frozen=True)
class CveCatalog:
    version: str
    entries: tuple[CveEntry, ...]
    source_note: str = ""

    def usable(self) -> list[CveEntry]:
        """Entries eligible for default generation (brief: exclude needs_human_review)."""
        return [e for e in self.entries if not e.needs_human_review]

    def for_package(self, package: str) -> list[CveEntry]:
        return [e for e in self.usable() if e.package == package]

    by_id: dict[str, CveEntry] = field(default_factory=dict)


def _load_yaml(path: Path) -> dict[str, Any]:
    data: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data


def _as_date(v: Any) -> date:
    return v if isinstance(v, date) else date.fromisoformat(str(v))


@lru_cache(maxsize=2)
def load_software(root: Path | None = None) -> SoftwareCatalog:
    base = root if root is not None else repo_root() / "configs" / "catalog"
    raw = _load_yaml(base / "software.yaml")
    packages = {
        pid: Package(
            id=pid,
            purl_name=p["purl_name"],
            os_profiles=tuple(p["os_profiles"]),
            versions=tuple(str(v) for v in p["versions"]),
            recipe=p.get("recipe"),
        )
        for pid, p in raw["packages"].items()
    }
    return SoftwareCatalog(
        version=raw["catalog_version"],
        packages=packages,
        os_base_count={k: int(v) for k, v in raw["os_base_package_count"].items()},
        purl_type=dict(raw["purl_type"]),
        patch_floor={k: float(v) for k, v in raw["patch_floor_by_maturity"].items()},
    )


@lru_cache(maxsize=2)
def load_cves(root: Path | None = None) -> CveCatalog:
    base = root if root is not None else repo_root() / "configs" / "catalog"
    raw = _load_yaml(base / "cve_seed.yaml")
    software = load_software(root)
    entries: list[CveEntry] = []
    for c in raw["cves"]:
        if c["package"] not in software.packages:
            raise ValueError(f"{c['cve_id']}: package {c['package']} not in software catalog")
        kev = c.get("kev", {}) or {}
        entries.append(
            CveEntry(
                cve_id=c["cve_id"],
                package=c["package"],
                affected_below=str(c["affected_below"]),
                fixed_version=str(c["fixed_version"]),
                published_at=_as_date(c["published_at"]),
                severity=c.get("severity"),
                cvss=c.get("cvss"),
                cvss_version=c.get("cvss_version"),
                cwe=c.get("cwe"),
                kev_listed=bool(kev.get("listed", False)),
                kev_date_added=_as_date(kev["date_added"]) if kev.get("date_added") else None,
                epss=c.get("epss"),
                epss_date=_as_date(c["epss_date"]) if c.get("epss_date") else None,
                source=c.get("source", "unknown"),
                review_status=c.get("review_status", "unreviewed"),
                needs_human_review=bool(c.get("needs_human_review", False)),
            )
        )
    cat = CveCatalog(
        version=raw["catalog_version"], entries=tuple(entries), source_note=raw.get("source_note", "")
    )
    object.__setattr__(cat, "by_id", {e.cve_id: e for e in entries})
    return cat


def version_key(v: str) -> list[tuple[int, int | str]]:
    """Comparable key for messy version strings (``9.2p1``, ``1.9.13p3``, ``2.38-1``).

    Splits into numeric and alphabetic runs; a numeric run sorts before an alphabetic run at
    the same position (so ``9.8`` < ``9.8p1``). Good enough for the catalog's real strings;
    not a full dpkg/rpm comparator (documented limitation)."""
    tokens: list[tuple[int, int | str]] = []
    num = ""
    alpha = ""
    for ch in v:
        if ch.isdigit():
            if alpha:
                tokens.append((1, alpha))
                alpha = ""
            num += ch
        elif ch.isalpha():
            if num:
                tokens.append((0, int(num)))
                num = ""
            alpha += ch
        else:  # separator . - _ ~
            if num:
                tokens.append((0, int(num)))
                num = ""
            if alpha:
                tokens.append((1, alpha))
                alpha = ""
    if num:
        tokens.append((0, int(num)))
    if alpha:
        tokens.append((1, alpha))
    return tokens


def version_lt(a: str, b: str) -> bool:
    """True when version ``a`` is older than ``b``."""
    ka, kb = version_key(a), version_key(b)
    for x, y in zip(ka, kb, strict=False):
        if x != y:
            # numeric (0) sorts before alphabetic (1); within a kind compare the value
            if x[0] != y[0]:
                return x[0] < y[0]
            return x[1] < y[1]  # type: ignore[operator]
    return len(ka) < len(kb)
