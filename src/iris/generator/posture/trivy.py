"""Parse Trivy JSON reports (``SchemaVersion: 2``, ``--list-all-pkgs``).

One report per image digest, made once on a lab machine by ``iris posture scan`` and
cached under ``$IRIS_DATA/cache/posture/``. Real CVEs therefore come from the real
package versions in our images; scenarios only decide when they become visible.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from iris.core.vclock import parse_iso
from iris.settings import paths

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
SEVERITIES = ("UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL")
CVSS_PREFERENCE = ("nvd", "ghsa", "redhat")


@dataclass(frozen=True)
class Package:
    name: str
    version: str  # full installed version (with release)
    purl: str | None
    src_name: str | None
    kind: str  # os | lang
    target: str
    depends_on: tuple[str, ...] = ()
    pkg_id: str | None = None


@dataclass(frozen=True)
class Vuln:
    cve_id: str
    pkg_name: str
    purl: str | None
    installed_version: str
    fixed_version: str | None
    status: str | None
    severity: str
    cvss: float | None
    cvss_version: str | None
    published_at: datetime | None
    modified_at: datetime | None
    cwe_ids: tuple[str, ...] = ()
    kind: str = "os"


@dataclass
class ImageReport:
    image: str
    image_id: str | None
    os_family: str | None
    os_name: str | None
    packages: list[Package]
    vulns: list[Vuln]
    skipped_ids: int = 0  # advisories without a CVE id (e.g. TEMP-...)
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return parse_iso(value)
    except Exception:  # Trivy dates vary in precision; unknown means "not dated"
        return None


def _cvss(v: dict[str, Any]) -> tuple[float | None, str | None]:
    table = v.get("CVSS") or {}
    for src in CVSS_PREFERENCE:
        entry = table.get(src)
        if not entry:
            continue
        if entry.get("V3Score") is not None:
            vector = str(entry.get("V3Vector") or "")
            return float(entry["V3Score"]), ("3.1" if vector.startswith("CVSS:3.1") else None)
        if entry.get("V40Score") is not None:
            return float(entry["V40Score"]), "4.0"
    return None, None


def parse_trivy(doc: dict[str, Any], image: str | None = None) -> ImageReport:
    if doc.get("SchemaVersion") != 2:
        raise ValueError(f"unsupported Trivy SchemaVersion {doc.get('SchemaVersion')!r}")
    meta = doc.get("Metadata") or {}
    os_meta = meta.get("OS") or {}
    packages: list[Package] = []
    vulns: list[Vuln] = []
    skipped = 0
    for result in doc.get("Results") or []:
        kind = "os" if result.get("Class") == "os-pkgs" else "lang"
        target = str(result.get("Target", ""))
        ids_to_purl: dict[str, str] = {}
        for p in result.get("Packages") or []:
            version = str(p.get("Version", ""))
            if p.get("Release"):
                version = f"{version}-{p['Release']}"
            if p.get("Epoch"):
                version = f"{p['Epoch']}:{version}"
            purl = (p.get("Identifier") or {}).get("PURL")
            if p.get("ID") and purl:
                ids_to_purl[p["ID"]] = purl
            packages.append(
                Package(
                    name=str(p["Name"]),
                    version=version,
                    purl=purl,
                    src_name=p.get("SrcName"),
                    kind=kind,
                    target=target,
                    depends_on=tuple(p.get("DependsOn") or ()),
                    pkg_id=p.get("ID"),
                )
            )
        for v in result.get("Vulnerabilities") or []:
            cve = str(v.get("VulnerabilityID", ""))
            if not CVE_RE.match(cve):
                skipped += 1
                continue
            score, cvss_ver = _cvss(v)
            sev = str(v.get("Severity", "UNKNOWN")).upper()
            vulns.append(
                Vuln(
                    cve_id=cve,
                    pkg_name=str(v.get("PkgName", "")),
                    purl=(v.get("PkgIdentifier") or {}).get("PURL") or ids_to_purl.get(v.get("PkgID", "")),
                    installed_version=str(v.get("InstalledVersion", "")),
                    fixed_version=v.get("FixedVersion") or None,
                    status=v.get("Status"),
                    severity=sev if sev in SEVERITIES else "UNKNOWN",
                    cvss=score,
                    cvss_version=cvss_ver,
                    published_at=_dt(v.get("PublishedDate")),
                    modified_at=_dt(v.get("LastModifiedDate")),
                    cwe_ids=tuple(v.get("CweIDs") or ()),
                    kind=kind,
                )
            )
    # Resolve DependsOn package IDs to purls where possible (CycloneDX dependency graph).
    by_id = {p.pkg_id: p.purl for p in packages if p.pkg_id and p.purl}
    packages = [
        Package(**{**asdict(p), "depends_on": tuple(by_id.get(d, d) for d in p.depends_on)}) for p in packages
    ]
    return ImageReport(
        image=image or str(doc.get("ArtifactName", "")),
        image_id=meta.get("ImageID"),
        os_family=os_meta.get("Family"),
        os_name=os_meta.get("Name"),
        packages=packages,
        vulns=vulns,
        skipped_ids=skipped,
    )


# ---------------------------------------------------------------- cache


def safe_name(image: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", image)


def cache_dir(data_dir: Path | None = None) -> Path:
    return (data_dir or paths().data) / "cache" / "posture"


def cache_path(image: str, data_dir: Path | None = None) -> Path:
    return cache_dir(data_dir) / f"{safe_name(image)}.json"


def load_cached(image: str, data_dir: Path | None = None) -> ImageReport | None:
    """A cached scan: ``{"image", "scanner", "db", "report": <trivy json>}``."""
    p = cache_path(image, data_dir)
    if not p.exists():
        return None
    wrapper = json.loads(p.read_text(encoding="utf-8"))
    rep = parse_trivy(wrapper["report"], image=wrapper["image"])
    rep.meta = {"scanner": wrapper.get("scanner", {}), "db": wrapper.get("db", {})}
    return rep
