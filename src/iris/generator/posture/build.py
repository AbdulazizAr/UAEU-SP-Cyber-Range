"""Scenario posture: who gets scanned when, what the scanner saw, and what intel said then.

Reality ties to GRC. The real state of CTRL-VUL-001 (vulnerability scanning) sets the
scanner cadence and coverage, and "missing" means there is no scanner at all.
CTRL-INV-002 (software inventory) decides which assets have an SBOM. The CVEs are the
real ones in our images, from cached Trivy reports. This module only decides which of
them are visible at a given virtual time.

No future leakage: a finding at scan time S lists only CVEs published on or before S.
Enrichment at as-of T uses only KEV entries added by T and the latest EPSS snapshot
on or before T. A CVE with no publication date is left out.
"""

from __future__ import annotations

import fnmatch
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, time, timedelta
from typing import Any

from iris.contracts.common import AssetRole
from iris.contracts.spec import AssetSpec, ScenarioSpec
from iris.contracts.visible import Component, CveEnrichment, ScannerFinding
from iris.core.seeds import SeedSet
from iris.core.vclock import iso_z
from iris.generator.catalog import load_catalog
from iris.generator.compiler import asset_images
from iris.generator.grc.recorded import GrcBundle
from iris.generator.posture.sbom import cyclonedx
from iris.generator.posture.trivy import ImageReport, Vuln
from iris.references.intel import Intel

POSTURE_VERSION = "posture-0.1.0"
SCANNER_PROFILE = {"implemented": (7, 0.95), "partial": (30, 0.60)}  # cadence days, asset coverage
SBOM_COVERAGE = {"implemented": 1.0, "partial": 0.5, "missing": 0.0}
NOT_SCANNED = {AssetRole.ROUTER_FIREWALL, AssetRole.IDS_SENSOR}  # appliances: out of Trivy's scope
LINKED_CONTROLS = ("CTRL-INV-002", "CTRL-VUL-001", "CTRL-VUL-002")
APPROXIMATIONS = [
    "fixed_version and CVSS come from the pinned Trivy DB and may postdate the scan (no history)",
    "package versions are those of the built image, not of a dated distribution snapshot",
]


class MissingScans(RuntimeError):
    def __init__(self, images: list[str]) -> None:
        self.images = images
        super().__init__(
            f"{len(images)} image(s) have no cached scan; run `iris posture scan` for: " + ", ".join(images)
        )


@dataclass
class PostureBundle:
    components: list[Component]
    findings: list[ScannerFinding]
    enrichment: list[CveEnrichment]
    sboms: dict[str, dict[str, Any]]
    reality: dict[str, Any]
    meta: dict[str, Any]
    episodes: list[tuple[str, datetime]]
    scans_at: dict[str, dict[str, datetime]] = field(default_factory=dict)  # episode -> asset -> scan time

    def asof(self, eid: str) -> dict[str, Any]:
        """Posture files as seen at the start of one episode."""
        at = dict(self.episodes)[eid]
        latest = self.scans_at.get(eid, {})
        return {
            "posture/scanner_findings.jsonl": [
                f.model_dump(mode="json") for f in self.findings if latest.get(f.asset_id) == f.timestamp
            ],
            "posture/cve_enrichment.jsonl": [
                e.model_dump(mode="json") for e in self.enrichment if e.as_of == at
            ],
        }

    def visible(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "enterprise/components.json": [c.model_dump(mode="json") for c in self.components],
            "posture/scanner_findings.jsonl": [f.model_dump(mode="json") for f in self.findings],
            "posture/cve_enrichment.jsonl": [e.model_dump(mode="json") for e in self.enrichment],
        }
        for aid, bom in sorted(self.sboms.items()):
            out[f"posture/sbom/{aid}.cdx.json"] = bom
        return out

    def hidden(self) -> dict[str, Any]:
        return {"truth/posture_reality.json": self.reality}


def _state(bundle: GrcBundle, cid: str) -> str:
    c = bundle.reality.controls.get(cid)
    return c.state if c else "missing"


def _code(asset_id: str) -> str:
    _, role, num = asset_id.split("-")
    return f"{role}{num}"


def _exposure(a: AssetSpec, mgmt_zones: set[str]) -> str:
    if a.internet_exposed:
        return "internet"
    if any(att.zone in mgmt_zones for att in a.attachments):
        return "restricted"
    return "internal"


def _visible(v: Vuln, at: datetime) -> bool:
    return v.published_at is not None and v.published_at <= at


def build_posture(
    spec: ScenarioSpec,
    bundle: GrcBundle,
    reports: Mapping[str, ImageReport],
    intel: Intel,
    episodes: list[tuple[str, datetime]],
    seeds: SeedSet | None = None,
    scanner_version: str = "unknown",
    db_meta: Mapping[str, Any] | None = None,
) -> PostureBundle:
    seeds = seeds or SeedSet.from_dict(spec.seeds.model_dump())
    start, end = bundle.reality.calendar_start, bundle.reality.calendar_end
    images = asset_images(spec)
    scope = [a for a in spec.assets if a.role not in NOT_SCANNED]
    missing = sorted({images[a.asset_id] for a in scope if images[a.asset_id] not in reports})
    if missing:
        raise MissingScans(missing)
    rep = {a.asset_id: reports[images[a.asset_id]] for a in scope}

    # ---- scanner reality from CTRL-VUL-001
    vul_state, inv_state = _state(bundle, "CTRL-VUL-001"), _state(bundle, "CTRL-INV-002")
    rng = seeds.stream("monitoring", "scanner")
    scan_times: dict[str, list[datetime]] = {}
    cadence: int | None = None
    if vul_state in SCANNER_PROFILE and scope:
        cadence, coverage = SCANNER_PROFILE[vul_state]
        scanned = [a for a in scope if rng.random() < coverage] or [rng.choice(scope)]
        first = datetime.combine(
            (start - timedelta(days=rng.randint(1, cadence))).date(), time(1), start.tzinfo
        )
        first += timedelta(minutes=rng.randint(0, 180))
        runs: list[datetime] = []
        t = first
        while t < end:
            runs.append(t)
            t += timedelta(days=cadence)
        offsets = {a.asset_id: timedelta(minutes=i * rng.randint(2, 9)) for i, a in enumerate(scanned)}
        scan_times = {aid: [r + off for r in runs] for aid, off in offsets.items()}

    # ---- the scans that matter: the latest per asset before each episode start
    scans_at: dict[str, dict[str, datetime]] = {}
    for eid, at in episodes:
        latest = {
            aid: max((ts for ts in times if ts <= at), default=None) for aid, times in scan_times.items()
        }
        scans_at[eid] = {aid: ts for aid, ts in latest.items() if ts is not None}
    emitted = sorted({(ts, aid) for per in scans_at.values() for aid, ts in per.items()})

    findings: list[ScannerFinding] = []
    future_hidden = undated = 0
    for ts, aid in emitted:
        r = rep[aid]
        for v in sorted(r.vulns, key=lambda v: (v.cve_id, v.pkg_name, v.installed_version)):
            if not _visible(v, ts):
                if v.published_at is None:
                    undated += 1
                else:
                    future_hidden += 1
                continue
            findings.append(
                ScannerFinding(
                    finding_id=f"FND-{len(findings) + 1:05d}",
                    asset_id=aid,
                    scanner="trivy",
                    scanner_version=scanner_version,
                    timestamp=ts,
                    finding_type="cve",
                    cve=v.cve_id,
                    package=v.pkg_name,
                    installed_version=v.installed_version,
                    fixed_version=v.fixed_version,
                    severity=v.severity,
                    cvss=v.cvss,
                    fix_available=v.fixed_version is not None,
                    evidence=f"{v.kind} package {v.pkg_name} {v.installed_version} "
                    f"({v.status or 'affected'})",
                )
            )

    # ---- enrichment as of each episode start
    vinfo: dict[str, Vuln] = {}
    for r in rep.values():
        for v in r.vulns:
            vinfo.setdefault(v.cve_id, v)
    enrichment: list[CveEnrichment] = []
    for eid, at in episodes:
        seen = scans_at.get(eid, {})
        cves = sorted({f.cve for f in findings if f.cve and seen.get(f.asset_id) == f.timestamp})
        snap = intel.epss_snapshot_at(at)
        for cve in cves:
            v = vinfo[cve]
            kev = intel.kev_at(cve, at)
            epss = snap.scores.get(cve) if snap else None
            sources = ["trivy-db", "cisa-kev"] + (["first-epss"] if epss else [])
            enrichment.append(
                CveEnrichment(
                    cve_id=cve,
                    cvss=v.cvss,
                    cvss_version=v.cvss_version,
                    severity=v.severity,
                    epss=epss[0] if epss else None,
                    epss_percentile=epss[1] if epss else None,
                    kev_listed=kev is not None,
                    kev_date_added=kev.date_added if kev else None,
                    published_at=v.published_at,
                    modified_at=v.modified_at if v.modified_at and v.modified_at <= at else None,
                    source="+".join(sources),
                    as_of=at,
                )
            )

    # ---- SBOMs from CTRL-INV-002
    srng = seeds.stream("monitoring", "sbom")
    share = SBOM_COVERAGE.get(inv_state, 0.0)
    sbom_at = datetime.combine((start - timedelta(days=srng.randint(1, 30))).date(), time(3), start.tzinfo)
    sboms = {
        a.asset_id: cyclonedx(a.asset_id, a.hostname, rep[a.asset_id], sbom_at, scanner_version)
        for a in scope
        if srng.random() < share
    }

    components = _components(
        spec, bundle, rep, findings, scans_at.get(episodes[0][0], {}) if episodes else {}
    )

    reality = {
        "version": POSTURE_VERSION,
        "scanner": {
            "control_state": vul_state,
            "cadence_days": cadence,
            "scanned_assets": sorted(scan_times),
            "unscanned_assets": sorted(a.asset_id for a in scope if a.asset_id not in scan_times),
        },
        "sbom": {"control_state": inv_state, "assets": sorted(sboms)},
        "assets": {
            aid: {
                "image": images[aid],
                "image_id": r.image_id,
                "cves_total": len({v.cve_id for v in r.vulns}),
                "cves_published_by_end": len({v.cve_id for v in r.vulns if _visible(v, end)}),
                "cves_undated": len({v.cve_id for v in r.vulns if v.published_at is None}),
                "non_cve_advisories": r.skipped_ids,
            }
            for aid, r in sorted(rep.items())
        },
        "hidden_by_date_gate": {"not_yet_published": future_hidden, "undated": undated},
        "approximations": APPROXIMATIONS,
    }
    db = dict(db_meta or {})
    meta = {
        "tool_versions": {"trivy": scanner_version, "trivy_db_date": db.get("updated_at")},
        "enrichment_as_of": {"nvd": "date-gated", "kev": "date-gated", "epss": "date-gated or absent"},
        "epss_snapshots": [
            iso_z(datetime.combine(s.snapshot_date, time(0), start.tzinfo)) for s in intel.epss
        ],
    }
    return PostureBundle(
        components=components,
        findings=findings,
        enrichment=enrichment,
        sboms=sboms,
        reality=reality,
        meta=meta,
        episodes=episodes,
        scans_at=scans_at,
    )


def _components(
    spec: ScenarioSpec,
    bundle: GrcBundle,
    rep: Mapping[str, ImageReport],
    findings: list[ScannerFinding],
    first_scan: Mapping[str, datetime],
) -> list[Component]:
    """One component per service plus a base-system component per recorded asset.

    Finding links use the scan visible at the first episode, so nothing comes from later.
    """
    cat = load_catalog()
    mgmt = {z.name for z in spec.zones if z.kind.value == "mgmt"}
    recorded = {a.asset_id for a in bundle.assets}
    controls = {c.control_id: c for c in bundle.controls}
    by_id = {a.asset_id: a for a in spec.assets}
    out: list[Component] = []
    for aid in sorted(recorded & set(rep)):
        a, r = by_id[aid], rep[aid]
        fnd = [f for f in findings if f.asset_id == aid and first_scan.get(aid) == f.timestamp]
        ctrl = [cid for cid in LINKED_CONTROLS if cid in controls and aid in controls[cid].applies_to_assets]
        claimed: set[str] = set()
        k = 0
        for s in sorted((s for s in spec.services if s.asset_id == aid), key=lambda s: s.service_id):
            patterns = cat.recipes[s.recipe].get("packages", [])
            pk = [
                p
                for p in r.packages
                if any(
                    fnmatch.fnmatch((n or "").lower(), pat) for pat in patterns for n in (p.name, p.src_name)
                )
            ]
            names = {p.name for p in pk}
            mine = [f.finding_id for f in fnd if f.package in names and f.finding_id not in claimed]
            claimed |= set(mine)
            k += 1
            out.append(
                Component(
                    component_id=f"CMP-{_code(aid)}-{k:03d}",
                    asset_id=aid,
                    service_id=s.service_id,
                    component_type=str(cat.recipes[s.recipe]["category"]),
                    name=s.recipe,
                    version=s.version,
                    exposure=_exposure(a, mgmt),
                    linked_package_refs=sorted({p.purl for p in pk if p.purl}),
                    linked_finding_ids=mine,
                    linked_control_ids=ctrl,
                )
            )
        k += 1
        out.append(
            Component(
                component_id=f"CMP-{_code(aid)}-{k:03d}",
                asset_id=aid,
                component_type="base_system",
                name=r.os_family or "base",
                version=r.os_name,
                exposure=_exposure(a, mgmt),
                linked_finding_ids=[f.finding_id for f in fnd if f.finding_id not in claimed],
                linked_control_ids=ctrl,
            )
        )
    return out
