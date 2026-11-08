"""Synthetic posture: SBOM, scanner findings and dated CVE enrichment (builder brief file 03).

One software state, two views: the SBOM and (later) syscollector list the same packages.
Scanner findings are the join ``SBOM ⨝ cve_seed`` evaluated at the scan time, with real
imperfections (distro-backport false positives, coverage gaps). Everything is date-gated:
at virtual time T only CVEs published on or before T are visible, so a package can be
vulnerable yet invisible until its CVE is published — the Engine sees vulnerabilities appear
over time. A finding is presence, never proof of exploitation (contract §7).

No CVE ID, score, date or fixed version is invented: findings come only from the pinned
``cve_seed.yaml`` (brief file 03 §3 option B), and each carries its ``source`` and
``review_status`` so nothing unverified is presented as validated.
"""

from __future__ import annotations

import random
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from iris.core.hashing import sha256_hex
from iris.core.vclock import iso_z
from iris.synth.catalogs import (
    CveCatalog,
    CveEntry,
    Package,
    SoftwareCatalog,
    load_cves,
    load_software,
    version_lt,
)
from iris.synth.seeds import SynthSeeds
from iris.synth.world import World

POSTURE_VERSION = "synth-posture-0.1.0"
SCANNER = "trivy"
SCANNER_VERSION = "0.76.1"
CDX_SPEC = "1.6"

# CTRL-VUL-001 true state -> (fraction of in-scope assets scanned, backport-FP rate).
_SCAN_COVERAGE = {"implemented": 0.95, "partial": 0.60, "missing": 0.0}
_BACKPORT_FP = {
    "debian-12": 0.06,
    "ubuntu-22.04": 0.05,
    "ubuntu-24.04": 0.04,
    "rocky-9": 0.05,
    "alma-9": 0.05,
}


@dataclass
class InstalledPackage:
    package: Package
    version: str


@dataclass
class SynthPosture:
    scanner_findings: list[dict[str, Any]]
    cve_enrichment_by_episode: dict[str, list[dict[str, Any]]]
    sboms: dict[str, dict[str, Any]]  # asset_id -> CycloneDX
    installed: dict[str, list[InstalledPackage]]
    scanned_assets: list[str]
    reality_metrics: dict[str, Any]
    fp_ledger: list[dict[str, Any]] = field(default_factory=list)

    def visible(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "posture/scanner_findings.jsonl": self.scanner_findings,
            "posture/cve_enrichment.jsonl": self._all_enrichment(),
        }
        for aid, sbom in self.sboms.items():
            out[f"posture/sbom/{aid}.cdx.json"] = sbom
        return out

    def _all_enrichment(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for eid in sorted(self.cve_enrichment_by_episode):
            rows.extend(self.cve_enrichment_by_episode[eid])
        return rows

    def asof(self, episode_id: str) -> dict[str, Any]:
        return {"posture": {"cve_enrichment": self.cve_enrichment_by_episode.get(episode_id, [])}}

    def hidden(self) -> dict[str, Any]:
        return {
            "posture/posture_reality.json": {
                "version": POSTURE_VERSION,
                "scanned_assets": sorted(self.scanned_assets),
                "false_positive_ledger": self.fp_ledger,
                "known_approximations": [
                    "SBOM pads the package count with labelled synthetic filler components",
                    "CVE seed catalog is hand-curated (option B); verify against an NVD/Trivy snapshot",
                    "version comparison is a simplified comparator, not full dpkg/rpm vercmp",
                ],
            },
            "truth/reality_metrics.json": self.reality_metrics,
        }


def _installed_version(pkg: Package, maturity: str, software: SoftwareCatalog, rng: random.Random) -> str:
    floor = software.patch_floor.get(maturity, 0.5)
    n = len(pkg.versions)
    idx = round(floor * (n - 1)) + rng.choice([-1, 0, 0, 1])
    return pkg.versions[min(n - 1, max(0, idx))]


def _asset_packages(
    world: World, asset_id: str, software: SoftwareCatalog, syn: SynthSeeds
) -> list[InstalledPackage]:
    asset = world.assets[asset_id]
    os_profile = asset.os_profile
    recipes = {s.recipe for s in world.services_by_asset.get(asset_id, [])}
    maturity = world.spec.organization.maturity.value
    out: list[InstalledPackage] = []
    for p in software.for_os(os_profile):
        if p.recipe is not None and p.recipe not in recipes:
            continue
        rng = syn.rng("telemetry", "pkgver", asset_id, p.id)
        out.append(InstalledPackage(p, _installed_version(p, maturity, software, rng)))
    return out


def _purl(software: SoftwareCatalog, os_profile: str, name: str, version: str) -> str:
    ptype = software.purl_type.get(os_profile, "generic")
    distro = os_profile.replace("-", "")
    return f"pkg:{ptype}/{distro}/{name}@{version}"


def _sbom(
    world: World, asset_id: str, pkgs: list[InstalledPackage], software: SoftwareCatalog, at: datetime
) -> dict[str, Any]:
    asset = world.assets[asset_id]
    os_profile = asset.os_profile
    serial = uuid.UUID(hex=sha256_hex(f"sbom|{asset_id}|{iso_z(at)}")[:32], version=4)
    components: list[dict[str, Any]] = [
        {
            "type": "operating-system",
            "bom-ref": f"os:{os_profile}",
            "name": os_profile.split("-")[0],
            "version": os_profile.split("-", 1)[1] if "-" in os_profile else "",
        }
    ]
    for ip in sorted(pkgs, key=lambda x: x.package.purl_name):
        purl = _purl(software, os_profile, ip.package.purl_name, ip.version)
        components.append(
            {
                "type": "library",
                "bom-ref": purl,
                "name": ip.package.purl_name,
                "version": ip.version,
                "purl": purl,
                "properties": [{"name": "iris:synthetic_hash", "value": "true"}],
            }
        )
    # pad to a plausible count with clearly-labelled synthetic filler (brief file 03 §2)
    target = software.os_base_count.get(os_profile, 150)
    for i in range(len(components), target):
        components.append(
            {
                "type": "library",
                "bom-ref": f"synthetic-base:{os_profile}:{i:04d}",
                "name": f"base-component-{i:04d}",
                "version": "0",
                "properties": [{"name": "iris:synthetic_filler", "value": "true"}],
            }
        )
    return {
        "bomFormat": "CycloneDX",
        "specVersion": CDX_SPEC,
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": iso_z(at),
            "tools": {"components": [{"type": "application", "name": SCANNER, "version": SCANNER_VERSION}]},
            "component": {"type": "device", "bom-ref": asset_id, "name": asset.hostname},
        },
        "components": components,
    }


def _finding_id(asset_id: str, cve: str, version: str) -> str:
    return "FND-" + str(int(sha256_hex(f"{asset_id}|{cve}|{version}")[:8], 16) % 100000).zfill(5)


def build_posture(
    world: World,
    seeds_bundle: SynthSeeds,
    episodes: list[tuple[str, datetime]],
) -> SynthPosture:
    software = load_software()
    cves: CveCatalog = load_cves()
    vul_state = (
        world.reality.controls["CTRL-VUL-001"].state
        if "CTRL-VUL-001" in world.reality.controls
        else "partial"
    )
    coverage = _SCAN_COVERAGE.get(vul_state, 0.6)
    first_ep = min((at for _, at in episodes), default=world.reality.calendar_start)
    scan_time = first_ep - timedelta(hours=6)

    sboms: dict[str, dict[str, Any]] = {}
    installed: dict[str, list[InstalledPackage]] = {}
    findings: list[dict[str, Any]] = []
    scanned: list[str] = []
    fp_ledger: list[dict[str, Any]] = []

    server_like = {s.asset_id for s in world.spec.services}
    for asset_id in sorted(world.assets):
        asset = world.assets[asset_id]
        if asset_id not in server_like:
            continue  # Trivy scope is service-bearing hosts (routers/sensors out of scope)
        pkgs = _asset_packages(world, asset_id, software, seeds_bundle)
        installed[asset_id] = pkgs
        sboms[asset_id] = _sbom(world, asset_id, pkgs, software, scan_time)
        cov_rng = seeds_bundle.rng("sensor", "scan_coverage", asset_id)
        if cov_rng.random() >= coverage:
            continue  # coverage gap: asset never scanned
        scanned.append(asset_id)
        for ip in pkgs:
            for cve in cves.for_package(ip.package.id):
                if cve.published_at > scan_time.date():
                    continue  # date gate: CVE not yet public at scan time
                vulnerable = version_lt(ip.version, cve.fixed_version)
                fp_rng = seeds_bundle.rng("sensor", "backport_fp", asset_id, cve.cve_id)
                backport = (not vulnerable) and fp_rng.random() < _BACKPORT_FP.get(asset.os_profile, 0.05)
                if not vulnerable and not backport:
                    continue
                evidence = "installed version precedes fixed version"
                if backport:
                    evidence = "flagged by scanner; may be a distro backport (possible false positive)"
                    fp_ledger.append({"asset_id": asset_id, "cve": cve.cve_id, "reason": "backport_fp"})
                findings.append(
                    {
                        "finding_id": _finding_id(asset_id, cve.cve_id, ip.version),
                        "asset_id": asset_id,
                        "scanner": SCANNER,
                        "scanner_version": SCANNER_VERSION,
                        "timestamp": iso_z(scan_time),
                        "finding_type": "cve",
                        "cve": cve.cve_id,
                        "package": ip.package.purl_name,
                        "installed_version": ip.version,
                        "fixed_version": cve.fixed_version,
                        "severity": cve.severity or "UNKNOWN",
                        "cvss": cve.cvss,
                        "fix_available": True,
                        "evidence": evidence,
                    }
                )

    enrichment = _enrichment_by_episode(findings, cves, episodes)
    metrics = _reality_metrics(world, installed, software)
    return SynthPosture(
        scanner_findings=sorted(findings, key=lambda f: (f["asset_id"], f["cve"])),
        cve_enrichment_by_episode=enrichment,
        sboms=sboms,
        installed=installed,
        scanned_assets=scanned,
        reality_metrics=metrics,
        fp_ledger=fp_ledger,
    )


def _enrichment_by_episode(
    findings: list[dict[str, Any]], cves: CveCatalog, episodes: list[tuple[str, datetime]]
) -> dict[str, list[dict[str, Any]]]:
    """One date-gated enrichment row per CVE present in findings, per episode (as_of = start)."""
    present = sorted({f["cve"] for f in findings})
    out: dict[str, list[dict[str, Any]]] = {}
    for eid, as_of in episodes:
        rows: list[dict[str, Any]] = []
        for cid in present:
            e: CveEntry = cves.by_id[cid]
            if e.published_at > as_of.date():
                continue
            kev = e.kev_listed and e.kev_date_added is not None and e.kev_date_added <= as_of.date()
            rows.append(
                {
                    "cve_id": e.cve_id,
                    "cvss": e.cvss,
                    "cvss_version": e.cvss_version,
                    "severity": e.severity,
                    "epss": e.epss if (e.epss_date and e.epss_date <= as_of.date()) else None,
                    "epss_percentile": None,
                    "kev_listed": kev,
                    "kev_date_added": e.kev_date_added.isoformat() if kev and e.kev_date_added else None,
                    "published_at": iso_z(
                        datetime.combine(e.published_at, datetime.min.time()).replace(tzinfo=as_of.tzinfo)
                    ),
                    "modified_at": None,
                    "source": e.source,
                    "as_of": iso_z(as_of),
                }
            )
        out[eid] = rows
    return out


def _reality_metrics(
    world: World, installed: dict[str, list[InstalledPackage]], software: SoftwareCatalog
) -> dict[str, Any]:
    """Hidden maturity/posture metrics (brief file 03 §6), for D7 later."""
    maturity = world.spec.organization.maturity.value
    agents = sum(world.is_monitored(a) for a in world.assets)
    exposed = sum(1 for a in world.spec.assets if a.internet_exposed)
    mfa_identities = [i for i in world.spec.identities if i.kind == "human"]
    mfa_cov = sum(i.mfa_enforced for i in mfa_identities) / max(1, len(mfa_identities))
    return {
        "version": POSTURE_VERSION,
        "maturity_tier_input": maturity,
        "agent_coverage": round(agents / max(1, len(world.assets)), 4),
        "internet_exposed_services": exposed,
        "mfa_coverage_human": round(mfa_cov, 4),
        "patch_floor": software.patch_floor.get(maturity),
        "scanned_asset_count": len(installed),
    }
