"""CycloneDX 1.6 SBOM per asset, built from the cached scan (deterministic bytes)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from iris.core.hashing import sha256_hex
from iris.core.vclock import iso_z
from iris.generator.posture.trivy import ImageReport

CDX_SPEC = "1.6"


def _ref(name: str, version: str, purl: str | None) -> str:
    return purl or f"{name}@{version}"


def cyclonedx(
    asset_id: str, hostname: str, report: ImageReport, at: datetime, scanner_version: str
) -> dict[str, Any]:
    serial = uuid.UUID(hex=sha256_hex(f"sbom|{asset_id}|{report.image_id}|{iso_z(at)}")[:32], version=4)
    components: list[dict[str, Any]] = []
    deps: list[dict[str, Any]] = []
    seen: set[str] = set()
    for p in sorted(report.packages, key=lambda p: (p.kind, p.name, p.version)):
        ref = _ref(p.name, p.version, p.purl)
        if ref in seen:
            continue
        seen.add(ref)
        comp: dict[str, Any] = {"type": "library", "bom-ref": ref, "name": p.name, "version": p.version}
        if p.purl:
            comp["purl"] = p.purl
        components.append(comp)
        if p.depends_on:
            deps.append({"ref": ref, "dependsOn": sorted(set(p.depends_on))})
    if report.os_family:
        components.insert(
            0,
            {
                "type": "operating-system",
                "bom-ref": f"os:{report.os_family}@{report.os_name}",
                "name": report.os_family,
                "version": report.os_name or "",
            },
        )
    return {
        "bomFormat": "CycloneDX",
        "specVersion": CDX_SPEC,
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": iso_z(at),
            "tools": {"components": [{"type": "application", "name": "trivy", "version": scanner_version}]},
            "component": {"type": "device", "bom-ref": asset_id, "name": hostname},
        },
        "components": components,
        "dependencies": deps,
    }
