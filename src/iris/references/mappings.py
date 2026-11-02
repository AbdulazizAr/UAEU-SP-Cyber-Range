"""CTID Mappings Explorer parser (security control -> ATT&CK technique).

The CTID NIST 800-53 mappings target an older ATT&CK version than our pin, so
:func:`check_against_attack` reports every technique that is unknown or retired in
the pinned ATT&CK release. Those links must be reviewed before use (provenance
"official" stays, review_status becomes "needs_review").
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from iris.references.attack import AttackCatalog
from iris.references.oscal import normalise_id

_NON_MAPPING = {"non_mappable", "non-mappable"}


@dataclass(frozen=True)
class ControlTechniqueLink:
    control_id: str  # normalised, e.g. AC-2(1)
    technique_id: str
    mapping_type: str  # e.g. mitigates, protects


@dataclass
class MappingSet:
    framework: str | None
    attack_version: str | None
    links: list[ControlTechniqueLink] = field(default_factory=list)

    def techniques_for(self, control_id: str) -> set[str]:
        return {link.technique_id for link in self.links if link.control_id == control_id}

    def controls_for(self, technique_id: str) -> set[str]:
        return {link.control_id for link in self.links if link.technique_id == technique_id}


def _norm_control(raw: str) -> str:
    raw = raw.strip()
    try:
        return normalise_id(raw.lower().replace("(", ".").replace(")", ""))
    except ValueError:
        return raw.upper()


def parse(doc: dict[str, Any]) -> MappingSet:
    meta = doc.get("metadata", {})
    out = MappingSet(
        framework=meta.get("mapping_framework") or meta.get("technology_domain"),
        attack_version=str(meta["attack_version"]) if meta.get("attack_version") else None,
    )
    for obj in doc.get("mapping_objects", []):
        status = str(obj.get("status", "")).lower()
        mtype = str(obj.get("mapping_type", "")).lower()
        cap, tech = obj.get("capability_id"), obj.get("attack_object_id")
        if not cap or not tech or status in _NON_MAPPING or mtype in _NON_MAPPING:
            continue
        out.links.append(ControlTechniqueLink(_norm_control(str(cap)), str(tech), mtype or "mitigates"))
    return out


def load(path: Path) -> MappingSet:
    return parse(json.loads(path.read_text(encoding="utf-8")))


@dataclass(frozen=True)
class VersionGapReport:
    mapping_attack_version: str | None
    pinned_attack_version: str | None
    unknown: tuple[str, ...]
    retired: tuple[str, ...]

    @property
    def clean(self) -> bool:
        return not self.unknown and not self.retired


def check_against_attack(mappings: MappingSet, attack: AttackCatalog) -> VersionGapReport:
    techs = {link.technique_id for link in mappings.links}
    retired = sorted(t for t in techs if t in attack.retired)
    unknown = sorted(t for t in techs if t not in attack.techniques and t not in attack.retired)
    return VersionGapReport(mappings.attack_version, attack.version, tuple(unknown), tuple(retired))
