"""MITRE ATT&CK STIX 2.1 bundle parser.

Tactic names always come from the pinned bundle, never from code: ATT&CK v19 replaced
Defense Evasion with Stealth and Impair Defenses, and later releases may change more.
Revoked and deprecated objects are dropped (their IDs are kept in ``retired`` so
templates referencing them fail loudly).
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_MITRE_SOURCES = {"mitre-attack"}


@dataclass(frozen=True)
class Tactic:
    tactic_id: str  # TA0001
    shortname: str  # initial-access
    name: str


@dataclass(frozen=True)
class Technique:
    technique_id: str  # T1110 or T1110.001
    name: str
    tactics: tuple[str, ...]  # tactic shortnames
    platforms: tuple[str, ...]
    is_subtechnique: bool
    stix_id: str

    @property
    def parent_id(self) -> str | None:
        return self.technique_id.split(".")[0] if self.is_subtechnique else None


@dataclass
class AttackCatalog:
    version: str | None
    tactics: dict[str, Tactic] = field(default_factory=dict)  # by shortname
    techniques: dict[str, Technique] = field(default_factory=dict)  # by technique id
    retired: set[str] = field(default_factory=set)

    def for_platforms(self, platforms: Iterable[str]) -> dict[str, Technique]:
        wanted = set(platforms)
        return {tid: t for tid, t in self.techniques.items() if wanted.intersection(t.platforms)}

    def platforms(self) -> set[str]:
        return {p for t in self.techniques.values() for p in t.platforms}

    def get(self, technique_id: str) -> Technique:
        if technique_id in self.retired:
            raise KeyError(f"{technique_id} is revoked or deprecated in ATT&CK {self.version}")
        return self.techniques[technique_id]


def _external_id(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") in _MITRE_SOURCES and ref.get("external_id"):
            return str(ref["external_id"])
    return None


def parse_bundle(bundle: dict[str, Any]) -> AttackCatalog:
    if bundle.get("type") != "bundle":
        raise ValueError("not a STIX bundle")
    objects: list[dict[str, Any]] = bundle.get("objects", [])

    version: str | None = None
    for obj in objects:
        if obj.get("type") == "x-mitre-collection":
            version = obj.get("x_mitre_version")
            break

    catalog = AttackCatalog(version=version)
    for obj in objects:
        retired = bool(obj.get("revoked")) or bool(obj.get("x_mitre_deprecated"))
        ext = _external_id(obj)
        if obj.get("type") == "x-mitre-tactic" and ext and not retired:
            short = obj.get("x_mitre_shortname")
            if short:
                catalog.tactics[short] = Tactic(tactic_id=ext, shortname=short, name=obj.get("name", short))
        elif obj.get("type") == "attack-pattern" and ext:
            if retired:
                catalog.retired.add(ext)
                continue
            phases = tuple(
                p["phase_name"]
                for p in obj.get("kill_chain_phases", [])
                if p.get("kill_chain_name") == "mitre-attack" and p.get("phase_name")
            )
            catalog.techniques[ext] = Technique(
                technique_id=ext,
                name=obj.get("name", ext),
                tactics=phases,
                platforms=tuple(obj.get("x_mitre_platforms", [])),
                is_subtechnique=bool(obj.get("x_mitre_is_subtechnique", "." in ext)),
                stix_id=obj["id"],
            )
    catalog.retired -= set(catalog.techniques)  # an ID live in this bundle is not retired
    unknown = {t for tech in catalog.techniques.values() for t in tech.tactics} - set(catalog.tactics)
    if unknown:
        raise ValueError(f"techniques reference tactics missing from the bundle: {sorted(unknown)}")
    return catalog


def load(path: Path) -> AttackCatalog:
    return parse_bundle(json.loads(path.read_text(encoding="utf-8")))
