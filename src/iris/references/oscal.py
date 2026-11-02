"""NIST OSCAL catalog parser (SP 800-53 Rev. 5): the spine of the internal control catalog.

Control IDs are normalised to the familiar form: ``ac-2`` -> ``AC-2``,
``ac-2.1`` -> ``AC-2(1)``. Withdrawn controls are kept separately.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_ID = re.compile(r"^([a-z]{2})-(\d+)(?:\.(\d+))?$")


def normalise_id(oscal_id: str) -> str:
    m = _ID.match(oscal_id)
    if not m:
        raise ValueError(f"unexpected OSCAL control id: {oscal_id}")
    family, number, enh = m.groups()
    return f"{family.upper()}-{int(number)}" + (f"({int(enh)})" if enh else "")


@dataclass(frozen=True)
class OscalControl:
    control_id: str  # AC-2 or AC-2(1)
    oscal_id: str
    title: str
    family: str  # AC
    family_title: str
    parent_id: str | None


@dataclass
class OscalCatalog:
    title: str
    version: str | None
    controls: dict[str, OscalControl] = field(default_factory=dict)
    withdrawn: set[str] = field(default_factory=set)

    def families(self) -> dict[str, str]:
        return {c.family: c.family_title for c in self.controls.values()}

    def base_controls(self) -> dict[str, OscalControl]:
        return {k: v for k, v in self.controls.items() if v.parent_id is None}


def _is_withdrawn(ctrl: dict[str, Any]) -> bool:
    return any(p.get("name") == "status" and p.get("value") == "withdrawn" for p in ctrl.get("props", []))


def _walk(
    ctrls: list[dict[str, Any]], family: str, family_title: str, parent: str | None
) -> Iterator[tuple[dict[str, Any], str, str, str | None]]:
    for ctrl in ctrls:
        yield ctrl, family, family_title, parent
        yield from _walk(ctrl.get("controls", []), family, family_title, normalise_id(ctrl["id"]))


def parse_catalog(doc: dict[str, Any]) -> OscalCatalog:
    cat = doc.get("catalog")
    if not isinstance(cat, dict):
        raise ValueError("not an OSCAL catalog document")
    meta = cat.get("metadata", {})
    out = OscalCatalog(title=meta.get("title", ""), version=meta.get("version"))
    for group in cat.get("groups", []):
        family = str(group.get("id", "")).upper()
        for ctrl, fam, fam_title, parent in _walk(
            group.get("controls", []), family, group.get("title", ""), None
        ):
            cid = normalise_id(ctrl["id"])
            if _is_withdrawn(ctrl):
                out.withdrawn.add(cid)
                continue
            out.controls[cid] = OscalControl(
                control_id=cid,
                oscal_id=ctrl["id"],
                title=ctrl.get("title", ""),
                family=fam,
                family_title=fam_title,
                parent_id=parent,
            )
    return out


def load(path: Path) -> OscalCatalog:
    return parse_catalog(json.loads(path.read_text(encoding="utf-8")))
