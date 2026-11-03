"""Loads the generator catalogs from ``configs/catalog/`` (documented assumptions in YAML)."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from iris.settings import repo_root


@dataclass(frozen=True)
class Catalog:
    archetypes: dict[str, Any]
    industries: dict[str, Any]
    sizes: dict[str, Any]
    maturity: dict[str, Any]
    timezones: list[str]
    calendar: dict[str, Any]
    recipes: dict[str, Any]
    role_services: dict[str, list[str]]
    role_dependencies: dict[str, list[str]]
    base_criticality: dict[str, int]
    os_profiles: dict[str, list[str]]
    weaknesses: dict[str, Any]
    first_names: list[str]
    last_names: list[str]
    versions: dict[str, str]
    live: dict[str, Any]


def _load(path: Path) -> dict[str, Any]:
    data: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data


@lru_cache(maxsize=4)
def load_catalog(root: Path | None = None) -> Catalog:
    base = root if root is not None else repo_root() / "configs" / "catalog"
    arch = _load(base / "archetypes.yaml")
    ind = _load(base / "industries.yaml")
    rec = _load(base / "recipes.yaml")
    wk = _load(base / "weaknesses.yaml")
    names = _load(base / "names.yaml")
    live = _load(base / "live.yaml")
    return Catalog(
        archetypes=arch["archetypes"],
        industries=ind["industries"],
        sizes=ind["sizes"],
        maturity=ind["maturity"],
        timezones=list(ind["timezones"]),
        calendar=ind["calendar"],
        recipes=rec["recipes"],
        role_services=rec["role_services"],
        role_dependencies=rec["role_dependencies"],
        base_criticality=rec["base_criticality"],
        os_profiles=rec["os_profiles"],
        weaknesses=wk["modules"],
        first_names=list(names["first"]),
        last_names=list(names["last"]),
        versions={
            "archetypes": arch["catalog_version"],
            "industries": ind["catalog_version"],
            "recipes": rec["catalog_version"],
            "weaknesses": wk["catalog_version"],
            "names": names["catalog_version"],
            "live": live["catalog_version"],
        },
        live=live,
    )
