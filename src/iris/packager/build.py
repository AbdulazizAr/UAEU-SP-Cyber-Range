"""Assemble and write a scenario package (INPUT Part 5; IRIS Input Agreement v2.0, section 3).

Layout::

    scenario-<scenario_id>/
      visible/   manifest.visible.json + Engine input (read-only mount)
      hidden/    manifest.json + recipe/, truth/, evaluation_key/, posture/generated_weaknesses.json

v0 packages are *context* packages: enterprise, GRC, timeline, as-of snapshots and,
when scans are cached, posture. Telemetry and episode bundles join with the live range
and the composer (P6, part 2). ``enabled_sensors`` is empty until then.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, time, timedelta
from pathlib import Path
from typing import Any

from iris import CONTRACT_SCHEMA_VERSION, GENERATOR_MAJOR, SPEC_VERSION, __version__
from iris.contracts.spec import ScenarioSpec
from iris.contracts.visible import EpisodeRef, VirtualCalendar, VisibleManifest
from iris.core.hashing import episode_id, merkle_root, package_id, sha256_hex
from iris.core.seeds import SeedSet
from iris.core.vclock import iso_z, provenance_utc_now
from iris.generator.catalog import load_catalog
from iris.generator.enterprise import visible_files as enterprise_files
from iris.generator.grc.reality import GRC_FORMULA_VERSION
from iris.generator.grc.recorded import MAPPING_VERSION, RUBRIC_VERSION, build_grc
from iris.generator.grc.timeline import TIMELINE_VERSION, build_timeline
from iris.generator.posture.build import POSTURE_VERSION, build_posture
from iris.generator.posture.trivy import ImageReport
from iris.generator.sampler import SampleOverrides, sample_spec
from iris.generator.soc import SOC_VERSION, belief_gaps, build_soc, soc_inventory
from iris.oracle.d6 import D6_KEY_VERSION, build_d6_key
from iris.references.intel import Intel

PACKAGE_FORMAT = "pkg-0.1.0"
VISIBLE_MANIFEST = "manifest.visible.json"
HIDDEN_MANIFEST = "manifest.json"


@dataclass
class PackageOptions:
    """Tier and contents flags for the package manifests. The default is a v0 *context*
    package (no telemetry); the composer and the live recorder override these."""

    data_tier: str = "context"  # context | train | gold | SYN
    telemetry: bool = False
    episode_bundles: bool = False
    enabled_sensors: tuple[str, ...] = ()
    extra_versions: dict[str, str] = field(default_factory=dict)
    schema_version: str = "2.0.0"  # synth packages set "2.1.0"
    extra_hidden_manifest: dict[str, Any] = field(default_factory=dict)  # e.g. noise_profile (hidden only)


def json_default(o: Any) -> Any:
    if isinstance(o, datetime):
        return iso_z(o)
    if isinstance(o, date):
        return o.isoformat()
    if isinstance(o, (set, frozenset, tuple)):
        return list(o)
    raise TypeError(f"not JSON serialisable: {type(o).__name__}")


def encode(rel: str, content: Any) -> bytes:
    """Deterministic bytes: JSON Lines for ``.jsonl``, indented JSON otherwise."""
    if rel.endswith(".jsonl"):
        text = "".join(json.dumps(row, default=json_default, ensure_ascii=False) + "\n" for row in content)
    else:
        text = json.dumps(content, indent=2, default=json_default, ensure_ascii=False) + "\n"
    return text.encode("utf-8")


def record_count(rel: str, content: Any) -> int | None:
    if isinstance(content, list):
        return len(content)
    return None


@dataclass
class Assembled:
    scenario_id: str
    spec: ScenarioSpec
    seeds: SeedSet
    visible: dict[str, Any]
    hidden: dict[str, Any]
    meta: dict[str, Any]


def assemble(
    seeds: SeedSet,
    overrides: SampleOverrides | None = None,
    spec: ScenarioSpec | None = None,
    reports: Mapping[str, ImageReport] | None = None,
    intel: Intel | None = None,
    scanner_version: str = "unknown",
    db_meta: Mapping[str, Any] | None = None,
) -> Assembled:
    spec = spec or sample_spec(seeds, overrides)
    grc = build_grc(spec, seeds)
    tl = build_timeline(spec, grc, seeds)
    visible: dict[str, Any] = enterprise_files(spec, grc) | grc.visible() | tl.visible()
    hidden: dict[str, Any] = grc.hidden() | tl.hidden()
    meta: dict[str, Any] = {"tool_versions": {}, "enrichment_as_of": {}, "posture": False}
    if reports is not None and intel is not None:
        p = build_posture(spec, grc, reports, intel, tl.episodes, seeds, scanner_version, db_meta)
        visible |= p.visible()
        for eid, _ in tl.episodes:
            visible[f"snapshots/asof/{eid}.json"] = visible[f"snapshots/asof/{eid}.json"] | p.asof(eid)
        hidden |= p.hidden()
        meta = {
            "tool_versions": {k: str(v) for k, v in p.meta["tool_versions"].items() if v},
            "enrichment_as_of": p.meta["enrichment_as_of"],
            "posture": True,
            "epss_snapshots": p.meta["epss_snapshots"],
        }
    soc = build_soc(spec, grc.reality, seeds)
    recorded = {c.control_id: c.implementation_state for c in grc.controls}
    visible["soc/soc_inventory.json"] = soc_inventory(spec, soc, recorded).model_dump(mode="json")
    hidden["truth/soc_profile.json"] = soc.to_dict()
    hidden["truth/soc_gap_ledger.jsonl"] = [asdict(g) for g in belief_gaps(soc, recorded)]
    for eid, key in build_d6_key(spec, grc, tl).items():
        hidden[f"evaluation_key/d6/{eid}.json"] = key
    hidden["posture/generated_weaknesses.json"] = [w.model_dump(mode="json") for w in spec.weaknesses]
    hidden["recipe/seeds.json"] = seeds.to_dict()
    hidden["recipe/spec.json"] = spec.model_dump(mode="json")
    return Assembled(tl.scenario_id, spec, seeds, visible, hidden, meta)


@dataclass
class PackageResult:
    root: Path
    scenario_id: str
    package_id: str
    merkle_root: str
    visible_files: int
    hidden_files: int


def _write(base: Path, files: Mapping[str, Any]) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for rel in sorted(files):
        data = encode(rel, files[rel])
        path = base / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        hashes[rel] = sha256_hex(data)
    return hashes


def write_package(a: Assembled, out_dir: Path, options: PackageOptions | None = None) -> PackageResult:
    options = options or PackageOptions()
    root = out_dir / f"scenario-{a.scenario_id}"
    if root.exists():
        raise FileExistsError(f"{root} exists; packages are immutable (delete it to rebuild)")
    vis_hashes = _write(root / "visible", a.visible)
    vroot = merkle_root(vis_hashes.items())
    pkg = package_id(vroot)
    cal = a.spec.calendar
    tz = a.spec.organization.timezone
    start = datetime.combine(cal.start, time(0), tzinfo=a.spec.episodes[0].virtual_start.tzinfo)
    manifest = VisibleManifest(
        schema_version=options.schema_version,
        package_id=pkg,
        scenario_id=a.scenario_id,
        organization_id=a.spec.organization.organization_id,
        virtual_calendar=VirtualCalendar(
            start=start, end=start + timedelta(days=cal.horizon_days) - timedelta(seconds=1), timezone=tz
        ),
        episodes=[
            EpisodeRef(
                episode_id=episode_id(a.scenario_id, e.index),
                virtual_start=e.virtual_start,
                virtual_end=e.virtual_end,
            )
            for e in a.spec.episodes
        ],
        enabled_sensors=list(options.enabled_sensors),
        available_artifacts=sorted(a.visible),
        record_counts={k: n for k, v in sorted(a.visible.items()) if (n := record_count(k, v)) is not None},
        tool_versions=a.meta["tool_versions"],
        enrichment_as_of=a.meta["enrichment_as_of"],
        artifact_hashes={k: f"sha256:{v}" for k, v in vis_hashes.items()},
        merkle_root=vroot,
    )
    (root / "visible" / VISIBLE_MANIFEST).write_bytes(
        encode(VISIBLE_MANIFEST, manifest.model_dump(mode="json"))
    )

    hid_hashes = _write(root / "hidden", a.hidden)
    cat = load_catalog()
    full = {
        "format": PACKAGE_FORMAT,
        "package_id": pkg,
        "scenario_id": a.scenario_id,
        "group_id": a.seeds.group_id(),
        "data_tier": options.data_tier,
        "contents": {
            "posture": a.meta["posture"],
            "telemetry": options.telemetry,
            "episode_bundles": options.episode_bundles,
        },
        "generator": {
            "iris": __version__,
            "generator_major": GENERATOR_MAJOR,
            "spec_version": SPEC_VERSION,
            "contract": CONTRACT_SCHEMA_VERSION,
            "catalogs": cat.versions,
            "grc_formula": GRC_FORMULA_VERSION,
            "mapping": MAPPING_VERSION,
            "rubric": RUBRIC_VERSION,
            "timeline": TIMELINE_VERSION,
            "posture": POSTURE_VERSION,
            "d6_key": D6_KEY_VERSION,
            "soc": SOC_VERSION,
            **options.extra_versions,
        },
        "seeds": a.seeds.to_dict(),
        "lineage": {"parent": None, "overridden_subseeds": sorted(a.seeds.overridden)},
        "split_hints": {
            "industry": a.spec.organization.industry.value,
            "maturity": a.spec.organization.maturity.value,
            "size": a.spec.organization.size.value,
        },
        "epss_snapshots": a.meta.get("epss_snapshots", []),
        "created_at_real": iso_z(provenance_utc_now()),  # provenance only; SOURCE_DATE_EPOCH pins it
        "visible_merkle_root": vroot,
        "hidden_hashes": {k: f"sha256:{v}" for k, v in hid_hashes.items()},
        "hidden_merkle_root": merkle_root(hid_hashes.items()),
    }
    for k, v in options.extra_hidden_manifest.items():
        full.setdefault(k, v)  # additive only; never overwrite a core manifest field
    (root / "hidden" / HIDDEN_MANIFEST).write_bytes(encode(HIDDEN_MANIFEST, full))
    return PackageResult(root, a.scenario_id, pkg, vroot, len(vis_hashes) + 1, len(hid_hashes) + 1)
