"""Verify a package: integrity, contract validity and the no-peek audit.

- Integrity: every visible file is listed with the right SHA-256, nothing extra is present,
  and the Merkle root and package ID recompute. The same holds for the hidden plane.
- Contract: every known visible file validates against its v2.0 model.
- No peek: no hidden-only token appears in visible bytes. That covers seeds, group_id,
  flaw, event, item and review IDs, generator internals, image names and maturity.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from iris.contracts.visible import (
    Asset,
    BusinessContext,
    Component,
    ContextChange,
    Control,
    ControlMapping,
    CveEnrichment,
    Identity,
    Organization,
    PolicyException,
    Risk,
    ScaleDefinition,
    ScannerFinding,
    Service,
    Topology,
    VisibleManifest,
)
from iris.core.hashing import merkle_root, package_id, sha256_hex
from iris.packager.build import HIDDEN_MANIFEST, VISIBLE_MANIFEST

FILE_MODELS: dict[str, tuple[Any, bool]] = {  # path -> (model, is_list)
    "enterprise/organization.json": (Organization, False),
    "enterprise/assets.json": (Asset, True),
    "enterprise/topology.json": (Topology, False),
    "enterprise/identities.json": (Identity, True),
    "enterprise/services.json": (Service, True),
    "enterprise/components.json": (Component, True),
    "grc/business_context.json": (BusinessContext, True),
    "grc/controls.json": (Control, True),
    "grc/control_mappings.json": (ControlMapping, True),
    "grc/risk_register.json": (Risk, True),
    "grc/policy_exceptions.json": (PolicyException, True),
    "grc/scale_definition.json": (ScaleDefinition, False),
    "posture/scanner_findings.jsonl": (ScannerFinding, True),
    "posture/cve_enrichment.jsonl": (CveEnrichment, True),
    "snapshots/context_history.jsonl": (ContextChange, True),
}
FORBIDDEN_PATTERNS = {
    "flaw id": re.compile(r'"F-\d{3}"'),
    "timeline event id": re.compile(r'"EV-\d{3}"'),
    "pending item id": re.compile(r'"P-\d{3}"'),
    "review id": re.compile(r'"RV-\d{2}"'),
    "weakness id": re.compile(r"\bWK-\d{4}\b"),
    "group id": re.compile(r"\bgrp-[0-9a-f]{12}\b"),
    "image reference": re.compile(r"\biris/[a-z]"),
    "compose project": re.compile(r"\biris-[0-9a-f]{10}\b"),
}
FORBIDDEN_WORDS = ("maturity", "true_criticality", "attackable", "flaw_ledger", "evaluation_key", "truth/")


@dataclass
class VerifyReport:
    root: Path
    ok: bool = True
    problems: list[str] = field(default_factory=list)
    checked_files: int = 0

    def fail(self, msg: str) -> None:
        self.ok = False
        self.problems.append(msg)


def _load(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".jsonl":
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    return json.loads(text)


def _files(base: Path) -> dict[str, Path]:
    return {p.relative_to(base).as_posix(): p for p in sorted(base.rglob("*")) if p.is_file()}


def verify_package(root: Path) -> VerifyReport:
    rep = VerifyReport(root)
    vis, hid = root / "visible", root / "hidden"
    if not (vis / VISIBLE_MANIFEST).exists() or not (hid / HIDDEN_MANIFEST).exists():
        rep.fail("missing manifest(s)")
        return rep
    vman_raw = _load(vis / VISIBLE_MANIFEST)
    try:
        vman = VisibleManifest(**vman_raw)
    except Exception as exc:
        rep.fail(f"visible manifest invalid: {exc}")
        return rep
    full = _load(hid / HIDDEN_MANIFEST)

    # ---- integrity, visible
    present = {k: v for k, v in _files(vis).items() if k != VISIBLE_MANIFEST}
    listed = {k: v.removeprefix("sha256:") for k, v in vman.artifact_hashes.items()}
    for rel in sorted(set(present) - set(listed)):
        rep.fail(f"unlisted visible file {rel}")
    for rel in sorted(set(listed) - set(present)):
        rep.fail(f"listed visible file missing {rel}")
    actual: dict[str, str] = {}
    for rel, path in present.items():
        actual[rel] = sha256_hex(path.read_bytes())
        if rel in listed and listed[rel] != actual[rel]:
            rep.fail(f"hash mismatch {rel}")
    root_hash = merkle_root(actual.items())
    if root_hash != vman.merkle_root:
        rep.fail("visible Merkle root does not match")
    if package_id(vman.merkle_root) != vman.package_id or full.get("package_id") != vman.package_id:
        rep.fail("package_id does not match the Merkle root")
    if sorted(vman.available_artifacts) != sorted(present):
        rep.fail("available_artifacts does not list exactly the visible files")

    # ---- integrity, hidden
    hpresent = {k: v for k, v in _files(hid).items() if k != HIDDEN_MANIFEST}
    hlisted = {k: v.removeprefix("sha256:") for k, v in full.get("hidden_hashes", {}).items()}
    if set(hpresent) != set(hlisted):
        rep.fail("hidden file list does not match its manifest")
    for rel, path in hpresent.items():
        if hlisted.get(rel) != sha256_hex(path.read_bytes()):
            rep.fail(f"hidden hash mismatch {rel}")

    # ---- contract
    for rel, path in present.items():
        rep.checked_files += 1
        model = FILE_MODELS.get(rel)
        if model is None:
            continue
        cls, is_list = model
        try:
            data = _load(path)
            if is_list:
                for row in data:
                    cls(**row)
            else:
                cls(**data)
        except Exception as exc:
            rep.fail(f"{rel} violates the contract: {str(exc).splitlines()[0]}")

    # ---- no peek
    seeds = full.get("seeds", {})
    secrets = {str(v) for v in seeds.get("subseeds", {}).values() if len(str(v)) >= 10}
    secrets.add(str(full.get("group_id", "")))
    secrets.discard("")
    for rel, path in [(VISIBLE_MANIFEST, vis / VISIBLE_MANIFEST), *present.items()]:
        text = path.read_text(encoding="utf-8")
        for s in secrets:
            if s in text:
                rep.fail(f"{rel}: contains a hidden seed or group id")
        for label, pat in FORBIDDEN_PATTERNS.items():
            if pat.search(text):
                rep.fail(f"{rel}: contains a {label}")
        low = text.lower()
        for word in FORBIDDEN_WORDS:
            if word in low:
                rep.fail(f"{rel}: contains '{word}'")
    return rep
