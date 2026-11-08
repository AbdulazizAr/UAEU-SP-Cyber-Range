"""Pinned, in-repo reference bundles for the synthetic path (builder brief file 01/04).

The live path fetches single reference files into ``$IRIS_DATA`` and pins them one by one
(:mod:`iris.references.registry`). The synth path instead needs several *directories* of
real rule/decoder/standard files available at generation time with no network, so they are
committed under ``configs/references/<id>/`` and pinned as **bundle digests** in the same
``configs/references/lock.json``:

* ``wazuh-ruleset``  — Wazuh 4.14.9 rule + decoder XML subset (MiniWazuh loads these).
* ``suricata-rules`` — Suricata 8.0.6 built-in event rules.
* ``attack-synth``   — ATT&CK Enterprise v20.0 STIX, filtered to Linux/Network/Containers/PRE.

A bundle digest is ``sha256`` over the sorted manifest ``"<relpath>\\0<file sha256>"`` of
every file in the directory, so any edit, addition or removal changes it. ``verify_bundles``
re-computes and compares; ``iris refs verify`` and ``iris synth refs verify`` call it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from iris.core.hashing import sha256_file, sha256_hex
from iris.references.attack import AttackCatalog
from iris.references.attack import load as load_attack
from iris.references.registry import default_lock_path

BUNDLE_IDS = ("wazuh-ruleset", "suricata-rules", "attack-synth")
ATTACK_BUNDLE_FILE = "enterprise-attack-linux-20.0.json"


def references_root() -> Path:
    """``configs/references`` in the repo (committed bundles live here)."""
    return Path(__file__).resolve().parents[3] / "configs" / "references"


def bundle_root(bundle_id: str) -> Path:
    if bundle_id not in BUNDLE_IDS:
        raise KeyError(f"unknown synth reference bundle: {bundle_id}")
    return references_root() / bundle_id


def bundle_digest(directory: Path) -> tuple[str, int, int]:
    """Return ``(sha256, file_count, total_bytes)`` over a directory's sorted manifest."""
    files = sorted(p for p in directory.rglob("*") if p.is_file())
    lines, total = [], 0
    for p in files:
        total += p.stat().st_size
        lines.append(f"{p.relative_to(directory).as_posix()}\0{sha256_file(p)}")
    return sha256_hex("\n".join(lines)), len(files), total


@dataclass(frozen=True)
class BundleCheck:
    bundle_id: str
    status: str  # ok | missing | unpinned | mismatch
    detail: str = ""


def verify_bundles(lock_path: Path | None = None) -> list[BundleCheck]:
    lock = json.loads((lock_path or default_lock_path()).read_text(encoding="utf-8") or "{}")
    out: list[BundleCheck] = []
    for bid in BUNDLE_IDS:
        root = bundle_root(bid)
        if bid not in lock:
            out.append(BundleCheck(bid, "unpinned", "not in lock.json"))
        elif not root.is_dir():
            out.append(BundleCheck(bid, "missing", str(root)))
        else:
            got, _, _ = bundle_digest(root)
            want = lock[bid]["sha256"]
            out.append(
                BundleCheck(
                    bid,
                    "ok" if got == want else "mismatch",
                    "" if got == want else f"{got[:12]} != {want[:12]}",
                )
            )
    return out


def require_bundle(bundle_id: str, lock_path: Path | None = None) -> Path:
    """Path to a pinned, verified bundle directory, or a clear error."""
    check = next(c for c in verify_bundles(lock_path) if c.bundle_id == bundle_id)
    if check.status != "ok":
        raise RuntimeError(f"reference bundle {bundle_id}: {check.status} {check.detail}")
    return bundle_root(bundle_id)


@lru_cache(maxsize=1)
def attack_catalog() -> AttackCatalog:
    """The pinned ATT&CK catalog (verified). Techniques used anywhere in synth must exist here."""
    return load_attack(require_bundle("attack-synth") / ATTACK_BUNDLE_FILE)
