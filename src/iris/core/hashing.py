"""Canonical JSON, hashes, content-derived IDs and Merkle roots (INPUT Part 5, section 3)."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from datetime import date, datetime
from pathlib import Path
from typing import Any

from iris.core.vclock import iso_z


def _default(obj: Any) -> Any:
    if isinstance(obj, datetime):
        return iso_z(obj)
    if isinstance(obj, date):
        return obj.isoformat()
    if isinstance(obj, (set, frozenset)):
        return sorted(obj)
    if isinstance(obj, Path):
        return obj.as_posix()
    model_dump = getattr(obj, "model_dump", None)
    if callable(model_dump):
        return model_dump(mode="json")
    raise TypeError(f"not JSON-serialisable: {type(obj).__name__}")


def canonical_json(obj: Any) -> str:
    """Deterministic JSON: sorted keys, no whitespace, UTF-8, ISO-Z datetimes."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=_default)


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while block := fh.read(chunk):
            h.update(block)
    return h.hexdigest()


def scenario_id(recipe: Mapping[str, Any]) -> str:
    """Content-derived: the same recipe always gives the same ID."""
    return "scn-" + sha256_hex(canonical_json(recipe))[:12]


def episode_id(scn_id: str, index: int) -> str:
    if not 1 <= index <= 999:
        raise ValueError("episode index must be 1..999")
    return f"{scn_id}-ep{index:03d}"


def event_id(source: str, fields: Mapping[str, Any]) -> str:
    """Deterministic per-source event ID (stable across re-exports of the same record)."""
    return "evt-" + sha256_hex(source + "|" + canonical_json(fields))[:20]


def merkle_root(leaves: Iterable[tuple[str, str]]) -> str:
    """Merkle root over (path, sha256) pairs, sorted by path. Empty input hashes to sha256('')."""
    level = [sha256_hex(f"{path}\0{digest}") for path, digest in sorted(leaves)]
    if not level:
        return sha256_hex("")
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [sha256_hex(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def package_id(root: str) -> str:
    return "pkg-" + root[:12]
