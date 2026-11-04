"""Pack a context-tier dataset into compact, offline-friendly artifacts.

Two outputs, both using only the Python standard library (works air-gapped, Windows or Linux):

* ``<name>.tar.xz`` — the whole dataset (every ``scenario-*`` package) in one LZMA-compressed
  archive. Typically ~30x smaller than the loose files. This is the thing you carry/store.
* ``<name>.labels.jsonl.xz`` — a compact, ML-ready label index: one line per episode with its
  D6 ground truth (clean flag and the planted flaws' key/module/detectability/collection/harm).
  Tiny; load it directly as training labels without unpacking the full archive.

Deterministic: same dataset -> same bytes (members are added in sorted order, timestamps zeroed).
"""

from __future__ import annotations

import json
import lzma
import tarfile
from dataclasses import dataclass
from pathlib import Path


@dataclass
class PackResult:
    archive: Path
    labels: Path
    scenarios: int
    episodes: int
    raw_bytes: int
    archive_bytes: int

    def to_dict(self) -> dict[str, object]:
        ratio = (self.raw_bytes / self.archive_bytes) if self.archive_bytes else 0.0
        return {
            "archive": str(self.archive),
            "labels": str(self.labels),
            "scenarios": self.scenarios,
            "episodes": self.episodes,
            "raw_bytes": self.raw_bytes,
            "archive_bytes": self.archive_bytes,
            "compression_ratio": round(ratio, 1),
        }


def _label_rows(store: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for pkg in sorted(store.glob("scenario-*")):
        for keyf in sorted((pkg / "hidden" / "evaluation_key" / "d6").glob("*.json")):
            key = json.loads(keyf.read_text(encoding="utf-8"))
            rows.append(
                {
                    "episode": key.get("episode_id"),
                    "scenario": pkg.name,
                    "clean": key.get("clean"),
                    "flaws": [
                        {
                            "key": f.get("key"),
                            "module": f.get("module"),
                            "detectability": f.get("detectability"),
                            "collection": f.get("collection"),
                            "harm": f.get("harm"),
                        }
                        for f in key.get("flaws", [])
                    ],
                }
            )
    return rows


def pack_dataset(store: Path, out_dir: Path, name: str = "iris_d6_dataset") -> PackResult:
    """Pack every ``scenario-*`` package under ``store`` into ``out_dir``."""
    packages = sorted(p for p in store.glob("scenario-*") if p.is_dir())
    if not packages:
        raise FileNotFoundError(f"no scenario-* packages under {store}")
    out_dir.mkdir(parents=True, exist_ok=True)

    raw_bytes = 0
    archive_path = out_dir / f"{name}.tar.xz"
    # deterministic tar.xz: sorted members, zeroed mtime/uid/gid
    with lzma.open(archive_path, "wb", preset=6) as xz, tarfile.open(fileobj=xz, mode="w") as tf:
        members: list[Path] = []
        for pkg in packages:
            members.extend(sorted(f for f in pkg.rglob("*") if f.is_file()))
        for f in members:
            raw_bytes += f.stat().st_size
            ti = tf.gettarinfo(str(f), arcname=f.relative_to(store).as_posix())
            ti.mtime = 0
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = ""
            with f.open("rb") as fh:
                tf.addfile(ti, fh)

    rows = _label_rows(store)
    labels_path = out_dir / f"{name}.labels.jsonl.xz"
    body = "\n".join(json.dumps(r, separators=(",", ":"), sort_keys=True) for r in rows)
    labels_path.write_bytes(lzma.compress(body.encode("utf-8"), preset=6))

    return PackResult(
        archive=archive_path,
        labels=labels_path,
        scenarios=len(packages),
        episodes=len(rows),
        raw_bytes=raw_bytes,
        archive_bytes=archive_path.stat().st_size,
    )


def load_labels(labels_xz: Path) -> list[dict[str, object]]:
    """Read back a ``*.labels.jsonl.xz`` index (for the training pipeline)."""
    text = lzma.decompress(labels_xz.read_bytes()).decode("utf-8")
    return [json.loads(line) for line in text.splitlines() if line]
