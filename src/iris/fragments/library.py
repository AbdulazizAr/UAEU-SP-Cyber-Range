"""Fragment library on disk: ``$IRIS_DATA/fragments/<group_id>/<family>/<id>.json``.

Split by enterprise group like everything else, so composition can enforce that a
training scenario of one group is only built from fragments of allowed groups and that
reuse of any one fragment is capped per split (docs/decisions.md).
"""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from iris.fragments.model import Fragment
from iris.settings import paths


def fragments_dir(data_dir: Path | None = None) -> Path:
    return (data_dir or paths().data) / "fragments"


def save_fragment(fragment: Fragment, data_dir: Path | None = None) -> Path:
    d = fragments_dir(data_dir) / fragment.group_id / fragment.truth.family
    d.mkdir(parents=True, exist_ok=True)
    path = d / f"{fragment.fragment_id}.json"
    path.write_text(json.dumps(fragment.to_dict(), indent=1) + "\n", encoding="utf-8")
    return path


def load_fragment(path: Path) -> Fragment:
    return Fragment.from_dict(json.loads(path.read_text(encoding="utf-8")))


def iter_fragments(data_dir: Path | None = None, group_id: str | None = None) -> Iterable[Fragment]:
    base = fragments_dir(data_dir)
    root = base / group_id if group_id else base
    if not root.exists():
        return
    for path in sorted(root.rglob("*.json")):
        yield load_fragment(path)


@dataclass
class LibraryIndex:
    by_group: dict[str, list[Fragment]]
    by_family: dict[str, list[Fragment]]

    @property
    def total(self) -> int:
        return sum(len(v) for v in self.by_group.values())


def index_library(data_dir: Path | None = None) -> LibraryIndex:
    by_group: dict[str, list[Fragment]] = defaultdict(list)
    by_family: dict[str, list[Fragment]] = defaultdict(list)
    for frag in iter_fragments(data_dir):
        by_group[frag.group_id].append(frag)
        by_family[frag.truth.family].append(frag)
    return LibraryIndex(dict(by_group), dict(by_family))
