"""Filesystem locations. Code lives in git; data lives under IRIS_DATA (default /srv/iris)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

DEFAULT_DATA_DIR = Path("/srv/iris")
DATA_SUBDIRS = ("store", "fragments", "runs", "cache", "references", "registry")


@dataclass(frozen=True)
class Paths:
    """Resolved data directories. Nothing else in the code hard-codes a path."""

    data: Path

    @property
    def store(self) -> Path:
        return self.data / "store"

    @property
    def fragments(self) -> Path:
        return self.data / "fragments"

    @property
    def runs(self) -> Path:
        return self.data / "runs"

    @property
    def cache(self) -> Path:
        return self.data / "cache"

    @property
    def references(self) -> Path:
        return self.data / "references"

    def ensure(self) -> None:
        for name in DATA_SUBDIRS:
            (self.data / name).mkdir(parents=True, exist_ok=True)


def paths() -> Paths:
    """Return the data paths, honouring the IRIS_DATA environment variable."""
    return Paths(data=Path(os.environ.get("IRIS_DATA", str(DEFAULT_DATA_DIR))).expanduser())


def repo_root() -> Path:
    """Repository root (two levels above src/iris)."""
    return Path(__file__).resolve().parents[2]
