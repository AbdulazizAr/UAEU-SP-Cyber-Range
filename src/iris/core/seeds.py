"""Seed hierarchy (INPUT Part 1, 0.1, with seed_time and seed_grc from Part 2).

* Each module gets an independent sub-seed derived from the master seed and the
  generator MAJOR version, so changing one module never shifts another's randomness.
* Sub-seeds are stored explicitly and can be overridden one at a time (alterations,
  Part 5, 8.3). An override is just a different stored value.
* Inside a module every random choice uses a NAMED stream, so adding a new choice
  later does not change existing ones.
* ``group_id`` (the ML split unit) depends only on the modules that define the
  enterprise: org, topology, services, identity.

Determinism note: streams use :class:`random.Random`. Its integer seeding and
``random()`` output are stable across CPython versions; the resolved spec is
stored with every scenario anyway, so replication never depends on re-sampling.
``tests/test_seeds.py`` pins golden values so any drift fails CI.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any

from iris import GENERATOR_MAJOR
from iris.core.hashing import canonical_json, sha256_hex

#: Fixed order. Never reorder or rename: names are part of the hash.
SEED_MODULES: tuple[str, ...] = (
    "org",
    "topology",
    "services",
    "identity",
    "weakness",
    "traffic",
    "attack",
    "monitoring",
    "time",
    "grc",
)

#: Modules whose change means "a different enterprise" (new group_id).
ENTERPRISE_MODULES: tuple[str, ...] = ("org", "topology", "services", "identity")

_SEED_BITS = 63  # keep sub-seeds positive and JSON-safe in most consumers


def derive_subseed(master_seed: int, module: str, generator_major: int = GENERATOR_MAJOR) -> int:
    if module not in SEED_MODULES:
        raise KeyError(f"unknown seed module: {module}")
    digest = sha256_hex(f"iris|seed|v{generator_major}|{master_seed}|{module}")
    return int(digest[:16], 16) & ((1 << _SEED_BITS) - 1)


def _stream_seed(subseed: int, name: str) -> int:
    return int(sha256_hex(f"iris|stream|{subseed}|{name}")[:16], 16)


@dataclass(frozen=True)
class SeedSet:
    """All seeds of one scenario. Serialise with :meth:`to_dict` into the recipe."""

    master: int
    generator_major: int = GENERATOR_MAJOR
    subseeds: dict[str, int] = field(default_factory=dict)
    overridden: frozenset[str] = frozenset()

    @classmethod
    def from_master(cls, master: int, generator_major: int = GENERATOR_MAJOR) -> SeedSet:
        if master < 0:
            raise ValueError("master seed must be non-negative")
        subs = {m: derive_subseed(master, m, generator_major) for m in SEED_MODULES}
        return cls(master=master, generator_major=generator_major, subseeds=subs)

    def __post_init__(self) -> None:
        missing = [m for m in SEED_MODULES if m not in self.subseeds]
        extra = [m for m in self.subseeds if m not in SEED_MODULES]
        if missing or extra:
            raise ValueError(f"seed set incomplete or unknown modules: missing={missing} extra={extra}")

    def get(self, module: str) -> int:
        return self.subseeds[module]

    def with_override(self, module: str, value: int) -> SeedSet:
        """Return a copy with one sub-seed replaced (an alteration)."""
        if module not in SEED_MODULES:
            raise KeyError(f"unknown seed module: {module}")
        if value < 0:
            raise ValueError("seed values must be non-negative")
        subs = dict(self.subseeds)
        subs[module] = value
        return SeedSet(self.master, self.generator_major, subs, self.overridden | {module})

    def stream(self, module: str, name: str) -> random.Random:
        """A named, independent random stream inside a module."""
        return random.Random(_stream_seed(self.get(module), name))

    def group_id(self) -> str:
        key = {m: self.subseeds[m] for m in ENTERPRISE_MODULES}
        key["generator_major"] = self.generator_major
        return "grp-" + sha256_hex(canonical_json(key))[:12]

    def to_dict(self) -> dict[str, Any]:
        return {
            "master": self.master,
            "generator_major": self.generator_major,
            "subseeds": {m: self.subseeds[m] for m in SEED_MODULES},
            "overridden": sorted(self.overridden),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SeedSet:
        return cls(
            master=int(data["master"]),
            generator_major=int(data["generator_major"]),
            subseeds={k: int(v) for k, v in data["subseeds"].items()},
            overridden=frozenset(data.get("overridden", ())),
        )
