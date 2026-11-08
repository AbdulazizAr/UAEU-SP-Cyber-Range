"""Synthetic-path sub-seeds (builder brief README §5.4, file 09 §1).

The frozen enterprise seeds (``core/seeds.py``: org, topology, services, identity,
weakness, traffic, attack, monitoring, time, grc) stay exactly as they are — changing that
tuple would move every ``group_id`` and break determinism. The synthetic telemetry layer
needs its own independent sub-seeds, so this module derives four more from the master seed:

* ``activity``  — benign personas, attack placement, hard-negative ratios.
* ``telemetry`` — per-host log variants, PIDs, ports, user agents.
* ``sensor``    — agent/placement coverage and outage windows.
* ``noise``     — the post-processing noise layer (independent, so the same scenario can be
  regenerated at another noise level with identical world/activities/clean logs).

Every random draw comes from :func:`child_rng`, which hashes ``(subseed, namespace, index)``
into an independent stream. Draws therefore never depend on call order, so adding a new
draw later never shifts an existing one (brief determinism rule).
"""

from __future__ import annotations

import random

from iris.core.hashing import sha256_hex
from iris.core.seeds import SeedSet

SYNTH_MODULES = ("activity", "telemetry", "sensor", "noise")
_SEED_BITS = 63


def synth_subseed(seeds: SeedSet, module: str, *, override: int | None = None) -> int:
    """An independent sub-seed for one synthetic module. ``override`` pins it explicitly
    (used for the noise seed, which must vary independently of the scenario seed)."""
    if module not in SYNTH_MODULES:
        raise KeyError(f"unknown synth seed module: {module!r} (expected one of {SYNTH_MODULES})")
    if override is not None:
        if override < 0:
            raise ValueError("seed override must be non-negative")
        return override
    digest = sha256_hex(f"iris|synth-seed|v{seeds.generator_major}|{seeds.master}|{module}")
    return int(digest[:16], 16) & ((1 << _SEED_BITS) - 1)


def child_rng(subseed: int, namespace: str, *index: object) -> random.Random:
    """A named, order-independent child RNG derived by hashing ``(subseed, namespace, index)``."""
    key = "|".join(["iris|synth-stream", str(subseed), namespace, *[str(i) for i in index]])
    return random.Random(int(sha256_hex(key)[:16], 16))


class SynthSeeds:
    """Convenience bundle: the four synthetic sub-seeds for one scenario.

    ``noise_seed`` defaults to the derived noise sub-seed but can be overridden so the same
    world and activities regenerate at a different noise level.
    """

    def __init__(self, seeds: SeedSet, *, noise_override: int | None = None) -> None:
        self.base = seeds
        self.activity = synth_subseed(seeds, "activity")
        self.telemetry = synth_subseed(seeds, "telemetry")
        self.sensor = synth_subseed(seeds, "sensor")
        self.noise = synth_subseed(seeds, "noise", override=noise_override)

    def rng(self, module: str, namespace: str, *index: object) -> random.Random:
        subseed = {
            "activity": self.activity,
            "telemetry": self.telemetry,
            "sensor": self.sensor,
            "noise": self.noise,
        }[module]
        return child_rng(subseed, namespace, *index)

    def to_dict(self) -> dict[str, int]:
        return {
            "activity": self.activity,
            "telemetry": self.telemetry,
            "sensor": self.sensor,
            "noise": self.noise,
        }
