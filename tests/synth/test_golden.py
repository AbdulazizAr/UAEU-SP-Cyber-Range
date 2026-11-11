"""Phase 10 gate: golden determinism. Rebuilding a pinned (seed, noise) reproduces the exact
visible Merkle root recorded in golden_manifest.json — byte-for-byte reproducibility (brief
file 09 DoD). If this fails, generation has become non-deterministic (an unseeded RNG, set
ordering, or a stray wall-clock/`hash()` call) — find it, do not re-bless the hash."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from iris.core.seeds import SeedSet
from iris.synth.build import build_synth_scenario, write_synth_scenario

GOLDEN = json.loads((Path(__file__).parent / "golden" / "golden_manifest.json").read_text())


@pytest.mark.parametrize("entry", GOLDEN, ids=lambda e: f"m{e['master']}-{e['noise']}")
def test_golden_merkle_is_reproducible(entry, tmp_path):
    built = build_synth_scenario(SeedSet.from_master(entry["master"]), noise_level=entry["noise"])
    res = write_synth_scenario(built, tmp_path)
    assert res.scenario_id == entry["scenario_id"]
    assert res.merkle_root == entry["visible_merkle"], (
        "visible plane changed — generation is not deterministic"
    )
    assert built.n_malicious == entry["n_malicious"]
    assert built.n_telemetry == entry["n_telemetry"]
