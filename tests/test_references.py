import shutil
from pathlib import Path

import pytest

from iris.references import attack, mappings, oscal
from iris.references.registry import ReferenceError, fetch, load_registry, verify

FIX = Path(__file__).parent / "fixtures"
ROOT = Path(__file__).resolve().parents[1]


def test_attack_parser_keeps_live_techniques_and_retires_old_ones():
    cat = attack.load(FIX / "attack_mini.json")
    assert cat.version == "20.0"
    assert set(cat.techniques) == {"T1110", "T1110.001", "T1190", "T1112"}
    assert cat.retired == {"T1064", "T1088"}
    assert cat.techniques["T1110.001"].parent_id == "T1110"
    assert cat.tactics["stealth"].tactic_id == "TA0099"  # tactic names come from data, not code
    with pytest.raises(KeyError, match="revoked or deprecated"):
        cat.get("T1064")


def test_attack_platform_scope():
    cat = attack.load(FIX / "attack_mini.json")
    scoped = cat.for_platforms(["Linux", "Network", "Network Devices", "Containers"])
    assert set(scoped) == {"T1110", "T1110.001", "T1190"}  # Windows-only T1112 excluded


def test_attack_parser_rejects_unknown_tactics():
    bundle = {
        "type": "bundle",
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--x",
                "name": "x",
                "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "made-up"}],
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1000"}],
            }
        ],
    }
    with pytest.raises(ValueError, match="missing from the bundle"):
        attack.parse_bundle(bundle)


def test_oscal_parser():
    cat = oscal.load(FIX / "oscal_mini.json")
    assert set(cat.base_controls()) == {"AC-2", "AC-4", "IA-2"}
    assert cat.controls["AC-2(1)"].parent_id == "AC-2"
    assert cat.controls["IA-2(1)"].family == "IA"
    assert cat.withdrawn == {"AC-2(10)"}
    assert oscal.normalise_id("sc-7.12") == "SC-7(12)"


def test_ctid_mappings_and_version_gap():
    ms = mappings.load(FIX / "ctid_mini.json")
    assert ms.attack_version == "14.1"
    assert ms.techniques_for("IA-2(1)") == {"T1110", "T1110.001"}
    assert ms.controls_for("T1190") == {"AC-4"}
    gap = mappings.check_against_attack(ms, attack.load(FIX / "attack_mini.json"))
    assert gap.retired == ("T1064",)
    assert gap.unknown == ("T1999",)
    assert not gap.clean


def test_registry_loads_and_declares_core_references():
    specs = load_registry()
    assert {"attack-enterprise", "nist-800-53-r5", "ctid-800-53-attack"} <= set(specs)
    assert specs["attack-enterprise"].version == "20.0"
    assert specs["iso-27001-2022"].fetch == "manual"


def test_manual_fetch_pin_and_verify(tmp_path):
    specs = load_registry()
    spec = specs["ctid-800-53-attack"]
    with pytest.raises(ReferenceError, match="place the file"):
        fetch(spec, data_dir=tmp_path)
    target = spec.local_path(tmp_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(FIX / "ctid_mini.json", target)
    entry = fetch(spec, data_dir=tmp_path)
    lock = {spec.id: entry}

    results = {r.id: r.status for r in verify({spec.id: spec}, lock, tmp_path)}
    assert results == {spec.id: "ok"}

    target.write_text("{}")
    assert verify({spec.id: spec}, lock, tmp_path)[0].status == "mismatch"
    with pytest.raises(ReferenceError, match="content changed upstream"):
        fetch(spec, data_dir=tmp_path, lock=lock)


def test_verify_reports_unpinned_and_missing(tmp_path):
    specs = load_registry()
    spec = specs["attack-enterprise"]
    assert verify({spec.id: spec}, {}, tmp_path)[0].status == "unpinned"
    lock = {spec.id: {"sha256": "0" * 64}}
    assert verify({spec.id: spec}, lock, tmp_path)[0].status == "missing"
