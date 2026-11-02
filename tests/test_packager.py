import json
from datetime import UTC, datetime

import pytest

from iris.contracts.decisions import D6Payload, DecisionRecord, SubjectRef
from iris.core.seeds import SeedSet
from iris.engine.baselines.d6_rules import decide
from iris.evaluator.d6 import D6Score, norm_ref, score_episode, score_package
from iris.generator.enterprise import topology
from iris.generator.grc.recorded import build_grc
from iris.generator.sampler import sample_spec
from iris.packager.build import assemble, write_package
from iris.packager.verify import verify_package


@pytest.fixture(scope="module")
def packages(tmp_path_factory):
    out = tmp_path_factory.mktemp("pk")
    return [write_package(assemble(SeedSet.from_master(m)), out) for m in range(60)]


def test_packages_verify(packages):
    for p in packages[:20]:
        rep = verify_package(p.root)
        assert rep.ok, rep.problems


def test_visible_plane_is_deterministic(tmp_path):
    a = write_package(assemble(SeedSet.from_master(9)), tmp_path / "a")
    b = write_package(assemble(SeedSet.from_master(9)), tmp_path / "b")
    assert a.merkle_root == b.merkle_root and a.package_id == b.package_id
    with pytest.raises(FileExistsError):
        write_package(assemble(SeedSet.from_master(9)), tmp_path / "a")


def test_tampering_is_detected(tmp_path):
    p = write_package(assemble(SeedSet.from_master(4)), tmp_path)
    (p.root / "visible" / "extra.json").write_text("{}")
    rep = verify_package(p.root)
    assert not rep.ok and any("unlisted" in x for x in rep.problems)
    (p.root / "visible" / "extra.json").unlink()
    f = p.root / "visible" / "enterprise" / "organization.json"
    org = json.loads(f.read_text())
    full = json.loads((p.root / "hidden" / "manifest.json").read_text())
    org["name"] = f"{org['name']} {full['group_id']}"
    f.write_text(json.dumps(org))
    rep = verify_package(p.root)
    assert any("hash mismatch" in x for x in rep.problems)
    assert any("hidden seed or group id" in x for x in rep.problems)


def test_hidden_holds_the_truth(packages):
    p = packages[0]
    hidden = p.root / "hidden"
    full = json.loads((hidden / "manifest.json").read_text())
    assert full["group_id"].startswith("grp-") and full["seeds"]["subseeds"]
    assert (hidden / "recipe" / "spec.json").exists()
    keys = sorted((hidden / "evaluation_key" / "d6").glob("*.json"))
    vman = json.loads((p.root / "visible" / "manifest.visible.json").read_text())
    assert [k.stem for k in keys] == [e["episode_id"] for e in vman["episodes"]]
    assert vman["enabled_sensors"] == [] and "maturity" not in json.dumps(vman)


def test_topology_lists_recorded_assets_only():
    for m in range(80):
        seeds = SeedSet.from_master(m)
        spec = sample_spec(seeds)
        grc = build_grc(spec, seeds)
        shadow = [f.object_ref.split(":")[1] for f in grc.ledger if f.module == "asset.shadow"]
        ghost = [f.object_ref.split(":")[1] for f in grc.ledger if f.module == "asset.ghost"]
        members = {a for z in topology(spec, grc).zones for a in z.member_asset_ids}
        assert not set(shadow) & members
        assert set(ghost) <= members


_COUNTER = iter(range(1, 10_000))


def _dec(eid, ref, ftype, conf=0.8):
    return DecisionRecord(
        decision_id=f"dec-t{next(_COUNTER)}",
        scenario_id="scn-000000000000",
        episode_id=eid,
        as_of=datetime(2026, 1, 1, tzinfo=UTC),
        type="D6",
        subject_ref=SubjectRef(kind="record", id=ref),
        payload=D6Payload(record_ref=ref, flaw_type=ftype, explanation="x"),
        status="ASSESSED",
        confidence=conf,
        context_refs=["grc/controls.json"],
        engine_version="t",
        model_version="t",
        policy_version="t",
    )


def test_scoring_rules():
    eid = "scn-000000000000-ep001"
    key = {
        "episode_id": eid,
        "clean": False,
        "tolerated_keys": ["RSK-WEB-001"],
        "flaws": [
            {"flaw_id": "F-001", "key": "CTRL-CRY-002", "aliases": ["CTRL-CRY-002"],
             "module": "control.paper", "detectability": "DC2", "harm": "high"},
            {"flaw_id": "F-002", "key": "AST-WEB-001", "aliases": ["AST-WEB-001", "shop-web1", "10.1.1.10"],
             "module": "asset.shadow", "detectability": "DC2", "harm": "medium"},
            {"flaw_id": "F-003", "key": "AST-APP-001", "aliases": ["AST-APP-001"],
             "module": "asset.process_misattributed", "detectability": "DC4", "harm": "low"},
        ],
    }  # fmt: skip
    decs = [
        _dec(eid, "grc/controls.json#CTRL-CRY-002", "control.paper", 0.9),
        _dec(eid, "assets:shop-web1", "asset.ghost", 0.7),
        _dec(eid, "business_context:AST-APP-001", "asset.process_misattributed", 0.8),
        _dec(eid, "risks:RSK-WEB-001", "risk.stale", 0.6),
        _dec(eid, "controls:CTRL-LOG-001", "control.paper", 0.5),
    ]
    s = score_episode(key, decs).summary()
    assert s["recall"] == 1.0 and s["type_accuracy"] == 0.5
    assert s["false_positives"] == 1 and s["noise_claims"] == 1 and s["unsupported_dc4_claims"] == 1
    assert s["precision"] == round(2 / 3, 4)
    assert norm_ref("10.1.1.10") == "10.1.1.10" and norm_ref("controls:CTRL-X") == "ctrl-x"


def test_rule_baseline_matches_detectability_design(packages):
    total = D6Score()
    for p in packages:
        total.merge(score_package(p.root, decide(p.root / "visible")))
    s = total.summary()
    assert s["recall_by_class"]["DC1"] >= 0.9
    assert s["recall_by_class"]["DC3"] >= 0.9
    assert s["recall_by_class"].get("DC2", 0) <= 0.3  # needs telemetry or posture
    assert s["unsupported_dc4_claims"] == 0
    assert s["precision"] >= 0.75
