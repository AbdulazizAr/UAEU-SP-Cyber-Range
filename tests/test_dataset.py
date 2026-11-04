from iris.dataset.coverage import CoverageUniverse, coverage_report, from_keys
from iris.dataset.drift import EpisodeFeatures, drift_report, episode_features, smd, tvd
from iris.dataset.factory import FactoryPlan, GroupCandidate, plan_factory, run_factory
from iris.dataset.splits import GroupProfile, OodConfig, assign, build_splits


# ---------------------------------------------------------------- splits
def _profiles():
    return [
        GroupProfile("grp-1", "compact_three_zone", "retail", ("F1",), "1_10|iso", gold=True),
        GroupProfile("grp-2", "flat_small", "healthcare", ("F1", "F2"), "3_level|nist", gold=True),
        GroupProfile("grp-3", "flat_small", "finance", ("F2",), "qualitative|coso", gold=False),
    ]


def test_split_precedence_topology_wins():
    p = GroupProfile("g", "compact_three_zone", "healthcare", ("F1",), "3_level|nist")
    ood = OodConfig(topologies=frozenset({"compact_three_zone"}), industries=frozenset({"healthcare"}))
    a = assign(p, ood)
    assert a.split == "ood_topology" and a.dimension == "topology"


def test_split_attack_family_and_blocklist():
    ood = OodConfig(families=frozenset({"F2"}))
    splits = build_splits(_profiles(), ood)
    # grp-2 and grp-3 hold F2 -> OOD; grp-1 stays in-distribution
    assert splits.in_distribution == ["grp-1"]
    assert "ood_attack_family" in splits.ood_sets
    assert set(splits.ood_sets["ood_attack_family"].group_ids) == {"grp-2", "grp-3"}
    # the sampler must not use F2 in in-distribution groups
    assert splits.indist_blocked_families == ["F2"]


def test_ood_set_indicative_when_few_gold():
    ood = OodConfig(industries=frozenset({"healthcare", "finance"}))
    splits = build_splits(_profiles(), ood)
    assert splits.ood_sets["ood_industry"].indicative  # <15 Gold groups
    assert splits.warnings()


# ---------------------------------------------------------------- coverage
def test_coverage_counts_and_gaps():
    mal = from_keys(
        {
            "verdict": "malicious",
            "family": "F1",
            "techniques": ["T1190"],
            "tactics": ["initial-access"],
            "detectability": "DC1",
        },
        {"priority": "HIGH"},
        {"recommendations": [{"control_id": "CTRL-VUL-001"}]},
        "train",
        d6_flaws=2,
    )
    ben = from_keys(
        {"verdict": "benign", "detectability": "n/a"}, {"priority": None}, {"recommendations": []}, "train"
    )
    rep = coverage_report(
        [mal, ben],
        CoverageUniverse(families=frozenset({"F1", "F2"}), techniques=frozenset({"T1190", "T1110"})),
    )
    assert rep.episodes == 2
    assert rep.by_verdict == {"benign": 1, "malicious": 1}
    assert (
        rep.decision_presence["D1"] == 1
        and rep.decision_presence["D4"] == 1
        and rep.decision_presence["D6"] == 1
    )
    assert rep.by_technique == {"T1190": 1}
    assert rep.missing_families == ["F2"] and rep.missing_techniques == ["T1110"]
    assert rep.d6_flaws_total == 2


# ---------------------------------------------------------------- drift
def test_smd_and_tvd_basic():
    assert smd([1, 1, 1], [1, 1, 1]) == 0.0
    assert smd([0, 0], [10, 10]) == float("inf")  # no variance, different means
    assert tvd(["a", "a", "b"], ["a", "a", "b"]) == 0.0
    assert tvd(["a", "a"], ["b", "b"]) == 1.0


def test_episode_features_and_drift_pass():
    visible = {
        "telemetry/wazuh/alerts.jsonl": [
            {"timestamp": "2026-11-03T08:00:00.000+0000"},
            {"timestamp": "2026-11-03T08:00:05.000+0000"},
        ],
        "telemetry/suricata/eve.jsonl": [{"timestamp": "2026-11-03T08:00:01.000000+0000"}],
    }
    truth = {
        "placements": [
            {"label": "malicious", "family": "F1", "technique": "T1190", "expected_rules": [100112]}
        ]
    }
    f = episode_features(visible, truth)
    assert f.numeric["records"] == 3.0 and f.categorical["dominant_family"] == "F1"
    assert f.categorical["detectability"] == "DC1"
    # a population against itself has zero drift and passes
    rep = drift_report([f, f, f], [f, f, f])
    assert rep.ok and not rep.failures()


def test_drift_detects_shift():
    lo = EpisodeFeatures(numeric={"records": 10.0}, categorical={"dominant_family": "F1"})
    hi = EpisodeFeatures(numeric={"records": 1000.0}, categorical={"dominant_family": "F2"})
    rep = drift_report([lo, lo, lo, lo], [hi, hi, hi, hi])
    assert not rep.ok
    assert "records" in rep.failures()[0].feature or any(f.feature == "records" for f in rep.failures())


# ---------------------------------------------------------------- factory
def test_plan_skips_blocked_families_in_indist():
    ood = OodConfig(families=frozenset({"F2"}))
    # an in-distribution group that also lists F2: F2 must be dropped from its plan
    indist = [GroupProfile("grp-9", "flat_small", "retail", ("F1",), "s")]
    splits2 = build_splits(indist, ood)
    cand = GroupCandidate("grp-9", 9, ("F1", "F2"), ("flask_shop",))
    plan = plan_factory([cand], splits2, have={}, per_family_target=3)
    assert plan.targets[0].families == ["F1"]  # F2 held out of in-distribution
    assert plan.targets[0].needed == {"F1": 3}


def test_plan_counts_existing_and_runs_with_injected_recorder():
    cand = GroupCandidate("grp-1", 1, ("F1",), ("flask_shop",))
    ood = OodConfig()
    splits = build_splits([GroupProfile("grp-1", "t", "i", ("F1",), "s")], ood)
    plan = plan_factory([cand], splits, have={("grp-1", "F1"): 1}, per_family_target=3)
    assert plan.targets[0].needed == {"F1": 2}
    result = run_factory(plan, record_fn=lambda t: sum(t.needed.values()))
    assert result.fragments_recorded == 2 and result.targets_run == 1


def test_run_factory_captures_errors():
    cand = GroupCandidate("grp-1", 1, ("F1",), ("flask_shop",))
    splits = build_splits([GroupProfile("grp-1", "t", "i", ("F1",), "s")], OodConfig())
    plan = plan_factory([cand], splits, have={}, per_family_target=1)

    def boom(_t):
        raise RuntimeError("docker down")

    result = run_factory(plan, record_fn=boom)
    assert result.targets_run == 0 and "grp-1" in result.errors


def test_factory_plan_serialises():
    plan = FactoryPlan("v", [])
    assert plan.to_dict()["total_fragments_wanted"] == 0


# ------------------------------------------------ context (D6) coverage
def _d6_key(clean, flaws):
    return {"clean": clean, "flaws": flaws}


def test_context_coverage_counts_flaws_and_classes():
    from iris.dataset.coverage import context_coverage_report

    keys = [
        _d6_key(True, []),
        _d6_key(
            False,
            [
                {
                    "module": "risk.orphan_owner",
                    "detectability": "DC1",
                    "collection": "risks",
                    "harm": "low",
                    "level": "L2",
                },
                {
                    "module": "control.paper",
                    "detectability": "DC2",
                    "collection": "controls",
                    "harm": "high",
                    "level": "L4",
                },
            ],
        ),
        _d6_key(
            False,
            [
                {
                    "module": "asset.ghost",
                    "detectability": "DC2",
                    "collection": "assets",
                    "harm": "medium",
                    "level": "L3",
                }
            ],
        ),
    ]
    rep = context_coverage_report(keys, packages=2).to_dict()
    assert rep["tier"] == "context"
    assert rep["episodes"] == 3
    assert rep["clean_episodes"] == 1
    assert rep["flawed_episodes"] == 2
    assert rep["flaws_total"] == 3
    assert rep["by_detectability"] == {"DC1": 1, "DC2": 2}
    assert rep["by_collection"] == {"assets": 1, "controls": 1, "risks": 1}
    assert rep["packages"] == 2


def test_context_coverage_reports_missing_modules():
    from iris.dataset.coverage import context_coverage_report

    keys = [
        _d6_key(
            False,
            [
                {
                    "module": "risk.stale",
                    "detectability": "DC3",
                    "collection": "risks",
                    "harm": "low",
                    "level": "L2",
                }
            ],
        )
    ]
    rep = context_coverage_report(keys, expected_modules=frozenset({"risk.stale", "asset.shadow"})).to_dict()
    assert rep["missing_modules"] == ["asset.shadow"]


# ------------------------------------------------ pack (offline compaction)
def test_pack_dataset_roundtrip_and_deterministic(tmp_path):
    import json as _json
    import lzma
    import tarfile

    from iris.dataset.pack import load_labels, pack_dataset

    # build a minimal fake context store: two scenarios, each one D6 key
    store = tmp_path / "store"
    for sc in ("scenario-scn-aaa", "scenario-scn-bbb"):
        d6 = store / sc / "hidden" / "evaluation_key" / "d6"
        d6.mkdir(parents=True)
        (store / sc / "visible").mkdir(parents=True)
        (store / sc / "visible" / "x.json").write_text('{"a":1}')
        (d6 / f"{sc}-ep001.json").write_text(
            _json.dumps(
                {
                    "episode_id": f"{sc}-ep001",
                    "clean": False,
                    "flaws": [
                        {
                            "key": "K1",
                            "module": "risk.stale",
                            "detectability": "DC2",
                            "collection": "risks",
                            "harm": "low",
                        }
                    ],
                }
            )
        )

    r1 = pack_dataset(store, tmp_path / "out1")
    r2 = pack_dataset(store, tmp_path / "out2")
    assert r1.scenarios == 2 and r1.episodes == 2
    # deterministic bytes
    assert r1.archive.read_bytes() == r2.archive.read_bytes()
    assert r1.labels.read_bytes() == r2.labels.read_bytes()
    # archive unpacks
    with lzma.open(r1.archive) as xz, tarfile.open(fileobj=xz) as tf:
        assert any(n.endswith("ep001.json") for n in tf.getnames())
    # labels load back
    rows = load_labels(r1.labels)
    assert len(rows) == 2
    assert rows[0]["flaws"][0]["module"] == "risk.stale"
