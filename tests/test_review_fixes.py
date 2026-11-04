"""Regression tests for the issues found in the November 2026 code review."""

import json
from datetime import UTC, datetime, timedelta

import pytest

from iris.core.seeds import SeedSet
from iris.core.vclock import TimeError, provenance_utc_now
from iris.dataset.splits import GroupProfile, OodConfig, build_splits
from iris.devtools.boundaries import check_tree
from iris.engine.baselines.d6_rules import decide
from iris.evaluator.d6 import score_episode, score_package
from iris.fragments.model import abstract_value, token
from iris.generator.enterprise import organization
from iris.generator.retime import shift_iso_stamps, shift_syslog_prefix
from iris.generator.sampler import SUN_THU_TIMEZONES, WORKWEEK, sample_spec
from iris.live.attacks import outcome_of_action
from iris.oracle.decisions import build_d2_key, build_d4_key
from iris.oracle.outcome import from_plan_truth
from iris.packager.build import assemble, write_package
from iris.packager.verify import verify_package
from tests.test_packager import _dec

# ---------------------------------------------------------------- retime


def test_leap_day_syslog_stamp_does_not_crash():
    ref = datetime(2028, 2, 29, 10, 0, tzinfo=UTC)
    out = shift_syslog_prefix("Feb 29 10:00:00 host sshd[1]: ok", timedelta(days=1), ref)
    assert out.startswith("Mar  1 10:00:00")


def test_nanosecond_fraction_is_kept_at_full_precision():
    out = shift_iso_stamps("at 2026-11-02T08:07:41.123456789Z x", timedelta(hours=1))
    assert out == "at 2026-11-02T09:07:41.123456789Z x"
    assert shift_iso_stamps("2026-11-02T08:07:41.5+0400", timedelta(hours=1)) == "2026-11-02T09:07:41.5+0400"


# ---------------------------------------------------------------- fragment abstraction


def test_ip_abstraction_respects_address_boundaries():
    pairs = [("10.5.20.1", token("IP_ROUTER")), ("10.5.20.25", token("IP_WEB"))]
    text = "bridge 10.5.20.254 ghost 10.5.20.137 router 10.5.20.1 web 10.5.20.25. x10.5.20.1"
    out = abstract_value({"log": text}, pairs)["log"]
    assert "10.5.20.254" in out and "10.5.20.137" in out  # unmapped neighbours untouched
    assert f"router {token('IP_ROUTER')} " in out and f"web {token('IP_WEB')}." in out


def test_non_ip_values_still_match_as_substrings():
    out = abstract_value(
        {"u": "user=j.doe@corp", "h": "db01.corp.lan"}, [("j.doe", token("U")), ("db01", token("H"))]
    )
    assert out == {"u": f"user={token('U')}@corp", "h": f"{token('H')}.corp.lan"}


# ---------------------------------------------------------------- outcomes


def test_password_guessing_is_malicious_but_not_a_compromise():
    assert outcome_of_action("login_guessing", "malicious") == "failed"
    assert outcome_of_action("path_traversal", "malicious") == "success"
    assert outcome_of_action("browse_home", "benign") == "n/a"
    spec = sample_spec(SeedSet.from_master(11))
    act = from_plan_truth(
        spec,
        "scn-000000000000-ep001",
        datetime(2026, 1, 5, 9, tzinfo=UTC),
        [{"label": "malicious", "name": "login_guessing", "family": "F2", "technique": "T1110"}],
    )
    assert act.malicious and not act.compromised
    assert build_d2_key(act)["compromised"] is False


def test_d4_key_states_where_the_control_state_comes_from():
    spec = sample_spec(SeedSet.from_master(11))
    wk = spec.weaknesses[0]
    act = from_plan_truth(
        spec,
        "scn-000000000000-ep001",
        datetime(2026, 1, 5, 9, tzinfo=UTC),
        [{"label": "malicious", "name": "x", "weakness_id": wk.weakness_id, "target_asset": wk.asset_id}],
    )
    rec = build_d4_key(act, {wk.enabling_control: "partial"})["recommendations"][0]
    assert rec["control_state"] == "partial" and rec["state_source"] == "reality"
    assert "recorded_state" not in rec


# ---------------------------------------------------------------- evaluator


def test_claim_matches_the_flaw_of_its_own_type_on_a_shared_record():
    eid = "scn-000000000000-ep001"
    key = {
        "episode_id": eid,
        "clean": False,
        "tolerated_keys": [],
        "flaws": [
            {"flaw_id": "F-001", "key": "RSK-NET-001", "aliases": ["RSK-NET-001"],
             "module": "risk.stale", "detectability": "DC3", "harm": "medium"},
            {"flaw_id": "F-002", "key": "RSK-NET-001", "aliases": ["RSK-NET-001"],
             "module": "risk.orphan_owner", "detectability": "DC1", "harm": "low"},
        ],
    }  # fmt: skip
    s = score_episode(key, [_dec(eid, "risks:RSK-NET-001", "risk.orphan_owner", 0.9)]).summary()
    assert s["type_accuracy"] == 1.0
    assert s["recall_by_class"] == {"DC1": 1.0, "DC3": 0.0}
    assert s["strict_recall"] == 0.5


def test_decisions_for_unknown_episodes_are_reported_unscored(tmp_path):
    res = write_package(assemble(SeedSet.from_master(3)), tmp_path)
    stray = _dec("scn-ffffffffffff-ep001", "risks:RSK-NET-001", "risk.stale", 0.9)
    s = score_package(res.root, [*decide(res.root / "visible"), stray]).summary()
    assert s["unscored"] == 1


def test_baseline_decision_ids_are_unique_across_scenarios(tmp_path):
    ids: list[str] = []
    for m in (1, 2, 3, 4):
        res = write_package(assemble(SeedSet.from_master(m)), tmp_path)
        ids += [d.decision_id for d in decide(res.root / "visible")]
    assert len(ids) == len(set(ids))


# ---------------------------------------------------------------- packages


def test_source_date_epoch_makes_whole_packages_byte_identical(tmp_path, monkeypatch):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    assert provenance_utc_now() == datetime(2023, 11, 14, 22, 13, 20, tzinfo=UTC)
    a = write_package(assemble(SeedSet.from_master(9)), tmp_path / "a").root
    b = write_package(assemble(SeedSet.from_master(9)), tmp_path / "b").root
    files_a = sorted(p.relative_to(a) for p in a.rglob("*") if p.is_file())
    assert files_a == sorted(p.relative_to(b) for p in b.rglob("*") if p.is_file())
    assert all((a / f).read_bytes() == (b / f).read_bytes() for f in files_a)
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "not-a-number")
    with pytest.raises(TimeError):
        provenance_utc_now()


def test_verify_checks_hidden_merkle_root_and_diff_audit(tmp_path):
    res = write_package(assemble(SeedSet.from_master(5)), tmp_path)
    man = res.root / "hidden" / "manifest.json"
    full = json.loads(man.read_text(encoding="utf-8"))
    full["hidden_merkle_root"] = "0" * 64
    man.write_text(json.dumps(full), encoding="utf-8")
    assert "hidden Merkle root does not match" in verify_package(res.root).problems

    res2 = write_package(assemble(SeedSet.from_master(6)), tmp_path)
    audit = res2.root / "hidden" / "truth" / "grc_diff_audit.json"
    data = json.loads(audit.read_text(encoding="utf-8"))
    data["ok"] = False
    audit.write_text(json.dumps(data), encoding="utf-8")
    problems = verify_package(res2.root).problems
    assert any("diff audit failed" in p for p in problems)  # (its hash mismatch is reported too)


# ---------------------------------------------------------------- splits, boundaries, calendar


def test_held_out_groups_are_never_composed_into_training():
    profiles = [
        GroupProfile("grp-a", "t1", "retail", ("F1",), "s"),
        GroupProfile("grp-b", "t2", "retail", ("F1",), "s"),
    ]
    splits = build_splits(profiles, OodConfig(topologies=frozenset({"t2"})))
    ood = {g for s in splits.ood_sets.values() for g in s.group_ids}
    allowed = {"grp-a", "grp-b"} - ood  # what build_dataset now does with the library groups
    assert allowed == {"grp-a"}


def test_relative_imports_cannot_bypass_boundaries(tmp_path):
    def w(rel: str, text: str) -> None:
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")

    w(
        "iris/engine/model.py",
        "from ..generator import sampler\nfrom .. import oracle\nfrom . import helpers\n",
    )
    w("iris/engine/__init__.py", "from ..evaluator.d6 import score_package\n")
    found = sorted(v.detail for v in check_tree(tmp_path))
    assert found == [
        "iris.engine imports iris.evaluator.d6",
        "iris.engine.model imports iris.generator",
        "iris.engine.model imports iris.oracle",
    ]


def test_sun_thu_workweek_has_one_source_of_truth():
    assert set(WORKWEEK) == SUN_THU_TIMEZONES
    spec = sample_spec(SeedSet.from_master(0))
    week = organization(spec).workweek
    assert (week[0] == "sun") == (spec.organization.timezone in SUN_THU_TIMEZONES)
