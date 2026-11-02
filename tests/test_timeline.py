import json

import pytest

from iris.core.seeds import SeedSet
from iris.core.vclock import parse_iso
from iris.generator.grc.recorded import build_grc
from iris.generator.grc.timeline import ENTITY_COLLECTION, build_timeline
from iris.generator.sampler import sample_spec

N = 80


def _build(master, seeds=None):
    seeds = seeds or SeedSet.from_master(master)
    spec = sample_spec(seeds)
    bundle = build_grc(spec, seeds)
    return spec, bundle, build_timeline(spec, bundle, seeds)


@pytest.fixture(scope="module")
def timelines():
    return [_build(m) for m in range(N)]


def test_snapshots_never_contain_the_future(timelines):
    for _, _, t in timelines:
        for _, at in t.episodes:
            snap = t.snapshot(at)
            for rows in snap.values():
                for r in rows:
                    assert parse_iso(r["recorded_at"]) <= at
            assert all(c.recorded_at <= at for c in t.history(at))


def test_changes_are_recorded_after_they_happen(timelines):
    for _, _, t in timelines:
        for c in t.changes:
            assert c.effective_at <= c.recorded_at <= t.calendar_end
        ids = [c.change_id for c in t.changes]
        assert ids == sorted(ids) and len(set(ids)) == len(ids)
        assert [c.recorded_at for c in t.changes] == sorted(c.recorded_at for c in t.changes)


def test_snapshot_before_any_change_is_the_baseline(timelines):
    for _, bundle, t in timelines:
        snap = t.snapshot(t.calendar_start)
        vis = bundle.visible()
        assert snap["controls"] == vis["grc/controls.json"]
        assert snap["risks"] == vis["grc/risk_register.json"]
        assert snap["business_context"] == vis["grc/business_context.json"]


def test_previous_values_match_replay(timelines):
    for _, _, t in timelines:
        for c in t.changes:
            before = t.snapshot(c.recorded_at - _tick())
            # changes recorded at the same instant are applied in change_id order
            same = [x for x in t.changes if x.recorded_at == c.recorded_at and x.change_id < c.change_id]
            rows = {r[_key(c)]: r for r in before[ENTITY_COLLECTION[c.entity_type]]}
            rec = dict(rows[c.entity_id])
            for x in same:
                if x.entity_id == c.entity_id and x.entity_type == c.entity_type:
                    rec.update(x.new or {})
            for k, v in (c.previous or {}).items():
                assert rec.get(k) == v, (c.change_id, k)


def test_baseline_flaws_are_left_alone(timelines):
    for _, bundle, t in timelines:
        flawed = {f.object_ref for f in bundle.ledger}
        for c in t.changes:
            assert f"{ENTITY_COLLECTION[c.entity_type]}:{c.entity_id}" not in flawed


def test_items_and_flaws_agree(timelines):
    seen_open = seen_resolved = 0
    for _, _, t in timelines:
        assert len(t.ledger) == len(t.items)
        for item, flaw in zip(t.items, t.ledger, strict=True):
            assert flaw.origin == "timeline" and flaw.detectability == "DC3"
            assert flaw.active_from == item.visible_from >= item.effective_at
            assert flaw.active_until == item.resolved_at
            if item.resolved_at is None:
                seen_open += 1
                final = t.snapshot(t.calendar_end)
                rows = {r[_key_of(item.entity_type)]: r for r in final[ENTITY_COLLECTION[item.entity_type]]}
                assert any(rows[item.entity_id].get(k) != v for k, v in item.new.items())
            else:
                seen_resolved += 1
                after = t.snapshot(item.resolved_at)
                rows = {r[_key_of(item.entity_type)]: r for r in after[ENTITY_COLLECTION[item.entity_type]]}
                for k, v in item.new.items():
                    assert rows[item.entity_id][k] == v
    assert seen_open and seen_resolved


def test_ids_and_hidden_asof(timelines):
    for _, _, t in timelines:
        flaw_ids = [f.flaw_id for f in t.all_flaws()]
        assert len(set(flaw_ids)) == len(flaw_ids)
        hidden = t.hidden()
        for eid, at in t.episodes:
            truth = hidden[f"truth/asof/{eid}.json"]
            assert set(truth["active_flaw_ids"]) <= set(flaw_ids)
            assert truth["active_flaw_ids"] == [f.flaw_id for f in t.all_flaws() if f.active_at(at)]


def test_visible_plane_has_no_truth(timelines):
    for _, _, t in timelines[:30]:
        text = json.dumps(t.visible(), default=str)
        for word in ("flaw", '"EV-', '"P-0', '"RV-', '"F-0', "active_until", "resolved_by"):
            assert word not in text, word


def test_deterministic():
    a, b = _build(7)[2], _build(7)[2]
    assert json.dumps(a.visible(), default=str) == json.dumps(b.visible(), default=str)
    assert json.dumps(a.hidden(), default=str) == json.dumps(b.hidden(), default=str)


def test_grc_seed_does_not_change_reality_events():
    for m in range(30):
        base = SeedSet.from_master(m)
        e1 = _build(m, base)[2].events
        e2 = _build(m, base.with_override("grc", 999_999))[2].events
        assert [(e.kind, e.effective_at, e.entity_ref, e.details) for e in e1] == [
            (e.kind, e.effective_at, e.entity_ref, e.details) for e in e2
        ]


def _tick():
    from datetime import timedelta

    return timedelta(microseconds=1)


def _key(c):
    return _key_of(c.entity_type)


def _key_of(entity_type):
    return {"asset": "entity_ref", "control": "control_id", "risk": "risk_id", "exception": "exception_id"}[
        entity_type
    ]
