from datetime import UTC, datetime, timedelta, timezone

import pytest

from iris.core.hashing import canonical_json, episode_id, event_id, merkle_root, scenario_id
from iris.core.seeds import ENTERPRISE_MODULES, SEED_MODULES, SeedSet, derive_subseed
from iris.core.vclock import (
    EpisodeClock,
    EpisodeWindow,
    TimeError,
    VClock,
    iso_z,
    parse_iso,
    validate_episode_sequence,
)

T0 = datetime(2025, 3, 1, tzinfo=UTC)

# ---------------------------------------------------------------- VClock


def test_vclock_is_forward_only():
    c = VClock(T0)
    c.advance_by(timedelta(days=2))
    with pytest.raises(TimeError):
        c.advance_to(T0)
    with pytest.raises(TimeError):
        c.advance_by(timedelta(seconds=-1))


def test_vclock_rejects_naive_times():
    with pytest.raises(TimeError):
        VClock(datetime(2025, 3, 1))


def test_vclock_runs_events_in_order_with_stable_ties():
    c = VClock(T0)
    c.schedule(T0 + timedelta(days=3), "c")
    c.schedule(T0 + timedelta(days=1), "a")
    c.schedule(T0 + timedelta(days=1), "b")  # same time: insertion order
    seen = list(c.run_until(T0 + timedelta(days=2)))
    assert [e for _, e in seen] == ["a", "b"]
    assert c.now() == T0 + timedelta(days=2)
    assert c.pending() == 1
    with pytest.raises(TimeError):
        c.schedule(T0, "past")


def test_vclock_converts_other_timezones_to_utc():
    dubai = timezone(timedelta(hours=4))
    c = VClock(datetime(2025, 3, 1, 4, 0, tzinfo=dubai))
    assert c.now() == T0
    assert iso_z(c.now()) == "2025-03-01T00:00:00Z"
    assert parse_iso("2025-03-01T00:00:00Z") == T0


def test_episode_window_rules():
    with pytest.raises(TimeError):
        EpisodeWindow(1, T0, T0)
    with pytest.raises(TimeError):
        EpisodeWindow(1, datetime(2025, 12, 31, 23, 55, tzinfo=UTC), datetime(2026, 1, 1, 0, 5, tzinfo=UTC))
    w = EpisodeWindow(1, T0, T0 + timedelta(minutes=10))
    assert w.contains(T0 + timedelta(minutes=11), tolerance=timedelta(minutes=2))
    assert not w.contains(T0 + timedelta(minutes=13), tolerance=timedelta(minutes=2))


def test_episode_sequence_rules():
    a = EpisodeWindow(1, T0, T0 + timedelta(minutes=10))
    b = EpisodeWindow(2, T0 + timedelta(minutes=5), T0 + timedelta(minutes=20))
    with pytest.raises(TimeError):
        validate_episode_sequence([a, b])
    c = EpisodeWindow(3, T0 + timedelta(days=1), T0 + timedelta(days=1, minutes=10))
    with pytest.raises(TimeError):
        validate_episode_sequence([a, c])  # non-consecutive index


def test_episode_clock_offset_maps_observe_start_exactly():
    real = datetime(2026, 11, 2, 10, 0, tzinfo=UTC)
    ec = EpisodeClock.for_observe_start(T0, real)
    assert ec.to_virtual(real) == T0
    assert ec.to_virtual(real + timedelta(minutes=5)) == T0 + timedelta(minutes=5)
    assert ec.to_real(T0) == real
    assert ec.faketime_spec().startswith("-")


# ---------------------------------------------------------------- seeds


def test_seed_golden_values_are_stable():
    s = SeedSet.from_master(20261102)
    assert s.get("org") == 2107895964927993195
    assert s.group_id() == "grp-31f730e65d1b"
    r = s.stream("topology", "zone_count")
    assert r.random() == 0.8351154672820994
    assert r.random() == 0.5404742551894349
    assert r.randrange(1000) == 965


def test_seed_modules_are_independent_and_complete():
    s = SeedSet.from_master(7)
    assert set(s.subseeds) == set(SEED_MODULES)
    assert len(set(s.subseeds.values())) == len(SEED_MODULES)
    assert derive_subseed(7, "attack", generator_major=1) != s.get("attack")


def test_group_id_tracks_enterprise_modules_only():
    s = SeedSet.from_master(20261102)
    for module in SEED_MODULES:
        altered = s.with_override(module, 42)
        same = altered.group_id() == s.group_id()
        assert same == (module not in ENTERPRISE_MODULES), module
    assert s.with_override("attack", 42).overridden == frozenset({"attack"})


def test_named_streams_do_not_interfere():
    s = SeedSet.from_master(1)
    a1 = s.stream("topology", "a").random()
    _ = s.stream("topology", "b").random()
    assert s.stream("topology", "a").random() == a1
    assert s.stream("topology", "a").random() != s.stream("topology", "b").random()


def test_seed_round_trip():
    s = SeedSet.from_master(99).with_override("grc", 5)
    assert SeedSet.from_dict(s.to_dict()) == s


def test_seed_validation():
    with pytest.raises(ValueError):
        SeedSet.from_master(-1)
    with pytest.raises(KeyError):
        SeedSet.from_master(1).with_override("nope", 1)


# ---------------------------------------------------------------- hashing and ids


def test_canonical_json_is_order_independent():
    assert canonical_json({"b": 1, "a": [T0]}) == canonical_json({"a": [T0], "b": 1})
    assert canonical_json({"t": T0}) == '{"t":"2025-03-01T00:00:00Z"}'


def test_ids():
    assert scenario_id({"a": 1}) == "scn-015abd7f5cc5"
    assert scenario_id({"a": 1}) != scenario_id({"a": 2})
    assert episode_id("scn-015abd7f5cc5", 3) == "scn-015abd7f5cc5-ep003"
    with pytest.raises(ValueError):
        episode_id("scn-015abd7f5cc5", 0)
    e = event_id("wazuh_alert", {"id": "1", "ts": "x"})
    assert e.startswith("evt-") and len(e) == 24
    assert e == event_id("wazuh_alert", {"ts": "x", "id": "1"})


def test_merkle_root_is_order_independent_and_sensitive():
    leaves = [("a", "x"), ("b", "y"), ("c", "z")]
    assert merkle_root(leaves) == merkle_root(list(reversed(leaves)))
    assert merkle_root(leaves) != merkle_root([("a", "x"), ("b", "y"), ("c", "w")])
    assert (
        merkle_root([("a", "x"), ("b", "y")])
        == "ddbc6dc3e502375ff03dec8490518b79c7bd74b78d586d0d631dfc4a7cb927ca"
    )
