import json
from datetime import UTC, datetime, timedelta

from iris.compose.episode import compose_episode
from iris.compose.realize import fragment_offset, realize_fragment
from iris.compose.scenario import compose_scenario, scenario_truth
from iris.compose.select import ReuseLedger, choose, fits
from iris.core.seeds import SeedSet
from iris.fragments.assemble import assemble_fragment
from iris.fragments.mapping import scenario_mapping, target_bindings
from iris.fragments.model import FragmentTruth, residual_tokens
from iris.generator.retime import parse_wazuh_ts
from iris.generator.sampler import SampleOverrides, sample_spec
from iris.generator.secrets import scenario_secrets

T0 = datetime(2026, 11, 3, 8, 0, tzinfo=UTC)


def _spec(m):
    seeds = SeedSet.from_master(m)
    spec = sample_spec(seeds, SampleOverrides(live=True))
    return spec, scenario_secrets(spec), seeds


def _web_fragment(spec, sec, *, label="malicious", family="F1", seconds=(0, 3, 5), group_id="grp-src"):
    """Build an abstracted fragment from a source enterprise's telemetry."""
    pairs, hints = scenario_mapping(spec, sec)
    atk = next(e.ip for e in spec.externals if e.kind == "attacker")
    web = next(a for a in spec.assets if a.role.value == "web_server")
    raw = [
        (
            "suricata_eve",
            T0 + timedelta(seconds=seconds[0]),
            "timestamp",
            {
                "timestamp": "2026-11-03T08:00:00.000000+0000",
                "src_ip": atk,
                "dest_ip": web.attachments[0].ip,
                "flow_id": 12,
                "event_type": "alert",
            },
        ),
        (
            "wazuh_alert",
            T0 + timedelta(seconds=seconds[1]),
            "timestamp",
            {
                "timestamp": "2026-11-03T08:00:03.000+0000",
                "rule": {"id": "100112"},
                "agent": {"name": web.hostname, "ip": web.attachments[0].ip},
                "data": {"srcip": atk},
                "full_log": f"traversal from {atk} on {web.hostname}",
            },
        ),
    ]
    truth = FragmentTruth(
        label=label, family=family, technique="T1190", expected_rules=[100112], outcome="success"
    )
    return assemble_fragment(
        "frg-web", group_id, "attack_stage", truth, raw, pairs, hints, {"role": "web_server"}
    )


def test_realize_retime_no_leak_and_pins_first_record():
    src_spec, src_sec, _ = _spec(1)
    frag = _web_fragment(src_spec, src_sec)
    tgt_spec, tgt_sec, _ = _spec(2)
    bindings = target_bindings(tgt_spec, tgt_sec, set(frag.tokens))
    at = datetime(2027, 1, 5, 14, 0, tzinfo=UTC)
    out = realize_fragment(frag, bindings, at)
    # first record pinned to `at`, interval preserved (3 s between eve and wazuh)
    times = [t for _f, t, _b in out]
    assert times[0] == at
    assert times[1] - times[0] == timedelta(seconds=3)
    # no residual tokens and no source-enterprise value leaks
    blob = json.dumps([b for _f, _t, b in out])
    assert "@@IRIS:" not in blob
    src_web = next(a for a in src_spec.assets if a.role.value == "web_server")
    assert src_web.hostname not in blob
    # the wazuh timestamp really moved to the target window
    wz = next(b for f, _t, b in out if f == "telemetry/wazuh/alerts.jsonl")
    assert parse_wazuh_ts(wz["timestamp"]).year == 2027


def test_fragment_offset_zero_when_pinned_to_own_start():
    spec, sec, _ = _spec(3)
    frag = _web_fragment(spec, sec)
    first = min(frag.records, key=lambda r: r.offset_ms)
    from iris.compose.realize import record_time

    assert fragment_offset(frag, record_time(first)) == timedelta(0)


def test_compose_episode_sorts_and_reports_truth():
    src_spec, src_sec, _ = _spec(4)
    frag = _web_fragment(src_spec, src_sec)
    tgt_spec, tgt_sec, _ = _spec(5)
    bindings = target_bindings(tgt_spec, tgt_sec, set(frag.tokens))
    import random

    ep = compose_episode("scn-x-ep001", T0, T0 + timedelta(hours=1), [(frag, bindings)], random.Random(0))
    assert ep.activity_truth["expected_rules"] == [100112]
    assert ep.activity_truth["malicious_fragments"] == 1
    assert ep.counts["fragments_placed"] == 1
    # the wazuh record falls inside the episode window
    wz = ep.visible["telemetry/wazuh/alerts.jsonl"][0]
    assert T0 <= parse_wazuh_ts(wz["timestamp"]) <= T0 + timedelta(hours=1)


def test_reuse_ledger_caps_placement():
    spec, sec, _ = _spec(6)
    frag = _web_fragment(spec, sec)
    ledger = ReuseLedger(cap=2)
    allowed = {frag.group_id}
    import random

    picks = choose([frag] * 5, spec, sec, allowed, ledger, 5, random.Random(0))
    assert len(picks) == 2  # the same fragment id can be taken at most twice


def test_fits_rejects_wrong_group():
    spec, sec, _ = _spec(7)
    frag = _web_fragment(spec, sec)
    assert fits(frag, spec, sec, {"grp-other"}, ReuseLedger()) is None
    assert fits(frag, spec, sec, {"grp-src"}, ReuseLedger()) is not None


def test_compose_scenario_end_to_end():
    src_spec, src_sec, _ = _spec(8)
    frag = _web_fragment(src_spec, src_sec, label="malicious")
    benign = _web_fragment(src_spec, src_sec, label="benign", family="persona_web")
    benign.fragment_id = "frg-benign"
    tgt_spec, tgt_sec, tgt_seeds = _spec(9)
    composed = compose_scenario(
        tgt_spec, [frag, benign], {"grp-src"}, tgt_seeds, secrets=tgt_sec, ledger=ReuseLedger(cap=50)
    )
    assert len(composed.episodes) == len(tgt_spec.episodes)
    truth = scenario_truth(composed)
    assert truth["scenario_id"] == composed.scenario_id
    # no composed telemetry leaks a placeholder token
    blob = json.dumps(composed.visible_telemetry())
    assert "@@IRIS:" not in blob
    assert not residual_tokens(composed.visible_telemetry())


def _target_with_two_episodes():
    for m in range(40):
        spec, sec, seeds = _spec(m)
        if len(spec.episodes) >= 2:
            return spec, sec, seeds
    raise AssertionError("no sampled enterprise had >= 2 episodes")


def test_scenario_composes_attacks_when_fragments_exist():
    # the sampler never marks an episode attack_stage; the composer must choose attack
    # episodes itself. F2 is always applicable, so an F2 fragment must land.
    src_spec, src_sec, _ = _spec(100)
    mal = _web_fragment(src_spec, src_sec, label="malicious", family="F2")
    mal.fragment_id = "frg-f2"
    ben = _web_fragment(src_spec, src_sec, label="benign", family="persona_web")
    ben.fragment_id = "frg-ben"
    tgt_spec, tgt_sec, tgt_seeds = _target_with_two_episodes()
    composed = compose_scenario(
        tgt_spec, [mal, ben], {"grp-src"}, tgt_seeds, secrets=tgt_sec, ledger=ReuseLedger(cap=99)
    )
    assert any(ep.activity_truth["malicious_fragments"] > 0 for ep in composed.episodes)
    # the first episode stays a clean baseline
    assert composed.episodes[0].activity_truth["malicious_fragments"] == 0


def test_blocked_family_is_not_composed():
    src_spec, src_sec, _ = _spec(100)
    mal = _web_fragment(src_spec, src_sec, label="malicious", family="F2")
    mal.fragment_id = "frg-f2"
    tgt_spec, tgt_sec, tgt_seeds = _target_with_two_episodes()
    composed = compose_scenario(
        tgt_spec,
        [mal],
        {"grp-src"},
        tgt_seeds,
        secrets=tgt_sec,
        ledger=ReuseLedger(cap=99),
        blocked_families={"F2"},
    )
    assert all(ep.activity_truth["malicious_fragments"] == 0 for ep in composed.episodes)
