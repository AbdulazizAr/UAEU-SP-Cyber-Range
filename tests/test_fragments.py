import json
from datetime import UTC, datetime, timedelta

from iris.core.seeds import SeedSet
from iris.fragments.assemble import assemble_fragment
from iris.fragments.library import index_library, iter_fragments, save_fragment
from iris.fragments.mapping import scenario_mapping, target_bindings, unresolved
from iris.fragments.model import (
    Fragment,
    FragmentTruth,
    abstract_value,
    realize_value,
    residual_tokens,
    token,
)
from iris.generator.sampler import SampleOverrides, sample_spec
from iris.generator.secrets import scenario_secrets

T0 = datetime(2026, 11, 3, 8, 0, tzinfo=UTC)


def _spec(m):
    seeds = SeedSet.from_master(m)
    spec = sample_spec(seeds, SampleOverrides(live=True))
    return spec, scenario_secrets(spec)


def test_abstract_realize_round_trip():
    spec, sec = _spec(42)
    pairs, _ = scenario_mapping(spec, sec)
    web = next(a for a in spec.assets if a.role.value == "web_server")
    alert = {
        "timestamp": "2026-11-03T08:00:00.000+0000",
        "rule": {"id": "100104"},
        "agent": {"name": web.hostname, "ip": web.attachments[0].ip},
        "data": {"srcip": next(e.ip for e in spec.externals if e.kind == "attacker")},
        "full_log": f"login from {web.hostname} ({web.attachments[0].ip})",
    }
    abstracted = abstract_value(alert, pairs)
    assert web.hostname not in json.dumps(abstracted)
    assert web.attachments[0].ip not in json.dumps(abstracted)
    assert token("HOST_WEB_SERVER_1") in json.dumps(abstracted)
    # realise back onto the SAME enterprise reproduces the original
    toks = residual_tokens(abstracted)
    bindings = target_bindings(spec, sec, toks)
    realised = realize_value(abstracted, bindings)
    assert realised == alert
    assert not residual_tokens(realised)


def test_realize_onto_a_different_enterprise_has_no_leaks():
    src_spec, src_sec = _spec(1)
    pairs, _ = scenario_mapping(src_spec, src_sec)
    body = {
        "host": next(a.hostname for a in src_spec.assets if a.role.value == "database"),
        "ip": next(a.attachments[0].ip for a in src_spec.assets if a.role.value == "database"),
    }
    abstracted = abstract_value(body, pairs)
    tgt_spec, tgt_sec = _spec(2)
    toks = residual_tokens(abstracted)
    bindings = target_bindings(tgt_spec, tgt_sec, toks)
    realised = realize_value(abstracted, bindings)
    if not unresolved(toks, bindings):
        assert not residual_tokens(realised)
        tgt_db = next(a for a in tgt_spec.assets if a.role.value == "database")
        assert realised["host"] == tgt_db.hostname and realised["ip"] == tgt_db.attachments[0].ip


def test_ip_substitution_is_not_fooled_by_prefixes():
    pairs = [("10.0.0.1", token("IP_A")), ("10.0.0.10", token("IP_B"))]
    out = abstract_value({"a": "10.0.0.1", "b": "10.0.0.10"}, pairs)
    assert out == {"a": token("IP_A"), "b": token("IP_B")}


def test_assemble_fragment_offsets_and_tokens():
    spec, sec = _spec(9)
    pairs, hints = scenario_mapping(spec, sec)
    atk = next(e.ip for e in spec.externals if e.kind == "attacker")
    web = next(a for a in spec.assets if a.role.value == "web_server")
    raw = [
        ("suricata_eve", T0, "timestamp", {"src_ip": atk, "dest_ip": web.attachments[0].ip}),
        (
            "wazuh_alert",
            T0 + timedelta(seconds=3),
            "timestamp",
            {"rule": {"id": "100112"}, "agent": {"name": web.hostname}},
        ),
    ]
    truth = FragmentTruth(
        label="malicious", family="F1", technique="T1190", expected_rules=[100112], outcome="success"
    )
    frag = assemble_fragment(
        "frg-1", "grp-x", "attack_stage", truth, raw, pairs, hints, {"role": "web_server"}
    )
    assert frag.records[0].offset_ms == 0 and frag.records[1].offset_ms == 3000
    assert frag.duration_ms == 3000
    assert token("IP_WEB_SERVER_1") in frag.tokens and token("ATTACKER_IP") in frag.tokens
    assert Fragment.from_dict(frag.to_dict()).to_dict() == frag.to_dict()


def test_library_roundtrip(tmp_path):
    truth = FragmentTruth(label="benign", family="persona_customer")
    frag = Fragment("frg-9", "benign", "grp-aa", 1000, {}, [], truth)
    save_fragment(frag, tmp_path)
    loaded = list(iter_fragments(tmp_path, "grp-aa"))
    assert len(loaded) == 1 and loaded[0].fragment_id == "frg-9"
    idx = index_library(tmp_path)
    assert idx.total == 1 and "persona_customer" in idx.by_family


def test_delta_extraction():
    from iris.fragments.record import delta

    lines = ["{a}", "{b}", "{c}", "{d}"]
    assert delta(2, lines) == ["{c}", "{d}"]
    assert delta(4, lines) == []
    assert delta(0, lines) == lines
