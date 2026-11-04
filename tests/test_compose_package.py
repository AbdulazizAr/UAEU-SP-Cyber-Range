import json
from datetime import UTC, datetime, timedelta

from iris.core.seeds import SeedSet
from iris.fragments.assemble import assemble_fragment
from iris.fragments.mapping import scenario_mapping
from iris.fragments.model import FragmentTruth
from iris.generator.grc.recorded import build_grc
from iris.generator.sampler import SampleOverrides, sample_spec
from iris.generator.secrets import scenario_secrets
from iris.packager.build import assemble, write_package
from iris.packager.compose_build import compose_onto
from iris.packager.verify import verify_package

T0 = datetime(2026, 11, 3, 8, 0, tzinfo=UTC)


def _benign_fragment(spec, sec, group_id):
    pairs, hints = scenario_mapping(spec, sec)
    web = next(a for a in spec.assets if a.role.value == "web_server")
    client = next((e.ip for e in spec.externals if e.kind == "client"), None)
    raw = [
        (
            "suricata_eve",
            T0,
            "timestamp",
            {
                "timestamp": "2026-11-03T08:00:00.000000+0000",
                "src_ip": client or web.attachments[0].ip,
                "dest_ip": web.attachments[0].ip,
                "flow_id": 3,
                "event_type": "flow",
            },
        ),
        (
            "wazuh_alert",
            T0 + timedelta(seconds=2),
            "timestamp",
            {
                "timestamp": "2026-11-03T08:00:02.000+0000",
                "rule": {"id": "5501"},
                "agent": {"name": web.hostname, "ip": web.attachments[0].ip},
                "full_log": f"session opened on {web.hostname}",
            },
        ),
    ]
    truth = FragmentTruth(label="benign", family="persona_web", outcome="n/a")
    return assemble_fragment(
        "frg-benign", group_id, "benign", truth, raw, pairs, hints, {"role": "web_server"}
    )


def test_composed_package_builds_and_verifies(tmp_path):
    seeds = SeedSet.from_master(21)
    spec = sample_spec(seeds, SampleOverrides(live=True))
    sec = scenario_secrets(spec)
    grc = build_grc(spec, seeds)
    gid = seeds.group_id()

    assembled = assemble(seeds, spec=spec)
    library = [_benign_fragment(spec, sec, gid)]
    _composed, options = compose_onto(assembled, grc.reality, library, {gid})

    result = write_package(assembled, tmp_path, options)
    rep = verify_package(result.root)
    assert rep.ok, rep.problems

    vman = json.loads((result.root / "visible" / "manifest.visible.json").read_text())
    full = json.loads((result.root / "hidden" / "manifest.json").read_text())
    assert full["data_tier"] == "train"
    assert full["contents"]["telemetry"] is True
    assert set(vman["enabled_sensors"]) <= {"wazuh", "suricata"}
    # per-episode telemetry and decision keys exist for every episode
    eids = [e["episode_id"] for e in vman["episodes"]]
    for eid in eids:
        assert any(a.startswith(f"telemetry/{eid}/") for a in vman["available_artifacts"])
        for dtype in ("d1", "d2", "d4"):
            assert (result.root / "hidden" / "evaluation_key" / dtype / f"{eid}.json").exists()
        assert (result.root / "hidden" / "truth" / "outcomes" / f"{eid}.json").exists()
    assert (result.root / "hidden" / "truth" / "composition.json").exists()


def test_composed_telemetry_has_no_tokens(tmp_path):
    seeds = SeedSet.from_master(22)
    spec = sample_spec(seeds, SampleOverrides(live=True))
    sec = scenario_secrets(spec)
    grc = build_grc(spec, seeds)
    gid = seeds.group_id()
    assembled = assemble(seeds, spec=spec)
    compose_onto(assembled, grc.reality, [_benign_fragment(spec, sec, gid)], {gid})
    telemetry = {k: v for k, v in assembled.visible.items() if k.startswith("telemetry/")}
    assert telemetry  # at least one episode placed the benign fragment
    assert "@@IRIS:" not in json.dumps(telemetry)
