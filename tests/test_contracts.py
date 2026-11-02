import copy
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from iris.contracts.decisions import DecisionRecord
from iris.contracts.export import all_models, export_schemas
from iris.contracts.spec import ScenarioSpec
from iris.contracts.visible import Asset, TelemetryEnvelope, VisibleManifest

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = ROOT / "examples" / "golden_v0.spec.yaml"


@pytest.fixture
def golden() -> dict:
    return yaml.safe_load(GOLDEN.read_text())


def _expect_spec_error(data: dict, fragment: str) -> None:
    with pytest.raises(ValidationError) as exc:
        ScenarioSpec.model_validate(data)
    assert fragment in str(exc.value), str(exc.value)


# ---------------------------------------------------------------- spec


def test_golden_spec_validates(golden):
    spec = ScenarioSpec.model_validate(golden)
    assert len(spec.assets) == 9
    assert [a.hostname for a in spec.assets if not a.monitored] == ["rtr-01", "siem-01", "adm-01"]


def test_spec_round_trips_through_json(golden):
    spec = ScenarioSpec.model_validate(golden)
    again = ScenarioSpec.model_validate_json(spec.model_dump_json())
    assert again == spec
    assert '"2025-03-03T05:40:00Z"' in spec.model_dump_json()


def test_spec_rejects_unknown_fields(golden):
    golden["organization"]["maturty"] = "high"
    _expect_spec_error(golden, "maturty")


def test_spec_rejects_ip_outside_zone(golden):
    golden["assets"][2]["attachments"][0]["ip"] = "10.64.99.10"
    _expect_spec_error(golden, "not in dmz")


def test_spec_rejects_duplicate_ip(golden):
    golden["assets"][3]["attachments"][0]["ip"] = "10.64.30.30"
    _expect_spec_error(golden, "already used")


def test_spec_rejects_non_gateway_on_two_zones(golden):
    golden["assets"][2]["attachments"].append({"zone": "servers", "ip": "10.64.30.77"})
    _expect_spec_error(golden, "only gateway roles")


def test_spec_rejects_dangling_references(golden):
    bad = copy.deepcopy(golden)
    bad["services"][0]["depends_on"] = ["SVC-NOPE-001"]
    _expect_spec_error(bad, "depends on unknown")
    bad = copy.deepcopy(golden)
    bad["weaknesses"][0]["asset_id"] = "AST-NOPE-001"
    _expect_spec_error(bad, "unknown asset")


def test_spec_rejects_overlapping_subnets(golden):
    golden["zones"][2]["subnet"] = "10.64.0.0/16"
    golden["zones"][2]["gateway"] = "10.64.20.1"
    _expect_spec_error(golden, "subnets overlap")


def test_spec_rejects_bad_episodes(golden):
    bad = copy.deepcopy(golden)
    bad["episodes"][1]["virtual_start"] = "2025-03-03T05:45:00Z"
    _expect_spec_error(bad, "overlaps")
    bad = copy.deepcopy(golden)
    bad["episodes"][2]["virtual_start"] = "2025-05-01T07:00:00Z"
    bad["episodes"][2]["virtual_end"] = "2025-05-01T07:10:00Z"
    _expect_spec_error(bad, "outside the scenario calendar")
    bad = copy.deepcopy(golden)
    bad["episodes"][0]["virtual_end"] = "2025-03-03T05:40:00Z"
    _expect_spec_error(bad, "end must be after start")


def test_spec_rejects_incomplete_seeds(golden):
    del golden["seeds"]["subseeds"]["grc"]
    _expect_spec_error(golden, "subseeds must contain exactly")


def test_spec_rejects_naive_timestamps(golden):
    golden["episodes"][0]["virtual_start"] = "2025-03-03T05:40:00"
    _expect_spec_error(golden, "naive datetime")


def test_spec_requires_gateway_holder(golden):
    golden["zones"][1]["gateway"] = "10.64.10.254"
    _expect_spec_error(golden, "not held by any gateway asset")


# ---------------------------------------------------------------- visible plane

TS = datetime(2025, 3, 3, 5, 41, tzinfo=UTC)


def test_visible_manifest_excludes_leaky_fields():
    fields = set(VisibleManifest.model_fields)
    for leaky in (
        "generator_version",
        "group_id",
        "tier",
        "seeds",
        "lineage",
        "activity_counts",
        "created_at_real",
    ):
        assert leaky not in fields


def test_telemetry_envelope_allows_unresolved_asset():
    env = TelemetryEnvelope(
        event_id="evt-0123456789abcdef0123",
        scenario_id="scn-015abd7f5cc5",
        episode_id="scn-015abd7f5cc5-ep001",
        source_type="suricata_eve",
        event_timestamp=TS,
        asset_ref=None,
        raw={"event_type": "flow"},
    )
    assert json.loads(env.model_dump_json())["event_timestamp"] == "2025-03-03T05:41:00Z"


def test_recorded_asset_may_be_incomplete():
    a = Asset(
        asset_id="AST-WEB-001",
        hostname="web-01",
        role="web_server",
        asset_type="server",
        ip_addresses=["10.64.10.10"],
        recorded_at=TS,
    )
    assert a.zone is None and a.os_profile is None


# ---------------------------------------------------------------- decisions

BASE = {
    "decision_id": "dec-1",
    "scenario_id": "scn-015abd7f5cc5",
    "episode_id": "scn-015abd7f5cc5-ep002",
    "as_of": "2025-03-10T06:10:00Z",
    "subject_ref": {"kind": "asset", "id": "AST-DB-001"},
    "engine_version": "0.1",
    "model_version": "m1",
    "policy_version": "p1",
}


def test_assessed_decision_is_valid():
    d = DecisionRecord.model_validate(
        {
            **BASE,
            "type": "D2",
            "status": "ASSESSED",
            "payload": {"type": "D2", "priority": "CRITICAL"},
            "confidence": 0.8,
            "evidence_event_ids": ["evt-0123456789abcdef0123"],
        }
    )
    assert d.payload is not None and d.payload.type == "D2"


@pytest.mark.parametrize(
    ("patch", "fragment"),
    [
        (
            {"type": "D2", "status": "ASSESSED", "confidence": 0.8, "evidence_event_ids": ["e"]},
            "needs a payload",
        ),
        (
            {
                "type": "D2",
                "status": "ASSESSED",
                "payload": {"type": "D2", "priority": "LOW"},
                "evidence_event_ids": ["e"],
            },
            "needs a confidence",
        ),
        (
            {
                "type": "D3",
                "status": "ASSESSED",
                "confidence": 0.5,
                "evidence_event_ids": ["e"],
                "payload": {"type": "D2", "priority": "LOW"},
            },
            "does not match",
        ),
        (
            {
                "type": "D2",
                "status": "ASSESSED",
                "confidence": 0.5,
                "payload": {"type": "D2", "priority": "LOW"},
            },
            "must cite visible evidence",
        ),
    ],
)
def test_decision_rules(patch, fragment):
    with pytest.raises(ValidationError) as exc:
        DecisionRecord.model_validate({**BASE, **patch})
    assert fragment in str(exc.value)


def test_d4_allows_at_most_three_controls():
    rec = {"control_id": "CTRL-IAM-002", "action": "implement", "rationale": "password-only SSH on db-01"}
    with pytest.raises(ValidationError):
        DecisionRecord.model_validate(
            {
                **BASE,
                "type": "D4",
                "status": "ASSESSED",
                "confidence": 0.7,
                "context_refs": ["control:CTRL-IAM-002"],
                "payload": {"type": "D4", "recommendations": [rec] * 4},
            }
        )


def test_abstention_needs_no_payload():
    d = DecisionRecord.model_validate({**BASE, "type": "D1", "status": "ABSTAINED"})
    assert d.payload is None and d.confidence is None


# ---------------------------------------------------------------- schema export


def test_schema_export(tmp_path):
    written = export_schemas(tmp_path)
    assert len(written) == len(all_models())
    spec_schema = json.loads((tmp_path / "scenario_spec.schema.json").read_text())
    assert spec_schema["$id"] == "iris:scenario_spec"
    assert "assets" in spec_schema["properties"]


def test_spec_reserves_last_usable_address_for_bridge(golden):
    golden["assets"][2]["attachments"][0]["ip"] = "10.64.10.254"
    _expect_spec_error(golden, "reserved for the container bridge")
