"""Pure-logic tests for the P1 spikes (the Docker parts run on the laptop)."""

import json
from datetime import UTC, datetime

import yaml

from iris.spikes.common import SpikeResult, parse_mem_mib
from iris.spikes.network import HTTP_REQUESTS, SERVER_IP, analyse, parse_interfaces
from iris.spikes.wazuh import (
    alert_time,
    canary_alerts,
    error_lines,
    parse_agent_list,
    parse_control_status,
    parse_json_lines,
)

from .conftest_paths import ROOT


def test_parse_agent_list():
    text = """
Wazuh agent_control. List of available agents:
   ID: 000, Name: siem-01 (server), IP: 127.0.0.1, Active/Local
   ID: 001, Name: spike-web-01, IP: any, Active
   ID: 002, Name: spike-db-01, IP: any, Disconnected
"""
    assert parse_agent_list(text) == {
        "spike-web-01": ("001", "Active"),
        "spike-db-01": ("002", "Disconnected"),
    }


def test_parse_control_status():
    text = "wazuh-clusterd not running...\nwazuh-modulesd is running...\nwazuh-analysisd is running...\n"
    assert parse_control_status(text) == (2, ["wazuh-clusterd"])


def test_alert_parsing_and_filtering():
    lines = "\n".join(
        json.dumps(a)
        for a in [
            {
                "timestamp": "2025-03-03T05:41:02.123+0000",
                "rule": {"id": "5710"},
                "agent": {"name": "spike-web-01"},
            },
            {
                "timestamp": "2025-03-03T05:41:09.001+0000",
                "rule": {"id": "5712"},
                "agent": {"name": "spike-web-01"},
            },
            {
                "timestamp": "2025-03-03T05:41:09.001+0000",
                "rule": {"id": "530"},
                "agent": {"name": "spike-web-01"},
            },
            {
                "timestamp": "2025-03-03T05:41:09.001+0000",
                "rule": {"id": "5710"},
                "agent": {"name": "spike-db-01"},
            },
        ]
    )
    alerts = parse_json_lines(lines + "\nnot json\n")
    assert len(alerts) == 4
    picked = canary_alerts(alerts, "spike-web-01")
    assert [a["rule"]["id"] for a in picked] == ["5710", "5712"]
    assert alert_time(picked[0]) == datetime(2025, 3, 3, 5, 41, 2, 123000, tzinfo=UTC)
    assert (
        canary_alerts(alerts, "spike-web-01", since=datetime(2025, 3, 3, 5, 41, 5, tzinfo=UTC))[0]["rule"][
            "id"
        ]
        == "5712"
    )


def test_error_lines():
    log = "2025/03/03 05:40:01 wazuh-remoted: INFO: ok\n2025/03/03 wazuh-db: ERROR: boom\n"
    assert error_lines(log) == ["2025/03/03 wazuh-db: ERROR: boom"]


def test_parse_mem():
    assert parse_mem_mib("123.4MiB / 14.77GiB") == 123.4
    assert parse_mem_mib("1.5GiB / 14.77GiB") == 1536.0
    assert parse_mem_mib("garbage") is None


def test_parse_interfaces():
    text = (
        "1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever\n"
        "52: eth0    inet 10.99.1.1/24 brd 10.99.1.255 scope global eth0\n"
        "54: eth1    inet 10.99.2.1/24 brd 10.99.2.255 scope global eth1\n"
    )
    assert parse_interfaces(text) == {"10.99.1.1": "eth0", "10.99.2.1": "eth1"}


def _eve(ts: str, etype: str, sport: int, iface: str, dport: int = 8080) -> dict:
    return {
        "timestamp": ts,
        "event_type": etype,
        "src_ip": "10.99.1.10",
        "src_port": sport,
        "dest_ip": SERVER_IP,
        "dest_port": dport,
        "proto": "TCP",
        "in_iface": iface,
        "community_id": f"1:conn{sport}",
    }


def test_network_analysis_on_synthetic_eve():
    events = []
    for i in range(HTTP_REQUESTS):
        ts = f"2026-11-02T10:00:{10 + 2 * i:02d}.100000+0000"
        ts2 = f"2026-11-02T10:00:{10 + 2 * i:02d}.300000+0000"
        for etype in ("flow", "http"):
            events.append(_eve(ts, etype, 40000 + i, "eth0"))
            events.append(_eve(ts2, etype, 40000 + i, "eth1"))
    events.append(_eve("2026-11-02T10:00:30.000000+0000", "flow", 41000, "eth0", dport=9090))
    events.append(
        {
            "timestamp": "2026-11-02T10:00:40.000000+0000",
            "event_type": "stats",
            "stats": {"capture": {"kernel_drops": 0}},
        }
    )
    result = SpikeResult("network", "x")
    analyse(events, result)
    status = {c.name: c.status for c in result.checks}
    assert status["eve.dedup_one_per_connection"] == "pass"
    assert status["eve.http_events_after_dedup"] == "pass"
    assert status["eve.kernel_drops_zero"] == "pass"
    assert status["eve.time_shift_into_virtual_window"] == "pass"
    assert result.measurements["eve.raw_flows_8080"] == 2 * HTTP_REQUESTS
    assert result.passed


def test_spike_compose_files_parse():
    for name in ("wazuh.compose.yml", "network.compose.yml"):
        data = yaml.safe_load((ROOT / "spikes" / name).read_text())
        assert "services" in data
    wazuh = yaml.safe_load((ROOT / "spikes" / "wazuh.compose.yml").read_text())
    assert wazuh["services"]["agent1"]["environment"]["FAKETIME_DONT_FAKE_MONOTONIC"] == "1"
