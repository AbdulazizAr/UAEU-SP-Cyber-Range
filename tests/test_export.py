from datetime import UTC, datetime, timedelta

from iris.generator.eve import format_eve_ts
from iris.generator.export import EpisodeCapture, export_episode
from iris.generator.retime import format_wazuh_ts, parse_wazuh_ts

REAL = datetime(2026, 11, 3, 8, 0, tzinfo=UTC)
VIRT = datetime(2025, 6, 10, 9, 30, tzinfo=UTC)


def _alert(t, text="sshd: Failed password", rule="5710"):
    return {"timestamp": format_wazuh_ts(t), "rule": {"id": rule}, "full_log": f"Nov  3 08:00:00 h {text}"}


def _eve(t, iface, url="/", cid="1:abc"):
    return {
        "timestamp": format_eve_ts(t),
        "event_type": "http",
        "community_id": cid,
        "in_iface": iface,
        "http": {"url": url},
        "dest_ip": "10.0.0.5",
    }


def _capture():
    start, end = REAL, REAL + timedelta(minutes=10)
    return EpisodeCapture(
        episode_id="scn-000000000000-ep001",
        virtual_start=VIRT,
        observe_start_real=start,
        observe_end_real=end,
        alerts=[
            _alert(start - timedelta(minutes=2)),  # pre-roll
            _alert(start + timedelta(minutes=1)),
            _alert(start + timedelta(minutes=3), text="healthcheck hc-1234-web01"),  # canary inside window
            _alert(start + timedelta(minutes=12)),  # drain
        ],
        archives=[_alert(start + timedelta(minutes=2))],
        eve=[
            _eve(start + timedelta(minutes=4), "eth0"),
            _eve(start + timedelta(minutes=4, milliseconds=200), "eth1"),  # same flow, other interface
            _eve(start + timedelta(minutes=5), "eth0", url="/hc", cid="1:def"),  # canary
        ],
    )


def test_window_split_and_shift():
    out = export_episode(_capture())
    alerts = out.visible["telemetry/wazuh/alerts.jsonl"]
    assert len(alerts) == 1
    assert parse_wazuh_ts(alerts[0]["timestamp"]) == VIRT + timedelta(minutes=1)
    assert alerts[0]["full_log"].startswith("Jun 10 09:30:00")
    assert out.counts["preroll_records"] == 3 and out.counts["drain_records"] == 1  # 1 pre + 2 canaries
    assert len(out.visible["telemetry/suricata/eve.jsonl"]) == 1  # deduped, canary hidden
    assert out.counts["eve_raw"] == 3 and out.counts["eve_deduped"] == 2


def test_canaries_never_visible():
    out = export_episode(_capture())
    text = str(out.visible)
    assert "healthcheck" not in text and "/hc" not in text and "hc-1234" not in text


def test_archives_follow_retention():
    kept = export_episode(_capture(), archives_retained=True)
    dropped = export_episode(_capture(), archives_retained=False)
    assert len(kept.visible["telemetry/wazuh/archives.jsonl"]) == 1
    assert "telemetry/wazuh/archives.jsonl" not in dropped.visible
    assert any(k.endswith("archives_not_retained.jsonl") for k in dropped.hidden)
