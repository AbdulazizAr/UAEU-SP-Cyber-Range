from datetime import UTC, datetime, timedelta

import pytest

from iris.core.vclock import EpisodeClock
from iris.generator.retime import (
    format_syslog,
    parse_wazuh_ts,
    shift_iso_stamps,
    shift_syslog_prefix,
    shift_wazuh,
)

ALERT = {
    "timestamp": "2026-11-02T08:07:41.123+0000",
    "rule": {"id": "5712", "frequency": 8, "timeframe": 120},
    "agent": {"id": "001", "name": "web-01"},
    "predecoder": {"program_name": "sshd", "timestamp": "Nov  2 08:07:41", "hostname": "web-01"},
    "full_log": "Nov  2 08:07:41 web-01 sshd[4001]: Failed password for invalid user admin1 from 10.0.0.9",
    "location": "/var/log/iris/canary.log",
}


def test_alert_moves_into_the_virtual_window():
    window = datetime(2025, 3, 3, 5, 40, tzinfo=UTC)
    clock = EpisodeClock.for_observe_start(window, datetime(2026, 11, 2, 8, 7, 41, tzinfo=UTC))
    out = shift_wazuh(ALERT, clock.offset)
    assert out["timestamp"] == "2025-03-03T05:40:00.123+0000"
    assert out["predecoder"]["timestamp"] == "Mar  3 05:40:00"
    assert out["full_log"].startswith("Mar  3 05:40:00 web-01 sshd[4001]: Failed password")
    assert out["rule"] == ALERT["rule"] and ALERT["timestamp"].startswith("2026")  # original untouched


def test_intervals_are_preserved():
    off = timedelta(days=-600, seconds=17)
    a = dict(ALERT)
    b = dict(ALERT, timestamp="2026-11-02T08:09:30.500+0000", full_log="Nov  2 08:09:30 web-01 x")
    sa, sb = shift_wazuh(a, off), shift_wazuh(b, off)
    gap_real = parse_wazuh_ts(b["timestamp"]) - parse_wazuh_ts(a["timestamp"])
    assert parse_wazuh_ts(sb["timestamp"]) - parse_wazuh_ts(sa["timestamp"]) == gap_real


def test_syslog_year_and_day_padding():
    ref = datetime(2026, 1, 1, 0, 0, 5, tzinfo=UTC)
    # a stamp from 31 Dec belongs to the previous year
    assert shift_syslog_prefix("Dec 31 23:59:59 h x", timedelta(seconds=2), ref) == "Jan  1 00:00:01 h x"
    assert format_syslog(datetime(2025, 3, 13, 1, 2, 3, tzinfo=UTC)) == "Mar 13 01:02:03"
    assert shift_syslog_prefix("no stamp here", timedelta(days=1), ref) == "no stamp here"


def test_iso_stamps_in_text_keep_their_format():
    off = timedelta(days=-1)
    text = 'app {"ts":"2026-11-02T08:07:41Z","b":"2026-11-02T08:07:41.250+04:00","c":"2026-11-02T08:07:41"}'
    out = shift_iso_stamps(text, off)
    assert '"ts":"2026-11-01T08:07:41Z"' in out
    assert '"b":"2026-11-01T08:07:41.250+04:00"' in out
    assert '"c":"2026-11-01T08:07:41"' in out


def test_record_without_timestamp_is_rejected():
    with pytest.raises(ValueError):
        shift_wazuh({"full_log": "x"}, timedelta(0))
