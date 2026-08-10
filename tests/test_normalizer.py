from __future__ import annotations

from datetime import datetime, timezone

from syslogcef.api import normalize_event, parse_syslog


NOW = datetime(2023, 1, 2, tzinfo=timezone.utc)


def test_derives_src_dst_from_ip_suffixed_keys():
    line = "<166>Jan  1 12:34:56 fw1 app: connection src_ip=1.2.3.4 dst_ip=5.6.7.8"
    event = normalize_event(parse_syslog(line, now=NOW))
    assert event.kv["src"] == "1.2.3.4"
    assert event.kv["dst"] == "5.6.7.8"


def test_extracts_cisco_style_event_code():
    line = "<166>Jan  1 12:34:56 fw1 app: %ASA-6-302013: Built inbound TCP connection"
    event = normalize_event(parse_syslog(line, now=NOW))
    assert event.kv["event_code"] == "ASA-6-302013"


def test_timestamp_is_timezone_aware():
    line = "<166>Jan  1 12:34:56 fw1 app: hello"
    event = normalize_event(parse_syslog(line, now=NOW))
    assert event.ts.tzinfo is not None


def test_message_short_truncates_to_120_chars():
    long_msg = "x" * 300
    line = f"<166>Jan  1 12:34:56 fw1 app: {long_msg}"
    event = normalize_event(parse_syslog(line, now=NOW))
    assert len(event.extras["message_short"]) == 120


def test_field_dict_drops_none_values():
    line = "<166>Jan  1 12:34:56 fw1 app: hello"
    event = normalize_event(parse_syslog(line, now=NOW))
    fields = event.as_field_dict()
    assert None not in fields.values()
    assert fields["host"] == "fw1"
    assert fields["app"] == "app"


def test_normalize_is_idempotent():
    line = "<166>Jan  1 12:34:56 fw1 app: hello"
    event = normalize_event(parse_syslog(line, now=NOW))
    assert normalize_event(event) is event
