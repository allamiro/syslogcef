from __future__ import annotations

from datetime import datetime, timezone

from syslogcef.api import convert_line, normalize_event, parse_syslog


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


def test_message_kv_cannot_override_parsed_metadata_for_mappings():
    line = (
        "<166>Jan  1 12:34:56 trusted app[42]: "
        "host=evil app=spoof pid=999 severity=0 facility=0"
    )
    event = normalize_event(parse_syslog(line, now=NOW))
    fields = event.as_field_dict()

    # Keep the source values available as kv data, but the parsed syslog
    # envelope is authoritative for the canonical metadata fields.
    assert event.kv["host"] == "evil"
    assert fields["host"] == "trusted"
    assert fields["app"] == "app"
    assert fields["pid"] == "42"
    assert fields["severity"] == 6
    assert fields["facility"] == 20

    cef = convert_line(line, now=NOW, mapping={})
    assert cef.split("|")[6] == "2"
    assert "shost=trusted" in cef
    assert "shost=evil" not in cef


def test_field_names_are_case_normalized_without_losing_originals():
    line = (
        "<14>Jan  1 12:34:56 fw1 app: "
        "SRCIP=10.1.1.1 DSTPORT=443 User=alice DeviceExternalId=abc"
    )
    event = normalize_event(parse_syslog(line, now=NOW))

    assert event.kv["SRCIP"] == "10.1.1.1"
    assert event.kv["srcip"] == "10.1.1.1"
    assert event.kv["src"] == "10.1.1.1"
    assert event.kv["dpt"] == "443"
    assert event.kv["suser"] == "alice"
    assert event.kv["deviceExternalId"] == "abc"


def test_case_normalization_keeps_explicit_canonical_value():
    line = "<14>Jan  1 12:34:56 fw1 app: srcip=99.9.9.9 SRC=10.0.0.1 action=x"
    event = normalize_event(parse_syslog(line, now=NOW))

    assert event.kv["src"] == "10.0.0.1"
