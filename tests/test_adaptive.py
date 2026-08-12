from __future__ import annotations

"""Tests for the new format parsers and the adaptive pattern detector."""


from syslogcef import convert_line, normalize_event, parse_syslog
from syslogcef.adaptive import cache_size, clear_cache


def fields(cef: str) -> list[str]:
    return cef.split("|")


# --- key=value stream formats -------------------------------------------------

FORTINET_LINE = '<189>date=2020-04-23 time=12:32:48 devname="testswitch3" devid="someotherrouteridagain" logid="0102043014" type="event" subtype="user" level="notice" vd="root" srcip=10.1.1.1 dstip=10.2.2.2 action="login"'
SOPHOS_LINE = '<30>device="SFW" date=2020-05-18 time=14:38:48 timezone="CEST" device_name="XG230" device_id=1234567890123456 log_id=041101618035 log_type="Anti-Spam" log_component="SMTP" log_subtype="Allowed" priority=Information src_ip="10.9.9.9" user_name="alice"'


def test_fortinet_kv_line():
    ev = parse_syslog(FORTINET_LINE)
    assert ev.source_hint == "kv"
    assert ev.host == "testswitch3"
    assert ev.pri == 189
    assert ev.ts.year == 2020
    cef = convert_line(FORTINET_LINE)
    assert fields(cef)[1] == "Fortinet"
    assert fields(cef)[4] == "fortinet.0102043014"
    assert "src=10.1.1.1" in cef
    assert "dvchost=testswitch3" in cef


def test_sophos_kv_line():
    ev = parse_syslog(SOPHOS_LINE)
    assert ev.source_hint == "kv"
    assert ev.host == "XG230"
    cef = convert_line(SOPHOS_LINE)
    assert fields(cef)[1] == "Sophos"
    assert fields(cef)[4] == "sophos.041101618035"
    assert "suser=alice" in cef


def test_kv_severity_from_level_word_without_pri():
    line = 'date=2020-04-23 time=12:32:48 devname="fw1" logid="0100000001" level="warning" msgtext="x"'
    ev = normalize_event(parse_syslog(line))
    assert ev.severity == 4


def test_quoted_kv_values_with_spaces():
    line = '<30>device="SFW" date=2020-05-18 time=14:38:48 device_name="XG230" log_id=1 reason="Email has been accepted" x=1'
    ev = normalize_event(parse_syslog(line))
    assert ev.kv["reason"] == "Email has been accepted"


# --- native Cisco console formats ---------------------------------------------

def test_cisco_native_sequence_line():
    line = "000123: Feb  8 04:00:47.272: %SEC-6-IPACCESSLOGP: list 100 denied tcp 10.1.1.1(1024) -> 10.2.2.2(80), 1 packet"
    ev = parse_syslog(line)
    assert ev.source_hint == "cisco"
    assert ev.sd["cisco.sequence"] == "000123"
    norm = normalize_event(ev)
    assert norm.kv["event_code"] == "SEC-6-IPACCESSLOGP"
    assert norm.severity == 6


def test_cisco_star_clock_line():
    line = "*Mar  1 18:46:11.012: %SYS-5-CONFIG_I: Configured from console by vty2 (10.34.195.36)"
    ev = parse_syslog(line)
    assert ev.source_hint == "cisco"
    norm = normalize_event(ev)
    assert norm.kv["event_code"] == "SYS-5-CONFIG_I"
    assert norm.severity == 5
    assert fields(convert_line(line))[2] == "IOS"


def test_cisco_native_with_year_and_timezone():
    line = "Feb  8 2024 04:00:47 UTC: %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down"
    ev = parse_syslog(line)
    assert ev.source_hint == "cisco"
    assert ev.ts.year == 2024
    assert normalize_event(ev).severity == 3


# --- ISO syslog without RFC5424 framing ---------------------------------------

def test_iso_timestamp_with_pri_and_tag():
    line = "<13>2023-07-01T12:00:00Z web01 nginx[42]: GET /index.html"
    ev = parse_syslog(line)
    assert ev.source_hint == "iso_syslog"
    assert ev.pri == 13
    assert ev.host == "web01"
    assert ev.app == "nginx"
    assert ev.pid == "42"
    assert ev.msg == "GET /index.html"


# --- adaptive detection -------------------------------------------------------

def test_adaptive_learns_unknown_layout_and_caches():
    clear_cache()
    line1 = "2020/04/23 12:32:48 fw-edge-01 session established peer=10.0.0.1"
    line2 = "2020/04/24 09:10:11 fw-edge-02 session torn down peer=10.0.0.2"
    ev1 = parse_syslog(line1)
    assert ev1.source_hint == "adaptive"
    assert ev1.host == "fw-edge-01"
    assert ev1.ts.year == 2020 and ev1.ts.month == 4 and ev1.ts.day == 23
    assert cache_size() == 1
    ev2 = parse_syslog(line2)
    assert ev2.source_hint == "adaptive"
    assert ev2.host == "fw-edge-02"
    assert cache_size() == 1  # reused the learned pattern


def test_adaptive_dmy_dash_timestamp():
    line = "17-Apr-2020 14:08:08 core01 link flap detected"
    ev = parse_syslog(line)
    assert ev.source_hint == "adaptive"
    assert ev.ts.year == 2020 and ev.ts.month == 4
    assert ev.host == "core01"


def test_adaptive_preserves_pri():
    line = "<86>2020/04/23 12:32:48 bastion sudo session opened"
    ev = parse_syslog(line)
    assert ev.source_hint == "adaptive"
    assert ev.pri == 86
    assert ev.severity == 6


def test_garbage_still_falls_back_to_unknown():
    ev = parse_syslog("complete garbage with no timestamp at all ###")
    assert ev.source_hint == "unknown"
    ev2 = parse_syslog("<30>still garbage but with a pri")
    assert ev2.source_hint == "unknown"
    assert ev2.pri == 30


# --- fixes from code review of the adaptive parsing PR -------------------------

def test_kv_without_id_falls_back_to_nonempty_event_class():
    line = '<30>device="SFW" date=2020-05-18 time=14:38:48 device_name="XG230" reason="x" a=1'
    cef = convert_line(line)
    header_fields = fields(cef)
    assert header_fields[4] != ""  # eventClassId never empty


def test_kv_numeric_timezone_applied():
    line = 'date=2020-04-23 time=12:32:48 devname="fw1" logid="0100000001" tz="-0500" x=1'
    ev = parse_syslog(line)
    assert ev.ts.utcoffset().total_seconds() == -5 * 3600


def test_cisco_milliseconds_preserved():
    line = "000123: Feb  8 04:00:47.272: %SEC-6-IPACCESSLOGP: list 100 denied tcp"
    ev = parse_syslog(line)
    assert ev.ts.microsecond == 272000


def test_adaptive_mon_day_year_rollover():
    import re
    from datetime import datetime, timezone

    from syslogcef.adaptive import TIMESTAMP_LIB

    src, conv = next((s, c) for n, s, c in TIMESTAMP_LIB if n == "mon_day")
    match = re.compile(src).match("Dec 31 23:59:59")
    ts = conv(match, datetime(2026, 1, 2, tzinfo=timezone.utc))
    assert ts.year == 2025


def test_adaptive_cached_host_revalidated():
    clear_cache()
    good = "2021/05/01 10:00:00 fw-edge-01 session established"
    bad = "2021/05/02 11:00:00 ERROR link down"
    ev1 = parse_syslog(good)
    assert ev1.host == "fw-edge-01"
    ev2 = parse_syslog(bad)
    assert ev2.source_hint == "adaptive"
    assert ev2.host is None
    assert ev2.msg.startswith("ERROR")


def test_adaptive_cached_empty_message_preserved():
    clear_cache()
    ev1 = parse_syslog("2021/05/01 10:00:00 fw-edge-01 something happened")
    assert ev1.msg == "something happened"
    ev2 = parse_syslog("2021/05/02 11:00:00 fw-edge-02")
    assert ev2.host == "fw-edge-02"
    assert ev2.msg == ""


def test_adaptive_hostless_line_does_not_poison_host_learning():
    clear_cache()
    first = parse_syslog("2021/05/01 10:00:00 ERROR link down")
    assert first.host is None

    # ERROR and an alphabetic hostname have the same reduced signature.
    # A hostless cached pattern must not suppress the valid host later.
    second = parse_syslog("2021/05/02 11:00:00 firewall session established")
    assert second.source_hint == "adaptive"
    assert second.host == "firewall"
    assert second.msg == "session established"


def test_adaptive_cached_host_strips_delimiter_consistently():
    clear_cache()
    first = parse_syslog("2021/05/01 10:00:00 fw-edge-01, session established")
    second = parse_syslog("2021/05/02 11:00:00 fw-edge-02, session ended")

    assert first.host == "fw-edge-01"
    assert second.host == "fw-edge-02"


def test_adaptive_preserves_original_timestamp_text():
    clear_cache()
    first = parse_syslog("2021/05/01 10:00:00 fw1 session established")
    second = parse_syslog("2021/05/02 11:00:00 fw2 session ended")

    assert first.ts_orig == "2021/05/01 10:00:00"
    assert second.ts_orig == "2021/05/02 11:00:00"


def test_adaptive_named_timezone_is_not_a_host():
    clear_cache()
    event = parse_syslog("2021/05/01 10:00:00 CEST firewall session established")

    assert event.source_hint == "adaptive"
    assert event.host is None
    assert event.msg.startswith("CEST ")


def test_adaptive_accepts_ipv6_host_tokens_on_fresh_and_cached_paths():
    clear_cache()
    first = parse_syslog("2021/05/01 10:00:00 2001:db8::1 session established")
    second = parse_syslog("2021/05/02 11:00:00 2001:db8::2 session ended")

    assert first.host == "2001:db8::1"
    assert second.host == "2001:db8::2"


def test_uppercase_kv_metadata_and_aliases_are_normalized():
    line = (
        "DATE=2020-04-23 TIME=12:32:48 DEVNAME=fw1 "
        "LOGID=0100000001 LEVEL=warning SRCIP=10.1.1.1"
    )
    event = normalize_event(parse_syslog(line))

    assert event.ts.year == 2020
    assert event.host == "fw1"
    assert event.severity == 4
    assert event.kv["src"] == "10.1.1.1"
    assert fields(convert_line(line))[1] == "Fortinet"
